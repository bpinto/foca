// Package command exposes host-declared actions as "action:<id>" resources
// (design §11, D14). An action runs a fixed command with execve, never a
// shell, in its own process group, with stdin from /dev/null and exactly the
// environment config gives it. Callers choose only the action and the
// values of its declared parameters.
package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"slices"
	"sort"
	"syscall"
	"time"

	"github.com/bpinto/foca/internal/action"
	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/plugin"
)

// Grace is how long a command has to exit after SIGTERM before its process
// group is killed.
const Grace = 2 * time.Second

// Provider serves the actions one instance is offered.
type Provider struct {
	actions map[string]*action.Spec
	// secrets is the instance's secret provider, so env_secrets resolve
	// in the instance's own vault, under its exposure rules.
	secrets plugin.Provider
	grace   time.Duration
}

// New offers specs, which config has checked, to one instance.
func New(specs []*action.Spec, secrets plugin.Provider) *Provider {
	p := &Provider{actions: map[string]*action.Spec{}, secrets: secrets, grace: Grace}
	for _, s := range specs {
		p.actions[s.ID] = s
	}
	return p
}

// WithGrace sets the grace after SIGTERM, for tests.
func (p *Provider) WithGrace(d time.Duration) *Provider {
	p.grace = d
	return p
}

func (p *Provider) Kind() string { return "action" }

func (p *Provider) List(context.Context) ([]plugin.Resource, error) {
	ids := make([]string, 0, len(p.actions))
	for id := range p.actions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]plugin.Resource, len(ids))
	for i, id := range ids {
		out[i] = resource(p.actions[id])
	}
	return out, nil
}

func resource(s *action.Spec) plugin.Resource {
	r := plugin.Resource{
		Ref:         plugin.ResourceRef{Kind: "action", ID: s.ID, Display: s.Display()},
		Description: s.Description,
	}
	for _, name := range s.ParamNames() {
		pa := s.Params[name]
		r.Params = append(r.Params, plugin.ParamInfo{Name: name, Description: pa.Description,
			Allowed: append([]string(nil), pa.Allowed...), Pattern: pa.Pattern, AllowLeadingDash: pa.AllowLeadingDash})
	}
	return r
}

// Resolve looks up actions, and the secrets they use with one lookup in
// the instance's vault. An action using a secret the instance can't read
// gets a *plugin.UseError, which matches plugin.ErrNotFound.
func (p *Provider) Resolve(ctx context.Context, ids []string) ([]plugin.Resource, []error, error) {
	rs := make([]plugin.Resource, len(ids))
	errs := make([]error, len(ids))
	var secretIDs []string
	for i, id := range ids {
		s := p.actions[id]
		if s == nil {
			errs[i] = plugin.ErrNotFound
			continue
		}
		rs[i] = resource(s)
		secretIDs = append(secretIDs, s.SecretIDs()...)
	}
	if len(secretIDs) == 0 {
		return rs, errs, nil
	}
	if p.secrets == nil {
		return nil, nil, errors.New("actions use secrets, but the instance has no secret provider")
	}
	srs, serrs, err := p.secrets.Resolve(ctx, secretIDs)
	if err != nil {
		return nil, nil, err
	}
	byID := map[string]int{}
	for j, id := range secretIDs {
		byID[id] = j
	}
	for i, id := range ids {
		if errs[i] != nil {
			continue
		}
		for _, sid := range p.actions[id].SecretIDs() {
			j := byID[sid]
			if serrs[j] != nil {
				errs[i] = &plugin.UseError{Secret: sid, Err: serrs[j]}
				break
			}
			rs[i].Uses = append(rs[i].Uses, srs[j].Ref)
		}
	}
	return rs, errs, nil
}

func (p *Provider) Validate(_ context.Context, r plugin.Resource, params map[string]string) (map[string]string, error) {
	s := p.actions[r.Ref.ID]
	if s == nil {
		return nil, plugin.ErrNotFound
	}
	return s.Validate(params)
}

// Serve runs the action with validated params. The secrets it uses are read
// only now, after approval, and live only for the life of the child.
func (p *Provider) Serve(ctx context.Context, r plugin.Resource, params map[string]string) (plugin.Result, error) {
	s := p.actions[r.Ref.ID]
	if s == nil {
		return plugin.Result{}, plugin.ErrNotFound
	}
	failed := func(reason string, err error) (plugin.Result, error) {
		return plugin.Result{Run: &plugin.RunInfo{ExitCode: -1}}, &plugin.RunError{Reason: reason, Err: err}
	}
	path, err := CheckCommand(s.Command)
	if err != nil {
		return failed(plugin.RunCommandUntrusted, err)
	}

	env := s.Environ()
	values := map[string][]byte{}
	defer func() {
		for _, v := range values {
			zero(v)
		}
	}()
	for _, id := range s.SecretIDs() {
		// Read each secret from the vault Resolve found it in.
		i := slices.IndexFunc(r.Uses, func(u plugin.ResourceRef) bool { return u.ID == id })
		if i < 0 {
			return failed(plugin.RunSecretUnreadable, fmt.Errorf("secret %s was not resolved: %w", id, plugin.ErrNotFound))
		}
		res, err := p.secrets.Serve(ctx, plugin.Resource{Ref: r.Uses[i]}, nil)
		if err != nil {
			return failed(plugin.RunSecretUnreadable, err)
		}
		values[id] = res.Value
	}
	vars := make([]string, 0, len(s.EnvSecrets))
	for k := range s.EnvSecrets {
		vars = append(vars, k)
	}
	sort.Strings(vars)
	for _, k := range vars {
		v := values[s.EnvSecrets[k]]
		for _, c := range v {
			if c == 0 {
				return failed(plugin.RunSecretUnreadable, fmt.Errorf("secret %s contains a NUL byte, which an environment variable can't hold", s.EnvSecrets[k]))
			}
		}
		// A Go string can't be zeroed; this copy lives until the GC takes
		// it (design §12.4).
		env = append(env, k+"="+string(v))
	}
	var masker *action.Masker
	if s.Mask {
		masker = action.NewMasker(values)
		defer masker.Zero()
	}
	return p.run(ctx, s, path, s.Argv(params), env, masker, len(values) > 0)
}

// CheckCommand checks the command like a helper (design §5): absolute,
// the file and every directory above it owned by root or the user and not
// writable by group or others, and executable. It returns the resolved
// path, which is what runs.
func CheckCommand(path string) (string, error) {
	resolved, err := fsutil.CheckTrustedFile(path)
	if err != nil {
		return "", fmt.Errorf("command not trusted: %w", err)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("command not trusted: %s is not executable", resolved)
	}
	return resolved, nil
}

var (
	errTimedOut = errors.New("timed out")
	errTooLarge = errors.New("output too large")
)

func (p *Provider) run(ctx context.Context, s *action.Spec, path string, argv, env []string, masker *action.Masker, usesSecrets bool) (plugin.Result, error) {
	cctx, cancelCause := context.WithCancelCause(ctx)
	defer cancelCause(nil)
	tctx, cancel := context.WithTimeoutCause(cctx, s.Timeout, errTimedOut)
	defer cancel()

	stdout := &capped{max: s.MaxBytes, over: func() { cancelCause(errTooLarge) }}
	defer stdout.zero()
	stderr := &tailBuf{keep: action.StderrTail + masker.Window()}
	if !usesSecrets {
		stderr.sum = sha256.New()
	}
	defer stderr.zero()

	cmd := exec.Command(path)
	cmd.Args = argv
	cmd.Env = env
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// A child left holding stdout or stderr after the command exits gets
	// this long before the pipes are closed.
	cmd.WaitDelay = p.grace

	info := &plugin.RunInfo{ExitCode: -1, Masked: masker.Active()}
	res := plugin.Result{Run: info}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return res, &plugin.RunError{Reason: plugin.RunStartFailed, Err: err}
	}
	// The group is signalled only before cmd.Wait reaps the command: until
	// then its id can't be reused, so a signal can't reach another group.
	pgid := cmd.Process.Pid
	exited := make(chan error, 1)
	go func() { exited <- waitExited(pgid) }()
	var waitErr error
	select {
	case waitErr = <-exited:
	case <-tctx.Done():
		syscall.Kill(-pgid, syscall.SIGTERM)
		grace := time.NewTimer(p.grace)
		select {
		case waitErr = <-exited:
		case <-grace.C:
			syscall.Kill(-pgid, syscall.SIGKILL)
			waitErr = <-exited
		}
		grace.Stop()
	}
	if tctx.Err() != nil || usesSecrets || waitErr != nil {
		// Whatever is left of the group goes with the command: children
		// that ignored SIGTERM or outlived it, and, for an action with
		// secrets, any that would keep them in their environment. Other
		// actions may leave a child running on purpose (a browser).
		syscall.Kill(-pgid, syscall.SIGKILL)
	}
	werr := cmd.Wait()
	info.Duration = time.Since(start)
	info.StdoutBytes, info.StderrBytes = stdout.n, stderr.n
	if stderr.sum != nil {
		info.StderrSHA256 = hex.EncodeToString(stderr.sum.Sum(nil))
	}
	if cmd.ProcessState != nil {
		info.ExitCode = cmd.ProcessState.ExitCode()
	}
	if masker.Active() {
		info.StderrTail = masker.MaskTail(stderr.buf, action.StderrTail)
		// Marks can be longer than what they replace. Every secret is
		// replaced by now, so cutting can only shorten a mark.
		if n := len(info.StderrTail); n > action.StderrTail {
			info.StderrTail = info.StderrTail[n-action.StderrTail:]
		}
	} else {
		info.StderrTail = append([]byte(nil), stderr.buf[max(0, len(stderr.buf)-action.StderrTail):]...)
	}

	switch cause := context.Cause(tctx); {
	case errors.Is(cause, errTimedOut):
		info.TimedOut = true
		return res, &plugin.RunError{Reason: plugin.RunTimeout, Err: fmt.Errorf("killed after %s", s.Timeout)}
	case errors.Is(cause, errTooLarge):
		return res, &plugin.RunError{Reason: plugin.RunOutputTooLarge, Err: fmt.Errorf("stdout passed %d bytes", s.MaxBytes)}
	case cause != nil:
		return res, &plugin.RunError{Reason: plugin.RunCancelled, Err: cause}
	}
	if waitErr != nil {
		return res, &plugin.RunError{Reason: plugin.RunStartFailed, Err: fmt.Errorf("waiting for the command: %w", waitErr)}
	}
	var exitErr *exec.ExitError
	if werr != nil && !errors.As(werr, &exitErr) && !errors.Is(werr, exec.ErrWaitDelay) {
		return res, &plugin.RunError{Reason: plugin.RunStartFailed, Err: werr}
	}

	if info.ExitCode != 0 && !s.ReturnOnFailure {
		return res, nil
	}
	out := masker.Mask(stdout.buf)
	if len(out) > action.MaxMaxBytes {
		// Masking a short secret can make the output grow past what one
		// protocol message carries.
		zero(out)
		return res, &plugin.RunError{Reason: plugin.RunOutputTooLarge, Err: fmt.Errorf("masked stdout passed %d bytes", action.MaxMaxBytes)}
	}
	if info.ExitCode == 0 {
		if err := action.ValidateOutput(s.Format, out); err != nil {
			zero(out)
			return res, &plugin.RunError{Reason: plugin.RunOutputInvalid, Err: fmt.Errorf("output is not %s: %v", s.Format, err)}
		}
	}
	res.Value = out
	info.StdoutReturned = true
	return res, nil
}

// capped keeps up to max bytes and calls over, once, when more arrive.
type capped struct {
	buf    []byte
	max    int
	n      int64
	over   func()
	passed bool
}

func (c *capped) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	room := c.max - len(c.buf)
	if len(p) > room {
		c.buf = append(c.buf, p[:max(room, 0)]...)
		if !c.passed {
			c.passed = true
			c.over()
		}
		return len(p), nil
	}
	c.buf = append(c.buf, p...)
	return len(p), nil
}

func (c *capped) zero() { zero(c.buf[:cap(c.buf)]) }

// tailBuf keeps the last keep bytes written, counts them all, and hashes
// them if sum is set.
type tailBuf struct {
	buf  []byte
	keep int
	n    int64
	sum  hash.Hash
}

func (t *tailBuf) Write(p []byte) (int, error) {
	t.n += int64(len(p))
	if t.sum != nil {
		t.sum.Write(p)
	}
	t.buf = append(t.buf, p...)
	if len(t.buf) > 2*t.keep {
		cut := len(t.buf) - t.keep
		zero(t.buf[:cut])
		t.buf = append(t.buf[:0], t.buf[cut:]...)
	}
	return len(p), nil
}

func (t *tailBuf) zero() { zero(t.buf[:cap(t.buf)]) }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
