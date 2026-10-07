package core

import (
	"context"
	"errors"

	"github.com/bpinto/foca/internal/action"
	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/protocol"
)

// maxRunning bounds the actions one instance has in flight at once, from
// before their approval until their command exits. Reuse grants and the
// request rate already bound how often a realm can run an action; this bounds
// how many host processes it can hold at once.
const maxRunning = 4

// ---- action.list ----

func (s *Service) ListActions(ctx context.Context, c Call) ([]plugin.Resource, error) {
	if err := s.limit(ctx, c, protocol.MethodActionList); err != nil {
		return nil, err
	}
	var rs []plugin.Resource
	if c.Instance.Actions != nil {
		var err error
		if rs, err = c.Instance.Actions.List(ctx); err != nil {
			return nil, s.internal(ctx, c, audit.TypeActionList, "", err)
		}
	}
	e := s.Event(c, audit.TypeActionList, audit.OutcomeOK)
	e.Approval = &audit.Approval{Mode: audit.ModeNone}
	e.Count = len(rs)
	if _, aerr := s.recordCoalesced(ctx, c, e); aerr != nil {
		return nil, aerr
	}
	return rs, nil
}

// ---- action.run ----

// ActionOutput is what a run returns to the caller. Stdout is nil when it
// is withheld. The caller zeroes it with Zero.
type ActionOutput struct {
	ExitCode   int
	Stdout     []byte
	StderrTail []byte
}

func (o *ActionOutput) Zero() {
	zero(o.Stdout)
	zero(o.StderrTail)
	o.Stdout, o.StderrTail = nil, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// RunAction is the pipeline for one action: resolve it and the secrets it
// uses, check the caller's params, approve, run, and record the run before
// returning anything. Callers send a name and param values only; the
// command, its arguments and environment come from host config.
func (s *Service) RunAction(ctx context.Context, c Call, name string, params map[string]string) (*ActionOutput, error) {
	if err := s.limit(ctx, c, protocol.MethodActionRun); err != nil {
		return nil, err
	}
	if !action.ValidID(name) {
		return nil, s.fail(c, protocol.CodeInvalidParams, 0, "invalid action name %q", safeMethodName(name))
	}
	res := &audit.Resource{Kind: "action", ID: name}

	var r plugin.Resource
	var rerr error
	if c.Instance.Actions == nil {
		rerr = plugin.ErrNotFound
	} else {
		rs, errs, err := c.Instance.Actions.Resolve(ctx, []string{name})
		if err != nil {
			e := s.Event(c, audit.TypeActionRun, audit.OutcomeError)
			e.Resource = res
			return nil, s.internalEvent(ctx, c, e, err)
		}
		r, rerr = rs[0], errs[0]
	}
	var use *plugin.UseError
	switch {
	case errors.As(rerr, &use):
		// The action exists, but this instance can't read a secret it
		// uses; it can't run here.
		reason := "uses_unknown_secret"
		if errors.Is(use.Err, plugin.ErrNotExposed) {
			reason = "uses_unexposed_secret"
		}
		e := s.Event(c, audit.TypeActionRun, audit.OutcomeError)
		e.Resource, e.Reason = res, reason
		e.Uses = []audit.Resource{{Kind: "secret", ID: use.Secret}}
		seq, aerr := s.recordCoalesced(ctx, c, e)
		if aerr != nil {
			return nil, aerr
		}
		return nil, s.fail(c, protocol.CodeNotFound, seq, "action %s uses a secret this instance can't read", name)
	case errors.Is(rerr, plugin.ErrNotFound):
		e := s.Event(c, audit.TypeActionRun, audit.OutcomeNotFound)
		e.Resource, e.Reason = res, "unknown"
		seq, aerr := s.recordCoalesced(ctx, c, e)
		if aerr != nil {
			return nil, aerr
		}
		return nil, s.fail(c, protocol.CodeNotFound, seq, "action not found: %s", name)
	case rerr != nil:
		e := s.Event(c, audit.TypeActionRun, audit.OutcomeError)
		e.Resource = res
		return nil, s.internalEvent(ctx, c, e, rerr)
	}

	var vparams map[string]string
	if len(params) > action.MaxParams {
		rerr = &action.ParamError{Msg: "too many params"}
	} else {
		vparams, rerr = c.Instance.Actions.Validate(ctx, r, params)
	}
	if rerr != nil {
		// Rejected values are recorded only inside the quoted, shortened
		// message, never as params: they aren't trusted.
		e := s.Event(c, audit.TypeActionRun, audit.OutcomeRejected)
		e.Resource, e.Reason = res, "param_rejected"
		e.Error = &audit.ErrorInfo{Code: protocol.CodeName(protocol.CodeParamRejected), Message: rerr.Error()}
		seq, aerr := s.recordCoalesced(ctx, c, e)
		if aerr != nil {
			return nil, aerr
		}
		return nil, s.fail(c, protocol.CodeParamRejected, seq, "%s", rerr.Error())
	}

	if !s.startRun(c) {
		e := s.Event(c, audit.TypeRequestRejected, audit.OutcomeRejected)
		e.Resources = []audit.Resource{*res}
		e.Reason = "too_many_running"
		seq, err := s.RecordRejection(ctx, e)
		if err != nil {
			return nil, s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
		}
		return nil, s.fail(c, protocol.CodeBusy, seq, "too many actions running for this instance; try again")
	}
	defer s.endRun(c)

	approvals, err := s.approve(ctx, c, access{op: "action.run", accessType: audit.TypeActionRun, params: vparams}, []plugin.Resource{r})
	if err != nil {
		return nil, err
	}
	run := func(outcome string) *audit.Event {
		e := s.Event(c, audit.TypeActionRun, outcome)
		e.Resource = res
		e.Uses = refsToAudit(r.Uses)
		e.Params = copyParams(vparams)
		e.Approval = approvals[name]
		return e
	}
	if ctx.Err() != nil {
		// Approved, but the client is gone: nothing runs for it.
		e := run(audit.OutcomeError)
		e.Reason = "cancelled"
		if _, aerr := s.record(ctx, c, e); aerr != nil {
			return nil, aerr
		}
		return nil, s.fail(c, protocol.CodeTimeout, 0, "request cancelled")
	}

	out, err := c.Instance.Actions.Serve(ctx, r, vparams)
	defer zero(out.Value)
	e := run(audit.OutcomeOK)
	if out.Run != nil {
		e.Run = &audit.Run{ExitCode: out.Run.ExitCode, DurationMS: out.Run.Duration.Milliseconds(),
			StdoutBytes: out.Run.StdoutBytes, StdoutReturned: out.Run.StdoutReturned && err == nil,
			StderrBytes: out.Run.StderrBytes, StderrSHA256: out.Run.StderrSHA256,
			Masked: out.Run.Masked, TimedOut: out.Run.TimedOut}
		defer zero(out.Run.StderrTail)
	}
	if err == nil && out.Run == nil {
		err = errors.New("the provider returned no run")
	}
	if err != nil {
		return nil, s.runFailed(ctx, c, e, err)
	}
	if out.Run.ExitCode != 0 {
		e.Outcome, e.Reason = audit.OutcomeError, "exit_status"
	}
	stdout := out.Value
	if !out.Run.StdoutReturned {
		stdout = nil // withheld: not in the answer
	} else if stdout == nil {
		stdout = []byte{}
	}
	if protocol.ActionRunLen(out.Run.ExitCode, stdout, out.Run.StderrTail) > protocol.MaxResult {
		// The client could never read the answer: nothing is returned,
		// and the run is recorded as such.
		e.Outcome, e.Reason = audit.OutcomeError, "response_too_large"
		e.Run.StdoutReturned = false
		seq, aerr := s.record(ctx, c, e)
		if aerr != nil {
			return nil, aerr
		}
		return nil, s.fail(c, protocol.CodeInternal, seq, "the action's output doesn't fit in one answer (%d bytes)", protocol.MaxMessage)
	}
	// Record the run before returning anything from it.
	if _, aerr := s.record(ctx, c, e); aerr != nil {
		return nil, aerr
	}
	o := &ActionOutput{ExitCode: out.Run.ExitCode, StderrTail: append([]byte(nil), out.Run.StderrTail...)}
	if out.Run.StdoutReturned {
		o.Stdout = append([]byte{}, out.Value...)
	}
	return o, nil
}

// runFailed records a run that failed or whose result can't be returned,
// and answers with what the caller may know about it.
func (s *Service) runFailed(ctx context.Context, c Call, e *audit.Event, err error) error {
	e.Outcome = audit.OutcomeError
	code, msg := protocol.CodeInternal, "the action failed on the host"
	var re *plugin.RunError
	if errors.As(err, &re) {
		e.Reason = re.Reason
		switch re.Reason {
		case plugin.RunTimeout:
			code, msg = protocol.CodeTimeout, "the action timed out"
		case plugin.RunCancelled:
			code, msg = protocol.CodeTimeout, "request cancelled"
		case plugin.RunOutputTooLarge:
			msg = "the action's output was larger than allowed"
		case plugin.RunOutputInvalid:
			msg = "the action's output failed its format check"
		case plugin.RunCommandUntrusted:
			msg = "the action's command is not trusted on the host"
		case plugin.RunStartFailed:
			msg = "the action's command could not run"
		case plugin.RunSecretUnreadable:
			msg = "the action could not read a secret it uses"
		}
	}
	if errors.Is(err, plugin.ErrNotInitialized) {
		code, msg = protocol.CodeNotInitialized, notInitialized(err)
	}
	e.Error = &audit.ErrorInfo{Code: protocol.CodeName(code), Message: err.Error()}
	seq, aerr := s.record(ctx, c, e)
	if aerr != nil {
		return aerr
	}
	return s.fail(c, code, seq, "%s", msg)
}

func (s *Service) startRun(c Call) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[c.Instance.Name] >= maxRunning {
		return false
	}
	s.running[c.Instance.Name]++
	return true
}

func (s *Service) endRun(c Call) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running[c.Instance.Name]--
}

// safeMethodName bounds a caller-supplied name before it is echoed.
func safeMethodName(n string) string {
	b := []byte(n)
	if len(b) > 64 {
		b = b[:64]
	}
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			b[i] = '?'
		}
	}
	return string(b)
}
