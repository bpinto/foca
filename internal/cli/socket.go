package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/bpinto/foca/internal/client"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/format"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/protocol"
	"github.com/bpinto/foca/internal/secretname"
)

// socketPath finds the client socket: --socket, FOCA_SOCK, the socket of
// --instance / FOCA_INSTANCE, ~/.foca.sock if it exists (the forwarded
// socket inside a realm), else the only instance in the host config.
func (g *Globals) socketPath(e *Env) (string, error) {
	path, _, err := g.findSocket(e)
	return path, err
}

// findSocket is socketPath, plus whether the path was derived from the
// runtime directory rather than given or forwarded. Such a socket must be
// served by this user (see dial).
func (g *Globals) findSocket(e *Env) (path string, derived bool, err error) {
	if g.Socket != "" {
		return g.Socket, false, nil
	}
	if s := e.Getenv("FOCA_SOCK"); s != "" {
		return s, false, nil
	}
	paths, err := g.paths(e)
	if inst := g.instanceName(e); inst != "" {
		if err != nil {
			return "", false, err
		}
		if !config.ValidName(inst) {
			return "", false, fmt.Errorf("invalid instance name %q", inst)
		}
		return paths.ClientSocket(inst), true, nil
	}
	if home := e.Getenv("HOME"); home != "" {
		if s := filepath.Join(home, ".foca.sock"); exists(s) {
			return s, false, nil
		}
	}
	if err != nil {
		return "", false, fmt.Errorf("no socket found: set FOCA_SOCK or pass --socket (%v)", err)
	}
	cfg, err := config.Load(paths.Config)
	if err != nil {
		return "", false, fmt.Errorf("no socket found: set FOCA_SOCK or pass --socket (%v)", err)
	}
	if len(cfg.Instances) != 1 {
		names := make([]string, len(cfg.Instances))
		for i, inst := range cfg.Instances {
			names[i] = inst.Name
		}
		return "", false, fmt.Errorf("the config has several instances (%s): pass --instance", strings.Join(names, ", "))
	}
	return paths.ClientSocket(cfg.Instances[0].Name), true, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dial connects to the client socket. A socket found in the runtime
// directory must be served by this user: if that directory was shared or
// prepared by someone else, their socket is refused before anything is sent
// or received. A socket given by --socket or FOCA_SOCK, or forwarded into a
// realm, is taken as is.
func (g *Globals) dial(e *Env) (*client.Client, error) {
	path, derived, err := g.findSocket(e)
	if err != nil {
		return nil, err
	}
	dial := client.Dial
	if derived {
		dial = client.DialOwn
	}
	c, err := dial(background(), path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "connection refused") {
			return nil, fmt.Errorf("service not running (no socket at %s)", path)
		}
		return nil, err
	}
	return c, nil
}

// reported is what the CLI says about itself. The service never trusts it;
// prompts label it as a claim (design §8.3).
func reported() *identity.ClientInfo {
	exe, _ := os.Executable()
	host, _ := os.Hostname()
	return &identity.ClientInfo{
		PID: os.Getpid(), PPID: os.Getppid(), UID: os.Getuid(), Exe: exe, Name: filepath.Base(exe),
		Hostname: host, Tool: "foca", Parents: parents(os.Getppid()),
	}
}

// readSecrets fetches names in one request, so one approval covers them all.
// target, for run, is the command that will get the values.
func (g *Globals) readSecrets(e *Env, names []string, target *identity.Target) ([]format.Secret, error) {
	c, err := g.dial(e)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	cl := reported()
	cl.Target = target
	var res protocol.SecretReadResult
	err = c.Call(background(), protocol.MethodSecretRead,
		protocol.SecretReadParams{Common: protocol.Common{Client: cl}, Names: names}, &res)
	if err != nil {
		return nil, err
	}
	return collectSecrets(names, res.Secrets)
}

// decodeValue is protocol.DecodeValue; tests see the values it makes.
var decodeValue = protocol.DecodeValue

// collectSecrets decodes the values the service sent, in the order of
// names. Every decoded value it doesn't return, because it wasn't asked
// for or the answer is refused, is zeroed first.
func collectSecrets(names []string, got []protocol.SecretOut) ([]format.Secret, error) {
	byName := map[string][]byte{}
	drop := func() {
		for _, v := range byName {
			zero(v)
		}
	}
	for _, s := range got {
		if _, dup := byName[s.Name]; dup {
			drop()
			return nil, fmt.Errorf("the service returned %s twice", s.Name)
		}
		v, err := decodeValue(s.Value, s.Encoding)
		if err != nil {
			drop()
			return nil, fmt.Errorf("secret %s: %w", s.Name, err)
		}
		byName[s.Name] = v
	}
	out := make([]format.Secret, len(names))
	for i, n := range names {
		v, ok := byName[n]
		if !ok {
			drop()
			return nil, fmt.Errorf("the service did not return %s", n)
		}
		out[i] = format.Secret{Name: n, Value: v}
	}
	for n, v := range byName {
		if !slices.Contains(names, n) {
			zero(v)
		}
	}
	return out, nil
}

func zeroSecrets(ss []format.Secret) {
	for _, s := range ss {
		zero(s.Value)
	}
}

// ---- list ----

type ListCmd struct{}

func (ListCmd) Run(g *Globals, e *Env) error {
	c, err := g.dial(e)
	if err != nil {
		return err
	}
	defer c.Close()
	var res protocol.SecretListResult
	if err := c.Call(background(), protocol.MethodSecretList, protocol.SecretListParams{Common: protocol.Common{Client: reported()}}, &res); err != nil {
		return err
	}
	if len(res.Secrets) == 0 {
		fmt.Fprintln(e.Stderr, "no secrets visible here")
		return nil
	}
	w := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDESCRIPTION")
	for _, s := range res.Secrets {
		desc := s.Description
		if s.DisplayName != "" {
			desc = strings.TrimSpace(s.DisplayName + ": " + desc)
		}
		fmt.Fprintf(w, "%s\t%s\n", s.Name, clean(desc))
	}
	return w.Flush()
}

// clean keeps service-supplied text from moving the terminal cursor or
// breaking the table.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

// ---- get ----

type GetCmd struct {
	Names  []string `arg:"" help:"Secrets to read. With --format env, write VAR=name to choose the variable."`
	Format string   `short:"f" enum:"raw,json,env" default:"raw" help:"Output format: raw (one value, as stored), json or env."`
	Output string   `short:"o" help:"Write to this file (made 0600) instead of stdout." placeholder:"FILE"`
}

func (c *GetCmd) Run(g *Globals, e *Env) error {
	names := make([]string, len(c.Names))
	vars := make([]string, len(c.Names))
	seen := map[string]bool{}
	for i, arg := range c.Names {
		v, n, explicit := strings.Cut(arg, "=")
		if !explicit {
			n, v = arg, format.EnvVar(arg)
		} else if c.Format != "env" {
			return fmt.Errorf("%q: VAR=name only applies to --format env", arg)
		}
		if _, _, ok := secretname.Split(n); !ok {
			return fmt.Errorf("invalid secret name %q: name secrets <vault>:<secret>", n)
		}
		if c.Format == "env" && !format.ValidEnvVar(v) {
			return fmt.Errorf("%q is not a valid variable name; write VAR=%s", v, n)
		}
		if c.Format == "env" && seen[v] {
			return fmt.Errorf("variable %s is set twice", v)
		}
		seen[v] = true
		names[i], vars[i] = n, v
	}
	if c.Format == "raw" && len(names) != 1 {
		return errors.New("raw output takes exactly one secret; use --format json or env for several")
	}
	// Refuse before asking anyone to approve anything.
	if c.Output == "" && e.StdoutTTY {
		return errors.New("refusing to write a secret to a terminal: redirect stdout to a pipe or file, or use --output FILE")
	}
	if c.Output != "" {
		if err := checkOutput(c.Output); err != nil {
			return err
		}
	}
	// A shell redirect creates the file under the umask, often 0644. The
	// user chose the file, so this warns rather than refuses.
	if f, ok := e.Stdout.(*os.File); ok && c.Output == "" {
		if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(e.Stderr, "foca: warning: stdout is a file others may read (mode %04o); use --output FILE, or umask 077 before redirecting\n", fi.Mode().Perm())
		}
	}

	secrets, err := g.readSecrets(e, names, nil)
	if err != nil {
		return err
	}
	defer zeroSecrets(secrets)
	var buf bytes.Buffer
	defer func() { zero(buf.Bytes()) }()
	switch c.Format {
	case "raw":
		err = format.Raw(&buf, secrets[0])
	case "json":
		err = format.JSON(&buf, secrets)
	case "env":
		err = format.Env(&buf, secrets, vars)
	}
	if err != nil {
		return err
	}
	if c.Output == "" {
		_, err = e.Stdout.Write(buf.Bytes())
		return err
	}
	return writeOutput(c.Output, buf.Bytes())
}

// ---- run ----

type RunCmd struct {
	Env     []string `short:"e" required:"" help:"VAR=name puts secret name in VAR; a bare name uses its upper-cased name (common:github-pat → GITHUB_PAT). Repeatable." placeholder:"VAR=NAME"`
	Command []string `arg:"" passthrough:"" help:"Command to run, after --."`
}

func (c *RunCmd) Run(g *Globals, e *Env) error {
	argv := c.Command
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}
	if len(argv) == 0 {
		return errors.New("no command given: foca run -e VAR=name -- command [args]")
	}
	var names, vars []string
	seen := map[string]bool{}
	for _, arg := range c.Env {
		v, n, explicit := strings.Cut(arg, "=")
		if !explicit {
			n, v = arg, format.EnvVar(arg)
		}
		if _, _, ok := secretname.Split(n); !ok {
			return fmt.Errorf("invalid secret name %q: name secrets <vault>:<secret>", n)
		}
		if !format.ValidEnvVar(v) {
			return fmt.Errorf("%q is not a valid variable name; write VAR=%s", v, n)
		}
		if seen[v] {
			return fmt.Errorf("variable %s is set twice", v)
		}
		seen[v] = true
		names, vars = append(names, n), append(vars, v)
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	// The prompt names the command, as a claim: only its path and name
	// are sent, never its arguments.
	target := &identity.Target{Exe: path, Argv0: filepath.Base(argv[0])}
	if abs, err := filepath.Abs(path); err == nil {
		target.Exe = abs
	}
	secrets, err := g.readSecrets(e, names, target)
	if err != nil {
		return err
	}
	defer zeroSecrets(secrets)
	env := make([]string, 0, len(os.Environ())+len(vars))
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !seen[k] {
			env = append(env, kv)
		}
	}
	for i, s := range secrets {
		if bytes.IndexByte(s.Value, 0) >= 0 {
			return fmt.Errorf("secret %s contains a NUL byte, which an environment variable can't hold", s.Name)
		}
		env = append(env, vars[i]+"="+string(s.Value))
	}
	return e.Exec(path, argv, env)
}
