package cli

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/bpinto/foca/internal/protocol"
)

// exitStatus ends the CLI with a code and no message: the action's own exit
// code, which `foca exec` passes on.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// ---- exec ----

type ExecCmd struct {
	Action string   `arg:"" help:"Action to run, as the host config names it."`
	Param  []string `short:"p" help:"name=value for one of the action's params. Repeatable." placeholder:"NAME=VALUE"`
}

// Run asks the service to run a host-declared action and passes its output
// on: stdout to stdout, the end of stderr to stderr, and its exit code.
// Only the action's name and param values are sent; the command and its
// arguments come from host config (design §11).
func (c *ExecCmd) Run(g *Globals, e *Env) error {
	params := map[string]string{}
	for _, kv := range c.Param {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return fmt.Errorf("%q: write --param name=value", kv)
		}
		if _, dup := params[k]; dup {
			return fmt.Errorf("param %s is given twice", k)
		}
		params[k] = v
	}
	cl, err := g.dial(e)
	if err != nil {
		return err
	}
	defer cl.Close()
	var res protocol.ActionRunResult
	err = cl.Call(background(), protocol.MethodActionRun,
		protocol.ActionRunParams{Common: protocol.Common{Client: reported()}, Name: c.Action, Params: params}, &res)
	if err != nil {
		return err
	}
	if res.StderrTail != "" {
		b, err := protocol.DecodeValue(res.StderrTail, res.StderrEncoding)
		if err != nil {
			return fmt.Errorf("stderr: %w", err)
		}
		// The command's own output: it mustn't drive the terminal.
		fmt.Fprint(e.Stderr, cleanLines(string(b)))
	}
	if res.StdoutEncoding != "" {
		b, err := protocol.DecodeValue(res.Stdout, res.StdoutEncoding)
		if err != nil {
			return fmt.Errorf("stdout: %w", err)
		}
		defer zero(b)
		// Like get: what an action prints may be credentials, which
		// don't belong in a terminal's scrollback.
		if len(b) > 0 && e.StdoutTTY {
			return errors.New("refusing to write the action's output to a terminal: redirect stdout to a pipe or file")
		}
		if _, err := e.Stdout.Write(b); err != nil {
			return err
		}
	}
	if res.ExitCode != 0 {
		if res.ExitCode < 0 || res.ExitCode > 255 {
			return exitStatus(1)
		}
		return exitStatus(res.ExitCode)
	}
	return nil
}

// ---- actions ----

type ActionsCmd struct{}

func (ActionsCmd) Run(g *Globals, e *Env) error {
	cl, err := g.dial(e)
	if err != nil {
		return err
	}
	defer cl.Close()
	var res protocol.ActionListResult
	if err := cl.Call(background(), protocol.MethodActionList, protocol.ActionListParams{Common: protocol.Common{Client: reported()}}, &res); err != nil {
		return err
	}
	if len(res.Actions) == 0 {
		fmt.Fprintln(e.Stderr, "no actions offered here")
		return nil
	}
	w := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDESCRIPTION\tPARAMS")
	for _, a := range res.Actions {
		var ps []string
		for _, p := range a.Params {
			ps = append(ps, paramSummary(p))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", clean(a.Name), clean(a.Description), clean(strings.Join(ps, " ")))
	}
	return w.Flush()
}

// paramSummary is name=<one of the allowed values> or name=/pattern/.
func paramSummary(p protocol.ParamSchema) string {
	switch {
	case len(p.Allowed) > 0:
		return p.Name + "=" + strings.Join(p.Allowed, "|")
	case p.Pattern != "":
		return p.Name + "=/" + p.Pattern + "/"
	}
	return p.Name
}

// asExit reports the code of an exitStatus error.
func asExit(err error) (int, bool) {
	var s exitStatus
	if errors.As(err, &s) {
		return int(s), true
	}
	return 0, false
}
