//go:build linux

package server

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/bpinto/foca/internal/action"
	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/plugins/provider/command"
	"github.com/bpinto/foca/internal/protocol"
)

// startActions runs a server whose instance is offered two actions: hello
// (a param, uses github-pat) and slow (starts a child that outlives it,
// writing the child's pid to pidFile).
func startActions(t *testing.T, pidFile string) *env {
	t.Helper()
	dir := t.TempDir()
	sh := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700)
		return p
	}
	path := map[string]string{"PATH": os.Getenv("PATH")}
	specs := []*action.Spec{
		{ID: "hello", Description: "Say hello", Command: sh("hello", `echo "hello $1 $GH_TOKEN"; echo oops >&2; exit 2`),
			Args: []string{"{who}"}, Env: path, EnvSecrets: map[string]string{"GH_TOKEN": "dev:github-pat"}, Mask: true,
			ReturnOnFailure: true, Params: map[string]*action.Param{"who": {Pattern: "[a-z]+"}}},
		{ID: "slow", Command: sh("slow", `sleep 30 & echo $! > "$1"; wait`), Args: []string{pidFile}, Env: path},
	}
	for _, s := range specs {
		if err := s.Check(); err != nil {
			t.Fatal(err)
		}
	}
	e := startWith(t, hostRealm, nil, func(o *Options) {
		inst, _ := o.Core.Instance("dev")
		inst.Actions = command.New(specs, inst.Secrets)
	})
	e.auth.Default = fake.Approve
	return e
}

func TestActionsOverTheSocket(t *testing.T) {
	e := startActions(t, filepath.Join(t.TempDir(), "pid"))
	c := dial(t, e.paths.ClientSocket("dev"))

	var list protocol.ActionListResult
	if err := c.Call(ctx(t), protocol.MethodActionList, protocol.ActionListParams{}, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Actions) != 2 || list.Actions[0].Name != "hello" || list.Actions[0].Params[0].Pattern != "[a-z]+" {
		t.Fatalf("list %+v", list)
	}

	var res protocol.ActionRunResult
	err := c.Call(ctx(t), protocol.MethodActionRun, protocol.ActionRunParams{Name: "hello", Params: map[string]string{"who": "world"}}, &res)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 2 || res.Stdout != "hello world [hidden:dev:github-pat]\n" || res.StdoutEncoding != "utf8" || res.StderrTail != "oops\n" {
		t.Fatalf("run %+v", res)
	}

	// Unknown fields are refused by strict decoding, before the pipeline.
	raw := `{"jsonrpc":"2.0","id":9,"method":"action.run","params":{"name":"hello","params":{"who":"x"},"command":"/bin/sh"}}`
	if err := c.WriteRaw([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	line, _ := c.ReadRaw()
	if !strings.Contains(string(line), `"invalid_params"`) {
		t.Fatalf("got %s", line)
	}
	err = c.Call(ctx(t), protocol.MethodActionRun, protocol.ActionRunParams{Name: "hello", Params: map[string]string{"who": "-x"}}, nil)
	if pe := callErr(err); pe == nil || pe.Code != protocol.CodeParamRejected {
		t.Fatalf("param: %v", err)
	}

	runs := 0
	for _, ev := range e.sink.Events() {
		if ev.Type == audit.TypeActionRun && ev.Outcome == audit.OutcomeError && ev.Reason == "exit_status" {
			runs++
			if ev.Origin != audit.OriginClientSocket || ev.Peer == nil || ev.Run.ExitCode != 2 || ev.Uses[0].ID != "dev:github-pat" {
				t.Fatalf("run event %+v", ev)
			}
		}
	}
	if runs != 1 {
		t.Fatalf("%d run events", runs)
	}
}

// A client that hangs up while its action runs cancels it: the whole
// process group is killed, and the run is recorded as cancelled.
func TestHangUpDuringRunKillsTheGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	e := startActions(t, pidFile)
	c := dial(t, e.paths.ClientSocket("dev"))
	if err := c.WriteRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"action.run","params":{"name":"slow"}}`)); err != nil {
		t.Fatal(err)
	}
	var pid int
	waitFor(t, func() bool {
		b, _ := os.ReadFile(pidFile)
		pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		return pid > 0
	})
	c.Close()
	waitFor(t, func() bool {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		return err != nil || strings.Contains(string(b), ") Z ")
	})
	waitFor(t, func() bool {
		for _, ev := range e.sink.Events() {
			if ev.Type == audit.TypeActionRun && ev.Reason == "cancelled" && ev.Run != nil && ev.Run.ExitCode == -1 {
				return true
			}
		}
		return false
	})
}
