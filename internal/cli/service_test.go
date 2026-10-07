package cli

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/protocol"
)

// cannedService answers every request on a socket with what answer returns
// for its method, and returns the socket's path. It stands in for a service
// that sends whatever it likes.
func cannedService(t *testing.T, answer func(method string) (any, *protocol.Error)) string {
	t.Helper()
	// Under /tmp: macOS limits socket paths to 104 bytes.
	dir, err := os.MkdirTemp("/tmp", "foca")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); os.RemoveAll(dir) })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := protocol.ReadMessage(r)
					if err != nil {
						return
					}
					var req protocol.Request
					if json.Unmarshal(line, &req) != nil {
						return
					}
					res, perr := answer(req.Method)
					resp := protocol.Response{JSONRPC: "2.0", ID: req.ID, Error: perr}
					if perr == nil {
						resp.Result, _ = json.Marshal(res)
					}
					protocol.WriteMessage(c, resp)
				}
			}()
		}
	}()
	return sock
}

// An action's output may be credentials: like get, exec won't write it to
// a terminal. What the service sends for the terminal itself (the stderr
// tail, error messages, names) can't drive it.
func TestExecKeepsTheTerminalSafe(t *testing.T) {
	const creds = `{"AccessKeyId":"AKIA"}` + "\n"
	sock := cannedService(t, func(string) (any, *protocol.Error) {
		return protocol.ActionRunResult{Stdout: creds, StdoutEncoding: "utf8",
			StderrTail: "warn\x1b[2J\ttab\u009b\n\u202eend\r\n", StderrEncoding: "utf8"}, nil
	})
	env, out, errb := testEnv(t, nil)
	env.StdoutTTY = true
	if code := Main([]string{"exec", "--socket", sock, "aws-creds"}, env, "test"); code != 1 || out.Len() != 0 ||
		!strings.Contains(errb.String(), "refusing to write the action's output to a terminal") {
		t.Fatalf("to a terminal: exit %d, stdout %q, stderr %q", code, out, errb)
	}
	if !strings.HasPrefix(errb.String(), "warn[2J\ttab\nend\n") {
		t.Fatalf("stderr tail %q", errb)
	}
	// To a pipe, stdout passes unchanged.
	env, out, _ = testEnv(t, nil)
	if code := Main([]string{"exec", "--socket", sock, "aws-creds"}, env, "test"); code != 0 || out.String() != creds {
		t.Fatalf("to a pipe: exit %d, stdout %q", code, out)
	}

	// An action with no output runs from a terminal.
	sock = cannedService(t, func(string) (any, *protocol.Error) { return protocol.ActionRunResult{}, nil })
	env, _, errb = testEnv(t, nil)
	env.StdoutTTY = true
	if code := Main([]string{"exec", "--socket", sock, "notify"}, env, "test"); code != 0 {
		t.Fatalf("no output: exit %d: %s", code, errb)
	}

	// A service's error message is printed without its controls.
	sock = cannedService(t, func(string) (any, *protocol.Error) {
		return nil, protocol.NewError(protocol.CodeDenied, "no\x1b]0;pwned\x07\u202e")
	})
	env, _, errb = testEnv(t, nil)
	if code := Main([]string{"exec", "--socket", sock, "x"}, env, "test"); code != 1 || errb.String() != "foca: denied: no]0;pwned\n" {
		t.Fatalf("error: exit %d: %q", code, errb)
	}

	// So are the names list shows.
	sock = cannedService(t, func(string) (any, *protocol.Error) {
		return protocol.SecretListResult{Secrets: []protocol.SecretInfo{{Name: "v:a\x1b[1A\u202e", Description: "d\u009b"}}}, nil
	})
	env, out, _ = testEnv(t, nil)
	if code := Main([]string{"list", "--socket", sock}, env, "test"); code != 0 || !strings.Contains(out.String(), "v:a[1A  d\n") {
		t.Fatalf("list: exit %d: %q", code, out)
	}
}
