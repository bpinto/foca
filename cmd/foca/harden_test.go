//go:build foca_testing && linux

package main

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
)

// hidden reports whether another process of the same user is refused this
// process's memory and environment.
func hidden(pid int) bool {
	dir := "/proc/" + strconv.Itoa(pid)
	_, environ := os.ReadFile(dir + "/environ")
	_, mem := os.Open(dir + "/mem")
	return errors.Is(environ, fs.ErrPermission) && errors.Is(mem, fs.ErrPermission)
}

// The commands that hold vault keys or values, the service and the host
// commands, hide their memory from other processes of the same user, from
// before they read anything; reload and stop still reach the service.
func TestBinaryKeyHoldersHideTheirMemory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any process's memory")
	}
	p := setup(t)
	p.ok("", "init")

	add := p.cmd("", "add", "dev:github-pat")
	add.Stdin = nil
	value, err := add.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := add.Start(); err != nil {
		t.Fatal(err)
	}
	// add is waiting for its value on stdin, hidden already.
	waitFor(t, func() bool { return hidden(add.Process.Pid) })
	value.Write([]byte("ghp_123\n"))
	value.Close()
	if err := add.Wait(); err != nil {
		t.Fatalf("add: %v", err)
	}

	srv := p.serve()
	if !hidden(srv.Process.Pid) {
		t.Fatal("the service's memory is readable by another process of its user")
	}
	if out := p.ok("", "get", "dev:github-pat"); out != "ghp_123" {
		t.Fatalf("get: %q", out)
	}
	if _, errs, err := p.run("", "reload"); err != nil || !strings.Contains(errs, "reload requested") {
		t.Fatalf("reload of a hidden service: %v %s", err, errs)
	}
	waitFor(t, func() bool { return strings.Contains(p.auditTypes(), `"type":"config.reload","outcome":"ok"`) })
	if _, errs, err := p.run("", "stop"); err != nil || !strings.Contains(errs, "stopped") {
		t.Fatalf("stop of a hidden service: %v %s", err, errs)
	}
}
