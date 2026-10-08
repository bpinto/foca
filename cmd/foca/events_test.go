//go:build foca_testing && linux

package main

import (
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// lockedBuffer is a child's stdout, read while it runs.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// events follow, as its own process, sees the stored events and then what
// the service records live, and exits 0 on SIGINT.
func TestBinaryEventsFollow(t *testing.T) {
	p := setup(t)
	p.ok("", "init")
	p.ok("ghp_123\n", "add", "dev:github-pat")
	p.serve()

	follow := p.cmd("", "events", "follow", "--from-seq", "1", "--type", "vault.init", "--type", "secret.read")
	var out lockedBuffer
	follow.Stdout = &out
	if err := follow.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { follow.Process.Kill(); follow.Wait() })
	waitFor(t, func() bool { return strings.Contains(out.String(), `"type":"vault.init"`) })
	p.ok("", "get", "dev:github-pat")
	waitFor(t, func() bool { return strings.Contains(out.String(), `"type":"secret.read"`) })

	follow.Process.Signal(syscall.SIGINT)
	done := make(chan error, 1)
	go func() { done <- follow.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("follow exited with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow still running after SIGINT")
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 2 {
		t.Fatalf("followed %d events: %s", len(lines), out.String())
	}

	q := p.ok("", "events", "query", "--limit", "1")
	if lines := strings.Split(strings.TrimSpace(q), "\n"); len(lines) != 2 || !strings.HasPrefix(lines[1], `{"next_after_seq":1}`) {
		t.Fatalf("query: %s", q)
	}
}
