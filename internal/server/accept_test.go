package server

import (
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// failingListener fails every accept, as a listener does once the process
// is out of file descriptors.
type failingListener struct{ calls atomic.Int64 }

func (f *failingListener) AcceptUnix() (*net.UnixConn, error) {
	f.calls.Add(1)
	return nil, syscall.EMFILE
}

// A failing accept is retried after a growing pause, not at once: retrying
// at once would spin a CPU for as long as the error lasts.
func TestFailingAcceptBacksOff(t *testing.T) {
	s := New(Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	l := &failingListener{}
	s.wg.Add(1)
	go s.acceptLoop(l, nil)
	time.Sleep(200 * time.Millisecond)
	s.cancel()
	s.wg.Wait()
	// 5 + 10 + 20 + 40 + 80 ms: six tries fit in 200 ms.
	if n := l.calls.Load(); n < 2 || n > 7 {
		t.Fatalf("%d accepts in 200ms", n)
	}
}
