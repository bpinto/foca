package client

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// DialOwn takes a socket served by this user, and refuses one served by
// anyone else before sending anything.
func TestDialOwnChecksTheServersUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan []byte, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			b, _ := io.ReadAll(c)
			c.Close()
			got <- b
		}
	}()

	c, err := DialOwn(context.Background(), path)
	if err != nil {
		t.Fatalf("own server refused: %v", err)
	}
	c.Close()
	<-got

	real := serverUID
	t.Cleanup(func() { serverUID = real })
	serverUID = func(net.Conn) (int, error) { return os.Getuid() + 1, nil }
	if _, err := DialOwn(context.Background(), path); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("another user's server accepted: %v", err)
	}
	if b := <-got; len(b) != 0 {
		t.Fatalf("sent %q to another user's server", b)
	}
}
