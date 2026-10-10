// Package client talks to a foca socket. It is used by the CLI, by tests
// and later by the relay, and must never import service-side packages.
package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/bpinto/foca/internal/protocol"
)

type Client struct {
	// wmu orders writes and rmu reads, so one goroutine may wait for
	// answers while another sends (the guest relay). Call takes both.
	wmu, rmu sync.Mutex
	conn     net.Conn
	r        *bufio.Reader
	next     int
}

func Dial(ctx context.Context, path string) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, r: bufio.NewReaderSize(conn, 64*1024)}, nil
}

// DialOwn is Dial for a socket the caller found in its own runtime
// directory. It also checks, from the kernel, that the server runs as the
// same user, so a socket someone else left there is refused before anything
// is sent or read.
func DialOwn(ctx context.Context, path string) (*Client, error) {
	c, err := Dial(ctx, path)
	if err != nil {
		return nil, err
	}
	uid, err := serverUID(c.conn)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("%s: cannot tell who serves it: %w", path, err)
	}
	if uid != os.Getuid() {
		c.Close()
		return nil, fmt.Errorf("%s is served by uid %d, not by you (uid %d): refusing it", path, uid, os.Getuid())
	}
	return c, nil
}

func (c *Client) Close() error { return c.conn.Close() }

// ErrHungUp is a connection closed before its answer. The service closes a
// connection it refuses without saying why (design §6.2); the reason is in
// its audit log.
var ErrHungUp = errors.New("the service closed the connection without answering")

// Call sends one request and waits for its response. A JSON-RPC error is
// returned as *protocol.Error.
func (c *Client) Call(ctx context.Context, method string, params, result any) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.rmu.Lock()
	defer c.rmu.Unlock()
	c.next++
	id := json.RawMessage(strconv.Itoa(c.next))
	var raw json.RawMessage
	if params != nil {
		b, err := protocol.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	if dl, ok := ctx.Deadline(); ok {
		c.conn.SetDeadline(dl)
	} else {
		c.conn.SetDeadline(time.Time{})
	}
	stop := context.AfterFunc(ctx, func() { c.conn.SetDeadline(time.Now()) })
	defer stop()

	if err := protocol.WriteMessage(c.conn, protocol.Request{JSONRPC: "2.0", ID: id, Method: method, Params: raw}); err != nil {
		// A refused connection may be closed before the request is sent.
		if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
			return ErrHungUp
		}
		return err
	}
	line, err := protocol.ReadMessage(c.r)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) {
			return ErrHungUp
		}
		return err
	}
	var resp protocol.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("bad response: %w", err)
	}
	if string(resp.ID) != string(id) {
		return fmt.Errorf("response id %s does not match request %s", resp.ID, id)
	}
	if resp.Error != nil {
		return resp.Error
	}
	if result != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, result)
	}
	return nil
}

// WriteRaw sends raw bytes followed by a newline. Tests use it to send
// malformed input.
func (c *Client) WriteRaw(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.conn.Write(append(append([]byte(nil), b...), '\n'))
	return err
}

// ReadRaw reads one raw response line.
func (c *Client) ReadRaw() ([]byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return protocol.ReadMessage(c.r)
}

// SetDeadline sets the connection's deadline for WriteRaw and ReadRaw. Call
// sets its own. A net.Conn takes deadlines from any goroutine.
func (c *Client) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
