package helper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/protocol"
)

// Events runs the helper's long-lived events kind (macOS sleep, screen lock
// and session end).
//
// After start-up it reads one line, {"v":1,"op":"subscribe","params":{}},
// then writes one JSON object per line:
//
//	{"v":1,"seq":1,"event":"ready"}
//	{"v":1,"seq":2,"event":"sleep"}
//
// A sleep is acknowledged with {"v":1,"op":"ack","params":{"seq":2}} once
// the core has handled it (grants wiped, lock recorded), or after
// plugin.HandledWait, and the helper lets the machine sleep only then (or
// after its own 5 s limit). The helper exits when its stdin closes or it
// gets SIGTERM. Anything unexpected on stdout ends Run with an error, so the
// core wipes and turns reuse off until the source is back.
type Events struct {
	h    *Helper
	name string
	// handledWait bounds the wait for the core before a sleep is acked;
	// zero means plugin.HandledWait. Tests shorten it.
	handledWait time.Duration
}

func NewEvents(h *Helper, name string) *Events { return &Events{h: h, name: name} }

func (e *Events) waitForCore() time.Duration {
	if e.handledWait > 0 {
		return e.handledWait
	}
	return plugin.HandledWait
}

func (e *Events) Name() string { return e.name }

const maxEventLine = 4 << 10

type eventLine struct {
	V     int    `json:"v"`
	Seq   uint64 `json:"seq"`
	Event string `json:"event"`
}

type ackParams struct {
	Seq uint64 `json:"seq"`
}

var eventKinds = map[string]plugin.EventKind{
	string(plugin.EventReady):      plugin.EventReady,
	string(plugin.EventSleep):      plugin.EventSleep,
	string(plugin.EventScreenLock): plugin.EventScreenLock,
	string(plugin.EventSessionEnd): plugin.EventSessionEnd,
}

func (e *Events) Run(ctx context.Context, out chan<- plugin.PlatformEvent) error {
	// Not CommandContext: the stop sequence below must also run while
	// we're still reading, before Wait.
	cmd, err := e.h.command(context.Background(), KindEvents)
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr := &capped{max: maxStderr}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s events: %w", e.name, err)
	}

	// stop closes stdin, then sends SIGTERM, then SIGKILL after the grace
	// period. Killing closes stdout, which ends the read loop.
	var once sync.Once
	stop := func() {
		once.Do(func() {
			stdin.Close()
			cmd.Process.Signal(syscall.SIGTERM)
			time.AfterFunc(e.h.cfg.Grace, func() { cmd.Process.Kill() })
		})
	}
	unhook := context.AfterFunc(ctx, stop)
	defer unhook()

	runErr := e.read(ctx, stdin, stdout, out)
	stop()
	io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if runErr == nil {
		runErr = fmt.Errorf("%s events: helper exited (%v)%s", e.name, waitErr, tail(stderr))
	}
	return runErr
}

func (e *Events) read(ctx context.Context, stdin io.Writer, stdout io.Reader, out chan<- plugin.PlatformEvent) error {
	write := func(op string, params any) error {
		b, err := json.Marshal(request{V: Protocol, Op: op, Params: params})
		if err != nil {
			return err
		}
		_, err = stdin.Write(append(b, '\n'))
		return err
	}
	if err := write("subscribe", struct{}{}); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("%s events: subscribe: %w", e.name, err)
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 512), maxEventLine)
	var last uint64
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		ev, err := parseEvent(line)
		if err != nil {
			return fmt.Errorf("%s events: %w", e.name, err)
		}
		if ev.Seq <= last {
			return fmt.Errorf("%s events: seq %d after %d", e.name, ev.Seq, last)
		}
		last = ev.Seq
		kind := eventKinds[ev.Event]
		pe := plugin.PlatformEvent{Kind: kind, At: time.Now(), Source: e.name, Done: make(chan struct{})}
		select {
		case out <- pe:
		case <-ctx.Done():
			return nil
		}
		if kind == plugin.EventSleep {
			// The machine waits for the ack, so it sleeps only once the
			// core has wiped. A failed write shows up as the helper
			// exiting.
			pe.WaitHandled(ctx, e.waitForCore())
			write("ack", ackParams{Seq: ev.Seq})
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s events: %w", e.name, err)
	}
	return nil
}

func parseEvent(line []byte) (eventLine, error) {
	if err := protocol.CheckStrict(line, reflect.TypeOf(eventLine{})); err != nil {
		return eventLine{}, fmt.Errorf("malformed event: %w", err)
	}
	var ev eventLine
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return eventLine{}, fmt.Errorf("malformed event: %w", err)
	}
	if ev.V != Protocol {
		return eventLine{}, fmt.Errorf("protocol version %d, want %d", ev.V, Protocol)
	}
	if _, ok := eventKinds[ev.Event]; !ok {
		return eventLine{}, errors.New("unknown event " + fmt.Sprintf("%q", clean(ev.Event)))
	}
	return ev, nil
}
