package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/alecthomas/kong"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/secretname"
)

// ---- events (design §8.5) ----

type EventsCmd struct {
	Query  EventsQueryCmd  `cmd:"" help:"Print the audit events that match, oldest first, as JSON lines."`
	Follow EventsFollowCmd `cmd:"" help:"Print audit events as they are recorded, as JSON lines, until interrupted."`
}

// EventFilter is the filter flags query and follow share. The global
// --instance flag picks the instance; FOCA_INSTANCE doesn't, so a variable
// left set in a shell can't hide events.
type EventFilter struct {
	Since    string   `help:"Only events at or after TIME: RFC 3339, or a duration ago such as 90m." placeholder:"TIME"`
	Until    string   `help:"Only events before TIME: RFC 3339, or a duration ago." placeholder:"TIME"`
	Type     []string `help:"Only events of this type; repeat for more." placeholder:"TYPE"`
	Resource string   `help:"Only events about this secret or action." placeholder:"KIND:ID"`
	Outcome  string   `help:"Only events with this outcome: ok, denied, error, not_found or rejected."`
	Mode     string   `help:"Only events with this approval mode: fresh, reused or none."`

	filter audit.Filter
}

type EventsQueryCmd struct {
	EventFilter
	AfterSeq uint64 `help:"Only events after seq N, to read the next page." placeholder:"N"`
	Limit    int    `default:"100" help:"Print at most N events (1-500). When more match, a last line {\"next_after_seq\": N} says where to go on." placeholder:"N"`
}

type EventsFollowCmd struct {
	EventFilter
	FromSeq *uint64 `help:"First print the stored events from seq N on, then new ones. Without it, only new ones." placeholder:"N"`
}

func (c *EventsQueryCmd) Validate(kctx *kong.Context) error {
	if c.Limit < 1 || c.Limit > audit.MaxPageLimit {
		return fmt.Errorf("--limit %d is outside 1..%d", c.Limit, audit.MaxPageLimit)
	}
	return c.parse(kctx, time.Now())
}

func (c *EventsFollowCmd) Validate(kctx *kong.Context) error {
	return c.parse(kctx, time.Now())
}

// parse checks every filter flag, so a typo is a usage error instead of a
// filter that silently matches nothing.
func (c *EventFilter) parse(kctx *kong.Context, now time.Time) error {
	var f audit.Filter
	var err error
	if f.Since, err = parseWhen("--since", c.Since, now); err != nil {
		return err
	}
	if f.Until, err = parseWhen("--until", c.Until, now); err != nil {
		return err
	}
	if !f.Since.IsZero() && !f.Until.IsZero() && !f.Since.Before(f.Until) {
		return fmt.Errorf("--since %s is not before --until %s", c.Since, c.Until)
	}
	for _, t := range c.Type {
		if !slices.Contains(audit.Types, t) {
			return fmt.Errorf("--type %q is not an event type (%s)", t, strings.Join(audit.Types, ", "))
		}
	}
	f.Types = c.Type
	if c.Resource != "" {
		kind, id, _ := strings.Cut(c.Resource, ":")
		_, _, secret := secretname.Split(id)
		if !(kind == audit.KindSecret && secret || kind == audit.KindAction && config.ValidSecretID(id)) {
			return fmt.Errorf("--resource %q is not secret:<vault>:<secret> or action:<name>", c.Resource)
		}
		f.Resource = &audit.Resource{Kind: kind, ID: id}
	}
	if c.Outcome != "" && !slices.Contains(audit.Outcomes, c.Outcome) {
		return fmt.Errorf("--outcome %q is not one of %s", c.Outcome, strings.Join(audit.Outcomes, ", "))
	}
	f.Outcome = c.Outcome
	if c.Mode != "" && !slices.Contains(audit.Modes, c.Mode) {
		return fmt.Errorf("--mode %q is not one of %s", c.Mode, strings.Join(audit.Modes, ", "))
	}
	f.Mode = c.Mode
	for _, fl := range kctx.Flags() {
		if fl.Name == "instance" {
			f.Instance, _ = kctx.FlagValue(fl).(string)
		}
	}
	if f.Instance != "" && !config.ValidName(f.Instance) {
		return fmt.Errorf("--instance %q is not an instance name", f.Instance)
	}
	c.filter = f
	return nil
}

// parseWhen reads an RFC 3339 time, or a duration that long before now.
func parseWhen(flag, s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("%s %q is neither an RFC 3339 time nor a duration such as 90m", flag, s)
}

func openEvents(g *Globals, e *Env) (*audit.Log, error) {
	paths, err := g.paths(e)
	if err != nil {
		return nil, err
	}
	return audit.OpenLog(paths.AuditLog())
}

func (c *EventsQueryCmd) Run(g *Globals, e *Env) error {
	log, err := openEvents(g, e)
	if err != nil {
		return err
	}
	evs, next, err := log.Query(background(), c.filter, audit.Page{AfterSeq: c.AfterSeq, Limit: c.Limit})
	if err != nil {
		return err
	}
	for _, ev := range evs {
		if err := writeJSONLine(e.Stdout, ev); err != nil {
			return err
		}
	}
	if next != 0 {
		return writeJSONLine(e.Stdout, struct {
			NextAfterSeq uint64 `json:"next_after_seq"`
		}{next})
	}
	return nil
}

// writeJSONLine writes v as one line of JSON, with every rune that doesn't
// print as itself escaped. Events keep verified names exactly as the kernel
// gave them, and a process can name itself with terminal controls (C1 such
// as U+009B) or bidi overrides (U+202E) that the JSON encoder passes through
// raw, and that would act on a terminal or hide text in a pager.
func writeJSONLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(escapeNonPrinting(b), '\n'))
	return err
}

// escapeNonPrinting rewrites runes that aren't printable as \u escapes.
// Outside strings, JSON text is ASCII, and the encoder has already escaped
// ASCII controls, so the result is the same JSON value.
func escapeNonPrinting(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r < utf8.RuneSelf || unicode.IsPrint(r) {
			out = append(out, b[:n]...)
		} else {
			for _, u := range utf16.Encode([]rune{r}) {
				out = fmt.Appendf(out, `\u%04x`, u)
			}
		}
		b = b[n:]
	}
	return out
}

// Run prints until SIGINT, SIGTERM or SIGHUP, then exits 0.
func (c *EventsFollowCmd) Run(g *Globals, e *Env) error {
	log, err := openEvents(g, e)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(background())
	defer cancel()
	sig := make(chan os.Signal, 4)
	defer e.notify(sig)()
	go func() {
		for {
			select {
			case s := <-sig:
				if s != syscall.SIGUSR1 {
					cancel()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	after := audit.FromNow
	if c.FromSeq != nil {
		after = max(*c.FromSeq, 1) - 1
	}
	return log.Follow(ctx, c.filter, after, func(ev audit.Event) error { return writeJSONLine(e.Stdout, ev) })
}
