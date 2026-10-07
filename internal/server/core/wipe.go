package core

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/plugin"
)

// Wipe reasons, recorded in the lock event (design §8.2).
const (
	WipeSleep           = "sleep"
	WipeScreenLock      = "screen-lock"
	WipeSessionEnd      = "session-end"
	WipeShutdown        = "shutdown"
	WipeReload          = "reload"
	WipeManual          = "manual"
	WipeExpired         = "expired"
	WipeEventsUnhealthy = "events-unhealthy"
)

// SleepJump is how far wall-clock and monotonic elapsed time may drift apart
// between two watchdog checks before it counts as a missed sleep.
const SleepJump = 30 * time.Second

// Wipe drops every grant and resets denial backoff and strikes, then records a lock
// event with the reason and how many grants were dropped. It happens
// whatever the config says. Secret values and data keys are never held
// between requests, so there is nothing else to zero.
func (s *Service) Wipe(ctx context.Context, reason string, params map[string]string) error {
	// Wait for any approval between deciding on a grant and making it;
	// its grant is then dropped and counted here.
	s.grantMu.Lock()
	s.mu.Lock()
	n := len(s.grants)
	clear(s.grants)
	clear(s.denials)
	clear(s.strikes)
	s.wipes++
	s.mu.Unlock()
	s.grantMu.Unlock()
	e := &audit.Event{Type: audit.TypeLock, Outcome: audit.OutcomeOK, Reason: reason, Count: n, Params: params}
	_, err := s.appendEvent(ctx, e)
	return err
}

// setHealthy records whether platform events are reporting. Losing them
// wipes, and reuse stays off until they report again (design D13).
func (s *Service) setHealthy(ctx context.Context, ok bool, log *slog.Logger) {
	s.mu.Lock()
	was := s.healthy
	s.healthy = ok
	s.mu.Unlock()
	if was && !ok {
		if err := s.Wipe(ctx, WipeEventsUnhealthy, nil); err != nil {
			log.Error("audit failed for lock", "err", err)
		}
	}
}

// Healthy reports whether grants can currently be made and reused.
func (s *Service) Healthy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.healthy
}

// expire drops grants whose window has ended and records how many.
func (s *Service) expire(ctx context.Context) error {
	now := s.wall()
	s.mu.Lock()
	n := 0
	for k, g := range s.grants {
		if !now.Before(g.expiresAt) {
			delete(s.grants, k)
			n++
		}
	}
	s.mu.Unlock()
	if n == 0 {
		return nil
	}
	e := &audit.Event{Type: audit.TypeLock, Outcome: audit.OutcomeOK, Reason: WipeExpired, Count: n}
	_, err := s.appendEvent(ctx, e)
	return err
}

// Guard runs the wipe controller until ctx ends: it follows platform events,
// runs the sleep-jump watchdog and drops expired grants. A nil source means
// none is configured, so reuse stays off. done is closed once Guard has
// stopped.
func (s *Service) Guard(ctx context.Context, src plugin.PlatformEvents, log *slog.Logger) (done <-chan struct{}) {
	if log == nil {
		log = slog.Default()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.watch(ctx, log)
	}()
	go func() {
		defer wg.Done()
		if src != nil {
			s.follow(ctx, src, log)
		}
	}()
	ch := make(chan struct{})
	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch
}

// watch checks the clock (checkClock) every WatchEvery, and drops expired
// grants.
func (s *Service) watch(ctx context.Context, log *slog.Logger) {
	t := time.NewTicker(s.opts.WatchEvery)
	defer t.Stop()
	check := func() {
		if drift, err := s.checkClock(ctx); err != nil {
			log.Error("audit failed for lock", "err", err)
		} else if drift != 0 {
			log.Warn("clock jump; treating it as sleep", "drift", drift)
		}
	}
	check()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		check()
		if err := s.expire(ctx); err != nil {
			log.Error("audit failed for expired grants", "err", err)
		}
	}
}

// checkClock compares wall-clock and monotonic time elapsed since the last
// check. The monotonic clock stops during sleep, so a gap larger than
// SleepJump means the machine slept, even if no event said so (design D11),
// and it wipes. A clock change looks the same and also wipes, which is safe.
// It returns the drift if it wiped, else 0. The watchdog checks every
// WatchEvery, and every request that could reuse a grant checks first.
func (s *Service) checkClock(ctx context.Context) (time.Duration, error) {
	s.clock.mu.Lock()
	w, m := s.wall(), s.opts.Mono()
	var drift time.Duration
	if !s.clock.wall.IsZero() {
		drift = w.Sub(s.clock.wall) - (m - s.clock.mono)
	}
	s.clock.wall, s.clock.mono = w, m
	s.clock.mu.Unlock()
	if drift <= SleepJump && drift >= -SleepJump {
		return 0, nil
	}
	return drift, s.Wipe(ctx, WipeSleep, map[string]string{"clock_jump": drift.Round(time.Second).String()})
}

// follow runs the platform-events source and restarts it when it fails.
// Reuse is off from the moment it fails until it reports ready again. Each
// event is marked handled once its wipe is done and recorded, so a source
// can let the machine sleep only then.
func (s *Service) follow(ctx context.Context, src plugin.PlatformEvents, log *slog.Logger) {
	retry := time.Second
	for ctx.Err() == nil {
		events := make(chan plugin.PlatformEvent, 16)
		errc := make(chan error, 1)
		rctx, cancel := context.WithCancel(ctx)
		go func() { errc <- src.Run(rctx, events) }()
		var err error
		ready := time.Time{}
	loop:
		for {
			select {
			case ev := <-events:
				if ev.Kind == plugin.EventReady {
					ready = time.Now()
				}
				s.handle(ctx, ev, log)
				ev.Handled()
			case err = <-errc:
				break loop
			}
		}
		cancel()
		// Events sent before Run returned still count.
		for {
			select {
			case ev := <-events:
				s.handle(ctx, ev, log)
				ev.Handled()
				continue
			default:
			}
			break
		}
		if ctx.Err() != nil {
			return
		}
		log.Error("platform events stopped; reuse is off until they return", "source", src.Name(), "err", err)
		s.setHealthy(ctx, false, log)
		if !ready.IsZero() && time.Since(ready) > time.Minute {
			retry = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
		retry = min(retry*2, 30*time.Second)
	}
}

func (s *Service) handle(ctx context.Context, ev plugin.PlatformEvent, log *slog.Logger) {
	var reason string
	switch ev.Kind {
	case plugin.EventReady:
		log.Info("platform events ready; reuse can apply", "source", ev.Source)
		s.setHealthy(ctx, true, log)
		return
	case plugin.EventSleep:
		reason = WipeSleep
	case plugin.EventScreenLock:
		reason = WipeScreenLock
	case plugin.EventSessionEnd:
		reason = WipeSessionEnd
	default:
		log.Warn("ignoring unknown platform event", "kind", ev.Kind, "source", ev.Source)
		return
	}
	if err := s.Wipe(ctx, reason, map[string]string{"source": ev.Source}); err != nil {
		log.Error("audit failed for lock", "err", err)
	}
}

// DropGrants drops the caller's grants, all of them or those for names.
// Tightening is always allowed. It is recorded as grants.drop.
func (s *Service) DropGrants(ctx context.Context, c Call, names []string) (int, error) {
	if len(names) > 0 {
		var perr error
		if names, perr = s.checkNamesErr(c, names); perr != nil {
			return 0, perr
		}
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	s.mu.Lock()
	n := 0
	for gk := range s.grants {
		if k, ok := keyFor(gk.scope, c); !ok || k != gk.key {
			continue
		}
		if len(want) > 0 && !want[gk.resource.ID] {
			continue
		}
		delete(s.grants, gk)
		n++
	}
	s.mu.Unlock()
	e := s.Event(c, audit.TypeGrantsDrop, audit.OutcomeOK)
	e.Count = n
	if len(names) > 0 {
		e.Params = map[string]string{"names": strings.Join(names, ",")}
	}
	if _, aerr := s.record(ctx, c, e); aerr != nil {
		return 0, aerr
	}
	return n, nil
}

func (s *Service) checkNamesErr(c Call, names []string) ([]string, error) {
	out, perr := s.checkNames(c, names)
	if perr != nil {
		return nil, perr
	}
	return out, nil
}
