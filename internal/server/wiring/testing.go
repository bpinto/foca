//go:build foca_testing

package wiring

import (
	"context"
	"time"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
)

// In test builds only, "fake" approves everything. Production builds can't
// select it, so no config line can turn approval off.
func init() {
	TestBuild = true
	authenticators["fake"] = func(*env) (plugin.Authenticator, error) {
		a := fake.New()
		a.Default = fake.Approve
		return a, nil
	}
}

// readyEvents is the test builds' "fake" platform-events source: healthy at
// once, and it never reports anything. Tests wipe with `foca lock`.
type readyEvents struct{}

func (readyEvents) Name() string { return "fake" }

func (readyEvents) Run(ctx context.Context, out chan<- plugin.PlatformEvent) error {
	select {
	case out <- plugin.PlatformEvent{Kind: plugin.EventReady, At: time.Now(), Source: "fake"}:
	case <-ctx.Done():
		return nil
	}
	<-ctx.Done()
	return nil
}

func init() {
	eventSources["fake"] = func(*env) (plugin.PlatformEvents, error) { return readyEvents{}, nil }
}
