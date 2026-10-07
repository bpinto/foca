package wiring

import (
	"fmt"
	"runtime"

	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/events/logind"
)

// eventSources maps platform_events names to constructors. Test-only
// entries are added by files built with the foca_testing tag.
var eventSources = map[string]func() plugin.PlatformEvents{
	"logind": func() plugin.PlatformEvents { return logind.New() },
}

var plannedEvents = map[string]bool{"darwin": true}

// PlatformEventsName resolves platform_events = "auto" for this OS. On
// macOS there is no darwin source yet, so "auto" means none,
// which keeps reuse off.
func PlatformEventsName(cfg *config.Config) string {
	name := cfg.Plugins.PlatformEvents
	if name != "auto" {
		return name
	}
	if runtime.GOOS == "linux" {
		return "logind"
	}
	return "none"
}

// platformEvents returns the configured source, or nil for "none": without
// one, grants can't be wiped on sleep or lock, so reuse stays off (D13).
func platformEvents(cfg *config.Config) (plugin.PlatformEvents, error) {
	name := PlatformEventsName(cfg)
	if name == "none" {
		return nil, nil
	}
	if mk, ok := eventSources[name]; ok {
		return mk(), nil
	}
	if testOnly[name] {
		return nil, fmt.Errorf("platform_events %q is only available in test builds (built with -tags foca_testing)", name)
	}
	if plannedEvents[name] {
		return nil, fmt.Errorf("platform_events %q is not implemented yet", name)
	}
	return nil, fmt.Errorf("unknown platform_events %q (auto | logind | none)", name)
}
