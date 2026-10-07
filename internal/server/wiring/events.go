package wiring

import (
	"fmt"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugin/helper"
	"github.com/bpinto/foca/internal/plugins/events/logind"
)

// eventSources maps platform_events names to constructors. Test-only
// entries are added by files built with the foca_testing tag.
var eventSources = map[string]func(*env) (plugin.PlatformEvents, error){
	"logind": func(*env) (plugin.PlatformEvents, error) { return logind.New(), nil },
	"darwin": func(e *env) (plugin.PlatformEvents, error) {
		h, err := e.darwinHelper()
		if err != nil {
			return nil, err
		}
		return helper.NewEvents(h, "darwin"), nil
	},
}

// platformEvents returns the configured source, or nil for "none": without
// one, grants can't be wiped on sleep or lock, so reuse stays off (D13).
func platformEvents(e *env) (plugin.PlatformEvents, error) {
	name := e.cfg.PlatformEventsName()
	if name == "none" {
		return nil, nil
	}
	if mk, ok := eventSources[name]; ok {
		return mk(e)
	}
	if testOnly[name] {
		return nil, fmt.Errorf("platform_events %q is only available in test builds (built with -tags foca_testing)", name)
	}
	return nil, fmt.Errorf("unknown platform_events %q (auto | logind | darwin | none)", name)
}
