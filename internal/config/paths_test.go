package config

import (
	"strings"
	"testing"
)

// An explicit config path needs no HOME or XDG_CONFIG_HOME to find a default.
func TestExplicitConfigNeedsNoHome(t *testing.T) {
	env := map[string]string{"FOCA_CONFIG": "/etc/foca.toml", "FOCA_DATA_DIR": "/d", "FOCA_RUNTIME_DIR": "/r"}
	p, err := ResolvePaths(Overrides{}, func(k string) string { return env[k] })
	if err != nil || p.Config != "/etc/foca.toml" {
		t.Fatalf("got %+v, %v", p, err)
	}
	p, err = ResolvePaths(Overrides{Config: "/x.toml"}, func(k string) string { return env[k] })
	if err != nil || p.Config != "/x.toml" {
		t.Fatalf("got %+v, %v", p, err)
	}
	delete(env, "FOCA_CONFIG")
	if _, err := ResolvePaths(Overrides{}, func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "set FOCA_CONFIG") {
		t.Fatalf("got %v", err)
	}
}
