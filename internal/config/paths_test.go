package config

import (
	"os"
	"strconv"
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

// Without XDG_RUNTIME_DIR the runtime directory is named after the user, so
// another user can't create it first. XDG, env vars and flags still win.
func TestRuntimeDirFallbackIsPerUser(t *testing.T) {
	env := map[string]string{"HOME": "/home/u", "TMPDIR": "/tmp"}
	get := func(k string) string { return env[k] }
	p, err := ResolvePaths(Overrides{}, get)
	if want := "/tmp/foca-" + strconv.Itoa(os.Getuid()); err != nil || p.RuntimeDir != want {
		t.Fatalf("runtime dir %q, %v; want %q", p.RuntimeDir, err, want)
	}
	if p.Config != "/home/u/.config/foca/config.toml" || p.DataDir != "/home/u/.local/share/foca" {
		t.Fatalf("got %+v", p)
	}
	env["XDG_RUNTIME_DIR"] = "/run/user/1000"
	if p, _ := ResolvePaths(Overrides{}, get); p.RuntimeDir != "/run/user/1000/foca" {
		t.Fatalf("runtime dir %q", p.RuntimeDir)
	}
	env["FOCA_RUNTIME_DIR"] = "/r"
	if p, _ := ResolvePaths(Overrides{}, get); p.RuntimeDir != "/r" {
		t.Fatalf("runtime dir %q", p.RuntimeDir)
	}
	if p, _ := ResolvePaths(Overrides{RuntimeDir: "/f"}, get); p.RuntimeDir != "/f" {
		t.Fatalf("runtime dir %q", p.RuntimeDir)
	}
}
