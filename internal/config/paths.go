package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Paths are the resolved locations a service uses.
type Paths struct {
	Config     string
	DataDir    string
	RuntimeDir string
}

// Overrides are values from command-line flags; empty means "not given".
type Overrides struct {
	Config     string
	DataDir    string
	RuntimeDir string
}

// ResolvePaths applies flags, then FOCA_* env vars, then XDG defaults.
// getenv is injected so tests don't depend on the real environment.
func ResolvePaths(o Overrides, getenv func(string) string) (Paths, error) {
	home := getenv("HOME")
	pick := func(flag, env, xdg, xdgFallback string) (string, error) {
		if flag != "" {
			return filepath.Abs(flag)
		}
		if v := getenv(env); v != "" {
			return filepath.Abs(v)
		}
		if v := getenv(xdg); v != "" {
			return filepath.Join(v, "foca"), nil
		}
		if xdgFallback == "" {
			return "", fmt.Errorf("cannot determine %s: set %s", env, env)
		}
		return filepath.Join(xdgFallback, "foca"), nil
	}
	var p Paths
	var err error
	if p.Config, err = pick(o.Config, "FOCA_CONFIG", "XDG_CONFIG_HOME", join(home, ".config")); err != nil {
		return p, err
	}
	if o.Config == "" && getenv("FOCA_CONFIG") == "" {
		p.Config = filepath.Join(p.Config, "config.toml")
	}
	if p.DataDir, err = pick(o.DataDir, "FOCA_DATA_DIR", "XDG_DATA_HOME", join(home, ".local/share")); err != nil {
		return p, err
	}
	tmp := getenv("TMPDIR")
	if tmp == "" {
		tmp = os.TempDir()
	}
	if p.RuntimeDir, err = pick(o.RuntimeDir, "FOCA_RUNTIME_DIR", "XDG_RUNTIME_DIR", tmp); err != nil {
		return p, err
	}
	return p, nil
}

func join(home, rel string) string {
	if home == "" {
		return ""
	}
	return filepath.Join(home, rel)
}

// InstanceDir is the per-instance runtime directory holding its sockets.
func (p Paths) InstanceDir(instance string) string {
	return filepath.Join(p.RuntimeDir, instance)
}

func (p Paths) ClientSocket(instance string) string {
	return filepath.Join(p.InstanceDir(instance), "client.sock")
}

func (p Paths) AuditLog() string { return filepath.Join(p.DataDir, "audit.jsonl") }

// MaxSocketPath is the longest usable Unix socket path on this OS (sun_path
// minus the terminating NUL).
func MaxSocketPath() int {
	if runtime.GOOS == "linux" {
		return 107
	}
	return 103
}

// CheckSocketPath fails with a clear message instead of a truncated bind.
func CheckSocketPath(path string) error {
	if len(path) > MaxSocketPath() {
		return fmt.Errorf("socket path %s is %d bytes; the limit on %s is %d (set FOCA_RUNTIME_DIR to a shorter directory)",
			path, len(path), runtime.GOOS, MaxSocketPath())
	}
	return nil
}
