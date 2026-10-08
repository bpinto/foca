package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	// fallback is the whole directory to use when neither is set.
	pick := func(flag, env, xdg, fallback string) (string, error) {
		if flag != "" {
			return filepath.Abs(flag)
		}
		if v := getenv(env); v != "" {
			return filepath.Abs(v)
		}
		if v := getenv(xdg); v != "" {
			return filepath.Join(v, "foca"), nil
		}
		if fallback == "" {
			return "", fmt.Errorf("cannot determine %s: set %s", env, env)
		}
		return fallback, nil
	}
	var p Paths
	var err error
	if p.Config, err = pick(o.Config, "FOCA_CONFIG", "XDG_CONFIG_HOME", join(home, ".config/foca")); err != nil {
		return p, err
	}
	if o.Config == "" && getenv("FOCA_CONFIG") == "" {
		p.Config = filepath.Join(p.Config, "config.toml")
	}
	if p.DataDir, err = pick(o.DataDir, "FOCA_DATA_DIR", "XDG_DATA_HOME", join(home, ".local/share/foca")); err != nil {
		return p, err
	}
	// Without XDG_RUNTIME_DIR (cron, su, ssh without pam_systemd) the
	// runtime directory is foca-<uid> in the temporary directory. A shared
	// name such as /tmp/foca could be created first by another local user:
	// the service then couldn't start, and the CLI could reach a socket that
	// user listens on.
	tmp := getenv("TMPDIR")
	if tmp == "" {
		tmp = os.TempDir()
	}
	runtimeFallback := filepath.Join(tmp, "foca-"+strconv.Itoa(os.Getuid()))
	if p.RuntimeDir, err = pick(o.RuntimeDir, "FOCA_RUNTIME_DIR", "XDG_RUNTIME_DIR", runtimeFallback); err != nil {
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

// VaultsDir holds one encrypted file per vault.
func (p Paths) VaultsDir() string { return filepath.Join(p.DataDir, "vaults") }

func (p Paths) VaultFile(vault string) string {
	return filepath.Join(p.VaultsDir(), vault+".fcv")
}

// KeysDir holds the file key protector's keys (test builds only).
func (p Paths) KeysDir() string { return filepath.Join(p.DataDir, "keys") }

// PIDFile is where the service serving instance records its pid, so the host
// CLI can signal it. One process may serve several instances; each has one.
func (p Paths) PIDFile(instance string) string {
	return filepath.Join(p.InstanceDir(instance), "serve.pid")
}

// LockFile is the lock a service holds for every instance it serves, so no
// other process can serve it at the same time.
func (p Paths) LockFile(instance string) string {
	return filepath.Join(p.InstanceDir(instance), "serve.lock")
}

// PIDFiles finds the pid files of every instance in the runtime directory.
func (p Paths) PIDFiles() ([]string, error) {
	return filepath.Glob(filepath.Join(p.RuntimeDir, "*", "serve.pid"))
}

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
