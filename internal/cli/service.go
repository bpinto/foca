package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/server/wiring"
	"github.com/bpinto/foca/internal/svcctl"
)

// ---- serve ----

type ServeCmd struct{}

// Run serves until SIGINT or SIGTERM. SIGHUP reloads the config: a config
// that fails to load or wire keeps the old one running. A good one replaces
// the running service, which closes open connections and cancels pending
// approvals; clients reconnect.
func (ServeCmd) Run(g *Globals, e *Env) error {
	log := logger(e, slog.LevelInfo)
	paths, err := g.paths(e)
	if err != nil {
		return err
	}
	cfg, err := config.Load(paths.Config)
	if err != nil {
		return err
	}
	// Signals are caught before the pid file exists, so a reload sent as
	// soon as the file appears can't kill the process.
	sig := make(chan os.Signal, 4)
	defer e.notify(sig)()

	b, err := start(cfg, paths, g.version, log)
	if err != nil {
		return err
	}
	removePID, err := svcctl.WritePIDFile(paths.PIDFile())
	if err != nil {
		b.Server.Shutdown("pid file: " + err.Error())
		b.Audit.Close()
		return err
	}
	defer removePID()

	for {
		select {
		case s := <-sig:
			if s != syscall.SIGHUP {
				b.Server.Shutdown("signal " + s.String())
				b.Audit.Close()
				return nil
			}
			b, cfg, err = reload(b, cfg, paths, g.version, log)
			if err != nil {
				return err
			}
		case <-b.Server.Done():
			b.Audit.Close()
			return nil
		}
	}
}

func start(cfg *config.Config, paths config.Paths, version string, log *slog.Logger) (*wiring.Built, error) {
	b, err := wiring.Build(cfg, paths, version, log)
	if err != nil {
		return nil, err
	}
	if err := b.Server.Start(); err != nil {
		b.Audit.Close()
		return nil, err
	}
	for _, inst := range cfg.Instances {
		log.Info("serving", "instance", inst.Name, "realm", inst.Realm.Kind, "socket", paths.ClientSocket(inst.Name))
	}
	return b, nil
}

// reload swaps in a new config. Only an error that leaves nothing running is
// returned; everything else is logged, audited, and the old config stays.
func reload(old *wiring.Built, oldCfg *config.Config, paths config.Paths, version string, log *slog.Logger) (*wiring.Built, *config.Config, error) {
	record := func(b *wiring.Built, outcome string, err error) {
		ev := &audit.Event{Type: audit.TypeConfigReload, Outcome: outcome, Reason: paths.Config}
		if err != nil {
			ev.Error = &audit.ErrorInfo{Code: "invalid_config", Message: err.Error()}
		}
		if _, aerr := b.Audit.Append(background(), ev); aerr != nil {
			log.Error("audit failed for config.reload", "err", aerr)
		}
	}
	cfg, err := config.Load(paths.Config)
	if err != nil {
		log.Error("reload: config rejected, keeping the running one", "err", err)
		record(old, audit.OutcomeError, err)
		return old, oldCfg, nil
	}
	nb, err := wiring.Build(cfg, paths, version, log)
	if err != nil {
		log.Error("reload: config can't be wired, keeping the running one", "err", err)
		record(old, audit.OutcomeError, err)
		return old, oldCfg, nil
	}
	old.Server.Shutdown("reload")
	old.Audit.Close()
	if err := nb.Server.Start(); err != nil {
		nb.Audit.Close()
		log.Error("reload: new config failed to start, restoring the old one", "err", err)
		restored, rerr := start(oldCfg, paths, version, log)
		if rerr != nil {
			return nil, nil, fmt.Errorf("reload failed (%v) and the old config could not be restarted: %w", err, rerr)
		}
		record(restored, audit.OutcomeError, err)
		return restored, oldCfg, nil
	}
	record(nb, audit.OutcomeOK, nil)
	log.Info("reloaded", "config", paths.Config)
	return nb, cfg, nil
}

// ---- reload, stop ----

type ReloadCmd struct{}

// Run checks the config here first, so a mistake is reported at once
// instead of only in the service's log.
func (ReloadCmd) Run(g *Globals, e *Env) error {
	paths, err := g.paths(e)
	if err != nil {
		return err
	}
	if _, err := config.Load(paths.Config); err != nil {
		return fmt.Errorf("not reloading: %w", err)
	}
	pid, err := svcctl.Signal(paths.PIDFile(), syscall.SIGHUP)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.Stderr, "reload requested (pid %d)\n", pid)
	return nil
}

type StopCmd struct {
	Wait time.Duration `default:"10s" help:"How long to wait for the service to exit."`
}

func (c *StopCmd) Run(g *Globals, e *Env) error {
	paths, err := g.paths(e)
	if err != nil {
		return err
	}
	pid, err := svcctl.Signal(paths.PIDFile(), syscall.SIGTERM)
	if err != nil {
		return err
	}
	for deadline := time.Now().Add(c.Wait); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(paths.PIDFile()); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(e.Stderr, "stopped (pid %d)\n", pid)
			return nil
		}
	}
	return fmt.Errorf("pid %d did not exit within %s", pid, c.Wait)
}
