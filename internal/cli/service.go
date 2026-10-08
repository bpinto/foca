package cli

import (
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/server/core"
	"github.com/bpinto/foca/internal/server/wiring"
	"github.com/bpinto/foca/internal/svcctl"
)

// ---- serve ----

type ServeCmd struct {
	Only []string `help:"Serve only this instance; repeat for more. Instances that read a vault in common must be served by one process." placeholder:"INSTANCE"`
}

// Run serves until SIGINT or SIGTERM. SIGUSR1 (foca lock) drops every grant.
// SIGHUP reloads the config: a config
// that fails to load or wire keeps the old one running. A good one replaces
// the running service, which closes open connections and cancels pending
// approvals; clients reconnect.
func (c *ServeCmd) Run(g *Globals, e *Env) error {
	log := logger(e, slog.LevelInfo)
	paths, err := g.paths(e)
	if err != nil {
		return err
	}
	cfg, err := loadOnly(paths, c.Only)
	if err != nil {
		return err
	}
	// Signals are caught before the pid file exists, so a reload sent as
	// soon as the file appears can't kill the process.
	sig := make(chan os.Signal, 4)
	defer e.notify(sig)()

	pids := &pidFiles{paths: paths, held: map[string]func(){}, locks: map[string]func(){}}
	if err := pids.lock(cfg); err != nil {
		pids.release()
		return err
	}
	b, err := start(cfg, paths, g.version, log)
	if err != nil {
		pids.release()
		return err
	}
	if err := pids.sync(cfg); err != nil {
		b.Server.Shutdown("pid file: " + err.Error())
		b.Audit.Close()
		pids.release()
		return err
	}
	defer pids.release()

	for {
		select {
		case s := <-sig:
			if s == syscall.SIGUSR1 {
				// foca lock: wipe now. Tightening, so no approval.
				if err := b.Core.Wipe(background(), core.WipeManual, nil); err != nil {
					log.Error("audit failed for lock", "err", err)
				}
				continue
			}
			if s != syscall.SIGHUP {
				b.Server.Shutdown("signal " + s.String())
				b.Audit.Close()
				return nil
			}
			b, cfg, err = reload(b, cfg, paths, c.Only, g.version, log, pids.lock)
			if err != nil {
				return err
			}
			if err := pids.sync(cfg); err != nil {
				log.Error("reload: pid file", "err", err)
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
// lock takes the lock of every instance the new config adds.
func reload(old *wiring.Built, oldCfg *config.Config, paths config.Paths, only []string, version string, log *slog.Logger, lock func(*config.Config) error) (*wiring.Built, *config.Config, error) {
	record := func(b *wiring.Built, outcome string, err error) {
		ev := &audit.Event{Type: audit.TypeConfigReload, Outcome: outcome, Reason: paths.Config}
		if err != nil {
			ev.Error = &audit.ErrorInfo{Code: "invalid_config", Message: err.Error()}
		}
		if _, aerr := b.Audit.Append(background(), ev); aerr != nil {
			log.Error("audit failed for config.reload", "err", aerr)
		}
	}
	cfg, err := loadOnly(paths, only)
	if err != nil {
		log.Error("reload: config rejected, keeping the running one", "err", err)
		record(old, audit.OutcomeError, err)
		return old, oldCfg, nil
	}
	if err := lock(cfg); err != nil {
		log.Error("reload: can't lock the new config's instances, keeping the running one", "err", err)
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
	pids, _, err := g.signalServices(e, paths, syscall.SIGHUP)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.Stderr, "reload requested (pid %s)\n", pidList(pids))
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
	pids, files, err := g.signalServices(e, paths, syscall.SIGTERM)
	if err != nil {
		return err
	}
	// Each service removes its pid files as it exits.
	for deadline := time.Now().Add(c.Wait); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if !slices.ContainsFunc(files, exists) {
			fmt.Fprintf(e.Stderr, "stopped (pid %s)\n", pidList(pids))
			return nil
		}
	}
	return fmt.Errorf("pid %s did not exit within %s", pidList(pids), c.Wait)
}

// loadOnly loads the config, narrowed to the --only instances.
func loadOnly(paths config.Paths, only []string) (*config.Config, error) {
	cfg, err := config.Load(paths.Config)
	if err != nil {
		return nil, err
	}
	return cfg.Only(only)
}

// pidFiles are the locks and pid files of the instances this process serves,
// one each per instance, so another process can't serve one of them too.
type pidFiles struct {
	paths config.Paths
	held  map[string]func()
	locks map[string]func()
}

// lock takes the lock of every instance of cfg not yet held. It comes before
// anything touches an instance's socket or pid file, so a second service
// starting at the same time fails here.
func (p *pidFiles) lock(cfg *config.Config) error {
	for _, inst := range cfg.Instances {
		if p.locks[inst.Name] != nil {
			continue
		}
		release, err := svcctl.Lock(p.paths.LockFile(inst.Name))
		if err != nil {
			return fmt.Errorf("instance %s: %w", inst.Name, err)
		}
		p.locks[inst.Name] = release
	}
	return nil
}

// sync holds a pid file for every instance of cfg, and lets go of the rest,
// pid files and locks.
func (p *pidFiles) sync(cfg *config.Config) error {
	want := map[string]bool{}
	for _, inst := range cfg.Instances {
		want[inst.Name] = true
		if p.held[inst.Name] != nil {
			continue
		}
		remove, err := svcctl.WritePIDFile(p.paths.PIDFile(inst.Name))
		if err != nil {
			return err
		}
		p.held[inst.Name] = remove
	}
	for name, remove := range p.held {
		if !want[name] {
			remove()
			delete(p.held, name)
		}
	}
	for name, release := range p.locks {
		if !want[name] {
			release()
			delete(p.locks, name)
		}
	}
	return nil
}

// release removes the pid files before letting go of the locks, so a pid
// file never names this process while another holds the lock.
func (p *pidFiles) release() {
	for name, remove := range p.held {
		remove()
		delete(p.held, name)
	}
	for name, release := range p.locks {
		release()
		delete(p.locks, name)
	}
}

// signalServices signals every running service once: the one serving
// --instance / FOCA_INSTANCE if given, else every one in the runtime
// directory. It returns the pids signalled and their pid files.
func (g *Globals) signalServices(e *Env, paths config.Paths, sig syscall.Signal) ([]int, []string, error) {
	files, err := paths.PIDFiles()
	if err != nil {
		return nil, nil, err
	}
	if inst := g.instanceName(e); inst != "" {
		files = []string{paths.PIDFile(inst)}
	}
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("%w (no pid file in %s)", svcctl.ErrNotRunning, paths.RuntimeDir)
	}
	var pids []int
	var signalled []string
	seen := map[int]bool{}
	for _, f := range files {
		pid, err := svcctl.PID(f)
		if err != nil {
			if len(files) == 1 {
				return nil, nil, err
			}
			continue
		}
		signalled = append(signalled, f)
		if seen[pid] {
			continue
		}
		seen[pid] = true
		if _, err := svcctl.Signal(f, sig); err != nil {
			return pids, signalled, err
		}
		pids = append(pids, pid)
	}
	if len(pids) == 0 {
		return nil, nil, fmt.Errorf("%w (no live service behind %s)", svcctl.ErrNotRunning, strings.Join(files, ", "))
	}
	return pids, signalled, nil
}

func pidList(pids []int) string {
	s := make([]string, len(pids))
	for i, p := range pids {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

// ---- config check ----

type ConfigCmd struct {
	Check ConfigCheckCmd `cmd:"" help:"Check a config file as serve would, without using it."`
}

type ConfigCheckCmd struct {
	File string `arg:"" optional:"" help:"Config file (default: the one serve reads)." placeholder:"FILE"`
}

// Run validates the file. It reads it without the trust checks Load makes,
// since nothing is done with it: Nix checks a generated config at build
// time, in a sandbox where the store looks owned by nobody.
func (c *ConfigCheckCmd) Run(g *Globals, e *Env) error {
	path := c.File
	if path == "" {
		paths, err := g.paths(e)
		if err != nil {
			return err
		}
		path = paths.Config
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, err := config.Parse(b); err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	fmt.Fprintf(e.Stderr, "config %s is valid\n", path)
	return nil
}
