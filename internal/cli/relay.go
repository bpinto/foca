package cli

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/bpinto/foca/internal/protocol"
	"github.com/bpinto/foca/internal/relay"
)

// ---- relay (design §14) ----

type RelayCmd struct {
	Serve  RelayServeCmd  `cmd:"" help:"Relay the realm's callers to foca on the host, with their identity from this kernel."`
	Keygen RelayKeygenCmd `cmd:"" help:"Create the relay's key and print the public key for the host's config."`
	Pubkey RelayPubkeyCmd `cmd:"" help:"Print the relay's public key for the host's config."`
}

// relayKey is the key file: --key-file, else ~/.config/foca/relay.key of the
// relay's user.
func relayKey(e *Env, flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	dir := e.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home := e.Getenv("HOME")
		if home == "" {
			return "", errors.New("no HOME: pass --key-file")
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "foca", "relay.key"), nil
}

type RelayServeCmd struct {
	Listen         string `default:"/run/foca/relay.sock" help:"Socket the realm's processes use (mode 0666)." placeholder:"PATH"`
	Upstream       string `help:"The socket forwarded from the host, which only the relay's user can reach (default ~/.foca.sock)." placeholder:"PATH"`
	KeyFile        string `help:"The relay's private key (default ~/.config/foca/relay.key)." placeholder:"FILE"`
	MaxConnections int    `default:"32" help:"Callers served at once (1-1024)." placeholder:"N"`
	MaxPerUser     int    `default:"8" help:"Callers of one uid served at once (1-1024), so one user can't take every connection the host allows." placeholder:"N"`
}

// Run relays until SIGINT or SIGTERM.
func (c *RelayServeCmd) Run(g *Globals, e *Env) error {
	log := logger(e, slog.LevelInfo)
	keyPath, err := relayKey(e, c.KeyFile)
	if err != nil {
		return err
	}
	upstream := c.Upstream
	if upstream == "" {
		home := e.Getenv("HOME")
		if home == "" {
			return errors.New("no HOME: pass --upstream")
		}
		upstream = filepath.Join(home, ".foca.sock")
	}
	for _, l := range []struct {
		flag string
		n    int
	}{{"--max-connections", c.MaxConnections}, {"--max-per-user", c.MaxPerUser}} {
		if l.n < 1 || l.n > relay.MaxLimit {
			return fmt.Errorf("%s must be 1 to %d (got %d)", l.flag, relay.MaxLimit, l.n)
		}
	}
	if os.Geteuid() == 0 {
		return errors.New("refusing to run as root: run the relay as a user of its own, the one ssh logs in as for the forwarded socket")
	}
	key, err := relay.LoadKey(keyPath, os.Getuid())
	if err != nil {
		return err
	}
	r := relay.New(relay.Options{Listen: c.Listen, Upstream: upstream, Key: key, Log: log,
		MaxConnections: c.MaxConnections, MaxPerUser: c.MaxPerUser})
	if err := r.Start(); err != nil {
		return err
	}
	log.Info("relaying", "listen", c.Listen, "upstream", upstream, "public_key", protocol.FormatRelayKey(key.Public().(ed25519.PublicKey)))
	ctx, cancel := context.WithCancel(background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	defer e.notify(sig)()
	go func() {
		<-sig
		cancel()
	}()
	return r.Serve(ctx)
}

type RelayKeygenCmd struct {
	KeyFile string `help:"Where to create the key (default ~/.config/foca/relay.key)." placeholder:"FILE"`
}

func (c *RelayKeygenCmd) Run(g *Globals, e *Env) error {
	path, err := relayKey(e, c.KeyFile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	pub, err := relay.Keygen(path)
	if err != nil {
		return err
	}
	fmt.Fprintln(e.Stdout, protocol.FormatRelayKey(pub))
	fmt.Fprintf(e.Stderr, "created %s; on the host, set guest_relay = { public_key = \"%s\" } on this realm's instance\n", path, protocol.FormatRelayKey(pub))
	return nil
}

type RelayPubkeyCmd struct {
	KeyFile string `help:"The relay's private key (default ~/.config/foca/relay.key)." placeholder:"FILE"`
}

func (c *RelayPubkeyCmd) Run(g *Globals, e *Env) error {
	path, err := relayKey(e, c.KeyFile)
	if err != nil {
		return err
	}
	key, err := relay.LoadKey(path, os.Getuid())
	if err != nil {
		return err
	}
	fmt.Fprintln(e.Stdout, protocol.FormatRelayKey(key.Public().(ed25519.PublicKey)))
	return nil
}
