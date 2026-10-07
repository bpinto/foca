package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/ids"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/store/vaultfile"
	"github.com/bpinto/foca/internal/secretname"
	"github.com/bpinto/foca/internal/server/core"
	"github.com/bpinto/foca/internal/server/wiring"
)

// hostOp is an open host session on one vault: config, plugins, and the
// vault's write lock, held until close.
type hostOp struct {
	cfg    *config.Config
	host   *wiring.Host
	vault  string
	store  *vaultfile.Store
	unlock func() error
	call   core.Call
}

func (g *Globals) openHost(e *Env, vaultFlag string) (*hostOp, error) {
	cfg, paths, err := g.load(e)
	if err != nil {
		return nil, err
	}
	vault, err := g.pickVault(e, cfg, vaultFlag)
	if err != nil {
		return nil, err
	}
	h, err := wiring.BuildHost(cfg, paths, logger(e, slog.LevelWarn))
	if err != nil {
		return nil, err
	}
	store := h.Vaults[vault]
	unlock, err := store.Lock()
	if err != nil {
		h.Audit.Close()
		return nil, err
	}
	return &hostOp{cfg: cfg, host: h, vault: vault, store: store, unlock: unlock,
		call: core.HostCall(ids.New(), vault, selfPeer())}, nil
}

func (o *hostOp) close() {
	o.unlock()
	o.host.Audit.Close()
}

// pickVault: --vault, else the vault of --instance / FOCA_INSTANCE if it reads
// only one, else the only vault in the config.
func (g *Globals) pickVault(e *Env, cfg *config.Config, flag string) (string, error) {
	if flag != "" {
		if !slices.Contains(cfg.Vaults, flag) {
			return "", fmt.Errorf("vault %q is not in the config (vaults: %s)", flag, strings.Join(cfg.Vaults, ", "))
		}
		return flag, nil
	}
	if inst := g.instanceName(e); inst != "" {
		i, ok := cfg.Instance(inst)
		if !ok {
			return "", fmt.Errorf("instance %q is not in the config", inst)
		}
		if vs := i.Vaults(); len(vs) == 1 {
			return vs[0], nil
		}
		return "", fmt.Errorf("instance %s reads several vaults (%s): pass --vault", inst, strings.Join(i.Vaults(), ", "))
	}
	if len(cfg.Vaults) == 1 {
		return cfg.Vaults[0], nil
	}
	return "", fmt.Errorf("the config has several vaults (%s): pass --vault", strings.Join(cfg.Vaults, ", "))
}

func (g *Globals) instanceName(e *Env) string {
	if g.Instance != "" {
		return g.Instance
	}
	return e.Getenv("FOCA_INSTANCE")
}

// selfPeer describes this CLI process for prompts and audit.
func selfPeer() identity.VerifiedPeer {
	exe, _ := os.Executable()
	return identity.VerifiedPeer{Source: "self", UID: os.Getuid(), GID: os.Getgid(), PID: os.Getpid(),
		Exe: exe, Name: filepath.Base(exe)}
}

func visibility(c core.Change) string {
	s := "visible to no instance"
	if len(c.VisibleTo) > 0 {
		s = "visible to " + strings.Join(c.VisibleTo, ", ")
	}
	return s
}

// ---- init ----

type InitCmd struct {
	Vault    string `help:"Vault to create (default: the only vault in the config)."`
	Recovery bool   `help:"Add a recovery passphrase, read from a hidden prompt or the first line of stdin."`
}

func (c *InitCmd) Run(g *Globals, e *Env) error {
	op, err := g.openHost(e, c.Vault)
	if err != nil {
		return err
	}
	defer op.close()
	if op.store.Exists() {
		return fmt.Errorf("vault %s already exists (%s)", op.vault, op.store.Path())
	}
	var pass []byte
	if c.Recovery {
		if pass, err = readPassphrase(e, "recovery passphrase"); err != nil {
			return err
		}
		defer zero(pass)
	}
	prot := op.host.Protector
	err = op.host.Core.InitVault(background(), op.call, op.vault, func(ctx context.Context) (string, func(context.Context) error, error) {
		h, err := op.store.Create(ctx, prot, vaultfile.CreateOptions{Recovery: pass})
		if err != nil {
			return "", nil, err
		}
		undo := func(ctx context.Context) error {
			return errors.Join(os.Remove(op.store.Path()),
				prot.Destroy(ctx, plugin.KeyRef{Vault: op.vault, VaultID: h.VaultID}, nil))
		}
		return h.VaultID, undo, nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(e.Stderr, "created vault %s at %s\n", op.vault, op.store.Path())
	return nil
}

// ---- add ----

type AddCmd struct {
	Name        string `arg:"" optional:"" help:"Secret name, <vault>:<secret> (letters, digits, - and _). Asked for on a terminal if left out."`
	DisplayName string `help:"Name shown in prompts instead of the secret name."`
	Description string `help:"What the secret is for."`
	FromFile    string `help:"Read the value from this file, byte for byte. Otherwise it comes from stdin or a hidden prompt." placeholder:"FILE"`
}

func (c *AddCmd) Run(g *Globals, e *Env) error {
	if c.Name == "" {
		if !e.interactive() {
			return errors.New("missing secret name")
		}
		f := huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("Secret name").Description("<vault>:<secret>").Value(&c.Name).Validate(func(s string) error {
				if _, _, ok := secretname.Split(s); !ok {
					return errors.New("<vault>:<secret>, with letters, digits, - and _")
				}
				return nil
			}),
			huh.NewInput().Title("Description").Value(&c.Description),
		))
		if err := runForm(e, f); err != nil {
			return err
		}
	}
	vault, id, err := splitName(c.Name)
	if err != nil {
		return err
	}
	value, err := readValue(e, "Value for "+c.Name, c.FromFile)
	if err != nil {
		return err
	}
	defer zero(value)

	op, err := g.openHost(e, vault)
	if err != nil {
		return err
	}
	defer op.close()
	ch, err := op.host.Core.AddSecret(background(), op.call, core.NewSecret{
		Vault: op.vault, ID: id, DisplayName: c.DisplayName, Description: c.Description, Value: value,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(e.Stderr, "added %s, %s\n", c.Name, visibility(ch))
	return nil
}

// ---- edit ----

type EditCmd struct {
	Name        string  `arg:"" help:"Secret to change, <vault>:<secret>."`
	DisplayName *string `help:"New display name (empty to clear)."`
	Description *string `help:"New description (empty to clear)."`
	Value       bool    `help:"Change the value: read it from stdin or a hidden prompt."`
	FromFile    string  `help:"Change the value: read it from this file, byte for byte." placeholder:"FILE"`
}

func (c *EditCmd) Run(g *Globals, e *Env) error {
	vault, id, err := splitName(c.Name)
	if err != nil {
		return err
	}
	op, err := g.openHost(e, vault)
	if err != nil {
		return err
	}
	defer op.close()

	ed := core.SecretEdit{Vault: op.vault, ID: id, DisplayName: c.DisplayName, Description: c.Description}
	changeValue := c.Value || c.FromFile != ""
	if ed.DisplayName == nil && ed.Description == nil && !changeValue {
		if !e.interactive() {
			return errors.New("nothing to change: pass --display-name, --description, --value or --from-file")
		}
		if changeValue, err = c.ask(e, op, &ed); err != nil {
			return err
		}
	}
	if changeValue {
		if ed.Value, err = readValue(e, "New value for "+c.Name, c.FromFile); err != nil {
			return err
		}
		defer zero(ed.Value)
	}
	ch, err := op.host.Core.EditSecret(background(), op.call, ed)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.Stderr, "changed %s, %s\n", c.Name, visibility(ch))
	return nil
}

// ask shows a form prefilled with the secret's current metadata.
func (c *EditCmd) ask(e *Env, op *hostOp, ed *core.SecretEdit) (changeValue bool, err error) {
	dek, release, err := op.store.DEKFunc(op.host.Protector)(background())
	if err != nil {
		return false, err
	}
	metas, err := op.store.List(background(), dek)
	release()
	if err != nil {
		return false, err
	}
	i := slices.IndexFunc(metas, func(m plugin.SecretMeta) bool { return m.ID == ed.ID })
	if i < 0 {
		return false, fmt.Errorf("secret %q not found", c.Name)
	}
	m := metas[i]
	display, desc := m.DisplayName, m.Description
	f := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Display name").Value(&display),
		huh.NewInput().Title("Description").Value(&desc),
		huh.NewConfirm().Title("Change the value too?").Value(&changeValue),
	))
	if err := runForm(e, f); err != nil {
		return false, err
	}
	if display != m.DisplayName {
		ed.DisplayName = &display
	}
	if desc != m.Description {
		ed.Description = &desc
	}
	if ed.DisplayName == nil && ed.Description == nil && !changeValue {
		return false, errors.New("nothing changed")
	}
	return changeValue, nil
}

// ---- remove ----

type RemoveCmd struct {
	Name string `arg:"" help:"Secret to remove, <vault>:<secret>."`
}

func (c *RemoveCmd) Run(g *Globals, e *Env) error {
	vault, id, err := splitName(c.Name)
	if err != nil {
		return err
	}
	op, err := g.openHost(e, vault)
	if err != nil {
		return err
	}
	defer op.close()
	ch, err := op.host.Core.RemoveSecret(background(), op.call, op.vault, id)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("removed %s", c.Name)
	if len(ch.HiddenFrom) > 0 {
		msg += ", no longer visible to " + strings.Join(ch.HiddenFrom, ", ")
	}
	fmt.Fprintln(e.Stderr, msg)
	return nil
}

// splitName splits a secret's full name for a host command.
func splitName(name string) (vault, id string, err error) {
	vault, id, ok := secretname.Split(name)
	if !ok {
		return "", "", fmt.Errorf("invalid secret name %q: name secrets <vault>:<secret>", name)
	}
	return vault, id, nil
}
