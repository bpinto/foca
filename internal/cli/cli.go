// Package cli is the foca command line: the service (serve), host
// management (init, add, edit, remove, reload, stop) and the socket client
// (list, get, run) that also runs inside realms.
//
// Interaction rules (design D21): prompts appear only when stdin and stderr
// are terminals, and draw on stderr so stdout stays clean. Secret values are
// read only from a hidden prompt, stdin or a file, never from a flag or
// argument, and are written only to a pipe, a 0600 file or a child's
// environment, never to a terminal.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/charmbracelet/huh"
	"golang.org/x/term"

	"github.com/bpinto/foca/internal/config"
)

// Env is everything the CLI touches outside its own memory, so tests can run
// commands in-process.
type Env struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// Whether each stream is a terminal.
	StdinTTY, StdoutTTY, StderrTTY bool
	Getenv                         func(string) string
	// ReadPassword reads one line from the terminal without echo.
	ReadPassword func() ([]byte, error)
	// Form runs an interactive form on the terminal.
	Form func(*huh.Form) error
	// Exec replaces the process (run).
	Exec func(path string, argv, env []string) error
	// Signals receives the signals serve handles; nil means the real ones.
	Signals func(chan<- os.Signal)
	// Harden keeps other processes from inspecting this one, for the
	// commands that hold vault keys or values (hardened). nil does nothing,
	// so in-process tests run unaltered.
	Harden func() error
}

// OSEnv is the real process environment.
func OSEnv() *Env {
	return &Env{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		StdinTTY:  term.IsTerminal(int(os.Stdin.Fd())),
		StdoutTTY: term.IsTerminal(int(os.Stdout.Fd())),
		StderrTTY: term.IsTerminal(int(os.Stderr.Fd())),
		Getenv:    os.Getenv,
		ReadPassword: func() ([]byte, error) {
			return term.ReadPassword(int(os.Stdin.Fd()))
		},
		Form: func(f *huh.Form) error {
			return f.WithInput(os.Stdin).WithOutput(os.Stderr).Run()
		},
		Exec:   syscall.Exec,
		Harden: harden,
	}
}

// interactive reports whether prompts are allowed.
func (e *Env) interactive() bool { return e.StdinTTY && e.StderrTTY }

// notify delivers the signals serve handles to ch until stop is called.
func (e *Env) notify(ch chan<- os.Signal) (stop func()) {
	if e.Signals != nil {
		e.Signals(ch)
		return func() {}
	}
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	return func() { signal.Stop(ch) }
}

// Globals are flags every command accepts.
type Globals struct {
	Config     string `help:"Config file (env FOCA_CONFIG)." placeholder:"FILE"`
	DataDir    string `help:"Data directory (env FOCA_DATA_DIR)." placeholder:"DIR"`
	RuntimeDir string `help:"Runtime directory for sockets (env FOCA_RUNTIME_DIR)." placeholder:"DIR"`
	Socket     string `help:"Client socket to use (env FOCA_SOCK)." placeholder:"PATH"`
	Instance   string `short:"i" help:"Instance whose socket to use on the host (env FOCA_INSTANCE)."`

	version string
}

type CLI struct {
	Globals

	Serve   ServeCmd   `cmd:"" help:"Run the service for every instance in the config."`
	Init    InitCmd    `cmd:"" help:"Create an encrypted vault (host)."`
	Add     AddCmd     `cmd:"" help:"Add a secret to a vault (host)."`
	Edit    EditCmd    `cmd:"" help:"Change a secret's value or metadata (host)."`
	Remove  RemoveCmd  `cmd:"" aliases:"rm" help:"Remove a secret from a vault (host)."`
	List    ListCmd    `cmd:"" aliases:"ls" help:"List the secrets this realm can see."`
	Get     GetCmd     `cmd:"" help:"Read secrets to a pipe or a file."`
	Run     RunCmd     `cmd:"" help:"Run a command with secrets in its environment."`
	Reload  ReloadCmd  `cmd:"" help:"Make the running service reload its config (host)."`
	Stop    StopCmd    `cmd:"" help:"Stop the running service (host)."`
	Version VersionCmd `cmd:"" help:"Print the version."`
}

type exitCode int

// Parser builds the command-line parser. Tests use it to inspect the model.
func Parser(cli *CLI, e *Env) (*kong.Kong, error) {
	return kong.New(cli,
		kong.Name("foca"),
		kong.Description("Approval-gated credentials for processes, VMs and containers."),
		kong.Writers(e.Stdout, e.Stderr),
		kong.Exit(func(code int) { panic(exitCode(code)) }),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
	)
}

// Main runs the CLI and returns the process exit code.
func Main(args []string, e *Env, version string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			c, ok := r.(exitCode)
			if !ok {
				panic(r)
			}
			code = int(c)
		}
	}()
	cli := &CLI{Globals: Globals{version: version}}
	k, err := Parser(cli, e)
	if err != nil {
		fmt.Fprintln(e.Stderr, "foca:", err)
		return 2
	}
	kctx, err := k.Parse(args)
	if err != nil {
		k.Errorf("%s", err)
		return 2
	}
	if hardened[strings.Fields(kctx.Command())[0]] && e.Harden != nil {
		// Before anything is read: refuse rather than run exposed.
		if err := e.Harden(); err != nil {
			fmt.Fprintln(e.Stderr, "foca: can't keep this process private:", err)
			return 1
		}
	}
	if err := kctx.Run(&cli.Globals, e); err != nil {
		fmt.Fprintln(e.Stderr, "foca:", err)
		return 1
	}
	return 0
}

func (g *Globals) paths(e *Env) (config.Paths, error) {
	return config.ResolvePaths(config.Overrides{Config: g.Config, DataDir: g.DataDir, RuntimeDir: g.RuntimeDir}, e.Getenv)
}

func (g *Globals) load(e *Env) (*config.Config, config.Paths, error) {
	paths, err := g.paths(e)
	if err != nil {
		return nil, paths, err
	}
	cfg, err := config.Load(paths.Config)
	return cfg, paths, err
}

func logger(e *Env, level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(e.Stderr, &slog.HandlerOptions{Level: level}))
}

type VersionCmd struct{}

func (VersionCmd) Run(g *Globals, e *Env) error {
	fmt.Fprintln(e.Stdout, "foca", g.version)
	return nil
}

// errAborted is returned when the user leaves an interactive form.
var errAborted = errors.New("aborted")

func runForm(e *Env, f *huh.Form) error {
	if err := e.Form(f); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return errAborted
		}
		return err
	}
	return nil
}

var background = context.Background

// hardened are the commands that hold vault keys or values in memory: the
// service, and the host commands that unseal a vault. Socket clients aren't
// among them: the service identifies them through /proc, which a hardened
// process hides.
var hardened = map[string]bool{"serve": true, "init": true, "add": true, "edit": true, "remove": true}
