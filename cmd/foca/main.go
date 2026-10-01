// Command foca runs the foca service (foca serve).
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/server/wiring"
)

var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "version", "--version":
		fmt.Println("foca", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "foca: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "foca:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: foca <command> [flags]

commands:
  serve     run the service for every instance in the config
  version   print the version
`)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var o config.Overrides
	fs.StringVar(&o.Config, "config", "", "config file (env FOCA_CONFIG)")
	fs.StringVar(&o.DataDir, "data-dir", "", "data directory (env FOCA_DATA_DIR)")
	fs.StringVar(&o.RuntimeDir, "runtime-dir", "", "runtime directory for sockets (env FOCA_RUNTIME_DIR)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New("serve takes no arguments")
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	paths, err := config.ResolvePaths(o, os.Getenv)
	if err != nil {
		return err
	}
	cfg, err := config.Load(paths.Config)
	if err != nil {
		return err
	}
	b, err := wiring.Build(cfg, paths, version, log)
	if err != nil {
		return err
	}
	defer b.Audit.Close()
	if err := b.Server.Start(); err != nil {
		return err
	}
	for _, inst := range cfg.Instances {
		log.Info("serving", "instance", inst.Name, "realm", inst.Realm.Kind, "socket", paths.ClientSocket(inst.Name))
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		b.Server.Shutdown("signal " + s.String())
	case <-b.Server.Done():
	}
	<-b.Server.Done()
	return nil
}
