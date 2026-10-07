// Command foca is both the service (foca serve) and the CLI.
package main

import (
	"os"

	"github.com/bpinto/foca/internal/cli"
)

var version = "0.1.0-dev"

func main() {
	os.Exit(cli.Main(os.Args[1:], cli.OSEnv(), version))
}
