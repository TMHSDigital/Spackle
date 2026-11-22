// Command spackle is an agentic security and debugging tool for systems the
// operator owns or is authorized to test.
package main

import (
	"os"

	"github.com/TMHSDigital/spackle/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
