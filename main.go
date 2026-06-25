// Command contro1 is the official developer CLI for connecting AI agents to
// Contro1.
//
// It lets developers and AI coding agents register agents, create and wait for
// approval requests, update inventory, and retrieve audit-ready evidence using a
// scoped, browser-issued token. Coding agents can also gate local commands when
// a shell step is the action being controlled.
package main

import (
	"os"

	"github.com/contro1-hq/contro1-cli/cmd"
)

// version is overridden at build time via -ldflags "-X main.version=..."
var version = "0.1.0"

func main() {
	cmd.Version = version
	os.Exit(cmd.Execute())
}
