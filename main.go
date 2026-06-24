// Command contro1 is the official CLI for the Contro1 Human Approval Layer.
//
// It lets developers and AI coding agents work through Contro1 in practice:
// register agents, create and wait for approval requests, run gated commands,
// and retrieve audit-ready evidence - using a scoped, browser-issued token.
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
