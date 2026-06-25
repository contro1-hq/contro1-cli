// Command contro1 exposes Contro1 approval, routing, inventory and evidence
// workflows to terminals, scripts, CI jobs and coding agents.
//
// It lets developers and agents register identities, preview Control Map
// routing, create role-based approval requests, enforce quorum, wait for
// decisions, update inventory, and retrieve audit-ready evidence using a scoped,
// browser-issued token.
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
