package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

// The bootstrap package is the one artifact handed to an agent by hand.
// Everything else it learns at runtime.
//
// It deliberately carries NO credential and NO skill bodies. That is not
// minimalism, it is the reason the file can be checked into a repository at
// all: a bootstrap package gets copied into repos, prompt templates, onboarding
// docs and support tickets, and nobody ever revokes a config file. Anything it
// contains, it eventually publishes.

var (
	bootstrapOut          string
	bootstrapMCPOnly      bool
	bootstrapMCPTransport string
)

func init() {
	bootstrapCmd := &cobra.Command{
		Use:     "bootstrap",
		Short:   "Get the connection package a new agent needs",
		GroupID: groupAgent,
		Long: `Prints the bootstrap package: where the Contro1 MCP server is, how to
authenticate to it, how often to synchronize skills, and one short skill
explaining that Contro1 decides what this agent may do.

Safe to commit. It contains no credentials and no skill bodies - only pointers.
Your organization's actual instructions are fetched per agent, authenticated,
and revocable; they are deliberately not in this file, because this file is the
one that gets copied around.`,
		Example: `  contro1 bootstrap
  contro1 bootstrap --out .contro1/bootstrap.json
  contro1 bootstrap --mcp-only --out .mcp.json`,
		RunE: runBootstrap,
	}
	bootstrapCmd.Flags().StringVar(&bootstrapOut, "out", "", "write to a file instead of stdout")
	bootstrapCmd.Flags().BoolVar(&bootstrapMCPOnly, "mcp-only", false,
		"emit only the MCP server entry, in the shape most clients expect")
	bootstrapCmd.Flags().StringVar(&bootstrapMCPTransport, "mcp-transport", "remote",
		"MCP config transport: remote|stdio")

	rootCmd.AddCommand(bootstrapCmd)
}

func runBootstrap(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/skills/bootstrap", nil)
	if err != nil {
		return err
	}
	pkg := asMap(resp["bootstrap"])
	if len(pkg) == 0 {
		return fmt.Errorf("the server returned no bootstrap package")
	}

	payload := pkg
	if bootstrapMCPOnly {
		if bootstrapMCPTransport != "remote" && bootstrapMCPTransport != "stdio" {
			return fmt.Errorf("--mcp-transport must be remote or stdio")
		}
		mcp := asMap(pkg["mcp"])
		auth := asMap(mcp["authorization"])
		entry := map[string]any{
			"type":                   "http",
			"url":                    str(mcp["url"]),
			"authorization_metadata": str(auth["metadata_url"]),
		}
		if bootstrapMCPTransport == "stdio" {
			entry = map[string]any{"command": "contro1", "args": []string{"mcp", "serve"}}
		}
		payload = map[string]any{
			"mcpServers": map[string]any{
				"contro1": entry,
			},
		}
	}

	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')

	if bootstrapOut == "" {
		fmt.Print(string(encoded))
		if !bootstrapMCPOnly {
			printBootstrapNotes(pkg)
		}
		return nil
	}

	if dir := filepath.Dir(bootstrapOut); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// 0644, not 0600. Marking a file that holds no secret as private tells the
	// next reader it holds one, and that reader will eventually put a secret in
	// it to match.
	if err := os.WriteFile(bootstrapOut, encoded, 0o644); err != nil {
		return err
	}
	infof("Wrote %s (%s).", bootstrapOut, str(pkg["digest"]))
	if !bootstrapMCPOnly {
		printBootstrapNotes(pkg)
	}
	return output.Render(outFormat(pr), map[string]any{
		"path":   bootstrapOut,
		"digest": str(pkg["digest"]),
	}, nil)
}

// The two things an operator gets wrong if nobody says them: that this file is
// safe to commit, and that the sync interval has nothing to do with revocation.
func printBootstrapNotes(pkg map[string]any) {
	sync := asMap(pkg["synchronization"])
	interval := "daily"
	if v, ok := sync["recommended_interval_seconds"].(float64); ok && v > 0 {
		interval = fmt.Sprintf("every %.0f hours", v/3600)
	}
	infof("Safe to commit: no credentials, no skill bodies. Skills sync %s from %s.",
		interval, strings.TrimPrefix(str(sync["manifest_url"]), "https://"))
	infof("Sync timing is about load, not permissions - revoking access takes " +
		"effect at the gateway on the agent's next call.")
}
