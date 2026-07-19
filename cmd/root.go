// Package cmd defines the contro1 CLI command tree (Cobra), grouped by topic so
// `contro1 help` lists capabilities by area.
package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/keychain"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

// Version is set from main at startup.
var Version = "dev"

// Global flags.
var (
	flagFormat  string
	flagProfile string
	flagAPIURL  string
	flagQuiet   bool
)

// Command groups (topics) for `contro1 help`.
const (
	groupCore  = "core"
	groupAgent = "agent"
	groupAdmin = "admin"
	groupQueue = "queue"
)

var rootCmd = &cobra.Command{
	Use:   "contro1",
	Short: "Contro1 CLI - approvals, routing and evidence for AI agents",
	Long: `contro1 brings Contro1 approvals, routing checks and evidence into the
terminal workflows where AI agents and developers already work.

Register agents, preview Control Map routing, create role-based approval
requests, enforce quorum, wait for decisions, update AI inventory, and retrieve
audit-ready evidence - all with a scoped, browser-issued token.

For coding agents and developer workflows, contro1 can also gate a local command
before it runs.

Get started:
  contro1 auth login
  contro1 init --name "Claude Code - Laptop"
  contro1 requests create --type approval --question "Approve this action?" --wait
  contro1 ask "Which region should I use?" --wait --format json`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute runs the root command and returns a process exit code.
func Execute() int {
	// Wire the version (set from main after init) so `contro1 --version` works.
	rootCmd.Version = Version
	if err := rootCmd.Execute(); err != nil {
		var ee *output.ExitError
		if asExit(err, &ee) {
			fmt.Fprintln(os.Stderr, "error: "+ee.Msg)
			return ee.Code
		}
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		// Cobra usage errors (bad flags/args/unknown command) map to exit 2.
		if isUsageError(err.Error()) {
			return output.CodeBadArgs
		}
		return output.CodeGeneral
	}
	return output.CodeOK
}

// isUsageError detects Cobra's argument/flag/usage error messages so they map to
// the documented "bad arguments" exit code (2) rather than a general error.
func isUsageError(msg string) bool {
	for _, p := range []string{
		"unknown command",
		"unknown flag",
		"unknown shorthand flag",
		"required flag",
		"invalid argument",
		"flag needs an argument",
		"accepts ",
		"requires at least",
		"requires exactly",
		"requires between",
	} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagFormat, "format", "", "output format: table|json|yaml")
	rootCmd.PersistentFlags().StringVar(&flagProfile, "profile", "", "configuration profile to use")
	rootCmd.PersistentFlags().StringVar(&flagAPIURL, "api-url", "", "override the API base URL")
	rootCmd.PersistentFlags().BoolVar(&flagQuiet, "quiet", false, "suppress status messages")

	rootCmd.AddGroup(
		&cobra.Group{ID: groupCore, Title: "Core:"},
		&cobra.Group{ID: groupAgent, Title: "Agent workflows:"},
		&cobra.Group{ID: groupAdmin, Title: "Read-only admin:"},
		&cobra.Group{ID: groupQueue, Title: "Operator queue:"},
	)
}

// ---- shared helpers ----

func userAgent() string {
	return fmt.Sprintf("contro1-cli/%s (%s)", Version, runtime.GOOS)
}

// outFormat resolves the effective output format.
func outFormat(pr *config.Profile) string {
	if flagFormat != "" {
		return flagFormat
	}
	if pr != nil && pr.OutputFormat != "" {
		return pr.OutputFormat
	}
	if os.Getenv("CI") != "" {
		return "json"
	}
	return "table"
}

// loadCtx loads config + the active profile + its name.
func loadCtx() (*config.Config, *config.Profile, string, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, "", output.Errf(output.CodeGeneral, "loading config: %v", err)
	}
	name := cfg.ActiveName(flagProfile)
	pr := cfg.Profile(name)
	return cfg, pr, name, nil
}

// resolveToken returns the bearer token: CONTRO1_TOKEN env wins, else the keychain.
func resolveToken(profileName string) (string, error) {
	if tok := os.Getenv("CONTRO1_TOKEN"); tok != "" {
		return tok, nil
	}
	tok, err := keychain.Retrieve(profileName)
	if err != nil {
		return "", output.Errf(output.CodeAuth, "%v", err)
	}
	return tok, nil
}

// newClient builds an authenticated client for the active profile.
func newClient() (*client.Client, *config.Profile, error) {
	_, pr, name, err := loadCtx()
	if err != nil {
		return nil, nil, err
	}
	if pr.AccessProfile == "operator" && os.Getenv("CONTRO1_TOKEN") != "" {
		return nil, nil, output.Errf(output.CodeAuth, "operator mode requires an interactive browser-issued profile; CONTRO1_TOKEN is only supported for agent/CI use")
	}
	apiURL := pr.APIURL
	if flagAPIURL != "" {
		apiURL = flagAPIURL
	}
	tok, err := resolveToken(name)
	if err != nil {
		return nil, nil, err
	}
	return client.New(apiURL, tok, userAgent()), pr, nil
}

func infof(format string, args ...any) {
	if suppressInfo(flagFormat, flagQuiet, os.Getenv("CI") != "") {
		return
	}

	output.Info(format, args...)
}

func suppressInfo(format string, quiet bool, ci bool) bool {
	if quiet || ci {
		return true
	}
	switch strings.ToLower(format) {
	case "json", "yaml":
		return true
	}
	return false
}

// asExit is a tiny errors.As wrapper kept local to avoid importing errors widely.
func asExit(err error, target **output.ExitError) bool {
	if e, ok := err.(*output.ExitError); ok {
		*target = e
		return true
	}
	return false
}
