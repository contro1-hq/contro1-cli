// Package cmd defines the contro1 CLI command tree (Cobra), grouped by topic so
// `contro1 help` lists capabilities by area.
package cmd

import (
	"fmt"
	"os"
	"runtime"

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
	groupCore    = "core"
	groupAgent   = "agent"
	groupAdmin   = "admin"
	groupQueue   = "queue"
)

var rootCmd = &cobra.Command{
	Use:   "contro1",
	Short: "Contro1 CLI - human approval layer for AI workflows",
	Long: `contro1 is the official CLI for the Contro1 Human Approval Layer.

Register agents, create and wait for approval requests, run gated commands, and
retrieve audit-ready evidence - all with a scoped, browser-issued token.

Get started:
  contro1 auth login
  contro1 whoami
  contro1 run --requires-approval -- npm run deploy`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute runs the root command and returns a process exit code.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		var ee *output.ExitError
		if asExit(err, &ee) {
			fmt.Fprintln(os.Stderr, "error: "+ee.Msg)
			return ee.Code
		}
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return output.CodeGeneral
	}
	return output.CodeOK
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
	if !flagQuiet {
		output.Info(format, args...)
	}
}

// asExit is a tiny errors.As wrapper kept local to avoid importing errors widely.
func asExit(err error, target **output.ExitError) bool {
	if e, ok := err.(*output.ExitError); ok {
		*target = e
		return true
	}
	return false
}
