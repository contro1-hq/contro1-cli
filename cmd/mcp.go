package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/mcpbridge"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
	"github.com/spf13/cobra"
)

func init() {
	mcpCmd := &cobra.Command{
		Use: "mcp", Short: "Connect stdio clients to the Contro1 Remote MCP server", GroupID: groupAgent,
		Long: "OAuth credentials for MCP are stored separately from CLI API credentials. The local adapter forwards JSON-RPC only; policy, grants and Action execution remain on the remote server.",
	}
	var clientName string
	var allowExecute bool
	login := &cobra.Command{Use: "login", Short: "Authorize the local MCP adapter; approve on any device with a code", RunE: func(_ *cobra.Command, _ []string) error {
		_, profile, name, err := loadCtx()
		if err != nil {
			return err
		}
		apiURL := profile.APIURL
		if flagAPIURL != "" {
			apiURL = flagAPIURL
		}
		// The same line auth login and connect print: a person sign-in made
		// against a leftover localhost profile looked exactly like a real one.
		printDevelopmentServerNote(os.Stderr, flagAPIURL)
		credentials, err := mcpbridge.Login(apiURL, name, clientName, allowExecute)
		if err != nil {
			return err
		}
		infof("MCP connected for profile %s (%s).", name, strings.Join(strings.Fields(credentials.Scope), ", "))
		infof("See or disconnect it anytime in Contro1: Settings > Connected apps.")
		return nil
	}}
	login.Flags().StringVar(&clientName, "client-name", "contro1 CLI stdio adapter", "name shown on the OAuth consent screen")
	login.Flags().BoolVar(&allowExecute, "execute", false, "also ask to run Actions ("+mcpbridge.ExecuteScope+"); they run with your own authority and are recorded as yours")
	status := &cobra.Command{Use: "status", Short: "Show local MCP OAuth status", RunE: func(_ *cobra.Command, _ []string) error {
		_, _, name, err := loadCtx()
		if err != nil {
			return err
		}
		credentials, err := mcpbridge.Load(name)
		if err != nil {
			fmt.Fprintln(os.Stdout, "not logged in")
			return nil
		}
		state := "active"
		if time.Now().Unix() >= credentials.ExpiresAt {
			state = "access token expired; refresh available"
		}
		fmt.Fprintf(os.Stdout, "profile: %s\nstatus: %s\nclient_id: %s\nscopes: %s\n", name, state, credentials.ClientID, credentials.Scope)
		return nil
	}}
	logout := &cobra.Command{Use: "logout", Short: "Revoke and remove MCP OAuth credentials", RunE: func(_ *cobra.Command, _ []string) error {
		_, profile, name, err := loadCtx()
		if err != nil {
			return err
		}
		apiURL := profile.APIURL
		if flagAPIURL != "" {
			apiURL = flagAPIURL
		}
		if err := mcpbridge.Logout(apiURL, name); err != nil {
			return err
		}
		infof("MCP credentials revoked for profile %s.", name)
		return nil
	}}
	var mcpAgent string
	serve := &cobra.Command{Use: "serve", Short: "Forward MCP JSON-RPC between stdio and the remote server", RunE: func(_ *cobra.Command, _ []string) error {
		/*
		 * An agent's own connection is ALWAYS preferred, and it is found rather
		 * than configured.
		 *
		 * The endpoint was already written to this computer by `contro1
		 * connect`. Requiring a person to dig it out of a mapping file and paste
		 * it into a client config was the difference between the good path and
		 * the easy one, and people take the easy one: they fall back to the
		 * browser OAuth flow, which hands them a person-bound connection that is
		 * weaker than the agent-bound one they already had, without ever saying
		 * so. Reading the file is the whole fix.
		 *
		 * When no connection can be picked, the server does NOT exit. An exit
		 * shows up in OpenClaw as "MCP error -32000: Connection closed" and the
		 * reason, on stderr, reaches nobody. It serves one setup tool instead,
		 * whose description and result are the exact command to run.
		 */
		raw := resolveBrokerEndpoint()
		if raw == "" {
			connection, err := selectServeConnection(mcpAgent)
			switch {
			case err == nil:
				raw = connection.Endpoint
			case errors.Is(err, platforms.ErrNoLocalConnection) && strings.TrimSpace(mcpAgent) == "":
				// Nothing is connected here. A person sign-in from `contro1 mcp
				// login` is used only when someone set one up on purpose; it
				// is not a downgrade then, and without it there is nothing to
				// connect to, which the setup tool says.
				if personSignInConfigured() {
					return servePerson()
				}
				return serveSetupRequired(err, mcpAgent)
			default:
				// A named agent that does not exist, or several to choose from.
				// Falling through to OAuth would quietly connect as the PERSON
				// after they asked to act as an AGENT.
				return serveSetupRequired(err, mcpAgent)
			}
		}
		if anyEnvTokenConfigured() {
			return serveSetupMessage(twoIdentitiesRemediation.PublicMessage + " " + twoIdentitiesRemediation.NextStep)
		}
		ep, err := localipc.ParseEndpoint(raw)
		if err != nil {
			return serveSetupMessage(fmt.Sprintf("The Contro1 service endpoint %q is not valid (%v). Run contro1 doctor on this computer.", raw, err))
		}
		return mcpbridge.ServeViaEndpoint(localipc.HTTPClient(ep, brokerServerPrincipal()), localipc.BaseURL, os.Stdin, os.Stdout)
	}}
	serve.Flags().StringVar(&mcpAgent, "agent", "", "act as this agent (Contro1 agent id or the platform's own id); only needed when this computer has more than one connection")

	endpoint := &cobra.Command{
		Use:   "endpoint",
		Short: "Print the local endpoint for an agent's connection",
		Long: "For a client that cannot run `contro1 mcp serve` itself and needs the address. " +
			"Prefer `contro1 mcp serve`, which finds this without anyone copying anything.",
		RunE: func(_ *cobra.Command, _ []string) error {
			connection, err := platforms.SelectLocalConnection(mcpAgent)
			if err != nil {
				return output.Errf(output.CodeBadArgs, "%v", err)
			}
			fmt.Println(connection.Endpoint)
			return nil
		},
	}
	endpoint.Flags().StringVar(&mcpAgent, "agent", "", "Contro1 agent id or the platform's own id")

	mcpCmd.AddCommand(login, status, logout, serve, endpoint)
	rootCmd.AddCommand(mcpCmd)
}

// selectServeConnection is the connection `mcp serve` acts as: the named one,
// or the only one. Several and none named is the setup tool, never a guess,
// whatever process started this one.
func selectServeConnection(selector string) (platforms.LocalConnection, error) {
	return platforms.SelectLocalConnection(selector)
}

// personSignInConfigured reports whether `contro1 mcp login` stored a person
// sign-in for the active profile.
func personSignInConfigured() bool {
	_, _, name, err := loadCtx()
	if err != nil {
		return false
	}
	_, err = mcpbridge.Load(name)
	return err == nil
}

func servePerson() error {
	_, profile, name, err := loadCtx()
	if err != nil {
		return err
	}
	apiURL := profile.APIURL
	if flagAPIURL != "" {
		apiURL = flagAPIURL
	}
	return mcpbridge.Serve(apiURL, name, os.Stdin, os.Stdout)
}

func serveSetupRequired(cause error, selector string) error {
	connections, _ := platforms.LocalConnections()
	exe, _ := os.Executable()
	return serveSetupMessage(mcpSetupMessage(cause, selector, platforms.ClientPlatform(os.Getenv), connections, exe))
}

// serveSetupMessage keeps the server up and says the fix through MCP. The
// same sentence goes to stderr once, for a person running it in a terminal.
func serveSetupMessage(message string) error {
	fmt.Fprintln(os.Stderr, "contro1 mcp serve: "+message)
	return mcpbridge.ServeSetupRequired(message, Version, os.Stdin, os.Stdout)
}

/*
mcpSetupMessage is the one sentence an agent reads out when this server could
not pick a connection. It names the exact command, with a real agent id in it,
because the person reading it is in a chat with no other way to find one.

The OpenClaw line is there because its MCP servers are shared by every agent:
the fix is one server per agent plus tool rules between them, which `contro1
connect openclaw` writes through OpenClaw's own config paths. The server name
is the same sanitized one connect writes, so the rules match it.
*/
func mcpSetupMessage(cause error, selector, client string, connections []platforms.LocalConnection, exe string) string {
	selector = strings.TrimSpace(selector)
	if len(connections) == 0 {
		platform := client
		if platform == "" {
			platform = "<claude-code|cursor|codex|openclaw|nanoclaw>"
		}
		msg := "This computer is not connected to Contro1. Run contro1 connect " + platform + " on this computer, approve it in the browser, then restart this MCP server."
		if selector != "" {
			msg = fmt.Sprintf("No agent named %q is connected on this computer. ", selector) + msg
		}
		if cause != nil && !errors.Is(cause, platforms.ErrNoLocalConnection) {
			msg += " (" + cause.Error() + ")"
		}
		return msg
	}

	names := make([]string, 0, len(connections))
	samePlatform := true
	hasOpenClaw := false
	for _, c := range connections {
		if c.Platform != connections[0].Platform {
			samePlatform = false
		}
		if c.Platform == "openclaw" {
			hasOpenClaw = true
		}
	}
	for _, c := range connections {
		if samePlatform {
			names = append(names, c.PlatformSubject)
		} else {
			names = append(names, c.PlatformSubject+" ("+c.Platform+")")
		}
	}
	example := connections[0].PlatformSubject
	for _, c := range connections {
		if client != "" && c.Platform == client {
			example = c.PlatformSubject
			break
		}
	}

	var msg string
	switch {
	case selector != "":
		msg = fmt.Sprintf("No agent named %q is connected on this computer. Connected here: %s. Start this server with --agent <id>, e.g. contro1 mcp serve --agent %s", selector, strings.Join(names, ", "), example)
	case len(connections) == 1:
		msg = fmt.Sprintf("The agent connected on this computer is %s. Start this server with --agent %s, e.g. contro1 mcp serve --agent %s", names[0], example, example)
	default:
		msg = fmt.Sprintf("Several agents are connected on this computer: %s. Start this server with --agent <id>, e.g. contro1 mcp serve --agent %s", strings.Join(names, ", "), example)
	}
	if hasOpenClaw {
		if exe == "" {
			exe = "contro1"
		}
		openclawExample := example
		for _, c := range connections {
			if c.Platform == "openclaw" {
				openclawExample = c.PlatformSubject
				break
			}
		}
		msg += fmt.Sprintf(". For OpenClaw, run contro1 connect openclaw: it gives each agent its own server (%s runs %s mcp serve --agent %s) and the tool rules that keep the agents apart, and OpenClaw loads them without a restart", platforms.OpenClawServerName(openclawExample), exe, openclawExample)
	}
	return msg
}
