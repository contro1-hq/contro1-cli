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
	login := &cobra.Command{Use: "login", Short: "Authorize the local MCP adapter with OAuth 2.1 + PKCE", RunE: func(_ *cobra.Command, _ []string) error {
		_, profile, name, err := loadCtx()
		if err != nil {
			return err
		}
		apiURL := profile.APIURL
		if flagAPIURL != "" {
			apiURL = flagAPIURL
		}
		credentials, err := mcpbridge.Login(apiURL, name, clientName)
		if err != nil {
			return err
		}
		infof("MCP connected for profile %s (%s).", name, strings.Join(strings.Fields(credentials.Scope), ", "))
		infof("See or disconnect it anytime in Contro1: Settings > Connected apps.")
		return nil
	}}
	login.Flags().StringVar(&clientName, "client-name", "contro1 CLI stdio adapter", "name shown on the OAuth consent screen")
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
		 */
		raw := resolveBrokerEndpoint()
		if raw == "" {
			connection, err := platforms.SelectLocalConnection(mcpAgent)
			switch {
			case err == nil:
				raw = connection.Endpoint
			case errors.Is(err, platforms.ErrNoLocalConnection):
				// Nothing is connected here, so the OAuth path below is the only
				// one available and is not a downgrade.
			default:
				// A named agent that does not exist, or several to choose from.
				// Falling through to OAuth would quietly connect as the PERSON
				// after they asked to act as an AGENT.
				return output.Errf(output.CodeBadArgs, "%v", err)
			}
		}
		if raw != "" {
			if anyEnvTokenConfigured() {
				return output.Errf(output.CodeUnsafeBlocked, "a Contro1 service endpoint and a runtime token are both configured").WithRemediation(&twoIdentitiesRemediation)
			}
			ep, err := localipc.ParseEndpoint(raw)
			if err != nil {
				return output.Errf(output.CodeBadArgs, "%v", err)
			}
			return mcpbridge.ServeViaEndpoint(localipc.HTTPClient(ep, brokerServerPrincipal()), localipc.BaseURL, os.Stdin, os.Stdout)
		}
		_, profile, name, err := loadCtx()
		if err != nil {
			return err
		}
		apiURL := profile.APIURL
		if flagAPIURL != "" {
			apiURL = flagAPIURL
		}
		return mcpbridge.Serve(apiURL, name, os.Stdin, os.Stdout)
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
