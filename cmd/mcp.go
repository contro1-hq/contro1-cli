package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/mcpbridge"
	"github.com/contro1-hq/contro1-cli/internal/output"
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
	serve := &cobra.Command{Use: "serve", Short: "Forward MCP JSON-RPC between stdio and the remote server", RunE: func(_ *cobra.Command, _ []string) error {
		// An agent's own connection: the Contro1 service holds the credential.
		if raw := resolveBrokerEndpoint(); raw != "" {
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
	mcpCmd.AddCommand(login, status, logout, serve)
	rootCmd.AddCommand(mcpCmd)
}
