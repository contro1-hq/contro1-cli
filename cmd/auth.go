package cmd

import (
	"fmt"
	"os"

	"github.com/contro1-hq/contro1-cli/internal/auth"
	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/keychain"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	loginNoBrowser bool
	loginName      string
	loginPlaintext bool
	printTokenYes  bool
	whoamiScopes   bool
)

func init() {
	authCmd := &cobra.Command{
		Use:     "auth",
		Short:   "Authenticate and manage CLI access tokens",
		GroupID: groupCore,
	}

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Log in via the browser and store a scoped access token",
		Example: `  contro1 auth login
  contro1 auth login --no-browser
  contro1 auth login --name "Ariel Laptop"`,
		RunE: runLogin,
	}
	loginCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false, "print a URL to approve on another device instead of opening a browser")
	loginCmd.Flags().StringVar(&loginName, "name", "", "device/token name (defaults to hostname)")
	loginCmd.Flags().BoolVar(&loginPlaintext, "allow-plaintext-token-store", false, "store the token in a 0600 file instead of the OS keychain")

	logoutCmd := &cobra.Command{
		Use:   "logout",
		Short: "Revoke and remove the stored access token",
		RunE:  runLogout,
	}

	whoamiCmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show the current account, org and scopes",
		RunE:  runWhoami,
	}
	whoamiCmd.Flags().BoolVar(&whoamiScopes, "scopes", false, "list granted scopes")

	tokensCmd := &cobra.Command{Use: "tokens", Short: "List and revoke your CLI access tokens"}
	tokensCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List active CLI tokens",
		RunE:  runTokensList,
	})
	tokensCmd.AddCommand(&cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a CLI token by id",
		Args:  cobra.ExactArgs(1),
		RunE:  runTokensRevoke,
	})

	printTokenCmd := &cobra.Command{
		Use:   "print-access-token",
		Short: "Print the raw access token (sensitive)",
		Long: `Print the raw CLI access token to stdout.

Anyone with this token can act with your CLI scopes until it expires or is revoked.
For safety this refuses to run in an interactive terminal unless you pass --yes.
Intended for CI: contro1 auth print-access-token --yes | some-tool`,
		RunE: runPrintToken,
	}
	printTokenCmd.Flags().BoolVar(&printTokenYes, "yes", false, "confirm printing a live credential")

	authCmd.AddCommand(loginCmd, logoutCmd, whoamiCmd, tokensCmd, printTokenCmd)
	rootCmd.AddCommand(authCmd)
}

func runLogin(cmd *cobra.Command, _ []string) error {
	cfg, pr, name, err := loadCtx()
	if err != nil {
		return err
	}
	if flagAPIURL != "" {
		pr.APIURL = flagAPIURL
	}

	device := loginName
	if device == "" {
		if h, e := os.Hostname(); e == nil && h != "" {
			device = "contro1 CLI on " + h
		} else {
			device = "contro1 CLI"
		}
	}

	res, err := auth.Login(pr, device, Version, loginNoBrowser)
	if err != nil {
		return output.Errf(output.CodeAuth, "%v", err)
	}

	if err := keychain.Store(name, res.AccessToken, loginPlaintext); err != nil {
		return output.Errf(output.CodeGeneral, "storing token: %v", err)
	}

	pr.OperatorEmail = res.OperatorEmail
	pr.OrgName = res.OrgName
	pr.TokenID = res.TokenID
	pr.Scopes = res.Scopes
	if err := cfg.Save(); err != nil {
		return output.Errf(output.CodeGeneral, "saving config: %v", err)
	}

	infof("Logged in as %s (Org: %s)", res.OperatorEmail, res.OrgName)
	infof("Token stored for profile %q. Scopes: %d. Expires: %s", name, len(res.Scopes), res.ExpiresAt)
	return nil
}

func runLogout(_ *cobra.Command, _ []string) error {
	cfg, pr, name, err := loadCtx()
	if err != nil {
		return err
	}
	// Best-effort remote revoke of the active token.
	if pr.TokenID != "" {
		if c, _, e := newClient(); e == nil {
			_, _ = c.Do("DELETE", "/api/centcom/auth/cli/tokens/"+pr.TokenID, nil)
		}
	}
	_ = keychain.Delete(name)
	pr.OperatorEmail, pr.OrgName, pr.TokenID, pr.Scopes = "", "", "", nil
	_ = cfg.Save()
	infof("Logged out of profile %q.", name)
	return nil
}

func runWhoami(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/cli/whoami", nil)
	if err != nil {
		return err
	}
	data := client.Data(resp)
	if whoamiScopes && outFormat(pr) == "table" {
		authm := asMap(asMap(data)["auth"])
		for _, s := range asSlice(authm["scopes"]) {
			output.Info("  %s", str(s))
		}
	}
	return output.Render(outFormat(pr), data, whoamiTable(data))
}

func runTokensList(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/auth/cli/tokens", nil)
	if err != nil {
		return err
	}
	data := client.Data(resp)
	tbl := &output.Table{Headers: []string{"ID", "NAME", "PREFIX", "LAST USED", "EXPIRES"}}
	for _, item := range asSlice(data) {
		m := asMap(item)
		tbl.Rows = append(tbl.Rows, []string{
			str(m["id"]), str(m["name"]), str(m["token_prefix"]),
			str(m["last_used_at"]), str(m["expires_at"]),
		})
	}
	return output.Render(outFormat(pr), data, tbl)
}

func runTokensRevoke(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("DELETE", "/api/centcom/auth/cli/tokens/"+args[0], nil)
	if err != nil {
		return err
	}
	infof("Token %s revoked.", args[0])
	return output.Render(outFormat(pr), client.Data(resp), nil)
}

func runPrintToken(_ *cobra.Command, _ []string) error {
	_, _, name, err := loadCtx()
	if err != nil {
		return err
	}
	tok, err := resolveToken(name)
	if err != nil {
		return err
	}
	// Refuse to print a live credential into an interactive terminal unless the
	// user explicitly confirms with --yes.
	if isTerminal(os.Stdout) && !printTokenYes {
		return output.Errf(output.CodeBadArgs,
			"refusing to print a live token to a terminal. This prints a live CLI token; "+
				"anyone with it can act with your CLI scopes until it expires or is revoked. "+
				"Re-run with --yes (intended for CI, e.g. piping to another tool).")
	}
	fmt.Fprintln(os.Stderr, "warning: live CLI credential - do not share, paste or log it")
	fmt.Println(tok)
	return nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func whoamiTable(data any) *output.Table {
	m := asMap(data)
	op := asMap(m["operator"])
	org := asMap(m["org"])
	authm := asMap(m["auth"])
	return &output.Table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"operator", str(op["email"])},
			{"org", str(org["name"])},
			{"auth_type", str(authm["type"])},
			{"scopes", fmt.Sprintf("%d", len(asSlice(authm["scopes"])))},
		},
	}
}
