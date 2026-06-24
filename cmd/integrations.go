package cmd

import (
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
)

func init() {
	integrationsCmd := &cobra.Command{
		Use:     "integrations",
		Short:   "View integration connection status (read-only in v1)",
		GroupID: groupAdmin,
	}

	integrationsCmd.AddCommand(&cobra.Command{Use: "list", Short: "Show all integration statuses", RunE: runIntegrationsList})
	integrationsCmd.AddCommand(integrationProvider("slack", "Slack"))
	integrationsCmd.AddCommand(integrationProvider("teams", "Microsoft Teams"))
	integrationsCmd.AddCommand(integrationProvider("microsoft", "Microsoft"))
	integrationsCmd.AddCommand(&cobra.Command{
		Use:   "open-install",
		Short: "Open the dashboard integrations page to install an integration",
		RunE:  runIntegrationsOpenInstall,
	})

	rootCmd.AddCommand(integrationsCmd)
}

func fetchIntegrations(c *client.Client) (map[string]any, error) {
	resp, err := c.Do("GET", "/api/centcom/v1/cli/integrations", nil)
	if err != nil {
		return nil, err
	}
	return asMap(client.Data(resp)), nil
}

func runIntegrationsList(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	data, err := fetchIntegrations(c)
	if err != nil {
		return err
	}
	tbl := &output.Table{Headers: []string{"INTEGRATION", "CONNECTED", "DETAIL"}}
	for _, name := range []string{"slack", "microsoft", "teams"} {
		m := asMap(data[name])
		detail := str(firstNonEmpty(m["team_name"], m["tenant_name"]))
		tbl.Rows = append(tbl.Rows, []string{name, str(m["connected"]), detail})
	}
	return output.Render(outFormat(pr), data, tbl)
}

func integrationProvider(name, label string) *cobra.Command {
	provider := &cobra.Command{Use: name, Short: label + " integration"}
	provider.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show " + label + " connection status",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, pr, err := newClient()
			if err != nil {
				return err
			}
			data, err := fetchIntegrations(c)
			if err != nil {
				return err
			}
			m := asMap(data[name])
			return output.Render(outFormat(pr), m, &output.Table{
				Headers: []string{"FIELD", "VALUE"},
				Rows: [][]string{
					{"integration", name},
					{"connected", str(m["connected"])},
					{"detail", str(firstNonEmpty(m["team_name"], m["tenant_name"]))},
				},
			})
		},
	})
	return provider
}

func runIntegrationsOpenInstall(_ *cobra.Command, _ []string) error {
	_, pr, _, err := loadCtx()
	if err != nil {
		return err
	}
	url := strings.TrimRight(pr.WebURL, "/") + "/settings/integrations"
	infof("Opening %s", url)
	_ = browser.OpenURL(url)
	return nil
}
