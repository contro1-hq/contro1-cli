package cmd

import (
	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

func init() {
	webhooksCmd := &cobra.Command{
		Use:     "webhooks",
		Short:   "Read webhook configuration and delivery logs (read-only in v1)",
		GroupID: groupAdmin,
	}
	webhooksCmd.AddCommand(&cobra.Command{Use: "status", Short: "Show webhook configuration status", RunE: runWebhooksStatus})
	webhooksCmd.AddCommand(&cobra.Command{Use: "logs", Short: "Show recent webhook deliveries", RunE: runWebhooksLogs})
	rootCmd.AddCommand(webhooksCmd)
}

func fetchWebhooks(c *client.Client) (map[string]any, error) {
	resp, err := c.Do("GET", "/api/centcom/v1/cli/webhooks", nil)
	if err != nil {
		return nil, err
	}
	return asMap(client.Data(resp)), nil
}

func runWebhooksStatus(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	data, err := fetchWebhooks(c)
	if err != nil {
		return err
	}
	tbl := &output.Table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"configured", str(data["configured"])},
			{"secret_revealed_at", str(data["secret_revealed_at"])},
			{"recent_deliveries", itoa(len(asSlice(data["recent_deliveries"])))},
		},
	}
	return output.Render(outFormat(pr), data, tbl)
}

func runWebhooksLogs(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	data, err := fetchWebhooks(c)
	if err != nil {
		return err
	}
	logs := asSlice(data["recent_deliveries"])
	tbl := &output.Table{Headers: []string{"REQUEST", "EVENT", "STATUS", "CODE", "TIME"}}
	for _, l := range logs {
		m := asMap(l)
		tbl.Rows = append(tbl.Rows, []string{
			str(m["request_id"]), str(m["event"]), str(m["status"]), str(m["status_code"]), str(m["timestamp"]),
		})
	}
	return output.Render(outFormat(pr), logs, tbl)
}
