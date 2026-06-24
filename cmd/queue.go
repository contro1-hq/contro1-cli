package cmd

import (
	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

func init() {
	queueCmd := &cobra.Command{
		Use:     "queue",
		Short:   "View the approval queue",
		GroupID: groupQueue,
	}
	queueCmd.AddCommand(&cobra.Command{Use: "list", Short: "List open requests", RunE: runQueueList})
	queueCmd.AddCommand(&cobra.Command{Use: "my-requests", Short: "List requests assigned to you", RunE: runMyRequests})
	queueCmd.AddCommand(&cobra.Command{
		Use:   "get <id>",
		Short: "Show one request",
		Args:  cobra.ExactArgs(1),
		RunE:  runRequestGet,
	})
	rootCmd.AddCommand(queueCmd)
}

func renderQueue(pr *config.Profile, items []any) error {
	tbl := &output.Table{Headers: []string{"ID", "TYPE", "STATE", "PRIORITY", "QUESTION"}}
	for _, it := range items {
		m := asMap(it)
		tbl.Rows = append(tbl.Rows, []string{
			str(m["id"]), str(m["type"]), str(m["state"]), str(m["priority"]), truncate(str(m["question"]), 40),
		})
	}
	return output.Render(outFormat(pr), items, tbl)
}

func runQueueList(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/cli/queue", nil)
	if err != nil {
		return err
	}
	return renderQueue(pr, asSlice(client.Data(resp)))
}

func runMyRequests(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/cli/my-requests", nil)
	if err != nil {
		return err
	}
	return renderQueue(pr, asSlice(client.Data(resp)))
}
