package cmd

import (
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

func init() {
	runtimeCmd := &cobra.Command{Use: "runtime", Short: "Inspect runtime Agent Credential status", GroupID: groupAgent}
	statusCmd := &cobra.Command{Use: "status", Short: "Show runtime credential status", RunE: runRuntimeStatus}
	runtimeCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(runtimeCmd)
}

func runRuntimeStatus(_ *cobra.Command, _ []string) error {
	c, pr, source, err := newRuntimeClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/runtime/status", nil)
	if err != nil {
		return err
	}
	resp["token_source"] = source
	return output.Render(outFormat(pr), resp, runtimeStatusTable(resp))
}

func runtimeStatusTable(m map[string]any) *output.Table {
	auth := asMap(m["auth"])
	org := asMap(m["org"])
	return &output.Table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"org", str(org["name"])},
			{"auth_type", str(auth["type"])},
			{"credential_kind", str(auth["credential_kind"])},
			{"agent_id", str(auth["agent_id"])},
			{"token_source", str(m["token_source"])},
		},
	}
}
