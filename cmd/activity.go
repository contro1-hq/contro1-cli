package cmd

import (
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var activityPayloadFile string

func init() {
	activityCmd := &cobra.Command{Use: "activity", Short: "Report runtime activity with an Agent Credential", GroupID: groupAgent}
	reportCmd := &cobra.Command{Use: "report", Short: "Report a runtime activity/audit event", RunE: runActivityReport}
	reportCmd.Flags().StringVar(&activityPayloadFile, "file", "", "read the activity JSON body from a file, or '-' for stdin")
	_ = reportCmd.MarkFlagRequired("file")
	activityCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(activityCmd)
}

func runActivityReport(_ *cobra.Command, _ []string) error {
	body, err := readJSONMap(activityPayloadFile, "activity")
	if err != nil {
		return err
	}
	c, pr, _, err := newRuntimeClient()
	if err != nil {
		return err
	}
	if _, err := requireRuntimeStatus(c, "audit:write"); err != nil {
		return err
	}
	resp, err := c.Do("POST", "/api/centcom/v1/audit-records", body)
	if err != nil {
		return err
	}
	return output.Render(outFormat(pr), resp, nil)
}
