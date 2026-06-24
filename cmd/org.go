package cmd

import (
	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

func init() {
	orgCmd := &cobra.Command{
		Use:     "org",
		Short:   "Read organization profile",
		GroupID: groupAdmin,
	}
	orgCmd.AddCommand(&cobra.Command{
		Use:   "get",
		Short: "Show organization profile (read-only)",
		RunE:  runOrgGet,
	})
	rootCmd.AddCommand(orgCmd)
}

func runOrgGet(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/cli/org", nil)
	if err != nil {
		return err
	}
	data := asMap(client.Data(resp))
	tbl := &output.Table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"id", str(data["id"])},
			{"name", str(data["name"])},
			{"tier", str(data["subscription_tier"])},
			{"departments", itoa(len(asSlice(data["departments"])))},
			{"roles", itoa(len(asSlice(data["roles"])))},
		},
	}
	return output.Render(outFormat(pr), data, tbl)
}
