package cmd

import (
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

func init() {
	evidenceCmd := &cobra.Command{
		Use:     "evidence",
		Short:   "Retrieve audit-ready decision evidence",
		GroupID: groupAgent,
	}

	// Evidence packets are request-scoped; `get` and `for-request` are aliases
	// that fetch the signed evidence packet for a request id.
	evidenceCmd.AddCommand(&cobra.Command{
		Use:   "for-request <request_id>",
		Short: "Get the signed evidence packet for a request",
		Args:  cobra.ExactArgs(1),
		RunE:  runEvidenceForRequest,
	})
	evidenceCmd.AddCommand(&cobra.Command{
		Use:   "get <request_id>",
		Short: "Alias of for-request",
		Args:  cobra.ExactArgs(1),
		RunE:  runEvidenceForRequest,
	})

	rootCmd.AddCommand(evidenceCmd)
}

func runEvidenceForRequest(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/requests/"+args[0]+"/evidence", nil)
	if err != nil {
		return err
	}
	return output.Render(outFormat(pr), resp, nil)
}
