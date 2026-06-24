package cmd

import (
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

func init() {
	tracesCmd := &cobra.Command{
		Use:     "traces",
		Short:   "Inspect agent execution traces",
		GroupID: groupAgent,
	}

	tracesCmd.AddCommand(&cobra.Command{
		Use:   "get <trace_id>",
		Short: "Get a full execution trace",
		Args:  cobra.ExactArgs(1),
		RunE:  runTraceGet,
	})
	tracesCmd.AddCommand(&cobra.Command{
		Use:   "for-request <request_id>",
		Short: "Get the trace linked to a request",
		Args:  cobra.ExactArgs(1),
		RunE:  runTraceForRequest,
	})
	tracesCmd.AddCommand(&cobra.Command{
		Use:   "for-agent <agent_id>",
		Short: "Show an agent's recent action trail",
		Args:  cobra.ExactArgs(1),
		RunE:  runAgentTrail,
	})

	rootCmd.AddCommand(tracesCmd)
}

func runTraceGet(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/traces/"+args[0], nil)
	if err != nil {
		return err
	}
	return output.Render(outFormat(pr), resp, nil)
}

func runTraceForRequest(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	reqResp, err := c.Do("GET", "/api/centcom/v1/requests/"+args[0], nil)
	if err != nil {
		return err
	}
	traceID := str(reqResp["trace_id"])
	if traceID == "" {
		return output.Errf(output.CodeGeneral, "request %s has no linked trace", args[0])
	}
	resp, err := c.Do("GET", "/api/centcom/v1/traces/"+traceID, nil)
	if err != nil {
		return err
	}
	return output.Render(outFormat(pr), resp, nil)
}
