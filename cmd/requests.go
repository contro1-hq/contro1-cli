package cmd

import (
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	reqType        string
	reqQuestion    string
	reqContext     string
	reqAgent       string
	reqRisk        string
	reqReason      string
	reqPriority    string
	reqCallbackURL string
	reqWait        bool

	reqListState string
	reqListAgent string
	reqListLimit int

	waitTimeout  time.Duration
	waitInterval time.Duration
)

func init() {
	requestsCmd := &cobra.Command{
		Use:     "requests",
		Short:   "Create and follow approval requests",
		GroupID: groupAgent,
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create an approval request",
		Example: `  contro1 requests create --type approval --question "Approve production deploy?"
  contro1 requests create --agent agt_123 --risk high --reason "DB migration" --wait`,
		RunE: runRequestCreate,
	}
	createCmd.Flags().StringVar(&reqType, "type", "approval", "request type: approval|yes_no|free_text")
	createCmd.Flags().StringVar(&reqQuestion, "question", "", "the question/title (required)")
	createCmd.Flags().StringVar(&reqContext, "context", "", "additional context (defaults to --reason or --question)")
	createCmd.Flags().StringVar(&reqAgent, "agent", "", "agent_id to attribute this request to")
	createCmd.Flags().StringVar(&reqRisk, "risk", "", "risk level: low|medium|high|critical")
	createCmd.Flags().StringVar(&reqReason, "reason", "", "human-readable reason")
	createCmd.Flags().StringVar(&reqPriority, "priority", "normal", "priority: normal|urgent")
	createCmd.Flags().StringVar(&reqCallbackURL, "callback-url", "", "webhook callback URL")
	createCmd.Flags().BoolVar(&reqWait, "wait", false, "wait for the decision after creating")
	_ = createCmd.MarkFlagRequired("question")

	listCmd := &cobra.Command{Use: "list", Short: "List recent requests", RunE: runRequestList}
	listCmd.Flags().StringVar(&reqListState, "state", "", "filter by state")
	listCmd.Flags().StringVar(&reqListAgent, "agent", "", "filter by agent_id")
	listCmd.Flags().IntVar(&reqListLimit, "limit", 50, "max results")

	getCmd := &cobra.Command{Use: "get <id>", Short: "Get a request", Args: cobra.ExactArgs(1), RunE: runRequestGet}

	waitCmd := &cobra.Command{Use: "wait <id>", Short: "Wait for a request decision", Args: cobra.ExactArgs(1), RunE: runRequestWait}
	waitCmd.Flags().DurationVar(&waitTimeout, "timeout", 10*time.Minute, "max time to wait")
	waitCmd.Flags().DurationVar(&waitInterval, "interval", 3*time.Second, "poll interval")

	cancelCmd := &cobra.Command{Use: "cancel <id>", Short: "Cancel a request", Args: cobra.ExactArgs(1), RunE: runRequestCancel}

	requestsCmd.AddCommand(createCmd, listCmd, getCmd, waitCmd, cancelCmd)
	rootCmd.AddCommand(requestsCmd)
}

// buildCreatePayload assembles a legacy-schema create body (with agent attribution
// via metadata.actor.agent_id, which the backend resolves to request.agent_id).
func buildCreatePayload() map[string]any {
	ctx := reqContext
	if ctx == "" {
		ctx = reqReason
	}
	if ctx == "" {
		ctx = reqQuestion
	}
	payload := map[string]any{
		"type":     reqType,
		"question": reqQuestion,
		"context":  ctx,
		"priority": reqPriority,
	}
	if reqRisk != "" {
		payload["risk_level"] = reqRisk
	}
	if reqReason != "" {
		payload["policy_trigger"] = reqReason
	}
	if reqCallbackURL != "" {
		payload["callback_url"] = reqCallbackURL
	}
	meta := map[string]any{"source": "cli"}
	if reqAgent != "" {
		meta["actor"] = map[string]any{"agent_id": reqAgent}
	}
	payload["metadata"] = meta
	return payload
}

func runRequestCreate(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("POST", "/api/centcom/v1/requests", buildCreatePayload())
	if err != nil {
		return err
	}
	id := str(firstNonEmpty(resp["request_id"], resp["id"]))
	infof("Created request %s (state: %s)", id, str(resp["state"]))

	if reqWait {
		final, decision, werr := waitForRequest(c, id, 10*time.Minute, 3*time.Second)
		if werr != nil {
			return werr
		}
		return finishDecision(pr, final, decision)
	}
	return output.Render(outFormat(pr), resp, requestSummaryTable(resp))
}

func runRequestList(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	path := "/api/centcom/v1/requests?limit=" + itoa(reqListLimit)
	if reqListState != "" {
		path += "&state=" + reqListState
	}
	if reqListAgent != "" {
		path += "&agent_id=" + reqListAgent
	}
	resp, err := c.Do("GET", path, nil)
	if err != nil {
		return err
	}
	items := asSlice(resp["requests"])
	tbl := &output.Table{Headers: []string{"ID", "TYPE", "STATE", "PRIORITY", "QUESTION"}}
	for _, it := range items {
		m := asMap(it)
		tbl.Rows = append(tbl.Rows, []string{
			str(firstNonEmpty(m["id"], m["_id"])), str(m["type"]), str(m["state"]),
			str(m["priority"]), truncate(str(m["question"]), 40),
		})
	}
	return output.Render(outFormat(pr), items, tbl)
}

func runRequestGet(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/requests/"+args[0], nil)
	if err != nil {
		return err
	}
	return output.Render(outFormat(pr), resp, requestSummaryTable(resp))
}

func runRequestWait(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	final, decision, werr := waitForRequest(c, args[0], waitTimeout, waitInterval)
	if werr != nil {
		return werr
	}
	return finishDecision(pr, final, decision)
}

func runRequestCancel(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("DELETE", "/api/centcom/v1/requests/"+args[0], nil)
	if err != nil {
		return err
	}
	infof("Request %s cancelled.", args[0])
	return output.Render(outFormat(pr), resp, nil)
}

// waitForRequest polls until the request reaches a terminal state or the timeout.
// Returns the final request and a decision classification.
func waitForRequest(c *client.Client, id string, timeout, interval time.Duration) (map[string]any, string, error) {
	deadline := time.Now().Add(timeout)
	infof("Waiting for a decision on %s ...", id)
	for {
		resp, err := c.Do("GET", "/api/centcom/v1/requests/"+id, nil)
		if err != nil {
			return nil, "", err
		}
		state := str(resp["state"])
		switch state {
		case "answered", "closed", "callback_pending":
			return resp, classifyDecision(resp), nil
		case "expired":
			return resp, "expired", nil
		case "cancelled":
			return resp, "cancelled", nil
		}
		if time.Now().After(deadline) {
			return resp, "timeout", nil
		}
		time.Sleep(interval)
	}
}

// classifyDecision inspects the response payload of a terminal request.
func classifyDecision(resp map[string]any) string {
	r := asMap(resp["response"])
	if v, ok := r["approved"].(bool); ok {
		if v {
			return "approved"
		}
		return "denied"
	}
	status := strings.ToLower(str(r["status"]))
	switch status {
	case "approved", "approve", "yes", "allow":
		return "approved"
	case "denied", "deny", "rejected", "reject", "no", "block":
		return "denied"
	}
	return "responded"
}

// finishDecision renders the outcome and returns the proper exit code error.
func finishDecision(pr *config.Profile, final map[string]any, decision string) error {
	switch decision {
	case "approved":
		infof("Approved.")
		return output.Render(outFormat(pr), final, requestSummaryTable(final))
	case "denied":
		return output.Errf(output.CodeRequestDenied, "request was denied")
	case "expired":
		return output.Errf(output.CodeTimeout, "request expired before a decision")
	case "cancelled":
		return output.Errf(output.CodeRequestDenied, "request was cancelled")
	case "timeout":
		return output.Errf(output.CodeTimeout, "timed out waiting for a decision")
	default:
		infof("Request responded.")
		return output.Render(outFormat(pr), final, requestSummaryTable(final))
	}
}

func requestSummaryTable(m map[string]any) *output.Table {
	return &output.Table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"id", str(firstNonEmpty(m["id"], m["_id"], m["request_id"]))},
			{"type", str(m["type"])},
			{"state", str(m["state"])},
			{"question", truncate(str(m["question"]), 60)},
			{"agent_id", str(m["agent_id"])},
			{"risk_level", str(m["risk_level"])},
		},
	}
}
