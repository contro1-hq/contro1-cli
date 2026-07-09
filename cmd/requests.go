package cmd

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	reqType                    string
	reqQuestion                string
	reqContext                 string
	reqAgent                   string
	reqRisk                    string
	reqReason                  string
	reqPriority                string
	reqRole                    string
	reqSLAMinutes              int
	reqCallbackURL             string
	reqPayloadFile             string
	reqMetadataFile            string
	reqResponseSchemaFile      string
	reqPolicyContextFile       string
	reqToolCallsFile           string
	reqSubAgentsFile           string
	reqRetrievedContextFile    string
	reqExternalRequestID       string
	reqCorrelationID           string
	reqThreadID                string
	reqTraceID                 string
	reqParentTraceID           string
	reqApprovalMode            string
	reqRequiredApprovals       int
	reqApprovalRoles           []string
	reqMustIncludeRoles        []string
	reqSeparationOfDuties      bool
	reqFailClosedOnTimeout     bool
	reqStrictPolicy            bool
	reqApprovalCommentRequired bool
	reqWait                    bool

	reqListState  string
	reqListAgent  string
	reqListThread string
	reqListLimit  int

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
  contro1 requests create --role finance --required-approvals 2 --question "Approve vendor payment?" --wait
  contro1 requests create --file request.json`,
		RunE: runRequestCreate,
	}
	createCmd.Flags().StringVar(&reqType, "type", "approval", "request type: approval|yes_no|free_text")
	createCmd.Flags().StringVar(&reqQuestion, "question", "", "the question/title (required unless --file is used)")
	createCmd.Flags().StringVar(&reqContext, "context", "", "additional context (defaults to --reason or --question)")
	createCmd.Flags().StringVar(&reqAgent, "agent", "", "agent_id to attribute this request to")
	createCmd.Flags().StringVar(&reqRisk, "risk", "", "risk level: low|medium|high|critical")
	createCmd.Flags().StringVar(&reqReason, "reason", "", "human-readable reason")
	createCmd.Flags().StringVar(&reqPriority, "priority", "normal", "priority: normal|urgent")
	createCmd.Flags().StringVar(&reqRole, "role", "", "required reviewer role, e.g. finance|security|manager")
	createCmd.Flags().IntVar(&reqSLAMinutes, "sla-minutes", 0, "SLA in minutes before escalation")
	createCmd.Flags().StringVar(&reqCallbackURL, "callback-url", "", "webhook callback URL")
	addAdvancedRequestFlags(createCmd)
	createCmd.Flags().BoolVar(&reqWait, "wait", false, "wait for the decision after creating")

	listCmd := &cobra.Command{Use: "list", Short: "List recent requests", RunE: runRequestList}
	listCmd.Flags().StringVar(&reqListState, "state", "", "filter by state")
	listCmd.Flags().StringVar(&reqListAgent, "agent", "", "filter by agent_id")
	listCmd.Flags().StringVar(&reqListThread, "thread-id", "", "filter by thread_id")
	listCmd.Flags().IntVar(&reqListLimit, "limit", 50, "max results")

	controlMapCmd := &cobra.Command{
		Use:   "control-map",
		Short: "Preview routing, role mapping and quorum for a request",
		Example: `  contro1 requests control-map --role finance --required-approvals 2 --must-include-role cfo
  contro1 requests control-map --file request.json`,
		RunE: runRequestControlMap,
	}
	controlMapCmd.Flags().StringVar(&reqType, "type", "approval", "request type: approval|yes_no|free_text")
	controlMapCmd.Flags().StringVar(&reqQuestion, "question", "", "question/title used for API validation")
	controlMapCmd.Flags().StringVar(&reqContext, "context", "", "context used for API validation")
	controlMapCmd.Flags().StringVar(&reqRisk, "risk", "", "risk level: low|medium|high|critical")
	controlMapCmd.Flags().StringVar(&reqReason, "reason", "", "policy trigger/reason")
	controlMapCmd.Flags().StringVar(&reqRole, "role", "", "required reviewer role, e.g. finance|security|manager")
	addAdvancedRequestFlags(controlMapCmd)

	getCmd := &cobra.Command{Use: "get <id>", Short: "Get a request", Args: cobra.ExactArgs(1), RunE: runRequestGet}

	waitCmd := &cobra.Command{Use: "wait <id>", Short: "Wait for a request decision", Args: cobra.ExactArgs(1), RunE: runRequestWait}
	waitCmd.Flags().DurationVar(&waitTimeout, "timeout", 10*time.Minute, "max time to wait")
	waitCmd.Flags().DurationVar(&waitInterval, "interval", 3*time.Second, "poll interval")

	cancelCmd := &cobra.Command{Use: "cancel <id>", Short: "Cancel a request", Args: cobra.ExactArgs(1), RunE: runRequestCancel}

	requestsCmd.AddCommand(createCmd, controlMapCmd, listCmd, getCmd, waitCmd, cancelCmd)
	rootCmd.AddCommand(requestsCmd)
}

func addAdvancedRequestFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&reqPayloadFile, "file", "", "read the full request JSON body from a file, or '-' for stdin")
	cmd.Flags().StringVar(&reqMetadataFile, "metadata-file", "", "merge metadata from a JSON object file")
	cmd.Flags().StringVar(&reqResponseSchemaFile, "response-schema-file", "", "attach response_schema from a JSON object file")
	cmd.Flags().StringVar(&reqPolicyContextFile, "policy-context-file", "", "attach policy_context from a JSON object file")
	cmd.Flags().StringVar(&reqToolCallsFile, "tool-calls-file", "", "attach tool_calls from a JSON array file")
	cmd.Flags().StringVar(&reqSubAgentsFile, "sub-agents-file", "", "attach sub_agents from a JSON array file")
	cmd.Flags().StringVar(&reqRetrievedContextFile, "retrieved-context-file", "", "attach retrieved_context from a JSON array file")
	cmd.Flags().StringVar(&reqExternalRequestID, "external-request-id", "", "idempotency key for this external action")
	cmd.Flags().StringVar(&reqCorrelationID, "correlation-id", "", "case/business id shared across related records")
	cmd.Flags().StringVar(&reqThreadID, "thread-id", "", "thread id, e.g. thr_run_123")
	cmd.Flags().StringVar(&reqTraceID, "trace-id", "", "trace id, e.g. trc_run_123")
	cmd.Flags().StringVar(&reqParentTraceID, "parent-trace-id", "", "parent trace id for delegated/sub-agent runs")
	cmd.Flags().StringVar(&reqApprovalMode, "approval-mode", "", "approval policy mode: single|all_of|any_of|threshold")
	cmd.Flags().IntVar(&reqRequiredApprovals, "required-approvals", 0, "number of distinct approvals required")
	cmd.Flags().StringArrayVar(&reqApprovalRoles, "approval-role", nil, "approval policy role; repeat or comma-separate")
	cmd.Flags().StringArrayVar(&reqMustIncludeRoles, "must-include-role", nil, "role expected in evidence/control-map; repeat or comma-separate")
	cmd.Flags().BoolVar(&reqSeparationOfDuties, "separation-of-duties", true, "require distinct approvers for quorum")
	cmd.Flags().BoolVar(&reqFailClosedOnTimeout, "fail-closed-on-timeout", true, "treat timeout as failed approval")
	cmd.Flags().BoolVar(&reqStrictPolicy, "strict-policy", false, "block when agent policy/routing authority fails")
	cmd.Flags().BoolVar(&reqApprovalCommentRequired, "approval-comment-required", false, "require an approval comment")
}

// buildCreatePayload assembles a legacy-schema create body (with agent attribution
// via metadata.actor.agent_id, which the backend resolves to request.agent_id).
func buildCreatePayload() (map[string]any, error) {
	if reqPayloadFile != "" {
		return readJSONMap(reqPayloadFile, "request")
	}
	if reqQuestion == "" {
		return nil, output.Errf(output.CodeBadArgs, "--question is required unless --file is used")
	}
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
	if reqRole != "" {
		payload["required_role"] = reqRole
	}
	if reqSLAMinutes > 0 {
		payload["sla_minutes"] = reqSLAMinutes
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
	if reqExternalRequestID != "" {
		payload["external_request_id"] = reqExternalRequestID
	}
	if reqCorrelationID != "" {
		payload["correlation_id"] = reqCorrelationID
	}
	if reqThreadID != "" {
		payload["thread_id"] = reqThreadID
	}
	if reqTraceID != "" {
		payload["trace_id"] = reqTraceID
	}
	if reqParentTraceID != "" {
		payload["parent_trace_id"] = reqParentTraceID
	}
	if reqApprovalCommentRequired {
		payload["approval_comment_required"] = true
	}
	meta := map[string]any{"source": "cli"}
	if reqAgent != "" {
		meta["actor"] = map[string]any{"agent_id": reqAgent}
	}
	if reqMetadataFile != "" {
		fromFile, err := readJSONMap(reqMetadataFile, "metadata")
		if err != nil {
			return nil, err
		}
		for k, v := range fromFile {
			meta[k] = v
		}
	}
	payload["metadata"] = meta
	if err := attachRequestJSONFiles(payload); err != nil {
		return nil, err
	}
	attachApprovalFields(payload)
	return payload, nil
}

func runRequestCreate(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	payload, err := buildCreatePayload()
	if err != nil {
		return err
	}
	resp, err := c.Do("POST", "/api/centcom/v1/requests", payload)
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

func runRequestControlMap(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	if reqPayloadFile == "" && reqQuestion == "" {
		reqQuestion = "Preview routing"
	}
	if reqPayloadFile == "" && reqContext == "" {
		reqContext = "Preview routing"
	}
	payload, err := buildCreatePayload()
	if err != nil {
		return err
	}
	resp, err := c.Do("POST", "/api/centcom/v1/requests/control-map", payload)
	if err != nil {
		return err
	}
	infof("Control Map: %s (satisfiable: %s)", str(resp["status"]), str(resp["satisfiable"]))
	return output.Render(outFormat(pr), resp, controlMapTable(resp))
}

func runRequestList(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("limit", itoa(reqListLimit))
	if reqListState != "" {
		q.Set("state", reqListState)
	}
	if reqListAgent != "" {
		q.Set("agent_id", reqListAgent)
	}
	if reqListThread != "" {
		q.Set("thread_id", reqListThread)
	}
	resp, err := c.Do("GET", "/api/centcom/v1/requests?"+q.Encode(), nil)
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

func attachRequestJSONFiles(payload map[string]any) error {
	for _, item := range []struct {
		key   string
		path  string
		label string
	}{
		{"response_schema", reqResponseSchemaFile, "response_schema"},
		{"policy_context", reqPolicyContextFile, "policy_context"},
	} {
		if item.path == "" {
			continue
		}
		value, err := readJSONMap(item.path, item.label)
		if err != nil {
			return err
		}
		payload[item.key] = value
	}
	for _, item := range []struct {
		key   string
		path  string
		label string
	}{
		{"tool_calls", reqToolCallsFile, "tool_calls"},
		{"sub_agents", reqSubAgentsFile, "sub_agents"},
		{"retrieved_context", reqRetrievedContextFile, "retrieved_context"},
	} {
		if item.path == "" {
			continue
		}
		value, err := readJSONArray(item.path, item.label)
		if err != nil {
			return err
		}
		payload[item.key] = value
	}
	return nil
}

func attachApprovalFields(payload map[string]any) {
	approvalRoles := normalizeStringList(reqApprovalRoles)
	if reqRole != "" {
		approvalRoles = appendUnique(approvalRoles, reqRole)
	}
	mustIncludeRoles := normalizeStringList(reqMustIncludeRoles)

	policy := map[string]any{}
	if reqApprovalMode != "" {
		policy["mode"] = reqApprovalMode
	} else if reqRequiredApprovals > 1 {
		policy["mode"] = "threshold"
	}
	if reqRequiredApprovals > 0 {
		policy["required_approvals"] = reqRequiredApprovals
	}
	if len(approvalRoles) > 0 {
		policy["required_roles"] = approvalRoles
	}
	if reqSeparationOfDuties == false {
		policy["separation_of_duties"] = false
	}
	if reqFailClosedOnTimeout == false {
		policy["fail_closed_on_timeout"] = false
	}
	if reqStrictPolicy {
		policy["enforcement"] = "strict"
	}
	if len(policy) > 0 {
		payload["approval_policy"] = policy
	}

	requirements := map[string]any{}
	if reqRequiredApprovals > 0 {
		requirements["required_approvals"] = reqRequiredApprovals
	}
	if len(approvalRoles) > 0 {
		requirements["required_roles"] = approvalRoles
	}
	if len(mustIncludeRoles) > 0 {
		requirements["must_include_roles"] = mustIncludeRoles
	}
	if len(requirements) > 0 {
		payload["approval_requirements"] = requirements
	}
}

func readJSONMap(path, label string) (map[string]any, error) {
	var value map[string]any
	if err := readJSON(path, &value); err != nil {
		return nil, output.Errf(output.CodeBadArgs, "%s JSON: %v", label, err)
	}
	if value == nil {
		return nil, output.Errf(output.CodeBadArgs, "%s must be a JSON object", label)
	}
	return value, nil
}

func readJSONArray(path, label string) ([]any, error) {
	var value []any
	if err := readJSON(path, &value); err != nil {
		return nil, output.Errf(output.CodeBadArgs, "%s JSON: %v", label, err)
	}
	if value == nil {
		return nil, output.Errf(output.CodeBadArgs, "%s must be a JSON array", label)
	}
	return value, nil
}

func readJSON(path string, target any) error {
	raw, err := readInput(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}

func normalizeStringList(values []string) []string {
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = appendUnique(out, part)
			}
		}
	}
	return out
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func runRequestGet(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/requests/"+url.PathEscape(args[0]), nil)
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
	resp, err := c.Do("DELETE", "/api/centcom/v1/requests/"+url.PathEscape(args[0]), nil)
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
		resp, err := c.Do("GET", "/api/centcom/v1/requests/"+url.PathEscape(id), nil)
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
			{"required_role", str(m["required_role"])},
			{"sla_minutes", str(m["sla_minutes"])},
			{"agent_id", str(m["agent_id"])},
			{"risk_level", str(m["risk_level"])},
			{"correlation_id", str(m["correlation_id"])},
			{"trace_id", str(m["trace_id"])},
		},
	}
}

func controlMapTable(m map[string]any) *output.Table {
	warnings := asSlice(m["warnings"])
	roles := asSlice(m["roles"])
	policy := asMap(m["approval_policy"])
	action := asMap(m["suggested_action"])
	return &output.Table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"status", str(m["status"])},
			{"satisfiable", str(m["satisfiable"])},
			{"eligible_reviewers", str(m["eligible_reviewer_count"])},
			{"on_shift_reviewers", str(m["on_shift_reviewer_count"])},
			{"required_approvals", str(policy["required_approvals"])},
			{"roles_checked", itoa(len(roles))},
			{"warnings", itoa(len(warnings))},
			{"suggested_action", str(action["label"])},
		},
	}
}
