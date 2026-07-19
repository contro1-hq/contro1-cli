package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	runAgent             string
	runRisk              string
	runReason            string
	runType              string
	runRole              string
	runSLAMinutes        int
	runRequiredApprovals int
	runApprovalRoles     []string
	runMustIncludeRoles  []string
	runCorrelationID     string
	runExternalRequestID string
	runTraceID           string
	runEnvironment       string
	runTarget            string
	runSetup             string
	runTimeout           time.Duration
	runRequiresApprove   bool
)

func init() {
	runCmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run a command only after it is approved, then store evidence",
		Long: `run requests human approval for a command, waits for the decision, and only
executes the command if it is approved. The command, working directory, git
context, approver and exit code are recorded as audit-ready evidence.`,
		Example: `  contro1 run --requires-approval -- npm run deploy
  contro1 run --role release-manager --required-approvals 2 --risk high --reason "DB migration" -- npm run migrate`,
		GroupID: groupAgent,
		RunE:    runRun,
	}
	runCmd.Flags().StringVar(&runAgent, "agent", "", "agent_id to attribute this action to")
	runCmd.Flags().StringVar(&runRisk, "risk", "high", "risk level: low|medium|high|critical")
	runCmd.Flags().StringVar(&runReason, "reason", "", "reason shown to the approver")
	runCmd.Flags().StringVar(&runType, "type", "approval", "request type")
	runCmd.Flags().StringVar(&runRole, "role", "", "required reviewer role")
	runCmd.Flags().IntVar(&runSLAMinutes, "sla-minutes", 0, "SLA in minutes before escalation")
	runCmd.Flags().IntVar(&runRequiredApprovals, "required-approvals", 0, "number of distinct approvals required")
	runCmd.Flags().StringArrayVar(&runApprovalRoles, "approval-role", nil, "approval policy role; repeat or comma-separate")
	runCmd.Flags().StringArrayVar(&runMustIncludeRoles, "must-include-role", nil, "role expected in evidence/control-map; repeat or comma-separate")
	runCmd.Flags().StringVar(&runCorrelationID, "correlation-id", "", "case/business id shared across related records")
	runCmd.Flags().StringVar(&runExternalRequestID, "external-request-id", "", "idempotency key for this external action")
	runCmd.Flags().StringVar(&runTraceID, "trace-id", "", "trace id, e.g. trc_run_123")
	runCmd.Flags().StringVar(&runEnvironment, "environment", "", "environment shown to the reviewer, e.g. production")
	runCmd.Flags().StringVar(&runTarget, "target", "", "service, cluster, account, or other action target")
	runCmd.Flags().StringVar(&runSetup, "setup", "convenience", "gate label: convenience|enterprise")
	runCmd.Flags().DurationVar(&runTimeout, "timeout", 15*time.Minute, "max time to wait for approval")
	runCmd.Flags().BoolVar(&runRequiresApprove, "requires-approval", true, "require approval before running (always on in v1)")

	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
	dash := cmd.ArgsLenAtDash()
	if dash < 0 || dash >= len(args) {
		return output.Errf(output.CodeBadArgs, "provide the command after '--', e.g. contro1 run -- npm run deploy")
	}
	command := args[dash:]
	safeCommand := redactCommandArgs(command)
	safeCmdStr := strings.Join(safeCommand, " ")
	safeReason := redactSecretText(runReason)
	if runType != "approval" {
		return output.Errf(output.CodeBadArgs, "contro1 run supports --type approval only")
	}

	c, pr, err := newClient()
	if err != nil {
		return err
	}
	if runAgent == "" {
		runAgent = pr.DefaultAgent
	}

	cwd, _ := os.Getwd()
	gitBranch := gitOutput("rev-parse", "--abbrev-ref", "HEAD")
	gitCommit := gitOutput("rev-parse", "HEAD")
	workspaceState := gitOutput("status", "--porcelain=v1", "--untracked-files=normal")
	workspaceStateHash := sha256Hex(workspaceState)
	encodedCommand, _ := json.Marshal(command)
	commandHash := sha256Hex(string(encodedCommand))
	if runSetup != "convenience" && runSetup != "enterprise" {
		return output.Errf(output.CodeBadArgs, "--setup must be convenience or enterprise")
	}

	// 1) create approval request
	contextLines := []string{"Command: " + safeCmdStr, "Working dir: " + cwd}
	if gitBranch != "" {
		contextLines = append(contextLines, "Git branch: "+gitBranch)
	}
	if gitCommit != "" {
		contextLines = append(contextLines, "Git commit: "+gitCommit)
	}
	if runReason != "" {
		contextLines = append(contextLines, "Reason: "+safeReason)
	}

	// Canonical protocol request: machine-observed facts and agent-reported text
	// stay separate so routing never depends on the model's own justification.
	machineObserved := map[string]any{
		"command": safeCmdStr, "command_sha256": commandHash, "cwd": cwd,
		"git_branch": gitBranch, "git_commit": gitCommit,
		"workspace_state_hash": workspaceStateHash, "environment": runEnvironment,
		"target": runTarget, "enforcement_setup": runSetup,
	}
	context := map[string]any{
		"action":           map[string]any{"tool": "shell", "input": map[string]any{"command": safeCmdStr, "argv": safeCommand}},
		"summary":          "A local command is blocked until the routed human approval resolves.",
		"machine_observed": machineObserved,
	}
	if runEnvironment != "" {
		context["environment"] = runEnvironment
	}
	if runTarget != "" {
		context["resource"] = runTarget
	}
	if runReason != "" {
		context["agent_reported"] = map[string]any{"justification": safeReason}
	}
	source := map[string]any{"integration": "contro1-cli", "framework": "command-runner"}
	if runID := firstString(runExternalRequestID, runTraceID); runID != "" {
		source["run_id"] = runID
	}
	payload := map[string]any{
		"title":       "Approve running: " + truncate(safeCmdStr, 120),
		"description": strings.Join(contextLines, "\n"), "request_type": runType,
		"source": source, "context": context,
		"continuation": map[string]any{"mode": "decision", "expires_at": time.Now().Add(runTimeout).UTC().Format(time.RFC3339)},
		"risk_level":   runRisk,
		"metadata":     map[string]any{"source": "cli", "executor_wait_until": time.Now().Add(runTimeout).UTC().Format(time.RFC3339), "enforcement_setup": runSetup},
	}
	routing := map[string]any{"priority": "urgent"}
	if runRole != "" {
		routing["required_role"] = runRole
	}
	if runSLAMinutes > 0 {
		routing["sla_minutes"] = runSLAMinutes
	}
	payload["routing"] = routing
	if runAgent != "" {
		payload["actor"] = map[string]any{"agent_id": runAgent}
	}
	if runCorrelationID != "" {
		payload["correlation_id"] = runCorrelationID
	}
	if runExternalRequestID != "" {
		payload["external_request_id"] = runExternalRequestID
	}
	if runTraceID != "" {
		payload["trace_id"] = runTraceID
	}
	if runReason != "" {
		payload["policy_trigger"] = safeReason
		payload["policy_context"] = map[string]any{
			"source": "contro1-cli", "policy_name": "command-approval",
			"rule_id": "command.requires-human-authorization", "rule_reason": safeReason,
			"enforcement": runSetup,
		}
	}
	attachRunApprovalFields(payload)

	resp, err := c.Do("POST", "/api/centcom/v1/requests", payload)
	if err != nil {
		return err
	}
	reqID := str(firstNonEmpty(resp["request_id"], resp["id"]))
	infof("Approval required. Request: %s", reqID)

	// 2) wait for decision
	final, decision, werr := waitForRequest(c, reqID, runTimeout, 3*time.Second)
	if werr != nil {
		return werr
	}
	if decision != "approved" {
		// record the (non-execution) outcome too
		recordRunEvidence(c, reqID, safeCmdStr, cwd, gitBranch, gitCommit, commandHash, workspaceStateHash, workspaceStateHash, "not_executed_"+decision, nil, time.Now(), time.Now())
		if decision == "timeout" {
			// The CLI gave up waiting, but the request is still open server-side. Tell the
			// server the executor is gone: the request keeps escalating for the humans while a
			// later approval is not mistaken for a command that actually ran.
			recordExecutorDetached(c, reqID, safeCmdStr)
		}
		return finishDecision(pr, final, decision)
	}

	approver := approverName(final)
	actualCommit := gitOutput("rev-parse", "HEAD")
	actualWorkspaceHash := sha256Hex(gitOutput("status", "--porcelain=v1", "--untracked-files=normal"))
	if actualCommit != gitCommit || actualWorkspaceHash != workspaceStateHash {
		now := time.Now()
		recordRunEvidence(c, reqID, safeCmdStr, cwd, gitBranch, gitCommit, commandHash, workspaceStateHash, actualWorkspaceHash, "not_executed_workspace_changed", nil, now, now)
		return output.Errf(output.CodeGeneral, "workspace changed after approval; command was not run (create a new approval for the new state)")
	}
	infof("Approved%s. Running the command bound to the reviewed hash: %s", approverSuffix(approver), safeCmdStr)

	// 3) execute
	started := time.Now()
	exitCode := execCommand(command, outFormat(pr) != "table")
	finished := time.Now()

	// 4) store evidence
	evidenceID := recordRunEvidence(c, reqID, safeCmdStr, cwd, gitBranch, gitCommit, commandHash, workspaceStateHash, actualWorkspaceHash, "executed", &exitCode, started, finished)

	result := map[string]any{
		"request_id":  reqID,
		"status":      "approved",
		"command":     safeCmdStr,
		"exit_code":   exitCode,
		"evidence_id": evidenceID,
	}
	if exitCode == 0 {
		infof("Command completed successfully. Evidence (client-reported): %s", evidenceID)
	} else {
		infof("Command exited with code %d. Evidence (client-reported): %s", exitCode, evidenceID)
	}

	if err := output.Render(outFormat(pr), result, runResultTable(result)); err != nil {
		return err
	}
	if exitCode != 0 {
		return output.Errf(output.CodeGeneral, "command exited with code %d", exitCode)
	}
	return nil
}

func redactCommandArgs(command []string) []string {
	redacted := make([]string, len(command))
	copy(redacted, command)
	redactNext := false
	for i, arg := range redacted {
		if redactNext {
			redacted[i] = "[REDACTED]"
			redactNext = false
			continue
		}
		redacted[i] = redactSecretText(arg)
		flag := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
		if !strings.Contains(arg, "=") && secretFieldPattern.MatchString(flag) {
			redactNext = true
		}
	}
	return redacted
}

func execCommand(command []string, structuredOutput bool) int {
	c := exec.Command(command[0], command[1:]...)
	if structuredOutput {
		c.Stdout = os.Stderr
	} else {
		c.Stdout = os.Stdout
	}
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		output.Info("failed to start command: %v", err)
		return 127
	}
	return 0
}

func recordRunEvidence(c *client.Client, reqID, command, cwd, branch, commit, commandHash, expectedWorkspaceHash, actualWorkspaceHash, executionStatus string, exitCode *int, started, finished time.Time) string {
	body := map[string]any{
		"request_id": reqID, "command": command, "command_sha256": commandHash,
		"cwd": cwd, "git_branch": branch, "git_commit": commit,
		"expected_workspace_hash": expectedWorkspaceHash, "actual_workspace_hash": actualWorkspaceHash,
		"execution_status": executionStatus, "environment": runEnvironment, "target": runTarget,
		"enforcement_setup": runSetup, "agent_id": runAgent,
		"started_at": started.UTC().Format(time.RFC3339), "finished_at": finished.UTC().Format(time.RFC3339),
	}
	if exitCode != nil {
		body["exit_code"] = *exitCode
	}
	resp, err := c.Do("POST", "/api/centcom/v1/cli/run-evidence", body)
	if err != nil {
		return ""
	}
	return str(asMap(resp["data"])["evidence_id"])
}

// recordExecutorDetached notifies the server that the CLI stopped waiting (client-side
// timeout) before a decision was made. It never cancels the request, so SLA escalation and
// queue visibility continue. Best-effort: the CLI returns the timeout error regardless.
func recordExecutorDetached(c *client.Client, reqID, command string) {
	body := map[string]any{
		"request_id":     reqID,
		"reason":         "cli_wait_timeout",
		"waited_seconds": int(runTimeout.Seconds()),
		"command":        command,
		"agent_id":       runAgent,
	}
	_, _ = c.Do("POST", "/api/centcom/v1/cli/executor-detached", body)
}

func attachRunApprovalFields(payload map[string]any) {
	approvalRoles := normalizeStringList(runApprovalRoles)
	if runRole != "" {
		approvalRoles = appendUnique(approvalRoles, runRole)
	}
	mustIncludeRoles := normalizeStringList(runMustIncludeRoles)

	policy := map[string]any{}
	if runRequiredApprovals > 1 {
		policy["mode"] = "threshold"
	}
	if runRequiredApprovals > 0 {
		policy["required_approvals"] = runRequiredApprovals
	}
	if len(approvalRoles) > 0 {
		policy["required_roles"] = approvalRoles
	}
	if len(policy) > 0 {
		payload["approval_policy"] = policy
	}

	requirements := map[string]any{}
	if runRequiredApprovals > 0 {
		requirements["required_approvals"] = runRequiredApprovals
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

func gitOutput(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func approverName(final map[string]any) string {
	r := asMap(final["response"])
	if n := str(r["responded_by"]); n != "" {
		return n
	}
	return str(final["responded_by"])
}

func approverSuffix(name string) string {
	if name == "" {
		return ""
	}
	return " by " + name
}

func runResultTable(m map[string]any) *output.Table {
	return &output.Table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"request_id", str(m["request_id"])},
			{"status", str(m["status"])},
			{"command", truncate(str(m["command"]), 60)},
			{"exit_code", str(m["exit_code"])},
			{"evidence_id", str(m["evidence_id"])},
		},
	}
}
