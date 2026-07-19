package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

type codexHookInput struct {
	SessionID      string         `json:"session_id"`
	TurnID         string         `json:"turn_id"`
	ToolUseID      string         `json:"tool_use_id"`
	CWD            string         `json:"cwd"`
	HookEventName  string         `json:"hook_event_name"`
	PermissionMode string         `json:"permission_mode"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
}

var (
	codexHookRole              string
	codexHookRisk              string
	codexHookEnvironment       string
	codexHookTarget            string
	codexHookReason            string
	codexHookSetup             string
	codexHookSLAMinutes        int
	codexHookRequiredApprovals int
	codexHookTimeout           time.Duration
	codexHookMatch             []string
	codexHookAllBash           bool
)

var defaultDeployPatterns = []string{
	`(?i)(^|[;&|]\s*)(npm|pnpm|yarn)\s+(run\s+)?deploy(?::[a-z0-9_-]+)?\b`,
	`(?i)(^|[;&|]\s*)make\s+deploy\b`,
	`(?i)\bkubectl\s+(apply|create|delete|patch|replace|rollout|scale|set)\b`,
	`(?i)\bhelm\s+(install|upgrade|rollback|uninstall)\b`,
	`(?i)\bterraform\s+(apply|destroy)\b`,
	`(?i)\b(tofu|pulumi)\s+(up|destroy)\b`,
	`(?i)\b(vercel|netlify)\b[^\n]*(--prod|production)\b`,
	`(?i)\b(gcloud\s+(run|app)\s+deploy|az\s+(webapp|containerapp)\s+deploy)\b`,
	`(?i)\baws\s+(ecs\s+update-service|lambda\s+update-function-code|cloudformation\s+deploy)\b`,
	`(?i)\bgh\s+workflow\s+run\b[^\n]*deploy`,
}

var secretValuePatterns = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)cc_(?:live|test)_[a-z0-9_-]{8,}`), `[REDACTED_API_KEY]`},
	{regexp.MustCompile(`(?i)whsec_[a-z0-9_-]{8,}`), `[REDACTED_WEBHOOK_SECRET]`},
	{regexp.MustCompile(`(?i)(Bearer\s+)[^\s]+`), `${1}[REDACTED_TOKEN]`},
	{regexp.MustCompile(`(?i)((?:--?)(?:api[_-]?key|token|secret|password)(?:=|\s+))["']?[^\s"';&|]+["']?`), `${1}[REDACTED]`},
	{regexp.MustCompile(`(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*)["']?[^\s"',};&|]+["']?`), `${1}[REDACTED]`},
}

var secretFieldPattern = regexp.MustCompile(`(?i)^(api[_-]?key|token|secret|password|authorization)$`)

func init() {
	hooksCmd := &cobra.Command{Use: "hooks", Short: "Adapters for coding-agent lifecycle hooks", GroupID: groupAgent}
	codexCmd := &cobra.Command{
		Use:   "codex",
		Short: "Gate production deploys from Codex hooks",
		Long: `Read a Codex PreToolUse or PermissionRequest event from stdin. Deploy-like
Bash commands create a canonical Contro1 approval request and remain blocked
until the required reviewer approves. Non-deploy commands are left to Codex's
normal permission flow.`,
		Example: `  # Called by a Codex hook, not normally by hand:
  contro1 hooks codex --role cto --environment production --setup convenience
  contro1 hooks codex --role cto --required-approvals 2 --setup enterprise`,
		Args: cobra.NoArgs,
		RunE: runCodexHook,
	}
	codexCmd.Flags().StringVar(&codexHookRole, "role", envOr("CONTRO1_DEPLOY_REQUIRED_ROLE", "cto"), "reviewer role required for the deploy")
	codexCmd.Flags().StringVar(&codexHookRisk, "risk", envOr("CONTRO1_DEPLOY_RISK", "critical"), "risk level: low|medium|high|critical")
	codexCmd.Flags().StringVar(&codexHookEnvironment, "environment", envOr("CONTRO1_DEPLOY_ENVIRONMENT", "production"), "deployment environment shown to the reviewer")
	codexCmd.Flags().StringVar(&codexHookTarget, "target", os.Getenv("CONTRO1_DEPLOY_TARGET"), "service, cluster, account, or other deployment target")
	codexCmd.Flags().StringVar(&codexHookReason, "reason", envOr("CONTRO1_DEPLOY_REASON", "Production deploy requires human authorization"), "policy trigger shown to the reviewer")
	codexCmd.Flags().StringVar(&codexHookSetup, "setup", envOr("CONTRO1_DEPLOY_SETUP", "convenience"), "setup label: convenience|enterprise")
	codexCmd.Flags().IntVar(&codexHookSLAMinutes, "sla-minutes", envInt("CONTRO1_DEPLOY_SLA_MINUTES", 10), "SLA before escalation")
	codexCmd.Flags().IntVar(&codexHookRequiredApprovals, "required-approvals", envInt("CONTRO1_DEPLOY_REQUIRED_APPROVALS", 1), "number of distinct approvals required")
	codexCmd.Flags().DurationVar(&codexHookTimeout, "timeout", envDuration("CONTRO1_DEPLOY_TIMEOUT", 15*time.Minute), "maximum time Codex remains blocked")
	codexCmd.Flags().StringArrayVar(&codexHookMatch, "match", nil, "additional deploy command regex; repeat as needed")
	codexCmd.Flags().BoolVar(&codexHookAllBash, "all-bash", false, "gate every Bash command instead of deploy-like commands")
	hooksCmd.AddCommand(codexCmd)
	rootCmd.AddCommand(hooksCmd)
}

func runCodexHook(_ *cobra.Command, _ []string) error {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return output.Errf(output.CodeBadArgs, "reading Codex hook input: %v", err)
	}
	var input codexHookInput
	if err := json.Unmarshal(raw, &input); err != nil {
		return output.Errf(output.CodeBadArgs, "invalid Codex hook JSON: %v", err)
	}
	if input.HookEventName != "PreToolUse" && input.HookEventName != "PermissionRequest" {
		return output.Errf(output.CodeBadArgs, "unsupported Codex hook event %q", input.HookEventName)
	}
	if input.ToolName != "Bash" {
		return nil
	}
	command, _ := input.ToolInput["command"].(string)
	if strings.TrimSpace(command) == "" {
		return renderCodexHookDecision(input, false, "Blocked: Bash hook input did not contain a command.")
	}
	matched, err := matchesDeployCommand(command, codexHookMatch, codexHookAllBash)
	if err != nil {
		return renderCodexHookDecision(input, false, "Blocked: invalid deploy policy configuration.")
	}
	if !matched {
		return nil
	}
	if codexHookSetup != "convenience" && codexHookSetup != "enterprise" {
		return renderCodexHookDecision(input, false, "Blocked: --setup must be convenience or enterprise.")
	}
	c, _, err := newClient()
	if err != nil {
		return renderCodexHookDecision(input, false, "Blocked: Contro1 authentication is unavailable.")
	}
	payload := buildCodexDeployPayload(input, command)
	resp, err := c.Do("POST", "/api/centcom/v1/requests", payload)
	if err != nil {
		return renderCodexHookDecision(input, false, "Blocked: Contro1 could not create the approval request.")
	}
	requestID := str(firstNonEmpty(resp["request_id"], resp["id"]))
	if requestID == "" {
		return renderCodexHookDecision(input, false, "Blocked: Contro1 returned no request id.")
	}
	infof("Production deploy blocked. Contro1 request: %s", requestID)
	final, decision, waitErr := waitForRequest(c, requestID, codexHookTimeout, 3*time.Second)
	if waitErr != nil {
		cancelHookRequest(c, requestID)
		return renderCodexHookDecision(input, false, "Blocked: Contro1 approval check failed.")
	}
	if decision != "approved" {
		if decision == "timeout" {
			cancelHookRequest(c, requestID)
		}
		message := "Production deploy denied by Contro1."
		if comment := decisionComment(final); comment != "" {
			message += " " + comment
		}
		return renderCodexHookDecision(input, false, message)
	}
	infof("Approved by Contro1. Codex may run the exact reviewed command.")
	return renderCodexHookDecision(input, true, "")
}

func buildCodexDeployPayload(input codexHookInput, command string) map[string]any {
	commandHash := sha256Hex(command)
	safeCommand := redactSecretText(command)
	safeToolInput, _ := redactSecretValue(input.ToolInput, "").(map[string]any)
	commit := gitOutput("rev-parse", "HEAD")
	branch := gitOutput("rev-parse", "--abbrev-ref", "HEAD")
	workspaceState := gitOutput("status", "--porcelain=v1", "--untracked-files=normal")
	machineObserved := map[string]any{
		"command": safeCommand, "command_sha256": commandHash,
		"cwd": firstString(input.CWD, mustGetwd()), "git_branch": branch,
		"git_commit": commit, "workspace_state_hash": sha256Hex(workspaceState),
		"environment": codexHookEnvironment, "target": codexHookTarget,
		"hook_event": input.HookEventName, "permission_mode": input.PermissionMode,
		"enforcement_setup": codexHookSetup,
	}
	source := map[string]any{"integration": "codex", "framework": "codex-cli-hook"}
	if input.SessionID != "" {
		source["session_id"] = input.SessionID
	}
	if runID := firstString(input.ToolUseID, input.TurnID); runID != "" {
		source["run_id"] = runID
	}
	context := map[string]any{
		"action":           map[string]any{"tool": "shell", "input": safeToolInput},
		"environment":      codexHookEnvironment,
		"summary":          "Production deployment command intercepted by a Codex lifecycle hook.",
		"machine_observed": machineObserved,
		"agent_reported":   map[string]any{"justification": codexHookReason},
	}
	if codexHookTarget != "" {
		context["resource"] = codexHookTarget
	}
	payload := map[string]any{
		"title":        "Approve production deploy from Codex?",
		"description":  "Codex is blocked before executing the reviewed command.",
		"request_type": "approval", "source": source,
		"routing":      map[string]any{"required_role": codexHookRole, "priority": "urgent", "sla_minutes": codexHookSLAMinutes},
		"context":      context,
		"continuation": map[string]any{"mode": "decision", "expires_at": time.Now().Add(codexHookTimeout).UTC().Format(time.RFC3339)},
		"risk_level":   codexHookRisk, "policy_trigger": codexHookReason,
		"policy_context": map[string]any{
			"source": "codex-hook", "policy_name": "production-deploy-approval",
			"rule_id": "deploy.requires-human-authorization", "rule_reason": codexHookReason,
			"enforcement": codexHookSetup,
		},
		"external_request_id": codexExternalRequestID(input, commandHash),
		"correlation_id":      firstString(input.SessionID, "codex-deploy"),
		"metadata":            map[string]any{"adapter": "contro1-cli", "enforcement_setup": codexHookSetup},
	}
	if codexHookRequiredApprovals > 0 {
		payload["approval_policy"] = map[string]any{
			"mode": thresholdMode(codexHookRequiredApprovals), "required_approvals": codexHookRequiredApprovals,
			"required_roles": []string{codexHookRole}, "separation_of_duties": true,
			"fail_closed_on_timeout": true,
		}
		payload["approval_requirements"] = map[string]any{
			"required_approvals": codexHookRequiredApprovals, "required_roles": []string{codexHookRole},
		}
	}
	return payload
}

func redactSecretText(value string) string {
	redacted := value
	for _, item := range secretValuePatterns {
		redacted = item.pattern.ReplaceAllString(redacted, item.replacement)
	}
	return redacted
}

func redactSecretValue(value any, key string) any {
	if secretFieldPattern.MatchString(key) {
		return "[REDACTED]"
	}
	switch typed := value.(type) {
	case string:
		return redactSecretText(typed)
	case map[string]any:
		result := make(map[string]any, len(typed))
		for itemKey, itemValue := range typed {
			result[itemKey] = redactSecretValue(itemValue, itemKey)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for i, itemValue := range typed {
			result[i] = redactSecretValue(itemValue, "")
		}
		return result
	default:
		return value
	}
}

func renderCodexHookDecision(input codexHookInput, allow bool, message string) error {
	var payload map[string]any
	if input.HookEventName == "PreToolUse" {
		decision := "deny"
		if allow {
			decision = "allow"
		}
		specific := map[string]any{"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": message}
		if allow {
			specific["updatedInput"] = input.ToolInput
		}
		payload = map[string]any{"hookSpecificOutput": specific}
	} else {
		behavior := "deny"
		if allow {
			behavior = "allow"
		}
		decision := map[string]any{"behavior": behavior}
		if !allow && message != "" {
			decision["message"] = message
		}
		payload = map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PermissionRequest", "decision": decision}}
	}
	return json.NewEncoder(os.Stdout).Encode(payload)
}

func matchesDeployCommand(command string, extra []string, allBash bool) (bool, error) {
	if allBash {
		return true, nil
	}
	patterns := append([]string{}, defaultDeployPatterns...)
	if fromEnv := strings.TrimSpace(os.Getenv("CONTRO1_DEPLOY_MATCH")); fromEnv != "" {
		patterns = append(patterns, fromEnv)
	}
	patterns = append(patterns, extra...)
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, err
		}
		if re.MatchString(command) {
			return true, nil
		}
	}
	return false, nil
}

func codexExternalRequestID(input codexHookInput, commandHash string) string {
	return strings.Join([]string{"codex", input.SessionID, firstString(input.ToolUseID, input.TurnID), commandHash[:16]}, ":")
}

func cancelHookRequest(c *client.Client, requestID string) {
	_, _ = c.Do("DELETE", "/api/centcom/v1/requests/"+requestID, nil)
}

func decisionComment(final map[string]any) string {
	response := asMap(final["response"])
	return firstString(str(response["comment"]), str(response["reason"]), str(response["message"]))
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func thresholdMode(required int) string {
	if required > 1 {
		return "threshold"
	}
	return "single"
}
func mustGetwd() string { cwd, _ := os.Getwd(); return cwd }
func firstString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	var parsed int
	if _, err := fmt.Sscanf(value, "%d", &parsed); err == nil {
		return parsed
	}
	return fallback
}
func envDuration(name string, fallback time.Duration) time.Duration {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return fallback
}
