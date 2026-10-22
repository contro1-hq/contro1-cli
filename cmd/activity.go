package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
	"github.com/spf13/cobra"
)

var (
	activityPayloadFile string
	hookFailClosed      bool
	hookSource          string
	hookAgent           string
)

func init() {
	activityCmd := &cobra.Command{Use: "activity", Short: "Report runtime activity with an Agent Credential", GroupID: groupAgent}
	reportCmd := &cobra.Command{Use: "report", Short: "Report a runtime activity/audit event", RunE: runActivityReport}
	reportCmd.Flags().StringVar(&activityPayloadFile, "file", "", "read the activity JSON body from a file, or '-' for stdin")
	_ = reportCmd.MarkFlagRequired("file")
	activityCmd.AddCommand(reportCmd)

	// A hook, not a command people type: Claude Code runs it around every tool
	// call and hands it the event on stdin. It reports from outside the model,
	// so the trace does not depend on the model remembering to write one.
	hookCmd := &cobra.Command{
		Use:   "hook",
		Short: "Report a Claude Code PreToolUse/PostToolUse event read from stdin",
		Long: "Report every tool call to Contro1 from a Claude Code hook.\n\n" +
			"Add to .claude/settings.json (or ~/.claude/settings.json):\n\n" +
			"  \"hooks\": {\n" +
			"    \"PreToolUse\":  [{ \"matcher\": \"*\", \"hooks\": [{ \"type\": \"command\", \"command\": \"contro1 activity hook --fail-closed\" }] }],\n" +
			"    \"PostToolUse\": [{ \"matcher\": \"*\", \"hooks\": [{ \"type\": \"command\", \"command\": \"contro1 activity hook\" }] }]\n" +
			"  }\n\n" +
			"One Claude Code session is one trace. With --fail-closed, a tool whose start Contro1 could not\n" +
			"record is blocked (exit code 2) instead of running unrecorded.\n\n" +
			"It reports as the Claude Code agent that contro1 connect claude-code connected on this computer,\n" +
			"found the same way contro1 mcp serve finds it. Only a computer with more than one Claude Code\n" +
			"connection needs --agent <id>.",
		RunE:          runActivityHook,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	hookCmd.Flags().BoolVar(&hookFailClosed, "fail-closed", false, "block the tool (exit 2) when its start cannot be recorded")
	hookCmd.Flags().StringVar(&hookSource, "source", "claude-code", "integration name recorded with each step")
	hookCmd.Flags().StringVar(&hookAgent, "agent", "", "report as this agent (Contro1 agent id or the platform's own id); only needed when this computer has more than one connection for the platform")
	activityCmd.AddCommand(hookCmd)

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

// hookEvent is the part of a Claude Code hook payload this command reads.
type hookEvent struct {
	SessionID     string          `json:"session_id"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"`
}

// hookTraceID makes one trace per Claude Code session, stable across hook calls.
func hookTraceID(sessionID string) string {
	sum := sha256.Sum256([]byte("claude-code:" + sessionID))
	return "trc_" + hex.EncodeToString(sum[:16])
}

func hookTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-15] + "...[truncated]"
}

// hookBody turns one hook event into an audit record body, or nil for events
// that are not about a tool.
func hookBody(event hookEvent, source string, now time.Time) map[string]any {
	name := strings.TrimSpace(event.ToolName)
	if name == "" {
		return nil
	}
	if len(name) > 200 {
		name = name[:200]
	}
	call := map[string]any{"name": name}
	var action, summary string
	outcome := "success"
	switch event.HookEventName {
	case "PreToolUse":
		action, summary = "tool."+name+".started", "Calling "+name
		call["started_at"] = now.UTC().Format(time.RFC3339)
		var input map[string]any
		if json.Unmarshal(event.ToolInput, &input) == nil && input != nil {
			call["input"] = input
		}
	case "PostToolUse":
		action, summary = "tool."+name+".finished", name+" returned"
		call["ended_at"] = now.UTC().Format(time.RFC3339)
		var response map[string]any
		if json.Unmarshal(event.ToolResponse, &response) == nil {
			if msg, ok := response["error"].(string); ok && msg != "" {
				outcome = "failure"
				call["error"] = hookTruncate(msg, 2000)
			}
		}
		if outcome == "success" && len(event.ToolResponse) > 0 {
			call["output_summary"] = hookTruncate(string(event.ToolResponse), 2000)
		}
		call["outcome"] = outcome
	default:
		return nil
	}
	if len(action) > 128 {
		action = action[:128]
	}
	body := map[string]any{
		"action":     action,
		"summary":    summary,
		"source":     map[string]any{"integration": source, "run_id": event.SessionID},
		"outcome":    outcome,
		"tool_calls": []any{call},
	}
	if event.SessionID != "" {
		body["trace_id"] = hookTraceID(event.SessionID)
	}
	return body
}

func runActivityHook(_ *cobra.Command, _ []string) error {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return hookFailure("could not read the hook event: " + err.Error())
	}
	var event hookEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return hookFailure("the hook event is not JSON: " + err.Error())
	}
	body := hookBody(event, hookSource, time.Now())
	if body == nil {
		return nil
	}
	c, err := activityHookClient(hookSource, hookAgent)
	if err == nil {
		_, err = c.Do("POST", "/api/centcom/v1/audit-records", body)
	}
	if err != nil {
		// Only the start can be refused: by the time PostToolUse runs, the tool has.
		if hookFailClosed && event.HookEventName == "PreToolUse" {
			fmt.Fprintf(os.Stderr, "Contro1 could not record this tool call, so it was blocked: %v\n", err)
			os.Exit(2)
		}
		return nil
	}
	return nil
}

/*
activityHookClient is who the hook reports as: the agent `contro1 connect`
connected on this computer for the hook's platform, found the way `contro1 mcp
serve` finds it.

WHY. The hook needed --broker-endpoint "$(contro1 mcp endpoint)" to know which
agent it was, so the documented settings line carried a shell substitution
that does not run the same in every shell Claude Code uses, and a copy of an
address the service may change. The mapping the service publishes already
says it, with revoked, suspended and expired connections left out. An explicit
--broker-endpoint (or CONTRO1_BROKER_ENDPOINT) or agent token still wins; with
several connections for the platform and none named, the error names the flag
and the ids, rather than reporting as a guess.
*/
func activityHookClient(source, selector string) (*client.Client, error) {
	if resolveBrokerEndpoint() != "" || anyEnvTokenConfigured() {
		c, _, _, err := newRuntimeClient()
		return c, err
	}
	connection, err := hookConnection(source, selector)
	if err != nil {
		return nil, err
	}
	return runtimeEndpointClient(connection.Endpoint)
}

// hookConnection is the local connection the hook reports as, or the sentence
// that says which flag or command is missing.
func hookConnection(source, selector string) (platforms.LocalConnection, error) {
	platform := hookPlatform(source)
	connection, err := platforms.SelectLocalConnectionFor(platform, selector)
	if err != nil {
		return platforms.LocalConnection{}, errors.New(hookConnectionMessage(err, platform, selector))
	}
	return connection, nil
}

// hookPlatform is the platform whose connection a hook source reports as. A
// source that is not a platform contro1 connects narrows nothing.
func hookPlatform(source string) string {
	for _, p := range platforms.Supported {
		if p == source {
			return p
		}
	}
	return ""
}

// hookConnectionMessage is the one line a person reads when the hook could not
// pick a connection: what is wrong and the exact flag or command that fixes it.
func hookConnectionMessage(err error, platform, selector string) string {
	label := orDefault(platform, "Contro1")
	connect := "contro1 connect " + orDefault(platform, "<platform>")
	var ambiguous *platforms.AmbiguousConnectionError
	switch {
	case errors.As(err, &ambiguous):
		ids := make([]string, 0, len(ambiguous.Candidates))
		for _, c := range ambiguous.Candidates {
			ids = append(ids, c.AgentID)
		}
		return fmt.Sprintf("this computer has %d %s connections (%s), so the hook needs to be told which one it is. Add --agent <id> to the hook command, e.g. contro1 activity hook --agent %s", len(ids), label, strings.Join(ids, ", "), ids[0])
	case errors.Is(err, platforms.ErrInactiveConnection):
		return err.Error()
	case selector != "":
		return fmt.Sprintf("no active %s connection on this computer matches --agent %s. Run %s to see the agents connected here", label, selector, strings.TrimSpace("contro1 status "+platform))
	case errors.Is(err, platforms.ErrNoLocalConnection):
		return "this computer has no active " + label + " connection. Run " + connect + " and approve it; the hook then reports as that agent (" + err.Error() + ")"
	}
	return err.Error()
}

// hookFailure blocks the tool when failing closed, and otherwise lets it run.
func hookFailure(message string) error {
	if hookFailClosed {
		fmt.Fprintln(os.Stderr, "Contro1: "+message)
		os.Exit(2)
	}
	return nil
}
