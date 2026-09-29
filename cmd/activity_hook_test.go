package cmd

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHookBodyStartCarriesInputAndOneTracePerSession(t *testing.T) {
	now := time.Date(2026, 9, 28, 9, 41, 2, 0, time.UTC)
	event := hookEvent{SessionID: "sess-1", HookEventName: "PreToolUse", ToolName: "Bash", ToolInput: json.RawMessage(`{"command":"ls"}`)}
	body := hookBody(event, "claude-code", now)
	if body == nil {
		t.Fatal("expected a body for PreToolUse")
	}
	if body["action"] != "tool.Bash.started" {
		t.Fatalf("action = %v", body["action"])
	}
	call := body["tool_calls"].([]any)[0].(map[string]any)
	if call["input"].(map[string]any)["command"] != "ls" {
		t.Fatalf("input = %v", call["input"])
	}
	if body["trace_id"] != hookTraceID("sess-1") || hookTraceID("sess-1") == hookTraceID("sess-2") {
		t.Fatal("one stable trace per session")
	}
	if len(body["trace_id"].(string)) != 4+32 {
		t.Fatalf("trace id shape: %v", body["trace_id"])
	}
}

func TestHookBodyEndReportsFailure(t *testing.T) {
	event := hookEvent{SessionID: "s", HookEventName: "PostToolUse", ToolName: "Write", ToolResponse: json.RawMessage(`{"error":"permission denied"}`)}
	body := hookBody(event, "claude-code", time.Now())
	if body["outcome"] != "failure" {
		t.Fatalf("outcome = %v", body["outcome"])
	}
	call := body["tool_calls"].([]any)[0].(map[string]any)
	if call["error"] != "permission denied" || call["output_summary"] != nil {
		t.Fatalf("call = %v", call)
	}
}

func TestHookBodyIgnoresEventsThatAreNotAboutATool(t *testing.T) {
	if hookBody(hookEvent{HookEventName: "Stop"}, "claude-code", time.Now()) != nil {
		t.Fatal("Stop is not a tool call")
	}
	if hookBody(hookEvent{HookEventName: "UserPromptSubmit", ToolName: "x"}, "claude-code", time.Now()) != nil {
		t.Fatal("only PreToolUse and PostToolUse are reported")
	}
}
