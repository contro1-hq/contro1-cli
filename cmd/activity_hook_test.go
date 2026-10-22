package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
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

// publishMappings writes one mapping file per platform into a fresh platforms
// directory, as the Contro1 service would, and returns it.
func publishMappings(t *testing.T, byPlatform map[string][]runtimeproto.MappingEntry) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", dir)
	for platform, entries := range byPlatform {
		raw, _ := json.Marshal(runtimeproto.MappingFile{SchemaVersion: runtimeproto.SchemaVersion, Platform: platform, Entries: entries, Digest: runtimeproto.MappingDigest(entries)})
		if err := os.WriteFile(filepath.Join(dir, platform+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func hookEntry(subject, agent, enrollment string) runtimeproto.MappingEntry {
	return runtimeproto.MappingEntry{PlatformSubject: subject, AgentID: agent, EnrollmentID: enrollment,
		EndpointMode: runtimeproto.ModeApprovalsOnly, Endpoint: "unix:///run/contro1/ep/" + agent + ".sock"}
}

// The hook finds the Claude Code connection by itself, like mcp serve, and a
// Codex connection on the same computer does not make it ambiguous.
func TestActivityHookFindsTheClaudeCodeConnection(t *testing.T) {
	clearRuntimeEnv(t)
	publishMappings(t, map[string][]runtimeproto.MappingEntry{
		"claude-code": {hookEntry("claude-code@laptop", "agt_claude", "enr_claude")},
		"codex":       {hookEntry("codex@laptop", "agt_codex", "enr_codex")},
	})
	conn, err := hookConnection("claude-code", "")
	if err != nil || conn.AgentID != "agt_claude" {
		t.Fatalf("the Claude Code agent is used: %+v %v", conn, err)
	}
	if c, err := activityHookClient("claude-code", ""); err != nil || c == nil {
		t.Fatalf("a client through that endpoint: %v", err)
	}
}

// A connection the service reports revoked is skipped, exactly as mcp serve
// skips it, so the one left is used without anyone naming it.
func TestActivityHookSkipsARevokedConnection(t *testing.T) {
	clearRuntimeEnv(t)
	dir := publishMappings(t, map[string][]runtimeproto.MappingEntry{
		"claude-code": {hookEntry("old@laptop", "agt_old", "enr_old"), hookEntry("new@laptop", "agt_new", "enr_new")},
	})
	status, _ := json.Marshal(map[string]any{"enrollments": []map[string]string{{"enrollment_id": "enr_old", "state": "revoked"}, {"enrollment_id": "enr_new", "state": "active"}}})
	_ = os.WriteFile(filepath.Join(dir, "status.json"), status, 0o644)
	conn, err := hookConnection("claude-code", "")
	if err != nil || conn.AgentID != "agt_new" {
		t.Fatalf("the active connection is used: %+v %v", conn, err)
	}
	if _, err := hookConnection("claude-code", "agt_old"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("naming the revoked one says it is revoked: %v", err)
	}
}

// Several Claude Code connections and none named: the error is the exact flag
// and the ids to choose from, never a guess.
func TestActivityHookWithSeveralConnectionsNamesTheFlag(t *testing.T) {
	clearRuntimeEnv(t)
	publishMappings(t, map[string][]runtimeproto.MappingEntry{
		"claude-code": {hookEntry("a@laptop", "agt_a", "enr_a"), hookEntry("b@laptop", "agt_b", "enr_b")},
	})
	_, err := hookConnection("claude-code", "")
	if err == nil {
		t.Fatal("two connections and none named must not pick one")
	}
	for _, want := range []string{"--agent <id>", "contro1 activity hook --agent agt_a", "agt_a", "agt_b"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%q missing from: %v", want, err)
		}
	}
	conn, err := hookConnection("claude-code", "agt_b")
	if err != nil || conn.AgentID != "agt_b" {
		t.Fatalf("--agent picks it: %+v %v", conn, err)
	}
}

func TestActivityHookWithoutAConnectionSaysConnect(t *testing.T) {
	clearRuntimeEnv(t)
	t.Setenv("CONTRO1_PLATFORMS_DIR", t.TempDir())
	_, err := hookConnection("claude-code", "")
	if err == nil || !strings.Contains(err.Error(), "contro1 connect claude-code") {
		t.Fatalf("names the command: %v", err)
	}
	if strings.Contains(err.Error(), "mcp endpoint") {
		t.Fatal("never sends people to copy an endpoint")
	}
}

// An explicit endpoint still wins, with nothing published at all.
func TestActivityHookExplicitEndpointWins(t *testing.T) {
	clearRuntimeEnv(t)
	t.Setenv("CONTRO1_PLATFORMS_DIR", t.TempDir())
	flagBrokerEndpoint = "unix:///run/contro1/ep/explicit.sock"
	if c, err := activityHookClient("claude-code", ""); err != nil || c == nil {
		t.Fatalf("--broker-endpoint is used as given: %v", err)
	}
}
