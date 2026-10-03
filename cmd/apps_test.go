package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/platforms"
)

/*
The exact body /api/centcom/v1/runtime/status returns.

This is the shape that broke it: the credential description lives under `auth`,
it was read from `credential`, and a wrong field name decodes to an empty struct
rather than an error. So a healthy service produced "did not report this
connection's mode" and sent somebody looking for a broken broker.

Kept here as a literal, because the point is to notice if the server ever
renames it again.
*/
const runtimeStatusBody = `{
  "ok": true,
  "org": {"id": "6899", "name": "Contro1"},
  "auth": {
    "type": "runtime_enrollment",
    "credential_kind": "agent_runtime",
    "agent_id": "agt_8dd242a79e245e861fb6cfdf",
    "enrollment_id": "enr_2a793d8f774a827d0a1d94b1",
    "endpoint_mode": "approval_bridge_only",
    "mode_label": "Approvals only",
    "owner_approved": true
  }
}`

func decodeStatus(t *testing.T, body string) (runtimeStatus, error) {
	t.Helper()
	var parsed struct {
		Auth       *runtimeStatus `json:"auth"`
		Credential *runtimeStatus `json:"credential"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return runtimeStatus{}, err
	}
	for _, candidate := range []*runtimeStatus{parsed.Auth, parsed.Credential} {
		if candidate != nil && candidate.EndpointMode != "" {
			return *candidate, nil
		}
	}
	return runtimeStatus{}, errUnreadableStatus
}

var errUnreadableStatus = &statusError{}

type statusError struct{}

func (e *statusError) Error() string { return "no mode" }

func TestRuntimeStatusIsReadFromTheFieldTheServerUses(t *testing.T) {
	status, err := decodeStatus(t, runtimeStatusBody)
	if err != nil {
		t.Fatalf("the real server body must parse: %v", err)
	}
	if status.EndpointMode != "approval_bridge_only" || status.ModeLabel != "Approvals only" {
		t.Fatalf("mode was not read: %+v", status)
	}
	if status.AgentID != "agt_8dd242a79e245e861fb6cfdf" {
		t.Fatalf("agent id was not read: %+v", status)
	}
}

func TestAWrongFieldNameFailsLoudlyRatherThanSilently(t *testing.T) {
	// The failure this replaces: a body with no recognised field decoded to an
	// empty struct and read as "the service is broken".
	if _, err := decodeStatus(t, `{"ok":true,"something_else":{"endpoint_mode":"agent_runtime"}}`); err == nil {
		t.Fatal("an unrecognised shape must be an error, not an empty mode")
	}

	// The older name still works, so a newer CLI against an older server is
	// not a second version of this same bug.
	status, err := decodeStatus(t, `{"credential":{"endpoint_mode":"agent_runtime","mode_label":"Approvals + applications"}}`)
	if err != nil || status.EndpointMode != "agent_runtime" {
		t.Fatalf("the older field name must still be accepted: %+v %v", status, err)
	}
}

func TestAnUnexpectedBodyIsShownButNotDumped(t *testing.T) {
	long := strings.Repeat("x", 1000)
	if got := truncateForError(long); len(got) != 303 || !strings.HasSuffix(got, "...") {
		t.Fatalf("a long body must be trimmed, got %d chars", len(got))
	}
	if got := truncateForError("  short  "); got != "short" {
		t.Fatalf("a short body is shown as it stands: %q", got)
	}
}

func TestOnecliLeaseGrantedOnlyToMatchingNanoAgent(t *testing.T) {
	lease := "ccr_live_test_secret_never_in_argv"
	conn := platforms.LocalConnection{PlatformSubject: "nano-group-1"}
	var calls [][]string
	var tempPath string
	run := func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if strings.Contains(strings.Join(args, " "), lease) {
			t.Fatal("lease appeared in OneCLI arguments")
		}
		switch args[0] + " " + args[1] {
		case "agents list":
			return []byte(`[{"id":"other-id","identifier":"other-group"},{"id":"onecli-agent-1","identifier":"nano-group-1"}]`), nil
		case "secrets create":
			for i := range args {
				if args[i] == "--file" {
					tempPath = args[i+1]
					got, err := os.ReadFile(tempPath)
					if err != nil || string(got) != lease {
						t.Fatalf("OneCLI file did not contain the lease: %v", err)
					}
				}
			}
			return []byte(`{"id":"secret-1"}`), nil
		case "agents grants":
			return []byte(`{"status":"attached"}`), nil
		case "secrets list":
			return []byte(`[]`), nil
		}
		return nil, errors.New("unexpected OneCLI command")
	}
	if err := installOnecliLease(context.Background(), conn, "https://api.contro1.com/api/centcom/mcp", lease, run); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 4 || strings.Join(calls[3], " ") != "agents grants attach-secret --id onecli-agent-1 --secret-id secret-1" {
		t.Fatalf("secret was not granted to exactly the matching agent: %v", calls)
	}
	created := strings.Join(calls[1], " ")
	if !strings.Contains(created, "--path-pattern /api/centcom/mcp") || !strings.Contains(created, "--host-pattern api.contro1.com") {
		t.Fatalf("secret was not confined to the MCP endpoint: %s", created)
	}
	if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
		t.Fatal("temporary lease file was not removed")
	}
}

func TestOnecliLeaseNeverCreatedForUnmatchedAgent(t *testing.T) {
	called := 0
	run := func(_ context.Context, _ ...string) ([]byte, error) {
		called++
		return []byte(`[{"id":"other-id","identifier":"other-group"}]`), nil
	}
	err := installOnecliLease(context.Background(), platforms.LocalConnection{PlatformSubject: "nano-group-1"},
		"https://api.contro1.com/api/centcom/mcp", "ccr_live_test", run)
	if err == nil || called != 1 {
		t.Fatalf("must refuse to create a credential without the exact Nano agent: %v, calls=%d", err, called)
	}
}

func TestOnecliLeaseGrantFailureDeletesVaultSecret(t *testing.T) {
	var commands []string
	run := func(_ context.Context, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(args, " "))
		switch args[0] + " " + args[1] {
		case "agents list":
			return []byte(`[{"id":"onecli-agent-1","identifier":"nano-group-1"}]`), nil
		case "secrets create":
			return []byte(`{"id":"secret-1"}`), nil
		case "agents grants":
			return nil, errors.New("grant failed")
		case "secrets delete":
			return []byte(`{"status":"deleted"}`), nil
		}
		return nil, errors.New("unexpected command")
	}
	err := installOnecliLease(context.Background(), platforms.LocalConnection{PlatformSubject: "nano-group-1"},
		"https://api.contro1.com/api/centcom/mcp", "ccr_live_test", run)
	if err == nil || len(commands) != 5 || commands[4] != "secrets delete --id secret-1" {
		t.Fatalf("orphaned vault secret after failed grant: %v, commands=%v", err, commands)
	}
}

func TestOnecliLeaseRemovesOnlyStaleSecretsForSameAgentAndRoute(t *testing.T) {
	var deleted []string
	run := func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] + " " + args[1] {
		case "agents list":
			return []byte(`[{"id":"onecli-agent-1","identifier":"nano-group-1"}]`), nil
		case "secrets create":
			return []byte(`{"id":"secret-new"}`), nil
		case "agents grants":
			return []byte(`{"status":"attached"}`), nil
		case "secrets list":
			return []byte(`[
				{"id":"secret-new","name":"Contro1 nano-group-1","hostPattern":"api.contro1.com","pathPattern":"/api/centcom/mcp"},
				{"id":"secret-old","name":"Contro1 nano-group-1","hostPattern":"api.contro1.com","pathPattern":"/api/centcom/mcp"},
				{"id":"other-group","name":"Contro1 nano-group-2","hostPattern":"api.contro1.com","pathPattern":"/api/centcom/mcp"},
				{"id":"other-route","name":"Contro1 nano-group-1","hostPattern":"api.contro1.com","pathPattern":"/other"},
				{"id":"anthropic","name":"Anthropic","hostPattern":"api.anthropic.com","pathPattern":null}
			]`), nil
		case "secrets delete":
			deleted = append(deleted, args[3])
			return []byte(`{"status":"deleted"}`), nil
		}
		return nil, errors.New("unexpected command")
	}
	if err := installOnecliLease(context.Background(), platforms.LocalConnection{PlatformSubject: "nano-group-1"},
		"https://api.contro1.com/api/centcom/mcp", "ccr_live_test", run); err != nil {
		t.Fatal(err)
	}
	if strings.Join(deleted, ",") != "secret-old" {
		t.Fatalf("expected only the stale secret for this agent and route to be removed, got %v", deleted)
	}
}

// OneCLI 2.2.5 wraps every result as {"hint": ..., "data": ...}. Every read in
// the lease flow must accept it, including the created secret, which would
// otherwise decode as an object with no id.
func TestOnecliLeaseAcceptsHintDataEnvelope(t *testing.T) {
	var commands []string
	run := func(_ context.Context, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(args, " "))
		switch args[0] + " " + args[1] {
		case "agents list":
			return []byte(`{"hint":"Showing 1 agent","data":[{"id":"onecli-agent-1","identifier":"nano-group-1"}]}`), nil
		case "secrets create":
			return []byte(`{"hint":"Secret created","data":{"id":"secret-new"}}`), nil
		case "agents grants":
			return []byte(`{"hint":"Attached","data":{"status":"attached"}}`), nil
		case "secrets list":
			return []byte(`{"hint":"Showing 2 secrets","data":[
				{"id":"secret-new","name":"Contro1 nano-group-1","hostPattern":"api.contro1.com","pathPattern":"/api/centcom/mcp"},
				{"id":"secret-old","name":"Contro1 nano-group-1","hostPattern":"api.contro1.com","pathPattern":"/api/centcom/mcp"}
			]}`), nil
		case "secrets delete":
			return []byte(`{"hint":"Deleted","data":{"status":"deleted"}}`), nil
		}
		return nil, errors.New("unexpected command")
	}
	if err := installOnecliLease(context.Background(), platforms.LocalConnection{PlatformSubject: "nano-group-1"},
		"https://api.contro1.com/api/centcom/mcp", "ccr_live_test", run); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"agents grants attach-secret --id onecli-agent-1 --secret-id secret-new",
		"secrets delete --id secret-old",
	}
	for _, w := range want {
		found := false
		for _, c := range commands {
			found = found || c == w
		}
		if !found {
			t.Fatalf("missing %q in %v", w, commands)
		}
	}
}

func TestDecodeOnecliJSONKeepsBareObjectWithOwnDataField(t *testing.T) {
	var v struct {
		Data string `json:"data"`
	}
	if err := decodeOnecliJSON([]byte(`{"data":"kept"}`), &v); err != nil || v.Data != "kept" {
		t.Fatalf("object without hint must not be unwrapped: %v %q", err, v.Data)
	}
}

// fakeOnecli225 answers like OneCLI 2.2.5: every result wrapped, agents carry
// a secretMode, and there is no `agents grants`.
func fakeOnecli225(agentsJSON, assignedJSON string, commands *[]string) onecliRunner {
	return func(_ context.Context, args ...string) ([]byte, error) {
		*commands = append(*commands, strings.Join(args, " "))
		switch args[0] + " " + args[1] {
		case "agents list":
			return []byte(`{"hint":"Manage your agents","data":` + agentsJSON + `}`), nil
		case "agents secrets":
			return []byte(`{"hint":"Secrets","data":` + assignedJSON + `}`), nil
		case "agents set-secrets":
			return []byte(`{"hint":"Updated","data":{"ok":true}}`), nil
		case "secrets create":
			return []byte(`{"hint":"Created","data":{"id":"secret-new"}}`), nil
		case "secrets list":
			return []byte(`{"hint":"Secrets","data":[
				{"id":"secret-new","name":"Contro1 nano-group-1","hostPattern":"api.contro1.com","pathPattern":"/api/centcom/mcp"},
				{"id":"secret-old","name":"Contro1 nano-group-1","hostPattern":"api.contro1.com","pathPattern":"/api/centcom/mcp"}
			]}`), nil
		case "secrets delete":
			return []byte(`{"hint":"Deleted","data":{"ok":true}}`), nil
		}
		return nil, errors.New("unknown command")
	}
}

func installFor225(run onecliRunner) error {
	return installOnecliLease(context.Background(), platforms.LocalConnection{PlatformSubject: "nano-group-1"},
		"https://api.contro1.com/api/centcom/mcp", "ccr_live_test", run)
}

// set-secrets replaces the agent's list, so the agent must keep every secret it
// had, gain the new one, and lose only the Contro1 credential it replaces.
func TestOnecliSelectiveKeepsOtherSecretsAndSwapsTheLease(t *testing.T) {
	var commands []string
	run := fakeOnecli225(
		`[{"id":"uuid-nano","name":"Nano","identifier":"nano-group-1","accessToken":"aoc_x","secretMode":"selective"}]`,
		`[{"id":"anthropic-key","name":"Anthropic"},{"id":"secret-old","name":"Contro1 nano-group-1"}]`, &commands)
	if err := installFor225(run); err != nil {
		t.Fatal(err)
	}
	want := "agents set-secrets --id uuid-nano --secret-ids secret-new,anthropic-key"
	if !containsString(commands, want) {
		t.Fatalf("missing %q in %v", want, commands)
	}
	if !containsString(commands, "secrets delete --id secret-old") {
		t.Fatalf("stale lease not deleted: %v", commands)
	}
	for _, c := range commands {
		if strings.HasPrefix(c, "agents grants") {
			t.Fatalf("2.2.5 has no agents grants: %v", commands)
		}
	}
}

// In "all" mode another agent would receive this agent's identity, so nothing
// is created and the error names that agent and the way out.
func TestOnecliRefusesWhenAnotherAgentReceivesEverySecret(t *testing.T) {
	var commands []string
	run := fakeOnecli225(`[
		{"id":"uuid-nano","name":"Nano","identifier":"nano-group-1","accessToken":"aoc_secret_token","secretMode":"all"},
		{"id":"uuid-other","name":"Other","identifier":"other-group","accessToken":"aoc_other_token","secretMode":"all"}
	]`, `[]`, &commands)
	err := installFor225(run)
	if err == nil {
		t.Fatal("must refuse while another agent is in all mode")
	}
	if len(commands) != 1 {
		t.Fatalf("nothing may be created before the refusal: %v", commands)
	}
	msg := err.Error()
	if !strings.Contains(msg, `"Other" (uuid-other)`) || !strings.Contains(msg, "set-secret-mode") {
		t.Fatalf("refusal must name the agent and the fix: %s", msg)
	}
	if strings.Contains(msg, "aoc_") {
		t.Fatalf("an agent access token leaked into the error: %s", msg)
	}
}

// Alone in "all" mode, the agent already receives the new secret; the list is
// not rewritten, which would silently switch what it receives.
func TestOnecliAllModeAloneNeedsNoAssignment(t *testing.T) {
	var commands []string
	run := fakeOnecli225(`[
		{"id":"uuid-nano","name":"Nano","identifier":"nano-group-1","secretMode":"all"},
		{"id":"uuid-other","name":"Other","identifier":"other-group","secretMode":"selective"}
	]`, `[]`, &commands)
	if err := installFor225(run); err != nil {
		t.Fatal(err)
	}
	for _, c := range commands {
		if strings.HasPrefix(c, "agents set-secrets") || strings.HasPrefix(c, "agents grants") {
			t.Fatalf("all mode must not rewrite assignments: %v", commands)
		}
	}
	if !containsString(commands, "secrets delete --id secret-old") {
		t.Fatalf("stale lease not deleted: %v", commands)
	}
}

func TestOnecliSelectiveUnreadableListCreatesNothing(t *testing.T) {
	var commands []string
	run := fakeOnecli225(`[{"id":"uuid-nano","identifier":"nano-group-1","secretMode":"selective"}]`, `[{"name":"no id"}]`, &commands)
	if err := installFor225(run); err == nil {
		t.Fatal("an unreadable assignment list must stop before set-secrets could drop the agent's other secrets")
	}
	for _, c := range commands {
		if strings.HasPrefix(c, "secrets create") {
			t.Fatalf("created a secret it could not assign: %v", commands)
		}
	}
}

func TestOnecliLeaseExposureNamesAgentsInAllMode(t *testing.T) {
	var commands []string
	run := fakeOnecli225(`[
		{"id":"uuid-nano","name":"Nano","identifier":"nano-group-1","accessToken":"aoc_a","secretMode":"all"},
		{"id":"uuid-new","name":"NewGroup","identifier":"other-group","accessToken":"aoc_b","secretMode":"all"},
		{"id":"uuid-sel","name":"Careful","identifier":"third-group","secretMode":"selective"}
	]`, `[]`, &commands)
	stored, exposed, err := onecliLeaseExposure(context.Background(), "nano-group-1", "api.contro1.com", "/api/centcom/mcp", run)
	if err != nil || !stored {
		t.Fatalf("lease is stored: %v %v", stored, err)
	}
	if len(exposed) != 1 || exposed[0] != `"NewGroup" (uuid-new)` {
		t.Fatalf("only the other all-mode agent is exposed: %v", exposed)
	}
	for _, c := range commands {
		if !strings.HasPrefix(c, "agents list") && !strings.HasPrefix(c, "secrets list") {
			t.Fatalf("doctor must only read: %v", commands)
		}
	}
}
