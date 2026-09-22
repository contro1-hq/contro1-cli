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
		}
		return nil, errors.New("unexpected OneCLI command")
	}
	if err := installOnecliLease(context.Background(), conn, "https://api.contro1.com/api/centcom/mcp", lease, run); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || strings.Join(calls[2], " ") != "agents grants attach-secret --id onecli-agent-1 --secret-id secret-1" {
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
	if err == nil || len(commands) != 4 || commands[3] != "secrets delete --id secret-1" {
		t.Fatalf("orphaned vault secret after failed grant: %v, commands=%v", err, commands)
	}
}
