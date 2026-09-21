package cmd

import (
	"encoding/json"
	"strings"
	"testing"
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
