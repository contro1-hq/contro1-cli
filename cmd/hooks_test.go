package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMatchesDeployCommand(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{"npm test", false},
		{"npm run deploy", true},
		{"pnpm deploy:production", true},
		{"kubectl apply -f k8s/production.yaml", true},
		{"helm upgrade billing ./chart", true},
		{"terraform plan", false},
		{"terraform apply plan.tfplan", true},
		{"rg deploy README.md", false},
		{"npm test && git status", false},
		{"npm test && npm run deploy:prod", true},
	}
	for _, test := range tests {
		got, err := matchesDeployCommand(test.command, nil, false)
		if err != nil {
			t.Fatalf("matchesDeployCommand(%q): %v", test.command, err)
		}
		if got != test.want {
			t.Errorf("matchesDeployCommand(%q) = %v, want %v", test.command, got, test.want)
		}
	}
}

func TestMatchesDeployCommandRejectsInvalidCustomRegex(t *testing.T) {
	if _, err := matchesDeployCommand("deploy", []string{"["}, false); err == nil {
		t.Fatal("expected invalid regex to fail closed")
	}
}

func TestBuildCodexDeployPayloadSeparatesProvenance(t *testing.T) {
	oldRole, oldRisk, oldEnvironment, oldTarget, oldReason, oldSetup := codexHookRole, codexHookRisk, codexHookEnvironment, codexHookTarget, codexHookReason, codexHookSetup
	oldSLA, oldApprovals, oldTimeout := codexHookSLAMinutes, codexHookRequiredApprovals, codexHookTimeout
	t.Cleanup(func() {
		codexHookRole, codexHookRisk, codexHookEnvironment, codexHookTarget, codexHookReason, codexHookSetup = oldRole, oldRisk, oldEnvironment, oldTarget, oldReason, oldSetup
		codexHookSLAMinutes, codexHookRequiredApprovals, codexHookTimeout = oldSLA, oldApprovals, oldTimeout
	})
	codexHookRole = "release-manager"
	codexHookRisk = "critical"
	codexHookEnvironment = "production"
	codexHookTarget = "billing-api"
	codexHookReason = "Production deploy requires release manager approval"
	codexHookSetup = "enterprise"
	codexHookSLAMinutes = 10
	codexHookRequiredApprovals = 2

	payload := buildCodexDeployPayload(codexHookInput{
		SessionID:      "session-1",
		TurnID:         "turn-1",
		ToolUseID:      "tool-1",
		CWD:            "C:/repo",
		HookEventName:  "PreToolUse",
		PermissionMode: "default",
		ToolName:       "Bash",
		ToolInput:      map[string]any{"command": "npm run deploy"},
	}, "npm run deploy")

	if payload["request_type"] != "approval" || payload["risk_level"] != "critical" {
		t.Fatalf("unexpected canonical request: %#v", payload)
	}
	context := asMap(payload["context"])
	machine := asMap(context["machine_observed"])
	agent := asMap(context["agent_reported"])
	if machine["command"] != "npm run deploy" || machine["target"] != "billing-api" {
		t.Fatalf("missing machine-observed deploy facts: %#v", machine)
	}
	if agent["justification"] != codexHookReason {
		t.Fatalf("missing agent-reported justification: %#v", agent)
	}
	policy := asMap(payload["approval_policy"])
	if policy["required_approvals"] != 2 || policy["mode"] != "threshold" {
		t.Fatalf("unexpected approval policy: %#v", policy)
	}
	if roles, _ := policy["required_roles"].([]string); len(roles) != 1 || roles[0] != "release-manager" {
		t.Fatalf("a role asked for must be required: %#v", policy)
	}
	if asMap(payload["routing"])["required_role"] != "release-manager" {
		t.Fatalf("a role asked for must route: %#v", payload["routing"])
	}
	if _, err := json.Marshal(payload); err != nil {
		t.Fatalf("payload is not JSON serializable: %v", err)
	}
}

// Without --role nothing names a role, so the server routes the request to the
// agent's reviewer or the action's approval policy. A built-in "cto" sent it to
// a role most organizations do not have.
func TestBuildCodexDeployPayloadWithoutRoleNamesNone(t *testing.T) {
	oldRole, oldApprovals := codexHookRole, codexHookRequiredApprovals
	t.Cleanup(func() { codexHookRole, codexHookRequiredApprovals = oldRole, oldApprovals })
	codexHookRole = ""
	codexHookRequiredApprovals = 1

	payload := buildCodexDeployPayload(codexHookInput{SessionID: "s", ToolName: "Bash", ToolInput: map[string]any{"command": "npm run deploy"}}, "npm run deploy")
	if _, ok := asMap(payload["routing"])["required_role"]; ok {
		t.Fatalf("no role was asked for, yet routing names one: %#v", payload["routing"])
	}
	if _, ok := asMap(payload["approval_policy"])["required_roles"]; ok {
		t.Fatalf("approval_policy names roles: %#v", payload["approval_policy"])
	}
	if _, ok := asMap(payload["approval_requirements"])["required_roles"]; ok {
		t.Fatalf("approval_requirements names roles: %#v", payload["approval_requirements"])
	}
	encoded, _ := json.Marshal(payload)
	if strings.Contains(string(encoded), "cto") {
		t.Fatalf("payload still carries the old default role: %s", encoded)
	}
}

func TestBuildCodexDeployPayloadRedactsSecretsButHashesOriginal(t *testing.T) {
	command := "kubectl apply --token supersecret -f prod.yaml"
	payload := buildCodexDeployPayload(codexHookInput{
		SessionID: "session-1",
		ToolName:  "Bash",
		ToolInput: map[string]any{
			"command":  command,
			"password": "hunter2",
			"nested":   map[string]any{"api_key": "cc_live_abcdefgh"},
		},
	}, command)

	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, secret := range []string{"supersecret", "hunter2", "cc_live_abcdefgh"} {
		if strings.Contains(text, secret) {
			t.Fatalf("canonical payload leaked %q: %s", secret, text)
		}
	}
	machine := asMap(asMap(payload["context"])["machine_observed"])
	if machine["command_sha256"] != sha256Hex(command) {
		t.Fatalf("command hash must be calculated from the original command: %#v", machine)
	}
}

func TestRedactCommandArgsRedactsSeparatedSecretValue(t *testing.T) {
	redacted := redactCommandArgs([]string{"deploy", "--token", "supersecret", "--region", "us-east-1"})
	if got := strings.Join(redacted, " "); got != "deploy --token [REDACTED] --region us-east-1" {
		t.Fatalf("unexpected redacted argv: %s", got)
	}
}
