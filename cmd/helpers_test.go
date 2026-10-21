package cmd

import (
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/config"
)

// A localhost profile left over from development made a clean connect test
// run against a server nobody else can reach, silently.
func TestADevelopmentServerIsNamedAndProductionIsNot(t *testing.T) {
	cfg := &config.Config{CurrentProfile: "default", Profiles: map[string]*config.Profile{
		"default": {APIURL: "http://localhost:8080", WebURL: "http://localhost:3000"},
	}}
	note := developmentServerNote(cfg, "default", "http://localhost:8080", "http://localhost:3000")
	if note != "Using a development server at http://localhost:8080. For production: contro1 config profiles use prod" {
		t.Fatalf("%q", note)
	}
	// Only the web URL on this computer still counts.
	if note := developmentServerNote(cfg, "default", "https://api.contro1.com", "http://127.0.0.1:3000/"); !strings.Contains(note, "http://127.0.0.1:3000.") {
		t.Fatalf("%q", note)
	}
	// An existing production profile is the one named.
	cfg.Profiles["work"] = &config.Profile{APIURL: "https://api.contro1.com", WebURL: "https://contro1.com"}
	if note := developmentServerNote(cfg, "default", "http://[::1]:8080", ""); !strings.HasSuffix(note, "profiles use work") {
		t.Fatalf("%q", note)
	}
	for _, prod := range []string{"https://api.contro1.com", "https://contro1.com", "https://localhost.example.com", ""} {
		if note := developmentServerNote(cfg, "work", prod, "https://contro1.com"); note != "" {
			t.Fatalf("nothing for %q: %q", prod, note)
		}
	}
}

func TestStr(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"hello", "hello"},
		{true, "true"},
		{float64(5), "5"},
		{float64(2.5), "2.5"},
	}
	for _, c := range cases {
		if got := str(c.in); got != c.want {
			t.Errorf("str(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := str(firstNonEmpty(nil, "", "x", "y")); got != "x" {
		t.Errorf("firstNonEmpty = %q, want x", got)
	}
	if firstNonEmpty(nil, "") != nil {
		t.Error("firstNonEmpty of all-empty should be nil")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	if got := truncate("abcdefghij", 5); len([]rune(got)) != 5 {
		t.Errorf("truncate len = %d, want 5 (%q)", len([]rune(got)), got)
	}
	if got := truncate("a\nb", 10); got != "a b" {
		t.Errorf("truncate newline = %q, want 'a b'", got)
	}
}

func TestClassifyDecision(t *testing.T) {
	cases := []struct {
		resp map[string]any
		want string
	}{
		{map[string]any{"response": map[string]any{"approved": true}}, "approved"},
		{map[string]any{"response": map[string]any{"approved": false}}, "denied"},
		{map[string]any{"response": map[string]any{"status": "approved"}}, "approved"},
		{map[string]any{"response": map[string]any{"status": "rejected"}}, "denied"},
		{map[string]any{"response": map[string]any{"text": "fyi"}}, "responded"},
		{map[string]any{}, "responded"},
	}
	for i, c := range cases {
		if got := classifyDecision(c.resp); got != c.want {
			t.Errorf("case %d: classifyDecision = %q, want %q", i, got, c.want)
		}
	}
}

func TestBuildCreatePayloadAdvancedRouting(t *testing.T) {
	reqPayloadFile = ""
	reqType = "approval"
	reqQuestion = "Approve payment?"
	reqContext = ""
	reqAgent = "agt_123"
	reqRisk = "high"
	reqReason = "Payment exceeds limit"
	reqPriority = "urgent"
	reqRole = "finance"
	reqSLAMinutes = 10
	reqExternalRequestID = "payment-1"
	reqCorrelationID = "case-payment-1"
	reqTraceID = "trc_payment_1"
	reqApprovalMode = ""
	reqRequiredApprovals = 2
	reqApprovalRoles = []string{"finance"}
	reqMustIncludeRoles = []string{"cfo"}
	reqSeparationOfDuties = true
	reqFailClosedOnTimeout = true
	reqStrictPolicy = false
	reqApprovalCommentRequired = true
	reqMetadataFile = ""
	reqResponseSchemaFile = ""
	reqPolicyContextFile = ""
	reqToolCallsFile = ""
	reqSubAgentsFile = ""
	reqRetrievedContextFile = ""
	defer func() {
		reqQuestion = ""
		reqContext = ""
		reqAgent = ""
		reqRisk = ""
		reqReason = ""
		reqPriority = ""
		reqRole = ""
		reqSLAMinutes = 0
		reqExternalRequestID = ""
		reqCorrelationID = ""
		reqTraceID = ""
		reqRequiredApprovals = 0
		reqApprovalRoles = nil
		reqMustIncludeRoles = nil
		reqApprovalCommentRequired = false
	}()

	payload, err := buildCreatePayload()
	if err != nil {
		t.Fatalf("buildCreatePayload error: %v", err)
	}
	if got := payload["required_role"]; got != "finance" {
		t.Fatalf("required_role = %v, want finance", got)
	}
	if got := payload["sla_minutes"]; got != 10 {
		t.Fatalf("sla_minutes = %v, want 10", got)
	}
	policy := asMap(payload["approval_policy"])
	if got := policy["mode"]; got != "threshold" {
		t.Fatalf("approval_policy.mode = %v, want threshold", got)
	}
	if got := policy["required_approvals"]; got != 2 {
		t.Fatalf("approval_policy.required_approvals = %v, want 2", got)
	}
	requirements := asMap(payload["approval_requirements"])
	if got, ok := requirements["required_roles"].([]string); !ok || len(got) != 1 || got[0] != "finance" {
		t.Fatalf("approval_requirements.required_roles = %v, want [finance]", got)
	}
	if got, ok := requirements["must_include_roles"].([]string); !ok || len(got) != 1 || got[0] != "cfo" {
		t.Fatalf("approval_requirements.must_include_roles = %v, want [cfo]", got)
	}
	meta := asMap(payload["metadata"])
	actor := asMap(meta["actor"])
	if got := actor["agent_id"]; got != "agt_123" {
		t.Fatalf("metadata.actor.agent_id = %v, want agt_123", got)
	}
}
