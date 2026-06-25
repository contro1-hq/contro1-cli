//go:build e2e

// End-to-end developer test for the contro1 CLI, derived from the documentation
// at /docs/cli (and README.md). It exercises every documented command group against
// a live backend and asserts the documented behavior (exit codes, JSON shape).
//
// It is gated behind the `e2e` build tag so it never runs in the normal unit suite
// (`go test ./...`). Run it explicitly:
//
//	# get a token once: contro1 auth login && contro1 auth print-access-token --yes
//	export CONTRO1_API_URL=https://api.contro1.com   # or your local stack
//	export CONTRO1_TOKEN=cco_cli_live_xxx
//	go test -tags e2e -v .
//
// Without those env vars the test skips cleanly.
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var (
	bin    string
	apiURL string
)

func TestMain(m *testing.M) {
	apiURL = os.Getenv("CONTRO1_API_URL")
	if apiURL == "" || os.Getenv("CONTRO1_TOKEN") == "" {
		// Nothing to test against - skip the whole suite cleanly.
		os.Stderr.WriteString("e2e: set CONTRO1_API_URL and CONTRO1_TOKEN to run; skipping\n")
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "contro1-e2e")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "contro1")
	if os.PathSeparator == '\\' {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		panic("build failed: " + err.Error())
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// run invokes the CLI with --api-url injected; CONTRO1_TOKEN is inherited from env.
// It returns STDOUT only (status messages go to stderr, which is logged for
// debugging) so JSON output can be parsed cleanly.
func run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	full := append([]string{"--api-url", apiURL}, args...)
	cmd := exec.Command(bin, full...)
	cmd.Env = os.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("failed to run %v: %v", args, err)
		}
	}
	if stderr.Len() > 0 {
		t.Logf("[stderr %s] %s", strings.Join(args, " "), strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), code
}

// runJSON runs a command with --format json and decodes the stdout.
func runJSON(t *testing.T, v any, args ...string) int {
	t.Helper()
	out, code := run(t, append(args, "--format", "json")...)
	if code == 0 && strings.TrimSpace(out) != "" {
		if err := json.Unmarshal([]byte(out), v); err != nil {
			t.Fatalf("invalid JSON from %v: %v\n%s", args, err, out)
		}
	}
	return code
}

func mustZero(t *testing.T, code int, name string) {
	t.Helper()
	if code != 0 {
		t.Fatalf("%s: expected exit 0, got %d", name, code)
	}
}

// ---- Core: auth / config / whoami / doctor / scopes ----

func TestWhoami(t *testing.T) {
	var data struct {
		Operator struct{ Email string } `json:"operator"`
		Org      struct{ Name string } `json:"org"`
		Auth     struct {
			Type   string   `json:"type"`
			Scopes []string `json:"scopes"`
		} `json:"auth"`
	}
	mustZero(t, runJSON(t, &data, "whoami"), "whoami")
	if data.Org.Name == "" {
		t.Error("whoami: expected an org name")
	}
	if data.Auth.Type != "cli_operator_token" {
		t.Errorf("whoami: expected cli_operator_token, got %q", data.Auth.Type)
	}
	if len(data.Auth.Scopes) == 0 {
		t.Error("whoami: expected at least one scope")
	}
}

func TestScopes(t *testing.T) {
	var scopes []string
	mustZero(t, runJSON(t, &scopes, "scopes"), "scopes")
	if len(scopes) == 0 {
		t.Error("scopes: expected a non-empty scope list")
	}
}

func TestDoctor(t *testing.T) {
	// doctor returns 0 only when all checks pass; with a valid token it should.
	out, code := run(t, "doctor")
	if code != 0 {
		t.Fatalf("doctor: expected exit 0, got %d\n%s", code, out)
	}
}

func TestConfigList(t *testing.T) {
	var cfg map[string]any
	mustZero(t, runJSON(t, &cfg, "config", "list"), "config list")
}

func TestHelpGroupsByTopic(t *testing.T) {
	out, code := run(t, "help")
	mustZero(t, code, "help")
	for _, group := range []string{"Core:", "Agent workflows:", "Read-only admin:", "Operator queue:"} {
		if !strings.Contains(out, group) {
			t.Errorf("help: missing topic group %q", group)
		}
	}
}

// ---- Agent workflows: agents / requests / evidence / ai-registry ----

func TestAgentsRegisterAndList(t *testing.T) {
	var reg map[string]any
	mustZero(t, runJSON(t, &reg, "agents", "register", "--name", "E2E Test Agent", "--type", "coding-agent"), "agents register")
	if reg["agent_id"] == nil {
		t.Error("agents register: expected an agent_id")
	}
	var list []any
	mustZero(t, runJSON(t, &list, "agents", "list"), "agents list")
}

func TestRequestsLifecycle(t *testing.T) {
	var created map[string]any
	mustZero(t, runJSON(t, &created, "requests", "create", "--type", "approval", "--question", "E2E approve?", "--risk", "low"), "requests create")
	id, _ := created["request_id"].(string)
	if id == "" {
		id, _ = created["id"].(string)
	}
	if id == "" {
		t.Fatal("requests create: no request_id returned")
	}

	var got map[string]any
	mustZero(t, runJSON(t, &got, "requests", "get", id), "requests get")

	var list []any
	mustZero(t, runJSON(t, &list, "requests", "list"), "requests list")

	// Documented exit code 6 on timeout: an unapproved request times out fast.
	if _, code := run(t, "requests", "wait", id, "--timeout", "3s"); code != 6 {
		t.Errorf("requests wait (unapproved): expected exit 6 (timeout), got %d", code)
	}

	// Evidence for a real request must succeed.
	if _, code := run(t, "evidence", "for-request", id); code != 0 {
		t.Errorf("evidence for-request: expected exit 0, got %d", code)
	}
}

func TestAiRegistryImportAndList(t *testing.T) {
	inv := filepath.Join(t.TempDir(), "inventory.json")
	body := `{"ai_systems_found":[{"name":"E2E System","environment":"test","risk_category":"transparency_only"}]}`
	if err := os.WriteFile(inv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var imp map[string]any
	mustZero(t, runJSON(t, &imp, "ai-registry", "import", inv), "ai-registry import")
	var reg map[string]any
	mustZero(t, runJSON(t, &reg, "ai-registry", "list"), "ai-registry list")
}

// ---- Read-only admin + operator queue ----

func TestReadOnlySurfaces(t *testing.T) {
	cases := [][]string{
		{"org", "get"},
		{"api-keys", "list"},
		{"webhooks", "status"},
		{"integrations", "list"},
		{"queue", "list"},
		{"queue", "my-requests"},
	}
	for _, c := range cases {
		var v any
		if code := runJSON(t, &v, c...); code != 0 {
			t.Errorf("%s: expected exit 0, got %d", strings.Join(c, " "), code)
		}
	}
}

// ---- Documented exit codes ----

func TestExitCodes(t *testing.T) {
	// Bad arguments -> exit 2 (missing required --question).
	if _, code := run(t, "requests", "create"); code != 2 {
		t.Errorf("requests create with no flags: expected exit 2, got %d", code)
	}
	// Invalid request id -> non-zero (general error).
	if _, code := run(t, "requests", "get", "not-a-valid-id"); code == 0 {
		t.Error("requests get with bad id: expected non-zero exit")
	}
}
