package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/output"
)

func clearTokenEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CONTRO1_AGENT_TOKEN_FILE", "")
	t.Setenv("CONTRO1_AGENT_TOKEN", "")
	t.Setenv("CONTRO1_TOKEN", "")
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	exit, ok := err.(*output.ExitError)
	if !ok {
		t.Fatalf("error = %T (%v), want *output.ExitError", err, err)
	}
	return exit.Code
}

func writeToken(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRuntimeTokenRefusesBrowserCliTokenFromEverySource(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(t *testing.T)
	}{
		{"CONTRO1_TOKEN", func(t *testing.T) { t.Setenv("CONTRO1_TOKEN", "cco_cli_live_browser") }},
		{"CONTRO1_AGENT_TOKEN", func(t *testing.T) { t.Setenv("CONTRO1_AGENT_TOKEN", "cco_cli_live_browser") }},
		{"CONTRO1_AGENT_TOKEN_FILE", func(t *testing.T) {
			t.Setenv("CONTRO1_AGENT_TOKEN_FILE", writeToken(t, "cco_cli_live_browser\n"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearTokenEnv(t)
			tc.set(t)
			_, _, err := resolveRuntimeToken()
			if got := exitCode(t, err); got != output.CodeUnsafeBlocked {
				t.Fatalf("exit code = %d, want %d", got, output.CodeUnsafeBlocked)
			}
		})
	}
}

func TestAgentTokenVariablesAreIgnoredByNormalCommands(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("CONTRO1_AGENT_TOKEN", "cco_cli_live_browser")
	t.Setenv("CONTRO1_TOKEN", "cc_test_normal")
	tok, err := resolveToken("default")
	if err != nil || tok != "cc_test_normal" {
		t.Fatalf("normal resolveToken = %q, %v; it must ignore CONTRO1_AGENT_TOKEN", tok, err)
	}
}

func TestContro1TokenKeepsAcceptingCliTokensOutsideRuntime(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("CONTRO1_TOKEN", "cco_cli_live_ci")
	tok, err := resolveToken("default")
	if err != nil || tok != "cco_cli_live_ci" {
		t.Fatalf("resolveToken = %q, %v; CI use of CONTRO1_TOKEN must not change", tok, err)
	}
}

func TestRuntimeTokenPrecedenceAndNoKeychainFallback(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("CONTRO1_AGENT_TOKEN_FILE", writeToken(t, " cc_test_from_file \n"))
	t.Setenv("CONTRO1_AGENT_TOKEN", "cc_test_from_env")
	t.Setenv("CONTRO1_TOKEN", "cc_test_generic")
	token, source, err := resolveRuntimeToken()
	if err != nil || token != "cc_test_from_file" || source != "CONTRO1_AGENT_TOKEN_FILE" {
		t.Fatalf("resolveRuntimeToken = %q, %q, %v", token, source, err)
	}

	clearTokenEnv(t)
	if _, _, err := resolveRuntimeToken(); exitCode(t, err) != output.CodeAuth {
		t.Fatal("with no env token, runtime commands must fail instead of using the keychain")
	}
}

func TestOperatorProfileRefusesAgentTokenEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".contro1"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "current_profile: reviewer\nprofiles:\n  reviewer:\n    api_url: http://127.0.0.1:1\n    access_profile: operator\n"
	if err := os.WriteFile(filepath.Join(home, ".contro1", "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	clearTokenEnv(t)
	t.Setenv("CONTRO1_AGENT_TOKEN", "cc_test_agent")
	if _, _, err := newClient(); exitCode(t, err) != output.CodeAuth {
		t.Fatal("an operator profile must not run on an env-supplied agent token")
	}
}

func TestCheckRuntimeAuth(t *testing.T) {
	runtimeAuth := map[string]any{
		"credential_kind": "agent_runtime",
		"agent_id":        "agt_1",
		"scopes":          []any{"actions:execute", "audit:write"},
	}
	if err := checkRuntimeAuth(runtimeAuth, "actions:execute"); err != nil {
		t.Fatalf("valid runtime credential refused: %v", err)
	}
	if got := exitCode(t, checkRuntimeAuth(runtimeAuth, "requests:create")); got != output.CodeInsufficient {
		t.Fatalf("missing scope exit = %d", got)
	}
	orgKey := map[string]any{"credential_kind": "organization_integration", "agent_id": "agt_1", "scopes": []any{"actions:execute"}}
	if got := exitCode(t, checkRuntimeAuth(orgKey, "actions:execute")); got != output.CodeUnsafeBlocked {
		t.Fatalf("organization key exit = %d", got)
	}
	unbound := map[string]any{"credential_kind": "agent_runtime", "scopes": []any{"actions:execute"}}
	if got := exitCode(t, checkRuntimeAuth(unbound, "actions:execute")); got != output.CodeUnsafeBlocked {
		t.Fatalf("unbound credential exit = %d", got)
	}
}

func isolatedHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestRequestsRuntimeFlagNeverUsesKeychainOrBrowserToken(t *testing.T) {
	isolatedHome(t)
	reqRuntime = true
	t.Cleanup(func() { reqRuntime = false })

	clearTokenEnv(t)
	if _, _, err := requestClient("requests:create"); exitCode(t, err) != output.CodeAuth {
		t.Fatal("requests --runtime with no env token must fail, not fall back to the keychain")
	}

	clearTokenEnv(t)
	t.Setenv("CONTRO1_AGENT_TOKEN_FILE", writeToken(t, "cco_cli_live_browser"))
	if _, _, err := requestClient("requests:create"); exitCode(t, err) != output.CodeUnsafeBlocked {
		t.Fatal("requests --runtime must refuse a browser-issued token")
	}
}

func TestActionsReadRuntimeFlagNeverUsesKeychain(t *testing.T) {
	isolatedHome(t)
	actionsReadRuntime = true
	t.Cleanup(func() { actionsReadRuntime = false })
	clearTokenEnv(t)
	if _, _, err := fetchInvocation("inv_1"); exitCode(t, err) != output.CodeAuth {
		t.Fatal("actions get --runtime with no env token must fail, not fall back to the keychain")
	}
}

// Every manifest command must run as the host bridge's Agent Credential. A command
// that silently used the normal CLI identity would let a bridge act as whichever
// developer is logged in on the host.
func TestBridgeManifestCommandsAllUseRuntimeIdentity(t *testing.T) {
	alwaysRuntime := map[string]bool{"actions invoke": true, "actions cancel": true, "activity report": true}
	for _, command := range bridgeManifest("openclaw")["commands"].([]map[string]any) {
		cli := command["cli"].([]string)
		if alwaysRuntime[cli[1]+" "+cli[2]] {
			continue
		}
		hasRuntime := false
		for _, arg := range cli {
			hasRuntime = hasRuntime || arg == "--runtime"
		}
		if !hasRuntime {
			t.Fatalf("manifest command %v does not pin the runtime identity", cli)
		}
	}
}

func TestBridgeManifestIsDiscoveryOnly(t *testing.T) {
	manifest := bridgeManifest("openclaw")
	if manifest["runtime_contract"] != "contro1-cli-runtime-v1" {
		t.Fatalf("runtime_contract = %v", manifest["runtime_contract"])
	}
	commands, ok := manifest["commands"].([]map[string]any)
	if !ok || len(commands) == 0 {
		t.Fatal("manifest has no commands")
	}
	for _, command := range commands {
		cli := command["cli"].([]string)
		joined := strings.Join(cli, " ")
		for _, forbidden := range []string{"queue", "auth", "run", "mcp"} {
			if len(cli) > 1 && cli[1] == forbidden {
				t.Fatalf("manifest exposes %q to agents", joined)
			}
		}
	}
	serialized := strings.ToLower(str(manifest))
	for _, warning := range []string{"print-access-token", "queue approve", "queue reject", "not an enforcement boundary"} {
		if !strings.Contains(serialized, warning) {
			t.Fatalf("manifest should state %q", warning)
		}
	}
}

func TestBrokerEndpointIsExclusiveWithTokens(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("CONTRO1_BROKER_ENDPOINT", "npipe:////./pipe/contro1-ep-test-exclusive")
	t.Setenv("CONTRO1_AGENT_TOKEN", "cc_live_agent")
	_, _, _, err := newRuntimeClient()
	if exitCode(t, err) != output.CodeUnsafeBlocked {
		t.Fatalf("endpoint plus token must be refused locally, got %v", err)
	}
	if rem := err.(*output.ExitError).Remediation; rem == nil || rem.Code != "TWO_RUNTIME_IDENTITIES_CONFIGURED" {
		t.Fatalf("refusal must carry a remediation, got %+v", rem)
	}
}

func TestUnreachableBrokerNeverFallsBack(t *testing.T) {
	clearTokenEnv(t)
	endpoint := "npipe:////./pipe/contro1-ep-test-missing"
	if runtime.GOOS != "windows" {
		endpoint = "unix://" + filepath.ToSlash(filepath.Join(t.TempDir(), "missing.sock"))
	}
	t.Setenv("CONTRO1_BROKER_ENDPOINT", endpoint)
	c, _, source, err := newRuntimeClient()
	if err != nil || source != "broker_endpoint" || c.Token != "" {
		t.Fatalf("client via broker: %v %q", err, source)
	}
	_, err = c.Do("GET", "/api/centcom/v1/runtime/status", nil)
	if exitCode(t, err) != output.CodeNetwork {
		t.Fatalf("unreachable broker must be a network failure, got %v", err)
	}
	if rem := err.(*output.ExitError).Remediation; rem == nil || rem.Code != "BROKER_UNREACHABLE" {
		t.Fatalf("unreachable broker needs a remediation, got %+v", rem)
	}
}

func TestBadBrokerEndpointIsRejected(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("CONTRO1_BROKER_ENDPOINT", "http://127.0.0.1:9999")
	if _, _, _, err := newRuntimeClient(); exitCode(t, err) != output.CodeBadArgs {
		t.Fatalf("a network URL is not a local endpoint: %v", err)
	}
}
