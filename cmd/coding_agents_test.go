package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

func publishCodexMapping(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", dir)
	entries := []runtimeproto.MappingEntry{{PlatformSubject: "codex@abc", AgentID: "agt_codex", EnrollmentID: "enr_codex",
		EndpointMode: runtimeproto.ModeApplications, Endpoint: "unix:///run/contro1/ep/codex.sock"}}
	raw, _ := json.Marshal(runtimeproto.MappingFile{SchemaVersion: runtimeproto.SchemaVersion, Platform: "codex", Entries: entries, Digest: runtimeproto.MappingDigest(entries)})
	if err := os.WriteFile(filepath.Join(dir, "codex.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func clearRuntimeEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"CONTRO1_AGENT_TOKEN_FILE", "CONTRO1_AGENT_TOKEN", "CONTRO1_TOKEN", "CONTRO1_BROKER_ENDPOINT"} {
		t.Setenv(k, "")
	}
	old := flagBrokerEndpoint
	flagBrokerEndpoint = ""
	t.Cleanup(func() { flagBrokerEndpoint = old })
}

// With `contro1 connect codex` done, the deploy hook asks as the Codex agent,
// not as the person signed in to the CLI.
func TestCodexHookAsksAsTheCodexAgent(t *testing.T) {
	clearRuntimeEnv(t)
	publishCodexMapping(t)
	c, asAgent, err := codexHookClient()
	if err != nil || c == nil || !asAgent {
		t.Fatalf("the Codex connection is used: %v %v", asAgent, err)
	}

	// Revoked by the service: not used, and the hook goes back to how it worked
	// before (the person's sign-in), never to a refused agent.
	dir := os.Getenv("CONTRO1_PLATFORMS_DIR")
	status, _ := json.Marshal(map[string]any{"enrollments": []map[string]string{{"enrollment_id": "enr_codex", "state": "revoked"}}})
	_ = os.WriteFile(filepath.Join(dir, "status.json"), status, 0o644)
	if _, asAgent, _ := codexHookClient(); asAgent {
		t.Fatal("a revoked Codex connection is not used")
	}
}

func TestCodexHookWithoutAConnectionUsesTheSignIn(t *testing.T) {
	clearRuntimeEnv(t)
	t.Setenv("CONTRO1_PLATFORMS_DIR", t.TempDir())
	if _, asAgent, _ := codexHookClient(); asAgent {
		t.Fatal("no Codex connection: the person's sign-in, as before")
	}
}

// The elevated phase deletes a file named by the platform. Only a platform
// contro1 knows is accepted, so a phase file cannot point it elsewhere.
func TestLocalRevokeOnlyNamesKnownPlatforms(t *testing.T) {
	layout := brokerpaths.Development()
	layout.PlatformsDir = t.TempDir()
	layout.ControlEndpoint = "unix:///nonexistent/contro1-test-control.sock"
	for _, bad := range []string{"../../etc/passwd", "codex/../x", ""} {
		if err := revokePlatformOverControl(context.Background(), layout, bad); err == nil || !strings.Contains(err.Error(), "unknown platform") {
			t.Fatalf("%q must be refused: %v", bad, err)
		}
	}
	// A service that does not answer: the mapping it left is removed.
	path := filepath.Join(layout.PlatformsDir, "codex.json")
	_ = os.WriteFile(path, []byte("{}"), 0o644)
	if err := revokePlatformOverControl(context.Background(), layout, "codex"); err != nil {
		t.Fatalf("no service: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the leftover mapping is removed: %v", err)
	}
}
