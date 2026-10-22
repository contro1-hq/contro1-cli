package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/platforms"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

func openClawConnection(subject string) platforms.LocalConnection {
	return platforms.LocalConnection{Platform: "openclaw", PlatformSubject: subject, AgentID: "agt_" + subject}
}

// The words a person reads in their agent's chat. Each names a real id and the
// exact command, because there is nowhere else for them to look one up.
func TestMcpSetupMessageNamesTheExactFix(t *testing.T) {
	several := []platforms.LocalConnection{openClawConnection("main"), openClawConnection("dash"), openClawConnection("michaella")}
	ambiguous := &platforms.AmbiguousConnectionError{Candidates: several}

	got := mcpSetupMessage(ambiguous, "", "", several, "/usr/local/bin/contro1")
	for _, want := range []string{
		"Several agents are connected on this computer: main, dash, michaella.",
		"Start this server with --agent <id>, e.g. contro1 mcp serve --agent main",
		"run contro1 connect openclaw",
		"contro1-main runs /usr/local/bin/contro1 mcp serve --agent main",
		"without a restart",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}

	none := mcpSetupMessage(platforms.ErrNoLocalConnection, "", "", nil, "")
	if !strings.Contains(none, "This computer is not connected to Contro1. Run contro1 connect <claude-code|cursor|codex|openclaw|nanoclaw>") {
		t.Fatalf("unconnected: %q", none)
	}
	if fromClaude := mcpSetupMessage(platforms.ErrNoLocalConnection, "", "claude-code", nil, ""); !strings.Contains(fromClaude, "Run contro1 connect claude-code ") {
		t.Fatalf("the calling platform is named when known: %q", fromClaude)
	}

	wrong := mcpSetupMessage(fmt.Errorf("no connection on this computer matches %q", "mian"), "mian", "", several, "contro1")
	if !strings.Contains(wrong, `No agent named "mian"`) || !strings.Contains(wrong, "Connected here: main, dash, michaella") {
		t.Fatalf("a wrong --agent names what exists: %q", wrong)
	}

	mixed := []platforms.LocalConnection{{Platform: "claude-code", PlatformSubject: "claude-code@abc"}, openClawConnection("main")}
	if got := mcpSetupMessage(&platforms.AmbiguousConnectionError{Candidates: mixed}, "", "", mixed, "contro1"); !strings.Contains(got, "claude-code@abc (claude-code), main (openclaw)") {
		t.Fatalf("platforms are named when they differ: %q", got)
	}
	for _, msg := range []string{got, none, wrong} {
		if strings.ContainsRune(msg, 0x2014) {
			t.Fatalf("no em dash: %q", msg)
		}
	}
}

// A process started from a Claude Code session inherits CLAUDECODE. With two
// connections and no --agent it must get the setup tool, not Claude Code's
// identity.
func TestServeDoesNotPickAnIdentityFromTheParentProcess(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", dir)
	t.Setenv("CLAUDECODE", "1")
	for platform, subject := range map[string]string{"claude-code": "claude-code@abc", "openclaw": "main"} {
		entries := []runtimeproto.MappingEntry{{PlatformSubject: subject, AgentID: "agt_" + platform, EnrollmentID: "enr_" + platform,
			EndpointMode: runtimeproto.ModeApplications, Endpoint: "unix:///run/contro1/ep/" + platform + ".sock"}}
		raw, _ := json.Marshal(runtimeproto.MappingFile{SchemaVersion: runtimeproto.SchemaVersion, Platform: platform, Digest: runtimeproto.MappingDigest(entries), Entries: entries})
		if err := os.WriteFile(filepath.Join(dir, platform+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var ambiguous *platforms.AmbiguousConnectionError
	if _, err := selectServeConnection(""); !errors.As(err, &ambiguous) {
		t.Fatalf("no identity may be chosen from CLAUDECODE: %v", err)
	}
}
