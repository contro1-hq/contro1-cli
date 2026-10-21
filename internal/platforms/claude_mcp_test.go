package platforms

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// fakeClaude keeps one entry per scope, like the real CLI: get reports the one
// that wins (local, then project, then user); add and remove act on one scope.
type fakeClaude struct {
	scopes    map[string]string // scope -> "command args" or an http URL
	ran       []string
	removeErr error
}

func (f *fakeClaude) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.ran = append(f.ran, line)
	switch {
	case line == "claude mcp get contro1":
		for _, s := range []string{"local", "project", "user"} {
			if v, ok := f.scopes[s]; ok {
				label := map[string]string{"local": "Local config (private to you in this project)", "project": "Project config (shared via .mcp.json)", "user": "User config (available in all your projects)"}[s]
				if strings.HasPrefix(v, "http") {
					return []byte(fmt.Sprintf("contro1:\n  Scope: %s\n  Type: http\n  URL: %s\n", label, v)), nil
				}
				cmd, rest, _ := strings.Cut(v, " ")
				return []byte(fmt.Sprintf("contro1:\n  Scope: %s\n  Type: stdio\n  Command: %s\n  Args: %s\n", label, cmd, rest)), nil
			}
		}
		return nil, errors.New("exit status 1: No MCP server found with name: contro1")
	case strings.HasPrefix(line, "claude mcp remove --scope "):
		if f.removeErr != nil {
			return nil, f.removeErr
		}
		scope := args[3]
		if _, ok := f.scopes[scope]; !ok {
			return nil, errors.New("exit status 1: No " + scope + "-scoped MCP server found")
		}
		delete(f.scopes, scope)
		return nil, nil
	case strings.HasPrefix(line, "claude mcp add --scope user contro1 -- "):
		if _, ok := f.scopes["user"]; ok {
			return nil, errors.New("exit status 1: MCP server contro1 already exists in user config")
		}
		f.scopes["user"] = strings.TrimPrefix(line, "claude mcp add --scope user contro1 -- ")
		return nil, nil
	}
	return nil, errors.New("unexpected " + line)
}

func (f *fakeClaude) wrote() bool {
	for _, l := range f.ran {
		if strings.Contains(l, " add ") || strings.Contains(l, " remove ") {
			return true
		}
	}
	return false
}

func claudeWith(t *testing.T, f *fakeClaude) McpInstaller {
	a, _ := New("claude-code", Options{Home: t.TempDir(), Runner: f.run})
	return a.(McpInstaller)
}

const ccSubject = "claude-code@x"

// v0.2.27 finished with success when claude was not on PATH. Connect still
// does, and names the one line to run.
func TestClaudeMissingIsAStepForThePersonNotAFailure(t *testing.T) {
	pinHost(t)
	missing := func(context.Context, string, ...string) ([]byte, error) {
		return nil, &exec.Error{Name: "claude", Err: exec.ErrNotFound}
	}
	a, _ := New("claude-code", Options{Home: t.TempDir(), Runner: missing})
	want := "claude mcp add --scope user contro1 -- /usr/local/bin/contro1 mcp serve --agent " + ccSubject
	if ch := a.(McpInstaller).McpChanges(context.Background(), []string{ccSubject}); len(ch) != 1 || !strings.Contains(ch[0].Description, want) {
		t.Fatalf("the preview says what will be asked of the person: %+v", ch)
	}
	out, err := a.(McpInstaller).InstallMcp(context.Background(), []string{ccSubject}, &Journal{})
	if err != nil || len(out.ToDo) != 1 || !strings.Contains(out.ToDo[0], want) {
		t.Fatalf("a still-to-do with the exact line, not an error: %+v %v", out, err)
	}
}

// The docs form: local scope, no --agent. It acts as this agent while it is the
// only connection, so it is left alone, and a second run does not re-preview.
func TestALocalUnpinnedEntryThatServesThisAgentIsLeftAlone(t *testing.T) {
	pinHost(t)
	f := &fakeClaude{scopes: map[string]string{"local": "contro1 mcp serve"}}
	inst := claudeWith(t, f)
	for run := 1; run <= 2; run++ {
		f.ran = nil
		if ch := inst.McpChanges(context.Background(), []string{ccSubject}); len(ch) != 0 {
			t.Fatalf("run %d: nothing to preview: %+v", run, ch)
		}
		out, err := inst.InstallMcp(context.Background(), []string{ccSubject}, &Journal{})
		if err != nil || f.wrote() || len(out.Done) != 1 || !strings.Contains(out.Done[0], "names no agent") {
			t.Fatalf("run %d: untouched, with how to pin it: %+v %v %v", run, out, err, f.ran)
		}
	}
}

// The same unpinned entry once a second agent is connected here no longer
// acts as this one: it is replaced, and the preview shows what it was.
func TestAnUnpinnedEntryWithSeveralConnectionsIsReplacedVisibly(t *testing.T) {
	pinHost(t)
	dir := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", dir)
	writeMapping(t, dir, "openclaw", []runtimeproto.MappingEntry{entry("main", "agt_main", "unix:///run/contro1/ep/main.sock")})
	f := &fakeClaude{scopes: map[string]string{"local": "contro1 mcp serve"}}
	inst := claudeWith(t, f)
	ch := inst.McpChanges(context.Background(), []string{ccSubject})
	if len(ch) != 1 || ch[0].Before != "contro1 mcp serve" || !strings.Contains(ch[0].After, "remove --scope local") {
		t.Fatalf("the replacement is shown with what it replaces: %+v", ch)
	}
	if _, err := inst.InstallMcp(context.Background(), []string{ccSubject}, &Journal{}); err != nil {
		t.Fatal(err)
	}
	if _, local := f.scopes["local"]; local || f.scopes["user"] != "contro1 mcp serve --agent "+ccSubject {
		t.Fatalf("local removed, user pinned: %v", f.scopes)
	}
}

// A person sign-in (HTTP) is another identity: shown in the preview, and
// replaced only after the confirmation that preview asks for.
func TestAPersonSignInEntryIsShownBeforeItIsReplaced(t *testing.T) {
	pinHost(t)
	f := &fakeClaude{scopes: map[string]string{"user": "https://api.contro1.com/api/centcom/mcp"}}
	inst := claudeWith(t, f)
	ch := inst.McpChanges(context.Background(), []string{ccSubject})
	if len(ch) != 1 || ch[0].Before != "https://api.contro1.com/api/centcom/mcp" {
		t.Fatalf("the preview names the current entry: %+v", ch)
	}
	if _, err := inst.InstallMcp(context.Background(), []string{ccSubject}, &Journal{}); err != nil {
		t.Fatal(err)
	}
	if f.scopes["user"] != "contro1 mcp serve --agent "+ccSubject {
		t.Fatalf("replaced: %v", f.scopes)
	}
}

// A failed remove is the error, not the "already exists" that follows it.
func TestAFailedRemoveIsReportedAsItself(t *testing.T) {
	pinHost(t)
	f := &fakeClaude{scopes: map[string]string{"user": "contro1 mcp serve --agent claude-code@old"}, removeErr: errors.New("exit status 1")}
	_, err := claudeWith(t, f).InstallMcp(context.Background(), []string{ccSubject}, &Journal{})
	if err == nil || !strings.Contains(err.Error(), "could not remove") || strings.Contains(err.Error(), "already exists") {
		t.Fatalf("%v", err)
	}
}

// A project's .mcp.json is shared with everyone on the project: named, never changed.
func TestAProjectEntryForAnotherIdentityIsNamedNotChanged(t *testing.T) {
	pinHost(t)
	f := &fakeClaude{scopes: map[string]string{"project": "contro1 mcp serve --agent claude-code@colleague"}}
	out, err := claudeWith(t, f).InstallMcp(context.Background(), []string{ccSubject}, &Journal{})
	if err != nil || f.wrote() || len(out.ToDo) != 1 || !strings.Contains(out.ToDo[0], ".mcp.json") {
		t.Fatalf("%+v %v %v", out, err, f.ran)
	}
}

// A --development connection reads its own service's mappings for identity.
func TestDevelopmentIdentityReadsTheDevelopmentMappings(t *testing.T) {
	dev := t.TempDir()
	writeClaudeMapping(t, filepath.Join(dev, "claude-code.json"), "sha256:dev", "claude-code@devbox")
	t.Setenv("CONTRO1_PLATFORMS_DIR", t.TempDir()) // the production one is empty
	mac := machineReaders{goos: "darwin", runner: fakeRunner(map[string]string{
		"ioreg -rd1 -c IOPlatformExpertDevice": `"IOPlatformUUID" = "4C4C4544-0042-3510-8051-B4C04F4D4E32"`,
	})}
	c := &claudeCode{opts: Options{PlatformsDir: dev}, machine: &mac, hostname: func() (string, error) { return "devbox", nil }}
	_, subjects, err := c.Discover(context.Background())
	if err != nil || len(subjects) != 1 || subjects[0].ID != "claude-code@devbox" {
		t.Fatalf("the existing development subject is reused, not duplicated: %+v %v", subjects, err)
	}
}
