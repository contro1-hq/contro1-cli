package platforms

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// pinHost makes the host facts the installers read fixed for one test.
func pinHost(t *testing.T) {
	t.Helper()
	oldBin, oldNow := contro1Binary, nowFunc
	contro1Binary = func() string { return "/usr/local/bin/contro1" }
	nowFunc = func() time.Time { return time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC) }
	t.Cleanup(func() { contro1Binary, nowFunc = oldBin, oldNow })
	for _, k := range []string{"OPENCLAW_CONFIG_PATH", "OPENCLAW_STATE_DIR", "OPENCLAW_HOME", "OPENCLAW_PROFILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("CONTRO1_PLATFORMS_DIR", t.TempDir())
}

// ---- Claude Code -------------------------------------------------------------

func claudeRunner(registered string, ran *[]string) Runner {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		*ran = append(*ran, line)
		if line == "claude mcp get contro1" {
			if registered == "" {
				return nil, errors.New("exit status 1: No MCP server found with name: contro1")
			}
			return []byte(registered), nil
		}
		return []byte("ok"), nil
	}
}

func TestClaudeCodePreviewAndInstallTheMcpServer(t *testing.T) {
	pinHost(t)
	var ran []string
	a, _ := New("claude-code", Options{Home: t.TempDir(), Runner: claudeRunner("", &ran)})
	installer := a.(McpInstaller)

	changes := installer.McpChanges(context.Background(), []string{"claude-code@mac"})
	if len(changes) != 1 || changes[0].After != "claude mcp add --scope user contro1 -- contro1 mcp serve --agent claude-code@mac" {
		t.Fatalf("the preview shows the exact command: %+v", changes)
	}
	ran = nil
	var j Journal
	if _, err := installer.InstallMcp(context.Background(), []string{"claude-code@mac"}, &j); err != nil {
		t.Fatal(err)
	}
	if ran[len(ran)-1] != "claude mcp add --scope user contro1 -- contro1 mcp serve --agent claude-code@mac" {
		t.Fatalf("installed with the previewed command: %v", ran)
	}
}

// A second connect previews nothing and runs nothing but the question.
func TestClaudeCodeMcpIsSkippedWhenItAlreadyServesThisAgent(t *testing.T) {
	pinHost(t)
	registered := "contro1:\n  Scope: User config (available in all your projects)\n  Type: stdio\n  Command: contro1\n  Args: mcp serve --agent claude-code@mac\n"
	var ran []string
	a, _ := New("claude-code", Options{Home: t.TempDir(), Runner: claudeRunner(registered, &ran)})
	installer := a.(McpInstaller)
	if changes := installer.McpChanges(context.Background(), []string{"claude-code@mac"}); len(changes) != 0 {
		t.Fatalf("nothing to change, nothing to preview: %+v", changes)
	}
	ran = nil
	out, err := installer.InstallMcp(context.Background(), []string{"claude-code@mac"}, &Journal{})
	if err != nil || len(out.Done) != 1 {
		t.Fatalf("%+v %v", out, err)
	}
	for _, line := range ran {
		if strings.Contains(line, " add ") || strings.Contains(line, " remove ") {
			t.Fatalf("an entry that is right is left alone: %v", ran)
		}
	}

	// Registered for another agent: replaced, never left beside the new one.
	other := strings.ReplaceAll(registered, "claude-code@mac", "claude-code@old-name")
	ran = nil
	b, _ := New("claude-code", Options{Home: t.TempDir(), Runner: claudeRunner(other, &ran)})
	changes := b.(McpInstaller).McpChanges(context.Background(), []string{"claude-code@mac"})
	if len(changes) != 1 || !strings.Contains(changes[0].Before, "claude-code@old-name") {
		t.Fatalf("the preview says what it replaces: %+v", changes)
	}
	ran = nil
	if _, err := b.(McpInstaller).InstallMcp(context.Background(), []string{"claude-code@mac"}, &Journal{}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ran, "|")
	if !strings.Contains(joined, "claude mcp remove --scope user contro1|claude mcp add") {
		t.Fatalf("removed, then added: %s", joined)
	}
}

// Connect installs the MCP server now, so it is no longer the person's step.
func TestClaudeCodeRemainingSetupNoLongerNamesTheMcpServer(t *testing.T) {
	a, _ := New("claude-code", Options{Home: t.TempDir(), Runner: fakeRunner(nil)})
	for _, step := range a.RemainingSetup() {
		if strings.Contains(step, "apps enable") || strings.Contains(step, "MCP") {
			t.Fatalf("the MCP step belongs to connect now: %q", step)
		}
	}
}

// connect previews for the agents it found and the ones already mapped, which
// on Claude Code are the same one twice.
func TestClaudeCodePreviewIgnoresTheSameAgentNamedTwice(t *testing.T) {
	pinHost(t)
	var ran []string
	a, _ := New("claude-code", Options{Home: t.TempDir(), Runner: claudeRunner("", &ran)})
	if changes := a.(McpInstaller).McpChanges(context.Background(), []string{"claude-code@mac", "claude-code@mac"}); len(changes) != 1 {
		t.Fatalf("one agent, one change: %+v", changes)
	}
}
