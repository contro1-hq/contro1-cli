package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

var testMachine = machineReaders{goos: "linux", readFile: func(p string) ([]byte, error) {
	if p == "/etc/machine-id" {
		return []byte("b08dfa6083e7567a1921a715000001fb\n"), nil
	}
	return nil, os.ErrNotExist
}}

// Cursor and Codex are one agent per computer each, named by the machine, like
// Claude Code, and private to whoever is at it.
func TestCursorAndCodexAreTheirOwnAgentPerComputer(t *testing.T) {
	key := machineKey("b08dfa6083e7567a1921a715000001fb")
	for _, tc := range []struct{ platform, label string }{{"cursor", "Cursor"}, {"codex", "Codex"}} {
		a := &localCodingAgent{platform: tc.platform, label: tc.label, machine: &testMachine,
			hostname: func() (string, error) { return "Laptop-7", nil }, mappingPath: filepath.Join(t.TempDir(), "none.json")}
		instance, subjects, err := a.Discover(context.Background())
		if err != nil || len(subjects) != 1 {
			t.Fatalf("%s discover: %+v %v", tc.platform, subjects, err)
		}
		if subjects[0].ID != tc.platform+"@"+key || subjects[0].Display != tc.label+" on Laptop-7" || instance.Label != tc.label {
			t.Fatalf("%s identity: %+v %+v", tc.platform, subjects[0], instance)
		}
		a.opts.Principal = "ariel"
		reach, _ := a.Reach(context.Background(), subjects[0].ID)
		if !reach.Complete || len(reach.Contexts) != 1 || reach.Contexts[0].Kind != runtimeproto.ReachPrivate || reach.Platform != tc.platform {
			t.Fatalf("%s reach must be the private local host: %+v", tc.platform, reach)
		}
		if a.RemainingSetup() != nil || a.PlanConfig("x") != nil {
			t.Fatalf("%s needs nothing else from the person", tc.platform)
		}
	}

	// A subject already connected is kept even if the machine id stops being
	// readable: switching it would create a second agent.
	path := filepath.Join(t.TempDir(), "codex.json")
	raw, _ := json.Marshal(runtimeproto.MappingFile{SchemaVersion: runtimeproto.SchemaVersion, Platform: "codex", PlatformInstanceDigest: "sha256:kept",
		Entries: []runtimeproto.MappingEntry{entry("codex@laptop-7", "agt_c", "unix:///x.sock")}, Digest: runtimeproto.MappingDigest([]runtimeproto.MappingEntry{entry("codex@laptop-7", "agt_c", "unix:///x.sock")})})
	_ = os.WriteFile(path, raw, 0o644)
	a := &localCodingAgent{platform: "codex", label: "Codex", machine: &testMachine, hostname: func() (string, error) { return "laptop-7", nil }, mappingPath: path}
	instance, subjects, _ := a.Discover(context.Background())
	if subjects[0].ID != "codex@laptop-7" || instance.Digest != "sha256:kept" {
		t.Fatalf("an existing connection keeps its subject: %+v %+v", subjects, instance)
	}

	for _, p := range []string{"cursor", "codex"} {
		if adapter, err := New(p, Options{Home: t.TempDir()}); err != nil || adapter.Name() != p {
			t.Fatalf("New(%s): %v", p, err)
		}
	}
}

// ---- Cursor ------------------------------------------------------------------

func cursorIn(t *testing.T) (*cursor, string) {
	t.Helper()
	pinHost(t)
	home := t.TempDir()
	c := newCursor(Options{Home: home})
	return c, filepath.Join(home, ".cursor", "mcp.json")
}

const cursorSubject = "cursor@abc"

func TestCursorMcpKeepsEveryOtherServerAndBacksUpFirst(t *testing.T) {
	c, path := cursorIn(t)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	original := `{
  "mcpServers": {
    "zeta": {"command": "npx", "args": ["-y", "zeta-mcp"], "env": {"TOKEN": "keep-me"}},
    "alpha": {"url": "https://alpha.example/mcp"}
  },
  "otherSetting": true
}`
	_ = os.WriteFile(path, []byte(original), 0o600)

	changes := c.McpChanges(context.Background(), []string{cursorSubject})
	if len(changes) != 1 || changes[0].Path != path || !strings.Contains(changes[0].After, "--agent") {
		t.Fatalf("one previewed change naming the file: %+v", changes)
	}
	var j Journal
	out, err := c.InstallMcp(context.Background(), []string{cursorSubject}, &j)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	text := string(raw)
	if strings.Index(text, `"zeta"`) > strings.Index(text, `"alpha"`) || strings.Index(text, `"alpha"`) > strings.Index(text, `"contro1"`) {
		t.Fatalf("servers keep their order, ours is added last: %s", text)
	}
	if !strings.Contains(text, `"keep-me"`) || !strings.Contains(text, `"otherSetting": true`) {
		t.Fatalf("other servers and keys are kept as they were: %s", text)
	}
	servers, err := c.McpServers(context.Background())
	if err != nil || len(servers) != 3 || !servers[2].ServesAgent(cursorSubject) || servers[2].Command != "/usr/local/bin/contro1" {
		t.Fatalf("contro1 runs mcp serve for this agent: %+v %v", servers, err)
	}
	if backup, err := os.ReadFile(path + ".bak-contro1-20261020-093000"); err != nil || string(backup) != original {
		t.Fatalf("the file as it was is backed up: %v", err)
	}
	if len(j.CreatedFiles) != 0 || len(j.WrittenFiles) != 1 {
		t.Fatalf("never journaled as created, so disconnect cannot delete it: %+v", j)
	}
	if len(out.Done) == 0 {
		t.Fatal("the step says what it did")
	}

	// A second run changes nothing and says so.
	if again := c.McpChanges(context.Background(), []string{cursorSubject}); len(again) != 0 {
		t.Fatalf("second preview is empty: %+v", again)
	}
	out, _ = c.InstallMcp(context.Background(), []string{cursorSubject}, &j)
	if len(out.Done) != 1 || !strings.Contains(out.Done[0], "already") {
		t.Fatalf("idempotent: %+v", out)
	}
}

func TestCursorMcpCreatesTheFileAndReplacesAnotherIdentityOnlyVisibly(t *testing.T) {
	c, path := cursorIn(t)
	if changes := c.McpChanges(context.Background(), []string{cursorSubject}); len(changes) != 1 || !strings.Contains(changes[0].Description, "creates the file") {
		t.Fatalf("a missing file is created: %+v", changes)
	}
	var j Journal
	if _, err := c.InstallMcp(context.Background(), []string{cursorSubject}, &j); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	// Now another agent: the preview shows what runs today.
	changes := c.McpChanges(context.Background(), []string{"cursor@other"})
	if len(changes) != 1 || !strings.Contains(changes[0].Before, "--agent "+cursorSubject) || !strings.Contains(changes[0].Description, "Replace") {
		t.Fatalf("a replacement shows what it replaces: %+v", changes)
	}
}

func TestCursorMcpLeavesAFileItCannotReadAlone(t *testing.T) {
	c, path := cursorIn(t)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	commented := "{\n  // my servers\n  \"mcpServers\": {}\n}\n"
	_ = os.WriteFile(path, []byte(commented), 0o600)

	changes := c.McpChanges(context.Background(), []string{cursorSubject})
	if len(changes) != 1 || !strings.HasPrefix(changes[0].After, `"contro1": `) {
		t.Fatalf("the exact block is named instead: %+v", changes)
	}
	var j Journal
	out, err := c.InstallMcp(context.Background(), []string{cursorSubject}, &j)
	if err != nil || len(out.ToDo) != 1 || !strings.Contains(out.ToDo[0], `"contro1": `) {
		t.Fatalf("a step for the person with the block: %+v %v", out, err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != commented {
		t.Fatal("the file must not be touched")
	}
	if _, err := c.McpServers(context.Background()); !errors.Is(err, ErrMcpConfigUnreadable) {
		t.Fatalf("doctor hears it as unreadable: %v", err)
	}
}

func TestCursorDisconnectRemovesOnlyThisAgentsEntry(t *testing.T) {
	c, path := cursorIn(t)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(`{"mcpServers": {"other": {"command": "x"}, "contro1": {"command": "/usr/local/bin/contro1", "args": ["mcp", "serve", "--agent", "cursor@abc"]}}}`), 0o600)

	if changes := c.McpRemovalChanges(context.Background(), []string{"cursor@someone-else"}); len(changes) != 0 {
		t.Fatalf("an entry for another agent is not ours to remove: %+v", changes)
	}
	if changes := c.McpRemovalChanges(context.Background(), []string{cursorSubject}); len(changes) != 1 {
		t.Fatalf("this agent's entry is previewed: %+v", changes)
	}
	var j Journal
	if _, err := c.RemoveMcp(context.Background(), []string{cursorSubject}, &j); err != nil {
		t.Fatal(err)
	}
	servers, _ := c.McpServers(context.Background())
	if len(servers) != 1 || servers[0].Name != "other" {
		t.Fatalf("only contro1 is removed: %+v", servers)
	}
	// An entry the person wrote without --agent is theirs.
	_ = os.WriteFile(path, []byte(`{"mcpServers": {"contro1": {"command": "contro1", "args": ["mcp", "serve"]}}}`), 0o600)
	if changes := c.McpRemovalChanges(context.Background(), []string{cursorSubject}); len(changes) != 0 {
		t.Fatalf("an unpinned entry stays: %+v", changes)
	}
}

// ---- Codex -------------------------------------------------------------------

// fakeCodex behaves like `codex mcp` (codex-rs/cli/src/mcp_cmd.rs): get fails
// for a missing name, add replaces, remove succeeds either way.
type fakeCodex struct {
	entry []string // command + args, nil when none
	ran   []string
	path  string // config.toml it "writes"
}

func (f *fakeCodex) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.ran = append(f.ran, line)
	switch {
	case line == "codex mcp get contro1 --json":
		if f.entry == nil {
			return nil, errors.New("exit status 1: No MCP server named 'contro1' found.")
		}
		return json.Marshal(map[string]any{"name": "contro1", "enabled": true, "transport": map[string]any{"type": "stdio", "command": f.entry[0], "args": f.entry[1:], "env": nil, "cwd": nil}})
	case strings.HasPrefix(line, "codex mcp add contro1 -- "):
		f.entry = args[4:]
		_ = os.WriteFile(f.path, []byte("[mcp_servers.contro1]\ncommand = 'x'\n"), 0o600)
		return []byte("Added global MCP server 'contro1'."), nil
	case line == "codex mcp remove contro1":
		f.entry = nil
		return []byte("Removed global MCP server 'contro1'."), nil
	}
	return nil, errors.New("unexpected " + line)
}

func codexIn(t *testing.T, f *fakeCodex) (*codex, string) {
	t.Helper()
	pinHost(t)
	home := t.TempDir()
	t.Setenv("CODEX_HOME", "")
	runner := Runner(func(context.Context, string, ...string) ([]byte, error) {
		return nil, &exec.Error{Name: "codex", Err: exec.ErrNotFound}
	})
	if f != nil {
		runner = f.run
	}
	c := newCodex(Options{Home: home, Runner: runner})
	path := filepath.Join(home, ".codex", "config.toml")
	if f != nil {
		f.path = path
	}
	return c, path
}

const codexSubject = "codex@abc"

func TestCodexMcpUsesCodexsOwnCommandAndBacksUpConfig(t *testing.T) {
	f := &fakeCodex{}
	c, path := codexIn(t, f)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte("model = \"gpt-5\"\n"), 0o600)

	changes := c.McpChanges(context.Background(), []string{codexSubject})
	if len(changes) != 1 || changes[0].After != "codex mcp add contro1 -- /usr/local/bin/contro1 mcp serve --agent "+codexSubject {
		t.Fatalf("the preview is the exact codex command: %+v", changes)
	}
	var j Journal
	out, err := c.InstallMcp(context.Background(), []string{codexSubject}, &j)
	if err != nil {
		t.Fatal(err)
	}
	if backup, err := os.ReadFile(path + ".bak-contro1-20261020-093000"); err != nil || string(backup) != "model = \"gpt-5\"\n" {
		t.Fatalf("config.toml is backed up before codex writes it: %v", err)
	}
	if !strings.Contains(strings.Join(out.Done, " "), "Auth as Unsupported") {
		t.Fatalf("the done line explains Auth: Unsupported: %+v", out.Done)
	}
	if again := c.McpChanges(context.Background(), []string{codexSubject}); len(again) != 0 {
		t.Fatalf("idempotent: %+v", again)
	}
	before := len(f.ran)
	out, _ = c.InstallMcp(context.Background(), []string{codexSubject}, &j)
	if len(out.Done) != 1 || !strings.Contains(out.Done[0], "already") || strings.Contains(strings.Join(f.ran[before:], ";"), " add ") {
		t.Fatalf("a second run writes nothing: %+v %v", out, f.ran[before:])
	}

	// Another identity is shown before codex replaces it.
	f.entry = []string{"contro1", "mcp", "serve", "--agent", "codex@old"}
	if changes := c.McpChanges(context.Background(), []string{codexSubject}); len(changes) != 1 || !strings.Contains(changes[0].Before, "codex@old") {
		t.Fatalf("a replacement names what runs now: %+v", changes)
	}

	// Disconnect removes only an entry for this agent.
	if changes := c.McpRemovalChanges(context.Background(), []string{codexSubject}); len(changes) != 0 {
		t.Fatalf("not ours: %+v", changes)
	}
	f.entry = []string{"/usr/local/bin/contro1", "mcp", "serve", "--agent", codexSubject}
	if changes := c.McpRemovalChanges(context.Background(), []string{codexSubject}); len(changes) != 1 || changes[0].After != "codex mcp remove contro1" {
		t.Fatalf("ours: %+v", changes)
	}
	if _, err := c.RemoveMcp(context.Background(), []string{codexSubject}, &j); err != nil || f.entry != nil {
		t.Fatalf("removed: %v %v", err, f.entry)
	}
}

func TestCodexMissingNamesTheConfigBlock(t *testing.T) {
	c, path := codexIn(t, nil)
	changes := c.McpChanges(context.Background(), []string{codexSubject})
	if len(changes) != 1 || !strings.Contains(changes[0].After, "[mcp_servers.contro1]") {
		t.Fatalf("the block is previewed: %+v", changes)
	}
	var j Journal
	out, err := c.InstallMcp(context.Background(), []string{codexSubject}, &j)
	if err != nil || len(out.ToDo) != 1 {
		t.Fatalf("connect finishes and names the step: %+v %v", out, err)
	}
	want := "[mcp_servers.contro1]\ncommand = '/usr/local/bin/contro1'\nargs = [\"mcp\", \"serve\", \"--agent\", \"codex@abc\"]"
	if !strings.Contains(out.ToDo[0], want) {
		t.Fatalf("exact block:\n%s", out.ToDo[0])
	}

	// Pasted in by hand: doctor and the next connect see it without codex.
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte("model = \"x\"\n\n"+want+"\n\n[mcp_servers.other]\ncommand = \"y\"\n"), 0o600)
	if changes := c.McpChanges(context.Background(), []string{codexSubject}); len(changes) != 0 {
		t.Fatalf("a pasted block is recognised: %+v", changes)
	}
	servers, _ := c.McpServers(context.Background())
	if len(servers) != 1 || !servers[0].ServesAgent(codexSubject) {
		t.Fatalf("doctor reads it from config.toml: %+v", servers)
	}
}

func TestParseCodexTomlReadsTheFormsCodexWrites(t *testing.T) {
	text := `[mcp_servers.other]
command = "npx"

[mcp_servers."contro1"]   # ours
command = "C:\\Program Files\\Contro1\\contro1.exe"
args = [
  "mcp", "serve",
  "--agent", "codex@a]b",
]
startup_timeout_sec = 20

[profiles.x]
command = "not this"
`
	s, ok := parseCodexToml(text, "contro1")
	if !ok || s.Command != `C:\Program Files\Contro1\contro1.exe` || strings.Join(s.Args, " ") != "mcp serve --agent codex@a]b" {
		t.Fatalf("parsed: %+v %v", s, ok)
	}
	if _, ok := parseCodexToml("[mcp_servers.other]\ncommand = 'x'\n", "contro1"); ok {
		t.Fatal("no contro1 table, no entry")
	}
	if got := tomlString(`C:\Program Files\Contro1\contro1.exe`); got != `'C:\Program Files\Contro1\contro1.exe'` {
		t.Fatalf("a Windows path is a literal string: %s", got)
	}
}

// ---- A revoked connection is not offered -------------------------------------

// The real Codex test: disconnect revoked the agent in Contro1, the mapping
// stayed, and `mcp serve` kept choosing the revoked agent. What the service
// itself reports revoked is treated as absent; nothing else is guessed away.
func TestARevokedConnectionIsTreatedAsAbsent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", dir)
	writeMapping(t, dir, "codex", []runtimeproto.MappingEntry{entry(codexSubject, "agt_codex", "unix:///run/contro1/ep/codex.sock")})

	// No status: the entry is kept.
	if got, err := SelectLocalConnection(""); err != nil || got.AgentID != "agt_codex" {
		t.Fatalf("without a status the published entry is used: %+v %v", got, err)
	}
	status := func(state string) {
		raw, _ := json.Marshal(map[string]any{"schema_version": 1, "enrollments": []map[string]string{{"enrollment_id": "enr_agt_codex", "state": state}}})
		_ = os.WriteFile(filepath.Join(dir, "status.json"), raw, 0o644)
	}
	status("active")
	if _, err := SelectLocalConnection(""); err != nil {
		t.Fatalf("active is used: %v", err)
	}
	status("revoked")
	if _, err := SelectLocalConnection(""); !errors.Is(err, ErrNoLocalConnection) {
		t.Fatalf("a revoked connection is as if absent: %v", err)
	}
	if _, err := SelectLocalConnectionFor("codex", codexSubject); !errors.Is(err, ErrInactiveConnection) || !strings.Contains(err.Error(), "contro1 connect codex") {
		t.Fatalf("naming it says it is revoked and how to reconnect: %v", err)
	}
	// Another agent next to it is now the only one, so it is chosen unnamed.
	writeMapping(t, dir, "cursor", []runtimeproto.MappingEntry{entry(cursorSubject, "agt_cursor", "unix:///run/contro1/ep/cursor.sock")})
	if got, err := SelectLocalConnection(""); err != nil || got.AgentID != "agt_cursor" {
		t.Fatalf("the remaining agent is used: %+v %v", got, err)
	}
}
