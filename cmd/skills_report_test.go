package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The digest is how the server matches a reported skill to one it published and
// how it scans a skill once for everyone who has it. If the CLI and the server
// disagree, every laptop's copy of an organization skill shows up as unmanaged.
// The expected value is computed by backend/src/services/skills/skillFormat.ts
// bundleDigest for the same input.
func TestBundleDigestMatchesServer(t *testing.T) {
	md := []byte("---\nname: a\ndescription: b\n---\n\nhello\n")
	got := bundleDigestOf(md, map[string][]byte{"scripts/x.sh": []byte("echo 1")})
	want := "411b6c3077a83de259522ddb52c5ae0375cfcfcec899729f94eb820bef9eae05"
	if got != want {
		t.Fatalf("bundle digest %s, server computes %s", got, want)
	}
}

func TestReadSkillAndFind(t *testing.T) {
	home := t.TempDir()
	root := skillRoot{filepath.Join(home, ".claude", "skills"), "claude-code", "user", false}
	dir := filepath.Join(root.dir, "refunds")
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: refunds\ndescription: \"How we refund\"\n---\n\nbody\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "scripts", "a.sh"), []byte("echo hi"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "logo.png"), []byte{0x89, 'P', 'N', 'G', 0x00, 0x01}, 0o644)
	// A stray SKILL.md directly in the root is not a skill directory.
	_ = os.WriteFile(filepath.Join(root.dir, "SKILL.md"), []byte("x"), 0o644)

	dirs := findSkillDirs(root)
	if len(dirs) != 1 || dirs[0] != dir {
		t.Fatalf("found %v", dirs)
	}
	s, err := readSkill(dir, root, home)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "refunds" || s.Description != "How we refund" {
		t.Fatalf("frontmatter read as %q / %q", s.Name, s.Description)
	}
	if s.Path != "~/.claude/skills/refunds" {
		t.Fatalf("home must be shown as ~, got %s", s.Path)
	}
	if s.FileCount != 3 || len(s.Files) != 2 {
		t.Fatalf("files: count %d sent %d", s.FileCount, len(s.Files))
	}
	for _, f := range s.Files {
		if f.Path == "logo.png" && f.Encoding != "base64" {
			t.Fatal("binary files are sent as base64")
		}
	}

	skillsReportMetadataOnly = true
	defer func() { skillsReportMetadataOnly = false }()
	meta, _ := readSkill(dir, root, home)
	if meta.SkillMD != "" || len(meta.Files) != 0 || meta.BundleDigest != s.BundleDigest {
		t.Fatal("--metadata-only sends the same digest and no content")
	}
}

// Only plugins Claude Code lists as installed are reported. A marketplace
// checkout holds every plugin in the catalog, installed or not.
func TestClaudePluginsOnlyInstalled(t *testing.T) {
	home := t.TempDir()
	plugins := filepath.Join(home, ".claude", "plugins")
	write := func(rel, body string) {
		p := filepath.Join(plugins, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(p, []byte(body), 0o644)
	}
	skill := "---\nname: x\ndescription: d\n---\n\nbody\n"
	write("marketplaces/official/plugins/frontend-design/skills/frontend-design/SKILL.md", skill)
	write("marketplaces/official/plugins/plugin-dev/skills/hook-development/SKILL.md", skill)
	write("cache/official/frontend-design/old111/skills/frontend-design/SKILL.md", skill)
	write("cache/official/frontend-design/new222/skills/frontend-design/SKILL.md", skill)
	installed := filepath.Join(plugins, "cache", "official", "frontend-design", "new222")
	doc, _ := json.Marshal(map[string]any{"version": 2, "plugins": map[string]any{
		"frontend-design@official": []map[string]string{{"scope": "user", "installPath": installed}},
	}})
	write("installed_plugins.json", string(doc))

	var found []string
	for _, root := range claudePluginRoots(home) {
		found = append(found, findSkillDirs(root)...)
	}
	want := filepath.Join(installed, "skills", "frontend-design")
	if len(found) != 1 || found[0] != want {
		t.Fatalf("want only the installed copy %s, got %v", want, found)
	}

	// Without the record, installed copies only: never the marketplace catalog.
	_ = os.Remove(filepath.Join(plugins, "installed_plugins.json"))
	for _, root := range claudePluginRoots(home) {
		for _, dir := range findSkillDirs(root) {
			if strings.Contains(dir, "marketplaces") {
				t.Fatalf("a marketplace catalog is not an install: %s", dir)
			}
		}
	}
}

func TestLockCoversSkills(t *testing.T) {
	cases := map[string]bool{
		`true`:               true,
		`false`:              false,
		`["skills"]`:         true,
		`["agents","hooks"]`: false,
		`{"skills":true}`:    true,
		`{"skills":false}`:   false,
		`{"agents":true}`:    false,
	}
	for raw, want := range cases {
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatal(err)
		}
		if got := lockCoversSkills(v); got != want {
			t.Fatalf("%s: got %v want %v", raw, got, want)
		}
	}
}

func writeSkill(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	md := "---\nname: " + filepath.Base(dir) + "\ndescription: d\n---\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
}

func clientsFound(home, project string) map[string]string {
	found := map[string]string{}
	for _, root := range skillRoots(home, project) {
		for _, dir := range findSkillDirs(root) {
			if _, ok := found[filepath.Base(dir)]; !ok {
				found[filepath.Base(dir)] = root.client
			}
		}
	}
	return found
}

// NanoClaw, OpenClaw and Hermes keep skills where their install, workspace or
// config says. Each is found where its own docs put it.
// searchOnlyHome keeps a test from searching the real drives of the machine.
func searchOnlyHome(t *testing.T, extra ...string) {
	t.Helper()
	prev, prevWSL := nanoclawSearchBases, wslHomes
	nanoclawSearchBases = func(home string, _ []string) []string { return append([]string{home}, extra...) }
	wslHomes = func() []string { return nil }
	t.Cleanup(func() { nanoclawSearchBases, wslHomes = prev, prevWSL })
}

func makeNanoClaw(t *testing.T, dir string) {
	t.Helper()
	writeSkill(t, filepath.Join(dir, "container", "skills", "agent-browser"))
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"nanoclaw"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Found from any folder: the daily schedule never runs inside the checkout.
// Covers a checkout two levels down (C:\Projects\myNano) and one in another
// base, as a WSL home is.
func TestNanoClawFoundFromAnywhere(t *testing.T) {
	home := t.TempDir()
	wsl := t.TempDir()
	searchOnlyHome(t, wsl)
	makeNanoClaw(t, filepath.Join(home, "Projects", "myNano"))
	makeNanoClaw(t, filepath.Join(wsl, "nanoclaw"))
	if err := os.MkdirAll(filepath.Join(home, "elsewhere"), 0o755); err != nil {
		t.Fatal(err)
	}
	roots := nanoclawRoots(home, filepath.Join(home, "elsewhere"), nil, nil)
	if len(roots) != 2 {
		t.Fatalf("found %d NanoClaw installs, want 2: %v", len(roots), roots)
	}
	for _, r := range roots {
		if r.client != "nanoclaw" || r.scope != "user" {
			t.Errorf("root %v: want client nanoclaw, scope user", r)
		}
	}
}

func TestRuntimeAgentSkillsFound(t *testing.T) {
	home := t.TempDir()
	searchOnlyHome(t)
	t.Setenv("HERMES_HOME", "")
	t.Setenv("OPENCLAW_STATE_DIR", "")

	// Hermes: by category, plus external_dirs from config.yaml.
	writeSkill(t, filepath.Join(home, ".hermes", "skills", "research", "arxiv"))
	writeSkill(t, filepath.Join(home, ".hermes", "skills", ".hub", "cached"))
	team := filepath.Join(home, "team-skills")
	writeSkill(t, filepath.Join(team, "brand-voice"))
	cfg := "model: x\nskills:\n  project_discovery: true\n  external_dirs:\n    - ~/team-skills\n    - ~/missing # skipped\n"
	if err := os.WriteFile(filepath.Join(home, ".hermes", "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// OpenClaw: managed folder, default workspace, and a workspace from openclaw.json.
	writeSkill(t, filepath.Join(home, ".openclaw", "skills", "gog"))
	writeSkill(t, filepath.Join(home, ".openclaw", "workspace", "skills", "notes"))
	ws := filepath.Join(home, "writer-ws")
	writeSkill(t, filepath.Join(ws, "skills", "drafts"))
	oc := `{ agents: { entries: { writer: { "workspace": "` + filepath.ToSlash(ws) + `" } } } }`
	if err := os.WriteFile(filepath.Join(home, ".openclaw", "openclaw.json"), []byte(oc), 0o644); err != nil {
		t.Fatal(err)
	}

	// NanoClaw: a checkout in ~/nanoclaw.
	nc := filepath.Join(home, "nanoclaw")
	writeSkill(t, filepath.Join(nc, "container", "skills", "agent-browser"))
	if err := os.WriteFile(filepath.Join(nc, "package.json"), []byte(`{"name":"nanoclaw"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// The shared standard folder.
	writeSkill(t, filepath.Join(home, ".agents", "skills", "shared"))

	got := clientsFound(home, "")
	want := map[string]string{
		"arxiv": "hermes", "brand-voice": "hermes",
		"gog": "openclaw", "notes": "openclaw", "drafts": "openclaw",
		"agent-browser": "nanoclaw", "shared": "agents",
	}
	for name, client := range want {
		if got[name] != client {
			t.Errorf("%s: client %q, want %q (all: %v)", name, got[name], client, got)
		}
	}
	if _, ok := got["cached"]; ok {
		t.Error("Hermes hub state is not an installed skill")
	}
}

func TestHermesConfigDirs(t *testing.T) {
	got := hermesConfigDirs("skills:\n  create_dir: /opt/brain/skills\n  external_dirs: [\"~/a\", '~/b']\nother:\n  external_dirs:\n    - ~/not-skills\n")
	want := []string{"/opt/brain/skills", "~/a", "~/b"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// An agent installed inside WSL keeps its skills in the WSL home, which the
// Windows CLI reads through \wsl.localhost. Every agent there is found, not
// only NanoClaw.
func TestAgentsInsideWSLFound(t *testing.T) {
	home := t.TempDir()
	wslHome := t.TempDir()
	searchOnlyHome(t)
	wslHomes = func() []string { return []string{wslHome} }
	writeSkill(t, filepath.Join(wslHome, ".openclaw", "skills", "wsl-openclaw"))
	writeSkill(t, filepath.Join(wslHome, ".hermes", "skills", "ops", "wsl-hermes"))
	writeSkill(t, filepath.Join(wslHome, ".claude", "skills", "wsl-claude"))
	got := clientsFound(home, "")
	for name, client := range map[string]string{"wsl-openclaw": "openclaw", "wsl-hermes": "hermes", "wsl-claude": "claude-code"} {
		if got[name] != client {
			t.Errorf("%s: client %q, want %q (all: %v)", name, got[name], client, got)
		}
	}
}

// Cowork keeps the account's skills inside the Claude desktop app's folder.
func TestCoworkSkillsFound(t *testing.T) {
	home := t.TempDir()
	searchOnlyHome(t)
	var base string
	switch runtime.GOOS {
	case "windows":
		base = filepath.Join(home, "AppData", "Roaming", "Claude")
		t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
		t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	case "darwin":
		base = filepath.Join(home, "Library", "Application Support", "Claude")
	default:
		base = filepath.Join(home, ".config", "Claude")
	}
	writeSkill(t, filepath.Join(base, "local-agent-mode-sessions", "skills-plugin", "org", "user", "skills", "brand-deck"))
	if got := clientsFound(home, "")["brand-deck"]; got != "cowork" {
		t.Fatalf("client %q, want cowork", got)
	}
}
