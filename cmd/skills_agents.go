package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/spf13/cobra"
)

// Where agents keep skills on a computer.
//
// THE TABLE. Each agent's documented user folder (under the home directory)
// and project folder (inside a repository). Sources: each vendor's own docs,
// cross-checked against the agent table of vercel-labs/skills (`npx skills`),
// which installs into exactly these folders. A folder that does not exist is
// skipped, so listing an agent the person does not use costs nothing.
//
// RUNTIMES (NanoClaw, OpenClaw, Hermes) do not live in one fixed folder: their
// install, workspace or config says where. detectRuntimeRoots reads those.
type agentSkillDirs struct {
	client  string
	user    []string // relative to the home directory
	project []string // relative to the project root
}

var knownAgentSkillDirs = []agentSkillDirs{
	{"claude-code", []string{".claude/skills"}, []string{".claude/skills"}},
	{"codex", []string{".codex/skills"}, []string{".codex/skills"}},
	{"cursor", []string{".cursor/skills"}, []string{".cursor/skills"}},
	{"gemini", []string{".gemini/skills"}, []string{".gemini/skills"}},
	// The shared folder of the Agent Skills standard: Codex, Cline, Warp, Zed,
	// OpenCode, Amp and others read it, so it is reported once, as "agents".
	{"agents", []string{".agents/skills", ".config/agents/skills"}, []string{".agents/skills"}},
	{"copilot", []string{".copilot/skills"}, []string{".github/skills"}},
	{"antigravity", []string{".gemini/antigravity/skills"}, nil},
	{"windsurf", []string{".codeium/windsurf/skills"}, []string{".windsurf/skills"}},
	{"goose", []string{".config/goose/skills"}, []string{".goose/skills"}},
	{"opencode", []string{".config/opencode/skills"}, []string{".opencode/skills"}},
	{"kiro", []string{".kiro/skills"}, []string{".kiro/skills"}},
	{"roo", []string{".roo/skills"}, []string{".roo/skills"}},
	{"kilo", []string{".kilo/skills"}, nil},
	{"continue", []string{".continue/skills"}, []string{".continue/skills"}},
	{"augment", []string{".augment/skills"}, []string{".augment/skills"}},
	{"junie", []string{".junie/skills"}, []string{".junie/skills"}},
	{"qwen", []string{".qwen/skills"}, []string{".qwen/skills"}},
	{"factory", []string{".factory/skills"}, nil},
	{"trae", []string{".trae/skills"}, []string{".trae/skills"}},
	{"openhands", []string{".openhands/skills"}, []string{".openhands/skills"}},
	{"crush", []string{".config/crush/skills"}, []string{".crush/skills"}},
	{"devin", []string{".config/devin/skills"}, []string{".devin/skills"}},
	{"hermes", nil, []string{".hermes/skills"}}, // user folder: see hermesRoots
}

// knownAgentRoots turns the table into roots for this home and project.
func knownAgentRoots(home, project string) []skillRoot {
	var roots []skillRoot
	for _, a := range knownAgentSkillDirs {
		for _, rel := range a.user {
			roots = append(roots, skillRoot{filepath.Join(home, filepath.FromSlash(rel)), a.client, "user", false})
		}
	}
	if project != "" {
		for _, a := range knownAgentSkillDirs {
			for _, rel := range a.project {
				roots = append(roots, skillRoot{filepath.Join(project, filepath.FromSlash(rel)), a.client, "project", false})
			}
		}
	}
	return roots
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func expandHome(p, home string) string {
	p = os.ExpandEnv(strings.TrimSpace(p))
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home, p[2:])
	}
	return p
}

// hermesRoots: Hermes Agent (Nous Research). Skills live in $HERMES_HOME/skills
// (default ~/.hermes/skills), grouped by category one level deeper, plus
// skills.create_dir and skills.external_dirs from its config.yaml.
func hermesRoots(home string, useEnv bool) []skillRoot {
	base := ""
	if useEnv {
		base = os.Getenv("HERMES_HOME")
	}
	if base == "" {
		base = filepath.Join(home, ".hermes")
	}
	roots := []skillRoot{{filepath.Join(base, "skills"), "hermes", "user", true}}
	b, err := os.ReadFile(filepath.Join(base, "config.yaml"))
	if err != nil {
		return roots
	}
	for _, dir := range hermesConfigDirs(string(b)) {
		roots = append(roots, skillRoot{expandHome(dir, home), "hermes", "user", true})
	}
	return roots
}

// hermesConfigDirs reads skills.create_dir and skills.external_dirs from a
// Hermes config.yaml. A small reader for these two keys, not a YAML parser:
// anything it does not recognize is skipped, never guessed.
func hermesConfigDirs(text string) []string {
	var dirs []string
	inSkills, inExternal := false, false
	skillsIndent, externalIndent := -1, -1
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimRight(raw, " \t")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			inSkills = trimmed == "skills:"
			inExternal = false
			skillsIndent = -1
			continue
		}
		if !inSkills {
			continue
		}
		if skillsIndent < 0 {
			skillsIndent = indent
		}
		if inExternal && indent > externalIndent && strings.HasPrefix(trimmed, "- ") {
			dirs = append(dirs, unquoteYAML(strings.TrimPrefix(trimmed, "- ")))
			continue
		}
		if indent == skillsIndent {
			inExternal = false
			key, value, ok := strings.Cut(trimmed, ":")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			switch key {
			case "create_dir":
				if value != "" {
					dirs = append(dirs, unquoteYAML(value))
				}
			case "external_dirs":
				if strings.HasPrefix(value, "[") {
					for _, item := range strings.Split(strings.Trim(value, "[]"), ",") {
						if item = unquoteYAML(item); item != "" {
							dirs = append(dirs, item)
						}
					}
				} else {
					inExternal, externalIndent = true, indent
				}
			}
		}
	}
	return dirs
}

func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return strings.Trim(s, `"'`)
}

var (
	openclawWorkspaceRE = regexp.MustCompile(`"?workspace"?\s*:\s*"([^"]+)"`)
	openclawExtraDirsRE = regexp.MustCompile(`"?extraDirs"?\s*:\s*\[([^\]]*)\]`)
	quotedRE            = regexp.MustCompile(`"([^"]+)"`)
)

// openclawRoots: OpenClaw. Managed skills in <state>/skills (default
// ~/.openclaw, or OPENCLAW_STATE_DIR); each agent workspace's skills/ and
// .agents/skills; and skills.load.extraDirs. Workspaces and extra folders come
// from openclaw.json (JSON5, so read by pattern rather than a strict parser);
// ~/.openclaw/workspace is the folder onboarding creates.
func openclawRoots(home string, useEnv bool) []skillRoot {
	state := ""
	if useEnv {
		state = os.Getenv("OPENCLAW_STATE_DIR")
	}
	if state == "" {
		state = filepath.Join(home, ".openclaw")
	}
	roots := []skillRoot{{filepath.Join(state, "skills"), "openclaw", "user", false}}
	workspaces := []string{filepath.Join(state, "workspace")}
	if b, err := os.ReadFile(filepath.Join(state, "openclaw.json")); err == nil {
		text := string(b)
		for _, m := range openclawWorkspaceRE.FindAllStringSubmatch(text, -1) {
			workspaces = append(workspaces, expandHome(m[1], home))
		}
		for _, m := range openclawExtraDirsRE.FindAllStringSubmatch(text, -1) {
			for _, q := range quotedRE.FindAllStringSubmatch(m[1], -1) {
				roots = append(roots, skillRoot{expandHome(q[1], home), "openclaw", "user", false})
			}
		}
	}
	for _, ws := range workspaces {
		roots = append(roots,
			skillRoot{filepath.Join(ws, "skills"), "openclaw", "user", false},
			skillRoot{filepath.Join(ws, ".agents", "skills"), "openclaw", "user", false},
		)
	}
	return roots
}

// isNanoClawCheckout: NanoClaw is a repository people clone and run. Its
// agents load container/skills (mounted into every agent container at
// /app/skills), so a checkout is recognized by that folder plus its name in
// package.json.
func isNanoClawCheckout(dir string) bool {
	if !isDir(filepath.Join(dir, "container", "skills")) {
		return false
	}
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	return err == nil && strings.Contains(strings.ToLower(string(b)), "nanoclaw")
}

// Folders never worth opening while looking for a NanoClaw checkout.
var nanoclawSkipDirs = map[string]bool{
	"node_modules": true, "AppData": true, "Windows": true, "Program Files": true, "Program Files (x86)": true,
	"ProgramData": true, "$Recycle.Bin": true, "System Volume Information": true, "Library": true,
	"Applications": true, "proc": true, "sys": true, "dev": true, "usr": true, "bin": true, "sbin": true,
	"lib": true, "lib64": true, "etc": true, "var": true, "boot": true, "snap": true, "mnt": true,
}

// macOS asks the person before any program reads these, and a scheduled run
// cannot ask at all. The automatic search leaves them alone; a NanoClaw kept in
// one is added once with contro1 skills folders add.
var macProtectedDirs = map[string]bool{
	"Desktop": true, "Documents": true, "Downloads": true, "Pictures": true, "Movies": true, "Music": true,
}

// searchNanoClaw looks for checkouts up to two folders below each base
// (C:\Projects\myNano, ~/code/nanoclaw), opening at most a few thousand
// folders so a scheduled run stays quick.
func searchNanoClaw(bases []string) []string {
	var found []string
	budget := 4000
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if budget <= 0 {
				return
			}
			name := e.Name()
			if !e.IsDir() || strings.HasPrefix(name, ".") || nanoclawSkipDirs[name] || (runtime.GOOS == "darwin" && macProtectedDirs[name]) {
				continue
			}
			budget--
			child := filepath.Join(dir, name)
			if isNanoClawCheckout(child) {
				found = append(found, child)
				continue
			}
			if depth < 2 {
				walk(child, depth+1)
			}
		}
	}
	for _, base := range bases {
		walk(base, 1)
	}
	return found
}

// wslRunningDistros lists the WSL distributions running right now. Only
// running ones: opening a stopped distro's files would start it, every four
// hours, from the schedule. A NanoClaw service in WSL keeps its distro running.
var wslRunningDistros = func() []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "wsl.exe", "-l", "--running", "-q").Output()
	if err != nil {
		return nil
	}
	// wsl.exe writes UTF-16; the names are ASCII, so dropping the zero bytes is enough.
	var distros []string
	for _, line := range strings.Split(strings.ReplaceAll(string(out), "\x00", ""), "\n") {
		name := strings.TrimSpace(line)
		if name != "" && !strings.HasPrefix(strings.ToLower(name), "docker-desktop") {
			distros = append(distros, name)
		}
	}
	return distros
}

// wslHomes: the home folders inside running WSL distributions, as Windows
// sees them (\\wsl.localhost\Ubuntu\home\ariel). An agent installed in WSL
// keeps its skills there, out of sight of the Windows home folder.
var wslHomes = func() []string {
	var homes []string
	for _, distro := range wslRunningDistros() {
		wslRoot := `\\wsl.localhost\` + distro
		if users, err := os.ReadDir(filepath.Join(wslRoot, "home")); err == nil {
			for _, u := range users {
				if u.IsDir() {
					homes = append(homes, filepath.Join(wslRoot, "home", u.Name()))
				}
			}
		}
	}
	return homes
}

// nanoclawSearchBases: the home folder, every drive (Windows) or /opt and
// /srv, and the WSL homes.
var nanoclawSearchBases = func(home string, wsl []string) []string {
	bases := []string{home}
	if runtime.GOOS == "windows" {
		for d := 'C'; d <= 'Z'; d++ {
			if root := string(d) + `:\`; isDir(root) {
				bases = append(bases, root)
			}
		}
		bases = append(bases, wsl...)
	} else {
		bases = append(bases, "/opt", "/srv")
	}
	return bases
}

// nanoclawRoots finds NanoClaw checkouts wherever the report runs from: the
// current project, a search of the usual places (home, drives, running WSL
// distributions), and any folder added with `contro1 skills folders add`.
//
// Its skills are reported as "user", not "project": they belong to an
// installed, running agent, so every report must include them whatever folder
// it runs from. A "project" skill would vanish from a report run elsewhere.
func nanoclawRoots(home, project string, folders, wsl []string) []skillRoot {
	candidates := []string{project}
	candidates = append(candidates, folders...)
	candidates = append(candidates, searchNanoClaw(nanoclawSearchBases(home, wsl))...)
	var roots []skillRoot
	seen := map[string]bool{}
	for _, dir := range candidates {
		if dir != "" {
			dir = filepath.Clean(dir)
		}
		if dir == "" || seen[strings.ToLower(dir)] || !isNanoClawCheckout(dir) {
			continue
		}
		seen[strings.ToLower(dir)] = true
		roots = append(roots, skillRoot{filepath.Join(dir, "container", "skills"), "nanoclaw", "user", false})
	}
	return roots
}

// coworkRoots: Claude Cowork (the Claude desktop app). It keeps the account's
// skills, Anthropic's and the ones a person added under Customize > Skills, in
// local-agent-mode-sessions/skills-plugin/<id>/<id>/skills. The Microsoft
// Store build keeps the same folder inside its package.
func coworkRoots(home string) []skillRoot {
	var bases []string
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		bases = append(bases, filepath.Join(appdata, "Claude"))
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local = filepath.Join(home, "AppData", "Local")
		}
		if pkgs, err := filepath.Glob(filepath.Join(local, "Packages", "Claude_*", "LocalCache", "Roaming", "Claude")); err == nil {
			bases = append(bases, pkgs...)
		}
	case "darwin":
		bases = append(bases, filepath.Join(home, "Library", "Application Support", "Claude"))
	default:
		bases = append(bases, filepath.Join(home, ".config", "Claude"))
	}
	var roots []skillRoot
	for _, base := range bases {
		dirs, _ := filepath.Glob(filepath.Join(base, "local-agent-mode-sessions", "skills-plugin", "*", "*", "skills"))
		for _, d := range dirs {
			roots = append(roots, skillRoot{d, "cowork", "user", false})
		}
	}
	return roots
}

// detectRuntimeRoots: the agents whose skills are not in one fixed folder,
// and every agent installed inside a running WSL distribution.
func detectRuntimeRoots(home, project string) []skillRoot {
	folders := readSkillFolders()
	wsl := wslHomes()
	roots := append(hermesRoots(home, true), openclawRoots(home, true)...)
	roots = append(roots, coworkRoots(home)...)
	for _, h := range wsl {
		roots = append(roots, knownAgentRoots(h, "")...)
		roots = append(roots, hermesRoots(h, false)...)
		roots = append(roots, openclawRoots(h, false)...)
	}
	roots = append(roots, nanoclawRoots(home, project, folders, wsl)...)
	// A folder added by hand that is not a NanoClaw checkout is a skills folder.
	for _, dir := range folders {
		if !isNanoClawCheckout(dir) {
			roots = append(roots, skillRoot{dir, "other", "user", true})
		}
	}
	return roots
}

// ---- contro1 skills folders: extra places this computer reports ----

func skillFoldersPath() string {
	dir, err := config.Dir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "skills-folders")
}

func readSkillFolders() []string {
	if skillFoldersPath() == "" {
		return nil
	}
	b, err := os.ReadFile(skillFoldersPath())
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func writeSkillFolders(folders []string) error {
	if skillFoldersPath() == "" {
		return fmt.Errorf("cannot find the contro1 settings folder on this computer")
	}
	sort.Strings(folders)
	if err := os.MkdirAll(filepath.Dir(skillFoldersPath()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(skillFoldersPath(), []byte(strings.Join(folders, "\n")+"\n"), 0o600)
}

func init() {
	foldersCmd := &cobra.Command{
		Use:   "folders",
		Short: "Extra folders this computer reports skills from (a NanoClaw install, a team skills folder)",
		Long: `Most agents keep skills in a fixed folder, and contro1 skills report finds
them by itself: Claude Code, Codex, Cursor, Gemini CLI, Copilot, OpenClaw, Hermes
and more. Add a folder here when it is somewhere else, for example a NanoClaw
install in an unusual place. The daily report includes it from then on.`,
		Example: `  contro1 skills folders
  contro1 skills folders add D:\agents\nanoclaw
  contro1 skills folders remove D:\agents\nanoclaw`,
		RunE: func(_ *cobra.Command, _ []string) error {
			folders := readSkillFolders()
			if len(folders) == 0 {
				infof("No extra folders. The usual agent folders are always included.")
				return nil
			}
			for _, f := range folders {
				kind := "skills folder"
				if isNanoClawCheckout(f) {
					kind = "NanoClaw install"
				}
				fmt.Printf("%s  (%s)\n", f, kind)
			}
			return nil
		},
	}
	addCmd := &cobra.Command{
		Use:   "add <folder>",
		Short: "Report skills from this folder too",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			abs, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			if !isDir(abs) {
				return fmt.Errorf("%s is not a folder on this computer", abs)
			}
			folders := readSkillFolders()
			for _, f := range folders {
				if f == abs {
					infof("Already included: %s", abs)
					return nil
				}
			}
			if err := writeSkillFolders(append(folders, abs)); err != nil {
				return err
			}
			if isNanoClawCheckout(abs) {
				infof("Added NanoClaw install %s. Its agents' skills (container/skills) are reported from now on.", abs)
			} else {
				infof("Added %s. Every SKILL.md under it is reported from now on.", abs)
			}
			return nil
		},
	}
	removeCmd := &cobra.Command{
		Use:   "remove <folder>",
		Short: "Stop reporting skills from this folder",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			abs, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			var kept []string
			for _, f := range readSkillFolders() {
				if f != abs {
					kept = append(kept, f)
				}
			}
			if err := writeSkillFolders(kept); err != nil {
				return err
			}
			infof("Removed %s.", abs)
			return nil
		},
	}
	foldersCmd.AddCommand(addCmd, removeCmd)
	for _, c := range rootCmd.Commands() {
		if c.Name() == "skills" {
			c.AddCommand(foldersCmd)
		}
	}
}
