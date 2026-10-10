package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

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
func hermesRoots(home string) []skillRoot {
	base := os.Getenv("HERMES_HOME")
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
func openclawRoots(home string) []skillRoot {
	state := os.Getenv("OPENCLAW_STATE_DIR")
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

// nanoclawRoots finds NanoClaw checkouts: the project being reported, the
// folders people usually clone into, and any folder added with
// `contro1 skills folders add`.
func nanoclawRoots(home, project string, folders []string) []skillRoot {
	candidates := []string{project}
	for _, parent := range []string{"", "code", "src", "dev", "projects", "repos", "git", "github", "Documents", "Desktop"} {
		for _, name := range []string{"nanoclaw", "NanoClaw", "nanoclaw-pro"} {
			candidates = append(candidates, filepath.Join(home, parent, name))
		}
	}
	candidates = append(candidates, folders...)
	var roots []skillRoot
	seen := map[string]bool{}
	for _, dir := range candidates {
		if dir == "" || seen[dir] || !isNanoClawCheckout(dir) {
			continue
		}
		seen[dir] = true
		roots = append(roots, skillRoot{filepath.Join(dir, "container", "skills"), "nanoclaw", "user", false})
	}
	return roots
}

// detectRuntimeRoots: the agents whose skills are not in one fixed folder.
func detectRuntimeRoots(home, project string) []skillRoot {
	folders := readSkillFolders()
	roots := append(hermesRoots(home), openclawRoots(home)...)
	roots = append(roots, nanoclawRoots(home, project, folders)...)
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
