package cmd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

// Limits mirror the server (backend/src/services/skills/skillFormat.ts). A
// directory over them is almost certainly a repository rather than a skill and
// is reported by digest only.
const (
	reportMaxFiles      = 200
	reportMaxSkillBytes = 4 * 1024 * 1024
	reportBatchBytes    = 5 * 1024 * 1024
	reportMaxSkills     = 200
)

var (
	skillsReportDryRun       bool
	skillsReportMetadataOnly bool
	skillsReportProjectDir   string
	skillsReportEvery        time.Duration
)

func init() {
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Tell your organization which agent skills are installed on this machine",
		Long: `Looks in the folders coding agents load skills from and reports every SKILL.md
it finds to your organization, so administrators can see which skills are in use
and have them security-scanned.

Where it looks (each agent's documented folders; missing ones are skipped):
  Claude Code   ~/.claude/skills, and the plugins Claude Code lists as installed
                (~/.claude/plugins/installed_plugins.json; a catalog is not an install)
  Codex, Cursor, Gemini CLI, Copilot, Windsurf, Goose, OpenCode, Kiro, Roo,
  Kilo, Continue, Augment, Junie, Qwen Code, Factory Droid, Trae, OpenHands,
  Crush, Devin, Antigravity, and the shared ~/.agents/skills
  OpenClaw      ~/.openclaw/skills, each workspace's skills/ and .agents/skills,
                and skills.load.extraDirs from openclaw.json
  Hermes        ~/.hermes/skills (or $HERMES_HOME), plus create_dir and
                external_dirs from its config.yaml
  NanoClaw      container/skills of every NanoClaw install, found from any folder:
                up to two folders below your home and each drive (Windows), in
                running WSL distributions, or one you add with
                contro1 skills folders add <folder>
  Cowork        the skills of the Claude desktop app (Customize > Skills)
  WSL           on Windows, every agent above installed inside a running WSL
                distribution
  and each agent's project folder inside the current project.

What it sends: each skill's files (SKILL.md and its supporting files), with the
home directory shown as ~. Use --metadata-only to send names and digests without
any file content; the skill can then be scanned only if someone else in your
organization already reported the identical skill. Use --dry-run to see exactly
what would be sent.

It reads files. It never changes, deletes or disables a skill.`,
		Example: `  contro1 skills report --dry-run
  contro1 skills report
  contro1 skills report --every 24h --quiet   # for a SessionStart hook`,
		RunE: runSkillsReportRecorded,
	}
	reportCmd.Flags().BoolVar(&skillsReportDryRun, "dry-run", false, "print what would be sent and send nothing")
	reportCmd.Flags().BoolVar(&skillsReportMetadataOnly, "metadata-only", false, "send names and digests, no file content")
	reportCmd.Flags().StringVar(&skillsReportProjectDir, "project-dir", ".", "project whose .claude/skills etc. are included")
	reportCmd.Flags().DurationVar(&skillsReportEvery, "every", 0, "skip if a report was sent less than this long ago (e.g. 24h)")

	for _, c := range rootCmd.Commands() {
		if c.Name() == "skills" {
			c.AddCommand(reportCmd)
		}
	}
}

type reportFile struct {
	Path     string `json:"path"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

type reportSkill struct {
	Client        string       `json:"client"`
	LocationScope string       `json:"location_scope"`
	Path          string       `json:"path"`
	BundleDigest  string       `json:"bundle_digest"`
	Name          string       `json:"name,omitempty"`
	Description   string       `json:"description,omitempty"`
	FileCount     int          `json:"file_count"`
	TotalBytes    int          `json:"total_bytes"`
	SkillMD       string       `json:"skill_md,omitempty"`
	Files         []reportFile `json:"files,omitempty"`
	tooLarge      bool
}

type skillRoot struct {
	dir    string
	client string
	scope  string
	// plugin roots hold <plugin>/skills/<skill>/SKILL.md, one level deeper.
	nested bool
}

// claudePluginRoots returns the install directory of every plugin Claude Code
// lists as installed.
//
// NOT the whole plugins folder: ~/.claude/plugins/marketplaces holds a full
// checkout of every marketplace the person added, including every plugin they
// never installed, and cache/ can keep superseded versions. Walking either
// reports skills no agent loads (and the same skill twice). installed_plugins.json
// is Claude Code's own record of what is installed and where.
func claudePluginRoots(home string) []skillRoot {
	pluginsDir := filepath.Join(home, ".claude", "plugins")
	b, err := os.ReadFile(filepath.Join(pluginsDir, "installed_plugins.json"))
	if err != nil {
		// No record: fall back to installed copies only, never the catalogs.
		return []skillRoot{{filepath.Join(pluginsDir, "cache"), "claude-code", "plugin", true}}
	}
	var doc struct {
		Plugins map[string]json.RawMessage `json:"plugins"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return []skillRoot{{filepath.Join(pluginsDir, "cache"), "claude-code", "plugin", true}}
	}
	type install struct {
		InstallPath string `json:"installPath"`
	}
	var paths []string
	for _, raw := range doc.Plugins {
		// Version 2 stores a list of installs per plugin; version 1 one object.
		var many []install
		if json.Unmarshal(raw, &many) != nil {
			var one install
			if json.Unmarshal(raw, &one) == nil {
				many = []install{one}
			}
		}
		for _, in := range many {
			if in.InstallPath != "" {
				paths = append(paths, filepath.Clean(in.InstallPath))
			}
		}
	}
	sort.Strings(paths)
	roots := make([]skillRoot, 0, len(paths))
	for i, path := range paths {
		if i > 0 && paths[i-1] == path {
			continue
		}
		roots = append(roots, skillRoot{path, "claude-code", "plugin", true})
	}
	return roots
}

func skillRoots(home, project string) []skillRoot {
	abs := ""
	if project != "" {
		if a, err := filepath.Abs(project); err == nil && a != home {
			abs = a
		}
	}
	roots := knownAgentRoots(home, abs)
	roots = append(roots, claudePluginRoots(home)...)
	return append(roots, detectRuntimeRoots(home, abs)...)
}

// findSkillDirs returns every directory under root that directly holds a
// SKILL.md. Plugin roots are searched a few levels deep; others one level.
func findSkillDirs(root skillRoot) []string {
	var dirs []string
	maxDepth := 2
	if root.nested {
		maxDepth = 6
	}
	base := strings.Count(filepath.Clean(root.dir), string(os.PathSeparator))
	_ = filepath.WalkDir(root.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			// .hub is Hermes' hub state, not installed skills.
			if name == ".git" || name == "node_modules" || name == ".hub" {
				return filepath.SkipDir
			}
			if strings.Count(filepath.Clean(p), string(os.PathSeparator))-base > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "SKILL.md" && filepath.Dir(p) != filepath.Clean(root.dir) {
			dirs = append(dirs, filepath.Dir(p))
		}
		return nil
	})
	sort.Strings(dirs)
	return dirs
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// bundleDigestOf matches skillFormat.bundleDigest on the server: path-sorted
// "path:sha256" lines joined by newlines, then hashed.
func bundleDigestOf(skillMD []byte, files map[string][]byte) string {
	lines := []string{"SKILL.md:" + sha256hex(skillMD)}
	for p, b := range files {
		lines = append(lines, p+":"+sha256hex(b))
	}
	sort.Strings(lines)
	return sha256hex([]byte(strings.Join(lines, "\n")))
}

// frontmatterField reads one top-level scalar from SKILL.md frontmatter. Only
// for display; the server parses the real YAML.
func frontmatterField(text, field string) string {
	if !strings.HasPrefix(strings.TrimPrefix(text, string(rune(0xFEFF))), "---") {
		return ""
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "---" {
			break
		}
		if strings.HasPrefix(line, field+":") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, field+":")), `"'`)
		}
	}
	return ""
}

func displayPath(p, home string) string {
	if home != "" && strings.HasPrefix(p, home) {
		return "~" + filepath.ToSlash(strings.TrimPrefix(p, home))
	}
	return filepath.ToSlash(p)
}

func readSkill(dir string, root skillRoot, home string) (reportSkill, error) {
	skillMD, err := os.ReadFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		return reportSkill{}, err
	}
	files := map[string][]byte{}
	total := len(skillMD)
	count := 1
	tooLarge := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(dir, p)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "SKILL.md" || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		count++
		total += int(info.Size())
		if count > reportMaxFiles || total > reportMaxSkillBytes {
			tooLarge = true
			return filepath.SkipAll
		}
		b, readErr := os.ReadFile(p)
		if readErr == nil {
			files[rel] = b
		}
		return nil
	})

	text := string(skillMD)
	s := reportSkill{
		Client:        root.client,
		LocationScope: root.scope,
		Path:          displayPath(dir, home),
		Name:          frontmatterField(text, "name"),
		Description:   frontmatterField(text, "description"),
		FileCount:     count,
		TotalBytes:    total,
		BundleDigest:  bundleDigestOf(skillMD, files),
		tooLarge:      tooLarge,
	}
	if s.Name == "" {
		s.Name = filepath.Base(dir)
	}
	if !skillsReportMetadataOnly && !tooLarge {
		s.SkillMD = text
		paths := make([]string, 0, len(files))
		for p := range files {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			b := files[p]
			if utf8.Valid(b) && !strings.ContainsRune(string(b), 0) {
				s.Files = append(s.Files, reportFile{Path: p, Content: string(b), Encoding: "utf8"})
			} else {
				s.Files = append(s.Files, reportFile{Path: p, Content: base64.StdEncoding.EncodeToString(b), Encoding: "base64"})
			}
		}
	}
	return s, nil
}

// deviceID is a random id kept in ~/.contro1, so reports from one machine
// update the same rows without sending anything that identifies the hardware.
func deviceID() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "device-id")
	if b, readErr := os.ReadFile(p); readErr == nil {
		if id := strings.TrimSpace(string(b)); len(id) >= 16 {
			return id, nil
		}
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := "dev-" + hex.EncodeToString(buf)
	if err := os.WriteFile(p, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

func lastReportPath() string {
	dir, err := config.Dir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "skills-report-last")
}

// lastReportErrorPath holds why the last report failed, until one succeeds.
func lastReportErrorPath() string {
	dir, err := config.Dir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "skills-report-error")
}

// runSkillsReportRecorded keeps the reason a send failed, whatever step failed,
// so a scheduled run that nobody watches can still be explained by --status.
func runSkillsReportRecorded(cmd *cobra.Command, args []string) error {
	err := runSkillsReport(cmd, args)
	if err != nil && !skillsReportDryRun {
		_ = os.WriteFile(lastReportErrorPath(), []byte(time.Now().UTC().Format(time.RFC3339)+" "+err.Error()+"\n"), 0o600)
	}
	return err
}

func runSkillsReport(_ *cobra.Command, _ []string) error {
	if skillsReportEvery > 0 && !skillsReportDryRun {
		if b, err := os.ReadFile(lastReportPath()); err == nil {
			if t, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(string(b))); parseErr == nil && time.Since(t) < skillsReportEvery {
				infof("Skipped: last report was %s ago.", time.Since(t).Round(time.Minute))
				return nil
			}
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	var skills []reportSkill
	seen := map[string]bool{}
	for _, root := range skillRoots(home, skillsReportProjectDir) {
		for _, dir := range findSkillDirs(root) {
			// One folder, one report: Hermes or OpenClaw may also be set to
			// read ~/.agents/skills, which the table already covers.
			key := filepath.Clean(dir)
			if seen[key] {
				continue
			}
			seen[key] = true
			s, readErr := readSkill(dir, root, home)
			if readErr != nil {
				continue
			}
			skills = append(skills, s)
		}
	}
	if len(skills) > reportMaxSkills {
		skills = skills[:reportMaxSkills]
	}

	tbl := &output.Table{Headers: []string{"CLIENT", "WHERE", "SKILL", "FILES", "SENT"}}
	for _, s := range skills {
		sent := "content"
		if s.SkillMD == "" {
			sent = "digest only"
		}
		if s.tooLarge {
			sent = "digest only (too large)"
		}
		tbl.Rows = append(tbl.Rows, []string{s.Client, s.LocationScope, tailOf(s.Path, 50), fmt.Sprintf("%d", s.FileCount), sent})
	}

	if skillsReportDryRun {
		infof("Dry run: %d skill(s) found. Nothing was sent.", len(skills))
		return output.Render("table", skills, tbl)
	}

	c, pr, err := newClient()
	if err != nil {
		return err
	}
	id, err := deviceID()
	if err != nil {
		return err
	}
	label, _ := os.Hostname()

	// Content goes in batches under the server's body limit. The final call
	// lists every skill by digest with complete=true, so skills deleted from
	// this machine since the last report are marked removed.
	var batch []reportSkill
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		_, sendErr := c.Do("POST", "/api/centcom/v1/skills/inventory", map[string]any{
			"device": map[string]string{"id": id, "label": label}, "complete": false, "skills": batch,
		})
		batch, size = nil, 0
		return sendErr
	}
	for _, s := range skills {
		if s.SkillMD == "" {
			continue
		}
		encoded, _ := json.Marshal(s)
		if size+len(encoded) > reportBatchBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, s)
		size += len(encoded)
	}
	if err := flush(); err != nil {
		return err
	}

	summary := make([]reportSkill, 0, len(skills))
	for _, s := range skills {
		s.SkillMD, s.Files = "", nil
		summary = append(summary, s)
	}
	resp, err := c.Do("POST", "/api/centcom/v1/skills/inventory", map[string]any{
		"device": map[string]string{"id": id, "label": label}, "complete": true, "skills": summary,
		// Whether the organization's Claude Code policy blocks local skills here.
		"claude_code_skills_lock": claudeCodeSkillsLock(),
		// Complete for the person's own skills and this project only, so a run
		// in another repository does not mark this one's project skills removed.
		"project_root": projectRoot(home),
	})
	if err != nil {
		return err
	}
	_ = os.Remove(lastReportErrorPath())
	_ = os.WriteFile(lastReportPath(), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)

	infof("Reported %d skill(s) from this machine. Removed since last report: %v.", len(skills), resp["removed"])
	// The organization may allow only skills delivered by Contro1. Say so to
	// the person at the moment it matters, in plain words.
	if policy, ok := resp["policy"].(map[string]any); ok && policy["local_skills"] == "contro1_only" {
		if n, _ := policy["outside_policy"].(float64); n > 0 {
			infof("Your organization allows only skills delivered by Contro1. %d skill(s) on this machine are outside that policy; your administrators can see them. Ask them to add what you need to Contro1, then remove the local copy.", int(n))
		}
	}
	return output.Render(outFormat(pr), skills, tbl)
}

// projectRoot is the project this report covers, shown as the server stores
// project skill paths. Empty when the report runs in the home directory.
func projectRoot(home string) string {
	abs, err := filepath.Abs(skillsReportProjectDir)
	if err != nil || abs == home {
		return ""
	}
	return displayPath(abs, home)
}

// tailOf keeps the end of a path, which is the part that names the skill.
func tailOf(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "..." + string(r[len(r)-n+3:])
}
