package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// claudeCodeSkillsLock reports whether Claude Code on this computer is locked
// to skills from plugins and managed sources, by the organization's managed
// settings (`strictPluginOnlyCustomization`). Users cannot override managed
// settings, so a lock here means personal (~/.claude/skills) and project
// (.claude/skills) skills do not load at all.
//
// "locked", "not_locked", or "unknown" when no managed policy is on this
// computer. Server-managed settings (from the claude.ai console) live on
// Anthropic's side and are not visible here; they read as "unknown", never as
// "not_locked".
func claudeCodeSkillsLock() string {
	for _, doc := range claudeCodeManagedDocs() {
		var settings map[string]any
		if json.Unmarshal([]byte(doc), &settings) != nil {
			continue
		}
		if lockCoversSkills(settings["strictPluginOnlyCustomization"]) {
			return "locked"
		}
		return "not_locked"
	}
	return "unknown"
}

// lockCoversSkills accepts the forms the setting takes: true, a list naming
// "skills", or an object with skills: true.
func lockCoversSkills(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case []any:
		for _, item := range x {
			if s, ok := item.(string); ok && s == "skills" {
				return true
			}
		}
	case map[string]any:
		if b, ok := x["skills"].(bool); ok {
			return b
		}
	}
	return false
}

// claudeCodeManagedDocs returns the admin-managed settings documents on this
// computer, highest precedence first: the OS policy (macOS profile, Windows
// HKLM registry), then the managed-settings.json file.
func claudeCodeManagedDocs() []string {
	var docs []string
	switch runtime.GOOS {
	case "windows":
		if out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Policies\ClaudeCode`, "/v", "Settings").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if i := strings.Index(line, "REG_"); i >= 0 && strings.Contains(line, "Settings") {
					fields := strings.SplitN(strings.TrimSpace(line[i:]), " ", 2)
					if len(fields) == 2 {
						docs = append(docs, strings.TrimSpace(fields[1]))
					}
				}
			}
		}
		docs = append(docs, readIfExists(filepath.Join(`C:\Program Files\ClaudeCode`, "managed-settings.json"))...)
	case "darwin":
		if out, err := exec.Command("defaults", "read", "/Library/Managed Preferences/com.anthropic.claudecode", "strictPluginOnlyCustomization").Output(); err == nil {
			v := strings.TrimSpace(string(out))
			if v == "1" || strings.Contains(v, "skills") {
				docs = append(docs, `{"strictPluginOnlyCustomization": true}`)
			}
		}
		docs = append(docs, readIfExists("/Library/Application Support/ClaudeCode/managed-settings.json")...)
	default:
		docs = append(docs, readIfExists("/etc/claude-code/managed-settings.json")...)
	}
	return docs
}

func readIfExists(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil || len(strings.TrimSpace(string(b))) == 0 {
		return nil
	}
	return []string{string(b)}
}
