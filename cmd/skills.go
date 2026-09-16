package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	skillsSyncDir   string
	skillsSyncForce bool
)

func init() {
	skillsCmd := &cobra.Command{
		Use:     "skills",
		Short:   "Read the organizational skills this agent has been given",
		GroupID: groupAgent,
		Long: `Skills are your organization's own instructions for how work is done.

They are guidance, not permission. A skill can tell an agent how you want a
refund handled; whether it may actually send anything is decided by an
ActionGrant and re-checked at execution time. Reading a skill grants nothing.`,
	}

	listCmd := &cobra.Command{
		Use:     "list",
		Short:   "List the skills in this agent's manifest",
		Example: `  contro1 skills list`,
		RunE:    runSkillsList,
	}

	getCmd := &cobra.Command{
		Use:   "get <skill_key> [version]",
		Short: "Print one skill's instructions",
		Long: `Prints the body of a skill version. With no version, prints the version this
agent currently has according to its manifest - which is not necessarily the
latest published one, if the agent is pinned.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: runSkillsGet,
	}

	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Write this agent's skills to a local directory",
		Long: `Downloads every skill in the manifest into a directory, one file per skill.

Only skills whose content digest changed are downloaded. Files that are already
current are left alone, so running this repeatedly is cheap and its output tells
you what actually moved.

This writes files. It never sends anything.`,
		RunE: runSkillsSync,
	}
	syncCmd.Flags().StringVar(&skillsSyncDir, "dir", ".contro1/skills", "directory to write into")
	syncCmd.Flags().BoolVar(&skillsSyncForce, "force", false, "re-download even when the digest matches")

	skillsCmd.AddCommand(listCmd, getCmd, syncCmd)
	rootCmd.AddCommand(skillsCmd)
}

type skillEntry struct {
	Key        string
	Name       string
	Version    float64
	Digest     string
	ViaType    string
	ViaID      string
	Pinned     bool
	ActionRefs []string
}

// fetchManifest returns the entries plus whether a capability contract decided
// them, because "why am I on version 4 when 5 is published" is the first
// question a pinned agent's operator asks.
func fetchManifest() ([]skillEntry, *config.Profile, float64, error) {
	c, pr, err := newClient()
	if err != nil {
		return nil, nil, 0, err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/skills/manifest", nil)
	if err != nil {
		return nil, nil, 0, err
	}
	manifest := asMap(resp["manifest"])

	var contractRevision float64
	if v, ok := manifest["contract_revision"].(float64); ok {
		contractRevision = v
	}

	var entries []skillEntry
	for _, raw := range asSlice(manifest["skills"]) {
		m := asMap(raw)
		via := asMap(m["via"])
		entry := skillEntry{
			Key:     str(m["skill_key"]),
			Name:    str(m["name"]),
			Digest:  str(m["content_digest"]),
			ViaType: str(via["subject_type"]),
			ViaID:   str(via["subject_id"]),
		}
		if v, ok := m["version"].(float64); ok {
			entry.Version = v
		}
		if p, ok := via["pinned"].(bool); ok {
			entry.Pinned = p
		}
		for _, ref := range asSlice(m["action_refs"]) {
			r := asMap(ref)
			entry.ActionRefs = append(entry.ActionRefs,
				fmt.Sprintf("%s@%v", str(r["action_id"]), r["action_version"]))
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries, pr, contractRevision, nil
}

func runSkillsList(_ *cobra.Command, _ []string) error {
	entries, pr, contractRevision, err := fetchManifest()
	if err != nil {
		return err
	}

	if contractRevision > 0 {
		// Said before the table, because it changes how every row should be
		// read: these versions are frozen and will not move on publish.
		infof("Pinned by capability contract revision %.0f. These versions do not "+
			"change when a new one is published.", contractRevision)
	} else if len(entries) > 0 {
		infof("Following the current published versions. These change on the next " +
			"sync after anyone publishes.")
	}

	tbl := &output.Table{Headers: []string{"SKILL", "NAME", "VERSION", "VIA", "ACTIONS"}}
	for _, e := range entries {
		via := e.ViaType
		if e.Pinned {
			via += " (pinned)"
		}
		tbl.Rows = append(tbl.Rows, []string{
			e.Key, truncate(e.Name, 30), fmt.Sprintf("%.0f", e.Version),
			via, truncate(strings.Join(e.ActionRefs, ", "), 34),
		})
	}
	if len(entries) == 0 {
		infof("No skills are assigned to this agent.")
	}
	return output.Render(outFormat(pr), entries, tbl)
}

func runSkillsGet(_ *cobra.Command, args []string) error {
	key := args[0]
	version := ""
	if len(args) == 2 {
		version = args[1]
	} else {
		entries, _, _, err := fetchManifest()
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Key == key {
				version = fmt.Sprintf("%.0f", e.Version)
			}
		}
		if version == "" {
			return fmt.Errorf("skill %q is not in this agent's manifest; "+
				"pass a version explicitly to read it anyway", key)
		}
	}

	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/skills/"+key+"/versions/"+version, nil)
	if err != nil {
		return err
	}
	skill := asMap(resp["skill"])

	if outFormat(pr) == "table" {
		// The body is the point of this command, so it is printed as itself
		// rather than squeezed into a table cell.
		fmt.Printf("%s v%v\n\n%s\n", str(skill["skill_key"]), skill["version"], str(skill["body"]))
		return nil
	}
	return output.Render(outFormat(pr), skill, nil)
}

func runSkillsSync(_ *cobra.Command, _ []string) error {
	entries, pr, contractRevision, err := fetchManifest()
	if err != nil {
		return err
	}
	c, _, err := newClient()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(skillsSyncDir, 0o755); err != nil {
		return fmt.Errorf("could not create %s: %w", skillsSyncDir, err)
	}

	type result struct {
		Skill   string `json:"skill"`
		Version string `json:"version"`
		Action  string `json:"action"`
		Path    string `json:"path"`
	}
	var results []result
	changed := 0

	for _, e := range entries {
		path := filepath.Join(skillsSyncDir, e.Key+".md")

		// Two independent reasons to re-download, and they are different
		// questions. The manifest may have moved on (upstream published, or this
		// agent was upgraded), or the local file may have been edited by hand.
		// A check that only compared timestamps would miss the second entirely,
		// and a hand-edited skill file is precisely the one worth overwriting.
		if !skillsSyncForce && localIsCurrent(path, e.Digest) {
			results = append(results, result{e.Key, fmt.Sprintf("%.0f", e.Version), "unchanged", path})
			continue
		}

		resp, fetchErr := c.Do("GET",
			fmt.Sprintf("/api/centcom/v1/skills/%s/versions/%.0f", e.Key, e.Version), nil)
		if fetchErr != nil {
			return fmt.Errorf("could not fetch %s v%.0f: %w", e.Key, e.Version, fetchErr)
		}
		skill := asMap(resp["skill"])
		body := str(skill["body"])

		// Both digests are recorded. The server one answers "has the published
		// content moved"; the body one answers "has this file been edited
		// since we wrote it". Neither question can be answered from the other.
		bodySum := sha256.Sum256([]byte(body))
		header := fmt.Sprintf(
			"<!-- contro1 skill %s v%.0f\n"+
				"     digest %s\n"+
				"     body %s\n"+
				"     Do not edit. Published by your organization; local changes are\n"+
				"     overwritten on the next sync. -->\n\n",
			e.Key, e.Version, str(skill["content_digest"]), hex.EncodeToString(bodySum[:]))

		if writeErr := os.WriteFile(path, []byte(header+body), 0o644); writeErr != nil {
			return fmt.Errorf("could not write %s: %w", path, writeErr)
		}
		changed++
		results = append(results, result{e.Key, fmt.Sprintf("%.0f", e.Version), "written", path})
	}

	if contractRevision > 0 {
		infof("Pinned by capability contract revision %.0f.", contractRevision)
	}
	infof("%d skill(s) in manifest, %d written, %d already current.",
		len(entries), changed, len(entries)-changed)

	tbl := &output.Table{Headers: []string{"SKILL", "VERSION", "ACTION", "PATH"}}
	for _, r := range results {
		tbl.Rows = append(tbl.Rows, []string{r.Skill, r.Version, r.Action, r.Path})
	}
	return output.Render(outFormat(pr), results, tbl)
}

// localIsCurrent reports whether the file on disk still holds exactly what the
// manifest says it should.
//
// Two conditions, both required, because they answer different questions:
//
//   - the digest recorded in the header matches the manifest's, meaning the
//     PUBLISHED content has not moved
//   - the body hashes to what the header claims, meaning nobody has edited the
//     file since it was written
//
// Checking only the first would leave a hand-edited skill in place forever,
// silently feeding an agent instructions its organization never published -
// which is the failure this whole phase exists to prevent, arriving through the
// back door.
func localIsCurrent(path, manifestDigest string) bool {
	contents, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(contents)

	end := strings.Index(text, "-->")
	if end == -1 {
		return false
	}
	header := text[:end]
	body := strings.TrimPrefix(text[end+3:], "\n\n")

	if headerField(header, "digest ") != manifestDigest {
		return false
	}
	sum := sha256.Sum256([]byte(body))
	return headerField(header, "body ") == hex.EncodeToString(sum[:])
}

func headerField(header, marker string) string {
	i := strings.Index(header, marker)
	if i == -1 {
		return ""
	}
	rest := header[i+len(marker):]
	if end := strings.IndexAny(rest, "\r\n "); end != -1 {
		rest = rest[:end]
	}
	return strings.TrimSpace(rest)
}
