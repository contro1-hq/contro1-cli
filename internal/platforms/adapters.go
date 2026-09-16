package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// ---------------------------------------------------------------------------
// OpenClaw (UNVERIFIED discovery and config location)
// ---------------------------------------------------------------------------

type openClaw struct{ opts Options }

func (o *openClaw) Name() string { return "openclaw" }

func (o *openClaw) bin() string {
	if o.opts.Bin != "" {
		return o.opts.Bin
	}
	return "openclaw"
}

// Discover tries `openclaw agents list --json`, then the config file's
// agents.list[].id, then explicit --agent flags.
func (o *openClaw) Discover(ctx context.Context) (Instance, []Subject, error) {
	configPath := filepath.Join(o.opts.Home, ".openclaw", "openclaw.json")
	inst := Instance{Label: "OpenClaw", Digest: digest("openclaw", configPath)}
	if subjects := explicit(o.opts.Agents); len(subjects) > 0 {
		return inst, subjects, nil
	}
	if out, err := o.opts.Runner(ctx, o.bin(), "agents", "list", "--json"); err == nil {
		if subjects := parseAgentList(out); len(subjects) > 0 {
			return inst, subjects, nil
		}
	}
	if raw, err := os.ReadFile(configPath); err == nil {
		var cfg struct {
			Agents struct {
				List []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"list"`
			} `json:"agents"`
		}
		if json.Unmarshal(raw, &cfg) == nil {
			var subjects []Subject
			for _, a := range cfg.Agents.List {
				if a.ID != "" {
					subjects = append(subjects, Subject{ID: a.ID, Display: firstNonEmpty(a.Name, a.ID)})
				}
			}
			if len(subjects) > 0 {
				return inst, subjects, nil
			}
		}
	}
	return inst, nil, errors.New("no OpenClaw agents found; pass --agent <id> for each agent")
}

func parseAgentList(out []byte) []Subject {
	var list []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if json.Unmarshal(out, &list) != nil {
		var wrapped struct {
			Agents []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"agents"`
		}
		if json.Unmarshal(out, &wrapped) != nil {
			return nil
		}
		for _, a := range wrapped.Agents {
			list = append(list, struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}{a.ID, a.Name})
		}
	}
	var subjects []Subject
	for _, a := range list {
		if a.ID != "" {
			subjects = append(subjects, Subject{ID: a.ID, Display: firstNonEmpty(a.Name, a.ID)})
		}
	}
	return subjects
}

func (o *openClaw) envPath() string {
	if o.opts.ConfigDir != "" {
		return filepath.Join(o.opts.ConfigDir, "contro1.env")
	}
	return filepath.Join(o.opts.Home, ".openclaw", "contro1.env")
}

func (o *openClaw) PlanConfig(mappingPath string) []Change {
	return []Change{{Kind: "file", Path: o.envPath(), Description: "Point the OpenClaw Contro1 bridge at this computer's agent mapping", After: "CONTRO1_PLATFORM_MAPPING_FILE=" + mappingPath}}
}

func (o *openClaw) ApplyConfig(_ context.Context, mappingPath string, _ *runtimeproto.MappingFile, j *Journal) error {
	return writeEnvFile(o.envPath(), map[string]string{"CONTRO1_PLATFORM_MAPPING_FILE": mappingPath}, j)
}

func (o *openClaw) RemoveConfig(_ context.Context, j *Journal) error { return removeCreated(j) }
func (o *openClaw) RoleChanges(*runtimeproto.MappingFile) []Change   { return nil }
func (o *openClaw) ApplyRoles(context.Context, *runtimeproto.MappingFile, *Journal) error {
	return nil
}
func (o *openClaw) AllowedPrincipal(string) (string, error) {
	return currentPrincipal(o.opts.Principal)
}
func (o *openClaw) SafeTest() string {
	return `Try it: ask your assistant to run "sudo ls". Contro1 asks for approval first.`
}

// ---------------------------------------------------------------------------
// NanoClaw (UNVERIFIED group discovery, role commands and container mounts)
// ---------------------------------------------------------------------------

type nanoClaw struct{ opts Options }

func (n *nanoClaw) Name() string { return "nanoclaw" }

func (n *nanoClaw) bin() string {
	if n.opts.Bin != "" {
		return n.opts.Bin
	}
	return "ncl"
}

func (n *nanoClaw) Discover(ctx context.Context) (Instance, []Subject, error) {
	inst := Instance{Label: "NanoClaw", Digest: digest("nanoclaw", n.bin())}
	if subjects := explicit(n.opts.Agents); len(subjects) > 0 {
		return inst, subjects, nil
	}
	out, err := n.opts.Runner(ctx, n.bin(), "groups", "list", "--json")
	if err != nil {
		return inst, nil, fmt.Errorf("could not list NanoClaw groups with %s groups list: %w (pass --ncl or --agent <group id>)", n.bin(), err)
	}
	var groups []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Folder string `json:"folder"`
	}
	if err := json.Unmarshal(out, &groups); err != nil {
		var wrapped struct {
			Groups []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Folder string `json:"folder"`
			} `json:"groups"`
		}
		if err := json.Unmarshal(out, &wrapped); err != nil {
			return inst, nil, fmt.Errorf("unexpected output from %s groups list", n.bin())
		}
		groups = wrapped.Groups
	}
	var subjects []Subject
	for _, g := range groups {
		id := firstNonEmpty(g.ID, g.Folder)
		if id != "" {
			subjects = append(subjects, Subject{ID: id, Display: firstNonEmpty(g.Name, id)})
		}
	}
	if len(subjects) == 0 {
		return inst, nil, errors.New("no NanoClaw groups found")
	}
	return inst, subjects, nil
}

func (n *nanoClaw) envPath() string {
	if n.opts.ConfigDir != "" {
		return filepath.Join(n.opts.ConfigDir, "contro1.env")
	}
	return filepath.Join(n.opts.Home, ".config", "nanoclaw", "contro1.env")
}

func (n *nanoClaw) PlanConfig(mappingPath string) []Change {
	return []Change{{Kind: "file", Path: n.envPath(), Description: "Point the NanoClaw Contro1 channel at the per-group mapping (each group gets only its own endpoint)", After: "CONTRO1_PLATFORM_MAPPING_FILE=" + mappingPath}}
}

func (n *nanoClaw) ApplyConfig(_ context.Context, mappingPath string, _ *runtimeproto.MappingFile, j *Journal) error {
	return writeEnvFile(n.envPath(), map[string]string{"CONTRO1_PLATFORM_MAPPING_FILE": mappingPath}, j)
}

func (n *nanoClaw) RemoveConfig(_ context.Context, j *Journal) error { return removeCreated(j) }

// RoleChanges: the Contro1 channel needs a NanoClaw user allowed to resolve
// approvals in each group. This changes who can approve, so it is shown before
// and after and confirmed separately at a terminal.
func (n *nanoClaw) RoleChanges(m *runtimeproto.MappingFile) []Change {
	var out []Change
	if m == nil {
		return out
	}
	out = append(out, Change{Kind: "role", RoleChange: true, Description: "Create the NanoClaw user contro1:approvals", After: n.bin() + " users create --id contro1:approvals"})
	for _, e := range m.Entries {
		out = append(out, Change{Kind: "role", RoleChange: true, Description: "Let Contro1 decisions resolve approvals in group " + firstNonEmpty(e.DisplayName, e.PlatformSubject), Before: "contro1:approvals has no role in " + e.PlatformSubject, After: n.bin() + " roles grant --role admin --user contro1:approvals --group " + e.PlatformSubject})
	}
	return out
}

func (n *nanoClaw) ApplyRoles(ctx context.Context, m *runtimeproto.MappingFile, j *Journal) error {
	for _, c := range n.RoleChanges(m) {
		fields := strings.Fields(c.After)
		if len(fields) < 2 {
			continue
		}
		if _, err := n.opts.Runner(ctx, fields[0], fields[1:]...); err != nil && !strings.Contains(c.After, "users create") {
			return fmt.Errorf("%s: %w", c.After, err)
		}
		j.RoleCommands = append(j.RoleCommands, c.After)
	}
	return nil
}

func (n *nanoClaw) AllowedPrincipal(string) (string, error) {
	// Per-group container identities are UNVERIFIED; by default the host user
	// that runs NanoClaw, with isolation coming from mounting only that group's
	// socket into its container.
	return currentPrincipal(n.opts.Principal)
}

func (n *nanoClaw) SafeTest() string {
	return "Try it: in a connected group, ask the assistant to do something that needs approval."
}

// ---------------------------------------------------------------------------
// Claude Code
// ---------------------------------------------------------------------------

type claudeCode struct{ opts Options }

func (c *claudeCode) Name() string { return "claude-code" }

func (c *claudeCode) Discover(context.Context) (Instance, []Subject, error) {
	host, _ := os.Hostname()
	subject := "claude-code@" + strings.ToLower(firstNonEmpty(host, "computer"))
	if s := explicit(c.opts.Agents); len(s) > 0 {
		return Instance{Label: "Claude Code", Digest: digest("claude-code", host)}, s, nil
	}
	return Instance{Label: "Claude Code", Digest: digest("claude-code", host)}, []Subject{{ID: subject, Display: "Claude Code on " + firstNonEmpty(host, "this computer")}}, nil
}

func (c *claudeCode) envPath() string {
	if c.opts.ConfigDir != "" {
		return filepath.Join(c.opts.ConfigDir, "contro1.env")
	}
	return filepath.Join(c.opts.Home, ".contro1", "claude-code.env")
}

func (c *claudeCode) PlanConfig(mappingPath string) []Change {
	return []Change{{Kind: "file", Path: c.envPath(), Description: "Point the Contro1 Claude Code hook at this computer's mapping", After: "CONTRO1_PLATFORM_MAPPING_FILE=" + mappingPath}}
}

func (c *claudeCode) ApplyConfig(_ context.Context, mappingPath string, _ *runtimeproto.MappingFile, j *Journal) error {
	return writeEnvFile(c.envPath(), map[string]string{"CONTRO1_PLATFORM_MAPPING_FILE": mappingPath}, j)
}

func (c *claudeCode) RemoveConfig(_ context.Context, j *Journal) error { return removeCreated(j) }
func (c *claudeCode) RoleChanges(*runtimeproto.MappingFile) []Change   { return nil }
func (c *claudeCode) ApplyRoles(context.Context, *runtimeproto.MappingFile, *Journal) error {
	return nil
}
func (c *claudeCode) AllowedPrincipal(string) (string, error) {
	return currentPrincipal(c.opts.Principal)
}
func (c *claudeCode) SafeTest() string {
	return "Try it: ask Claude Code to run a command that needs approval."
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
