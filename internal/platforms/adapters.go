package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
		}
		if json.Unmarshal(out, &wrapped) != nil {
			return nil
		}
		if len(wrapped.Agents) == 0 {
			wrapped.Agents = wrapped.Data
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
		// ncl --json answers {ok, data: [...]}; older builds used {groups: [...]}.
		var wrapped struct {
			Groups []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Folder string `json:"folder"`
			} `json:"groups"`
			Data []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Folder string `json:"folder"`
			} `json:"data"`
		}
		if err := json.Unmarshal(out, &wrapped); err != nil {
			return inst, nil, fmt.Errorf("unexpected output from %s groups list", n.bin())
		}
		groups = wrapped.Groups
		if len(groups) == 0 {
			groups = wrapped.Data
		}
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

// ---------------------------------------------------------------------------
// Reach
// ---------------------------------------------------------------------------

// nclData unwraps ncl's {"ok":true,"data":...} envelope. Older builds answered
// with the bare value, which is accepted too.
func nclData(out []byte) (json.RawMessage, error) {
	var env struct {
		OK    *bool           `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &env); err == nil && env.OK != nil {
		if !*env.OK {
			return nil, fmt.Errorf("ncl: %s", env.Error.Message)
		}
		return env.Data, nil
	}
	return out, nil
}

// localHostReach is the reach of a platform whose only way in is a shell on
// this computer, as this operating system user.
//
// It is `private` because the boundary is enforced by the operating system
// rather than by anyone's configuration, which makes it the strongest one we
// have. It stops being true the moment the platform is fronted by anything
// reachable from elsewhere, so an adapter claims it only while it talks to a
// local process it started itself.
func localHostReach(platform, principal string) runtimeproto.AgentReach {
	host, _ := os.Hostname()
	if host == "" {
		host = "this computer"
	}
	label := platform + " on " + host
	if principal != "" {
		label = principal + "@" + host
	}
	return runtimeproto.AgentReach{
		SchemaVersion: runtimeproto.SchemaVersion,
		Platform:      platform,
		ObservedAt:    time.Now().UTC().Format(time.RFC3339),
		Complete:      true,
		Contexts: []runtimeproto.ReachContext{{
			ContextID:         "host:" + host,
			Label:             label,
			Kind:              runtimeproto.ReachPrivate,
			ParticipantsKnown: true,
			ParticipantCount:  1,
		}},
	}
}

// Reach reports an OpenClaw assistant as reachable by people we cannot name.
//
// It is tempting to call this private: the bridge talks to OpenClaw over a
// local socket as one operating system user, and connect runs as that user. But
// that is who can reach the CREDENTIAL. OpenClaw answers on WhatsApp, Telegram,
// iMessage, Signal and Slack, any of which can be a group, and nothing this
// adapter can see says which of them are wired up or who is in them.
//
// So the answer is unknown, which Contro1 reads exactly like a group chat.
// An operator who knows their assistant has no chat channels can say so, and
// that is a claim with a name behind it rather than a guess with none.
func (o *openClaw) Reach(_ context.Context, _ string) (runtimeproto.AgentReach, error) {
	host, _ := os.Hostname()
	if host == "" {
		host = "this computer"
	}
	return runtimeproto.AgentReach{
		SchemaVersion: runtimeproto.SchemaVersion,
		Platform:      "openclaw",
		ObservedAt:    time.Now().UTC().Format(time.RFC3339),
		Complete:      true,
		Contexts: []runtimeproto.ReachContext{{
			ContextID:         "host:" + host,
			Label:             "OpenClaw on " + host,
			Kind:              runtimeproto.ReachUnknown,
			ParticipantsKnown: false,
		}},
	}, nil
}

// Reach for Claude Code is the local host: it is a terminal tool driven by
// whoever is at the keyboard, with no channel anyone else can message.
func (c *claudeCode) Reach(_ context.Context, _ string) (runtimeproto.AgentReach, error) {
	principal, _ := c.AllowedPrincipal("")
	return localHostReach("claude-code", principal), nil
}

// Reach lists the conversations wired to one NanoClaw agent group.
//
// Two hops, because NanoClaw splits the question: a wiring says which
// conversation reaches which agent group and on what terms, and the messaging
// group says whether that conversation is a group chat. Neither alone answers
// "who can instruct this agent".
//
// The WhatsApp JID is deliberately left behind. It is a phone number or a group
// address, it would be stored in Contro1 and shown on screens, and nothing here
// needs it: the binding key is NanoClaw's own `mg-` id and the display name is
// the conversation's name.
func (n *nanoClaw) Reach(ctx context.Context, subject string) (runtimeproto.AgentReach, error) {
	reach := runtimeproto.AgentReach{
		SchemaVersion: runtimeproto.SchemaVersion,
		Platform:      "nanoclaw",
		ObservedAt:    time.Now().UTC().Format(time.RFC3339),
		Complete:      false,
	}
	if subject == "" {
		return reach, errors.New("reach needs an agent group id")
	}

	out, err := n.opts.Runner(ctx, n.bin(), "wirings", "list", "--json")
	if err != nil {
		return reach, fmt.Errorf("could not list NanoClaw wirings with %s wirings list: %w", n.bin(), err)
	}
	data, err := nclData(out)
	if err != nil {
		return reach, err
	}
	// Listed whole and filtered here: the flag spelling for a server-side filter
	// differs between builds, and reading one agent group's rows out of the full
	// list cannot silently return a short answer.
	var wirings []struct {
		MessagingGroupID string `json:"messaging_group_id"`
		AgentGroupID     string `json:"agent_group_id"`
		SenderScope      string `json:"sender_scope"`
	}
	if err := json.Unmarshal(data, &wirings); err != nil {
		return reach, fmt.Errorf("unexpected output from %s wirings list", n.bin())
	}

	for _, w := range wirings {
		if w.AgentGroupID != subject || w.MessagingGroupID == "" {
			continue
		}
		// Every conversation starts unknown. It is only downgraded to private
		// once NanoClaw has said, in this run, that it is not a group chat.
		entry := runtimeproto.ReachContext{
			ContextID:         w.MessagingGroupID,
			Kind:              runtimeproto.ReachUnknown,
			ParticipantsKnown: w.SenderScope == "known",
		}
		if mg, err := n.messagingGroup(ctx, w.MessagingGroupID); err == nil {
			entry.Label = mg.Name
			if mg.IsGroup == 0 {
				entry.Kind = runtimeproto.ReachPrivate
			} else {
				entry.Kind = runtimeproto.ReachShared
			}
		}
		reach.Contexts = append(reach.Contexts, entry)
	}

	// A wiring list that came back whole is a complete answer, including when it
	// is empty: an agent wired to nothing answers nobody.
	reach.Complete = true
	return reach, nil
}

type nclMessagingGroup struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IsGroup int    `json:"is_group"`
}

func (n *nanoClaw) messagingGroup(ctx context.Context, id string) (nclMessagingGroup, error) {
	var mg nclMessagingGroup
	out, err := n.opts.Runner(ctx, n.bin(), "messaging-groups", "get", "--id", id, "--json")
	if err != nil {
		return mg, err
	}
	data, err := nclData(out)
	if err != nil {
		return mg, err
	}
	if err := json.Unmarshal(data, &mg); err != nil {
		return mg, fmt.Errorf("unexpected output from %s messaging-groups get", n.bin())
	}
	return mg, nil
}
