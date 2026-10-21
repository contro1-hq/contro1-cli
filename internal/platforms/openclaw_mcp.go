package platforms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

/*
OpenClaw: one Contro1 MCP server per agent, and the tool rules between them.

OpenClaw's MCP servers belong to the gateway, not to an agent, so every agent
sees every server. One `contro1` entry on a gateway with three agents makes all
three the same identity. So each connected agent gets its own server, pinned to
that agent with --agent, and each agent gets tool rules that hide the other
agents' servers.

Checked against OpenClaw's source (2026.10.5) and docs:

  - Servers live at mcp.servers.<name> {command, args}
    (docs/gateway/config-extensions.md, docs/cli/mcp/registry.md).
  - A server's tools reach an agent as <safe server name>__<tool>, and the safe
    name replaces characters outside [A-Za-z0-9_-], must start with a letter and
    is cut to 30 characters (src/agents/agent-bundle-mcp-names.ts). Names here
    are generated inside those rules, so the pattern we deny is the one
    OpenClaw matches.
  - Per-agent tool policy is agents.entries.<id>.tools.{allow, alsoAllow,
    deny}, keyed by agent id; allow and alsoAllow together are rejected, and
    agents.list is not in the schema at all (src/config/zod-schema.agents.ts,
    src/config/zod-schema.agent-runtime.ts).
  - tools.deny "<server>__*" keeps that server from even connecting for the
    agent (docs/cli/mcp/registry.md).
  - While a gateway runs, `openclaw mcp add|set` and `openclaw config
    set|patch` refuse (docs/cli/config.md, docs/cli/mcp/registry.md). The
    gateway's own config.patch validates the change and waits until it is live
    (docs/gateway/configuration/config-rpc.md). With no gateway running,
    `openclaw config patch --file` takes the same patch.
  - mcp, agents.entries and tools are hot reloaded
    (src/gateway/config-reload-plan.ts), so nothing is restarted.

The whole change is one patch, written one of those two ways or not at all: a
half-applied set of servers without their rules is the leak this exists to
prevent. contro1 never edits openclaw.json itself; it only copies it first.
*/

const openClawMaxServerName = 30 // TOOL_NAME_MAX_PREFIX in agent-bundle-mcp-names.ts

var openClawUnsafeName = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// openClawServerName is "contro1-<agent id>" when that is already a safe
// OpenClaw server name, and otherwise a safe prefix of it plus a short hash of
// the id, so two agents never share a name and OpenClaw never renames ours.
func openClawServerName(subject string) string {
	safe := openClawUnsafeName.ReplaceAllString(subject, "-")
	name := "contro1-" + safe
	if safe == subject && len(name) <= openClawMaxServerName {
		return name
	}
	sum := sha256.Sum256([]byte(subject))
	short := hex.EncodeToString(sum[:])[:6]
	keep := openClawMaxServerName - len("contro1-") - 1 - len(short)
	if len(safe) > keep {
		safe = safe[:keep]
	}
	return "contro1-" + safe + "-" + short
}

func openClawToolPattern(subject string) string { return openClawServerName(subject) + "__*" }

// OpenClawServerName is the MCP server name connect gives an OpenClaw agent,
// for anything that has to name it to a person.
func OpenClawServerName(subject string) string { return openClawServerName(subject) }

// openClawServerEntry is what connect writes for one agent. An absolute path:
// the gateway is a service whose PATH does not include /usr/local/bin.
func openClawServerEntry(subject string) map[string]any {
	return map[string]any{"command": contro1Binary(), "args": mcpArgs(subject)}
}

// ---------------------------------------------------------------------------
// Where the configuration is (src/config/paths.ts, src/config/state-dir.ts,
// src/cli/profile-utils.ts). Asked of OpenClaw first; this is the fallback.
// ---------------------------------------------------------------------------

func (o *openClaw) openClawHome() string {
	if h := strings.TrimSpace(os.Getenv("OPENCLAW_HOME")); h != "" {
		return expandTilde(h, o.opts.Home)
	}
	return o.opts.Home
}

func (o *openClaw) openClawStateDir() string {
	home := o.openClawHome()
	if d := strings.TrimSpace(os.Getenv("OPENCLAW_STATE_DIR")); d != "" {
		return expandTilde(d, home)
	}
	if p := strings.TrimSpace(os.Getenv("OPENCLAW_PROFILE")); p != "" && !strings.EqualFold(p, "default") {
		return filepath.Join(home, ".openclaw-"+p)
	}
	return filepath.Join(home, ".openclaw")
}

// openClawConfigPath is where OpenClaw would read openclaw.json from.
func (o *openClaw) openClawConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("OPENCLAW_CONFIG_PATH")); p != "" {
		return expandTilde(p, o.openClawHome())
	}
	return filepath.Join(o.openClawStateDir(), "openclaw.json")
}

func expandTilde(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home, p[2:])
	}
	return p
}

// ---------------------------------------------------------------------------
// Reading the configuration
// ---------------------------------------------------------------------------

type ocServer struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"`
}

type ocTools struct {
	Allow     *[]string `json:"allow"`
	AlsoAllow *[]string `json:"alsoAllow"`
	Deny      []string  `json:"deny"`
}

type ocEntry struct {
	Tools *ocTools `json:"tools"`
}

type openClawState struct {
	// viaGateway: a running gateway answered, and writes go through it.
	viaGateway bool
	hash       string
	path       string
	servers    map[string]ocServer
	entries    map[string]ocEntry
}

/*
readState asks the running gateway first (config.get returns the config and the
hash a patch must be based on). No gateway: the CLI reads the same values with
`openclaw config get`, which works whether or not one runs. An unset path comes
back as the CLI's JSON failure envelope (docs/cli/index.md, "JSON failures").
*/
func (o *openClaw) readState(ctx context.Context) (openClawState, error) {
	st := openClawState{servers: map[string]ocServer{}, entries: map[string]ocEntry{}}
	if out, err := o.opts.Runner(ctx, o.bin(), "gateway", "call", "config.get", "--params", "{}", "--json"); err == nil {
		var resp struct {
			Path   string `json:"path"`
			Exists bool   `json:"exists"`
			Valid  *bool  `json:"valid"`
			Hash   string `json:"hash"`
			Config struct {
				Mcp struct {
					Servers map[string]ocServer `json:"servers"`
				} `json:"mcp"`
				Agents struct {
					Entries map[string]ocEntry `json:"entries"`
				} `json:"agents"`
			} `json:"config"`
		}
		if json.Unmarshal(out, &resp) == nil && (resp.Hash != "" || !resp.Exists) {
			if resp.Valid != nil && !*resp.Valid {
				return st, errors.New("OpenClaw reports its configuration as invalid, so it would refuse any change. Fix it first: openclaw config validate")
			}
			st.viaGateway, st.hash, st.path = true, resp.Hash, resp.Path
			for k, v := range resp.Config.Mcp.Servers {
				st.servers[k] = v
			}
			for k, v := range resp.Config.Agents.Entries {
				st.entries[k] = v
			}
			if st.path == "" {
				st.path = o.activeConfigPath(ctx)
			}
			return st, nil
		}
	}
	st.path = o.activeConfigPath(ctx)
	if err := o.configGet(ctx, "mcp.servers", &st.servers); err != nil {
		return st, err
	}
	if err := o.configGet(ctx, "agents.entries", &st.entries); err != nil {
		return st, err
	}
	return st, nil
}

func (o *openClaw) configGet(ctx context.Context, path string, into any) error {
	out, err := o.opts.Runner(ctx, o.bin(), "config", "get", path, "--json")
	if err != nil {
		var envelope struct {
			OK *bool `json:"ok"`
		}
		if json.Unmarshal(out, &envelope) == nil && envelope.OK != nil && !*envelope.OK {
			return nil // unset: nothing configured there yet
		}
		return fmt.Errorf("could not read %s from OpenClaw (%s config get %s): %w", path, o.bin(), path, err)
	}
	if err := json.Unmarshal(out, into); err != nil {
		return fmt.Errorf("OpenClaw answered %s config get %s with something this version cannot read", o.bin(), path)
	}
	return nil
}

// activeConfigPath asks `openclaw config file --json`, which knows profiles.
func (o *openClaw) activeConfigPath(ctx context.Context) string {
	if out, err := o.opts.Runner(ctx, o.bin(), "config", "file", "--json"); err == nil {
		var v struct {
			Path string `json:"path"`
		}
		if json.Unmarshal(out, &v) == nil && v.Path != "" {
			return v.Path
		}
	}
	return o.openClawConfigPath()
}

// ---------------------------------------------------------------------------
// Planning the one patch
// ---------------------------------------------------------------------------

type openClawPlan struct {
	servers map[string]any // server name -> entry to set
	added   []string       // subjects whose server is new or corrected
	tools   map[string]map[string][]string
	denied  map[string][]string
	allowed map[string]string
	issues  []McpIsolationIssue
	shared  bool
}

func (p openClawPlan) empty() bool { return len(p.servers) == 0 && len(p.tools) == 0 }

/*
planOpenClaw works out what is missing.

Every agent with an entry denies the servers of every connected agent but
itself, including agents that are not connected: those have no Contro1 identity
and must not borrow one. An agent with an explicit allow list also gets its own
server added to it, or the list would hide it; alsoAllow is left alone, since
OpenClaw rejects allow and alsoAllow together. Nothing already there is removed,
and a connected agent with no entry is reported rather than created.
*/
func planOpenClaw(st openClawState, subjects []string) openClawPlan {
	p := openClawPlan{servers: map[string]any{}, tools: map[string]map[string][]string{}, denied: map[string][]string{}, allowed: map[string]string{}}
	for _, s := range subjects {
		name := openClawServerName(s)
		current, ok := st.servers[name]
		have := McpServer{Name: name, Command: current.Command, Args: current.Args, URL: current.URL}
		if ok && have.ServesAgent(s) {
			continue
		}
		entry := openClawServerEntry(s)
		if current.URL != "" {
			entry["url"] = nil // a merge patch deletes with null
			entry["transport"] = nil
		}
		p.servers[name] = entry
		p.added = append(p.added, s)
	}

	ids := make([]string, 0, len(st.entries))
	for id := range st.entries {
		ids = append(ids, id)
	}
	all := sortedUnique(append(append([]string(nil), ids...), subjects...))
	_, p.shared = st.servers["contro1"]
	p.shared = p.shared && len(all) > 1
	if len(all) <= 1 {
		return p
	}
	connected := map[string]bool{}
	for _, s := range subjects {
		connected[s] = true
	}
	sort.Strings(ids)
	for _, id := range ids {
		entry := st.entries[id]
		var deny []string
		var allow *[]string
		if entry.Tools != nil {
			deny, allow = entry.Tools.Deny, entry.Tools.Allow
		}
		change := map[string][]string{}
		nextDeny := append([]string(nil), deny...)
		for _, s := range subjects {
			if s == id {
				continue
			}
			if pattern := openClawToolPattern(s); !containsString(nextDeny, pattern) {
				nextDeny = append(nextDeny, pattern)
				p.denied[id] = append(p.denied[id], pattern)
			}
		}
		if len(p.denied[id]) > 0 {
			change["deny"] = nextDeny
		}
		if connected[id] && allow != nil {
			if own := openClawToolPattern(id); !containsString(*allow, own) {
				change["allow"] = append(append([]string(nil), *allow...), own)
				p.allowed[id] = own
			}
		}
		if len(change) > 0 {
			p.tools[id] = change
		}
	}
	for _, s := range subjects {
		if _, ok := st.entries[s]; !ok {
			p.issues = append(p.issues, McpIsolationIssue{Agent: s, Exposure: true,
				Message: "Agent " + s + " has no entry under agents.entries in OpenClaw's configuration, so contro1 cannot give it tool rules, and it can use the other agents' Contro1 servers."})
		}
	}
	return p
}

func (p openClawPlan) patch() []byte {
	root := map[string]any{}
	if len(p.servers) > 0 {
		root["mcp"] = map[string]any{"servers": p.servers}
	}
	if len(p.tools) > 0 {
		entries := map[string]any{}
		for id, tools := range p.tools {
			entries[id] = map[string]any{"tools": tools}
		}
		root["agents"] = map[string]any{"entries": entries}
	}
	raw, _ := json.Marshal(root)
	return raw
}

func (p openClawPlan) describeRules() string {
	var parts []string
	for _, id := range sortedKeys(p.denied) {
		parts = append(parts, fmt.Sprintf("%s denies %s", id, strings.Join(p.denied[id], ", ")))
	}
	for _, id := range sortedKeys(p.allowed) {
		parts = append(parts, fmt.Sprintf("%s allows %s", id, p.allowed[id]))
	}
	return strings.Join(parts, "; ")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The installer
// ---------------------------------------------------------------------------

func (o *openClaw) McpChanges(ctx context.Context, subjects []string) []Change {
	subjects = sortedUnique(subjects)
	st, err := o.readState(ctx)
	if err != nil {
		return []Change{{Kind: "mcp", Description: "Set up the Contro1 MCP servers in OpenClaw. Its configuration could not be read (" + err.Error() + "), so this step will stop and print the exact change instead of writing anything"}}
	}
	p := planOpenClaw(st, subjects)
	if p.empty() {
		return nil
	}
	var changes []Change
	for _, s := range p.added {
		name := openClawServerName(s)
		entry, _ := json.Marshal(p.servers[name])
		changes = append(changes, Change{Kind: "mcp", Path: st.path,
			Description: fmt.Sprintf("Add the MCP server %s to OpenClaw, acting only as agent %s", name, s),
			After:       "mcp.servers." + name + " = " + string(entry)})
	}
	if len(p.tools) > 0 {
		changes = append(changes, Change{Kind: "file", Path: st.path,
			Description: "Give each OpenClaw agent tool rules so it sees only its own Contro1 server",
			After:       p.describeRules()})
	}
	how := Change{Kind: "file", Path: st.path,
		Description: "Written as one change with " + o.bin() + " config patch, since no OpenClaw gateway is running (openclaw.json is backed up first)"}
	if st.viaGateway {
		how.Description = "Applied as one change through the running OpenClaw gateway (" + o.bin() + " gateway call config.patch), which checks it and loads it without a restart (openclaw.json is backed up first)"
	}
	return append(changes, how)
}

func (o *openClaw) InstallMcp(ctx context.Context, subjects []string, j *Journal) (McpOutcome, error) {
	var out McpOutcome
	subjects = sortedUnique(subjects)
	st, err := o.readState(ctx)
	if err != nil {
		// Nothing can be based on a configuration nobody could read. The patch
		// without the person's own lists is still the clearest instruction.
		p := planOpenClaw(openClawState{servers: map[string]ocServer{}, entries: map[string]ocEntry{}}, subjects)
		return out, fmt.Errorf("%v. Nothing was changed. The change contro1 would make, to merge into OpenClaw's configuration with %s config patch --file <file> (keep any tools lists the agents already have): %s", err, o.bin(), p.patch())
	}
	p := planOpenClaw(st, subjects)
	for _, issue := range p.issues {
		out.ToDo = append(out.ToDo, issue.Message+" Add agents.entries."+issue.Agent+".tools.deny with the other agents' contro1-<id>__* patterns.")
	}
	if p.shared {
		out.ToDo = append(out.ToDo, "OpenClaw still has the older shared MCP server named contro1, which every agent on this gateway can use as one identity. Remove it: openclaw mcp unset contro1 (with the gateway stopped), or delete it in the Control UI. Each agent now has its own server.")
	}
	if p.empty() {
		if len(out.ToDo) == 0 {
			out.Done = append(out.Done, "OpenClaw already has a Contro1 MCP server for each agent, with its tool rules.")
		}
		return out, nil
	}
	patch := p.patch()
	if _, err := os.Stat(st.path); err == nil {
		backup, err := backupFile(st.path)
		if err != nil {
			return out, fmt.Errorf("could not back up %s, so nothing was changed: %w", st.path, err)
		}
		out.Done = append(out.Done, "Backed up OpenClaw's configuration to "+backup)
	}
	done, err := o.writePatch(ctx, st, subjects, patch, j)
	if err != nil {
		return out, fmt.Errorf("OpenClaw did not take the change (%v), so nothing was changed. The change, to apply yourself with %s config patch --file <file> once its gateway is stopped: %s", err, o.bin(), patch)
	}
	if len(p.added) > 0 {
		var names []string
		for _, s := range p.added {
			names = append(names, openClawServerName(s))
		}
		out.Done = append(out.Done, "Added the MCP servers "+strings.Join(names, ", ")+".")
	}
	if len(p.tools) > 0 {
		out.Done = append(out.Done, "Gave each agent tool rules so it sees only its own Contro1 server: "+p.describeRules()+".")
	}
	j.WrittenFiles = append(j.WrittenFiles, st.path)
	out.Done = append(out.Done, done)
	return out, nil
}

/*
writePatch sends the patch the one way OpenClaw accepts at this moment.

A gateway that answered config.get owns the configuration: config.patch, based on
the hash it returned, validates the whole result and waits until it is live. If
that call gives up while OpenClaw is still applying it (it can wait for unrelated
active work), the configuration is read again: a patch that landed is a success
that is still arriving, not a failure.
*/
func (o *openClaw) writePatch(ctx context.Context, st openClawState, subjects []string, patch []byte, j *Journal) (string, error) {
	if st.viaGateway {
		params := map[string]any{"raw": string(patch), "note": "contro1 connect: Contro1 MCP servers and per-agent tool rules"}
		if st.hash != "" {
			params["baseHash"] = st.hash
		}
		raw, _ := json.Marshal(params)
		args := []string{"gateway", "call", "config.patch", "--params", string(raw), "--json", "--timeout", "120000"}
		if _, err := o.opts.Runner(ctx, o.bin(), args...); err != nil {
			if again, rerr := o.readState(ctx); rerr == nil && planOpenClaw(again, subjects).empty() {
				j.RoleCommands = append(j.RoleCommands, o.bin()+" gateway call config.patch")
				return "OpenClaw saved the change and applies it within a few minutes.", nil
			}
			return "", err
		}
		j.RoleCommands = append(j.RoleCommands, o.bin()+" gateway call config.patch")
		return "OpenClaw checked the change and applied it live; no restart is needed.", nil
	}
	f, err := os.CreateTemp("", "contro1-openclaw-patch-*.json")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(patch); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if _, err := o.opts.Runner(ctx, o.bin(), "config", "patch", "--file", f.Name()); err != nil {
		return "", err
	}
	j.RoleCommands = append(j.RoleCommands, o.bin()+" config patch --file <contro1 patch>")
	return "Saved to OpenClaw's configuration. Its gateway is not running; it loads the servers when it starts.", nil
}

// ---------------------------------------------------------------------------
// What doctor asks
// ---------------------------------------------------------------------------

func (o *openClaw) McpServerName(subject string) string { return openClawServerName(subject) }

// McpServers reads `openclaw mcp list --json`, an object of name to definition
// (src/cli/mcp-cli.ts). It works while the gateway runs.
func (o *openClaw) McpServers(ctx context.Context) ([]McpServer, error) {
	out, err := o.opts.Runner(ctx, o.bin(), "mcp", "list", "--json")
	if err != nil {
		return nil, err
	}
	var servers map[string]ocServer
	if err := json.Unmarshal(out, &servers); err != nil {
		return nil, errors.New("openclaw mcp list --json answered something this version cannot read")
	}
	list := make([]McpServer, 0, len(servers))
	for _, name := range sortedKeys(servers) {
		s := servers[name]
		list = append(list, McpServer{Name: name, Command: s.Command, Args: s.Args, URL: s.URL})
	}
	return list, nil
}

func (o *openClaw) McpIsolation(ctx context.Context, subjects []string) ([]McpIsolationIssue, error) {
	st, err := o.readState(ctx)
	if err != nil {
		return nil, err
	}
	p := planOpenClaw(st, sortedUnique(subjects))
	issues := append([]McpIsolationIssue(nil), p.issues...)
	for _, id := range sortedKeys(p.denied) {
		issues = append(issues, McpIsolationIssue{Agent: id, Exposure: true,
			Message: fmt.Sprintf("Agent %s can use %s, which act as other agents.", id, strings.Join(p.denied[id], ", "))})
	}
	for _, id := range sortedKeys(p.allowed) {
		issues = append(issues, McpIsolationIssue{Agent: id,
			Message: fmt.Sprintf("Agent %s has a tools.allow list without %s, so it cannot use its own Contro1 server.", id, p.allowed[id])})
	}
	return issues, nil
}

/*
ConfigStatus asks `openclaw config validate --json` ({valid, error, issues};
docs/cli/config.md). A configuration OpenClaw rejects is worse than it looks:
the gateway keeps running the last good one, so every later change, the Contro1
servers included, silently does not apply.
*/
func (o *openClaw) ConfigStatus(ctx context.Context) (ConfigState, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, runErr := o.opts.Runner(ctx, o.bin(), "config", "validate", "--json")
	var resp struct {
		Valid  *bool           `json:"valid"`
		Error  json.RawMessage `json:"error"`
		Issues []struct {
			Path    string `json:"path"`
			Message string `json:"message"`
		} `json:"issues"`
	}
	if json.Unmarshal(out, &resp) != nil || resp.Valid == nil {
		if runErr != nil {
			return ConfigState{}, runErr
		}
		return ConfigState{}, errors.New("openclaw config validate --json answered something this version cannot read")
	}
	state := ConfigState{Valid: *resp.Valid}
	if !state.Valid {
		var msg struct {
			Message string `json:"message"`
		}
		var plain string
		switch {
		case len(resp.Issues) > 0:
			state.Problem = strings.TrimSpace(resp.Issues[0].Path + ": " + resp.Issues[0].Message)
		case json.Unmarshal(resp.Error, &msg) == nil && msg.Message != "":
			state.Problem = msg.Message
		case json.Unmarshal(resp.Error, &plain) == nil && plain != "":
			state.Problem = plain
		default:
			state.Problem = "see openclaw config validate"
		}
	}
	return state, nil
}
