package platforms

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

/*
`contro1 connect` installs the Contro1 MCP server itself, as its last step.

WHY. The MCP server used to be a second command in a different part of the docs,
with different syntax per platform, and a person who connected an agent was
never told about it. One customer found the OpenClaw form (`--arg` per word)
only by asking Claude Code, and then had to write per-agent tool rules by hand
so that two of her three agents would not act as the third. Everything that
step needs is known by the end of connect: the agents, their ids, the binary.
So connect does it, shown in the same preview and confirmed the same way.

Two platforms implement this. NanoClaw's MCP step needs an owner-approved lease
held in OneCLI, which lives with `apps enable`, and connect runs those steps as
they are.
*/

// McpInstaller is a platform where connect installs the Contro1 MCP server.
type McpInstaller interface {
	// McpChanges previews the MCP step for these platform subjects. It may read
	// the platform's configuration and never writes. Empty when nothing would
	// change, so a second run previews nothing.
	McpChanges(ctx context.Context, subjects []string) []Change
	// InstallMcp performs it. Idempotent: what is already right is left alone.
	InstallMcp(ctx context.Context, subjects []string, j *Journal) (McpOutcome, error)
}

// McpOutcome is what the MCP step did and what it could not do for the person.
type McpOutcome struct {
	// Done is said as progress.
	Done []string
	// ToDo is still the person's, named at the end of connect like any other
	// unfinished step.
	ToDo []string
}

// McpInspector is what doctor asks a platform about its Contro1 MCP servers.
type McpInspector interface {
	// McpServerName is the server name connect gives this subject.
	McpServerName(subject string) string
	// McpServers lists the configured MCP servers as the platform has them.
	McpServers(ctx context.Context) ([]McpServer, error)
	// McpIsolation names each way an agent could reach another agent's Contro1
	// tools, or lost its own. Empty is isolated; ErrNotReported is a platform
	// with nothing to isolate.
	McpIsolation(ctx context.Context, subjects []string) ([]McpIsolationIssue, error)
	// ConfigStatus reports whether the platform accepts its own configuration.
	// ErrNotReported on a platform with nothing to check.
	ConfigStatus(ctx context.Context) (ConfigState, error)
}

// ConfigState is the platform's own verdict on its configuration.
type ConfigState struct {
	Valid   bool
	Problem string
}

// McpIsolationIssue is one agent whose tool rules are not what connect writes.
type McpIsolationIssue struct {
	Agent   string
	Message string
	// Exposure is an agent that can act as another one. The others are an
	// agent that cannot reach its own server, which is broken but not a leak.
	Exposure bool
}

// ErrNotReported means the platform has no answer to give, which is not a
// finding.
var ErrNotReported = errors.New("not reported by this platform")

// McpServer is one configured MCP server.
type McpServer struct {
	Name    string
	Command string
	Args    []string
	URL     string
	// Scope is where the platform keeps it, when it says (Claude Code: user,
	// local or project).
	Scope string
}

// ServesAgent is true when the entry runs `contro1 mcp serve --agent <subject>`.
// The path to contro1 is not compared: /usr/local/bin/contro1 and the resolved
// Homebrew path are the same program.
func (s McpServer) ServesAgent(subject string) bool {
	if s.URL != "" || !isContro1Command(s.Command) {
		return false
	}
	return argsServe(s.Args, subject)
}

// Describe is the entry in one line, for a person comparing it with what it
// should be.
func (s McpServer) Describe() string {
	if s.URL != "" {
		return s.URL
	}
	return strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
}

func isContro1Command(command string) bool {
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(command, `\`, "/")))
	return strings.TrimSuffix(base, ".exe") == "contro1"
}

func argsServe(args []string, subject string) bool {
	hasServe := false
	for i, a := range args {
		if a == "serve" && i > 0 && args[i-1] == "mcp" {
			hasServe = true
		}
	}
	if !hasServe {
		return false
	}
	for i, a := range args {
		if a == "--agent="+subject || (a == "--agent" && i+1 < len(args) && args[i+1] == subject) {
			return true
		}
	}
	return false
}

// Overridable in tests.
var (
	contro1Binary = contro1BinaryPath
	nowFunc       = time.Now
)

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// McpSubjects is who the MCP step covers when `apps enable` names one agent.
// OpenClaw's tool rules are about every agent on the gateway, so all of its
// connected agents are included; elsewhere it is the one agent.
func McpSubjects(platform, subject string) []string {
	if platform != "openclaw" {
		return []string{subject}
	}
	subjects := []string{subject}
	connections, _ := LocalConnections()
	for _, c := range connections {
		if c.Platform == platform {
			subjects = append(subjects, c.PlatformSubject)
		}
	}
	return sortedUnique(subjects)
}

// ---------------------------------------------------------------------------
// Claude Code
// ---------------------------------------------------------------------------

const claudeMcpName = "contro1"

func claudeMcpAddArgs(subject string) []string {
	// User scope: the default is the folder the command ran in, so Claude Code
	// opened anywhere else had no Contro1 at all.
	return append([]string{"mcp", "add", "--scope", "user", claudeMcpName, "--", "contro1"}, mcpArgs(subject)...)
}

// errNoClaude is a computer where the claude command cannot be found from
// here. Not a failure of connect: the person runs one line themselves.
var errNoClaude = errors.New("the claude command is not on this computer's PATH")

// claudeManualAdd is the exact line for that person, with the absolute path to
// this contro1 so it works whatever PATH their shell has.
func claudeManualAdd(subject string) string {
	return "claude mcp add --scope user contro1 -- " + contro1Binary() + " " + strings.Join(mcpArgs(subject), " ")
}

// registeredMcp asks Claude Code itself, which knows every scope it reads and
// reports the one that wins (local, then project, then user). A non-zero exit
// is "no server by that name".
func (c *claudeCode) registeredMcp(ctx context.Context) (McpServer, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := c.opts.Runner(ctx, "claude", "mcp", "get", claudeMcpName)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return McpServer{}, false, errNoClaude
		}
		return McpServer{}, false, nil
	}
	return parseClaudeMcpGet(out), true, nil
}

/*
parseClaudeMcpGet reads `claude mcp get`, which is written for people:

	contro1:
	  Scope: User config (available in all your projects)
	  Type: stdio
	  Command: contro1
	  Args: mcp serve --agent claude-code@mac

Scope is the first word of its line (User, Local or Project). When the labels
are not there, the first word that is the contro1 binary starts the command
line, so a reworded output still compares.
*/
func parseClaudeMcpGet(out []byte) McpServer {
	s := McpServer{Name: claudeMcpName}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "scope":
			if fields := strings.Fields(value); len(fields) > 0 {
				s.Scope = strings.ToLower(fields[0])
			}
		case "command":
			s.Command = value
		case "args":
			s.Args = strings.Fields(value)
		case "url":
			s.URL = value
		}
	}
	if s.Command == "" && s.URL == "" {
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if isContro1Command(f) {
				s.Command, s.Args = f, fields[i+1:]
				break
			}
		}
	}
	return s
}

/*
claudeEntry is what the registered server means for this agent.

An entry without --agent is how our docs used to show it (`claude mcp add
contro1 -- contro1 mcp serve`, local scope). It still acts as this agent while
this agent is the only connection on the computer, because `mcp serve` then has
nobody else to pick. In local or project scope that entry is the person's and
works, so it is left alone: adding a user-scope one beside it would never
converge, because `claude mcp get` keeps reporting the local one.
*/
type claudeEntry struct {
	server McpServer
	found  bool
	serves bool // acts as this agent
	pinned bool // names it with --agent
	ours   bool // user scope, where connect writes
}

func (c *claudeCode) entryFor(ctx context.Context, subject string) (claudeEntry, error) {
	current, found, err := c.registeredMcp(ctx)
	e := claudeEntry{server: current, found: found}
	if err != nil || !found {
		return e, err
	}
	e.ours = current.Scope == "" || current.Scope == "user"
	e.pinned = current.ServesAgent(subject)
	e.serves = ClaudeServesAgent(current, subject)
	return e, nil
}

// ClaudeServesAgent is ServesAgent as Claude Code sees it: an entry without
// --agent counts while this agent is the only connection here.
func ClaudeServesAgent(s McpServer, subject string) bool {
	if s.ServesAgent(subject) {
		return true
	}
	if s.URL != "" || !isContro1Command(s.Command) || hasAgentFlag(s.Args) {
		return false
	}
	return argsServe(append(append([]string(nil), s.Args...), "--agent", subject), subject) && onlyConnectionIs(subject)
}

func hasAgentFlag(args []string) bool {
	for _, a := range args {
		if a == "--agent" || strings.HasPrefix(a, "--agent=") {
			return true
		}
	}
	return false
}

// onlyConnectionIs: every connection on this computer is this subject, which
// is when an unpinned `mcp serve` resolves to it. None yet counts: connect is
// creating it now.
func onlyConnectionIs(subject string) bool {
	connections, _ := LocalConnections()
	for _, c := range connections {
		if c.PlatformSubject != subject {
			return false
		}
	}
	return true
}

func scopeOr(scope string) string {
	if scope == "" {
		return "user"
	}
	return scope
}

func (c *claudeCode) McpChanges(ctx context.Context, subjects []string) []Change {
	subjects = sortedUnique(subjects)
	if len(subjects) != 1 {
		return nil
	}
	subject := subjects[0]
	e, err := c.entryFor(ctx, subject)
	if errors.Is(err, errNoClaude) {
		return []Change{{Kind: "mcp", Description: "Claude Code's claude command was not found from here, so connect names the one line to run instead: " + claudeManualAdd(subject)}}
	}
	if e.found && (e.pinned || (e.serves && !e.ours)) {
		return nil
	}
	change := Change{
		Kind:        "mcp",
		Description: "Register the Contro1 MCP server with Claude Code, for every folder",
		After:       "claude " + strings.Join(claudeMcpAddArgs(subject), " "),
	}
	switch {
	case e.found && e.server.Scope == "project":
		change.Description = "Claude Code uses a Contro1 MCP server from this project's .mcp.json; it is shared with the project, so connect leaves it and names the fix"
		change.Before = e.server.Describe()
		change.After = ""
	case e.found:
		// Never replaced silently: the person sees what is there now, and
		// their confirmation (or --yes) is what allows the replacement.
		change.Description = "Replace Claude Code's Contro1 MCP server (" + scopeOr(e.server.Scope) + " scope) with one that acts as this agent"
		change.Before = e.server.Describe()
		change.After = "claude mcp remove --scope " + scopeOr(e.server.Scope) + " contro1, then " + change.After
	}
	return []Change{change}
}

func (c *claudeCode) InstallMcp(ctx context.Context, subjects []string, j *Journal) (McpOutcome, error) {
	var out McpOutcome
	subjects = sortedUnique(subjects)
	if len(subjects) != 1 {
		// One server named contro1 per computer. Picking one would make Claude
		// Code act as an agent nobody chose.
		out.ToDo = append(out.ToDo, "Claude Code has one Contro1 MCP server per computer. Choose the agent it acts as: contro1 apps enable claude-code --agent <id>")
		return out, nil
	}
	subject := subjects[0]
	e, err := c.entryFor(ctx, subject)
	if errors.Is(err, errNoClaude) {
		// v0.2.27 finished here with success, and it still does: the agent is
		// connected, and the MCP server is one line the person runs.
		out.ToDo = append(out.ToDo, "Let Claude Code use Contro1 (the MCP server). The claude command was not found from here, so run it yourself: "+claudeManualAdd(subject))
		return out, nil
	}
	if err != nil {
		return out, err
	}
	switch {
	case e.found && e.pinned:
		out.Done = append(out.Done, "Claude Code already has the Contro1 MCP server for this agent.")
		return out, nil
	case e.found && e.serves && !e.ours:
		out.Done = append(out.Done, "Claude Code already uses the Contro1 MCP server from its "+e.server.Scope+" config. It names no agent, so it stops working if this computer connects a second one; to pin it: claude mcp remove --scope "+e.server.Scope+" contro1, then run contro1 connect claude-code again.")
		return out, nil
	case e.found && e.server.Scope == "project":
		out.ToDo = append(out.ToDo, "Claude Code uses a Contro1 MCP server from this project's .mcp.json that runs "+e.server.Describe()+", which is not this agent. It is shared with the project, so contro1 does not change it: remove contro1 from .mcp.json, then run contro1 connect claude-code again.")
		return out, nil
	case e.found:
		// Replaced, not added beside: claude refuses a second server with the
		// same name, and an entry for another identity must not survive.
		scope := scopeOr(e.server.Scope)
		args := []string{"mcp", "remove", "--scope", scope, claudeMcpName}
		if _, err := c.opts.Runner(ctx, "claude", args...); err != nil {
			return out, fmt.Errorf("could not remove Claude Code's current Contro1 MCP server (%s scope, runs %s): claude %s: %v. Remove it yourself, then run contro1 connect claude-code again", scope, e.server.Describe(), strings.Join(args, " "), err)
		}
		j.RoleCommands = append(j.RoleCommands, "claude "+strings.Join(args, " "))
	}
	args := claudeMcpAddArgs(subject)
	if _, err := c.opts.Runner(ctx, "claude", args...); err != nil {
		return out, fmt.Errorf("claude mcp add: %w", err)
	}
	j.RoleCommands = append(j.RoleCommands, "claude "+strings.Join(args, " "))
	out.Done = append(out.Done, "Registered the Contro1 MCP server with Claude Code. New sessions load it; a session already open needs a restart.")
	return out, nil
}

func (c *claudeCode) McpServerName(string) string { return claudeMcpName }

func (c *claudeCode) McpServers(ctx context.Context) ([]McpServer, error) {
	current, found, err := c.registeredMcp(ctx)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return []McpServer{current}, nil
}

// One agent per computer: there is nobody to be isolated from.
func (c *claudeCode) McpIsolation(context.Context, []string) ([]McpIsolationIssue, error) {
	return nil, ErrNotReported
}

func (c *claudeCode) ConfigStatus(context.Context) (ConfigState, error) {
	return ConfigState{}, ErrNotReported
}

// backupFile copies a file next to itself before contro1 changes it. Never
// journaled as created: disconnect must not delete the person's only copy.
func backupFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	backup := path + ".bak-contro1-" + nowFunc().Format("20060102-150405")
	if err := os.WriteFile(backup, raw, 0o600); err != nil {
		return "", err
	}
	return backup, nil
}
