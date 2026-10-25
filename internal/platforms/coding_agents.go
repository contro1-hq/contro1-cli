package platforms

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

/*
Cursor and Codex connect the way Claude Code does: one agent per computer, with
its own owner-approved connection, instead of a person sign-in.

WHY. Both could only reach Contro1 through `contro1 mcp login`, which acts as
the person who signed in. Every call was recorded as theirs, an approval card
could not say "Cursor" or "Codex", and nothing could be granted to the coding
agent alone. Claude Code already had the better path, and nothing in it is
specific to Claude: a terminal or editor tool on this computer, driven by
whoever sits at it, with an MCP client that runs `contro1 mcp serve`.

What differs per platform is only where its MCP server is registered
(cursor_mcp.go, codex_mcp.go). The subject is "<platform>@<machine key>", the
same stable machine id Claude Code uses (machineid.go), so a network that
renames the computer does not mint a second agent. There is no hostname-era
subject to keep: these platforms never had one.
*/
type localCodingAgent struct {
	platform string // "cursor" | "codex"
	label    string // "Cursor" | "Codex"
	opts     Options
	// Test seams; nil means this computer's own.
	hostname    func() (string, error)
	machine     *machineReaders
	mappingPath string
}

func newCursor(opts Options) *cursor {
	return &cursor{localCodingAgent{platform: "cursor", label: "Cursor", opts: opts}}
}
func newCodex(opts Options) *codex {
	return &codex{localCodingAgent{platform: "codex", label: "Codex", opts: opts}}
}

func (a *localCodingAgent) Name() string { return a.platform }

func (a *localCodingAgent) Discover(ctx context.Context) (Instance, []Subject, error) {
	hostname := a.hostname
	if hostname == nil {
		hostname = os.Hostname
	}
	host, _ := hostname()
	subject, instanceDigest := a.identity(ctx, host)
	instance := Instance{Label: a.label, Digest: instanceDigest}
	if s := explicit(a.opts.Agents); len(s) > 0 {
		return instance, s, nil
	}
	return instance, []Subject{{ID: subject, Display: a.label + " on " + firstNonEmpty(host, "this computer")}}, nil
}

/*
identity is the subject this platform on this computer connects as.

A subject already in this platform's mapping is kept when it is the only one:
the machine id can be unreadable on one run (a locked-down registry, a missing
ioreg) and readable on the next, and switching subject then would create the
duplicate agent the machine id exists to stop. Otherwise the machine-id
subject, and the hostname only when no machine id can be read at all, so
connecting never fails for want of one.
*/
func (a *localCodingAgent) identity(ctx context.Context, host string) (subject, instanceDigest string) {
	prefix := a.platform + "@"
	fallback := prefix + strings.ToLower(firstNonEmpty(host, "computer"))
	stable, stableDigest := "", ""
	readers := machineReaders{runner: a.opts.Runner}
	if a.machine != nil {
		readers = *a.machine
	}
	if id, err := readers.read(ctx); err == nil {
		key := machineKey(id)
		stable = prefix + key
		stableDigest = digest(a.platform, key)
	}
	path := a.mappingPath
	if path == "" {
		dir := a.opts.PlatformsDir
		if dir == "" {
			dir = PlatformsDir()
		}
		path = filepath.Join(dir, a.platform+".json")
	}
	if m, err := ReadMapping(path); err == nil && m.Platform == a.platform {
		for _, e := range m.Entries {
			if e.PlatformSubject == stable && stable != "" {
				return stable, firstNonEmpty(m.PlatformInstanceDigest, stableDigest)
			}
		}
		if len(m.Entries) == 1 && strings.HasPrefix(m.Entries[0].PlatformSubject, prefix) {
			return m.Entries[0].PlatformSubject, firstNonEmpty(m.PlatformInstanceDigest, stableDigest, digest(a.platform, host))
		}
	}
	if stable != "" {
		return stable, stableDigest
	}
	return fallback, digest(a.platform, host)
}

// Nothing on the platform side points at the mapping: `contro1 mcp serve`
// reads it itself, so connect changes no platform file before the MCP step.
func (a *localCodingAgent) PlanConfig(string) []Change { return nil }
func (a *localCodingAgent) ApplyConfig(context.Context, string, *runtimeproto.MappingFile, *Journal) error {
	return nil
}
func (a *localCodingAgent) RemoveConfig(_ context.Context, j *Journal) error {
	return removeCreated(j)
}
func (a *localCodingAgent) RoleChanges(*runtimeproto.MappingFile) []Change { return nil }
func (a *localCodingAgent) ApplyRoles(context.Context, *runtimeproto.MappingFile, *Journal) error {
	return nil
}
func (a *localCodingAgent) AllowedPrincipal(string) (string, error) {
	return currentPrincipal(a.opts.Principal)
}

// Reach is the local host, as for Claude Code: an editor or terminal tool
// driven by whoever is at this computer, with no channel anyone else can
// message. Cursor's background agents run in Cursor's cloud and never reach
// this computer's endpoint, so they do not widen it.
func (a *localCodingAgent) Reach(_ context.Context, _ string) (runtimeproto.AgentReach, error) {
	principal, _ := a.AllowedPrincipal("")
	return localHostReach(a.platform, principal), nil
}

/*
RemainingSetup is empty: once the MCP server is registered, which connect
does, the agent asks for approval and uses applications through Contro1. What
connect cannot do (no cursor/codex command on this computer, a config file it
will not edit) is said by the MCP step itself, with the exact block to paste.
*/
func (a *localCodingAgent) RemainingSetup() []string { return nil }

func (a *localCodingAgent) mcpConfigDir(defaultDir string) string {
	if a.opts.ConfigDir != "" {
		return a.opts.ConfigDir
	}
	return defaultDir
}

// ---------------------------------------------------------------------------
// The two platforms. Their MCP registration is in cursor_mcp.go and codex_mcp.go.
// ---------------------------------------------------------------------------

type cursor struct{ localCodingAgent }

func (c *cursor) SafeTest() string {
	return "Try it: open a new Cursor agent chat and ask it to call the Contro1 whoami tool. It answers with this agent's name."
}

func (c *cursor) ApplicationChanges(conn LocalConnection) []Change {
	return c.McpChanges(context.Background(), []string{conn.PlatformSubject})
}

func (c *cursor) ApplyApplications(ctx context.Context, conn LocalConnection, j *Journal) error {
	_, err := c.InstallMcp(ctx, []string{conn.PlatformSubject}, j)
	return err
}

type codex struct{ localCodingAgent }

func (c *codex) SafeTest() string {
	return "Try it: start a new Codex session and ask it to call the Contro1 whoami tool. It answers with this agent's name. To stop deploy commands for approval as well, add the contro1 hooks codex hook: https://contro1.com/docs/connect-an-agent/codex#codex-hooks"
}

func (c *codex) ApplicationChanges(conn LocalConnection) []Change {
	return c.McpChanges(context.Background(), []string{conn.PlatformSubject})
}

func (c *codex) ApplyApplications(ctx context.Context, conn LocalConnection, j *Journal) error {
	_, err := c.InstallMcp(ctx, []string{conn.PlatformSubject}, j)
	return err
}
