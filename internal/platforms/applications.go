package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

/*
Reaching company applications is a second, smaller setup than connecting.

Connecting an agent gives it a way to ask people for approval. Using a mailbox
is a different thing, and on every platform it needs the same pieces in the same
order:

  1. the owner allows applications for that connection, in Contro1. Only they
     can decide it and it does not happen here
  2. the Contro1 MCP server is pointed at THAT agent's endpoint
  3. whatever the platform needs so the server can actually reach it

Step 3 is where this goes wrong in practice. On NanoClaw the MCP server runs
inside the agent's container, where neither the contro1 binary nor the agent's
socket exists unless they are mounted, and the failure is quiet: the server
starts, finds nothing, and the agent reports that it is connected while every
call comes back 401. Somebody then spends an afternoon looking for a wrong URL.
*/

// contro1BinaryPath is the binary a platform should run. Resolved rather than
// assumed, because a container mount needs a real path and "contro1" on the
// host PATH is not one.
func contro1BinaryPath() string {
	if p, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return resolved
		}
		return p
	}
	if p, err := exec.LookPath("contro1"); err == nil {
		return p
	}
	return "contro1"
}

// mcpArgs is the one argument list, in one place. `serve` finds the endpoint
// itself from the mapping file, and the agent is named so a host with several
// connections can never serve the wrong identity.
func mcpArgs(subject string) []string {
	return []string{"mcp", "serve", "--agent", subject}
}

func mcpArgsJSON(subject string) string {
	raw, _ := json.Marshal(mcpArgs(subject))
	return string(raw)
}

// ---------------------------------------------------------------------------
// NanoClaw
// ---------------------------------------------------------------------------

/*
NANOCLAW REACHES CONTRO1 OVER HTTPS, NOT OVER THE LOCAL SOCKET.

This was built the other way round first, mounting the agent's socket and the
contro1 binary into its container, and it cannot work. NanoClaw's mount rules
rewrite every container path under a fixed prefix, reject absolute ones, and
have no way to ask for read-write: `ncl groups config add-mount` can set
readonly true and never false. A unix socket mounted read-only cannot be
connected to, so the socket could never have crossed that boundary.

What the container can do is reach the public API, which is how the older
setup was configured before this: `type: http` pointing at the MCP endpoint.
That shape was right. What it lacked was a credential, which is why every call
came back 401 while the agent reported itself connected.

So the container is given a bounded bearer lease for this agent's own
connection, in a header. It is issued by the accountable owner, it expires, it
can be revoked, and the audit record says a key-bound connection lent it. No
mounts, no allowlist, no socket leaving the host.
*/
func (n *nanoClaw) ApplicationChanges(conn LocalConnection) []Change {
	return []Change{
		{
			Kind:        "credential",
			Description: "Issue this agent a bounded credential for its container, which cannot hold its connection's key",
			After:       "contro1 issues a lease for " + conn.AgentID + " (expires, and can be revoked at any time)",
		},
		{
			Kind:        "mcp",
			Description: "Point the agent's Contro1 MCP server at Contro1, as itself. Replaces any earlier entry, including one with no credential",
			After:       fmt.Sprintf("%s groups config add-mcp-server --id %s --name contro1 --url <api>/api/centcom/mcp --headers <credential>", n.bin(), conn.PlatformSubject),
		},
		{
			Kind:        "restart",
			Description: "Restart the agent group so the server is loaded",
			After:       fmt.Sprintf("%s groups restart --id %s", n.bin(), conn.PlatformSubject),
		},
	}
}

// ApplyApplications needs the lease, so the caller issues it and passes it in.
// It is never logged, never written to a file by this process, and reaches ncl
// as one argument that ncl stores in the group's own config.
func (n *nanoClaw) ApplyApplications(ctx context.Context, conn LocalConnection, j *Journal) error {
	return errors.New("nanoclaw needs a credential for its container: use ApplyApplicationsWithCredential")
}

func (n *nanoClaw) ApplyApplicationsWithCredential(ctx context.Context, conn LocalConnection, mcpURL, lease string, j *Journal) error {
	if lease == "" {
		return errors.New("no credential was issued for this agent")
	}
	headers, err := json.Marshal(map[string]string{"Authorization": "Bearer " + lease})
	if err != nil {
		return err
	}

	steps := [][]string{
		// Removed first, so an earlier entry cannot survive beside the new one.
		{"groups", "config", "remove-mcp-server", "--id", conn.PlatformSubject, "--name", "contro1"},
		{"groups", "config", "add-mcp-server", "--id", conn.PlatformSubject, "--name", "contro1", "--url", mcpURL, "--headers", string(headers)},
		{"groups", "restart", "--id", conn.PlatformSubject},
	}
	for _, args := range steps {
		if _, err := n.opts.Runner(ctx, n.bin(), args...); err != nil {
			// Removing an entry that was never there is the ordinary first run.
			if len(args) > 2 && args[2] == "remove-mcp-server" {
				continue
			}
			// The lease is in one of these arguments, so the command is not
			// echoed back in the error.
			return fmt.Errorf("%s %s failed for %s: %w", n.bin(), strings.Join(args[:3], " "), conn.PlatformSubject, err)
		}
		j.RoleCommands = append(j.RoleCommands, n.bin()+" "+strings.Join(args[:3], " ")+" --id "+conn.PlatformSubject)
	}
	return nil
}

// ---------------------------------------------------------------------------
// OpenClaw and Claude Code
// ---------------------------------------------------------------------------

// OpenClaw runs its MCP servers in the gateway process, on this host, where the
// binary and the socket already are, so nothing is mounted. The entry is shown
// rather than written: this tool does not rewrite a config file it did not
// create, and openclaw.json is the person's.
func (o *openClaw) ApplicationChanges(conn LocalConnection) []Change {
	return []Change{{
		Kind:        "mcp",
		Path:        filepath.Join(o.opts.Home, ".openclaw", "openclaw.json"),
		Description: "Add the Contro1 MCP server to OpenClaw, pointed at this agent",
		After:       fmt.Sprintf("\"contro1\": {\"command\": \"contro1\", \"args\": %s}", mcpArgsJSON(conn.PlatformSubject)),
	}}
}

func (o *openClaw) ApplyApplications(context.Context, LocalConnection, *Journal) error {
	return fmt.Errorf("add the entry shown above to openclaw.json yourself: this tool does not rewrite a config file it did not create")
}

func (c *claudeCode) ApplicationChanges(conn LocalConnection) []Change {
	return []Change{{
		Kind:        "mcp",
		Description: "Register the Contro1 MCP server with Claude Code",
		After:       "claude mcp add contro1 -- contro1 " + strings.Join(mcpArgs(conn.PlatformSubject), " "),
	}}
}

func (c *claudeCode) ApplyApplications(ctx context.Context, conn LocalConnection, j *Journal) error {
	args := append([]string{"mcp", "add", "contro1", "--", "contro1"}, mcpArgs(conn.PlatformSubject)...)
	if _, err := c.opts.Runner(ctx, "claude", args...); err != nil {
		return fmt.Errorf("claude mcp add: %w", err)
	}
	j.RoleCommands = append(j.RoleCommands, "claude "+strings.Join(args, " "))
	return nil
}

// ---------------------------------------------------------------------------
// What connecting does not finish
// ---------------------------------------------------------------------------

/*
NanoClaw needs Contro1 installed into it before any approval is routed.

This is not automated here, and the choice is deliberate. Two of these steps
write TypeScript into NanoClaw's own source tree and one edits how NanoClaw
delivers approvals. That is the person's code, and a tool that reaches into it
from a release of a different project is a tool nobody can reason about when
something later breaks. Naming the steps at the moment they become relevant is
worth more than doing them invisibly.
*/
func (n *nanoClaw) RemainingSetup() []string {
	return []string{
		"Install the Contro1 channel into NanoClaw: copy contro1.ts and contro1-governance.ts into src/channels/ and add the import. See skills/add-contro1 in the connector.",
		"Make approval cards prefer Contro1, so a card raised in WhatsApp still comes here (step 4 of that skill).",
		"Build and restart NanoClaw.",
		"Make Contro1 an approver: contro1 connect nanoclaw --confirm-roles",
		"Check it: contro1 doctor nanoclaw",
	}
}

// The OpenClaw bridge is the approver by being deployed; nothing is installed
// into OpenClaw itself.
func (o *openClaw) RemainingSetup() []string { return nil }

// Claude Code is governed by the hook the connector installs, not by a channel.
func (c *claudeCode) RemainingSetup() []string { return nil }
