package platforms

import (
	"context"
	"encoding/json"
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

func (n *nanoClaw) ApplicationChanges(conn LocalConnection) []Change {
	socket := strings.TrimPrefix(conn.Endpoint, "unix://")
	binary := contro1BinaryPath()
	return []Change{
		{
			Kind:        "mount",
			Path:        socket,
			Description: "Mount this agent's own Contro1 socket into its container, and only this one, so the group can act as itself and as nothing else",
			After:       fmt.Sprintf("%s config add-mount --id %s --host %s --container %s", n.bin(), conn.PlatformSubject, socket, socket),
		},
		{
			Kind:        "mount",
			Path:        binary,
			Description: "Mount the contro1 binary into the container, read only. It carries no credential; the local Contro1 service holds the key",
			After:       fmt.Sprintf("%s config add-mount --id %s --host %s --container /usr/local/bin/contro1 --ro", n.bin(), conn.PlatformSubject, binary),
		},
		{
			Kind:        "mcp",
			Description: "Point the agent's Contro1 MCP server at its own connection. Replaces any earlier entry, including one holding an API key",
			After:       fmt.Sprintf("%s config add-mcp-server --id %s --name contro1 --command contro1 --args %s", n.bin(), conn.PlatformSubject, mcpArgsJSON(conn.PlatformSubject)),
		},
		{
			Kind:        "restart",
			Description: "Restart the agent group so the mounts and the server take effect",
			After:       fmt.Sprintf("%s groups restart --id %s", n.bin(), conn.PlatformSubject),
		},
	}
}

func (n *nanoClaw) ApplyApplications(ctx context.Context, conn LocalConnection, j *Journal) error {
	socket := strings.TrimPrefix(conn.Endpoint, "unix://")
	binary := contro1BinaryPath()
	// Checked before anything is changed: mounting a path that is not there
	// produces a container that starts and fails at the first call, which is
	// the exact silent mode this whole command exists to remove.
	if _, err := os.Stat(socket); err != nil {
		return fmt.Errorf("this agent's endpoint %s is not there; is the Contro1 service running? (contro1 doctor nanoclaw)", socket)
	}

	steps := [][]string{
		{"config", "add-mount", "--id", conn.PlatformSubject, "--host", socket, "--container", socket},
		{"config", "add-mount", "--id", conn.PlatformSubject, "--host", binary, "--container", "/usr/local/bin/contro1", "--ro"},
		// Removed first, so an earlier entry cannot survive beside the new one.
		{"config", "remove-mcp-server", "--id", conn.PlatformSubject, "--name", "contro1"},
		{"config", "add-mcp-server", "--id", conn.PlatformSubject, "--name", "contro1", "--command", "contro1", "--args", mcpArgsJSON(conn.PlatformSubject)},
		{"groups", "restart", "--id", conn.PlatformSubject},
	}
	for _, args := range steps {
		if _, err := n.opts.Runner(ctx, n.bin(), args...); err != nil {
			// Removing an entry that was never there is the ordinary first run.
			if args[1] == "remove-mcp-server" {
				continue
			}
			return fmt.Errorf("%s %s: %w", n.bin(), strings.Join(args, " "), err)
		}
		j.RoleCommands = append(j.RoleCommands, n.bin()+" "+strings.Join(args, " "))
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
