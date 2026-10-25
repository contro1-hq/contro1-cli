package platforms

import (
	"context"
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

// ---------------------------------------------------------------------------
// NanoClaw
// ---------------------------------------------------------------------------

/*
NANOCLAW GETS A URL AND NOTHING ELSE, WHICH IS HOW A REMOTE MCP SERVER WORKS.

This was built twice the wrong way before landing on the way it already worked.

First by mounting the agent's socket into its container. That cannot work:
NanoClaw rewrites every container path under a fixed prefix, rejects absolute
ones, and `ncl groups config add-mount` can set readonly true and never false,
so a unix socket can never be connected to through it.

Then by putting a bearer lease in the server's headers. That works and it is
wrong, which is worse. Anything stored in the group's config is readable by the
agent in that group: `ncl groups config get` returns it in full. An agent that
several people can instruct could be asked to read out the credential that IS
its identity, and whoever received it would then be that agent from anywhere.
The whole point of holding keys off the agent is lost the moment one is written
where it can read it back.

The Contro1 MCP server is configured here with a URL and no credential. NanoClaw
passes that URL to the Claude Agent SDK, but this path does not complete the
server's OAuth challenge or persist an MCP token. A 401 therefore means the
host gateway has not yet been provisioned; it is not evidence that NanoClaw
will finish authorization automatically. A credential must be held outside the
agent container and granted only to this NanoClaw agent in OneCLI.
*/
func (n *nanoClaw) ApplicationChanges(conn LocalConnection) []Change {
	return []Change{
		{
			Kind:        "mcp",
			Description: "Point the agent's Contro1 MCP server at Contro1. A URL and nothing else: no credential is written where the agent could read it back",
			After:       fmt.Sprintf("%s groups config add-mcp-server --id %s --name contro1 --url <api>/api/centcom/mcp", n.bin(), conn.PlatformSubject),
		},
		{
			Kind:        "restart",
			Description: "Restart the agent group so the server is loaded",
			After:       fmt.Sprintf("%s groups restart --id %s", n.bin(), conn.PlatformSubject),
		},
	}
}

func (n *nanoClaw) ApplyApplications(ctx context.Context, conn LocalConnection, j *Journal) error {
	url := n.opts.McpURL
	if url == "" {
		return errors.New("no Contro1 MCP address was resolved for this platform")
	}
	steps := [][]string{
		// Removed first, so an earlier entry cannot survive beside the new one.
		// That includes one carrying a credential, which must not be left behind.
		{"groups", "config", "remove-mcp-server", "--id", conn.PlatformSubject, "--name", "contro1"},
		{"groups", "config", "add-mcp-server", "--id", conn.PlatformSubject, "--name", "contro1", "--url", url},
		{"groups", "restart", "--id", conn.PlatformSubject},
	}
	for _, args := range steps {
		if _, err := n.opts.Runner(ctx, n.bin(), args...); err != nil {
			// Removing an entry that was never there is the ordinary first run.
			if len(args) > 2 && args[2] == "remove-mcp-server" {
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
// binary and the socket already are, so nothing is mounted. `apps enable` runs
// the same step as connect: one server per agent and the tool rules between
// them, which is why it covers every connected OpenClaw agent and not only the
// one it was asked about.
func (o *openClaw) ApplicationChanges(conn LocalConnection) []Change {
	return o.McpChanges(context.Background(), McpSubjects("openclaw", conn.PlatformSubject))
}

func (o *openClaw) ApplyApplications(ctx context.Context, conn LocalConnection, j *Journal) error {
	_, err := o.InstallMcp(ctx, McpSubjects("openclaw", conn.PlatformSubject), j)
	return err
}

func (c *claudeCode) ApplicationChanges(conn LocalConnection) []Change {
	return c.McpChanges(context.Background(), []string{conn.PlatformSubject})
}

func (c *claudeCode) ApplyApplications(ctx context.Context, conn LocalConnection, j *Journal) error {
	_, err := c.InstallMcp(ctx, []string{conn.PlatformSubject}, j)
	return err
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

/*
OpenClaw only sends Contro1 what it stops for, and connecting changes neither.

The bridge is the approver by being deployed, and nothing is installed into
OpenClaw itself, so connect cannot tell whether OpenClaw will ever stop. Its
exec tool may be off (the assistant then says it cannot run commands at all),
or on without asking. Saying "connected, try it" here sent people to a test
that could not work.
*/
func (o *openClaw) RemainingSetup() []string {
	return []string{
		// The preset sets security allowlist, ask on-miss and askFallback deny
		// together (OpenClaw docs/cli/approvals.md, src/cli/exec-policy-cli.ts).
		// `config set tools.exec.mode` refuses while a gateway owns the state.
		"Make commands outside the allowlist stop for approval, and refuse when nobody answers: openclaw exec-policy preset cautious",
		// An agent whose tool profile excludes terminal tools answers "I cannot
		// run commands"; show names the exact alsoAllow entry that fixes it.
		"Check each assistant can run commands at all: openclaw exec-policy show --agent <agent id>",
		"Start the Contro1 bridge for OpenClaw on this computer. It hands those approvals to Contro1: https://contro1.com/docs/connect-an-agent/personal-agents#openclaw",
		"Check it: contro1 doctor openclaw",
		`Then ask your assistant to run "touch ~/contro1-test.txt". Contro1 asks you to approve it first.`,
	}
}

/*
Claude Code needs one thing connecting does not install: the approval hook,
which nothing on the computer wires up. The end of `contro1 connect claude-code`
used to say "Try it" without it. The MCP server used to be the second item here;
connect installs it now, as its last step, so it is no longer the person's.
Named only while it is missing, so a computer that has the hook hears "Try it"
and nothing else.
*/
func (c *claudeCode) RemainingSetup() []string {
	if c.hookInstalled() {
		return nil
	}
	return []string{
		"Approvals for risky commands: npm install -g @contro1/claude-code, then add its PreToolUse hook to ~/.claude/settings.json: https://contro1.com/docs/connect-an-agent/claude-code#claude-code",
		"Check it: contro1 doctor claude-code",
	}
}

// hookInstalled reads the user's Claude Code settings for the Contro1 hook.
func (c *claudeCode) hookInstalled() bool {
	raw, err := os.ReadFile(filepath.Join(c.opts.Home, ".claude", "settings.json"))
	return err == nil && strings.Contains(string(raw), "centcom-claude-code")
}
