# contro1 CLI

The official developer CLI for connecting **AI agents** to Contro1.

Use `contro1` to register agents, create human approval requests, attribute actions
to an agent, update AI inventory, and retrieve audit-ready evidence from the
terminal, scripts, or CI. For coding agents and developer workflows, the CLI can
also put approval in front of a local command before it runs.

> v1 is broad around a *safe workflow*, not admin power. A CLI token can do the
> developer/agent workflow but **cannot** perform destructive org administration
> (no user/role/department management, no secret rotation, no integration installs).

## Install

One line, no build step (downloads the latest prebuilt binary):

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/contro1-hq/contro1-cli/main/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/contro1-hq/contro1-cli/main/install.ps1 | iex
```

Or download an archive for your OS from the [Releases page](https://github.com/contro1-hq/contro1-cli/releases/latest) and put `contro1` on your PATH.

From source (Go 1.22+):

```bash
git clone https://github.com/contro1-hq/contro1-cli.git
cd contro1-cli && go build -o contro1 .
```

Maintainers cut releases by pushing a tag (`git tag v0.1.0 && git push origin v0.1.0`); GoReleaser builds the cross-platform binaries (`.goreleaser.yaml`, `.github/workflows/release.yml`).

## Quick start

```bash
contro1 auth login                 # opens the browser to approve (defaults to api.contro1.com)
contro1 whoami

contro1 agents register --name "Claude Code - Laptop" --type coding-agent
contro1 requests create \
  --type approval \
  --question "Approve sending this customer email?" \
  --agent agt_123 \
  --wait

contro1 evidence for-request <request_id>
```

The CLI defaults to the hosted Contro1 (`https://api.contro1.com` / `https://contro1.com`),
so no configuration is needed. To point at a local stack or a self-hosted instance:

```bash
contro1 config set api-url http://localhost:8080
contro1 config set web-url http://localhost:3000
```

## What the CLI is for

The CLI is the fastest way to try and integrate Contro1 before writing a full
SDK/API integration.

1. Connect AI agents to Contro1 quickly: register the agent, attribute approval
   requests to it, and inspect the resulting evidence.
2. Test agent workflows manually: identity, approval request, human decision,
   evidence packet, and trace lookup.
3. Use scripts or CI when they are the right delivery channel. `contro1 run` is
   useful for coding agents and deployment steps, but command gating is one
   capability inside the broader agent workflow.

## Authentication

`contro1 auth login` runs a loopback + PKCE browser flow:

1. The CLI starts a local server and opens `WEB_URL/cli/authorize` with a PKCE challenge.
2. You approve in the dashboard. The dashboard returns a one-time code to the CLI.
3. The CLI exchanges the code for a scoped token (`cco_cli_live_...`), stored in your
   OS keychain (with a `0600` file fallback).

Headless machines: `contro1 auth login --no-browser` prints a URL to approve on any
device, then you paste the one-time code back.

CI: set `CONTRO1_TOKEN=cco_cli_live_...` to skip the keychain entirely. Output also
defaults to JSON when `CI` is set.

## Command groups

```
Core:              auth  config  whoami  doctor  scopes
Agent workflows:   agents  requests  run  evidence  traces  ai-registry
Read-only admin:   org  api-keys  webhooks  integrations
Operator queue:    queue
```

Run `contro1 help` for the grouped list, or `contro1 <topic> --help` for details.

## Agent workflow

```bash
# Register an agent once
contro1 agents register --name "Support Agent" --type custom-agent
contro1 agents list

# Ask a human before the agent acts
contro1 requests create \
  --type approval \
  --question "Approve refunding order #1842?" \
  --agent agt_123 \
  --risk high \
  --reason "Customer exception policy" \
  --wait

# Pull the record later
contro1 evidence for-request <request_id>
contro1 traces for-request <request_id>

# Keep inventory current
contro1 ai-registry import ./inventory.json
contro1 ai-registry list
```

## Optional command gating

For coding agents and developer workflows, `contro1 run` asks for approval, waits
for the decision, and only runs the local command if approved.

```bash
contro1 run --requires-approval -- npm run deploy
contro1 run --agent agt_123 --risk high --reason "DB migration" -- npm run migrate
```

The execution evidence is marked `client-reported`: it records what the local
machine reported after an approved action, not a cryptographic attestation.

## Output and exit codes

Every command supports `--format table|json|yaml` (table default for humans, JSON
default under CI) and `--quiet`.

```
0 ok        1 general      2 bad args   3 auth error
4 insufficient scope       5 request denied
6 timeout                  7 network error
```

## Token scopes (v1 default)

```
operator:me:read  org:read
agents:read  agents:register  agents:trail:read
requests:create  requests:read  requests:wait  requests:cancel_own  requests:respond_if_assigned
evidence:read  traces:read
ai_registry:read  ai_registry:import
api_keys:read  webhooks:read  integrations:read  queue:read
```

`requests:cancel_own` lets a CLI token cancel only requests it created (each request is
tagged with the creating token id). Full token management (listing/revoking other tokens)
is a dashboard action - a CLI token can only revoke itself.

Tokens expire after 90 days and can be revoked from `contro1 auth tokens revoke <id>`
or the dashboard (Settings -> APIs & Webhooks -> CLI Access Tokens).
