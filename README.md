# contro1 CLI

The terminal control layer for **AI agent approvals**, routing checks, and
audit evidence.

Use `contro1` from a terminal, script, CI job, or coding agent to register
agents, preview Control Map routing, create role-based approval requests,
enforce quorum, wait for decisions, and retrieve audit-ready evidence. For
developer workflows, the CLI can also put approval in front of a local command
before it runs.

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

Release archives are built automatically from GitHub Releases. Most users should
install with the script above or download the latest release archive directly.

## Quick start

```bash
contro1 auth login                 # opens the browser to approve (defaults to api.contro1.com)
contro1 whoami

AGENT_ID=$(contro1 agents register \
  --name "Claude Code - Laptop" \
  --type coding-agent \
  --quiet \
  --format json | jq -r .agent_id)

contro1 requests create \
  --type approval \
  --question "Approve sending this customer email?" \
  --agent "$AGENT_ID" \
  --role support-manager \
  --wait

contro1 evidence for-request <request_id>
```

PowerShell:

```powershell
contro1 auth login
$agent = contro1 agents register `
  --name "Claude Code - Laptop" `
  --type coding-agent `
  --quiet `
  --format json | ConvertFrom-Json

contro1 requests create `
  --type approval `
  --question "Approve sending this customer email?" `
  --agent $agent.agent_id `
  --role support-manager `
  --wait
```

The CLI defaults to the hosted Contro1 (`https://api.contro1.com` / `https://contro1.com`),
so no configuration is needed. To point at a local stack or a self-hosted instance:

```bash
contro1 config set api-url http://localhost:8080
contro1 config set web-url http://localhost:3000
```

If `contro1 doctor` points at localhost unexpectedly, check the active profile:

```bash
contro1 config get api-url
contro1 config get web-url
```

The role you pass to `--role` must exist in your organization or be mapped in
Control Map. If routing fails, run `contro1 requests control-map` with the same
role/quorum flags to see the missing mapping or capacity warning.

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
  --role support-manager \
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

## Routing, Control Map and quorum

Use role routing when the request must go to a specific business owner. Use
Control Map when the agent or operator wants a routing preview for role
mapping, shift coverage, fallback reviewers, and quorum. The approval request
is still the source of truth: create it and wait for the signed decision before
the action executes.

```bash
# Optional preview of who can approve
contro1 requests control-map \
  --role finance \
  --required-approvals 2 \
  --approval-role finance \
  --must-include-role cfo

# Create the real request with the same routing and quorum
contro1 requests create \
  --type approval \
  --question "Approve vendor transfer #9831?" \
  --context "Invoice exceeds auto-pay policy; PO and invoice are attached." \
  --agent agt_123 \
  --role finance \
  --required-approvals 2 \
  --approval-role finance \
  --must-include-role cfo \
  --sla-minutes 10 \
  --risk high \
  --reason "Payment exceeds autonomous limit" \
  --correlation-id case-transfer-9831 \
  --external-request-id transfer-9831-approval \
  --trace-id trc_transfer_9831 \
  --wait
```

Useful non-admin request flags:

```
--role <role>                    route to a reviewer role
--required-approvals <n>          enforce approval quorum (uses threshold mode by default)
--approval-mode <mode>            single|all_of|any_of|threshold
--approval-role <role>            required approval role; repeat or comma-separate
--must-include-role <role>        expected role for evidence/control-map
--separation-of-duties=false      allow one person to satisfy multiple approvals
--fail-closed-on-timeout=false    do not fail closed on timeout
--strict-policy                   block when strict policy checks fail
--approval-comment-required       require approval comments
--sla-minutes <n>                 SLA before escalation
--correlation-id <id>             case/business id across related records
--external-request-id <id>        idempotency key for retries
--thread-id <thr_...>             conversation/thread timeline id
--trace-id <trc_...>              execution trace id
--parent-trace-id <trc_...>       parent trace for sub-agent runs
```

For payloads that already match the public API, pass JSON directly. This is the
best path for advanced protocol fields, response schemas, tool calls,
sub-agents, retrieved context, or policy objects that should stay versioned in
your agent repo.

```bash
contro1 requests control-map --file request.json --format json
contro1 requests create --file request.json --wait
```

You can also attach structured JSON fragments without writing the full body:

```bash
contro1 requests create \
  --question "Approve publishing generated campaign?" \
  --role marketing-manager \
  --tool-calls-file tool-calls.json \
  --retrieved-context-file retrieved-context.json \
  --policy-context-file policy-context.json \
  --response-schema-file response-schema.json \
  --wait
```

## Optional command gating

For coding agents and developer workflows, `contro1 run` asks for approval, waits
for the decision, and only runs the local command if approved.

```bash
contro1 run --requires-approval -- npm run deploy
contro1 run \
  --agent agt_123 \
  --role release-manager \
  --required-approvals 2 \
  --risk high \
  --reason "DB migration" \
  -- npm run migrate
```

The execution evidence is marked `client-reported`: it records what the local
machine reported after an approved action, not a cryptographic attestation.

## Output and exit codes

Every command supports `--format table|json|yaml` (table default for humans, JSON
default under CI) and `--quiet`. In JSON/YAML mode, status messages are suppressed
so stdout stays parseable.

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

## Testing

Unit tests (pure logic - PKCE, output, decision classification) run with no setup:

```bash
go test ./...
```

End-to-end tests exercise every documented command against a live backend. They are
gated behind the `e2e` build tag and skip unless you provide a token and API URL:

```bash
# get a token once: contro1 auth login && contro1 auth print-access-token --yes
export CONTRO1_API_URL=https://api.contro1.com   # or your local stack
export CONTRO1_TOKEN=cco_cli_live_xxx
go test -tags e2e -v .
```

The e2e suite (`e2e_test.go`) covers auth/whoami/doctor/scopes, config, agents,
requests (create/get/list/wait), evidence, ai-registry import/list, the read-only
admin and queue views, help topic grouping, and the documented exit codes.
