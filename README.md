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
contro1 auth login --mode agent    # safe developer profile; browser + PKCE
contro1 init --name "Claude Code - Laptop"
contro1 requests create \
  --type approval \
  --question "Approve sending this customer email?" \
  --role support-manager \
  --wait

contro1 ask "Which region should I use?" --wait --format json

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

CI may use an agent `CONTRO1_TOKEN`. Operator profiles are browser-issued, expire
after 8 hours, require an interactive TTY for decisions, and cannot use that env var.

- `agent` (default): register/read self; create, read, wait for and cancel its own requests; related evidence/traces.
- `operator`: routed queue, atomic claim, and approve/reject/respond after assignment.
- `observer`: read-only organization, registry, evidence, and integration status.

## Command groups

```
Core:              auth  config  whoami  doctor  scopes
Agent workflows:   init  ask  agents  requests  run  hooks  evidence  traces
Read-only admin:   org  api-keys  webhooks  integrations
Operator queue:    queue
```

Run `contro1 help` for the grouped list, or `contro1 <topic> --help` for details.

## Agent workflow

```bash
# Register an agent once and save it as the profile default
contro1 init --name "Support Agent" --framework custom-agent

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

# Ask for human input (a free_text request)
contro1 ask "Which customer segment should I use?" --wait
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

`--reason` and `--context` answer different questions. `--reason` records why approval
is required - the policy trigger, for example "Payment exceeds autonomous limit".
`--context` carries what the reviewer needs to decide - fill it at the gate with
machine-observed facts: the redacted command or tool input plus hashes of the
original values, and the message or event that
triggered the run. Anything the agent writes about its own justification is
agent-reported: it helps the human decide, but it must never be the thing that changes
routing, risk level, or approval policy. See the full pattern at
https://contro1.com/docs/requests-api.

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

Set any agent, framework, or CLI wait timeout longer than `--sla-minutes` plus a
small callback/escalation buffer. For example, a request with `--sla-minutes 10`
should use a wait timeout above 10 minutes, so the local agent run does not
auto-cancel or detach before Contro1 reaches the SLA outcome.

For payloads that already match the public API, pass JSON directly. This is the
best path for advanced protocol fields, response schemas, tool calls,
sub-agents, retrieved context, or policy objects that should stay versioned in
your agent repo.

```bash
contro1 requests control-map --file request.json --format json
contro1 requests create --file request.json --dry-run --format json
contro1 requests create --file request.json --wait --format json
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

## Production deploy gate

For coding agents and developer workflows, `contro1 run` sends a canonical
approval request, waits for the decision, verifies that the repository state did
not change while it was waiting, and only then runs the original argv bound to
the reviewed hash. Secret-looking values are redacted from reviewer context.

```bash
contro1 run \
  --role cto \
  --risk critical \
  --environment production \
  --target billing-api \
  --reason "Production deploys require CTO authorization" \
  -- npm run deploy:production
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

Try the safe [production deploy demo](examples/production-deploy/README.md).

## Codex adapter

`contro1 hooks codex` reads a Codex `PreToolUse` or `PermissionRequest` event
from stdin. It gates deploy-like Bash commands and declines to decide on normal
tests, reads, and local development commands.

For a developer-controlled setup, copy
[`examples/codex/convenience-hooks.json`](examples/codex/convenience-hooks.json)
to a trusted project `.codex/hooks.json`, then use `/hooks` in Codex to review
and trust it.

For an organization-controlled setup, deploy
[`examples/codex/requirements.toml`](examples/codex/requirements.toml) through
your supported managed configuration channel and install the CLI at the absolute
path referenced by the managed hook. The adapter fails closed on invalid policy,
authentication failure, rejection, timeout, and Contro1 API failure.

## Convenience versus non-bypassable enforcement

| Setup | Protects against | What can still bypass it |
|---|---|---|
| `contro1 run` or a project hook | Accidental/autonomous agent actions | Running the deploy command directly or editing local config |
| Centrally managed Claude Code/Codex hook | Bypass inside that managed coding-agent client | Another terminal or tool with production credentials |
| CI/deployment credential boundary | Agent and developer paths without authorized credentials | Changes to the protected CI/deployment policy itself |

The strongest pattern is two jobs: an approval job with only a scoped Contro1
agent token, followed by a deploy job that obtains short-lived production
credentials only after approval. Start from the
[GitHub Actions template](examples/github-actions/production-deploy.yml).

Do not market a wrapper or project-local hook as a security boundary. It is a
valuable convenience gate. Non-bypassable enforcement requires managed client
policy plus a target-side credential boundary.

## Output and exit codes

Every command supports `--format table|json|yaml` (table default for humans, JSON
default under CI) and `--quiet`.

```
0 ok        1 general      2 bad args   3 auth error
4 insufficient scope       5 request denied
6 timeout                  7 network error
```

On a `contro1 run` timeout (exit 6) the command never executes. The CLI's `--timeout`
is the executor's patience, not the request's lifecycle: the request is left open
server-side so it keeps escalating to the humans and stays fully documented. The CLI
records an `executor_detached` event on it, so a later human approval is never mistaken
for a command that actually ran.

For approval gates with an SLA, keep `--timeout` greater than `--sla-minutes` so
the command runner does not give up before the approval window and escalation path
have had time to finish.

## Operator queue

Queue decisions require a separate interactive operator profile:

```bash
contro1 auth login --mode operator --profile reviewer
contro1 queue claim <request_id> --profile reviewer
contro1 queue approve <request_id> --profile reviewer
contro1 queue reject <request_id> --comment "policy mismatch" --profile reviewer
contro1 queue respond <request_id> --value "us-east-1" --profile reviewer
```

Comment requirements are snapshotted from the API-key policy (`optional`,
`risk_based`, or `always`) when the request is created.

## Agent token scopes

```
agents:read  agents:register  agents:trail:read
requests:create  requests:read  requests:wait  requests:cancel_own
evidence:read  traces:read
```

`requests:cancel_own` lets a CLI token cancel only requests it created (each request is
tagged with the creating token id). Full token management (listing/revoking other tokens)
is a dashboard action - a CLI token can only revoke itself.

Agent/observer tokens expire after 90 days; operator tokens expire after 8 hours.
Tokens can be revoked from `contro1 auth tokens revoke <id>`
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
