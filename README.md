# contro1 CLI

The official command-line interface for the **Contro1** Human Approval Layer.

It lets developers and AI coding agents work through Contro1 in practice: register
agents, create and wait for approval requests, **run gated commands**, and retrieve
audit-ready evidence - using a **scoped, browser-issued token** (gcloud-style login).

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
contro1 config set api-url http://localhost:8080
contro1 config set web-url http://localhost:3000
contro1 auth login                 # opens the browser to approve
contro1 whoami
contro1 run --requires-approval -- npm run deploy
```

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
api_keys:read  webhooks:read  integrations:read  queue:read
```

Tokens expire after 90 days and can be revoked from `contro1 auth tokens revoke <id>`
or the dashboard (Settings -> APIs & Webhooks -> CLI Access Tokens).
