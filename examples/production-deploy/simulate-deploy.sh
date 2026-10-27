#!/usr/bin/env bash
set -euo pipefail

# Safe demo: prints the reviewed deployment identity and performs no network call.
printf 'Simulated production deploy\n'
printf 'target=%s\n' "${DEPLOY_TARGET:-billing-api}"
printf 'environment=%s\n' "${DEPLOY_ENVIRONMENT:-production}"
printf 'commit=%s\n' "$(git rev-parse HEAD 2>/dev/null || printf unknown)"
