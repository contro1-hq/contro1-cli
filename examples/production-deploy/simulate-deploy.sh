#!/usr/bin/env sh
set -eu

# Safe demo payload: this script performs no network or deployment operation.
# Replace it with an organization-owned deployment entry point only after the
# approval path and credential boundary have been tested.
printf 'SIMULATED DEPLOY\n'
printf 'target=%s\n' "${DEPLOY_TARGET:-billing-api}"
printf 'environment=%s\n' "${DEPLOY_ENVIRONMENT:-production}"
printf 'commit=%s\n' "${GIT_COMMIT:-$(git rev-parse HEAD 2>/dev/null || printf unknown)}"
