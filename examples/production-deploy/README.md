# Production deploy approval demo

This demo shows the complete developer experience without touching a real
cluster or cloud account.

```bash
contro1 auth login --mode agent
contro1 init --name "Deploy demo agent"

contro1 run \
  --role cto \
  --risk critical \
  --environment production \
  --target billing-api \
  --reason "Production deploys require CTO authorization" \
  --sla-minutes 10 \
  --timeout 15m \
  -- ./examples/production-deploy/simulate-deploy.sh
```

Expected flow:

1. The command remains blocked and a canonical request appears in Contro1.
2. The request shows the redacted command, hash of the original argv, repo commit, workspace
   state, target, risk, policy trigger, and required reviewer role.
3. Reject or let it time out: the script never runs.
4. Approve: the CLI rechecks the repo state and runs the original argv bound to that hash.
5. `contro1 evidence for-request <id>` shows the decision and client-reported
   execution outcome.

This is a convenience gate. For an organization control, put production
credentials in a separate CI/deployment job and use the GitHub Actions template.
