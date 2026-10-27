# Safe production deploy demo

This demo exercises the same canonical approval and evidence path as a real
deployment without changing infrastructure or making a network call.

```bash
contro1 auth login --mode agent
contro1 init --name "deployment-demo"

contro1 run \
  --role cto \
  --risk critical \
  --environment production \
  --target billing-api \
  --reason "Production deploys require CTO authorization" \
  -- ./examples/production-deploy/simulate-deploy.sh
```

The reviewer receives the redacted command, hash of the original argv, current commit, workspace-state
hash, target, environment, risk, policy trigger, and source. Approval executes
the original argv bound to that hash only if the repository state still matches. Rejection,
timeout, API failure, or a changed workspace blocks execution.

This local wrapper is a convenience gate. For production enforcement, run the
approval in CI without production credentials and place deployment credentials
only in a protected downstream job. See
[`../github-actions/production-deploy.yml`](../github-actions/production-deploy.yml).
