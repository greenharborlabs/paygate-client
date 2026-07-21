# Paygate protected payment-canary runner

This is the reviewed source for the component installed at
`/opt/paygate/payment-canary-runner/current/payment-canary-runner`.  It is not
executed from the checkout.  Deployment, immutable image digest, rollback
digest, ownership, runner group, durable ledger and availability requirements
are pinned in `../runners/payment-canary.yml`.

The runner accepts no wallet material from GitHub.  It claims a durable attempt
key before any invoice boundary, treats an ambiguous submit as permanent
no-retry, and signs only redacted result records.  The deployer supplies its
private signing key outside this repository.
