# Paygate protected payment-canary runner

This is the reviewed source for the component installed at
`/opt/paygate/payment-canary-runner/current/payment-canary-runner`.  It is not
executed from the checkout.  Deployment, immutable image digest, rollback
digest, ownership, runner group, durable ledger and availability requirements
are pinned in `../runners/payment-canary.yml`.

The runner accepts no wallet material from GitHub. Before it can run the
candidate, a root-owned `candidate-approval.json` envelope is verified as an
Ed25519 signature over canonical claims with the root-owned approval keyring.
The signer must be known, unrevoked, and valid at issuance; the claims bind the
candidate file digest, source commit, lock digest, approved backend, and an
exact `sha256:<candidate_sha256>` attestation subject/digest. A separate
root-owned sandbox policy is passed to the fixed sandbox with `--policy`,
`--deny-network`, and `--protocol candidate-probe-v1`; candidate output is a
single fixed probe request, never adapter input.

The deployment inventory independently pins the active immutable digest and a
rollback digest. Contract checking rejects any active/rollback, approval trust,
or full sandbox-policy parity drift before payment capability is enabled.

The root-owned payment policy alone supplies the positive backend cap. The
adapter runs outside the candidate sandbox with literal runner-derived context.
The durable ledger is an exclusive-lock, fsync-backed state machine: an attempt
can be claimed once, then released before submission, terminally recorded, or
marked permanently unknown. A release is historical and cannot be claimed again.
The external signed-result validator remains the authority for a successful job.
