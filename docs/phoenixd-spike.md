# Phoenixd payer status

Phoenixd is intentionally unsupported in the current Rust release.

The Rust `PhoenixdPayer` is a fail-closed placeholder. It owns no endpoint,
password, HTTP client, or submission capability. Readiness returns unsupported,
payment returns a not-submitted unsupported outcome, and disconnect is a safe
no-op.

As a result:

- `paygate request` cannot pay a `402` challenge with `payer.backend:
  phoenixd`;
- `paygate backend doctor` returns an unsupported fee-limit classification;
- `paygate backend pay-invoice` does not submit an invoice; and
- the legacy Python Phoenixd adapter and earlier capability-spike plans do not
  imply Rust production support.

## What would be required

A future Phoenixd implementation would need reviewed evidence that the exact
target API can:

1. enforce a per-payment routing fee cap before submission;
2. return the successful Lightning payment preimage;
3. return invoice-bound payment hash, amount, and fee metadata;
4. distinguish not-submitted, submitted-unknown, final failure, and confirmed
   outcomes; and
5. apply the same redirect, timeout, redaction, cleanup, and proof-verification
   boundaries as the Breez production path.

Do not test those capabilities by sending an unbounded or unapproved payment.
They require a separate implementation and qualification change, not a config
switch.
