# Documentation

The production Paygate client is the Rust `paygate` binary. Start with the
[project README](../README.md) for installation, Breez configuration, and CLI
usage.

## Current documentation

- [Developer setup](dev-setup.md): Rust 1.88.0, `protoc`, Cargo checks, and the
  retained Python compatibility test environment.
- [Payer backend compatibility](payer-backend-compatibility.md): which payer
  backends are wired into the Rust CLI and which fail closed.
- [Native platform qualification](platform-qualification.md): qualification
  target matrix and release-artifact evidence requirements.
- [Release status and procedures](releasing.md): current Rust distribution
  status and the separate legacy Python package workflow.
- [Phoenixd status](phoenixd-spike.md): why Phoenixd is intentionally
  unsupported in the current Rust release.

## Historical migration evidence

These files preserve the completed Python-to-Rust migration and its evidence.
They are not fresh-install or ordinary release instructions.

- [Minimal Rust cutover runbook](minimal-rust-cutover-runbook.md)
- [Wave 5 evidence publication](wave5-evidence-publication.md)
- [Historical plans](../plans/README.md)
- [Historical reports](../reports/README.md)

Do not run a migration command merely because it appears in a retained
runbook. Existing recovery journals must be handled using the exact operation
and immutable records from the affected installation.
