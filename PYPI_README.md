# Legacy Python Paygate Client

This package contains the retained Python implementation of Paygate Client.
The production client is now the Rust `paygate` binary and is installed from
the locked Rust source checkout. New production deployments should follow the
[Rust installation guide](https://github.com/greenharborlabs/paygate-client#install-the-rust-cli),
not install this Python package.

## Install

For Python compatibility testing only, install the package and optional Breez
SDK Spark dependency:

```bash
pipx install "paygate-client[breez]"
```

This command installs the legacy Python console entry point. It does not
install or update the Rust binary.

## Legacy compatibility

The declared and tested CPython support range is 3.10 through 3.14. The Python
implementation remains available for regression comparison and package
compatibility; current backend and runtime support claims apply to the Rust
client unless explicitly labeled otherwise.

For configuration, supported payer details, and source code, see the
[documentation](https://github.com/greenharborlabs/paygate-client/tree/main/docs)
and [source repository](https://github.com/greenharborlabs/paygate-client).
