# Developer Setup

The production client is Rust. The repository also retains the Python client
and frozen oracle for compatibility testing. A complete contributor environment
needs Rust 1.88.0, `protoc`, and Python with the development dependencies.

## System prerequisites

Install [rustup](https://rustup.rs/) if it is not already available. The
checked-in `rust-toolchain.toml` selects Rust 1.88.0 and installs the `rustfmt`
and `clippy` components when a Rust command is run from this checkout. To
install them explicitly:

```bash
rustup toolchain install 1.88.0 \
  --profile minimal \
  --component rustfmt \
  --component clippy
```

The Breez/Spark dependency graph compiles Protocol Buffer definitions during
the build, so the Protocol Buffer compiler must be installed even though it is
not a runtime dependency.

macOS with Homebrew:

```bash
brew install protobuf
```

Ubuntu or Debian:

```bash
sudo apt-get update
sudo apt-get install --yes protobuf-compiler
```

Fedora:

```bash
sudo dnf install protobuf-compiler
```

Verify that all build tools are discoverable before compiling:

```bash
rustc --version
cargo --version
protoc --version
```

`rustc --version` should report 1.88.0 while inside this repository. If
`protoc` is installed outside `PATH`, point the Rust build scripts to its
absolute location:

```bash
PROTOC=/absolute/path/to/protoc cargo check --locked --lib
```

## Rust development setup

Fetch the exact dependency graph from `Cargo.lock`, then compile the library:

```bash
cargo fetch --locked
cargo check --locked --lib
```

Common local checks are:

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
```

Run a single integration target while iterating with, for example:

```bash
cargo test --locked --test request_flow
```

Linux developers who run the ignored native keyring qualification also need a
Secret Service implementation and development headers. On Ubuntu or Debian:

```bash
sudo apt-get install --yes dbus-x11 gnome-keyring libsecret-1-dev
```

The ordinary Rust build and non-keyring tests do not require a running desktop
keyring. See [platform-qualification.md](platform-qualification.md) for the
controlled native qualification environment and supported target matrix.

## Python compatibility-suite setup

The retained Python package supports modern editable installs
(`python3 -m pip install -e .`).
Older `pip` versions (for example `pip 21.2.4`) do not support PEP 660 editable
install behavior, so developers should upgrade first:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```

If you already have an editable checkout installed and dependencies changed,
reinstall it:

```bash
python3 -m pip install -e ".[dev]"
```

An editable Python install creates its own legacy `paygate` console entry point.
Do not use that executable to validate the Rust CLI. Use `cargo run --locked
--bin paygate -- ...` or an explicitly installed Rust binary so the runtime
under test is unambiguous.

## Profile-aware local CLI checks

Use `--profile` when testing multi-agent behavior. Each profile gets separate
credential cache metadata, keyring account names, and daily spend ledger state.

```bash
cargo run --locked --bin paygate -- request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/worker-a.yaml \
  --profile worker-a \
  --no-pay --trace-json

cargo run --locked --bin paygate -- credentials list --profile worker-a
cargo run --locked --bin paygate -- credentials purge --all --profile worker-a
```

Use explicit paths when tests or containers need disposable state:

```bash
cargo run --locked --bin paygate -- request GET "https://api.example.com/protected" \
  --config ~/.config/paygate-client/worker-a.yaml \
  --profile worker-a \
  --cache-path /tmp/paygate-worker-a/credentials.json \
  --ledger-path /tmp/paygate-worker-a/daily-spend-ledger.json
```

## Python verification commands

```bash
poe check
```

Run auto-formatting and safe Ruff fixes before committing:

```bash
poe fix
```

Useful local CLI checks:

```bash
cargo run --locked --bin paygate -- request --help
cargo run --locked --bin paygate -- credentials --help
cargo run --locked --bin paygate -- backend doctor --help
```
