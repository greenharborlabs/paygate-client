# Frozen executable Python oracle

This bundle replays commit
`f56cbd0c4bdf07254282a52e51bcf88ff1f48478` on the qualified platform:
CPython 3.11, Linux x86_64, and glibc 2.31 or newer. The runner image starts
from CPython 3.11.14 at immutable image digest
`sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d`.

The replay derives all 75 historical paths and blobs directly from Git, makes
a clean detached local clone with history, installs all 46 runtime, Breez,
development, build, and bootstrap packages from the checked-in wheelhouse, and
runs all 227 historical tests. Docker's network namespace is disabled, while
the injected Python guards make DNS, INET sockets, unmatched HTTP, real
keyring backends, remote Git, and unapproved subprocesses fatal. Two fresh
runs use deliberately different ambient HOME, XDG, locale, timezone, and clock
inputs; their complete evidence must be byte-identical.

This is a frozen legacy compatibility oracle, not an implementation target.
Its 37-case baseline is retained as a rollback and behavioral reference until
the Rust cutover is complete. New adapter-negative cases, configuration
precedence cases, backend payment evidence, and submission/cancellation
guarantees belong in Rust tests; do not expand this Python bundle.

Build the pinned qualified runner (the build may access Debian package mirrors
to install Git):

```sh
docker build --platform linux/amd64 \
  -t paygate-python-oracle:3.11 \
  -f compat/python_oracle/Dockerfile compat/python_oracle
```

Verify the checked-in golden with no network:

```sh
docker run --rm --platform linux/amd64 --network none \
  -e ORACLE_OS_NETWORK_BOUNDARY=docker-none \
  -e PYTHONPATH=/workspace \
  -v "$PWD:/workspace" -w /workspace \
  paygate-python-oracle:3.11 \
  python -m compat.python_oracle.replay
```

Golden regeneration is intentionally separate and explicit. Run it only after
reviewing an intentional historical-contract change:

```sh
docker run --rm --platform linux/amd64 --network none \
  -e ORACLE_OS_NETWORK_BOUNDARY=docker-none \
  -e PYTHONPATH=/workspace \
  -v "$PWD:/workspace" -w /workspace \
  paygate-python-oracle:3.11 \
  python -m compat.python_oracle.replay --regenerate-golden
```

The ordinary focused contract tests validate fail-closed behavior without
regenerating evidence:

```sh
python3.11 -m pytest compat/python_oracle/tests -q
```
