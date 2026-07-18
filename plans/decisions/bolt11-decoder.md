# ADR: BOLT11 decoder qualification is blocked

- Status: **release blocking — no dependency selected**
- Date: 2026-07-18
- Scope: W1-01 of `bind-validated-bolt11-amount-and-payment-hash-to-every-policy-approved-payment-before-wallet-submission.md`

## Decision

Do not add a BOLT11 decoder dependency and do not begin the production parsing
work in Wave 2. The available Python candidates reviewed on 2026-07-18 do not
simultaneously meet Paygate's supported interpreter range (`>=3.10,<3.15`) and
the real-funds safety requirement. This is intentionally a release-blocking
outcome, not a runtime fallback or a Python-support-policy change.

As a result, `pyproject.toml` and CI remain unchanged: there is no approved pin
for a smoke matrix to exercise. No production invoice or payment code was
changed.

## Required future decoder contract

Before this decision can be superseded, a candidate must be pinned and shown in
CI on Ubuntu CPython 3.10, 3.11, 3.12, 3.13, and 3.14 to:

1. validate Bech32 checksum and the BOLT11 recoverable secp256k1 signature;
2. expose the original invoice string, exact signed amount in millisatoshi, and
   the signed `p` tag as exactly 32 bytes; and
3. reject independent checksum and signature mutations of an official,
   amount-bearing BOLT11 conformance vector.

The eventual public boundary is expected to produce an immutable value with
those three values. It must fail closed and must not echo an invoice in an error.

## Candidates reviewed

| Candidate | Version reviewed | Result | Evidence |
| --- | --- | --- | --- |
| `bolt11` (LNbits) | `2.2.0` | Rejected: its published `Requires-Python` is `>=3.10,<3.13`, so it cannot install in the declared 3.13 and 3.14 CI jobs. It is a pure-Python wheel with direct dependencies `base58`, `bech32`, `bitstring`, `click`, and `coincurve`; that does not remedy the interpreter exclusion. | [PyPI release metadata](https://pypi.org/pypi/bolt11/2.2.0/json), [upstream project](https://github.com/lnbits/bolt11), accessed 2026-07-18. |
| `pyln-proto` (Core Lightning) | `26.6.5` | Rejected despite a compatible published range (`>=3.10,<4.0`) and BSD-MIT license. Its own PyPI description says it is intended for testing/minor tooling and is not deemed secure enough for any real funds. That explicit warning remains unresolved. Direct dependencies are `base58>=2.1.1`, `bitstring>=4.3.0`, `coincurve>=21`, `cryptography>=46`, and `pysocks>=1`. | [PyPI project description](https://pypi.org/project/pyln-proto/), [release metadata](https://pypi.org/pypi/pyln-proto/26.6.5/json), accessed 2026-07-18. |
| `light-bolt11-decoder` | Current upstream project | Rejected: it is JavaScript rather than an installable Python dependency and upstream explicitly says it does not check signatures. It therefore cannot establish the requested trust boundary. | [Upstream README](https://github.com/nbd-wtf/light-bolt11-decoder), accessed 2026-07-18. |

## Standards and vector source

The qualification vectors must come from the Lightning BOLT #11 specification.
The specification's examples identify both the Bech32 checksum and the
recoverable signature separately, so each can be independently mutated by the
smoke test. See [BOLT #11 payment encoding](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md),
accessed 2026-07-18.

## Local qualification evidence

- Host interpreter: CPython 3.14.5.
- The PyPI JSON metadata for `bolt11==2.2.0` reports
  `Requires-Python: >=3.10,<3.13`; pip correctly filters it from Python 3.14.
- `pyln-proto==26.6.5` reports `Requires-Python: >=3.10,<4.0`, but its explicit
  real-funds disclaimer means installation/import or decode success would not
  qualify it.

## Security and maintenance assessment

`bolt11` has recent releases, but its package metadata does not support the
project's stated interpreter contract. `pyln-proto` is maintained within the
Core Lightning project and publishes recent releases, but maintenance does not
override its package-level warning against real-funds use. No candidate is
approved merely because its decoder may expose an amount and payment hash; the
checksum and signature guarantees must be empirically demonstrated in the
eventual all-version CI smoke test.

## Release gate and next action

Wave 1 is blocked. Do not proceed to Waves 2 or 3 until an acceptable
maintained dependency, or a separately approved implementation/security design,
is identified and this ADR is superseded with an exact version pin, license,
transitive dependency list, API evidence, and successful 3.10–3.14 CI vector
results.
