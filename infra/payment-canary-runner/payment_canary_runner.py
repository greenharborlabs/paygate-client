#!/usr/bin/env python3
"""Fail-closed deployment-owned payment-canary control-plane runner.

This program deliberately contains no payment implementation.  It is the small
control boundary which validates deployment-owned evidence, isolates the
untrusted qualification probe, and invokes a separately protected adapter.
"""

import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

ROOT = Path("/opt/paygate/payment-canary-runner/current")
RUNNER = ROOT / "payment-canary-runner"
ADAPTER = ROOT / "protected-payment-adapter"
SANDBOX = ROOT / "candidate-sandbox"
CANDIDATE = ROOT / "payment_canary"
APPROVAL = ROOT / "candidate-approval.json"
SANDBOX_POLICY = ROOT / "candidate-sandbox-policy.json"
PAYMENT_POLICY = ROOT / "payment-policy.json"
APPROVAL_KEYRING = ROOT / "candidate-approval-keyring.json"
LEDGER = Path("/var/lib/paygate/payment-canary/durable-ledger.jsonl")
RESULT = Path("/var/lib/paygate/payment-canary/result.json")
BACKENDS = {"lnd-testnet-canary", "breez-mainnet-canary"}
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[0-9]+$")

APPROVAL_FIELDS = {
    "approved",
    "candidate_sha256",
    "source_commit",
    "cargo_lock_sha256",
    "attestation_subject",
    "attestation_digest",
    "approval_id",
    "approved_backends",
    "issuer",
    "key_id",
    "issued_at",
    "expires_at",
}
APPROVAL_ENVELOPE_FIELDS = {"claims", "signature"}
APPROVAL_KEY_FIELDS = {
    "id",
    "issuer",
    "public_key",
    "not_before",
    "not_after",
    "revoked",
}
SANDBOX_POLICY_FIELDS = {
    "schema_version",
    "network",
    "inherit_environment",
    "mounts",
    "forbidden_mounts",
    "candidate_protocol",
}
PAYMENT_POLICY_FIELDS = {"schema_version", "caps_msat", "adapter_protocol"}
TRANSITIONS = {
    None: {"claimed"},
    "claimed": {
        "unsubmitted_released",
        "succeeded",
        "definite_failed",
        "submitted_unknown_permanent_no_retry",
    },
}


def attempt_key(a):
    return ":".join(
        (a.source_commit, a.cargo_lock_sha256, a.backend, a.workflow_run_id)
    )


def validate_protected_path(path, executable=False, directory=False):
    """Reject symlinks, non-root ownership and group/world-writable components."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("protected path must be absolute")
    current = Path("/")
    for component in path.parts[1:]:
        current /= component
        st = os.lstat(current)
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("unsafe protected path")
        if current != path and not stat.S_ISDIR(st.st_mode):
            raise ValueError("unsafe protected component")
    if directory:
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError("protected directory required")
    elif not stat.S_ISREG(st.st_mode) or (executable and not st.st_mode & 0o111):
        raise ValueError("unsafe protected executable")


def _read_protected_json(path):
    validate_protected_path(path)
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("malformed protected descriptor") from exc


def _time(value):
    if not isinstance(value, str):
        raise ValueError("invalid approval time")
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid approval time") from exc


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value):
    """Canonical approval claims; the detached envelope signature is excluded."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _verify_approval_signature(claims, signature, public_key):
    """Verify a deployment-owned Ed25519 approval key without importing crypto code."""
    if not isinstance(signature, str):
        raise ValueError("invalid candidate approval signature")
    try:
        encoded = base64.b64decode(signature, validate=True)
    except ValueError as exc:
        raise ValueError("invalid candidate approval signature") from exc
    try:
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "claims.json"
            detached = Path(directory) / "signature.bin"
            payload.write_bytes(canonical_json(claims))
            detached.write_bytes(encoded)
            verified = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key),
                    "-rawin",
                    "-in",
                    str(payload),
                    "-sigfile",
                    str(detached),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("candidate approval signature unavailable") from exc
    if verified.returncode:
        raise ValueError("candidate approval signature rejected")


def validate_candidate_approval(a):
    """Validate fixed deployment evidence before the candidate can execute."""
    envelope = _read_protected_json(APPROVAL)
    keyring = _read_protected_json(APPROVAL_KEYRING)
    if not isinstance(envelope, dict) or set(envelope) != APPROVAL_ENVELOPE_FIELDS:
        raise ValueError("invalid candidate approval envelope")
    approval = envelope["claims"]
    if not isinstance(approval, dict) or set(approval) != APPROVAL_FIELDS:
        raise ValueError("invalid candidate approval schema")
    strings = APPROVAL_FIELDS - {"approved", "approved_backends"}
    if (
        approval["approved"] is not True
        or any(not isinstance(approval[x], str) or not approval[x] for x in strings)
        or not isinstance(approval["approved_backends"], list)
        or any(item not in BACKENDS for item in approval["approved_backends"])
    ):
        raise ValueError("invalid candidate approval")
    if (
        not DIGEST.fullmatch(approval["candidate_sha256"])
        or not DIGEST.fullmatch(approval["cargo_lock_sha256"])
        or not COMMIT.fullmatch(approval["source_commit"])
        or not DIGEST.fullmatch(approval["attestation_digest"])
    ):
        raise ValueError("invalid candidate approval digest")
    issued, expiry = _time(approval["issued_at"]), _time(approval["expires_at"])
    now = dt.datetime.now(dt.timezone.utc)
    if issued > now or expiry <= now or a.backend not in approval["approved_backends"]:
        raise ValueError("candidate approval expired or backend unapproved")
    if (
        not isinstance(keyring, dict)
        or keyring.get("purpose") != "candidate-approval"
        or not isinstance(keyring.get("keys"), list)
    ):
        raise ValueError("invalid candidate approval keyring")
    keys = [
        key
        for key in keyring["keys"]
        if isinstance(key, dict)
        and set(key) == APPROVAL_KEY_FIELDS
        and key["id"] == approval["key_id"]
        and key["issuer"] == approval["issuer"]
    ]
    if len(keys) != 1 or keys[0]["revoked"] is not False:
        raise ValueError("unknown or revoked candidate approval key")
    key = keys[0]
    if (
        not isinstance(key["public_key"], str)
        or not key["public_key"]
        or _time(key["not_before"]) > issued
        or _time(key["not_after"]) < issued
    ):
        raise ValueError("candidate approval key invalid at issuance")
    validate_protected_path(key["public_key"])
    _verify_approval_signature(approval, envelope["signature"], key["public_key"])
    if (
        approval["source_commit"] != a.source_commit
        or approval["cargo_lock_sha256"] != a.cargo_lock_sha256
        or approval["candidate_sha256"] != sha256_file(CANDIDATE)
        or approval["attestation_digest"] != approval["candidate_sha256"]
        or approval["attestation_subject"] != "sha256:" + approval["candidate_sha256"]
    ):
        raise ValueError("candidate approval does not bind invocation")
    return approval


def load_sandbox_policy():
    policy = _read_protected_json(SANDBOX_POLICY)
    forbidden = {"credentials", "backend", "result", "ledger"}
    if (
        not isinstance(policy, dict)
        or set(policy) != SANDBOX_POLICY_FIELDS
        or policy.get("schema_version") != 1
        or policy.get("network") != "denied"
        or policy.get("inherit_environment") is not False
        or policy.get("mounts") != []
        or set(policy.get("forbidden_mounts", [])) != forbidden
        or policy.get("candidate_protocol") != "candidate-probe-v1"
    ):
        raise ValueError("unsafe candidate sandbox policy")
    return policy


def load_payment_cap(backend):
    policy = _read_protected_json(PAYMENT_POLICY)
    if (
        not isinstance(policy, dict)
        or set(policy) != PAYMENT_POLICY_FIELDS
        or policy.get("schema_version") != 1
        or policy.get("adapter_protocol") != "payment-adapter-v1"
        or not isinstance(policy.get("caps_msat"), dict)
        or set(policy["caps_msat"]) != BACKENDS
    ):
        raise ValueError("unsafe payment policy")
    cap = policy["caps_msat"].get(backend)
    if type(cap) is not int or cap <= 0:
        raise ValueError("unsafe payment cap")
    return cap


def transition(record):
    """Atomically append one legal durable state transition, or fail closed."""
    validate_protected_path(LEDGER.parent, directory=True)
    if LEDGER.exists():
        validate_protected_path(LEDGER)
    if not isinstance(record, dict) or set(record) != {"attempt_key", "state"}:
        raise ValueError("invalid ledger record")
    if not isinstance(record["attempt_key"], str) or not record["attempt_key"]:
        raise ValueError("invalid ledger attempt")
    try:
        with LEDGER.open("a+", encoding="utf-8") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            stream.seek(0)
            states = {}
            for line in stream:
                if line.strip():
                    prior = json.loads(line)
                    if set(prior) != {"attempt_key", "state"}:
                        raise ValueError("malformed durable ledger")
                    states[prior["attempt_key"]] = prior["state"]
            previous = states.get(record["attempt_key"])
            if record["state"] not in TRANSITIONS.get(previous, set()):
                return False
            stream.seek(0, os.SEEK_END)
            stream.write(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("durable ledger unavailable") from exc
    return True


# Compatibility name for existing deployment tests; it now enforces transitions.
def append(record):
    return transition(record)


def run_candidate():
    """Candidate gets a fixed request and no inherited payment authority."""
    return subprocess.run(
        [
            str(SANDBOX),
            "--policy",
            str(SANDBOX_POLICY),
            "--deny-network",
            "--protocol",
            "candidate-probe-v1",
            "--",
            str(CANDIDATE),
        ],
        cwd="/",
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "PAYGATE_NETWORK_DENY": "required"},
        input=b"{}",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )


def run_adapter(a, key, cap):
    """The trusted adapter is intentionally not run through the candidate sandbox."""
    return subprocess.run(
        [
            str(ADAPTER),
            "--protocol",
            "payment-adapter-v1",
            "--attempt-key",
            key,
            "--source-commit",
            a.source_commit,
            "--cargo-lock-sha256",
            a.cargo_lock_sha256,
            "--workflow-run-id",
            a.workflow_run_id,
            "--backend",
            a.backend,
            "--cap-msat",
            str(cap),
            "--result",
            str(RESULT),
        ],
        cwd="/",
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )


def validate_local_result(a, key, cap):
    """Structurally pre-check a result before external signed validation."""
    validate_protected_path(RESULT)
    try:
        result = json.loads(RESULT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("malformed trusted adapter result") from exc
    required = {
        "backend",
        "source_commit",
        "cargo_lock_sha256",
        "workflow_run_id",
        "attempt_key",
        "cap_msat",
        "state",
    }
    if not isinstance(result, dict) or not required.issubset(result):
        raise ValueError("incomplete trusted adapter result")
    if any(
        result[name] != value
        for name, value in {
            "backend": a.backend,
            "source_commit": a.source_commit,
            "cargo_lock_sha256": a.cargo_lock_sha256,
            "workflow_run_id": a.workflow_run_id,
            "attempt_key": key,
            "cap_msat": cap,
        }.items()
    ):
        raise ValueError("trusted adapter result identity mismatch")
    if result["state"] not in {"succeeded", "definite_failed"}:
        raise ValueError("indeterminate trusted adapter result")
    return result["state"]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--backend", required=True)
    p.add_argument("--source-commit", required=True)
    p.add_argument("--cargo-lock-sha256", required=True)
    p.add_argument("--workflow-run-id", required=True)
    p.add_argument("--result", type=Path, required=True)
    a = p.parse_args()
    if (
        a.result != RESULT
        or a.backend not in BACKENDS
        or not COMMIT.fullmatch(a.source_commit)
        or not DIGEST.fullmatch(a.cargo_lock_sha256)
        or not RUN_ID.fullmatch(a.workflow_run_id)
    ):
        raise SystemExit("invalid fixed canary invocation")
    try:
        for candidate in (ROOT, RUNNER, ADAPTER, SANDBOX, CANDIDATE):
            validate_protected_path(candidate, candidate != ROOT)
        validate_protected_path(APPROVAL_KEYRING)
        validate_protected_path(LEDGER.parent, directory=True)
        validate_candidate_approval(a)
        load_sandbox_policy()
        cap = load_payment_cap(a.backend)
    except (OSError, ValueError) as exc:
        raise SystemExit(
            "protected deployment unavailable; no invoice created"
        ) from exc
    key = attempt_key(a)
    try:
        if not transition({"attempt_key": key, "state": "claimed"}):
            raise SystemExit("attempt already claimed; permanently refusing retry")
    except ValueError as exc:
        raise SystemExit("durable claim unavailable; no invoice created") from exc
    try:
        probe = run_candidate()
    except (OSError, subprocess.TimeoutExpired) as exc:
        transition({"attempt_key": key, "state": "unsubmitted_released"})
        raise SystemExit("candidate unavailable before invoice creation") from exc
    if (
        probe.returncode
        or probe.stdout != b'{"qualification_request":"candidate-probe-v1"}\n'
    ):
        transition({"attempt_key": key, "state": "unsubmitted_released"})
        raise SystemExit("candidate probe refused before invoice creation")
    try:
        submitted = run_adapter(a, key, cap)
        if submitted.returncode:
            raise ValueError("adapter returned nonzero")
        terminal = validate_local_result(a, key, cap)
        if not transition({"attempt_key": key, "state": terminal}):
            raise ValueError("durable terminal transition rejected")
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        # We cannot distinguish a crash from a partially submitted payment.
        try:
            transition(
                {"attempt_key": key, "state": "submitted_unknown_permanent_no_retry"}
            )
        except ValueError:
            pass
        raise SystemExit(
            "adapter outcome ambiguous; permanently refusing retry"
        ) from exc
    if terminal != "succeeded":
        raise SystemExit("trusted adapter reported definite failure")


if __name__ == "__main__":
    main()
