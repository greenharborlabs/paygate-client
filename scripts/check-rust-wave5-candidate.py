#!/usr/bin/env python3
"""Fail-closed, offline validation for a redacted Wave 5 evidence candidate."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

TARGETS = {
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
}
REQUIRED_CANARY_BACKENDS = {"breez-mainnet-canary"}
SHA256, COMMIT = re.compile(r"[0-9a-f]{64}"), re.compile(r"[0-9a-f]{40}")
DIGEST_SCOPE = "archive subject SHA-256; not a GitHub-attestation ID"
WORKFLOWS = {
    "integration": (
        "Rust integration qualification",
        "rust-integration-qualification.yml",
    ),
    "native": ("Rust native platform qualification", "rust-platform.yml"),
    "canary": (
        "Rust payment canaries (protected runner control plane)",
        "rust-payment-canary.yml",
    ),
}


def fail(message):
    raise ValueError(message)


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label}: unexpected or missing fields")
    return value


def strict_epoch(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{label}: invalid epoch")
    return value


def run_id(value, label):
    if not isinstance(value, str) or not value.isdigit() or int(value) <= 0:
        fail(f"{label}: invalid run id")
    return value


def rfc3339_epoch(value, label):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:Z|[+-]\d\d:\d\d)", value
    ):
        fail(f"{label}: timestamp must be RFC3339 with UTC offset")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label}: malformed timestamp")
    if parsed.tzinfo is None:
        fail(f"{label}: timestamp must have UTC offset")
    return int(parsed.astimezone(timezone.utc).timestamp())


def source_run(value, repository, kind, label, now):
    value = exact(
        value,
        {
            "run_id",
            "url",
            "workflow_name",
            "workflow_file",
            "started_at_epoch",
            "completed_at_epoch",
        },
        label + " source_run",
    )
    ident = run_id(value["run_id"], label)
    name, filename = WORKFLOWS[kind]
    if (
        value["url"] != f"https://github.com/{repository}/actions/runs/{ident}"
        or value["workflow_name"] != name
        or value["workflow_file"] != filename
    ):
        fail(f"{label}: source run binding mismatch")
    started, completed = (
        strict_epoch(value["started_at_epoch"], label),
        strict_epoch(value["completed_at_epoch"], label),
    )
    if started > completed or completed > now or now - completed > 86400:
        fail(f"{label}: stale, future, or invalid source run interval")
    return ident, started, completed


def within(value, interval, label):
    if not interval[0] <= value <= interval[1]:
        fail(f"{label}: timestamp outside source run interval")


def safe_path(value, root, label):
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        fail(f"{label}: unsafe path")
    path = (root / value).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        fail(f"{label}: path escapes evidence root")
    return path


def file_binding(value, root, label):
    value = exact(value, {"path", "sha256"}, label)
    path = safe_path(value["path"], root, label)
    if (
        not path.is_file()
        or not isinstance(value["sha256"], str)
        or SHA256.fullmatch(value["sha256"]) is None
        or hashlib.sha256(path.read_bytes()).hexdigest() != value["sha256"]
    ):
        fail(f"{label}: invalid artifact binding")
    return value


def trusted_binding(value, expected, root, label):
    binding = file_binding(value, root, label)
    if safe_path(binding["path"], root, label) != expected.resolve():
        fail(f"{label}: trusted path mismatch")
    return binding


def identity(record, source, lock, run, label):
    if (
        record["source_commit"] != source
        or record["cargo_lock_sha256"] != lock
        or record["workflow_run_id"] != run
    ):
        fail(f"{label}: source/lock/run identity mismatch")


def validate(
    candidate, root, checker, contract, result_keyring, ledger_keyring, repository, now
):
    candidate = exact(
        candidate,
        {
            "schema_version",
            "source_commit",
            "cargo_lock_sha256",
            "integration",
            "native_records",
            "canary_records",
        },
        "candidate",
    )
    if (
        candidate["schema_version"] != 3
        or not isinstance(candidate["source_commit"], str)
        or COMMIT.fullmatch(candidate["source_commit"]) is None
        or not isinstance(candidate["cargo_lock_sha256"], str)
        or SHA256.fullmatch(candidate["cargo_lock_sha256"]) is None
    ):
        fail("candidate: invalid schema or identity")
    source, lock = candidate["source_commit"], candidate["cargo_lock_sha256"]
    records = []
    integration = exact(
        candidate["integration"],
        {
            "record_schema",
            "status",
            "workflow",
            "workflow_run_id",
            "source_commit",
            "cargo_lock_sha256",
            "source_run",
            "bundle",
            "metadata",
        },
        "integration",
    )
    iid, istart, iend = source_run(
        integration["source_run"], repository, "integration", "integration", now
    )
    if (
        integration["record_schema"] != "wave5-integration-v1"
        or integration["status"] != "success"
        or integration["workflow"] != WORKFLOWS["integration"][1]
    ):
        fail("integration: invalid schema/status/workflow")
    identity(integration, source, lock, iid, "integration")
    bundle = file_binding(integration["bundle"], root, "integration bundle")
    metadata = exact(
        integration["metadata"],
        {
            "schema_version",
            "subject_name",
            "archive_subject_sha256",
            "digest_scope",
            "retention_days",
            "source_commit",
            "workflow_run_id",
            "observed_at_epoch",
        },
        "integration metadata",
    )
    if (
        metadata["schema_version"] != 2
        or metadata["subject_name"] != "semantic-evidence-bundle.tar.gz"
        or metadata["archive_subject_sha256"] != bundle["sha256"]
        or metadata["digest_scope"] != DIGEST_SCOPE
        or metadata["retention_days"] != 90
        or metadata["source_commit"] != source
        or metadata["workflow_run_id"] != iid
    ):
        fail("integration: metadata binding mismatch")
    within(
        strict_epoch(metadata["observed_at_epoch"], "integration metadata"),
        (istart, iend),
        "integration metadata",
    )
    records.append(
        {
            "id": "integration",
            "evidence_type": "integration",
            "source_run": integration["source_run"],
            "age_at_acceptance_seconds": now - iend,
            "provenance": {
                "kind": "github-slsa-v1",
                "bundle_sha256": bundle["sha256"],
                "metadata_sha256": hashlib.sha256(canonical_json(metadata)).hexdigest(),
                "signer_workflow": WORKFLOWS["integration"][1],
            },
        }
    )
    native = candidate["native_records"]
    if not isinstance(native, list) or len(native) != 4:
        fail("candidate: exactly four native records are required")
    seen = set()
    for record in native:
        record = exact(
            record,
            {
                "record_schema",
                "status",
                "target",
                "workflow",
                "workflow_run_id",
                "source_commit",
                "cargo_lock_sha256",
                "source_run",
                "runner_identity",
                "provenance",
                "bundle",
                "qualification_manifest",
                "runtime_evidence",
            },
            "native",
        )
        rid, start, end = source_run(
            record["source_run"], repository, "native", "native", now
        )
        if (
            record["record_schema"] != "wave5-native-v1"
            or record["status"] != "success"
            or record["workflow"] != WORKFLOWS["native"][1]
            or record["provenance"] != "github-attestation:slsa-v1"
            or not isinstance(record["runner_identity"], str)
            or not record["runner_identity"]
        ):
            fail("native: invalid record")
        identity(record, source, lock, rid, "native")
        if record["target"] not in TARGETS or record["target"] in seen:
            fail("native: unknown or duplicate target")
        seen.add(record["target"])
        file_binding(record["bundle"], root, "native bundle")
        q = exact(
            record["qualification_manifest"],
            {
                "target",
                "artifact_sha256",
                "binary_sha256",
                "source_commit",
                "cargo_lock_sha256",
                "builder_runner_identity",
                "workflow_run_id",
            },
            "native qualification manifest",
        )
        if (
            any(
                q[k] != record[k]
                for k in (
                    "target",
                    "source_commit",
                    "cargo_lock_sha256",
                    "workflow_run_id",
                )
            )
            or q["builder_runner_identity"] != record["runner_identity"]
            or any(
                not isinstance(q[k], str) or SHA256.fullmatch(q[k]) is None
                for k in ("artifact_sha256", "binary_sha256")
            )
        ):
            fail("native: attested manifest mismatch")
        bundle_binding = file_binding(record["bundle"], root, "native bundle")
        evidence = file_binding(
            record["runtime_evidence"], root, "native runtime evidence"
        )
        try:
            runtime = json.loads(
                safe_path(evidence["path"], root, "native runtime evidence").read_text()
            )
        except (OSError, json.JSONDecodeError):
            fail("native: malformed runtime evidence")
        runtime = exact(
            runtime,
            {
                "target",
                "artifact_sha256",
                "binary_sha256",
                "source_commit",
                "cargo_lock_sha256",
                "builder_runner_identity",
                "workflow_run_id",
                "status",
                "observed_at_epoch",
                "executor_runner_identity",
                "provenance",
            },
            "native runtime evidence",
        )
        if (
            any(runtime[k] != q[k] for k in q)
            or runtime["status"] != "success"
            or runtime["provenance"] != "github-attestation:slsa-v1"
            or not isinstance(runtime["executor_runner_identity"], str)
            or not runtime["executor_runner_identity"]
        ):
            fail("native: runtime evidence mismatch")
        if (
            not isinstance(runtime["observed_at_epoch"], str)
            or not runtime["observed_at_epoch"].isdigit()
        ):
            fail("native: invalid observed timestamp")
        within(
            int(runtime["observed_at_epoch"]), (start, end), "native runtime evidence"
        )
        records.append(
            {
                "id": "native:" + record["target"],
                "evidence_type": "native",
                "source_run": record["source_run"],
                "age_at_acceptance_seconds": now - end,
                "provenance": {
                    "kind": "github-slsa-v1",
                    "bundle_sha256": bundle_binding["sha256"],
                    "runtime_evidence_sha256": evidence["sha256"],
                    "signer_workflow": WORKFLOWS["native"][1],
                },
            }
        )
    if seen != TARGETS:
        fail("native: incomplete target set")
    canaries = candidate["canary_records"]
    if not isinstance(canaries, list) or len(canaries) != 1:
        fail("candidate: exactly one Breez canary record is required")
    seen = set()
    for record in canaries:
        record = exact(
            record,
            {
                "record_schema",
                "status",
                "backend",
                "workflow",
                "workflow_run_id",
                "source_commit",
                "cargo_lock_sha256",
                "source_run",
                "runner_identity",
                "artifact",
                "gate_logic",
            },
            "canary",
        )
        rid, start, end = source_run(
            record["source_run"], repository, "canary", "canary", now
        )
        if (
            record["record_schema"] != "wave5-canary-v2"
            or record["status"] != "succeeded"
            or record["workflow"] != WORKFLOWS["canary"][1]
            or not isinstance(record["runner_identity"], str)
            or not record["runner_identity"]
        ):
            fail("canary: invalid record")
        identity(record, source, lock, rid, "canary")
        if (
            record["backend"] not in REQUIRED_CANARY_BACKENDS
            or record["backend"] in seen
        ):
            fail("canary: unknown or duplicate backend")
        seen.add(record["backend"])
        artifact = file_binding(record["artifact"], root, "canary artifact")
        gate = exact(
            record["gate_logic"],
            {"checker", "contract", "result_keyring", "ledger_keyring"},
            "canary gate logic",
        )
        for value, expected, label in (
            (gate["checker"], checker, "checker"),
            (gate["contract"], contract, "contract"),
            (gate["result_keyring"], result_keyring, "result keyring"),
            (gate["ledger_keyring"], ledger_keyring, "ledger keyring"),
        ):
            trusted_binding(value, expected, root, "canary " + label)
        command = [
            sys.executable,
            str(checker),
            str(safe_path(artifact["path"], root, "canary artifact")),
            "--contract",
            str(contract),
            "--backend",
            record["backend"],
            "--source-commit",
            source,
            "--cargo-lock-sha256",
            lock,
            "--workflow-run-id",
            rid,
        ]
        if subprocess.run(command, cwd=root, capture_output=True).returncode != 0:
            fail("canary: signed result verification failed")
        try:
            signed = json.loads(
                safe_path(artifact["path"], root, "canary artifact").read_text()
            )
        except (OSError, json.JSONDecodeError):
            fail("canary: malformed signed result")
        receipt = signed.get("durable_receipt") if isinstance(signed, dict) else None
        if not isinstance(receipt, dict):
            fail("canary: missing durable receipt")
        issued, recorded = (
            rfc3339_epoch(signed.get("issued_at"), "canary issued_at"),
            rfc3339_epoch(receipt.get("recorded_at"), "canary recorded_at"),
        )
        if issued > recorded:
            fail("canary: issued after receipt")
        within(issued, (start, end), "canary issued_at")
        within(recorded, (start, end), "canary recorded_at")
        records.append(
            {
                "id": "canary:" + record["backend"],
                "evidence_type": "canary",
                "source_run": record["source_run"],
                "age_at_acceptance_seconds": now - end,
                "provenance": {
                    "kind": "signed-canary-v1",
                    "result_sha256": artifact["sha256"],
                    "result_key_id": signed.get("key_id"),
                    "ledger_key_id": receipt.get("key_id"),
                    "runner_identity": signed.get("runner_identity"),
                },
            }
        )
    if seen != REQUIRED_CANARY_BACKENDS:
        fail("canary: incomplete backend set")
    records.sort(key=lambda item: item["id"])
    return {
        "schema_version": 1,
        "repository": repository,
        "source_commit": source,
        "cargo_lock_sha256": lock,
        "accepted_at_epoch": now,
        "records": records,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--canary-checker", type=Path, required=True)
    parser.add_argument("--canary-contract", type=Path, required=True)
    parser.add_argument("--result-keyring", type=Path, required=True)
    parser.add_argument("--ledger-keyring", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--now-epoch", required=True)
    parser.add_argument("--evidence-index-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
            fail("repository: invalid owner/name")
        if not re.fullmatch(r"0|[1-9][0-9]*", args.now_epoch):
            fail("now epoch: invalid integer")
        now = int(args.now_epoch)
        root = args.evidence_root.resolve()
        for path, label in (
            (args.canary_checker, "checker"),
            (args.canary_contract, "contract"),
            (args.result_keyring, "result keyring"),
            (args.ledger_keyring, "ledger keyring"),
        ):
            if not path.is_file():
                fail(f"trusted {label} missing")
            path.resolve().relative_to(root)
        index = validate(
            json.loads(args.candidate.read_text()),
            root,
            args.canary_checker.resolve(),
            args.canary_contract.resolve(),
            args.result_keyring.resolve(),
            args.ledger_keyring.resolve(),
            args.repository,
            now,
        )
        args.evidence_index_output.unlink(missing_ok=True)
        args.evidence_index_output.write_bytes(canonical_json(index))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        args.evidence_index_output.unlink(missing_ok=True)
        print(f"Wave 5 candidate rejected: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(
        canonical_json(
            {
                "status": "accepted",
                "accepted_at_epoch": now,
                "candidate_manifest_sha256": hashlib.sha256(
                    canonical_json(json.loads(args.candidate.read_text()))
                ).hexdigest(),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
