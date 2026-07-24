#!/usr/bin/env python3
"""Fail-closed verification for the Wave 5 qualification report."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

BEGIN = "<!-- BEGIN WAVE5 ACCEPTED EVIDENCE -->"
END = "<!-- END WAVE5 ACCEPTED EVIDENCE -->"
MARKER_RE = re.compile(rb"<!-- (?:BEGIN|END) WAVE5[ -]ACCEPTED[ -]EVIDENCE -->")


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def fail(message):
    raise ValueError(message)


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
CANONICAL_IDENTIFIER = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._:@+-]{0,126}[A-Za-z0-9])?\Z"
)
IDENTIFIER_DELIMITER = re.compile(r"[-._:@+]+")
PLACEHOLDER_COMPONENTS = {
    "placeholder",
    "todo",
    "tbd",
    "pending",
    "changeme",
    "dummy",
    "example",
    "unknown",
}
TARGETS = {
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
}
MAX_EVIDENCE_AGE_SECONDS = 86_400
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


def nonnegative_epoch(argument):
    if re.fullmatch(r"[0-9]+", argument) is None:
        raise argparse.ArgumentTypeError("must be a nonnegative decimal integer")
    return int(argument)


def epoch(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(label + " must be a nonnegative integer")
    return value


def digest(value, label):
    if (
        not isinstance(value, str)
        or SHA256.fullmatch(value) is None
        or value == "0" * 64
    ):
        fail(label + " must be a non-placeholder lowercase SHA-256")
    return value


def canonical_identifier(value, label):
    if not isinstance(value, str) or CANONICAL_IDENTIFIER.fullmatch(value) is None:
        fail(label + " must be a canonical identifier of at most 128 characters")
    components = IDENTIFIER_DELIMITER.split(value.lower())
    if (
        value.lower() == "replace-me"
        or any(component in PLACEHOLDER_COMPONENTS for component in components)
        or any(
            pair == ["replace", "me"]
            for pair in (
                components[index : index + 2] for index in range(len(components) - 1)
            )
        )
    ):
        fail(label + " contains a placeholder identifier")
    return value


def validate_index(value, publication_epoch):
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "repository",
        "source_commit",
        "cargo_lock_sha256",
        "accepted_at_epoch",
        "records",
    }:
        fail("index has unexpected or missing fields")
    repository = value["repository"]
    if (
        isinstance(value["schema_version"], bool)
        or not isinstance(value["schema_version"], int)
        or value["schema_version"] != 1
        or not isinstance(repository, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
    ):
        fail("index schema or repository invalid")
    if (
        not isinstance(value["source_commit"], str)
        or SHA40.fullmatch(value["source_commit"]) is None
    ):
        fail("index source commit invalid")
    digest(value["cargo_lock_sha256"], "index lock digest")
    accepted = epoch(value["accepted_at_epoch"], "index accepted time")
    if accepted > publication_epoch:
        fail("index acceptance time is in the future at publication")
    records = value["records"]
    if not isinstance(records, list) or len(records) != 6:
        fail("index requires exactly six records")
    expected_ids = {
        "integration",
        "canary:breez-mainnet-canary",
    } | {"native:" + target for target in TARGETS}
    seen = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "id",
            "evidence_type",
            "source_run",
            "age_at_acceptance_seconds",
            "provenance",
        }:
            fail("index record fields invalid")
        record_id, kind = record["id"], record["evidence_type"]
        if (
            not isinstance(record_id, str)
            or record_id in seen
            or record_id not in expected_ids
        ):
            fail("index record ID invalid")
        seen.add(record_id)
        expected_kind = (
            "integration"
            if record_id == "integration"
            else "native"
            if record_id.startswith("native:")
            else "canary"
        )
        if kind != expected_kind:
            fail("index evidence type invalid")
        run = record["source_run"]
        if not isinstance(run, dict) or set(run) != {
            "run_id",
            "url",
            "workflow_name",
            "workflow_file",
            "started_at_epoch",
            "completed_at_epoch",
        }:
            fail("index source run fields invalid")
        run_id = run["run_id"]
        if not isinstance(run_id, str) or not re.fullmatch(r"[1-9][0-9]*", run_id):
            fail("index source run ID invalid")
        name, filename = WORKFLOWS[expected_kind]
        if (
            run["url"] != f"https://github.com/{repository}/actions/runs/{run_id}"
            or run["workflow_name"] != name
            or run["workflow_file"] != filename
        ):
            fail("index source run binding invalid")
        started, completed = (
            epoch(run["started_at_epoch"], "index source start"),
            epoch(run["completed_at_epoch"], "index source completion"),
        )
        if started > completed or completed > accepted:
            fail("index source run interval invalid")
        record_age = epoch(record["age_at_acceptance_seconds"], "index record age")
        if record_age != accepted - completed or record_age > MAX_EVIDENCE_AGE_SECONDS:
            fail("index record age invalid or outside freshness policy")
        publication_age = publication_epoch - completed
        if publication_age < 0 or publication_age > MAX_EVIDENCE_AGE_SECONDS:
            fail("index source completion is future or stale at publication")
        provenance = record["provenance"]
        if not isinstance(provenance, dict):
            fail("index provenance invalid")
        if expected_kind == "integration":
            if (
                set(provenance)
                != {"kind", "bundle_sha256", "metadata_sha256", "signer_workflow"}
                or provenance.get("kind") != "github-slsa-v1"
                or provenance.get("signer_workflow") != filename
            ):
                fail("integration provenance invalid")
            digest(provenance["bundle_sha256"], "integration bundle digest")
            digest(provenance["metadata_sha256"], "integration metadata digest")
        elif expected_kind == "native":
            if (
                set(provenance)
                != {
                    "kind",
                    "bundle_sha256",
                    "runtime_evidence_sha256",
                    "signer_workflow",
                }
                or provenance.get("kind") != "github-slsa-v1"
                or provenance.get("signer_workflow") != filename
            ):
                fail("native provenance invalid")
            digest(provenance["bundle_sha256"], "native bundle digest")
            digest(provenance["runtime_evidence_sha256"], "native runtime digest")
        else:
            if (
                set(provenance)
                != {
                    "kind",
                    "result_sha256",
                    "result_key_id",
                    "ledger_key_id",
                    "runner_identity",
                }
                or provenance.get("kind") != "signed-canary-v1"
            ):
                fail("canary provenance invalid")
            digest(provenance["result_sha256"], "canary result digest")
            for key in ("result_key_id", "ledger_key_id", "runner_identity"):
                canonical_identifier(provenance[key], "canary " + key)
    if seen != expected_ids:
        fail("index record set incomplete")
    return repository


def verified_json(path, checksum_path, label):
    content = path.read_bytes()
    value = json.loads(content)
    if content != canonical(value):
        fail(label + " is not canonical")
    expected = hashlib.sha256(content).hexdigest()
    checksum = checksum_path.read_text(encoding="utf-8")
    if checksum != f"{expected}  {path.name}\n":
        fail("invalid " + label + " checksum")
    return value, content, expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--candidate-sha256", type=Path)
    parser.add_argument("--index", type=Path)
    parser.add_argument("--index-sha256", type=Path)
    parser.add_argument("--envelope", type=Path)
    parser.add_argument("--envelope-sha256", type=Path)
    parser.add_argument("--validator-result", type=Path)
    parser.add_argument("--validator-result-sha256", type=Path)
    parser.add_argument("--publication-epoch", type=nonnegative_epoch)
    args = parser.parse_args()
    try:
        accepted_arguments = (
            args.candidate,
            args.candidate_sha256,
            args.index,
            args.index_sha256,
            args.envelope,
            args.envelope_sha256,
            args.validator_result,
            args.validator_result_sha256,
            args.publication_epoch,
        )
        report = args.report.read_bytes()
        if all(argument is None for argument in accepted_arguments):
            if (
                MARKER_RE.search(report)
                or b"accepted evidence" in report.lower()
                or b"accepted-evidence" in report.lower()
            ):
                fail("pending report contains accepted evidence marker")
            if b"No Wave 5 candidate has been accepted." not in report:
                fail("pending report is not explicit")
            return 0
        if any(argument is None for argument in accepted_arguments):
            fail("accepted report verification requires every artifact and checksum")
        candidate_value, _, candidate_digest = verified_json(
            args.candidate, args.candidate_sha256, "candidate manifest"
        )
        value, index_bytes, expected = verified_json(
            args.index, args.index_sha256, "evidence index"
        )
        envelope_value, _, _ = verified_json(
            args.envelope, args.envelope_sha256, "acceptance envelope"
        )
        validator_value, _, validator_digest = verified_json(
            args.validator_result,
            args.validator_result_sha256,
            "validator result",
        )
        repository = validate_index(value, args.publication_epoch)
        if (
            not isinstance(candidate_value, dict)
            or candidate_value.get("schema_version") != 3
            or isinstance(candidate_value.get("schema_version"), bool)
            or candidate_value.get("source_commit") != value["source_commit"]
            or candidate_value.get("cargo_lock_sha256") != value["cargo_lock_sha256"]
        ):
            fail("candidate manifest does not bind index source identity")
        if not isinstance(validator_value, dict) or set(validator_value) != {
            "status",
            "accepted_at_epoch",
            "candidate_manifest_sha256",
        }:
            fail("validator result fields invalid")
        validator_epoch = epoch(
            validator_value["accepted_at_epoch"], "validator acceptance time"
        )
        if (
            validator_value["status"] != "accepted"
            or validator_epoch != value["accepted_at_epoch"]
            or validator_value["candidate_manifest_sha256"] != candidate_digest
        ):
            fail("validator result does not bind candidate and acceptance clock")
        envelope_fields = {
            "schema_version",
            "repository",
            "acceptance_run_id",
            "acceptance_run_url",
            "generated_at_epoch",
            "candidate_manifest_sha256",
            "evidence_index_sha256",
            "validator_result_sha256",
        }
        if (
            not isinstance(envelope_value, dict)
            or set(envelope_value) != envelope_fields
        ):
            fail("acceptance envelope fields invalid")
        run_id = envelope_value["acceptance_run_id"]
        acceptance_url = f"https://github.com/{repository}/actions/runs/{run_id}"
        generated_at = epoch(
            envelope_value["generated_at_epoch"], "envelope generation time"
        )
        if (
            isinstance(envelope_value["schema_version"], bool)
            or envelope_value["schema_version"] != 1
            or envelope_value["repository"] != repository
            or not isinstance(run_id, str)
            or re.fullmatch(r"[1-9][0-9]*", run_id) is None
            or envelope_value["acceptance_run_url"] != acceptance_url
            or generated_at != value["accepted_at_epoch"]
            or envelope_value["candidate_manifest_sha256"] != candidate_digest
            or envelope_value["evidence_index_sha256"] != expected
            or envelope_value["validator_result_sha256"] != validator_digest
        ):
            fail("acceptance envelope does not bind canonical artifact set")
        if (
            len(MARKER_RE.findall(report)) != 2
            or report.count(BEGIN.encode()) != 1
            or report.count(END.encode()) != 1
        ):
            fail("accepted region must use exactly one canonical marker pair")
        start, end = report.index(BEGIN.encode()), report.index(END.encode())
        if start >= end:
            fail("invalid marker order")
        prefix, region, suffix = (
            report[:start],
            report[start + len(BEGIN) : end],
            report[end + len(END) :],
        )
        block = b"```json\n" + index_bytes + b"\n```\n"
        expected_region = (
            b"\n"
            + block
            + f"{expected}  {args.index.name}\n{acceptance_url}\n".encode()
        )
        if region != expected_region:
            fail("accepted region has invalid index, checksum, or URL")
        if re.search(rb"\baccepted\b", prefix + suffix, re.IGNORECASE):
            fail("accepted wording outside valid accepted block")
    except (OSError, json.JSONDecodeError, ValueError, KeyError) as exc:
        print(f"Wave 5 qualification report rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
