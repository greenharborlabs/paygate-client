"""Hermetic acceptance tests for the full Rust qualification evidence gate."""

import json
import os
import re
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / ".github/actions/aggregate-rust-qualification/action.yml"
WORKFLOW = ROOT / ".github/workflows/rust-qualification.yml"
TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)
COMMIT = "a" * 40
LOCK = "b" * 64
RUN_ID = "123456"
RUN_ATTEMPT = "1"


def validator_source() -> str:
    action = ACTION.read_text(encoding="utf-8")
    heredoc_start = "        python3 - <<'PY'\n"
    start = action.index(heredoc_start) + len(heredoc_start)
    end = action.index("        PY\n", start)
    return "\n".join(line[8:] for line in action[start:end].splitlines()) + "\n"


def record(target: str) -> dict:
    return {
        "schema_version": 1,
        "target": target,
        "source_commit": COMMIT,
        "cargo_lock_sha256": LOCK,
        "runner_identity": "native-runner",
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "binary_sha256": "c" * 64,
        "observed_platform": {
            "architecture": "x86_64",
            "os": "Linux",
            "runtime_floor": "glibc-2.31",
        },
        "checks": {
            name: "success"
            for name in (
                "breez_lifecycle",
                "native_keyring",
                "locked_offline_build",
                "linkage",
                "cli_runtime",
            )
        },
        "observed_at_epoch": int(time.time()),
    }


def write_records(directory: Path, mutate=None) -> None:
    for target in TARGETS:
        item = record(target)
        if mutate:
            mutate(target, item)
        path = directory / f"qualification-evidence-{target}.json"
        path.write_text(json.dumps(item), encoding="utf-8")


def run_validator(directory: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ | {
        "EVIDENCE_DIRECTORY": str(directory),
        "EXPECTED_SOURCE_COMMIT": COMMIT,
        "EXPECTED_RUN_ID": RUN_ID,
        "EXPECTED_RUN_ATTEMPT": RUN_ATTEMPT,
        "EXPECTED_CARGO_LOCK_SHA256": LOCK,
        "MAX_AGE_SECONDS": "86400",
    }
    return subprocess.run(
        ["python3", "-c", validator_source()],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def test_real_validator_accepts_complete_four_target_evidence(tmp_path: Path) -> None:
    write_records(tmp_path)
    result = run_validator(tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("target", TARGETS)
def test_real_validator_rejects_missing_target(tmp_path: Path, target: str) -> None:
    write_records(tmp_path)
    (tmp_path / f"qualification-evidence-{target}.json").unlink()
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert target in result.stderr


def test_real_validator_rejects_duplicate_json_target_identity(tmp_path: Path) -> None:
    def mutate(target, item):
        if target == TARGETS[0]:
            item["target"] = TARGETS[1]

    write_records(tmp_path, mutate)
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert TARGETS[1] in result.stderr
    assert "duplicate target" in result.stderr


def test_real_validator_rejects_future_timestamp(tmp_path: Path) -> None:
    def mutate(target, item):
        if target == TARGETS[0]:
            item["observed_at_epoch"] = int(time.time()) + 3600

    write_records(tmp_path, mutate)
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert TARGETS[0] in result.stderr
    assert "observed_at_epoch" in result.stderr


@pytest.mark.parametrize("outcome", ("skipped", "timed-out"))
def test_real_validator_rejects_skipped_or_timed_out_check(
    tmp_path: Path, outcome: str
) -> None:
    def mutate(target, item):
        if target == TARGETS[0]:
            item["checks"]["cli_runtime"] = outcome

    write_records(tmp_path, mutate)
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert TARGETS[0] in result.stderr
    assert "checks" in result.stderr


def test_real_validator_rejects_missing_named_check(tmp_path: Path) -> None:
    def mutate(target, item):
        if target == TARGETS[0]:
            del item["checks"]["linkage"]

    write_records(tmp_path, mutate)
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert TARGETS[0] in result.stderr
    assert "checks" in result.stderr


def test_real_validator_rejects_json_target_file_target_mismatch(
    tmp_path: Path,
) -> None:
    def mutate(target, item):
        if target == TARGETS[0]:
            item["target"] = TARGETS[1]

    write_records(tmp_path, mutate)
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert TARGETS[0] in result.stderr
    assert "target/file mismatch" in result.stderr


@pytest.mark.parametrize(
    ("field", "value", "diagnostic"),
    (
        ("source_commit", "d" * 40, "mixed source_commit"),
        ("cargo_lock_sha256", "e" * 64, "mixed cargo_lock_sha256"),
        ("source_commit", "invalid", "source_commit"),
        ("cargo_lock_sha256", "invalid", "cargo_lock_sha256"),
    ),
)
def test_real_validator_rejects_mixed_or_invalid_commit_and_lock(
    tmp_path: Path, field: str, value: str, diagnostic: str
) -> None:
    def mutate(target, item):
        if target == TARGETS[0]:
            item[field] = value

    write_records(tmp_path, mutate)
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert TARGETS[0] in result.stderr
    assert diagnostic in result.stderr


@pytest.mark.parametrize(
    ("field", "value", "diagnostic"),
    [
        ("schema_version", 2, "schema_version"),
        ("source_commit", "f" * 40, "source_commit"),
        ("cargo_lock_sha256", "d" * 64, "mixed cargo_lock_sha256"),
        ("runner_identity", "", "runner_identity"),
        ("run_id", "wrong", "run_id"),
        ("run_attempt", "2", "run_attempt"),
        ("binary_sha256", "not-a-hash", "binary_sha256"),
        ("observed_at_epoch", 0, "observed_at_epoch"),
    ],
)
def test_real_validator_rejects_identity_mutations(
    tmp_path: Path, field: str, value: object, diagnostic: str
) -> None:
    def mutate(target, item):
        if target == TARGETS[0]:
            item[field] = value

    write_records(tmp_path, mutate)
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert TARGETS[0] in result.stderr
    assert diagnostic in result.stderr


@pytest.mark.parametrize(
    "check",
    (
        "breez_lifecycle",
        "native_keyring",
        "locked_offline_build",
        "linkage",
        "cli_runtime",
    ),
)
def test_real_validator_rejects_every_named_check(tmp_path: Path, check: str) -> None:
    def mutate(target, item):
        if target == TARGETS[0]:
            item["checks"][check] = "failed"

    write_records(tmp_path, mutate)
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert TARGETS[0] in result.stderr
    assert "checks" in result.stderr


@pytest.mark.parametrize("status", ("failed", "skipped", "timed-out"))
def test_status_or_secret_shaped_unknown_field_fails_closed_without_echo(
    tmp_path: Path, status: str
) -> None:
    secret = "mnemonic-do-not-echo"

    def mutate(target, item):
        if target == TARGETS[0]:
            item["checks"]["cli_runtime"] = status
            item["mnemonic"] = secret

    write_records(tmp_path, mutate)
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert secret not in result.stderr
    assert "schema fields" in result.stderr


def test_real_validator_rejects_unexpected_target_and_malformed_json(
    tmp_path: Path,
) -> None:
    write_records(tmp_path)
    malformed = tmp_path / "qualification-evidence-x86_64-unknown-linux-gnu.json"
    malformed.write_text("{broken", encoding="utf-8")
    unexpected = tmp_path / "qualification-evidence-unexpected-target.json"
    unexpected.write_text("{}", encoding="utf-8")
    result = run_validator(tmp_path)
    assert result.returncode != 0
    assert "JSON" in result.stderr
    assert "unexpected-target" in result.stderr


def test_workflow_writes_only_after_named_checks_and_gate_requires_aggregation() -> (
    None
):
    workflow = WORKFLOW.read_text(encoding="utf-8")
    evidence_position = workflow.index(
        "- name: Write immutable native qualification evidence"
    )
    for marker in (
        "connect_readiness_prepare_disconnect_without_send",
        "keyring_qualification",
        "build --locked --offline --release",
        "scripts/check-rust-linkage.py",
        '"$binary" --version',
    ):
        assert workflow.index(marker) < evidence_position
    flow_start = workflow.index("  native-qualification:")
    flow_end = workflow.index("  qualification-gate:")
    evidence_flow = workflow[flow_start:flow_end]
    pinned_actions = re.findall(r"uses: (actions/[^@\s]+)@([^\s#]+)", evidence_flow)
    assert {name for name, _ in pinned_actions} == {
        "actions/checkout",
        "actions/download-artifact",
        "actions/upload-artifact",
    }
    for action, revision in pinned_actions:
        assert re.fullmatch(r"[0-9a-f]{40}", revision), action
    gate_needs = (
        "needs: [dependency-policy, native-qualification, "
        "aggregate-qualification-evidence]"
    )
    assert gate_needs in workflow
    assert 'test "$EVIDENCE_RESULT" = success' in workflow
