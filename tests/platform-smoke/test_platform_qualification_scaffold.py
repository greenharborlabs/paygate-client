"""Structural checks for the Rust platform-qualification workflow scaffold.

These deliberately inspect repository configuration: native runners and GitHub
artifacts are unavailable to unit tests and must never be faked locally.
"""

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/rust-platform.yml"
DOCS = ROOT / "docs/platform-qualification.md"
RUNNERS = ROOT / "infra/runners/platform-qualification.yml"
ACTION = ROOT / ".github/actions/aggregate-rust-platform/action.yml"
STUB = ROOT / "tests/platform-smoke/stub"

TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)


def read(path: Path) -> str:
    assert path.is_file(), f"missing qualification scaffold: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def embedded_python(source: str, marker: str) -> str:
    """Return a quoted workflow/action Python program so its behavior is testable."""
    start = source.index(marker) + len(marker)
    terminator = re.search(r"\n\s+PY\s*$", source[start:], re.MULTILINE)
    assert terminator, "embedded Python terminator is missing"
    return textwrap.dedent(source[start : start + terminator.start()])


def test_qualification_matrix_uses_available_native_hosted_runners() -> None:
    workflow = read(WORKFLOW)
    docs = read(DOCS)
    runners = read(RUNNERS)

    for target in TARGETS:
        assert target in workflow
        assert target in docs
        assert target in runners
    assert "glibc >= 2.31" in docs
    assert "macOS >= 15" in docs
    assert "emulation cannot qualify" in docs.lower()
    assert "provisioning_status: ready" in runners
    assert "macos-latest" not in workflow
    assert "self-hosted" not in workflow
    for label in ("ubuntu-22.04", "ubuntu-22.04-arm", "macos-15-intel", "macos-15"):
        assert label in workflow
        assert label in runners
    assert (
        "rust@sha256:b315f988b86912bafa7afd39a6ded0a497bf850ec36578ca9a3bdd6a14d5db4e"
        in workflow
    )
    assert 'test "$(getconf GNU_LIBC_VERSION)" = "glibc 2.31"' in workflow
    assert (STUB / "Cargo.toml").is_file()
    assert (STUB / "Cargo.lock").is_file()
    assert (STUB / "src/main.rs").is_file()
    assert '--manifest-path "$STUB_ROOT/Cargo.toml"' in workflow


def test_artifacts_are_digest_and_provenance_verified_before_native_execution() -> None:
    workflow = read(WORKFLOW)
    assert "artifact digest mismatch" in workflow
    assert "Cargo.lock" in workflow
    assert "source_commit" in workflow
    assert "builder_runner_identity" in workflow
    assert "executor_runner_identity" in workflow
    assert "actions/attest-build-provenance@" in workflow
    assert "github-attestation:slsa-v1" in workflow
    assert "gh attestation verify" in workflow
    assert "--signer-workflow" in workflow
    assert (
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/rust-platform.yml"'
        in workflow
    )
    assert '--source-digest "$GITHUB_SHA"' in workflow
    assert "--predicate-type https://slsa.dev/provenance/v1" in workflow
    assert "attestations: write" in workflow
    assert "attestations: read" in workflow
    assert "download-artifact@" in workflow
    assert "upload-artifact@" in workflow
    assert "runtime-evidence-${{ matrix.target }}.json" in workflow
    assert "readelf --version-info" in workflow
    assert "otool -l" in workflow
    assert "MACOSX_DEPLOYMENT_TARGET=15.0" in workflow
    assert "missing macOS deployment target" in workflow
    assert "macOS deployment target exceeds 15.0" in workflow
    assert "shasum -a 256" in workflow
    assert "python3" not in workflow


def test_artifact_and_provenance_rejection_paths_are_non_bypassable() -> None:
    workflow = read(WORKFLOW)
    # This hermetic check cannot call GitHub, but ensures verification occurs
    # before extraction and every binding failure exits non-zero.
    verify_at = workflow.index("gh attestation verify")
    extract_at = workflow.index("tar -C verified -xzf")
    assert verify_at < extract_at
    assert 'test "$(uname -s)" = Linux && test "$(uname -m)" = x86_64' in workflow
    assert 'test "$(uname -s)" = Linux && test "$(uname -m)" = aarch64' in workflow
    assert 'test "$(uname -s)" = Darwin && test "$(uname -m)" = x86_64' in workflow
    assert 'test "$(uname -s)" = Darwin && test "$(uname -m)" = arm64' in workflow
    assert "sysctl.proc_translated" in workflow
    architecture_at = workflow.index('case "$TARGET" in')
    assert verify_at < architecture_at < extract_at
    for message in (
        "target mismatch",
        "source commit mismatch",
        "Cargo.lock mismatch",
        "artifact digest mismatch",
        "missing builder identity",
    ):
        index = workflow.index(message)
        assert "exit 1" in workflow[index : index + 120]


def test_aggregate_fails_closed_for_all_expected_evidence() -> None:
    action = read(ACTION)
    assert "fail closed" in action.lower()
    assert "missing" in action
    assert "skipped" in action
    assert "timed-out" in action
    assert "stale" in action
    for target in TARGETS:
        assert target in action


def test_embedded_aggregate_executes_all_failure_injections(tmp_path: Path) -> None:
    action = read(ACTION)
    aggregate = embedded_python(action, "python3 - <<'PY'\n")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    now = __import__("time").time()
    record = {
        "status": "success",
        "observed_at_epoch": now,
        "artifact_sha256": "a" * 64,
        "source_commit": "c" * 40,
        "cargo_lock_sha256": "b" * 64,
        "builder_runner_identity": "builder",
        "executor_runner_identity": "executor",
        "provenance": "github-attestation:slsa-v1",
    }
    for target in TARGETS:
        (evidence / f"runtime-evidence-{target}.json").write_text(
            json.dumps({**record, "target": target})
        )
    env = {
        **os.environ,
        "EVIDENCE_DIRECTORY": str(evidence),
        "MAX_AGE_SECONDS": "86400",
    }
    command = [sys.executable, "-c", aggregate]
    assert subprocess.run(command, env=env, check=False).returncode == 0
    target = TARGETS[-1]
    path = evidence / f"runtime-evidence-{target}.json"
    cases = (
        ("missing", None),
        ("skipped", {"status": "skipped"}),
        ("timed-out", {"status": "timed-out"}),
        ("failed", {"status": "failed"}),
        ("stale", {"observed_at_epoch": now - 86401}),
        ("future", {"observed_at_epoch": now + 1}),
        ("invalid-timestamp", {"observed_at_epoch": "not-a-time"}),
        ("nan-timestamp", {"observed_at_epoch": "NaN"}),
        ("infinite-timestamp", {"observed_at_epoch": "Infinity"}),
        ("wrong-target", {"target": TARGETS[0]}),
        ("missing-artifact-digest", {"artifact_sha256": ""}),
        ("invalid-artifact-digest", {"artifact_sha256": "z" * 64}),
        ("missing-source-commit", {"source_commit": ""}),
        ("invalid-source-commit", {"source_commit": "c" * 39}),
        ("missing-lock-digest", {"cargo_lock_sha256": ""}),
        ("invalid-lock-digest", {"cargo_lock_sha256": "z" * 64}),
        ("missing-builder", {"builder_runner_identity": ""}),
        ("missing-executor", {"executor_runner_identity": ""}),
        ("wrong-provenance", {"provenance": "unverified"}),
    )
    for _name, mutation in cases:
        if mutation is None:
            path.unlink()
        else:
            path.write_text(json.dumps({**record, "target": target, **mutation}))
        assert subprocess.run(command, env=env, check=False).returncode != 0
        path.write_text(json.dumps({**record, "target": target}))

    for invalid_content in ("{", "[]", "null"):
        path.write_text(invalid_content)
        assert subprocess.run(command, env=env, check=False).returncode != 0

    for missing_field in record:
        incomplete = {**record, "target": target}
        del incomplete[missing_field]
        path.write_text(json.dumps(incomplete))
        assert subprocess.run(command, env=env, check=False).returncode != 0
