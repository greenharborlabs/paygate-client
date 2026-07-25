"""Structural checks for the Rust platform-qualification workflow scaffold.

These deliberately inspect repository configuration: native runners and GitHub
artifacts are unavailable to unit tests and must never be faked locally.
"""

import ast
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/rust-platform.yml"
DOCS = ROOT / "docs/platform-qualification.md"
RUNNERS = ROOT / "infra/runners/platform-qualification.yml"
ACTION = ROOT / ".github/actions/aggregate-rust-platform/action.yml"
STUB = ROOT / "tests/platform-smoke/stub"
KEYRING_BOOTSTRAP = ROOT / "scripts/bootstrap-native-keyring.py"
KEYRING_REQUIREMENTS = ROOT / "compat/native-keyring-requirements.txt"

TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)


def read(path: Path) -> str:
    assert path.is_file(), f"missing qualification scaffold: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def qualification_steps() -> list[dict[str, object]]:
    workflow = yaml.load(read(WORKFLOW), Loader=yaml.BaseLoader)
    return workflow["jobs"]["qualify-runtime"]["steps"]


def named_step(name: str) -> dict[str, object]:
    return next(step for step in qualification_steps() if step.get("name") == name)


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
    assert (ROOT / "Cargo.toml").is_file()
    assert (ROOT / "Cargo.lock").is_file()
    assert "cargo +1.88.0 fetch --locked" in workflow
    assert 'cargo build --locked --offline --release --target "$1"' in workflow
    assert (
        'cargo +1.88.0 build --locked --offline --release --target "$TARGET"'
        in workflow
    )
    assert "docker run --rm --network none" in workflow
    assert "cargo vendor" not in workflow


def test_artifacts_are_digest_and_provenance_verified_before_native_execution() -> None:
    workflow = read(WORKFLOW)
    assert "artifact digest mismatch" in workflow
    assert "Cargo.lock" in workflow
    assert "source_commit" in workflow
    assert "builder_runner_identity" in workflow
    assert "executor_runner_identity" in workflow
    assert "binary_sha256" in workflow
    assert "workflow_run_id" in workflow
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
    assert workflow.count("persist-credentials: false") == 3
    assert "download-artifact@" in workflow
    assert "upload-artifact@" in workflow
    assert "runtime-evidence-${{ matrix.target }}.json" in workflow
    assert "readelf --version-info" in workflow
    assert "otool -l" in workflow
    assert "MACOSX_DEPLOYMENT_TARGET=15.0" in workflow
    assert "missing macOS deployment target" in workflow
    assert "macOS deployment target exceeds 15.0" in workflow
    assert "shasum -a 256" in workflow
    assert "python3 scripts/check-rust-linkage.py" in workflow
    assert "--test keyring_qualification -- --ignored" in workflow
    assert "--test breez_lifecycle_qualification -- --ignored" in workflow


def test_native_keyring_uses_pinned_cross_platform_python_and_dependencies() -> None:
    bootstrap = read(KEYRING_BOOTSTRAP)
    requirements = read(KEYRING_REQUIREMENTS)
    setup = next(
        step
        for step in qualification_steps()
        if "setup-python@" in step.get("uses", "")
    )
    preparation = named_step("Prepare controlled native keyring environment")["run"]

    assert setup == {
        "uses": "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        "with": {"python-version": "3.11.14"},
    }
    python_pin = ast.literal_eval(
        re.search(r"^PYTHON_PIN = (.+)$", bootstrap, re.MULTILINE).group(1)
    )
    assert python_pin == (3, 11, 14)
    assert 'python -m venv "$RUNNER_TEMP/paygate-native-keyring"' in preparation
    assert "compat/python_oracle/wheelhouse" not in preparation
    assert "compat/python_oracle/wheelhouse" not in bootstrap
    assert "compat/native-keyring-requirements.txt" in bootstrap
    assert "--only-binary=:all:" in bootstrap
    assert "--require-hashes" in bootstrap

    expected = {
        "keyring": "25.7.0",
        "jaraco.classes": "3.4.0",
        "jaraco.context": "6.1.2",
        "jaraco.functools": "4.6.0",
        "more-itertools": "11.1.0",
        "importlib-metadata": "9.0.0",
        "zipp": "4.1.0",
        "backports.tarfile": "1.2.0",
        "secretstorage": "3.5.0",
        "jeepney": "0.9.0",
        "cryptography": "49.0.0",
        "cffi": "2.1.0",
        "pycparser": "3.0",
    }
    pinned = dict(re.findall(r"^([\w.-]+)==([\d.]+)", requirements, re.MULTILINE))
    assert pinned == expected
    assert requirements.count("--hash=sha256:") == 15
    architecture_hashes = {
        "cryptography": {
            "2afe9051da7ae7bd5905da5a949280c7d2bb75682e188f650a9d0f2756b834c6",
            "53ecee2e23f7169b6117e99fc8a944e5e50f79e69758a83b52a00cb98ab2b2d2",
        },
        "cffi": {
            "88023dfe18799507b73f1dbb0d14326a17465de1bc9c9c7655c22845e9ddc3a2",
            "aa7a1b53a2a4452ada2d1b5dade9960b2522f1e61293a811a077439e39029565",
        },
    }
    for package, expected_hashes in architecture_hashes.items():
        block = re.search(
            rf"^{package}==.*?(?=^[\w.-]+==|\Z)",
            requirements,
            re.MULTILINE | re.DOTALL,
        ).group()
        assert (
            set(re.findall(r"--hash=sha256:([0-9a-f]{64})", block)) == expected_hashes
        )


def test_native_keyring_fails_closed_on_metadata_and_backend_selection() -> None:
    bootstrap = read(KEYRING_BOOTSTRAP)
    rust_test = read(ROOT / "tests/keyring_qualification.rs")
    steps = qualification_steps()
    preparation = named_step("Prepare controlled native keyring environment")["run"]
    runtime = named_step("Reverify bundle bindings and run native smoke")["run"]

    for source in (bootstrap, rust_test):
        assert 'importlib.metadata.version("keyring")' in source
        assert "keyring.__version__" not in source
        for forbidden in ("null", "file", "chainer", "fail"):
            assert forbidden in source
    assert (
        "sudo apt-get install --yes --no-install-recommends "
        "dbus-x11 gnome-keyring libsecret-1-dev"
    ) in preparation
    assert (
        'python scripts/bootstrap-native-keyring.py --python "$controlled_python" '
        "--install-only"
    ) in preparation
    session_start = runtime.index("dbus-run-session -- bash -euo pipefail -c '")
    session_end = runtime.index(
        '\' bash "$keyring_home" "$controlled_python"', session_start
    )
    session = runtime[session_start:session_end]
    daemon = "gnome-keyring-daemon --unlock --components=secrets"
    verify = (
        'scripts/bootstrap-native-keyring.py --python "$controlled_python" '
        "--verify-only"
    )
    rust_probe = "cargo +1.88.0 test --locked --offline --test keyring_qualification"
    assert "dbus-run-session -- bash -euo pipefail -c" in session
    assert daemon in session
    assert verify in session
    assert rust_probe in session
    assert "PAYGATE_QUALIFICATION_KEYRING_MODE=native" in session
    assert session.index(daemon) < session.index(verify) < session.index(rust_probe)
    assert "--install-only" not in session
    assert steps.index(
        named_step("Prepare controlled native keyring environment")
    ) < steps.index(named_step("Reverify bundle bindings and run native smoke"))


def test_artifact_and_provenance_rejection_paths_are_non_bypassable() -> None:
    workflow = read(WORKFLOW)
    # This hermetic check cannot call GitHub, but ensures verification occurs
    # before extraction and every binding failure exits non-zero.
    verify_at = workflow.index("gh attestation verify")
    extract_at = workflow.index("tar -C verified -xzf")
    assert verify_at < extract_at
    attestation_step = workflow[verify_at:extract_at]
    assert "GH_TOKEN" not in attestation_step
    runtime_step = workflow[extract_at:]
    assert "GH_TOKEN" not in runtime_step
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
        "workflow run mismatch",
        "binary digest mismatch",
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
        "binary_sha256": "d" * 64,
        "source_commit": "c" * 40,
        "cargo_lock_sha256": "b" * 64,
        "builder_runner_identity": "builder",
        "executor_runner_identity": "executor",
        "workflow_run_id": "12345",
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
        "EXPECTED_WORKFLOW_RUN_ID": "12345",
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
        ("missing-binary-digest", {"binary_sha256": ""}),
        ("invalid-binary-digest", {"binary_sha256": "z" * 64}),
        ("missing-source-commit", {"source_commit": ""}),
        ("invalid-source-commit", {"source_commit": "c" * 39}),
        ("missing-lock-digest", {"cargo_lock_sha256": ""}),
        ("invalid-lock-digest", {"cargo_lock_sha256": "z" * 64}),
        ("missing-builder", {"builder_runner_identity": ""}),
        ("missing-executor", {"executor_runner_identity": ""}),
        ("wrong-workflow-run", {"workflow_run_id": "different"}),
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
