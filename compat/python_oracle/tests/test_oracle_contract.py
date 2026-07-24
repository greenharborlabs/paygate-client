from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from compat.python_oracle.oracle import OfflineGuard, OracleViolation, run_oracle
from compat.python_oracle.replay import (
    ReplayViolation,
    require_identical,
    validate_bundle,
    validate_cases,
    validate_inventory,
    verify_golden,
)
from compat.python_oracle.wheelhouse import (
    WheelhouseError,
    inspect_wheel,
    verify_manifest,
)

ROOT = Path(__file__).parents[3]


def test_bundle_is_git_derived_complete_and_offline_installable() -> None:
    validated = validate_bundle(ROOT)
    assert len(validated["tree"]) == 75
    assert len(validated["cases"]) == 37
    assert any(record["path"] == "pyproject.toml" for record in validated["tree"])
    summary = json.loads(run_oracle(ROOT, ambient={}))
    assert summary == {
        "baseline_commit": "f56cbd0c4bdf07254282a52e51bcf88ff1f48478",
        "case_count": 37,
        "inventory_count": 75,
    }


def test_live_network_dns_and_real_keyring_are_fatal() -> None:
    with OfflineGuard() as guard:
        with pytest.raises(OracleViolation, match="live network"):
            socket.socket()
        with pytest.raises(OracleViolation, match="live network"):
            socket.getaddrinfo("example.com", 443)
        with pytest.raises(OracleViolation, match="real keyring"):
            guard.real_keyring_get("service", "account")


def test_manifest_requires_exact_case_ids_classes_and_owners() -> None:
    manifest = json.loads((ROOT / "compat/manifest.yaml").read_text())
    for missing, message in (
        ("class", "class/later owner"),
        ("owner", "class/later owner"),
    ):
        changed = json.loads(json.dumps(manifest))
        changed["cases"][0].pop(missing)
        with pytest.raises(ReplayViolation, match=message):
            validate_cases(changed)
    changed = json.loads(json.dumps(manifest))
    changed["cases"][0]["owner"] = "W9-99"
    with pytest.raises(ReplayViolation, match="class/owner drifted"):
        validate_cases(changed)
    changed = json.loads(json.dumps(manifest))
    changed["cases"].pop()
    with pytest.raises(ReplayViolation, match="required behavior cases"):
        validate_cases(changed)


def test_git_inventory_rejects_source_mismatch_and_omitted_pyproject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = json.loads((ROOT / "compat/manifest.yaml").read_text())
    changed = json.loads(json.dumps(manifest))
    for group in changed["inventory"]:
        if "pyproject.toml" in group["paths"]:
            group["paths"].remove("pyproject.toml")
    with pytest.raises(ReplayViolation, match="manifest/tree mismatch"):
        validate_inventory(ROOT, changed)

    from compat.python_oracle import replay

    real_tree = replay.git_tree(ROOT)
    monkeypatch.setattr(replay, "git_tree", lambda _root: real_tree[:-1])
    with pytest.raises(ReplayViolation, match="inventory evidence is stale"):
        validate_inventory(ROOT, manifest)


def test_changed_or_unhashed_wheel_fails_closed(tmp_path: Path) -> None:
    wheel = next((ROOT / "compat/python_oracle/wheelhouse").glob("iniconfig-*.whl"))
    changed = tmp_path / wheel.name
    shutil.copy2(wheel, changed)
    changed.write_bytes(changed.read_bytes() + b"tamper")
    lock_text = (ROOT / "compat/python_oracle/requirements.lock").read_text()
    with pytest.raises(WheelhouseError, match="hash is absent"):
        inspect_wheel(changed, lock_text)
    with pytest.raises(WheelhouseError, match="hash is absent"):
        inspect_wheel(wheel, "iniconfig==2.3.0\n")


def test_missing_wheel_provenance_or_license_fails_closed(tmp_path: Path) -> None:
    manifest = json.loads(
        (ROOT / "compat/python_oracle/wheelhouse-manifest.json").read_text()
    )
    manifest["wheels"][0].pop("origin")
    manifest["wheels"][0].pop("license")
    changed = tmp_path / "manifest.json"
    changed.write_text(json.dumps(manifest))
    with pytest.raises(WheelhouseError, match="stale, or tampered"):
        verify_manifest(
            ROOT / "compat/python_oracle/wheelhouse",
            ROOT / "compat/python_oracle/requirements.lock",
            changed,
        )


def test_stale_golden_and_ambient_divergence_fail_closed() -> None:
    with pytest.raises(ReplayViolation, match="golden is stale"):
        verify_golden(b"actual", b"old")
    with pytest.raises(ReplayViolation, match="ambient environments"):
        require_identical(b"one", b"two")


def test_external_injection_rejects_unapproved_subprocess(tmp_path: Path) -> None:
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": str(ROOT / "compat/python_oracle/inject"),
            "ORACLE_SUBPROCESS_GUARD": "1",
            "ORACLE_KEYRING": str(ROOT / "compat/fixtures/keyring.json"),
            "ORACLE_CONTROLS": str(ROOT / "compat/fixtures/controls.json"),
            "ORACLE_BACKENDS": str(ROOT / "compat/fixtures/backends.json"),
        }
    )
    result = subprocess.run(
        [
            "python3.11",
            "-c",
            "import subprocess; subprocess.run(['curl', 'https://example.com'])",
        ],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "unapproved subprocess" in result.stderr


def test_qualified_replay_golden_is_checked_in() -> None:
    golden = ROOT / "compat/python_oracle/golden/evidence.json"
    assert golden.is_file()
    evidence = json.loads(golden.read_text())
    assert evidence["baseline_commit"].startswith("f56cbd0")
    assert evidence["pytest"]["failed"] == []
    assert evidence["pytest"]["skipped"] == []
    assert set(evidence["case_evidence"]) == {
        case["id"]
        for case in json.loads((ROOT / "compat/manifest.yaml").read_text())["cases"]
    }
    manifest_hash = evidence["manifest_sha256"]
    assert evidence["run"]["manifest_sha256"] == manifest_hash
    assert evidence["pytest"]["manifest_sha256"] == manifest_hash
    assert evidence["probes"]["manifest_sha256"] == manifest_hash
