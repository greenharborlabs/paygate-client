"""Fail-closed replay of the exact historical Python application."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from compat.python_oracle.wheelhouse import WheelhouseError, verify_manifest

BASELINE_COMMIT = "f56cbd0c4bdf07254282a52e51bcf88ff1f48478"
VALID_DISPOSITIONS = {
    "port",
    "replace",
    "neutral_fixture",
    "rollback_only",
    "retire",
}

# Exact case identity is a migration interface, not free-form manifest prose.
# Each case binds at least one historical node and one stable observation.
CASE_CONTRACTS: dict[str, tuple[str, str, tuple[str, ...], tuple[str, ...]]] = {
    "cli.help": (
        "must_match",
        "W3-01",
        ("tests/test_cli_smoke.py::test_cli_help_resolves",),
        ("cli.help",),
    ),
    "cli.no_args": (
        "must_match",
        "W3-01",
        ("tests/test_cli_smoke.py::test_cli_help_resolves",),
        ("cli.no_args",),
    ),
    "cli.fetch.envelope": (
        "must_match",
        "W3-01",
        ("tests/test_cli.py::test_request_command_emits_json_and_exits_zero",),
        ("fixtures.completeness",),
    ),
    "cli.diagnose": (
        "must_match",
        "W3-01",
        (
            "tests/test_cli.py::test_backend_doctor_missing_config_emits_diagnostic_json",
        ),
        ("cli.diagnose_missing_config",),
    ),
    "config.file_env_cli_precedence": (
        "must_match",
        "W3-01",
        (
            "tests/test_config.py::test_documented_example_config_loads_without_real_lightning_secrets",
        ),
        ("fixtures.controls",),
    ),
    "config.voltage_env_precedence": (
        "must_match",
        "W3-01",
        (
            "tests/test_config.py::test_lnd_config_loads_script_generated_companion_env_file",
        ),
        ("fixtures.controls",),
    ),
    "config.profile_paths": (
        "must_match",
        "W3-01",
        ("tests/test_cli.py::test_request_command_passes_profile_namespace",),
        ("fixtures.controls",),
    ),
    "challenge.l402": (
        "must_match",
        "W3-02",
        (
            "tests/test_paygate_fixtures.py::test_paygate_l402_only_fixture_parses_real_wire_format",
        ),
        ("challenge.l402",),
    ),
    "challenge.paygate": (
        "must_match",
        "W3-02",
        (
            "tests/test_paygate_fixtures.py::test_paygate_mpp_only_fixture_parses_real_wire_format",
        ),
        ("challenge.fixtures",),
    ),
    "challenge.dual": (
        "must_match",
        "W3-02",
        (
            "tests/test_paygate_fixtures.py::test_paygate_dual_fixture_selects_preferred_protocol_without_lost_fields",
        ),
        ("challenge.fixtures",),
    ),
    "challenge.invalid": (
        "must_match",
        "W3-02",
        (
            "tests/test_challenges.py::test_unsupported_scheme_produces_no_supported_challenge",
        ),
        ("challenge.fixtures",),
    ),
    "invoice.amount_hash": (
        "must_match",
        "W3-02",
        ("tests/test_invoices.py::test_amount_sats_from_invoice_parses_common_units",),
        ("challenge.fixtures",),
    ),
    "invoice.unvalidated_legacy": (
        "unsupported_legacy_input",
        "W3-02",
        (
            "tests/test_invoices.py::test_amount_sats_from_invoice_rounds_msats_up_for_policy",
        ),
        ("challenge.fixtures",),
    ),
    "credentials.l402": (
        "must_match",
        "W3-02",
        (
            "tests/test_credentials.py::test_build_l402_authorization_uses_token_and_lowercase_preimage",
        ),
        ("credential.l402",),
    ),
    "credentials.paygate": (
        "must_match",
        "W3-02",
        (
            "tests/test_credentials.py::test_build_payment_authorization_is_deterministic",
        ),
        ("challenge.fixtures",),
    ),
    "credentials.show_found": (
        "must_match",
        "W3-01",
        ("tests/test_cli.py::test_credentials_list_redacts_cached_authorization",),
        ("credentials.show_found",),
    ),
    "credentials.show_missing": (
        "must_match",
        "W3-01",
        ("tests/test_cli.py::test_credentials_list_redacts_cached_authorization",),
        ("credentials.show_missing",),
    ),
    "policy.approve_deny": (
        "must_match",
        "W3-03",
        (
            "tests/test_policy.py::test_request_amount_cap_is_checked_before_reservation",
        ),
        ("flow.definite_failure",),
    ),
    "cache.schema": (
        "must_match",
        "W3-03",
        (
            "tests/test_session_cache.py::test_file_cache_scopes_credentials_by_namespace",
        ),
        ("state.cache",),
    ),
    "ledger.schema_locking": (
        "must_match",
        "W3-03",
        (
            "tests/test_ledger.py::test_two_concurrent_reservations_cannot_exceed_daily_budget",
        ),
        ("state.ledger",),
    ),
    "ledger.reserve_commit": (
        "must_match",
        "W3-03",
        ("tests/test_ledger.py::test_successful_reservation_commit_is_date_scoped",),
        ("flow.success",),
    ),
    "ledger.pre_submission_failure": (
        "must_match",
        "W3-03",
        ("tests/test_policy.py::test_execute_rolls_back_on_generic_payer_failure",),
        ("flow.cancellation_pre_submission",),
    ),
    "ledger.submitted_success": (
        "must_match",
        "W3-03",
        (
            "tests/test_policy.py::test_execute_payer_passes_fee_limit_and_commits_on_success",
        ),
        ("flow.success",),
    ),
    "ledger.submitted_definite_failure": (
        "must_match",
        "W3-03",
        ("tests/test_policy.py::test_execute_rolls_back_on_generic_payer_failure",),
        ("flow.definite_failure",),
    ),
    "ledger.submitted_ambiguous": (
        "intentional_security_delta",
        "W3-03",
        (
            "tests/test_policy.py::test_post_payment_exception_after_execute_keeps_committed_spend",
        ),
        ("flow.ambiguous_post_submission",),
    ),
    "payer.cancellation_pre_submission": (
        "must_match",
        "W2-02",
        ("tests/test_policy.py::test_execute_rolls_back_on_keyboard_interrupt",),
        ("flow.cancellation_pre_submission",),
    ),
    "payer.cancellation_post_submission": (
        "intentional_security_delta",
        "W2-02",
        (
            "tests/test_policy.py::test_post_payment_exception_after_execute_keeps_committed_spend",
        ),
        ("flow.cancellation_post_submission",),
    ),
    "payer.test_mode": (
        "must_match",
        "W4-01",
        ("tests/test_payers_test_mode.py::test_test_mode_payer_uses_test_preimage",),
        ("fixtures.backends",),
    ),
    "payer.lnd_rest": (
        "must_match",
        "W4-02",
        (
            "tests/test_payers_lnd_rest.py::test_lnd_rest_success_response_returns_normalized_payment_result",
        ),
        ("fixtures.backends",),
    ),
    "payer.phoenixd": (
        "must_match",
        "W4-03",
        (
            "tests/test_payers_phoenixd.py::test_phoenixd_success_normalizes_uppercase_preimage_and_posts_fee_limit",
        ),
        ("fixtures.backends",),
    ),
    "payer.breez": (
        "must_match",
        "W4-04",
        (
            "tests/test_payers_breez.py::test_breez_success_forces_lightning_and_returns_verified_result",
        ),
        ("fixtures.backends",),
    ),
    "errors.envelope": (
        "must_match",
        "W3-01",
        ("tests/test_cli.py::test_request_command_exits_nonzero_for_error_envelope",),
        ("cli.diagnose_missing_config",),
    ),
    "redaction.user_success_hash": (
        "must_match",
        "W3-01",
        ("tests/test_orchestrator.py::test_success_paid_redacts_untrusted_receipt",),
        ("redaction.secret",),
    ),
    "redaction.trace_hash": (
        "intentional_security_delta",
        "W3-01",
        ("tests/test_redaction.py::test_redacts_env_secret_values_and_preimages",),
        ("redaction.secret",),
    ),
    "trace.events": (
        "must_match",
        "W3-01",
        ("tests/test_orchestrator.py::test_trace_sink_receives_key_events",),
        ("fixtures.controls",),
    ),
    "http.retry_flow": (
        "must_match",
        "W5-01",
        (
            "tests/test_orchestrator.py::test_paid_request_retries_with_payment_authorization_and_commits",
        ),
        ("guards.live_io",),
    ),
    "publication.python_artifact": (
        "must_match",
        "W6-01",
        (
            "tests/test_package_metadata.py::test_artifacts_install_in_separate_environments",
        ),
        ("fixtures.completeness",),
    ),
}


class ReplayViolation(RuntimeError):
    """Historical evidence cannot be trusted."""


def _run(
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            cwd=cwd,
            env=None if env is None else dict(env),
            check=check,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        stderr = getattr(exc, "stderr", "")
        raise ReplayViolation(f"command failed: {args!r}: {stderr}") from exc


def git_tree(root: Path) -> list[dict[str, str]]:
    _run(["git", "cat-file", "-e", f"{BASELINE_COMMIT}^{{commit}}"], cwd=root)
    result = _run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", BASELINE_COMMIT], cwd=root
    )
    records: list[dict[str, str]] = []
    for raw in result.stdout.split("\0"):
        if not raw:
            continue
        header, path = raw.split("\t", 1)
        mode, kind, blob = header.split(" ", 2)
        if kind != "blob":
            raise ReplayViolation(f"unexpected tracked object type: {path}:{kind}")
        records.append({"path": path, "mode": mode, "blob": blob})
    if not records:
        raise ReplayViolation("historical git tree is empty or unavailable")
    return records


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReplayViolation(f"missing or invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ReplayViolation(f"JSON root must be an object: {path}")
    return value


def validate_inventory(root: Path, manifest: Mapping[str, Any]) -> list[dict[str, str]]:
    derived = git_tree(root)
    fixture_path = root / "compat/fixtures/baseline_inventory.json"
    fixture = _load_object(fixture_path)
    if fixture.get("baseline_commit") != BASELINE_COMMIT:
        raise ReplayViolation("inventory evidence has the wrong historical commit")
    if fixture.get("tree") != derived:
        raise ReplayViolation(
            "Git-derived inventory evidence is stale or self-authored"
        )

    inventory = manifest.get("inventory")
    if not isinstance(inventory, list):
        raise ReplayViolation("manifest inventory is absent")
    assigned: dict[str, tuple[str, str]] = {}
    for group in inventory:
        if not isinstance(group, dict):
            raise ReplayViolation("manifest inventory group is invalid")
        disposition = group.get("disposition")
        owner = group.get("owner")
        paths = group.get("paths")
        if (
            disposition not in VALID_DISPOSITIONS
            or not isinstance(owner, str)
            or not owner
        ):
            raise ReplayViolation("inventory disposition/later owner is missing")
        if not isinstance(paths, list) or not paths:
            raise ReplayViolation("inventory group has no tracked paths")
        for item in paths:
            if not isinstance(item, str) or item in assigned:
                raise ReplayViolation(
                    f"inventory path is invalid or duplicated: {item!r}"
                )
            assigned[item] = (disposition, owner)
    expected = {record["path"] for record in derived}
    actual = set(assigned)
    if actual != expected:
        raise ReplayViolation(
            "manifest/tree mismatch; missing="
            f"{sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )
    if "pyproject.toml" not in assigned:
        raise ReplayViolation("pyproject.toml has no migration disposition")
    return derived


def validate_cases(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ReplayViolation("behavior manifest is empty")
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise ReplayViolation("behavior case has no stable id")
        case_id = case["id"]
        if case_id in seen:
            raise ReplayViolation(f"duplicate behavior case: {case_id}")
        seen.add(case_id)
        if not case.get("class") or not case.get("owner"):
            raise ReplayViolation(f"behavior class/later owner missing: {case_id}")
        expected = CASE_CONTRACTS.get(case_id)
        if expected is None:
            raise ReplayViolation(f"unexpected behavior case: {case_id}")
        expected_class, expected_owner, nodes, observations = expected
        if case.get("class") != expected_class or case.get("owner") != expected_owner:
            raise ReplayViolation(f"case class/owner drifted: {case_id}")
        if case.get("evidence") != [f"/case_evidence/{case_id}"]:
            raise ReplayViolation(f"case evidence pointer drifted: {case_id}")
        if not nodes or not observations:
            raise ReplayViolation(f"case evidence contract is empty: {case_id}")
        validated.append(case)
    missing = sorted(set(CASE_CONTRACTS) - seen)
    if missing:
        raise ReplayViolation(f"required behavior cases are missing: {missing}")
    return validated


def validate_bundle(root: Path) -> dict[str, Any]:
    manifest_path = root / "compat/manifest.yaml"
    manifest_bytes = manifest_path.read_bytes()
    manifest = _load_object(manifest_path)
    baseline = manifest.get("baseline")
    if not isinstance(baseline, dict) or baseline.get("commit") != BASELINE_COMMIT:
        raise ReplayViolation("manifest does not bind the exact historical commit")
    if baseline.get("python") != "3.11" or baseline.get("offline") is not True:
        raise ReplayViolation("manifest is not an offline Python 3.11 replay")
    tree = validate_inventory(root, manifest)
    cases = validate_cases(manifest)
    try:
        verify_manifest(
            root / "compat/python_oracle/wheelhouse",
            root / "compat/python_oracle/requirements.lock",
            root / "compat/python_oracle/wheelhouse-manifest.json",
        )
    except (OSError, json.JSONDecodeError, WheelhouseError) as exc:
        raise ReplayViolation(str(exc)) from exc
    return {
        "manifest": manifest,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "tree": tree,
        "cases": cases,
    }


def _verify_qualified_platform() -> None:
    if sys.version_info[:2] != (3, 11):
        raise ReplayViolation("qualified replay requires CPython 3.11")
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise ReplayViolation("qualified replay requires Linux x86_64")
    libc_name, libc_version = platform.libc_ver()
    if libc_name != "glibc" or tuple(map(int, libc_version.split(".")[:2])) < (2, 31):
        raise ReplayViolation("qualified replay requires glibc >= 2.31")
    if os.environ.get("ORACLE_OS_NETWORK_BOUNDARY") != "docker-none":
        raise ReplayViolation("an attested Docker --network none boundary is required")
    routes = [
        line.split()
        for line in Path("/proc/net/route").read_text(encoding="utf-8").splitlines()[1:]
        if line.strip()
    ]
    if any(fields[1] == "00000000" for fields in routes):
        raise ReplayViolation("network boundary exposes a default IPv4 route")


def _checkout(
    root: Path, destination: Path, expected_tree: list[dict[str, str]]
) -> None:
    _run(
        ["git", "clone", "--shared", "--no-checkout", str(root), str(destination)],
        cwd=root,
    )
    _run(["git", "checkout", "--detach", BASELINE_COMMIT], cwd=destination)
    head = _run(["git", "rev-parse", "HEAD"], cwd=destination).stdout.strip()
    if head != BASELINE_COMMIT:
        raise ReplayViolation(f"historical checkout HEAD drifted: {head}")
    if _run(["git", "status", "--porcelain=v1"], cwd=destination).stdout:
        raise ReplayViolation("historical checkout is not clean")
    if git_tree(destination) != expected_tree:
        raise ReplayViolation("historical checkout tree differs from source repository")
    for record in expected_tree:
        blob = _run(
            ["git", "hash-object", record["path"]], cwd=destination
        ).stdout.strip()
        if blob != record["blob"]:
            raise ReplayViolation(f"checked-out blob mismatch: {record['path']}")


def _controlled_environment(
    root: Path,
    work: Path,
    ledger_path: Path,
    ambient: Mapping[str, str],
    manifest_sha256: str,
) -> dict[str, str]:
    controls = _load_object(root / "compat/fixtures/controls.json")
    # Do not leak credentials, proxy settings, user Python paths, or ambient
    # tool configuration into the historical process or its children.
    env = {key: ambient[key] for key in ("PATH",) if key in ambient}
    home = work / "home"
    values = {
        "HOME": home,
        "XDG_CONFIG_HOME": home / ".config",
        "XDG_STATE_HOME": home / ".local/state",
        "XDG_CACHE_HOME": home / ".cache",
    }
    for value in values.values():
        value.mkdir(parents=True, exist_ok=True)
    env.update({key: str(value) for key, value in values.items()})
    env.update(
        {
            "LANG": str(controls["locale"]),
            "LC_ALL": str(controls["locale"]),
            "TZ": str(controls["timezone"]),
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_FIND_LINKS": str(root / "compat/python_oracle/wheelhouse"),
            "ORACLE_ROOT": str(root),
            "ORACLE_CONTROLS": str(root / "compat/fixtures/controls.json"),
            "ORACLE_KEYRING": str(root / "compat/fixtures/keyring.json"),
            "ORACLE_BACKENDS": str(root / "compat/fixtures/backends.json"),
            "ORACLE_PYTEST_LEDGER": str(ledger_path),
            "ORACLE_MANIFEST_SHA256": manifest_sha256,
            "ORACLE_SUBPROCESS_GUARD": "1",
        }
    )
    return env


def _execute_once(
    root: Path,
    validated: Mapping[str, Any],
    ambient: Mapping[str, str],
) -> bytes:
    with tempfile.TemporaryDirectory(prefix="paygate-oracle-") as raw:
        work = Path(raw)
        checkout = work / "historical"
        _checkout(root, checkout, validated["tree"])
        venv = work / "venv"
        _run([sys.executable, "-m", "venv", str(venv)], cwd=work)
        python = venv / "bin/python"
        pip_wheel = next(
            (root / "compat/python_oracle/wheelhouse").glob("pip-26.1.1-*.whl")
        )
        install_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(work / "install-home"),
        }
        install_env.update(
            {
                "PYTHONPATH": str(pip_wheel),
                "PIP_NO_INDEX": "1",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            }
        )
        _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-cache-dir",
                "--find-links",
                str(root / "compat/python_oracle/wheelhouse"),
                "--require-hashes",
                "-r",
                str(root / "compat/python_oracle/requirements.lock"),
            ],
            cwd=checkout,
            env=install_env,
        )
        ledger = work / "pytest-ledger.json"
        env = _controlled_environment(
            root, work, ledger, ambient, validated["manifest_sha256"]
        )
        inject = root / "compat/python_oracle/inject"
        env["PYTHONPATH"] = str(inject)
        result = _run(
            [str(python), "-m", "pytest", "-p", "oracle_pytest", "-q", "tests"],
            cwd=checkout,
            env=env,
            check=False,
        )
        if result.returncode != 0:
            raise ReplayViolation(
                "historical pytest corpus failed under controls:\n"
                + result.stdout[-16000:]
                + result.stderr[-16000:]
            )
        outcomes = _load_object(ledger)
        if (
            outcomes.get("skipped")
            or outcomes.get("xfailed")
            or outcomes.get("xpassed")
        ):
            raise ReplayViolation("unexpected skip/xfail/xpass in historical corpus")
        probes_path = work / "probes.json"
        env["ORACLE_PROBES"] = str(probes_path)
        env["PYTHONPATH"] = os.pathsep.join((str(inject), str(checkout)))
        probe = _run(
            [str(python), str(root / "compat/python_oracle/probes.py")],
            cwd=checkout,
            env=env,
            check=False,
        )
        if probe.returncode != 0:
            raise ReplayViolation(
                "historical behavioral probes failed: " + probe.stderr
            )
        probes = _load_object(probes_path)
        manifest_sha256 = validated["manifest_sha256"]
        if outcomes.get("manifest_sha256") != manifest_sha256:
            raise ReplayViolation("pytest ledger lost the raw manifest hash")
        if probes.get("manifest_sha256") != manifest_sha256:
            raise ReplayViolation("behavior probes lost the raw manifest hash")
        observations = probes.get("observations")
        if not isinstance(observations, dict):
            raise ReplayViolation("stable observation index is absent")
        passed = set(outcomes.get("passed", []))
        case_evidence: dict[str, Any] = {}
        for case in validated["cases"]:
            case_id = case["id"]
            expected_class, expected_owner, nodes, observation_ids = CASE_CONTRACTS[
                case_id
            ]
            missing_nodes = sorted(set(nodes) - passed)
            if missing_nodes:
                raise ReplayViolation(
                    f"case {case_id} has missing historical nodes: {missing_nodes}"
                )
            missing_observations = sorted(set(observation_ids) - set(observations))
            if missing_observations:
                raise ReplayViolation(
                    f"case {case_id} has missing observations: {missing_observations}"
                )
            case_evidence[case_id] = {
                "class": expected_class,
                "owner": expected_owner,
                "manifest_sha256": manifest_sha256,
                "nodes": {node: "passed" for node in nodes},
                "observations": {item: observations[item] for item in observation_ids},
            }
        evidence = {
            "schema_version": 3,
            "baseline_commit": BASELINE_COMMIT,
            "manifest_sha256": manifest_sha256,
            "qualified_platform": "CPython 3.11 / Linux x86_64 / glibc >= 2.31",
            "run": {"manifest_sha256": manifest_sha256},
            "source_tree": validated["tree"],
            "pytest": outcomes,
            "probes": probes,
            "case_evidence": case_evidence,
        }
        return (
            json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()


def replay(root: Path, *, regenerate_golden: bool = False) -> bytes:
    validated = validate_bundle(root)
    _verify_qualified_platform()
    first = _execute_once(
        root,
        validated,
        {**os.environ, "HOME": "/ambient/one", "LANG": "C", "TZ": "Pacific/Honolulu"},
    )
    second = _execute_once(
        root,
        validated,
        {
            **os.environ,
            "HOME": "/ambient/two",
            "LANG": "en_US.UTF-8",
            "TZ": "Asia/Tokyo",
        },
    )
    require_identical(first, second)
    golden = root / "compat/python_oracle/golden/evidence.json"
    if regenerate_golden:
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_bytes(first)
        return first
    try:
        expected = golden.read_bytes()
    except OSError as exc:
        raise ReplayViolation("checked-in evidence golden is missing") from exc
    verify_golden(first, expected)
    return first


def require_identical(first: bytes, second: bytes) -> None:
    if first != second:
        raise ReplayViolation("complete evidence differs across ambient environments")


def verify_golden(actual: bytes, expected: bytes) -> None:
    if actual != expected:
        raise ReplayViolation("checked-in evidence golden is stale")


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    regenerate = sys.argv[1:] == ["--regenerate-golden"]
    if sys.argv[1:] not in ([], ["--regenerate-golden"]):
        raise SystemExit(
            "usage: python -m compat.python_oracle.replay [--regenerate-golden]"
        )
    sys.stdout.buffer.write(replay(root, regenerate_golden=regenerate))


if __name__ == "__main__":
    main()
