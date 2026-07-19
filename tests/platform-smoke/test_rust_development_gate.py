"""Structural coverage for the balanced Rust Wave 2 pull-request gate."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/rust-qualification.yml"


def test_rust_pr_workflow_runs_only_the_balanced_development_gate() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "  development-gate:" in workflow
    assert "cargo +1.88.0 fmt --check" in workflow
    assert (
        "CARGO_NET_OFFLINE=true cargo +1.88.0 test --locked --offline "
        "--test interface_contract --test dependency_qualification "
        "--test keyring_qualification"
    ) in workflow
    assert (
        "CARGO_NET_OFFLINE=true cargo +1.88.0 metadata --locked --offline "
        "--all-features --format-version 1 > /tmp/paygate-wave2-metadata.json"
    ) in workflow
    assert "python3 scripts/check-rust-licenses.py --self-test" in workflow
    assert (
        "python3 scripts/check-rust-licenses.py /tmp/paygate-wave2-metadata.json"
    ) in workflow
    assert "git diff --check" in workflow

    for native_or_evidence_marker in (
        "native-qualification",
        "aggregate-qualification-evidence",
        "aggregate-rust-qualification",
        "rust-qualification-evidence",
        "breez_lifecycle_qualification",
        "check-rust-linkage.py",
        "upload-artifact",
    ):
        assert native_or_evidence_marker not in workflow
