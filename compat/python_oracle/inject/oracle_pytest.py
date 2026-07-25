"""Pytest outcome attestation for the complete historical corpus."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_outcomes: dict[str, list[str]] = {
    "passed": [],
    "failed": [],
    "skipped": [],
    "xfailed": [],
    "xpassed": [],
}


def pytest_runtest_logreport(report: Any) -> None:
    if report.when != "call":
        return
    if getattr(report, "wasxfail", None):
        key = "xpassed" if report.passed else "xfailed"
    else:
        key = report.outcome
    _outcomes[key].append(report.nodeid)


def pytest_sessionfinish(session: Any, exitstatus: int) -> None:
    del session
    path = os.environ.get("ORACLE_PYTEST_LEDGER")
    if not path:
        raise RuntimeError("ORACLE_PYTEST_LEDGER is required")
    evidence = {
        "manifest_sha256": os.environ.get("ORACLE_MANIFEST_SHA256"),
        "exit_status": exitstatus,
        **{key: sorted(value) for key, value in sorted(_outcomes.items())},
    }
    Path(path).write_text(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
