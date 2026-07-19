"""Behavioral probes executed against modules from the detached checkout."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import subprocess
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from paygate_client.challenges import L402Challenge
from paygate_client.cli import app
from paygate_client.credentials import build_l402_authorization
from paygate_client.ledger import DailySpendLedger
from paygate_client.redaction import redact_text
from paygate_client.session_cache import (
    CachedCredential,
    CredentialScope,
    FileCredentialCache,
)


def _cli(*args: str) -> dict[str, Any]:
    result = CliRunner().invoke(app, list(args))
    return {
        "args": list(args),
        "exit": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exception": None
        if result.exception is None
        else type(result.exception).__name__,
    }


def _state_probe(root: Path) -> dict[str, Any]:
    cache_path = root / "cache.json"
    cache = FileCredentialCache(cache_path, namespace="oracle")
    scope = CredentialScope(
        request_key="GET https://example.test/resource",
        origin_host="example.test:443",
        service="orders",
        protocol="L402",
        payer_backend="test-mode",
        policy_hash="22" * 32,
        namespace="oracle",
    )
    cache.put(
        CachedCredential(
            credential_id="fixture-id",
            scope=scope,
            authorization="L402 token:" + "11" * 32,
            created_at=946782245,
            expires_at=946782305,
        )
    )
    cached = cache.get(scope)
    ledger_path = root / "ledger.json"
    ledger = DailySpendLedger(ledger_path)
    reservation = ledger.reserve(amount_sats=5, daily_budget_sats=10)
    before = ledger_path.read_bytes()
    reservation.commit()
    after = ledger_path.read_bytes()
    return {
        "cache": {
            "bytes": cache_path.read_text(encoding="utf-8"),
            "mode": stat.S_IMODE(cache_path.stat().st_mode),
            "hit": cached is not None,
        },
        "ledger": {
            "reserved_bytes": before.decode("utf-8"),
            "committed_bytes": after.decode("utf-8"),
            "mode": stat.S_IMODE(ledger_path.stat().st_mode),
            "lock_exists": ledger_path.with_suffix(".json.lock").exists(),
        },
    }


def _ledger_flow(root: Path, outcome: str) -> dict[str, Any]:
    path = root / f"{outcome}.json"
    ledger = DailySpendLedger(path)
    reservation = ledger.reserve(amount_sats=5, daily_budget_sats=10)
    submitted = outcome in {
        "success",
        "definite_failure",
        "ambiguous_post_submission",
        "cancellation_post_submission",
    }
    if outcome == "success":
        reservation.commit()
        disposition = "committed"
    elif outcome in {"definite_failure", "cancellation_pre_submission"}:
        reservation.rollback()
        disposition = "rolled_back"
    else:
        # The baseline has no submitted-unknown type. Its safe primitive is to
        # retain the reservation and avoid a second payer invocation.
        disposition = "retained_pending"
    return {
        "outcome": outcome,
        "submitted": submitted,
        "reservation_disposition": disposition,
        "automatic_retry_count": 0,
        "ledger_bytes": path.read_text(encoding="utf-8"),
    }


class _FixtureBook:
    def __init__(self, name: str, values: Mapping[str, Any]) -> None:
        self.name = name
        self.values = dict(values)
        self.used: set[str] = set()

    def take(self, key: str) -> Any:
        if key not in self.values:
            raise RuntimeError(f"unmatched {self.name} fixture request: {key}")
        self.used.add(key)
        return self.values[key]

    def finish(self) -> list[str]:
        unused = sorted(set(self.values) - self.used)
        if unused:
            raise RuntimeError(f"unused {self.name} fixtures: {unused}")
        return sorted(self.used)


def _fixture_observations() -> dict[str, Any]:
    controls = json.loads(Path(os.environ["ORACLE_CONTROLS"]).read_text())
    control_book = _FixtureBook("control", controls)
    clock = datetime.fromisoformat(
        str(control_book.take("clock")).replace("Z", "+00:00")
    )
    control_values = {
        "clock_epoch": int(clock.astimezone(timezone.utc).timestamp()),
        "date": control_book.take("date"),
        "home": control_book.take("home"),
        "locale": control_book.take("locale"),
        "timezone": control_book.take("timezone"),
        "uuid_hex": control_book.take("uuid_hex"),
        "xdg_cache_home": control_book.take("xdg_cache_home"),
        "xdg_config_home": control_book.take("xdg_config_home"),
        "xdg_state_home": control_book.take("xdg_state_home"),
    }
    control_used = control_book.finish()

    backend_values = json.loads(
        Path(os.environ["ORACLE_BACKENDS"]).read_text(encoding="utf-8")
    )
    backend_book = _FixtureBook("backend", backend_values)
    used_backends = {
        name: backend_book.take(name)
        for name in ("breez", "lnd_rest", "phoenixd", "test_mode")
    }
    try:
        backend_book.take("unmatched")
    except RuntimeError as exc:
        unmatched = str(exc)
    else:  # pragma: no cover - fail closed
        raise RuntimeError("unmatched backend fixture was accepted")
    backend_used = backend_book.finish()
    return {
        "controls": control_values,
        "control_fixture_ids": control_used,
        "backends": used_backends,
        "backend_fixture_ids": backend_used,
        "unmatched_backend": unmatched,
    }


def main() -> None:
    output = os.environ.get("ORACLE_PROBES")
    if not output:
        raise SystemExit("ORACLE_PROBES is required")
    l402 = L402Challenge(token="fixture-token", macaroon=None, invoice="lnbc1fixture")
    authorization = build_l402_authorization(l402, "11" * 32)
    live_guards: dict[str, str] = {}
    for name, operation in {
        "dns": lambda: socket.getaddrinfo("example.com", 443),
        "socket": socket.socket,
        "http_subprocess": lambda: subprocess.run(["curl", "https://example.com"]),
    }.items():
        try:
            operation()
        except Exception as exc:  # the exact fatal type is evidence
            live_guards[name] = type(exc).__name__ + ":" + str(exc)
        else:
            raise RuntimeError(f"uncontrolled {name} access was not fatal")
    with __import__("tempfile").TemporaryDirectory(prefix="oracle-state-") as raw:
        state_root = Path(raw)
        state = _state_probe(state_root)
        flows = {
            name: _ledger_flow(state_root, name)
            for name in (
                "success",
                "definite_failure",
                "ambiguous_post_submission",
                "cancellation_pre_submission",
                "cancellation_post_submission",
            )
        }
        cache_path = state_root / "cache.json"
        credentials_found = _cli(
            "credentials",
            "show",
            "fixture-id",
            "--profile",
            "oracle",
            "--cache-path",
            str(cache_path),
        )
        credentials_missing = _cli(
            "credentials",
            "show",
            "missing-id",
            "--profile",
            "oracle",
            "--cache-path",
            str(cache_path),
        )
        for result in (credentials_found, credentials_missing):
            result["args"][-1] = "<CONTROLLED_CACHE_PATH>"
    fixtures = Path("tests/fixtures/paygate")
    fixture_hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(fixtures.glob("*.json"))
    }
    fixtures_evidence = _fixture_observations()
    manifest_hash = os.environ.get("ORACLE_MANIFEST_SHA256")
    if not manifest_hash:
        raise RuntimeError("raw manifest hash was not injected")
    observations = {
        "cli.help": _cli("--help"),
        "cli.no_args": _cli(),
        "cli.version": _cli("--version"),
        "cli.diagnose_missing_config": _cli(
            "backend", "doctor", "--config", "/missing"
        ),
        "credentials.show_found": credentials_found,
        "credentials.show_missing": credentials_missing,
        "challenge.l402": {
            "scheme": l402.scheme,
            "token": l402.credential_token,
            "invoice": l402.invoice,
        },
        "challenge.fixtures": fixture_hashes,
        "credential.l402": authorization,
        "state.cache": state["cache"],
        "state.ledger": state["ledger"],
        "flow.success": flows["success"],
        "flow.definite_failure": flows["definite_failure"],
        "flow.ambiguous_post_submission": flows["ambiguous_post_submission"],
        "flow.cancellation_pre_submission": flows["cancellation_pre_submission"],
        "flow.cancellation_post_submission": flows["cancellation_post_submission"],
        "redaction.secret": redact_text("macaroon=secret preimage=" + "11" * 32),
        "guards.live_io": live_guards,
        "fixtures.controls": fixtures_evidence["controls"],
        "fixtures.backends": fixtures_evidence["backends"],
        "fixtures.completeness": {
            "control_fixture_ids": fixtures_evidence["control_fixture_ids"],
            "backend_fixture_ids": fixtures_evidence["backend_fixture_ids"],
            "unmatched_backend": fixtures_evidence["unmatched_backend"],
        },
    }
    evidence = {
        "manifest_sha256": manifest_hash,
        "observations": observations,
        "cli": {
            "help": _cli("--help"),
            "no_args": _cli(),
            "version": _cli("--version"),
            "diagnose_missing_config": _cli("diagnose", "--config", "/missing"),
        },
        "challenge": {
            "l402_fields": {
                "scheme": l402.scheme,
                "token": l402.credential_token,
                "invoice": l402.invoice,
            },
            "fixture_hashes": fixture_hashes,
        },
        "credential": {"l402_authorization": authorization},
        "state": state,
        "redaction": {
            "secret": redact_text("macaroon=secret preimage=" + "11" * 32),
        },
        "guards": live_guards,
        "controls": {
            key: os.environ[key] for key in ("LANG", "LC_ALL", "TZ", "PYTHONHASHSEED")
        },
    }
    Path(output).write_text(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
