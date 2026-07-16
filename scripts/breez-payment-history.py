#!/usr/bin/env python3
"""Print Breez SDK Spark payment history as JSON."""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import os
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "bearer",
    "macaroon",
    "mnemonic",
    "passphrase",
    "password",
    "preimage",
    "private",
    "secret",
    "seed",
    "token",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List Breez SDK Spark wallet payment history."
    )
    parser.add_argument(
        "--network",
        choices=["mainnet", "testnet", "regtest", "signet"],
        default=os.environ.get("BREEZ_NETWORK", "mainnet"),
        help="Breez network. Defaults to BREEZ_NETWORK or mainnet.",
    )
    parser.add_argument(
        "--storage-dir",
        default=os.environ.get("BREEZ_STORAGE_DIR", ".breez-preimage-doctor"),
        help="Breez SDK storage directory. Defaults to BREEZ_STORAGE_DIR.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum payments to return. Defaults to 50.",
    )
    parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Pagination offset. Defaults to 0.",
    )
    parser.add_argument(
        "--ascending",
        action="store_true",
        help="Sort oldest first. Defaults to newest first.",
    )
    parser.add_argument(
        "--type",
        choices=["send", "receive"],
        help="Only include sent or received payments.",
    )
    parser.add_argument(
        "--status",
        choices=["completed", "pending", "failed"],
        help="Only include payments with this status.",
    )
    parser.add_argument(
        "--from",
        dest="from_timestamp",
        help="Start timestamp, either Unix seconds or ISO-8601.",
    )
    parser.add_argument(
        "--to",
        dest="to_timestamp",
        help="End timestamp, either Unix seconds or ISO-8601.",
    )
    parser.add_argument(
        "--include-sensitive",
        action="store_true",
        help="Include sensitive fields such as preimages. Avoid saving this output.",
    )
    return parser.parse_args()


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def parse_timestamp(value: str | None) -> int | None:
    if value is None:
        return None
    if value.isdigit():
        return int(value)
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def enum_value(enum_type: Any, value: str | None) -> list[Any] | None:
    if value is None:
        return None
    return [getattr(enum_type, value.upper())]


def network_value(sdk_module: Any, network_name: str) -> Any:
    attr = network_name.upper()
    if hasattr(sdk_module.Network, attr):
        return getattr(sdk_module.Network, attr)
    raise RuntimeError(f"Breez SDK does not expose network {attr}")


def is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def to_jsonable(value: Any, *, include_sensitive: bool, key: str = "") -> Any:
    if key and is_sensitive_key(key) and not include_sensitive:
        return "[REDACTED]"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple, set)):
        return [
            to_jsonable(item, include_sensitive=include_sensitive) for item in value
        ]
    if isinstance(value, dict):
        return {
            str(item_key): to_jsonable(
                item_value,
                include_sensitive=include_sensitive,
                key=str(item_key),
            )
            for item_key, item_value in value.items()
        }
    if dataclasses.is_dataclass(value):
        return to_jsonable(
            dataclasses.asdict(value),
            include_sensitive=include_sensitive,
            key=key,
        )
    if hasattr(value, "__dict__"):
        return {
            item_key: to_jsonable(
                item_value,
                include_sensitive=include_sensitive,
                key=item_key,
            )
            for item_key, item_value in vars(value).items()
            if not item_key.startswith("_")
        }
    return str(value)


def payment_record(payment: Any, *, include_sensitive: bool) -> dict[str, Any]:
    raw = to_jsonable(payment, include_sensitive=include_sensitive)
    if not isinstance(raw, dict):
        return {"raw": raw}
    timestamp = raw.get("timestamp")
    if isinstance(timestamp, int):
        raw["timestamp_iso"] = datetime.fromtimestamp(
            timestamp, tz=timezone.utc
        ).isoformat()
    return raw


async def run() -> dict[str, Any]:
    args = parse_args()
    if args.limit <= 0:
        raise RuntimeError("--limit must be greater than zero")
    if args.offset < 0:
        raise RuntimeError("--offset must be zero or greater")

    try:
        import breez_sdk_spark as breez
    except ImportError as exc:
        raise RuntimeError(
            "Install Breez support first: python -m pip install '.[breez]'"
        ) from exc

    api_key = require_env("BREEZ_API_KEY")
    mnemonic = require_env("BREEZ_MNEMONIC")
    storage_dir = Path(args.storage_dir).expanduser()
    storage_dir.mkdir(parents=True, exist_ok=True)

    config = breez.default_config(network=network_value(breez, args.network))
    config.api_key = api_key
    seed = breez.Seed.MNEMONIC(mnemonic=mnemonic, passphrase=None)

    sdk = await breez.connect(
        request=breez.ConnectRequest(
            config=config,
            seed=seed,
            storage_dir=str(storage_dir),
        )
    )
    try:
        info = await sdk.get_info(request=breez.GetInfoRequest(ensure_synced=True))
        response = await sdk.list_payments(
            request=breez.ListPaymentsRequest(
                type_filter=enum_value(breez.PaymentType, args.type),
                status_filter=enum_value(breez.PaymentStatus, args.status),
                from_timestamp=parse_timestamp(args.from_timestamp),
                to_timestamp=parse_timestamp(args.to_timestamp),
                offset=args.offset,
                limit=args.limit,
                sort_ascending=args.ascending,
            )
        )
        payments = [
            payment_record(payment, include_sensitive=args.include_sensitive)
            for payment in response.payments
        ]
        return {
            "ok": True,
            "identity_pubkey": info.identity_pubkey,
            "balance_sats": info.balance_sats,
            "storage_dir": str(storage_dir),
            "count": len(payments),
            "payments": payments,
        }
    finally:
        await sdk.disconnect()


def main() -> int:
    try:
        print(json.dumps(asyncio.run(run()), indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
