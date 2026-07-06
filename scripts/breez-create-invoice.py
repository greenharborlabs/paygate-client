#!/usr/bin/env python3
"""Create a Breez SDK Spark BOLT11 receive invoice."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a Breez SDK Spark BOLT11 invoice for funding/testing."
    )
    parser.add_argument(
        "--amount-sats",
        type=int,
        default=1000,
        help="Invoice amount in sats. Defaults to 1000.",
    )
    parser.add_argument(
        "--description",
        default="fund paygate breez test",
        help="Invoice memo/description.",
    )
    parser.add_argument(
        "--expiry-secs",
        type=int,
        default=3600,
        help="Invoice expiry in seconds. Defaults to 3600.",
    )
    parser.add_argument(
        "--storage-dir",
        default=os.environ.get("BREEZ_STORAGE_DIR", ".breez-preimage-doctor"),
        help="Breez SDK storage directory. Defaults to BREEZ_STORAGE_DIR.",
    )
    return parser.parse_args()


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


async def run() -> dict[str, Any]:
    args = parse_args()
    if args.amount_sats <= 0:
        raise RuntimeError("--amount-sats must be greater than zero")
    if args.expiry_secs <= 0:
        raise RuntimeError("--expiry-secs must be greater than zero")

    try:
        import breez_sdk_spark as breez
    except ImportError as exc:
        raise RuntimeError(
            "Install the Breez SDK first: python -m pip install breez-sdk-spark"
        ) from exc

    api_key = require_env("BREEZ_API_KEY")
    mnemonic = require_env("BREEZ_MNEMONIC")
    storage_dir = Path(args.storage_dir).expanduser()
    storage_dir.mkdir(parents=True, exist_ok=True)

    config = breez.default_config(network=breez.Network.MAINNET)
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
        response = await sdk.receive_payment(
            request=breez.ReceivePaymentRequest(
                payment_method=breez.ReceivePaymentMethod.BOLT11_INVOICE(
                    description=args.description,
                    amount_sats=args.amount_sats,
                    expiry_secs=args.expiry_secs,
                    payment_hash=None,
                )
            )
        )
        return {
            "ok": True,
            "payment_request": response.payment_request,
            "amount_sats": args.amount_sats,
            "receive_fee_sats": response.fee,
            "description": args.description,
            "expiry_secs": args.expiry_secs,
            "storage_dir": str(storage_dir),
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
