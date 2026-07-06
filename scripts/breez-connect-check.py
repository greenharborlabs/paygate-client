#!/usr/bin/env python3
"""Connect to Breez SDK Spark and print wallet identity/balance."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


async def run() -> dict[str, Any]:
    try:
        import breez_sdk_spark as breez
    except ImportError as exc:
        raise RuntimeError(
            "Install the Breez SDK first: python -m pip install breez-sdk-spark"
        ) from exc

    api_key = require_env("BREEZ_API_KEY")
    mnemonic = require_env("BREEZ_MNEMONIC")
    storage_dir = Path(os.environ.get("BREEZ_STORAGE_DIR", ".breez-preimage-doctor"))
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
        info = await sdk.get_info(request=breez.GetInfoRequest(ensure_synced=True))
        return {
            "ok": True,
            "result": "CONNECTED",
            "identity_pubkey": info.identity_pubkey,
            "balance_sats": info.balance_sats,
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
                    "result": "FAIL",
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
