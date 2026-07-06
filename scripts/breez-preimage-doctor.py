#!/usr/bin/env python3
"""Pay a BOLT11 invoice with Breez SDK Spark and verify the returned preimage.

This is intentionally isolated from paygate-client runtime code. It is a spike
for proving whether Breez can satisfy Paygate's hard payer contract:
pay_invoice(bolt11) -> payment_hash + preimage.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import os
import re
import sys
import uuid
from enum import Enum
from pathlib import Path
from typing import Any

HEX_32_BYTES = re.compile(r"^[0-9a-fA-F]{64}$")
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
    "private",
    "secret",
    "seed",
    "token",
)


class DoctorError(Exception):
    """Raised for expected doctor failures that should print as JSON."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Pay a BOLT11 invoice with Breez SDK Spark using prefer_spark=false "
            "and verify sha256(preimage) == payment_hash."
        )
    )
    parser.add_argument("invoice", help="BOLT11 invoice to pay")
    parser.add_argument(
        "--amount-sats",
        type=int,
        default=None,
        help="Amount for amountless invoices. Omit for fixed-amount invoices.",
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
        "--timeout-secs",
        type=int,
        default=int(os.environ.get("BREEZ_COMPLETION_TIMEOUT_SECS", "10")),
        help="Breez completion timeout for the Lightning send.",
    )
    parser.add_argument(
        "--idempotency-key",
        default=os.environ.get("BREEZ_IDEMPOTENCY_KEY"),
        help="Optional UUID idempotency key. Defaults to a generated UUID.",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Include sanitized raw prepare/send/payment objects in JSON output.",
    )
    return parser.parse_args()


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise DoctorError(
            "MISSING_ENV",
            f"{name} is required. Set it before running the Breez preimage doctor.",
        )
    return value


def network_value(sdk_module: Any, network_name: str) -> Any:
    network = sdk_module.Network
    attr = network_name.upper()
    if hasattr(network, attr):
        return getattr(network, attr)
    raise DoctorError("UNSUPPORTED_NETWORK", f"Breez SDK does not expose {attr}.")


def normalize_hex_32(value: str | None, *, field_name: str) -> str:
    if not value:
        raise DoctorError(
            "BREEZ_MISSING_PREIMAGE" if field_name == "preimage" else "MISSING_FIELD",
            (
                "Breez reported payment success, but no usable Lightning preimage "
                "was returned. Ensure prefer_spark=false and the payment completed "
                "over Lightning."
            )
            if field_name == "preimage"
            else f"Breez payment object did not include {field_name}.",
        )
    if not HEX_32_BYTES.fullmatch(value):
        raise DoctorError(
            "INVALID_FIELD",
            f"Breez returned {field_name}, but it is not a 32-byte hex string.",
        )
    return value.lower()


def verify_preimage(preimage_hex: str, payment_hash_hex: str) -> bool:
    calculated = hashlib.sha256(bytes.fromhex(preimage_hex)).hexdigest()
    return calculated == payment_hash_hex


def get_field(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


def iter_nested(value: Any) -> list[Any]:
    if value is None or isinstance(value, (str, int, float, bool)):
        return []
    if isinstance(value, dict):
        return list(value.values())
    if dataclasses.is_dataclass(value):
        return [getattr(value, field.name) for field in dataclasses.fields(value)]
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if hasattr(value, "__dict__"):
        return list(vars(value).values())
    return []


def find_first_field(root: Any, field_name: str) -> str | None:
    seen: set[int] = set()
    stack = [root]
    while stack:
        value = stack.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        candidate = get_field(value, field_name)
        if isinstance(candidate, str) and candidate:
            return candidate
        stack.extend(iter_nested(value))
    return None


def sanitize_for_json(value: Any, *, key: str | None = None, depth: int = 0) -> Any:
    if depth > 12:
        return "<max-depth>"
    if key and any(part in key.lower() for part in SENSITIVE_KEY_PARTS):
        return "<redacted>"
    if dataclasses.is_dataclass(value):
        return {
            field.name: sanitize_for_json(
                getattr(value, field.name), key=field.name, depth=depth + 1
            )
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, dict):
        return {
            str(item_key): sanitize_for_json(
                item_value, key=str(item_key), depth=depth + 1
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_for_json(item, depth=depth + 1) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "__dict__"):
        return sanitize_for_json(vars(value), depth=depth + 1)
    return repr(value)


async def run() -> dict[str, Any]:
    args = parse_args()
    api_key = require_env("BREEZ_API_KEY")
    mnemonic = require_env("BREEZ_MNEMONIC")

    try:
        import breez_sdk_spark as breez
    except ImportError as exc:
        raise DoctorError(
            "MISSING_DEPENDENCY",
            "Install the Breez SDK first: python3 -m pip install breez-sdk-spark",
        ) from exc

    storage_dir = Path(args.storage_dir).expanduser()
    storage_dir.mkdir(parents=True, exist_ok=True)

    seed = breez.Seed.MNEMONIC(mnemonic=mnemonic, passphrase=None)
    config = breez.default_config(network=network_value(breez, args.network))
    config.api_key = api_key

    sdk = None
    try:
        sdk = await breez.connect(
            request=breez.ConnectRequest(
                config=config,
                seed=seed,
                storage_dir=str(storage_dir),
            )
        )

        prepare_request = breez.PrepareSendPaymentRequest(
            payment_request=breez.PaymentRequest.INPUT(input=args.invoice),
            amount=args.amount_sats,
            token_identifier=None,
            conversion_options=None,
            fee_policy=None,
        )
        prepare_response = await sdk.prepare_send_payment(request=prepare_request)

        send_options = breez.SendPaymentOptions.BOLT11_INVOICE(
            prefer_spark=False,
            completion_timeout_secs=args.timeout_secs,
        )
        send_request = breez.SendPaymentRequest(
            prepare_response=prepare_response,
            options=send_options,
            idempotency_key=args.idempotency_key or str(uuid.uuid4()),
        )
        send_response = await sdk.send_payment(request=send_request)
        payment = send_response.payment

        payment_hash = normalize_hex_32(
            find_first_field(payment, "payment_hash"),
            field_name="payment_hash",
        )
        preimage = normalize_hex_32(
            find_first_field(payment, "preimage"),
            field_name="preimage",
        )
        verified = verify_preimage(preimage, payment_hash)
        if not verified:
            raise DoctorError(
                "BREEZ_PREIMAGE_HASH_MISMATCH",
                "Breez returned a preimage, but sha256(preimage) != payment_hash.",
            )

        result: dict[str, Any] = {
            "ok": True,
            "result": "PASS",
            "payment_hash": payment_hash,
            "preimage": preimage,
            "amount_sats": get_field(payment, "amount"),
            "fee_sats": get_field(payment, "fees"),
            "prefer_spark": False,
            "preimage_verified": True,
        }
        if args.raw:
            result["raw"] = {
                "prepare_response": sanitize_for_json(prepare_response),
                "send_response": sanitize_for_json(send_response),
                "payment": sanitize_for_json(payment),
            }
        return result
    finally:
        if sdk is not None:
            await sdk.disconnect()


def main() -> int:
    try:
        payload = asyncio.run(run())
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except DoctorError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "result": "FAIL",
                    "error": {"code": exc.code, "message": exc.message},
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "result": "FAIL",
                    "error": {
                        "code": "BREEZ_PAYMENT_FAILED",
                        "message": str(exc),
                    },
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
