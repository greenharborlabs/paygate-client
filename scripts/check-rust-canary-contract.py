#!/usr/bin/env python3
"""Validate immutable canary preconditions; this script never creates invoices."""
import argparse, json
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument("--contract", type=Path, default=Path("security/payment-canary-contract.yaml")); p.add_argument("--backend", required=True); p.add_argument("--runner-identity", required=True); a=p.parse_args()
c=json.loads(a.contract.read_text())
if c.get("schema_version") != 1 or a.backend not in c.get("backends", {}): raise SystemExit("invalid canary contract")
b=c["backends"][a.backend]
if not isinstance(b.get("cap_msat"), int) or b["cap_msat"] <= 0: raise SystemExit("immutable backend cap required")
if a.runner_identity != b.get("runner_identity") or c.get("attestation", {}).get("required") is not True: raise SystemExit("unapproved protected runner contract")
ledger=c.get("durable_ledger", {})
if ledger.get("authority") != "runner-contract://durable-atomic-ledger" or ledger.get("submitted_unknown") != "permanent-no-retry": raise SystemExit("durable no-retry ledger contract required")
print("canary contract: PASS")
