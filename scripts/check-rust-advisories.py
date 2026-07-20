#!/usr/bin/env python3
"""Offline advisory policy bound to the exact Cargo.lock package set."""
import argparse, hashlib, json
from pathlib import Path

p=argparse.ArgumentParser(); p.add_argument("--lock", type=Path, default=Path("Cargo.lock")); p.add_argument("--snapshot", type=Path, default=Path("security/advisory-snapshot.json")); a=p.parse_args()
lock=a.lock.read_bytes(); snapshot=json.loads(a.snapshot.read_text())
if snapshot.get("schema_version") != 1 or snapshot.get("cargo_lock_sha256") != hashlib.sha256(lock).hexdigest(): raise SystemExit("advisory snapshot is not pinned to Cargo.lock")
if not isinstance(snapshot.get("advisories"), list) or not isinstance(snapshot.get("exemptions"), list): raise SystemExit("invalid advisory policy")
seen=set()
for advisory in snapshot["advisories"]:
    if not isinstance(advisory, dict) or set(advisory) != {"id","package","affected_versions"}: raise SystemExit("invalid advisory")
    if advisory["id"] in seen: raise SystemExit("duplicate advisory")
    seen.add(advisory["id"])
    if f'name = "{advisory["package"]}"'.encode() in lock: raise SystemExit(f"unresolved advisory: {advisory['id']}")
for exemption in snapshot["exemptions"]:
    if not isinstance(exemption, dict) or set(exemption) != {"id","rationale","expires_on"} or exemption["id"] not in seen: raise SystemExit("invalid exemption")
print("Rust advisory policy: PASS")
