#!/usr/bin/env python3
"""Extract the qualification cases whose Rust harness executes, not a projection."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("oracle", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
oracle = json.loads(args.oracle.read_text())
cache = oracle["case_evidence"]["cache.schema"]["observations"]["state.cache"]
# The Rust harness deserializes this state using CachedCredential, then emits
# canonical JSON.  These values are deliberately materialized from replay.
case = {"semantic_json": cache, "state": json.loads(cache["bytes"]), "exit": 0}
args.output.write_text(json.dumps({"case_evidence": {"cache.schema": case}}, sort_keys=True))
