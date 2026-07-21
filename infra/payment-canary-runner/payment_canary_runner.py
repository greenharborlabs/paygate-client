#!/usr/bin/env python3
"""Fail-closed deployment-owned payment-canary control-plane runner."""
import argparse, fcntl, json, os, stat, subprocess
from pathlib import Path

ROOT=Path("/opt/paygate/payment-canary-runner/current"); RUNNER=ROOT/"payment-canary-runner"; ADAPTER=ROOT/"protected-payment-adapter"; SANDBOX=ROOT/"candidate-sandbox"
LEDGER=Path("/var/lib/paygate/payment-canary/durable-ledger.jsonl"); RESULT=Path("/var/lib/paygate/payment-canary/result.json")
def attempt_key(a): return ":".join((a.source_commit,a.cargo_lock_sha256,a.backend,a.workflow_run_id))
def validate_protected_path(path, executable=False):
    path=Path(path)
    if not path.is_absolute(): raise ValueError("protected path must be absolute")
    current=Path("/")
    for component in path.parts[1:]:
        current/=component; st=os.lstat(current)
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022: raise ValueError("unsafe protected path")
        if current != path and not stat.S_ISDIR(st.st_mode): raise ValueError("unsafe protected component")
    if not stat.S_ISREG(st.st_mode) or (executable and not st.st_mode & 0o111): raise ValueError("unsafe protected executable")
def append(record):
    validate_protected_path(LEDGER.parent)
    with LEDGER.open("a+",encoding="utf-8") as stream:
        fcntl.flock(stream,fcntl.LOCK_EX); stream.seek(0)
        states={json.loads(line)["attempt_key"]:json.loads(line)["state"] for line in stream if line.strip()}
        if record["state"]=="claimed" and record["attempt_key"] in states and states[record["attempt_key"]]!="unsubmitted_released": return False
        stream.write(json.dumps(record,sort_keys=True,separators=(",",":"))+"\n");stream.flush();os.fsync(stream.fileno())
    return True
def main():
    p=argparse.ArgumentParser();p.add_argument("--backend",required=True);p.add_argument("--source-commit",required=True);p.add_argument("--cargo-lock-sha256",required=True);p.add_argument("--workflow-run-id",required=True);p.add_argument("--result",type=Path,required=True);a=p.parse_args()
    if a.result != RESULT: raise SystemExit("fixed result path required")
    try:
        for candidate in (ROOT,RUNNER,ADAPTER,SANDBOX): validate_protected_path(candidate,candidate != ROOT)
    except (OSError,ValueError) as e: raise SystemExit("protected deployment unavailable; no invoice created") from e
    key=attempt_key(a)
    if not append({"attempt_key":key,"state":"claimed"}): raise SystemExit("attempt already claimed; permanently refusing retry")
    proc=subprocess.run([str(SANDBOX),"--deny-network","--",str(ADAPTER),"--attempt-key",key,"--result",str(RESULT)],cwd="/",env={"PATH":"/usr/bin:/bin","LANG":"C","PAYGATE_NETWORK_DENY":"required"},stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if proc.returncode:
        append({"attempt_key":key,"state":"submitted_unknown_permanent_no_retry"});raise SystemExit("adapter outcome ambiguous; permanently refusing retry")
if __name__=="__main__": main()
