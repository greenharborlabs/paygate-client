#!/usr/bin/env python3
"""Fail-closed validation of a signed, redacted canary result and receipt."""
import argparse,base64,datetime as dt,hashlib,json,re,subprocess,tempfile
from pathlib import Path
HEX=re.compile(r"^[0-9a-f]{64}$"); BAD=re.compile(r"(^invoice$|raw|preimage|credential|token|secret|authorization)",re.I)
def canon(v): return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def fail(s): raise ValueError(s)
def timestamp(s):
 if not isinstance(s,str): fail("invalid timestamp")
 return dt.datetime.fromisoformat(s.replace("Z","+00:00"))
def no_secrets(v):
 if isinstance(v,dict):
  for k,x in v.items():
   if not isinstance(k,str) or BAD.search(k): fail("secret-bearing field")
   no_secrets(x)
 elif isinstance(v,list):
  for x in v:no_secrets(x)
 elif isinstance(v,str) and (v.lower().startswith("lnbc") or "preimage" in v.lower()): fail("secret-bearing value")
def verify(payload,sig,pub):
 if not isinstance(sig,str): fail("invalid signature")
 try: raw=base64.b64decode(sig,validate=True)
 except Exception: fail("invalid signature")
 with tempfile.TemporaryDirectory() as d:
  p,s=Path(d)/"p",Path(d)/"s";p.write_bytes(canon(payload));s.write_bytes(raw)
  if subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",str(pub),"-rawin","-in",str(p),"-sigfile",str(s)],capture_output=True).returncode: fail("signature rejected")
def public(c,purpose,kid,issuer,when):
 ring=json.loads(Path(c["keyrings"][purpose]["path"]).read_text())
 if ring.get("purpose")!=c["keyrings"][purpose]["purpose"]:fail("wrong-purpose keyring")
 ks=[x for x in ring.get("keys",[]) if x.get("id")==kid and x.get("issuer")==issuer]
 if len(ks)!=1 or ks[0].get("revoked") is not False:fail("unknown key")
 if not timestamp(ks[0].get("not_before"))<=when<=timestamp(ks[0].get("not_after")):fail("expired key")
 return Path(ks[0]["public_key"])
def expected(a): return ":".join((a.source_commit,a.cargo_lock_sha256,a.backend,a.workflow_run_id))
def exact(obj,fields):
 if not isinstance(obj,dict) or set(obj)!=set(fields):fail("unexpected schema")
def main():
 p=argparse.ArgumentParser();p.add_argument("result",type=Path);p.add_argument("--contract",type=Path,default=Path("security/payment-canary-contract.yaml"));p.add_argument("--backend",required=True);p.add_argument("--source-commit",required=True);p.add_argument("--cargo-lock-sha256",required=True);p.add_argument("--workflow-run-id",required=True);a=p.parse_args()
 try:
  c=json.loads(a.contract.read_text());raw=json.loads(a.result.read_text());exact(raw,{"backend","source_commit","cargo_lock_sha256","workflow_run_id","attempt_key","invoice_hash","payment_hash","spend_msat","fee_msat","cap_msat","proof","redaction","state","durable_receipt","runner_identity","issued_at","issuer","key_id","signature"});no_secrets(raw)
  sig=raw["signature"];r={k:v for k,v in raw.items() if k!="signature"};b=c["backends"][a.backend]
  if [r[x] for x in ("backend","source_commit","cargo_lock_sha256","workflow_run_id") ] != [a.backend,a.source_commit,a.cargo_lock_sha256,a.workflow_run_id] or r["attempt_key"]!=expected(a):fail("attempt identity mismatch")
  if r["runner_identity"]!=b["runner_identity"] or r["cap_msat"]!=b["cap_msat"] or r["redaction"] is not True or r["state"]!="succeeded":fail("unapproved result")
  if not all(isinstance(r[x],str) and HEX.fullmatch(r[x]) for x in ("invoice_hash","payment_hash")) or r["invoice_hash"]!=r["payment_hash"]:fail("payment binding mismatch")
  if any(type(r[x]) is not int or r[x]<0 for x in ("spend_msat","fee_msat","cap_msat")) or r["spend_msat"]+r["fee_msat"]>r["cap_msat"]:fail("cap violated")
  exact(r["proof"],{"version","kind","invoice_hash","payment_hash","redacted_hash"})
  proof=r["proof"]
  if proof["version"]!=1 or proof["kind"]!="payment-hash-binding" or proof["invoice_hash"]!=r["invoice_hash"] or proof["payment_hash"]!=r["payment_hash"] or not isinstance(proof["redacted_hash"],str) or not HEX.fullmatch(proof["redacted_hash"]):fail("invalid proof")
  receipt=r["durable_receipt"];exact(receipt,{"authority_uri","record_version","attempt_key","result_digest","terminal_state","recorded_at","issuer","key_id","signature"});rsig=receipt["signature"];rcore={k:v for k,v in receipt.items() if k!="signature"}
  fields={"authority_uri","record_version","attempt_key","result_digest","terminal_state","recorded_at","issuer","key_id"};exact(rcore,fields)
  if rcore["authority_uri"]!=c["durable_ledger"]["authority_uri"] or rcore["record_version"]!=c["durable_ledger"]["record_version"] or rcore["attempt_key"]!=r["attempt_key"] or rcore["terminal_state"]!=c["durable_ledger"]["terminal_state"] or not isinstance(rcore["result_digest"],str) or not HEX.fullmatch(rcore["result_digest"]):fail("invalid durable receipt")
  # Both signatures are excluded from the result bytes; receipt separately binds result core.
  signed={k:( {x:y for x,y in v.items() if x!="signature"} if k=="durable_receipt" else v) for k,v in r.items()}
  if rcore["result_digest"]!=hashlib.sha256(canon({k:v for k,v in r.items() if k!="durable_receipt"})).hexdigest():fail("receipt result digest mismatch")
  verify(signed,sig,public(c,"result",r["key_id"],r["issuer"],timestamp(r["issued_at"])));verify(rcore,rsig,public(c,"ledger",rcore["key_id"],rcore["issuer"],timestamp(rcore["recorded_at"])))
 except (OSError,KeyError,TypeError,ValueError,json.JSONDecodeError) as e:print("canary result: FAIL:",e);return 1
 print("canary result: PASS");return 0
if __name__=="__main__":raise SystemExit(main())
