#!/usr/bin/env python3
"""Verify an exact, fresh signed live infrastructure attestation."""
import argparse,base64,datetime as dt,json,subprocess,tempfile
from pathlib import Path
def canon(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def fail(s):raise ValueError(s)
def timestamp(s):
 if not isinstance(s,str):fail("invalid timestamp")
 return dt.datetime.fromisoformat(s.replace("Z","+00:00"))
def verify(payload,signature,pub):
 if not isinstance(signature,str):fail("invalid detached signature")
 try:sig=base64.b64decode(signature,validate=True)
 except Exception:fail("invalid detached signature")
 with tempfile.TemporaryDirectory() as d:
  p,s=Path(d)/"p",Path(d)/"s";p.write_bytes(canon(payload));s.write_bytes(sig)
  if subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",str(pub),"-rawin","-in",str(p),"-sigfile",str(s)],capture_output=True).returncode:fail("signature rejected")
def key(c,kid,issuer,when):
 ring=json.loads(Path(c["keyrings"]["infrastructure"]["path"]).read_text())
 if ring.get("purpose")!=c["keyrings"]["infrastructure"]["purpose"]:fail("wrong-purpose keyring")
 hits=[x for x in ring.get("keys",[]) if x.get("id")==kid and x.get("issuer")==issuer]
 if len(hits)!=1 or hits[0].get("revoked") is not False:fail("unknown signing key")
 if not timestamp(hits[0].get("not_before"))<=when<=timestamp(hits[0].get("not_after")):fail("expired signing key")
 return Path(hits[0]["public_key"])
def main():
 p=argparse.ArgumentParser();p.add_argument("--contract",type=Path,default=Path("security/payment-canary-contract.yaml"));p.add_argument("--inventory",type=Path,default=Path("infra/runners/payment-canary.yml"));p.add_argument("--audit",type=Path,default=Path("infra/runners/payment-canary-github-audit.json"));p.add_argument("--backend",required=True);p.add_argument("--runner-identity",required=True);p.add_argument("--infrastructure-attestation",type=Path,required=True);a=p.parse_args()
 try:
  c=json.loads(a.contract.read_text());inv=json.loads(a.inventory.read_text());baseline=json.loads(a.audit.read_text())
  if c.get("schema_version")!=4 or not isinstance(baseline,dict):fail("unsupported contract or audit")
  # Exact deployment and durable-ledger authority must agree between contract and inventory.
  if inv.get("deployment",{}).get("immutable_digest")!=c["deployment"]["immutable_digest"] or inv.get("deployment",{}).get("paths")!=c["deployment"]["paths"] or inv.get("durable_ledger",{}).get("authority_uri")!=c["durable_ledger"]["authority_uri"] or inv.get("durable_ledger",{}).get("record_version")!=c["durable_ledger"]["record_version"]:fail("deployment inventory mismatch")
  for item in c["deployment"]["paths"].values():
   if not isinstance(item,dict) or item.get("owner_uid")!=0 or item.get("mode") not in ("0755","0555"):fail("unsafe deployment authority")
  b=c["backends"][a.backend];runner=inv["runners"][a.backend]
  if a.runner_identity!=b["runner_identity"] or runner.get("identity")!=a.runner_identity:fail("unapproved runner")
  raw=json.loads(a.infrastructure_attestation.read_text());fields=set(c["live_infrastructure_attestation"]["required_claims"])|{"issuer","key_id","issued_at","expires_at","signature"}
  if not isinstance(raw,dict) or set(raw)!=fields:fail("missing or unexpected live claims")
  sig=raw["signature"];att={k:v for k,v in raw.items() if k!="signature"}; issued,expiry=timestamp(att["issued_at"]),timestamp(att["expires_at"]);now=dt.datetime.now(dt.timezone.utc)
  if issued>now or expiry<=now or (expiry-issued).total_seconds()>c["live_infrastructure_attestation"]["max_age_seconds"]:fail("stale attestation")
  expected={"repository":c["repository"]["id"],"environment":b["environment"],"environment_protection":True,"reviewers":True,"allowed_deploy_refs":c["repository"]["allowed_deploy_refs"],"branch_restrictions":c["repository"]["branch_restrictions"],"runner_group_repository_access":True,"runner_group":runner["group"],"labels":runner["labels"],"backend":a.backend}
  for name,value in expected.items():
   if att.get(name)!=value:fail("live claim mismatch: "+name)
  if not isinstance(att["configuration_digest"],str) or not att["configuration_digest"].startswith("sha256:") or len(att["configuration_digest"])!=71:fail("invalid configuration digest")
  if not isinstance(att["issuer"],str) or not isinstance(att["key_id"],str):fail("invalid signer")
  verify(att,sig,key(c,att["key_id"],att["issuer"],issued))
 except (OSError,KeyError,TypeError,ValueError,json.JSONDecodeError) as e:print("canary contract: FAIL:",e);return 1
 print("canary contract: PASS");return 0
if __name__=="__main__":raise SystemExit(main())
