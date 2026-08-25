#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

usage() {
  echo "usage: $0 provision-lock --repo PATH --record PATH --confirm PROVISION_PAYGATE_RUNTIME_LOCK | $0 migrate-lock-binding --repo PATH --record PATH --authorization PATH --confirm MIGRATE_PAYGATE_RUNTIME_LOCK_BINDING | $0 --repo PATH --record PATH --output PATH" >&2
  exit 2
}

mode=package
if [[ "${1:-}" == provision-lock ]]; then mode=provision; shift; fi
if [[ "${1:-}" == migrate-lock-binding ]]; then mode=migrate; shift; fi
repo="" record="" output="" confirm="" authorization=""
while (($#)); do
  case "$1" in
    --repo) repo=${2:?}; shift 2 ;;
    --record) record=${2:?}; shift 2 ;;
    --output) output=${2:?}; shift 2 ;;
    --authorization) authorization=${2:?}; shift 2 ;;
    --confirm) confirm=${2:?}; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$repo" && -n "$record" ]] || usage
case "$mode" in
  provision) [[ -z "$output" && -z "$authorization" && "$confirm" == PROVISION_PAYGATE_RUNTIME_LOCK ]] || usage ;;
  migrate) [[ -z "$output" && "$authorization" == /* && "$confirm" == MIGRATE_PAYGATE_RUNTIME_LOCK_BINDING ]] || usage ;;
  package) [[ -n "$output" && -z "$authorization" && -z "$confirm" ]] || usage ;;
esac
repo=$(cd "$repo" && pwd -P)
if [[ "$mode" == package ]]; then
  [[ "$output" == /* && ! -e "$output" && "$output" != "$repo" && "$output" != "$repo"/* ]] || {
    echo "package: output must be a new absolute path outside the repository" >&2; exit 2;
  }
  mkdir -p "$(dirname "$output")"
fi

target=$(python3 - "$record" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); print(d["deployment"]["rust_target"])
PY
)
runtime_binding=$(python3 - "$record" <<'PY'
import json,pathlib,sys
d=json.load(open(sys.argv[1])); dep=d['deployment']; launcher=pathlib.Path(dep['launcher'])
uid=dep.get('process_uid')
if not launcher.is_absolute() or not isinstance(uid,int) or isinstance(uid,bool): raise SystemExit('package: invalid deployment lock binding')
launcher.parent.resolve(strict=True)
parent=launcher.parent
print(parent/'.paygate-runtime.lock',parent/'.paygate-runtime.lock.transaction.json',uid,sep='\t')
PY
)
IFS=$'\t' read -r runtime_lock runtime_marker runtime_uid <<< "$runtime_binding"
"$repo/scripts/preflight-minimal-rust-cutover.sh" guard --for build --repo "$repo" --record "$record" --target "$target" >/dev/null
runtime_binding_record="${runtime_lock}.binding.json"
runtime_binding_v2="${runtime_lock}.binding-v2.json"
if [[ "$mode" == provision ]]; then
  python3 - "$repo" "$record" "$runtime_binding_record" "$runtime_binding_v2" "$runtime_lock" "$runtime_marker" "$runtime_uid" <<'PY'
import fcntl,hashlib,json,os,pathlib,stat,sys
repo,record,binding,binding_v2,lock,marker=map(pathlib.Path,sys.argv[1:7]); uid=int(sys.argv[7]); flags=os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)
sys.path.insert(0,str(repo/'scripts')); from runtime_lock_identity import descriptor_identity
if binding.exists() or binding.is_symlink(): raise SystemExit('package: runtime lock binding already exists; ordinary packaging must reuse it')
if binding_v2.exists() or binding_v2.is_symlink(): raise SystemExit('package: unexpected runtime lock migration binding exists')
if lock.exists() or lock.is_symlink(): raise SystemExit('package: unbound deployment lock exists; refusing to adopt or replace it')
if os.geteuid()!=uid: raise SystemExit('package: deployment lock must be provisioned by its recorded owner')
fd=os.open(lock,flags|os.O_CREAT|os.O_EXCL,0o600)
try:
 fs=os.fstat(fd); ls=lock.lstat()
 if not stat.S_ISREG(fs.st_mode) or (ls.st_dev,ls.st_ino)!=(fs.st_dev,fs.st_ino) or fs.st_uid!=uid or fs.st_nlink!=1 or stat.S_IMODE(fs.st_mode)!=0o600: raise SystemExit('package: deployment lock identity is unsafe')
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 ls=lock.lstat()
 if (ls.st_dev,ls.st_ino)!=(fs.st_dev,fs.st_ino): raise SystemExit('package: deployment lock changed while binding candidate')
 os.fsync(fd); parent_fd=os.open(lock.parent,os.O_RDONLY); os.fsync(parent_fd); os.close(parent_fd)
 data={'schema':'paygate-runtime-lock-binding-v2','preflight':str(record.resolve()),'preflight_sha256':hashlib.sha256(record.read_bytes()).hexdigest(),'runtime_lock':str(lock),'runtime_transaction_marker':str(marker),'runtime_lock_uid':uid,'runtime_lock_identity':descriptor_identity(fd),'previous_binding':None,'previous_binding_sha256':None,'migration_authorization':None,'migration_authorization_sha256':None}
 raw=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode(); binding_fd=os.open(binding,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o400)
 try: os.write(binding_fd,raw); os.fsync(binding_fd)
 finally: os.close(binding_fd)
 parent_fd=os.open(binding.parent,os.O_RDONLY); os.fsync(parent_fd); os.close(parent_fd)
finally: os.close(fd)
PY
  echo "$runtime_binding_record"
  exit 0
fi

if [[ "$mode" == migrate ]]; then
  python3 - "$repo" "$record" "$runtime_binding_record" "$runtime_binding_v2" "$runtime_lock" "$runtime_marker" "$runtime_uid" "$authorization" <<'PY'
import fcntl,hashlib,json,os,pathlib,stat,subprocess,sys
repo,record,legacy,migration,lock,marker=map(pathlib.Path,sys.argv[1:7]); uid=int(sys.argv[7]); authorization=pathlib.Path(sys.argv[8])
sys.path.insert(0,str(repo/'scripts')); from runtime_lock_identity import descriptor_identity
def read(path,limit,label):
 try: fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
 except OSError: raise SystemExit(f'package: {label} is unavailable or unsafe')
 try: metadata=os.fstat(fd); raw=os.read(fd,limit+1)
 finally: os.close(fd)
 try: value=json.loads(raw)
 except (UnicodeError,json.JSONDecodeError): raise SystemExit(f'package: {label} is malformed')
 if not stat.S_ISREG(metadata.st_mode) or metadata.st_size!=len(raw) or not raw or len(raw)>limit or metadata.st_uid!=uid or metadata.st_nlink!=1 or stat.S_IMODE(metadata.st_mode)!=0o400: raise SystemExit(f'package: {label} is unsafe')
 return value,raw
if sys.platform!='darwin': raise SystemExit('package: runtime lock binding migration is only valid on macOS')
if migration.exists() or migration.is_symlink(): raise SystemExit('package: migrated runtime lock binding already exists')
old,old_raw=read(legacy,16384,'legacy runtime lock binding')
old_keys={'schema','preflight','preflight_sha256','runtime_lock','runtime_transaction_marker','runtime_lock_uid','runtime_lock_dev','runtime_lock_ino'}
record_hash=hashlib.sha256(record.read_bytes()).hexdigest()
if set(old)!=old_keys or old.get('schema')!='paygate-runtime-lock-binding-v1' or old.get('preflight')!=str(record.resolve()) or old.get('preflight_sha256')!=record_hash or old.get('runtime_lock')!=str(lock) or old.get('runtime_transaction_marker')!=str(marker) or old.get('runtime_lock_uid')!=uid: raise SystemExit('package: legacy runtime lock binding is invalid')
auth,auth_raw=read(authorization,16384,'device remap authorization')
auth_keys={'schema','boot_session_uuid','rollback_directory','rollback_manifest_sha256','preflight_sha256','installed_rust_target','installed_rust_binary_sha256','runtime_lock','runtime_lock_ino','recorded_device','current_device'}
try: boot=subprocess.run(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],check=True,text=True,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3).stdout.strip()
except (OSError,subprocess.SubprocessError): raise SystemExit('package: current boot identity is unverifiable')
rollback=pathlib.Path(auth.get('rollback_directory','')); rollback_manifest=rollback/'manifest.json'
try: rollback_raw=rollback_manifest.read_bytes(); rollback_data=json.loads(rollback_raw)
except (OSError,UnicodeError,json.JSONDecodeError): raise SystemExit('package: authorization rollback evidence is unavailable')
rust=pathlib.Path(auth.get('installed_rust_target',''))
try: rust_raw=rust.read_bytes(); rust_stat=rust.stat()
except OSError: raise SystemExit('package: authorization candidate is unavailable')
try: fd=os.open(lock,os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
except OSError: raise SystemExit('package: provisioned deployment lock is unavailable')
try:
 fs=os.fstat(fd); ls=lock.lstat()
 if not stat.S_ISREG(fs.st_mode) or (ls.st_dev,ls.st_ino)!=(fs.st_dev,fs.st_ino) or fs.st_uid!=uid or fs.st_nlink!=1 or stat.S_IMODE(fs.st_mode)!=0o600: raise SystemExit('package: deployment lock identity is unsafe')
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 if set(auth)!=auth_keys or auth.get('schema')!='paygate-rollback-device-remap-v1' or auth.get('boot_session_uuid')!=boot or auth.get('preflight_sha256')!=record_hash or auth.get('runtime_lock')!=str(lock) or auth.get('runtime_lock_ino')!=old.get('runtime_lock_ino') or auth.get('recorded_device')!=old.get('runtime_lock_dev') or auth.get('current_device')!=fs.st_dev or fs.st_ino!=old.get('runtime_lock_ino') or auth.get('recorded_device')==auth.get('current_device') or auth.get('rollback_manifest_sha256')!=hashlib.sha256(rollback_raw).hexdigest() or rollback_data.get('runtime_lock')!=str(lock) or rollback_data.get('runtime_lock_ino')!=old.get('runtime_lock_ino') or rollback_data.get('candidate_identity',{}).get('binary_sha256')!=auth.get('installed_rust_binary_sha256') or rollback_data.get('installed_rust_launcher_target')!=str(rust) or auth.get('installed_rust_binary_sha256')!=hashlib.sha256(rust_raw).hexdigest() or not stat.S_ISREG(rust_stat.st_mode) or rust_stat.st_uid!=uid or rust_stat.st_nlink!=1: raise SystemExit('package: device remap authorization is invalid')
 identity=descriptor_identity(fd)
finally: os.close(fd)
data={'schema':'paygate-runtime-lock-binding-v2','preflight':str(record.resolve()),'preflight_sha256':record_hash,'runtime_lock':str(lock),'runtime_transaction_marker':str(marker),'runtime_lock_uid':uid,'runtime_lock_identity':identity,'previous_binding':str(legacy),'previous_binding_sha256':hashlib.sha256(old_raw).hexdigest(),'migration_authorization':str(authorization),'migration_authorization_sha256':hashlib.sha256(auth_raw).hexdigest()}
raw=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode(); out_fd=os.open(migration,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o400)
try: os.write(out_fd,raw); os.fsync(out_fd)
finally: os.close(out_fd)
parent_fd=os.open(migration.parent,os.O_RDONLY); os.fsync(parent_fd); os.close(parent_fd)
PY
  echo "$runtime_binding_v2"
  exit 0
fi

if [[ -e "$runtime_binding_v2" || -L "$runtime_binding_v2" ]]; then runtime_binding_active="$runtime_binding_v2"; else runtime_binding_active="$runtime_binding_record"; fi
runtime_identity=$(python3 - "$repo" "$record" "$runtime_binding_active" "$runtime_binding_record" "$runtime_lock" "$runtime_marker" "$runtime_uid" <<'PY'
import fcntl,hashlib,json,os,pathlib,stat,sys
repo,record,binding,legacy,lock,marker=map(pathlib.Path,sys.argv[1:7]); uid=int(sys.argv[7])
sys.path.insert(0,str(repo/'scripts')); from runtime_lock_identity import descriptor_identity
try: binding_fd=os.open(binding,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
except OSError: raise SystemExit('package: provisioned runtime lock binding is required')
try: binding_stat=os.fstat(binding_fd); raw=os.read(binding_fd,16385)
finally: os.close(binding_fd)
try: binding_ls=binding.lstat(); data=json.loads(raw)
except (OSError,UnicodeError,json.JSONDecodeError): raise SystemExit('package: runtime lock binding is unsafe')
keys={'schema','preflight','preflight_sha256','runtime_lock','runtime_transaction_marker','runtime_lock_uid','runtime_lock_identity','previous_binding','previous_binding_sha256','migration_authorization','migration_authorization_sha256'}
if not stat.S_ISREG(binding_stat.st_mode) or (binding_ls.st_dev,binding_ls.st_ino)!=(binding_stat.st_dev,binding_stat.st_ino) or binding_stat.st_uid!=os.geteuid() or binding_stat.st_nlink!=1 or stat.S_IMODE(binding_stat.st_mode)!=0o400 or binding_stat.st_size!=len(raw) or not raw or len(raw)>16384 or set(data)!=keys or data.get('schema')!='paygate-runtime-lock-binding-v2' or data.get('preflight')!=str(record.resolve()) or data.get('preflight_sha256')!=hashlib.sha256(record.read_bytes()).hexdigest() or data.get('runtime_lock')!=str(lock) or data.get('runtime_transaction_marker')!=str(marker) or data.get('runtime_lock_uid')!=uid or not isinstance(data.get('runtime_lock_identity'),str): raise SystemExit('package: runtime lock binding is unsafe')
previous=data.get('previous_binding'); previous_hash=data.get('previous_binding_sha256'); authorization=data.get('migration_authorization'); authorization_hash=data.get('migration_authorization_sha256')
if previous is None:
 if binding!=legacy or any(value is not None for value in (previous_hash,authorization,authorization_hash)): raise SystemExit('package: runtime lock binding provenance is invalid')
else:
 if binding==legacy or previous!=str(legacy) or not all(isinstance(value,str) and value for value in (previous_hash,authorization,authorization_hash)): raise SystemExit('package: runtime lock binding provenance is invalid')
 for path,wanted in ((legacy,previous_hash),(pathlib.Path(authorization),authorization_hash)):
  try: held=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); source=os.read(held,16385); source_stat=os.fstat(held); os.close(held)
  except OSError: raise SystemExit('package: runtime lock binding provenance is unavailable')
  if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_uid!=uid or source_stat.st_nlink!=1 or stat.S_IMODE(source_stat.st_mode)!=0o400 or hashlib.sha256(source).hexdigest()!=wanted: raise SystemExit('package: runtime lock binding provenance is invalid')
try: fd=os.open(lock,os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
except OSError: raise SystemExit('package: provisioned deployment lock is unavailable')
try:
 fs=os.fstat(fd); ls=lock.lstat()
 if not stat.S_ISREG(fs.st_mode) or (ls.st_dev,ls.st_ino)!=(fs.st_dev,fs.st_ino) or descriptor_identity(fd)!=data['runtime_lock_identity'] or fs.st_uid!=uid or fs.st_nlink!=1 or stat.S_IMODE(fs.st_mode)!=0o600: raise SystemExit('package: provisioned deployment lock identity changed')
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 ls=lock.lstat()
 if (ls.st_dev,ls.st_ino)!=(fs.st_dev,fs.st_ino): raise SystemExit('package: deployment lock changed while binding candidate')
 print(data['runtime_lock_identity'])
finally: os.close(fd)
PY
)

source_commit=$(git -C "$repo" rev-parse HEAD)
rustc_version=$(rustc --version)
[[ "$rustc_version" == "rustc 1.88."* ]] || { echo "package: Rust 1.88 is required" >&2; exit 1; }
lock_hash=$(git -C "$repo" show "$source_commit:Cargo.lock" | shasum -a 256 | awk '{print $1}')
[[ "$lock_hash" == "$(shasum -a 256 "$repo/Cargo.lock" | awk '{print $1}')" ]] || {
  echo "package: Cargo.lock differs from the source commit" >&2; exit 1;
}

work=$(mktemp -d "${TMPDIR:-/tmp}/paygate-package.XXXXXX")
stage=$(mktemp -d "$(dirname "$output")/.paygate-candidate.XXXXXX")
cleanup() { rm -rf -- "$work"; [[ -n "$stage" && -d "$stage" ]] && rm -rf -- "$stage" || true; }
trap cleanup EXIT
git -C "$repo" archive "$source_commit" | tar -x -C "$work"
export CARGO_TARGET_DIR="$work/target"
(cd "$work" && PAYGATE_DEPLOYMENT_RUNTIME_LOCK="$runtime_lock" PAYGATE_DEPLOYMENT_TRANSACTION_MARKER="$runtime_marker" PAYGATE_DEPLOYMENT_RUNTIME_UID="$runtime_uid" PAYGATE_DEPLOYMENT_RUNTIME_LOCK_IDENTITY="$runtime_identity" cargo build --locked --release --target "$target" --bin paygate)
built="$CARGO_TARGET_DIR/$target/release/paygate"
[[ -f "$built" && -x "$built" ]] || { echo "package: expected paygate binary was not built" >&2; exit 1; }
cp "$built" "$stage/paygate"
chmod 0555 "$stage/paygate"
binary_hash=$(shasum -a 256 "$stage/paygate" | awk '{print $1}')

description=$(file -b "$stage/paygate")
case "$target" in
  x86_64-*) [[ "$description" == *x86-64* || "$description" == *x86_64* ]] ;;
  aarch64-*|arm64-*) [[ "$description" == *arm64* || "$description" == *aarch64* ]] ;;
  *) echo "package: unsupported deployment target: $target" >&2; exit 1 ;;
esac || { echo "package: binary architecture does not match deployment target" >&2; exit 1; }

python3 - "$stage/manifest.json" "$source_commit" "$lock_hash" "$binary_hash" "$target" "$rustc_version" "$runtime_lock" "$runtime_marker" "$runtime_uid" "$runtime_identity" "$runtime_binding_active" <<'PY'
import hashlib,json,os,pathlib,sys
path,commit,lock_hash,binary_hash,target,rustc_version,runtime_lock,runtime_marker,runtime_uid,runtime_identity,runtime_binding=sys.argv[1:]
data={"schema":"paygate-rust-candidate-v1","package":"paygate-client","binary":"paygate",
      "source_commit":commit,"cargo_lock_sha256":lock_hash,"binary_sha256":binary_hash,
      "rust_target":target,"rustc_version":rustc_version,"runtime_lock":runtime_lock,
      "runtime_transaction_marker":runtime_marker,"runtime_lock_uid":int(runtime_uid),
      "runtime_lock_identity":runtime_identity,"runtime_lock_binding":runtime_binding,
      "runtime_lock_binding_sha256":hashlib.sha256(pathlib.Path(runtime_binding).read_bytes()).hexdigest()}
with open(path,"w") as f: json.dump(data,f,sort_keys=True,indent=2); f.write("\n")
os.chmod(path,0o444)
PY
mv "$stage" "$output"
stage=""
echo "$output"
