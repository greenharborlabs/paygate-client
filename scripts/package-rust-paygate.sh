#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 provision-lock --repo PATH --record PATH --confirm PROVISION_PAYGATE_RUNTIME_LOCK | $0 --repo PATH --record PATH --output PATH" >&2
  exit 2
}

mode=package
if [[ "${1:-}" == provision-lock ]]; then mode=provision; shift; fi
repo="" record="" output="" confirm=""
while (($#)); do
  case "$1" in
    --repo) repo=${2:?}; shift 2 ;;
    --record) record=${2:?}; shift 2 ;;
    --output) output=${2:?}; shift 2 ;;
    --confirm) confirm=${2:?}; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$repo" && -n "$record" ]] || usage
if [[ "$mode" == provision ]]; then
  [[ -z "$output" && "$confirm" == PROVISION_PAYGATE_RUNTIME_LOCK ]] || usage
else
  [[ -n "$output" && -z "$confirm" ]] || usage
fi
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
if [[ "$mode" == provision ]]; then
  python3 - "$record" "$runtime_binding_record" "$runtime_lock" "$runtime_marker" "$runtime_uid" <<'PY'
import fcntl,hashlib,json,os,pathlib,stat,sys
record,binding,lock,marker=map(pathlib.Path,sys.argv[1:5]); uid=int(sys.argv[5]); flags=os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)
if binding.exists() or binding.is_symlink(): raise SystemExit('package: runtime lock binding already exists; ordinary packaging must reuse it')
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
 data={'schema':'paygate-runtime-lock-binding-v1','preflight':str(record.resolve()),'preflight_sha256':hashlib.sha256(record.read_bytes()).hexdigest(),'runtime_lock':str(lock),'runtime_transaction_marker':str(marker),'runtime_lock_uid':uid,'runtime_lock_dev':fs.st_dev,'runtime_lock_ino':fs.st_ino}
 raw=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode(); binding_fd=os.open(binding,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o400)
 try: os.write(binding_fd,raw); os.fsync(binding_fd)
 finally: os.close(binding_fd)
 parent_fd=os.open(binding.parent,os.O_RDONLY); os.fsync(parent_fd); os.close(parent_fd)
finally: os.close(fd)
PY
  echo "$runtime_binding_record"
  exit 0
fi
runtime_identity=$(python3 - "$record" "$runtime_binding_record" "$runtime_lock" "$runtime_marker" "$runtime_uid" <<'PY'
import fcntl,hashlib,json,os,pathlib,stat,sys
record,binding,lock,marker=map(pathlib.Path,sys.argv[1:5]); uid=int(sys.argv[5])
try: binding_fd=os.open(binding,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
except OSError: raise SystemExit('package: provisioned runtime lock binding is required')
try: binding_stat=os.fstat(binding_fd); raw=os.read(binding_fd,16385)
finally: os.close(binding_fd)
try: binding_ls=binding.lstat(); data=json.loads(raw)
except (OSError,UnicodeError,json.JSONDecodeError): raise SystemExit('package: runtime lock binding is unsafe')
keys={'schema','preflight','preflight_sha256','runtime_lock','runtime_transaction_marker','runtime_lock_uid','runtime_lock_dev','runtime_lock_ino'}
if not stat.S_ISREG(binding_stat.st_mode) or (binding_ls.st_dev,binding_ls.st_ino)!=(binding_stat.st_dev,binding_stat.st_ino) or binding_stat.st_uid!=os.geteuid() or binding_stat.st_nlink!=1 or stat.S_IMODE(binding_stat.st_mode)!=0o400 or binding_stat.st_size!=len(raw) or not raw or len(raw)>16384 or set(data)!=keys or data.get('schema')!='paygate-runtime-lock-binding-v1' or data.get('preflight')!=str(record.resolve()) or data.get('preflight_sha256')!=hashlib.sha256(record.read_bytes()).hexdigest() or data.get('runtime_lock')!=str(lock) or data.get('runtime_transaction_marker')!=str(marker) or data.get('runtime_lock_uid')!=uid: raise SystemExit('package: runtime lock binding is unsafe')
try: fd=os.open(lock,os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
except OSError: raise SystemExit('package: provisioned deployment lock is unavailable')
try:
 fs=os.fstat(fd); ls=lock.lstat()
 if not stat.S_ISREG(fs.st_mode) or (ls.st_dev,ls.st_ino)!=(fs.st_dev,fs.st_ino) or (fs.st_dev,fs.st_ino)!=(data['runtime_lock_dev'],data['runtime_lock_ino']) or fs.st_uid!=uid or fs.st_nlink!=1 or stat.S_IMODE(fs.st_mode)!=0o600: raise SystemExit('package: provisioned deployment lock identity changed')
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 ls=lock.lstat()
 if (ls.st_dev,ls.st_ino)!=(fs.st_dev,fs.st_ino): raise SystemExit('package: deployment lock changed while binding candidate')
 print(fs.st_dev,fs.st_ino,sep='\t')
finally: os.close(fd)
PY
)
IFS=$'\t' read -r runtime_lock_dev runtime_lock_ino <<< "$runtime_identity"

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
(cd "$work" && PAYGATE_DEPLOYMENT_RUNTIME_LOCK="$runtime_lock" PAYGATE_DEPLOYMENT_TRANSACTION_MARKER="$runtime_marker" PAYGATE_DEPLOYMENT_RUNTIME_UID="$runtime_uid" PAYGATE_DEPLOYMENT_RUNTIME_LOCK_DEV="$runtime_lock_dev" PAYGATE_DEPLOYMENT_RUNTIME_LOCK_INO="$runtime_lock_ino" cargo build --locked --release --target "$target" --bin paygate)
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

python3 - "$stage/manifest.json" "$source_commit" "$lock_hash" "$binary_hash" "$target" "$rustc_version" "$runtime_lock" "$runtime_marker" "$runtime_uid" "$runtime_lock_dev" "$runtime_lock_ino" <<'PY'
import json,os,sys,tempfile
path,commit,lock_hash,binary_hash,target,rustc_version,runtime_lock,runtime_marker,runtime_uid,runtime_lock_dev,runtime_lock_ino=sys.argv[1:]
data={"schema":"paygate-rust-candidate-v1","package":"paygate-client","binary":"paygate",
      "source_commit":commit,"cargo_lock_sha256":lock_hash,"binary_sha256":binary_hash,
      "rust_target":target,"rustc_version":rustc_version,"runtime_lock":runtime_lock,
      "runtime_transaction_marker":runtime_marker,"runtime_lock_uid":int(runtime_uid),
      "runtime_lock_dev":int(runtime_lock_dev),"runtime_lock_ino":int(runtime_lock_ino)}
with open(path,"w") as f: json.dump(data,f,sort_keys=True,indent=2); f.write("\n")
os.chmod(path,0o444)
PY
mv "$stage" "$output"
stage=""
echo "$output"
