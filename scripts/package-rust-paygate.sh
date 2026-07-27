#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --repo PATH --record PATH --output PATH" >&2
  exit 2
}

repo="" record="" output=""
while (($#)); do
  case "$1" in
    --repo) repo=${2:?}; shift 2 ;;
    --record) record=${2:?}; shift 2 ;;
    --output) output=${2:?}; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$repo" && -n "$record" && -n "$output" ]] || usage
repo=$(cd "$repo" && pwd -P)
[[ "$output" == /* && ! -e "$output" && "$output" != "$repo" && "$output" != "$repo"/* ]] || {
  echo "package: output must be a new absolute path outside the repository" >&2; exit 2;
}
mkdir -p "$(dirname "$output")"

target=$(python3 - "$record" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); print(d["deployment"]["rust_target"])
PY
)
"$repo/scripts/preflight-minimal-rust-cutover.sh" guard --for build --repo "$repo" --record "$record" --target "$target" >/dev/null

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
(cd "$work" && cargo build --locked --release --target "$target" --bin paygate)
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

python3 - "$stage/manifest.json" "$source_commit" "$lock_hash" "$binary_hash" "$target" "$rustc_version" <<'PY'
import json,os,sys,tempfile
path,commit,lock_hash,binary_hash,target,rustc_version=sys.argv[1:]
data={"schema":"paygate-rust-candidate-v1","package":"paygate-client","binary":"paygate",
      "source_commit":commit,"cargo_lock_sha256":lock_hash,"binary_sha256":binary_hash,
      "rust_target":target,"rustc_version":rustc_version}
with open(path,"w") as f: json.dump(data,f,sort_keys=True,indent=2); f.write("\n")
os.chmod(path,0o444)
PY
mv "$stage" "$output"
stage=""
echo "$output"
