#!/usr/bin/env bash
# Validate exactly the distribution bytes produced by a release build.
set -euo pipefail

dist_dir=${1:-dist}
expected_version=${2:?usage: scripts/check-dist.sh DIST_DIR EXPECTED_VERSION}

if [[ ! -d "$dist_dir" ]]; then
  echo "distribution directory does not exist: $dist_dir" >&2
  exit 1
fi

mapfile -t packages < <(find "$dist_dir" -maxdepth 1 -type f \( -name '*.whl' -o -name '*.tar.gz' \) -print | sort)
if [[ ${#packages[@]} -ne 2 ]]; then
  echo "expected exactly one wheel and one sdist; found ${#packages[@]} package files" >&2
  exit 1
fi

wheel=$(find "$dist_dir" -maxdepth 1 -type f -name '*.whl' -print -quit)
sdist=$(find "$dist_dir" -maxdepth 1 -type f -name '*.tar.gz' -print -quit)
if [[ -z "$wheel" || -z "$sdist" ]]; then
  echo "expected one wheel and one sdist" >&2
  exit 1
fi

python -m twine check --strict "${packages[@]}"

# The source tree is not the release artifact. Read each archive's own metadata
# before installing it so a dynamic-version or packaging mismatch fails before
# an OIDC-capable publish job is allowed to run.
python - "$wheel" "$sdist" "$expected_version" <<'PY'
import email
import sys
import tarfile
import zipfile

wheel, sdist, expected = sys.argv[1:]
with zipfile.ZipFile(wheel) as archive:
    metadata_names = [name for name in archive.namelist() if name.endswith('.dist-info/METADATA')]
    if len(metadata_names) != 1:
        raise SystemExit(f"wheel must contain exactly one .dist-info/METADATA, found {metadata_names}")
    wheel_version = email.message_from_bytes(archive.read(metadata_names[0]))['Version']
with tarfile.open(sdist, 'r:gz') as archive:
    metadata_members = [member for member in archive.getmembers() if member.name.endswith('/PKG-INFO')]
    if len(metadata_members) != 1:
        raise SystemExit(f"sdist must contain exactly one PKG-INFO, found {[member.name for member in metadata_members]}")
    sdist_version = email.message_from_binary_file(archive.extractfile(metadata_members[0]))['Version']
if wheel_version != expected or sdist_version != expected:
    raise SystemExit(
        f"built metadata version mismatch: expected {expected}, wheel={wheel_version}, sdist={sdist_version}"
    )
PY

validate_install() {
  local artifact=$1
  local work
  work=$(mktemp -d)
  trap 'rm -rf "$work"' RETURN
  python -m venv "$work/venv"
  "$work/venv/bin/python" -m pip install --upgrade pip
  # Run outside the checkout so imports cannot accidentally use source files.
  (
    cd "$work"
    "$work/venv/bin/python" -m pip install "$OLDPWD/$artifact"
    actual_version=$("$work/venv/bin/python" -c 'import importlib.metadata; print(importlib.metadata.version("paygate-client"))')
    [[ "$actual_version" == "$expected_version" ]]
    source_version=$("$work/venv/bin/python" -c 'import paygate_client; print(paygate_client.__version__)')
    [[ "$source_version" == "$expected_version" ]]
    [[ "$("$work/venv/bin/paygate" --version)" == "$expected_version" ]]
    module_path=$("$work/venv/bin/python" -c 'import paygate_client; print(paygate_client.__file__)')
    [[ "$module_path" == "$work"/* ]]
  )
}

validate_install "$wheel"
validate_install "$sdist"
