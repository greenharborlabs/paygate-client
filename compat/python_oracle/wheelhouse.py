"""Inspect and attest the checked-in offline wheel closure."""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from email.parser import BytesParser
from pathlib import Path
from typing import Any

PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^ \\]+)")


class WheelhouseError(RuntimeError):
    """The offline dependency closure is incomplete or unauditable."""


def canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def lock_pins(lock_path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        match = PIN.match(line)
        if match:
            name, version = match.groups()
            pins[canonical_name(name)] = version
    if not pins:
        raise WheelhouseError("dependency lock contains no exact pins")
    return pins


def inspect_wheel(path: Path, lock_text: str) -> dict[str, Any]:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if f"--hash=sha256:{digest}" not in lock_text:
        raise WheelhouseError(f"wheel hash is absent from lock: {path.name}")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        metadata_name = next(
            (
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ),
            None,
        )
        wheel_name = next(
            (name for name in archive.namelist() if name.endswith(".dist-info/WHEEL")),
            None,
        )
        record_name = next(
            (name for name in archive.namelist() if name.endswith(".dist-info/RECORD")),
            None,
        )
        if not metadata_name or not wheel_name or not record_name:
            raise WheelhouseError(f"wheel metadata is incomplete: {path.name}")
        metadata = BytesParser().parsebytes(archive.read(metadata_name))
        wheel_metadata = BytesParser().parsebytes(archive.read(wheel_name))
        license_names = sorted(
            name
            for name in archive.namelist()
            if "/licenses/" in name.lower()
            or Path(name).name.lower().startswith(("license", "copying"))
        )
        license_hashes = {
            name: hashlib.sha256(archive.read(name)).hexdigest()
            for name in license_names
        }
        declared_license_files = sorted(metadata.get_all("License-File", []))
        if not (
            metadata.get("License")
            or metadata.get("License-Expression")
            or license_hashes
        ):
            raise WheelhouseError(f"wheel has no license evidence: {path.name}")
        if declared_license_files and not license_hashes:
            raise WheelhouseError(f"declared license files are absent: {path.name}")
        return {
            "filename": path.name,
            "project": canonical_name(str(metadata["Name"])),
            "version": str(metadata["Version"]),
            "sha256": digest,
            "size": len(data),
            "tags": sorted(wheel_metadata.get_all("Tag", [])),
            "origin": f"https://pypi.org/project/{metadata['Name']}/{metadata['Version']}/",
            "acquisition": "pip download --require-hashes --only-binary=:all:",
            "tool": "pip 25.2",
            "dependencies": sorted(metadata.get_all("Requires-Dist", [])),
            "license": str(
                metadata.get("License-Expression")
                or metadata.get("License")
                or "license-file-attested"
            ).strip(),
            "license_files": license_hashes,
        }


def build_manifest(wheelhouse: Path, lock_path: Path) -> dict[str, Any]:
    lock_text = lock_path.read_text(encoding="utf-8")
    pins = lock_pins(lock_path)
    wheels = sorted(wheelhouse.glob("*.whl"))
    if not wheels or any(path.suffix != ".whl" for path in wheelhouse.iterdir()):
        raise WheelhouseError("wheelhouse must contain wheels only")
    records = [inspect_wheel(path, lock_text) for path in wheels]
    projects = {record["project"]: record["version"] for record in records}
    if projects != pins or len(projects) != len(records):
        missing = sorted(set(pins) - set(projects))
        extra = sorted(set(projects) - set(pins))
        raise WheelhouseError(
            f"lock/wheel project sets differ; missing={missing}, extra={extra}"
        )
    return {
        "schema_version": 1,
        "qualified_platform": "CPython 3.11 / Linux x86_64 / glibc >= 2.31",
        "wheels": records,
    }


def verify_manifest(wheelhouse: Path, lock_path: Path, manifest_path: Path) -> None:
    actual = build_manifest(wheelhouse, lock_path)
    expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    if actual != expected:
        raise WheelhouseError("wheelhouse manifest is missing, stale, or tampered")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = build_manifest(
        root / "python_oracle/wheelhouse", root / "python_oracle/requirements.lock"
    )
    print(json.dumps(manifest, sort_keys=True, indent=2) + "\n", end="")


if __name__ == "__main__":
    main()
