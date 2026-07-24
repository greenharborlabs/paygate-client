#!/usr/bin/env python3
"""Fail-closed native linkage and deployment-floor qualification."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

LINUX_LIBS = {
    "libc.so.6",
    "libdl.so.2",
    "libgcc_s.so.1",
    "libm.so.6",
    "libpthread.so.0",
    "librt.so.1",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
}
MAC_PATHS = {
    "/usr/lib/libSystem.B.dylib",
    "/usr/lib/libc++.1.dylib",
    "/usr/lib/libiconv.2.dylib",
    "/usr/lib/libresolv.9.dylib",
    "/usr/lib/libz.1.dylib",
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
    "/System/Library/Frameworks/Security.framework/Versions/A/Security",
    "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration",
}


def parse_linux(text: str, expected_loader: str) -> None:
    loader_seen = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("linux-vdso.so.1"):
            continue
        if "not found" in line:
            raise ValueError("dependency not found")
        if "=>" in line:
            name, rest = (part.strip() for part in line.split("=>", 1))
            path = rest.split()[0]
        else:
            path = line.split()[0]
            name = Path(path).name
        if name not in LINUX_LIBS or not path.startswith("/"):
            raise ValueError(f"unlisted Linux dependency: {name}")
        if name.startswith("ld-linux-") and name != expected_loader:
            raise ValueError("wrong target loader")
        if name == expected_loader:
            loader_seen = True
    if not loader_seen:
        raise ValueError("target loader missing")


def parse_glibc(text: str) -> None:
    versions = [(int(a), int(b)) for a, b in re.findall(r"GLIBC_(\d+)\.(\d+)", text)]
    if not versions or max(versions) > (2, 31):
        raise ValueError("invalid GLIBC symbol floor")


def parse_macos(text: str) -> None:
    lines = text.splitlines()[1:]
    if not lines:
        raise ValueError("missing macOS dependencies")
    for line in lines:
        path = line.strip().split(" (compatibility", 1)[0]
        if path not in MAC_PATHS:
            raise ValueError(f"unlisted macOS dependency: {path}")
        if path.startswith(
            ("@rpath", "@loader_path", "@executable_path", "/opt/", "/nix/", "/Users/")
        ):
            raise ValueError("non-system macOS dependency")


def output(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout


def inspect(target: str, binary: str) -> None:
    if target.endswith("linux-gnu"):
        loader = (
            "ld-linux-x86-64.so.2"
            if target.startswith("x86_64")
            else "ld-linux-aarch64.so.1"
        )
        parse_linux(output("ldd", binary), loader)
        parse_glibc(output("readelf", "--version-info", binary))
    elif target.endswith("apple-darwin"):
        expected_arch = "x86_64" if target.startswith("x86_64") else "arm64"
        if output("lipo", "-archs", binary).strip() != expected_arch:
            raise ValueError("wrong macOS architecture")
        parse_macos(output("otool", "-L", binary))
        load = output("otool", "-l", binary)
        match = re.search(r"\bminos\s+(\d+\.\d+)", load)
        if not match or match.group(1) != "15.0":
            raise ValueError("wrong macOS deployment floor")
    else:
        raise ValueError("unsupported qualification target")


def self_test() -> None:
    permitted_linux = (
        "linux-vdso.so.1 (0x0)\n"
        "libgcc_s.so.1 => /lib/aarch64-linux-gnu/libgcc_s.so.1 (0x0)\n"
        "libc.so.6 => /lib/aarch64-linux-gnu/libc.so.6 (0x0)\n"
        "/lib/ld-linux-aarch64.so.1 (0x0)"
    )
    parse_linux(permitted_linux, "ld-linux-aarch64.so.1")
    parse_glibc("Name: GLIBC_2.17 Name: GLIBC_2.31")
    permitted_mac = (
        "x:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
        "\t/System/Library/Frameworks/Security.framework/Versions/A/Security "
        "(compatibility version 1.0.0)"
    )
    parse_macos(permitted_mac)
    for function, fixture in [
        (
            lambda value: parse_linux(value, "ld-linux-x86-64.so.2"),
            "libssl.so.3 => /opt/homebrew/lib/libssl.so.3 (0x0)",
        ),
        (parse_glibc, "Name: GLIBC_2.32"),
        (parse_macos, "x:\n\t@rpath/libsqlite.dylib (compatibility version 1.0.0)"),
    ]:
        try:
            function(fixture)
        except ValueError:
            pass
        else:
            raise AssertionError("injected dependency was accepted")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) == 3:
        inspect(sys.argv[1], sys.argv[2])
    else:
        raise SystemExit("usage: check-rust-linkage.py TARGET BINARY | --self-test")
