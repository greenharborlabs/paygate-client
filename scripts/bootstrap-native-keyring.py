#!/usr/bin/env python3
"""Create and verify the only interpreter permitted for native keyring probes."""

import argparse
import subprocess
from pathlib import Path

PIN = "25.7.0"
PYTHON_PIN = (3, 11, 14)
FORBIDDEN = ("null", "file", "chainer", "fail")
ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "compat/native-keyring-requirements.txt"

parser = argparse.ArgumentParser()
parser.add_argument("--python", required=True, type=Path)
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument("--install-only", action="store_true")
mode.add_argument("--verify-only", action="store_true")
args = parser.parse_args()
if not args.python.is_absolute() or not args.python.is_file():
    raise SystemExit("controlled interpreter must be an existing absolute path")
subprocess.run(
    [
        str(args.python),
        "-c",
        f"import sys; assert sys.version_info[:3] == {PYTHON_PIN!r}",
    ],
    check=True,
)
if args.install_only:
    subprocess.run(
        [
            str(args.python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--only-binary=:all:",
            "--require-hashes",
            "--requirement",
            str(REQUIREMENTS),
        ],
        check=True,
    )
    print(args.python)
    raise SystemExit(0)

probe = """import importlib.metadata, keyring, sys
assert importlib.metadata.version("keyring") == '25.7.0'
b=keyring.get_keyring(); n=(b.__class__.__module__+'.'+b.__class__.__name__).lower()
assert not any(x in n for x in ('null','file','chainer','fail')), n
if sys.platform == 'darwin': assert 'macos' in n or 'keychain' in n, n
elif sys.platform.startswith('linux'): assert 'secretservice' in n, n
else: raise RuntimeError('unsupported native keyring platform')
"""
subprocess.run([str(args.python), "-c", probe], check=True)
print(args.python)
