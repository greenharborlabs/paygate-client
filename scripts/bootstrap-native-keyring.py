#!/usr/bin/env python3
"""Create and verify the only interpreter permitted for native keyring probes."""

import argparse
import subprocess
from pathlib import Path

PIN = "25.7.0"
FORBIDDEN = ("null", "file", "chainer", "fail")

parser = argparse.ArgumentParser()
parser.add_argument("--python", required=True, type=Path)
parser.add_argument(
    "--wheelhouse", default=Path("compat/python_oracle/wheelhouse"), type=Path
)
args = parser.parse_args()
if not args.python.is_absolute() or not args.python.is_file():
    raise SystemExit("controlled interpreter must be an existing absolute path")
subprocess.run(
    [
        str(args.python),
        "-m",
        "pip",
        "install",
        "--no-index",
        "--find-links",
        str(args.wheelhouse),
        f"keyring=={PIN}",
    ],
    check=True,
)
probe = """import keyring,sys
assert keyring.__version__ == '25.7.0', keyring.__version__
b=keyring.get_keyring(); n=(b.__class__.__module__+'.'+b.__class__.__name__).lower()
assert not any(x in n for x in ('null','file','chainer','fail')), n
if sys.platform == 'darwin': assert 'macos' in n or 'keychain' in n, n
elif sys.platform.startswith('linux'): assert 'secretservice' in n, n
else: raise RuntimeError('unsupported native keyring platform')
"""
subprocess.run([str(args.python), "-c", probe], check=True)
print(args.python)
