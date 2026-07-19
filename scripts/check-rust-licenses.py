#!/usr/bin/env python3
"""Fail-closed SPDX and missing-metadata policy for the locked Cargo graph."""

from __future__ import annotations

import json
import re
import sys

ALLOWED_LICENSES = {
    "0BSD", "Apache-2.0", "BSD-1-Clause", "BSD-2-Clause", "BSD-3-Clause",
    "BSL-1.0", "CC0-1.0", "CDLA-Permissive-2.0", "ISC", "LGPL-2.1-or-later",
    "MIT", "MIT-0", "MITNFA", "MPL-2.0", "Unicode-3.0", "Unlicense", "Zlib",
}
LEGACY_NORMALIZATIONS = {
    "Apache-2.0 / MIT": "Apache-2.0 OR MIT",
    "Apache-2.0/MIT": "Apache-2.0 OR MIT",
    "MIT/Apache-2.0": "MIT OR Apache-2.0",
}
SPARK_SOURCE = "git+https://github.com/breez/spark-sdk.git?rev=f660f5a3bf24323e5c14235efcd28e5aef06c8aa#f660f5a3bf24323e5c14235efcd28e5aef06c8aa"
BOLTZ_SOURCE = "git+https://github.com/breez/boltz-client?rev=809ac77cfc9ab2d809e3ef05f31c6d23ee9c4730#809ac77cfc9ab2d809e3ef05f31c6d23ee9c4730"
MISSING_CLASSIFICATIONS = {
    SPARK_SOURCE: {
        "breez-sdk-common", "breez-sdk-spark", "flashnet", "lnurl-models", "macros",
        "platform-utils", "spark", "spark-wallet", "utils",
    },
    BOLTZ_SOURCE: {"boltz-client", "macros", "platform-utils"},
    "registry+https://github.com/rust-lang/crates.io-index": {"tokio-tungstenite-wasm"},
}
TOKEN = re.compile(r"\s*(\(|\)|AND\b|OR\b|WITH\b|[A-Za-z0-9][A-Za-z0-9.+-]*)")


class Parser:
    def __init__(self, expression: str) -> None:
        expression = LEGACY_NORMALIZATIONS.get(expression, expression)
        self.tokens: list[str] = []
        offset = 0
        while offset < len(expression):
            match = TOKEN.match(expression, offset)
            if not match:
                raise ValueError("invalid SPDX syntax")
            self.tokens.append(match.group(1))
            offset = match.end()
        self.index = 0

    def parse(self) -> None:
        self.expression()
        if self.index != len(self.tokens):
            raise ValueError("trailing SPDX tokens")

    def expression(self) -> None:
        self.term()
        while self.take("OR"):
            self.term()

    def term(self) -> None:
        self.factor()
        while self.take("AND"):
            self.factor()

    def factor(self) -> None:
        if self.take("("):
            self.expression()
            self.require(")")
            return
        license_id = self.next()
        if license_id not in ALLOWED_LICENSES:
            raise ValueError(f"unclassified license: {license_id}")
        if self.take("WITH"):
            exception = self.next()
            if (license_id, exception) != ("Apache-2.0", "LLVM-exception"):
                raise ValueError("unclassified SPDX exception")

    def next(self) -> str:
        if self.index >= len(self.tokens):
            raise ValueError("incomplete SPDX expression")
        token = self.tokens[self.index]
        self.index += 1
        return token

    def take(self, token: str) -> bool:
        if self.index < len(self.tokens) and self.tokens[self.index] == token:
            self.index += 1
            return True
        return False

    def require(self, token: str) -> None:
        if not self.take(token):
            raise ValueError("unbalanced SPDX expression")


def check_package(package: dict[str, object]) -> None:
    license_expression = package.get("license")
    if isinstance(license_expression, str) and license_expression:
        Parser(license_expression).parse()
        return
    name = package.get("name")
    version = package.get("version")
    source = package.get("source")
    allowed_names = MISSING_CLASSIFICATIONS.get(source) if isinstance(source, str) else None
    if not isinstance(name, str) or version not in {"0.1.0", "0.8.2"} or not allowed_names or name not in allowed_names:
        raise ValueError(f"unclassified missing license metadata: {name}@{version}")


def check_metadata(path: str) -> None:
    packages = json.load(open(path, encoding="utf-8")).get("packages")
    if not isinstance(packages, list):
        raise ValueError("invalid cargo metadata")
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("invalid cargo package metadata")
        check_package(package)


def self_test() -> None:
    for expression in [
        "MIT OR Apache-2.0", "(Apache-2.0 OR MIT) AND BSD-3-Clause",
        "Apache-2.0 WITH LLVM-exception OR MIT", "MIT/Apache-2.0",
    ]:
        Parser(expression).parse()
    for expression in ["AGPL-3.0", "MIT OR Proprietary", "MIT WITH LLVM-exception", "MIT OR", "(MIT"]:
        try:
            Parser(expression).parse()
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe expression accepted: {expression}")
    check_package({"name": "breez-sdk-spark", "version": "0.1.0", "source": SPARK_SOURCE, "license": None})
    try:
        check_package({"name": "surprise", "version": "0.1.0", "source": SPARK_SOURCE, "license": None})
    except ValueError:
        pass
    else:
        raise AssertionError("unknown missing-license package accepted")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) == 2:
        check_metadata(sys.argv[1])
    else:
        raise SystemExit("usage: check-rust-licenses.py METADATA.json | --self-test")
