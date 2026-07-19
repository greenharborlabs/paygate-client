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
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"

# Each entry is a Cargo metadata identity: (package name, exact version, canonical
# Cargo source). Do not replace this with source/name matching or version ranges.
MISSING_LICENSE_EXCEPTIONS = (
    ("boltz-client", "0.1.0", BOLTZ_SOURCE),
    ("breez-sdk-common", "0.1.0", SPARK_SOURCE),
    ("breez-sdk-spark", "0.1.0", SPARK_SOURCE),
    ("flashnet", "0.1.0", SPARK_SOURCE),
    ("lnurl-models", "0.1.0", SPARK_SOURCE),
    ("macros", "0.1.0", BOLTZ_SOURCE),
    ("macros", "0.1.0", SPARK_SOURCE),
    ("platform-utils", "0.1.0", BOLTZ_SOURCE),
    ("platform-utils", "0.1.0", SPARK_SOURCE),
    ("spark", "0.1.0", SPARK_SOURCE),
    ("spark-wallet", "0.1.0", SPARK_SOURCE),
    ("tokio-tungstenite-wasm", "0.8.2", CRATES_IO_SOURCE),
    ("utils", "0.1.0", SPARK_SOURCE),
)
MISSING_LICENSE_EXCEPTION_SET = frozenset(MISSING_LICENSE_EXCEPTIONS)
if len(MISSING_LICENSE_EXCEPTION_SET) != len(MISSING_LICENSE_EXCEPTIONS):
    raise RuntimeError("duplicate missing-license exception identity")
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


def package_identity(package: dict[str, object]) -> tuple[object, object, object]:
    return package.get("name"), package.get("version"), package.get("source")


def format_identity(identity: tuple[object, object, object]) -> str:
    name, version, source = identity
    return f"{name}@{version} source={source}"


def check_package(package: dict[str, object]) -> tuple[str, str, str] | None:
    identity = package_identity(package)
    license_expression = package.get("license")
    if "license" not in package or license_expression is None:
        name, version, source = identity
        if not all(isinstance(component, str) for component in identity):
            raise ValueError(f"unclassified missing license metadata: {format_identity(identity)}")
        typed_identity = (name, version, source)
        if typed_identity not in MISSING_LICENSE_EXCEPTION_SET:
            raise ValueError(f"unclassified missing license metadata: {format_identity(identity)}")
        return typed_identity
    if not isinstance(license_expression, str) or not license_expression.strip():
        raise ValueError(f"invalid license metadata: {format_identity(identity)}")
    try:
        Parser(license_expression).parse()
    except ValueError as error:
        raise ValueError(f"unclassified license metadata: {format_identity(identity)}: {error}") from error
    return None


def check_metadata(path: str) -> None:
    packages = json.load(open(path, encoding="utf-8")).get("packages")
    if not isinstance(packages, list):
        raise ValueError("invalid cargo metadata")
    observed_missing: list[tuple[str, str, str]] = []
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("invalid cargo package metadata")
        identity = check_package(package)
        if identity is not None:
            observed_missing.append(identity)
    check_missing_license_completeness(observed_missing)


def check_missing_license_completeness(observed_missing: list[tuple[str, str, str]]) -> None:
    observed_set = frozenset(observed_missing)
    if len(observed_set) != len(observed_missing):
        duplicates = sorted(identity for identity in observed_set if observed_missing.count(identity) > 1)
        raise ValueError("duplicate missing-license metadata identities: " + "; ".join(map(format_identity, duplicates)))
    if observed_set != MISSING_LICENSE_EXCEPTION_SET:
        missing = sorted(MISSING_LICENSE_EXCEPTION_SET - observed_set)
        stale = sorted(observed_set - MISSING_LICENSE_EXCEPTION_SET)
        details = []
        if missing:
            details.append("allowlist identities absent from metadata: " + "; ".join(map(format_identity, missing)))
        if stale:
            details.append("new unlicensed metadata identities: " + "; ".join(map(format_identity, stale)))
        raise ValueError("missing-license allowlist completeness failure: " + " | ".join(details))


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
    for identity in MISSING_LICENSE_EXCEPTIONS:
        name, version, source = identity
        package: dict[str, object] = {"name": name, "version": version, "source": source, "license": None}
        if check_package(package) != identity:
            raise AssertionError(f"allowlisted identity rejected: {format_identity(identity)}")
        if check_package({key: value for key, value in package.items() if key != "license"}) != identity:
            raise AssertionError(f"allowlisted absent license rejected: {format_identity(identity)}")
        for field, mutated in (("name", name + "-mutated"), ("version", version + ".1"),
                               ("source", source + "-mutated")):
            changed = package | {field: mutated}
            try:
                check_package(changed)
            except ValueError as error:
                diagnostic = str(error)
                for component in (changed["name"], changed["version"], changed["source"]):
                    if str(component) not in diagnostic:
                        raise AssertionError(f"incomplete identity diagnostic: {diagnostic}")
            else:
                raise AssertionError(f"{field} drift accepted: {format_identity(identity)}")
        try:
            check_package(package | {"license": "MIT OR"})
        except ValueError as error:
            if format_identity(identity) not in str(error):
                raise AssertionError(f"license diagnostic omitted identity: {error}")
        else:
            raise AssertionError(f"unparsable SPDX accepted: {format_identity(identity)}")
        for malformed_license in (123, [], "", "   "):
            try:
                check_package(package | {"license": malformed_license})
            except ValueError as error:
                if format_identity(identity) not in str(error):
                    raise AssertionError(f"malformed license diagnostic omitted identity: {error}")
            else:
                raise AssertionError(f"malformed license accepted: {format_identity(identity)}")
    metadata_identities = [
        check_package({"name": name, "version": version, "source": source, "license": None})
        for name, version, source in MISSING_LICENSE_EXCEPTIONS
    ]
    check_missing_license_completeness(metadata_identities)
    try:
        check_missing_license_completeness(metadata_identities[:-1])
    except ValueError as error:
        if "allowlist identities absent from metadata" not in str(error):
            raise AssertionError(f"missing allowlist member was not diagnosed: {error}")
    else:
        raise AssertionError("stale allowlist accepted")
    try:
        check_missing_license_completeness(metadata_identities + [metadata_identities[0]])
    except ValueError as error:
        if "duplicate missing-license metadata identities" not in str(error):
            raise AssertionError(f"duplicate identity was not diagnosed: {error}")
    else:
        raise AssertionError("duplicate metadata identity accepted")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) == 2:
        check_metadata(sys.argv[1])
    else:
        raise SystemExit("usage: check-rust-licenses.py METADATA.json | --self-test")
