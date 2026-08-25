#!/usr/bin/env python3
"""Bind and verify the credential window used by a live Rust cutover."""

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import urllib.parse

MAX_JSON_BYTES = 131_072
SCHEMA = "paygate-cutover-cache-window-v1"
LIVE_COMMITMENT = "COMPLETE_INSTALL_REBOOT_AND_VERIFY_NOW"


class WindowError(RuntimeError):
    """A fail-closed cache-window validation error."""


def fail(message):
    raise WindowError(message)


def integer(value, description):
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{description} is invalid")
    return value


def safe_json(path, description, *, required_mode=None):
    path = pathlib.Path(path)
    try:
        parent_stat = path.parent.stat()
        path_stat = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError:
        fail(f"{description} is unavailable")
    try:
        descriptor_stat = os.fstat(descriptor)
        raw = b""
        while len(raw) <= MAX_JSON_BYTES:
            chunk = os.read(descriptor, MAX_JSON_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(path_stat.st_mode)
        or stat.S_ISLNK(path_stat.st_mode)
        or (path_stat.st_dev, path_stat.st_ino)
        != (descriptor_stat.st_dev, descriptor_stat.st_ino)
        or descriptor_stat.st_uid != os.getuid()
        or descriptor_stat.st_nlink != 1
        or descriptor_stat.st_size != len(raw)
        or not raw
        or len(raw) > MAX_JSON_BYTES
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or stat.S_IMODE(parent_stat.st_mode) & 0o022 != 0
        or (
            required_mode is not None
            and stat.S_IMODE(descriptor_stat.st_mode) != required_mode
        )
    ):
        fail(f"{description} is unsafe")
    try:
        return json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WindowError(f"{description} is malformed") from error


def canonical_binary(path):
    path = pathlib.Path(path)
    try:
        parent_stat = path.parent.stat()
        path_stat = path.lstat()
        resolved = path.resolve(strict=True)
        followed_stat = path.stat()
    except OSError as error:
        raise WindowError("paygate binary is unavailable") from error
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or stat.S_IMODE(parent_stat.st_mode) & 0o022 != 0
    ):
        fail("paygate binary parent is unsafe")
    if stat.S_ISLNK(path_stat.st_mode):
        if path_stat.st_uid != os.getuid() or path_stat.st_nlink != 1:
            fail("paygate launcher is unsafe")
    elif not stat.S_ISREG(path_stat.st_mode):
        fail("paygate binary is unsafe")
    return path, resolved, path_stat, followed_stat


def safe_binary_hash(path):
    path, resolved, path_stat, followed_stat = canonical_binary(path)
    try:
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise WindowError("paygate binary is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    try:
        final_path_stat = path.lstat()
    except OSError as error:
        raise WindowError("paygate binary is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or (metadata.st_dev, metadata.st_ino)
        != (followed_stat.st_dev, followed_stat.st_ino)
        or (final_path_stat.st_dev, final_path_stat.st_ino)
        != (path_stat.st_dev, path_stat.st_ino)
    ):
        fail("paygate binary is unsafe")
    return digest.hexdigest()


def request_key(method, url):
    digest = hashlib.sha256()
    digest.update(method.upper().encode())
    digest.update(b"\0")
    digest.update(url.encode())
    digest.update(b"\0")
    return digest.hexdigest()


def origin_host(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        fail("protected URL is invalid")
    try:
        port = parsed.port
    except ValueError as error:
        raise WindowError("protected URL is invalid") from error
    port = port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.hostname.lower()}:{port}"


def utc_time(epoch):
    return (
        dt.datetime.fromtimestamp(epoch, dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def acceptance_binding(acceptance_path):
    acceptance_path = pathlib.Path(acceptance_path)
    document = safe_json(acceptance_path, "acceptance record")
    if not isinstance(document, dict):
        fail("acceptance record is invalid")
    session = document.get("cutover_session_id")
    if (
        document.get("schema") != "paygate-cutover-acceptance-v2"
        or not isinstance(session, str)
        or len(session) != 32
        or any(character not in "0123456789abcdef" for character in session)
    ):
        fail("acceptance record is invalid")
    return str(acceptance_path.resolve()), session, document


def credential_listing(paygate, profile):
    try:
        result = subprocess.run(
            [str(paygate), "credentials", "list", "--profile", profile],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WindowError("credential listing failed") from error
    if (
        result.returncode != 0
        or not result.stdout
        or len(result.stdout) > MAX_JSON_BYTES
    ):
        fail("credential listing failed")
    try:
        document = json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WindowError("credential listing is malformed") from error
    if document.get("ok") is not True or not isinstance(
        document.get("credentials"), list
    ):
        fail("credential listing is malformed")
    return document


def matching_credentials(
    listing, *, method, url, profile, issued_after_epoch, now_epoch
):
    expected_request_key = request_key(method, url)
    expected_origin = origin_host(url)
    matches = []
    for credential in listing["credentials"]:
        if not isinstance(credential, dict) or not isinstance(
            credential.get("scope"), dict
        ):
            continue
        scope = credential["scope"]
        created = credential.get("createdAt")
        expires = credential.get("expiresAt")
        max_uses = credential.get("maxUses")
        use_count = credential.get("useCount")
        usable = (
            isinstance(created, int)
            and not isinstance(created, bool)
            and created >= issued_after_epoch
            and isinstance(expires, int)
            and not isinstance(expires, bool)
            and expires > now_epoch
            and isinstance(use_count, int)
            and not isinstance(use_count, bool)
            and use_count >= 0
            and (
                max_uses is None
                or (
                    isinstance(max_uses, int)
                    and not isinstance(max_uses, bool)
                    and use_count < max_uses
                )
            )
            and credential.get("lastRejectedAt") is None
        )
        if (
            usable
            and scope.get("namespace") == profile
            and scope.get("requestKey") == expected_request_key
            and scope.get("originHost") == expected_origin
            and scope.get("protocol") == "Payment"
            and isinstance(scope.get("payerBackend"), str)
            and isinstance(scope.get("policyHash"), str)
            and isinstance(credential.get("id"), str)
        ):
            matches.append(credential)
    return matches


def build_state(
    *,
    paygate,
    acceptance_path,
    listing,
    method,
    url,
    profile,
    issued_after_epoch,
    minimum_remaining_seconds,
    now_epoch,
):
    minimum_remaining_seconds = integer(
        minimum_remaining_seconds, "minimum remaining seconds"
    )
    if minimum_remaining_seconds < 300:
        fail("minimum remaining seconds must be at least 300")
    matches = matching_credentials(
        listing,
        method=method,
        url=url,
        profile=profile,
        issued_after_epoch=issued_after_epoch,
        now_epoch=now_epoch,
    )
    if len(matches) != 1:
        fail("fresh protected-request credential was not uniquely identified")
    credential = matches[0]
    expires = credential["expiresAt"]
    deadline = expires - minimum_remaining_seconds
    if now_epoch >= deadline:
        fail("credential does not leave enough time for install and restart")
    acceptance, session, document = acceptance_binding(acceptance_path)
    if not isinstance(document.get("checkpoints"), list):
        fail("acceptance record is not ready to bind the cache window")
    gates = [
        entry.get("gate") if isinstance(entry, dict) else None
        for entry in document.get("checkpoints", [])
    ]
    if document.get("phase") != "preinstall-recording" or gates != [
        "fixture-oracle-pass",
        "rust-product-tests-pass",
        "candidate-doctor-pass",
        "invoice-approved",
        "invoice-pass",
        "request-approved",
    ]:
        fail("acceptance record is not ready to bind the cache window")
    scope = credential["scope"]
    return {
        "schema": SCHEMA,
        "acceptanceRecord": acceptance,
        "cutoverSessionId": session,
        "candidatePath": str(pathlib.Path(paygate).resolve(strict=True)),
        "candidateSha256": safe_binary_hash(paygate),
        "method": method.upper(),
        "url": url,
        "profile": profile,
        "credentialId": credential["id"],
        "credentialScope": {
            key: scope.get(key)
            for key in (
                "namespace",
                "requestKey",
                "originHost",
                "service",
                "protocol",
                "payerBackend",
                "policyHash",
            )
        },
        "credentialCreatedAtEpoch": credential["createdAt"],
        "credentialExpiresAtEpoch": expires,
        "capturedAtEpoch": now_epoch,
        "minimumRemainingSeconds": minimum_remaining_seconds,
        "mustStartPostRebootByEpoch": deadline,
    }


def validate_state(*, state, paygate, listing, now_epoch):
    required = {
        "schema",
        "acceptanceRecord",
        "cutoverSessionId",
        "candidatePath",
        "candidateSha256",
        "method",
        "url",
        "profile",
        "credentialId",
        "credentialScope",
        "credentialCreatedAtEpoch",
        "credentialExpiresAtEpoch",
        "capturedAtEpoch",
        "minimumRemainingSeconds",
        "mustStartPostRebootByEpoch",
    }
    if (
        not isinstance(state, dict)
        or set(state) != required
        or state.get("schema") != SCHEMA
    ):
        fail("cache-window state is invalid")
    deadline = integer(state.get("mustStartPostRebootByEpoch"), "post-reboot deadline")
    expires = integer(state.get("credentialExpiresAtEpoch"), "credential expiry")
    minimum = integer(state.get("minimumRemainingSeconds"), "minimum remaining seconds")
    if deadline != expires - minimum or now_epoch >= deadline:
        fail("post-reboot cache-validation deadline has passed")
    try:
        candidate_path = str(pathlib.Path(paygate).resolve(strict=True))
    except OSError as error:
        raise WindowError("paygate binary is unavailable") from error
    if candidate_path != state.get("candidatePath") or safe_binary_hash(
        paygate
    ) != state.get("candidateSha256"):
        fail("installed paygate binary does not match the cache-window candidate")
    acceptance_path, session, acceptance = acceptance_binding(
        state.get("acceptanceRecord")
    )
    if (
        acceptance_path != state.get("acceptanceRecord")
        or session != state.get("cutoverSessionId")
        or acceptance.get("phase") not in {"installed", "postinstall-accepted"}
    ):
        fail("installed acceptance does not match the cache-window session")
    matches = [
        credential
        for credential in listing["credentials"]
        if isinstance(credential, dict)
        and credential.get("id") == state.get("credentialId")
        and credential.get("scope") == state.get("credentialScope")
        and credential.get("createdAt") == state.get("credentialCreatedAtEpoch")
        and credential.get("expiresAt") == expires
        and credential.get("lastRejectedAt") is None
        and (
            credential.get("maxUses") is None
            or (
                isinstance(credential.get("maxUses"), int)
                and not isinstance(credential.get("maxUses"), bool)
                and isinstance(credential.get("useCount"), int)
                and not isinstance(credential.get("useCount"), bool)
                and credential["useCount"] < credential["maxUses"]
            )
        )
    ]
    if len(matches) != 1:
        fail("bound credential is not retrievable and usable after restart")
    return {
        "ok": True,
        "credentialId": state["credentialId"],
        "credentialExpiresAtEpoch": expires,
        "credentialExpiresAtUtc": utc_time(expires),
        "mustStartPostRebootByEpoch": deadline,
        "mustStartPostRebootByUtc": utc_time(deadline),
        "secondsUntilDeadline": deadline - now_epoch,
        "minimumRemainingSeconds": minimum,
    }


def write_state(path, state):
    path = pathlib.Path(path)
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        fail("cache-window output path is unsafe")
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o022 != 0:
        fail("cache-window output parent is unsafe")
    raw = (json.dumps(state, sort_keys=True, indent=2) + "\n").encode()
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as error:
        raise WindowError("cache-window output already exists or is unsafe") from error
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
    finally:
        os.close(descriptor)
    parent_descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("--paygate", type=pathlib.Path, required=True)
    capture.add_argument("--acceptance", type=pathlib.Path, required=True)
    capture.add_argument("--output", type=pathlib.Path, required=True)
    capture.add_argument("--method", default="GET")
    capture.add_argument("--url", required=True)
    capture.add_argument("--profile", default="default")
    capture.add_argument("--issued-after-epoch", type=int, required=True)
    capture.add_argument("--minimum-remaining-seconds", type=int, default=600)
    capture.add_argument("--confirm", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--paygate", type=pathlib.Path, required=True)
    verify.add_argument("--state", type=pathlib.Path, required=True)
    return root


def main():
    arguments = parser().parse_args()
    now = int(dt.datetime.now(tz=dt.timezone.utc).timestamp())
    try:
        if arguments.command == "capture":
            if arguments.confirm != LIVE_COMMITMENT:
                fail(
                    "live cutover commitment is required; completing capture means "
                    "install, restart, and post-reboot verification must proceed now"
                )
            listing = credential_listing(arguments.paygate, arguments.profile)
            state = build_state(
                paygate=arguments.paygate,
                acceptance_path=arguments.acceptance,
                listing=listing,
                method=arguments.method,
                url=arguments.url,
                profile=arguments.profile,
                issued_after_epoch=arguments.issued_after_epoch,
                minimum_remaining_seconds=arguments.minimum_remaining_seconds,
                now_epoch=now,
            )
            write_state(arguments.output, state)
            result = {
                "ok": True,
                "state": str(arguments.output),
                "mustStartPostRebootByEpoch": state["mustStartPostRebootByEpoch"],
                "mustStartPostRebootByUtc": utc_time(
                    state["mustStartPostRebootByEpoch"]
                ),
                "secondsUntilDeadline": state["mustStartPostRebootByEpoch"] - now,
                "commitment": LIVE_COMMITMENT,
            }
        else:
            state = safe_json(
                arguments.state, "cache-window state", required_mode=0o400
            )
            profile = state.get("profile") if isinstance(state, dict) else None
            if not isinstance(profile, str):
                fail("cache-window state is invalid")
            listing = credential_listing(arguments.paygate, profile)
            result = validate_state(
                state=state,
                paygate=arguments.paygate,
                listing=listing,
                now_epoch=now,
            )
    except WindowError as error:
        print(f"cutover cache window: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
