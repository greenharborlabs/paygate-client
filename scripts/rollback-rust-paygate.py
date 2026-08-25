#!/usr/bin/env python3
"""Monotonic, crash-recoverable restoration of the Python paygate deployment."""

import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys

MAX_MARKER_BYTES = 131_072
DEVICE_REMAP_AUTH_ENV = "PAYGATE_ROLLBACK_DEVICE_REMAP_AUTHORIZATION"


def fail(message):
    raise SystemExit(f"rollback: {message}")


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def digest(path):
    result = hashlib.sha256()
    if path.is_file():
        result.update(path.read_bytes())
    elif path.is_dir():
        for child in sorted(path.rglob("*")):
            result.update(str(child.relative_to(path)).encode() + b"\0")
            if child.is_symlink():
                result.update(os.readlink(child).encode())
            elif child.is_file():
                result.update(child.read_bytes())
    return result.hexdigest()


def type_matches(path, path_type):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return not stat.S_ISLNK(metadata.st_mode) and (
        (path_type == "file" and stat.S_ISREG(metadata.st_mode))
        or (path_type == "directory" and stat.S_ISDIR(metadata.st_mode))
    )


def identity(path):
    metadata = path.lstat()
    return {
        "dev": metadata.st_dev,
        "ino": metadata.st_ino,
        "uid": metadata.st_uid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "digest": digest(path),
    }


def digest_descriptor(fd, path_type):
    if path_type == "file":
        result = hashlib.sha256()
        offset = 0
        while True:
            chunk = os.pread(fd, 1024 * 1024, offset)
            if not chunk:
                return result.hexdigest()
            result.update(chunk)
            offset += len(chunk)
    if path_type == "directory":
        cwd_fd = os.open(".", os.O_RDONLY)
        try:
            os.fchdir(fd)
            return digest(pathlib.Path("."))
        finally:
            os.fchdir(cwd_fd)
            os.close(cwd_fd)
    fail("state backup type mismatch")


def identity_matches(path, path_type, expected):
    return type_matches(path, path_type) and identity(path) == expected


def remove_owned(path, path_type, uid):
    if not type_matches(path, path_type) or path.lstat().st_uid != uid:
        raise RuntimeError(f"unsafe private recovery object: {path}")
    if path.is_file():
        path.unlink()
    else:
        shutil.rmtree(path)


def fsync_tree(path):
    if path.is_file():
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    else:
        for child in path.rglob("*"):
            if child.is_file() and not child.is_symlink():
                fd = os.open(child, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        sync_dir(path)
    sync_dir(path.parent)


def read_nofollow_json(path, max_bytes, description):
    try:
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except FileNotFoundError:
        return None
    except OSError:
        fail(f"{description} is unsafe")
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"{description} is unsafe")
        raw = b""
        while len(raw) <= max_bytes:
            chunk = os.read(fd, max_bytes + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != len(raw)
        or not raw
        or len(raw) > max_bytes
    ):
        fail(f"{description} is unsafe")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        fail(f"{description} is malformed")
    return value, raw, metadata


def device_matches(recorded, current, authorization=None):
    return recorded == current or (
        authorization is not None
        and recorded == authorization["recorded_device"]
        and current == authorization["current_device"]
    )


def load_device_remap_authorization(
    rollback_dir, manifest, manifest_hash, preflight_hash, uid
):
    authorization_name = os.environ.get(DEVICE_REMAP_AUTH_ENV)
    if not authorization_name:
        return None
    if sys.platform != "darwin":
        fail("device remap authorization is only valid on macOS")
    authorization_path = pathlib.Path(authorization_name)
    if not authorization_path.is_absolute():
        fail("device remap authorization path must be absolute")
    result = read_nofollow_json(
        authorization_path, 16_384, "device remap authorization"
    )
    if result is None:
        fail("device remap authorization is missing")
    authorization, _, authorization_stat = result
    keys = {
        "schema",
        "boot_session_uuid",
        "rollback_directory",
        "rollback_manifest_sha256",
        "preflight_sha256",
        "installed_rust_target",
        "installed_rust_binary_sha256",
        "runtime_lock",
        "runtime_lock_ino",
        "recorded_device",
        "current_device",
    }
    try:
        boot_session_uuid = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        fail("current boot identity is unverifiable")
    rust_target = pathlib.Path(manifest["installed_rust_launcher_target"])
    try:
        rust_fd = os.open(
            rust_target,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        fail("installed Rust binary is unavailable")
    try:
        rust_stat = os.fstat(rust_fd)
        rust_hash = digest_descriptor(rust_fd, "file")
    finally:
        os.close(rust_fd)
    expected_binary_hash = manifest.get("candidate_identity", {}).get("binary_sha256")
    if (
        not isinstance(authorization, dict)
        or authorization_stat.st_uid != uid
        or authorization_stat.st_nlink != 1
        or stat.S_IMODE(authorization_stat.st_mode) != 0o400
        or set(authorization) != keys
        or authorization.get("schema") != "paygate-rollback-device-remap-v1"
        or authorization.get("boot_session_uuid") != boot_session_uuid
        or authorization.get("rollback_directory") != str(rollback_dir.resolve())
        or authorization.get("rollback_manifest_sha256") != manifest_hash
        or authorization.get("preflight_sha256") != preflight_hash
        or authorization.get("installed_rust_target") != str(rust_target)
        or authorization.get("installed_rust_binary_sha256") != expected_binary_hash
        or rust_hash != expected_binary_hash
        or not stat.S_ISREG(rust_stat.st_mode)
        or rust_stat.st_uid != uid
        or rust_stat.st_nlink != 1
        or authorization.get("runtime_lock") != manifest.get("runtime_lock")
        or authorization.get("runtime_lock_ino") != manifest.get("runtime_lock_ino")
        or authorization.get("recorded_device") != manifest.get("runtime_lock_dev")
        or not isinstance(authorization.get("current_device"), int)
        or isinstance(authorization.get("current_device"), bool)
        or authorization.get("current_device") < 0
        or authorization.get("current_device") == authorization.get("recorded_device")
    ):
        fail("device remap authorization is invalid")
    return authorization


def main():
    if len(sys.argv) != 4:
        fail("internal invocation mismatch")
    rollback_dir = pathlib.Path(sys.argv[1])
    record_path = pathlib.Path(sys.argv[2])
    cutover_script = pathlib.Path(sys.argv[3])
    manifest_path = rollback_dir / "manifest.json"
    preflight_result = read_nofollow_json(record_path, MAX_MARKER_BYTES, "preflight")
    manifest_result = read_nofollow_json(
        manifest_path, MAX_MARKER_BYTES, "rollback manifest"
    )
    if preflight_result is None:
        fail("preflight is missing")
    if manifest_result is None:
        fail("rollback manifest is missing")
    preflight, preflight_raw, _ = preflight_result
    manifest, manifest_raw, _ = manifest_result
    deployment = preflight["deployment"]
    uid = manifest.get("process_uid")
    state_keys = ("config", "wallet_storage", "credential_cache", "ledger")
    state_paths = {
        item.get("key"): item.get("path")
        for item in manifest.get("state", [])
        if isinstance(item, dict)
    }
    expected_paths = {key: preflight["state"][key] for key in state_keys}
    launcher = pathlib.Path(manifest["launcher"])
    lock_path = pathlib.Path(manifest["runtime_lock"])
    marker_path = pathlib.Path(manifest["runtime_transaction_marker"])
    expected_lock = launcher.parent / ".paygate-runtime.lock"
    expected_marker = launcher.parent / ".paygate-runtime.lock.transaction.json"
    identity_fields = (
        "launcher_symlink_target",
        "resolved_launcher",
        "resolved_launcher_sha256",
        "process_uid",
    )
    if (
        manifest.get("schema") != "paygate-rust-rollback-v3"
        or manifest.get("rollback_directory") != str(rollback_dir.resolve())
        or manifest.get("repository") != preflight.get("repository")
        or manifest.get("launcher") != deployment["launcher"]
        or manifest.get("supervisor") != deployment.get("supervisor")
        or any(manifest.get(key) != deployment.get(key) for key in identity_fields)
        or lock_path != expected_lock
        or marker_path != expected_marker
        or not isinstance(manifest.get("runtime_lock_dev"), int)
        or isinstance(manifest.get("runtime_lock_dev"), bool)
        or not isinstance(manifest.get("runtime_lock_ino"), int)
        or isinstance(manifest.get("runtime_lock_ino"), bool)
        or len(manifest.get("state", [])) != 4
        or state_paths != expected_paths
        or not isinstance(uid, int)
        or isinstance(uid, bool)
    ):
        fail("manifest/preflight mismatch")

    manifest_hash = hashlib.sha256(manifest_raw).hexdigest()
    preflight_hash = hashlib.sha256(preflight_raw).hexdigest()
    device_remap = load_device_remap_authorization(
        rollback_dir, manifest, manifest_hash, preflight_hash, uid
    )

    receipt_path = pathlib.Path(manifest["transaction_receipt"])
    receipt_result = read_nofollow_json(receipt_path, 16_384, "receipt")
    if receipt_result is None:
        fail("receipt mismatch")
    receipt, receipt_raw, receipt_stat = receipt_result
    receipt_keys = {
        "schema",
        "candidate_identity",
        "acceptance_record",
        "cutover_session_id",
        "install_session_id",
        "installed_at_epoch",
        "rollback_directory",
        "rollback_manifest_sha256",
        "python_launcher_target",
        "installed_rust_launcher_target",
    }
    if (
        receipt_stat.st_uid not in (0, uid)
        or receipt_stat.st_nlink != 1
        or stat.S_IMODE(receipt_stat.st_mode) != 0o400
        or set(receipt) != receipt_keys
        or receipt.get("schema") != "paygate-rust-cutover-receipt-v1"
        or receipt.get("candidate_identity") != manifest.get("candidate_identity")
        or receipt.get("acceptance_record")
        != str(pathlib.Path(manifest["acceptance_record"]).resolve())
        or receipt.get("rollback_manifest_sha256") != manifest_hash
        or receipt.get("rollback_directory") != str(rollback_dir.resolve())
        or any(
            receipt.get(key) != manifest.get(key)
            for key in (
                "cutover_session_id",
                "install_session_id",
                "installed_at_epoch",
                "python_launcher_target",
                "installed_rust_launcher_target",
            )
        )
    ):
        fail("receipt mismatch")

    original = pathlib.Path(manifest["python_environment_original"])
    quarantine = pathlib.Path(manifest["python_environment_quarantine"])
    rust_target = manifest["installed_rust_launcher_target"]
    python_target = manifest["python_launcher_target"]
    hooks = set(
        filter(
            None, os.environ.get("PAYGATE_CUTOVER_TEST_ROLLBACK_HOOK", "").split(",")
        )
    )
    pending_marker = (
        marker_path.parent
        / f"{marker_path.name}.pending-{manifest['install_session_id']}"
    )

    try:
        lock_fd = os.open(
            lock_path,
            os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        fail("unsafe deployment lock")
    lock_stat = os.fstat(lock_fd)
    try:
        lock_path_stat = lock_path.lstat()
    except OSError:
        fail("unsafe deployment lock")
    if (
        not stat.S_ISREG(lock_stat.st_mode)
        or (lock_path_stat.st_dev, lock_path_stat.st_ino)
        != (lock_stat.st_dev, lock_stat.st_ino)
        or not device_matches(
            manifest["runtime_lock_dev"], lock_stat.st_dev, device_remap
        )
        or lock_stat.st_ino != manifest["runtime_lock_ino"]
        or lock_stat.st_uid != uid
        or lock_stat.st_nlink != 1
        or stat.S_IMODE(lock_stat.st_mode) != 0o600
        or (
            device_remap is not None
            and device_remap["current_device"] != lock_stat.st_dev
        )
    ):
        fail("unsafe deployment lock")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fail("Rust paygate is active")
    lock_path_stat = lock_path.lstat()
    if (lock_path_stat.st_dev, lock_path_stat.st_ino) != (
        lock_stat.st_dev,
        lock_stat.st_ino,
    ):
        fail("deployment lock changed while acquiring rollback authority")
    gate_env = os.environ.copy()
    gate_env.update(
        PAYGATE_OLD_ENTRY=str(original / manifest["python_paygate_relative"]),
        PAYGATE_QUARANTINE_ENTRY=str(quarantine / manifest["python_paygate_relative"]),
        PAYGATE_RECORDED_WRAPPER=str(launcher),
        PAYGATE_RECORDED_SUPERVISOR=manifest["supervisor"],
        PAYGATE_RUST_TARGET=rust_target,
        PAYGATE_RUNTIME_PHASE="rollback",
        PAYGATE_IGNORE_PIDS=f"{os.getpid()},{os.getppid()}",
    )
    subprocess.run(
        [str(cutover_script), "_supervisor-check"],
        env=gate_env,
        check=True,
        timeout=8,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )

    def environment_shape():
        found = []
        expected = manifest["python_environment_identity"]
        old_expected = manifest["python_paygate_identity"]
        for name, path in (("original", original), ("quarantine", quarantine)):
            if path.exists() or path.is_symlink():
                if path.is_symlink() or not path.is_dir():
                    raise RuntimeError("environment object has unsafe type")
                env_stat = path.stat()
                old = path / manifest["python_paygate_relative"]
                if (
                    not device_matches(expected["dev"], env_stat.st_dev, device_remap)
                    or (
                        env_stat.st_ino,
                        env_stat.st_uid,
                        stat.S_IMODE(env_stat.st_mode),
                    )
                    != (expected["ino"], expected["uid"], expected["mode"])
                    or old.is_symlink()
                    or not old.is_file()
                ):
                    raise RuntimeError("Python environment identity mismatch")
                old_stat = old.stat()
                if (
                    not device_matches(
                        old_expected["dev"], old_stat.st_dev, device_remap
                    )
                    or (
                        old_stat.st_ino,
                        old_stat.st_uid,
                        stat.S_IMODE(old_stat.st_mode),
                        old_stat.st_size,
                    )
                    != (
                        old_expected["ino"],
                        old_expected["uid"],
                        old_expected["mode"],
                        old_expected["size"],
                    )
                    or hashlib.sha256(old.read_bytes()).hexdigest()
                    != old_expected["sha256"]
                ):
                    raise RuntimeError("Python entrypoint identity mismatch")
                found.append(name)
        if len(found) != 1:
            raise RuntimeError("environment state is ambiguous")
        return found[0]

    def launcher_shape():
        if not launcher.is_symlink():
            raise RuntimeError("launcher is not a symlink")
        target = os.readlink(launcher)
        if target not in (rust_target, python_target):
            raise RuntimeError("unknown launcher state")
        return target

    try:
        initial_environment = environment_shape()
        initial_launcher = launcher_shape()
    except RuntimeError as error:
        fail(str(error))
    marker_exists = marker_path.exists() or marker_path.is_symlink()
    if (
        not marker_exists
        and initial_environment == "original"
        and initial_launcher == python_target
    ):
        return
    if not marker_exists and (initial_environment, initial_launcher) not in {
        ("quarantine", rust_target),
        ("original", rust_target),
    }:
        fail("invalid deployment shape")

    def replace_test_backup():
        key = os.environ.get("PAYGATE_CUTOVER_TEST_BACKUP_KEY", "ledger")
        item = next(
            (value for value in manifest["state"] if value.get("key") == key), None
        )
        if item is None:
            fail("unknown test backup key")
        source = rollback_dir / item["backup"]
        replacement = pathlib.Path(
            os.environ["PAYGATE_CUTOVER_TEST_BACKUP_REPLACEMENT"]
        )
        parked = pathlib.Path(os.environ["PAYGATE_CUTOVER_TEST_BACKUP_PARKED"])
        os.rename(source, parked)
        os.replace(replacement, source)
        sync_dir(source.parent)

    backup_handles = {}
    for item in manifest["state"]:
        source = rollback_dir / item["backup"]
        destination = pathlib.Path(item["path"])
        path_type = item.get("path_type")
        if item.get("backup") != str(pathlib.Path("state") / item.get("key", "")):
            fail("state backup path mismatch")
        if "replace-backup-before-open" in hooks and item.get("key") == os.environ.get(
            "PAYGATE_CUTOVER_TEST_BACKUP_KEY", "ledger"
        ):
            replace_test_backup()
        try:
            backup_fd = os.open(
                source,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError:
            fail("state backup mismatch")
        backup_stat = os.fstat(backup_fd)
        parent_stat = (
            destination.parent.stat()
            if destination.parent.exists() and not destination.parent.is_symlink()
            else None
        )
        expected_type = (
            stat.S_ISREG(backup_stat.st_mode)
            if path_type == "file"
            else stat.S_ISDIR(backup_stat.st_mode)
            if path_type == "directory"
            else False
        )
        if (
            parent_stat is None
            or not expected_type
            or backup_stat.st_uid not in (0, uid)
            or not device_matches(
                item.get("backup_dev"), backup_stat.st_dev, device_remap
            )
            or backup_stat.st_ino != item.get("backup_ino")
            or digest_descriptor(backup_fd, path_type) != item["sha256"]
            or str(destination.parent.resolve()) != item["parent_canonical"]
            or not device_matches(
                item.get("parent_dev"), parent_stat.st_dev, device_remap
            )
            or parent_stat.st_ino != item.get("parent_ino")
        ):
            os.close(backup_fd)
            fail("state backup mismatch")
        backup_handles[item["key"]] = (backup_fd, backup_stat)
    if "replace-backup-after-open" in hooks:
        replace_test_backup()

    def paths(index, item):
        destination = pathlib.Path(item["path"])
        token = f"{manifest['install_session_id']}-{index}"
        return (
            destination,
            destination.parent / f".paygate-rollback-stage-{token}",
            destination.parent / f".paygate-rollback-parked-{token}",
        )

    def parent_binding(item, destination):
        parent_stat = destination.parent.stat()
        return {
            "path": str(destination.parent),
            "canonical": item["parent_canonical"],
            "dev": parent_stat.st_dev,
            "ino": parent_stat.st_ino,
            "uid": parent_stat.st_uid,
        }

    def backup_binding(item):
        backup_fd, metadata = backup_handles[item["key"]]
        return {
            "path": str(rollback_dir / item["backup"]),
            "dev": metadata.st_dev,
            "ino": metadata.st_ino,
            "uid": metadata.st_uid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "digest": digest_descriptor(backup_fd, item["path_type"]),
        }

    install_recovery = False

    def publish_marker(payload):
        if (marker_path.exists() or marker_path.is_symlink()) and not install_recovery:
            raise RuntimeError("recovery marker already exists")
        if pending_marker.exists() or pending_marker.is_symlink():
            if (
                pending_marker.is_symlink()
                or not pending_marker.is_file()
                or pending_marker.lstat().st_uid != uid
            ):
                raise RuntimeError("unsafe pending recovery marker")
            pending_marker.unlink()
            sync_dir(marker_path.parent)
        raw = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()
        fd = os.open(
            pending_marker,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        if "crash-before-marker-rename" in hooks:
            os._exit(84)
        os.rename(pending_marker, marker_path)
        sync_dir(marker_path.parent)

    recovery = read_nofollow_json(marker_path, MAX_MARKER_BYTES, "recovery marker")
    if (
        recovery is not None
        and recovery[0].get("schema") == "paygate-rust-finalize-recovery-v1"
    ):
        fail("finalize recovery is active; rerun the finalize command")
    if (
        recovery is not None
        and recovery[0].get("schema") == "paygate-rust-install-recovery-v1"
    ):
        install_marker, _, install_marker_stat = recovery
        install_keys = {
            "schema",
            "install_session_id",
            "rollback_manifest_sha256",
            "process_uid",
            "runtime_lock",
            "runtime_lock_dev",
            "runtime_lock_ino",
            "launcher",
            "python_launcher_target",
            "installed_rust_launcher_target",
        }
        if (
            set(install_marker) != install_keys
            or install_marker_stat.st_uid != uid
            or install_marker_stat.st_nlink != 1
            or stat.S_IMODE(install_marker_stat.st_mode) != 0o600
            or install_marker["install_session_id"] != manifest["install_session_id"]
            or install_marker["rollback_manifest_sha256"] != manifest_hash
            or install_marker["process_uid"] != uid
            or install_marker["runtime_lock"] != str(lock_path)
            or not device_matches(
                install_marker["runtime_lock_dev"], lock_stat.st_dev, device_remap
            )
            or install_marker["runtime_lock_ino"] != lock_stat.st_ino
            or install_marker["launcher"] != str(launcher)
            or install_marker["python_launcher_target"] != python_target
            or install_marker["installed_rust_launcher_target"] != rust_target
        ):
            fail("install recovery marker identity mismatch")
        install_recovery = True
        recovery = None
    if recovery is None:
        for index, item in enumerate(manifest["state"]):
            destination, stage, parked = paths(index, item)
            parent_stat = destination.parent.stat()
            if (
                not device_matches(item["parent_dev"], parent_stat.st_dev, device_remap)
                or parent_stat.st_ino != item["parent_ino"]
            ):
                fail("state parent identity drift")
            if parked.exists() or parked.is_symlink():
                fail("parked state exists without recovery marker")
            if stage.exists() or stage.is_symlink():
                remove_owned(stage, item["path_type"], uid)
                sync_dir(destination.parent)
        if pending_marker.exists() or pending_marker.is_symlink():
            if (
                pending_marker.is_symlink()
                or not pending_marker.is_file()
                or pending_marker.lstat().st_uid != uid
            ):
                fail("unsafe pending recovery marker")
            pending_marker.unlink()
            sync_dir(marker_path.parent)
        entries = []
        try:
            for index, item in enumerate(manifest["state"]):
                backup_fd, backup_stat = backup_handles[item["key"]]
                destination, stage, parked = paths(index, item)
                if (
                    not type_matches(destination, item["path_type"])
                    or destination.lstat().st_uid != uid
                ):
                    raise RuntimeError("live state identity drift")
                live_identity = identity(destination)
                if "stage-failure" in hooks and index == 1:
                    raise RuntimeError("injected stage failure")
                if item["path_type"] == "directory":
                    cwd_fd = os.open(".", os.O_RDONLY)
                    try:
                        os.fchdir(backup_fd)
                        shutil.copytree(".", stage, symlinks=True)
                    finally:
                        os.fchdir(cwd_fd)
                        os.close(cwd_fd)
                else:
                    os.lseek(backup_fd, 0, os.SEEK_SET)
                    with (
                        os.fdopen(os.dup(backup_fd), "rb") as source,
                        open(stage, "xb") as target,
                    ):
                        shutil.copyfileobj(source, target)
                    os.chmod(stage, stat.S_IMODE(backup_stat.st_mode))
                fsync_tree(stage)
                if (
                    not type_matches(stage, item["path_type"])
                    or stage.lstat().st_uid != uid
                    or digest(stage) != item["sha256"]
                ):
                    raise RuntimeError("staged backup verification failed")
                entries.append(
                    {
                        "key": item["key"],
                        "path": str(destination),
                        "path_type": item["path_type"],
                        "parent": parent_binding(item, destination),
                        "backup": backup_binding(item),
                        "stage": {"path": str(stage), **identity(stage)},
                        "parked": str(parked),
                        "live": live_identity,
                    }
                )
                if index == 0 and "failure-after-stage-create" in hooks:
                    raise RuntimeError("injected failure after stage creation")
                if f"crash-during-staging-{index}" in hooks:
                    os._exit(80 + index)
            launcher_parent_stat = launcher.parent.stat()
            marker = {
                "schema": "paygate-rust-rollback-recovery-v1",
                "install_session_id": manifest["install_session_id"],
                "rollback_manifest_sha256": manifest_hash,
                "process_uid": uid,
                "runtime_lock": str(lock_path),
                "runtime_lock_dev": lock_stat.st_dev,
                "runtime_lock_ino": lock_stat.st_ino,
                "launcher": str(launcher),
                "launcher_parent": {
                    "path": str(launcher.parent),
                    "dev": launcher_parent_stat.st_dev,
                    "ino": launcher_parent_stat.st_ino,
                    "uid": launcher_parent_stat.st_uid,
                },
                "python_environment_original": str(original),
                "python_environment_quarantine": str(quarantine),
                "python_environment_identity": manifest["python_environment_identity"],
                "python_launcher_target": python_target,
                "installed_rust_launcher_target": rust_target,
                "entries": entries,
            }
            publish_marker(marker)
        except BaseException as error:
            if marker_path.exists() or marker_path.is_symlink():
                message = "recovery incomplete; retain the marker and rerun rollback"
                fail(f"{message}: {error}")
            for index, item in enumerate(manifest["state"]):
                _, stage, parked = paths(index, item)
                if parked.exists() or parked.is_symlink():
                    fail("parked state appeared before marker publication")
                if stage.exists() or stage.is_symlink():
                    remove_owned(stage, item["path_type"], uid)
                    sync_dir(stage.parent)
            fail(f"staging failed before recovery marker publication: {error}")
        if "crash-after-publication" in hooks:
            os._exit(85)
    else:
        marker, _, marker_stat = recovery
        if (
            marker_stat.st_uid != uid
            or marker_stat.st_nlink != 1
            or stat.S_IMODE(marker_stat.st_mode) != 0o600
        ):
            fail("recovery marker is unsafe")

    def validate_marker(marker):
        top_keys = {
            "schema",
            "install_session_id",
            "rollback_manifest_sha256",
            "process_uid",
            "runtime_lock",
            "runtime_lock_dev",
            "runtime_lock_ino",
            "launcher",
            "launcher_parent",
            "python_environment_original",
            "python_environment_quarantine",
            "python_environment_identity",
            "python_launcher_target",
            "installed_rust_launcher_target",
            "entries",
        }
        launcher_parent_stat = launcher.parent.stat()
        expected_launcher_parent = {
            "path": str(launcher.parent),
            "dev": launcher_parent_stat.st_dev,
            "ino": launcher_parent_stat.st_ino,
            "uid": launcher_parent_stat.st_uid,
        }
        if (
            not isinstance(marker, dict)
            or set(marker) != top_keys
            or marker.get("schema") != "paygate-rust-rollback-recovery-v1"
            or marker.get("install_session_id") != manifest["install_session_id"]
            or marker.get("rollback_manifest_sha256") != manifest_hash
            or marker.get("process_uid") != uid
            or marker.get("runtime_lock") != str(lock_path)
            or marker.get("runtime_lock_dev") != lock_stat.st_dev
            or marker.get("runtime_lock_ino") != lock_stat.st_ino
            or marker.get("launcher") != str(launcher)
            or marker.get("launcher_parent") != expected_launcher_parent
            or marker.get("python_environment_original") != str(original)
            or marker.get("python_environment_quarantine") != str(quarantine)
            or marker.get("python_environment_identity")
            != manifest["python_environment_identity"]
            or marker.get("python_launcher_target") != python_target
            or marker.get("installed_rust_launcher_target") != rust_target
        ):
            raise RuntimeError("recovery marker identity mismatch")
        entries = marker.get("entries")
        if not isinstance(entries, list) or len(entries) != 4:
            raise RuntimeError("recovery marker entries mismatch")
        identity_keys = {"dev", "ino", "uid", "mode", "digest"}
        for index, (entry, item) in enumerate(
            zip(entries, manifest["state"], strict=True)
        ):
            destination, stage, parked = paths(index, item)
            stage_value = entry.get("stage") if isinstance(entry, dict) else None
            live_value = entry.get("live") if isinstance(entry, dict) else None
            if (
                not isinstance(entry, dict)
                or set(entry)
                != {
                    "key",
                    "path",
                    "path_type",
                    "parent",
                    "backup",
                    "stage",
                    "parked",
                    "live",
                }
                or entry.get("key") != item["key"]
                or entry.get("path") != str(destination)
                or entry.get("path_type") != item["path_type"]
                or entry.get("parent") != parent_binding(item, destination)
                or entry.get("backup") != backup_binding(item)
                or entry.get("parked") != str(parked)
                or not isinstance(stage_value, dict)
                or set(stage_value) != identity_keys | {"path"}
                or stage_value.get("path") != str(stage)
                or not isinstance(live_value, dict)
                or set(live_value) != identity_keys
                or stage_value.get("uid") != uid
                or live_value.get("uid") != uid
                or stage_value.get("digest") != item["sha256"]
            ):
                raise RuntimeError("recovery marker entry binding mismatch")
        return entries

    try:
        entries = validate_marker(marker)
        deployment_shape = (environment_shape(), launcher_shape())
        if deployment_shape not in {
            ("quarantine", rust_target),
            ("original", rust_target),
            ("original", python_target),
        }:
            raise RuntimeError("invalid environment/launcher recovery shape")
        actions = []
        for entry, item in zip(entries, manifest["state"], strict=True):
            destination = pathlib.Path(entry["path"])
            stage = pathlib.Path(entry["stage"]["path"])
            parked = pathlib.Path(entry["parked"])
            path_type = item["path_type"]
            if entry["parent"] != parent_binding(item, destination):
                raise RuntimeError("state parent identity drift")

            def object_state(path, expected, expected_type):
                if not path.exists() and not path.is_symlink():
                    return "absent"
                if path.is_symlink() or not type_matches(path, expected_type):
                    return "invalid"
                return (
                    "match"
                    if identity_matches(path, expected_type, expected)
                    else "invalid"
                )

            stage_identity = {
                key: value for key, value in entry["stage"].items() if key != "path"
            }
            destination_live = object_state(destination, entry["live"], path_type)
            destination_stage = object_state(destination, stage_identity, path_type)
            stage_state = object_state(stage, stage_identity, path_type)
            parked_state = object_state(parked, entry["live"], path_type)
            destination_state = (
                "live"
                if destination_live == "match"
                else "restored"
                if destination_stage == "match"
                else "absent"
                if destination_live == "absent"
                else "invalid"
            )
            shape = (destination_state, stage_state, parked_state)
            accepted = {
                ("live", "match", "absent"): "park-and-restore",
                ("absent", "match", "match"): "restore",
                ("restored", "absent", "match"): "cleanup",
                ("restored", "absent", "absent"): "complete",
            }
            if shape not in accepted:
                raise RuntimeError(f"ambiguous state shape for {entry['key']}")
            actions.append((accepted[shape], destination, stage, parked, entry, item))

        # Validate all four shapes before performing the first state mutation.
        for index, (action, destination, stage, parked, entry, item) in enumerate(
            actions
        ):
            if action == "park-and-restore":
                os.rename(destination, parked)
                sync_dir(destination.parent)
                if f"crash-after-park-{index}" in hooks or (
                    index == 0 and "crash-after-first-park" in hooks
                ):
                    os._exit(90 + index)
                action = "restore"
            if action == "restore":
                os.rename(stage, destination)
                sync_dir(destination.parent)
                stage_identity = {
                    key: value for key, value in entry["stage"].items() if key != "path"
                }
                if not identity_matches(destination, item["path_type"], stage_identity):
                    raise RuntimeError("restored state verification failed")
                if f"crash-after-restore-{index}" in hooks or (
                    index == 0
                    and (
                        "crash-after-first-restored-entry" in hooks
                        or "crash-after-first-swap" in hooks
                    )
                ):
                    os._exit(94 + index)
                if index == 0 and "swap-failure" in hooks:
                    raise RuntimeError("injected monotonic restore failure")

        for entry, item in zip(entries, manifest["state"], strict=True):
            destination = pathlib.Path(entry["path"])
            stage = pathlib.Path(entry["stage"]["path"])
            parked = pathlib.Path(entry["parked"])
            stage_identity = {
                key: value for key, value in entry["stage"].items() if key != "path"
            }
            if (
                not identity_matches(destination, item["path_type"], stage_identity)
                or stage.exists()
                or stage.is_symlink()
                or (
                    (parked.exists() or parked.is_symlink())
                    and not identity_matches(parked, item["path_type"], entry["live"])
                )
            ):
                raise RuntimeError("state restoration is incomplete")

        current_deployment = (environment_shape(), launcher_shape())
        if current_deployment not in {
            ("quarantine", rust_target),
            ("original", rust_target),
            ("original", python_target),
        }:
            raise RuntimeError("invalid deployment recovery shape")
        if current_deployment[0] == "quarantine":
            os.rename(quarantine, original)
            sync_dir(original.parent)
            if "crash-after-environment-rename" in hooks:
                os._exit(101)
        if environment_shape() != "original":
            raise RuntimeError("Python environment restoration failed")

        # Cleanup is monotonic and launcher-last.
        for index, (entry, item) in enumerate(
            zip(entries, manifest["state"], strict=True)
        ):
            stage = pathlib.Path(entry["stage"]["path"])
            parked = pathlib.Path(entry["parked"])
            if stage.exists() or stage.is_symlink():
                raise RuntimeError("unexpected staging object during cleanup")
            if parked.exists() or parked.is_symlink():
                if not identity_matches(parked, item["path_type"], entry["live"]):
                    raise RuntimeError("parked state identity drift")
                remove_owned(parked, item["path_type"], uid)
                sync_dir(parked.parent)
            if f"crash-during-cleanup-{index}" in hooks or (
                index == 0 and "crash-mid-restored-cleanup" in hooks
            ):
                os._exit(102 + index)

        for entry, item in zip(entries, manifest["state"], strict=True):
            destination = pathlib.Path(entry["path"])
            stage = pathlib.Path(entry["stage"]["path"])
            parked = pathlib.Path(entry["parked"])
            stage_identity = {
                key: value for key, value in entry["stage"].items() if key != "path"
            }
            if (
                not identity_matches(destination, item["path_type"], stage_identity)
                or stage.exists()
                or stage.is_symlink()
                or parked.exists()
                or parked.is_symlink()
            ):
                raise RuntimeError("restored state cleanup verification failed")
        if (
            environment_shape() != "original"
            or quarantine.exists()
            or quarantine.is_symlink()
        ):
            raise RuntimeError("restored Python environment verification failed")
        if "crash-after-all-cleaned" in hooks:
            os._exit(106)

        if launcher_shape() == rust_target:
            temporary_launcher = (
                launcher.parent / f".paygate-rollback-{manifest['install_session_id']}"
            )
            if temporary_launcher.exists() or temporary_launcher.is_symlink():
                metadata = temporary_launcher.lstat()
                if (
                    not stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid != uid
                    or os.readlink(temporary_launcher) != python_target
                ):
                    raise RuntimeError("unsafe launcher staging object")
                temporary_launcher.unlink()
                sync_dir(launcher.parent)
            os.symlink(python_target, temporary_launcher)
            if "crash-before-launcher-replacement" in hooks:
                os._exit(108)
            os.replace(temporary_launcher, launcher)
            sync_dir(launcher.parent)
        if launcher_shape() != python_target:
            raise RuntimeError("launcher restore verification failed")
        if "crash-after-launcher-replacement" in hooks:
            os._exit(107)

        if (
            environment_shape() != "original"
            or quarantine.exists()
            or quarantine.is_symlink()
        ):
            raise RuntimeError("complete Python deployment verification failed")
        for entry, item in zip(entries, manifest["state"], strict=True):
            stage_identity = {
                key: value for key, value in entry["stage"].items() if key != "path"
            }
            if not identity_matches(
                pathlib.Path(entry["path"]), item["path_type"], stage_identity
            ):
                raise RuntimeError("complete Python state verification failed")
        marker_path.unlink()
        sync_dir(marker_path.parent)
    except BaseException as error:
        fail(f"recovery incomplete; retain the marker and rerun rollback: {error}")


if __name__ == "__main__":
    main()
