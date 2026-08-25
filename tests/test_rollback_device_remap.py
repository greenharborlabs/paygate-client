import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "rollback-rust-paygate.py"
SPEC = importlib.util.spec_from_file_location("rollback_rust_paygate", SCRIPT)
ROLLBACK = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(ROLLBACK)


def write_json(path, value, mode=0o600):
    if path.exists():
        path.chmod(0o600)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    path.chmod(mode)


class DeviceRemapAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary_directory.name)
        self.rollback_dir = self.root / "rollback"
        self.rollback_dir.mkdir()
        self.manifest_path = self.rollback_dir / "manifest.json"
        self.record_path = self.root / "preflight.json"
        self.rust_target = self.root / "paygate"
        self.rust_target.write_bytes(b"reboot-stable-candidate")
        self.rust_target.chmod(0o555)
        binary_hash = hashlib.sha256(self.rust_target.read_bytes()).hexdigest()
        self.manifest = {
            "candidate_identity": {"binary_sha256": binary_hash},
            "installed_rust_launcher_target": str(self.rust_target),
            "runtime_lock": str(self.root / ".paygate-runtime.lock"),
            "runtime_lock_dev": 100,
            "runtime_lock_ino": 200,
        }
        write_json(self.manifest_path, self.manifest, 0o400)
        write_json(self.record_path, {"schema": "preflight"})
        self.authorization_path = self.root / "authorization.json"
        self.authorization = {
            "schema": "paygate-rollback-device-remap-v1",
            "boot_session_uuid": "TEST-BOOT",
            "rollback_directory": str(self.rollback_dir.resolve()),
            "rollback_manifest_sha256": hashlib.sha256(
                self.manifest_path.read_bytes()
            ).hexdigest(),
            "preflight_sha256": hashlib.sha256(
                self.record_path.read_bytes()
            ).hexdigest(),
            "installed_rust_target": str(self.rust_target),
            "installed_rust_binary_sha256": binary_hash,
            "runtime_lock": self.manifest["runtime_lock"],
            "runtime_lock_ino": self.manifest["runtime_lock_ino"],
            "recorded_device": self.manifest["runtime_lock_dev"],
            "current_device": 101,
        }
        write_json(self.authorization_path, self.authorization, 0o400)
        self.environment = mock.patch.dict(
            os.environ,
            {ROLLBACK.DEVICE_REMAP_AUTH_ENV: str(self.authorization_path)},
            clear=False,
        )
        self.platform = mock.patch.object(ROLLBACK.sys, "platform", "darwin")
        self.run = mock.patch.object(
            ROLLBACK.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["sysctl"], 0, "TEST-BOOT\n", ""),
        )
        self.environment.start()
        self.platform.start()
        self.run.start()

    def tearDown(self):
        self.run.stop()
        self.platform.stop()
        self.environment.stop()
        self.temporary_directory.cleanup()

    def load(self):
        return ROLLBACK.load_device_remap_authorization(
            self.rollback_dir,
            self.manifest,
            hashlib.sha256(self.manifest_path.read_bytes()).hexdigest(),
            hashlib.sha256(self.record_path.read_bytes()).hexdigest(),
            os.getuid(),
        )

    def test_authorization_is_boot_and_artifact_bound(self):
        authorization = self.load()

        self.assertEqual(authorization["recorded_device"], 100)
        self.assertEqual(authorization["current_device"], 101)

    def test_authorization_rejects_wrong_boot(self):
        self.authorization["boot_session_uuid"] = "STALE-BOOT"
        write_json(self.authorization_path, self.authorization, 0o400)

        with self.assertRaisesRegex(
            SystemExit, "device remap authorization is invalid"
        ):
            self.load()

    def test_authorization_requires_read_only_file(self):
        self.authorization_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

        with self.assertRaisesRegex(
            SystemExit, "device remap authorization is invalid"
        ):
            self.load()

    def test_authorization_rejects_preflight_drift(self):
        write_json(self.record_path, {"schema": "changed-preflight"})

        with self.assertRaisesRegex(
            SystemExit, "device remap authorization is invalid"
        ):
            self.load()

    def test_authorization_rejects_installed_binary_drift(self):
        self.rust_target.chmod(0o755)
        self.rust_target.write_bytes(b"replacement-candidate")
        self.rust_target.chmod(0o555)

        with self.assertRaisesRegex(
            SystemExit, "device remap authorization is invalid"
        ):
            self.load()

    def test_authorization_is_macos_only(self):
        with (
            mock.patch.object(ROLLBACK.sys, "platform", "linux"),
            self.assertRaisesRegex(
                SystemExit, "device remap authorization is only valid on macOS"
            ),
        ):
            self.load()

    def test_authorization_rejects_invalid_current_device(self):
        for value in (self.authorization["recorded_device"], -1, True):
            with self.subTest(value=value):
                authorization = dict(self.authorization)
                authorization["current_device"] = value
                write_json(self.authorization_path, authorization, 0o400)

                with self.assertRaisesRegex(
                    SystemExit, "device remap authorization is invalid"
                ):
                    self.load()

    def test_device_match_accepts_only_the_authorized_mapping(self):
        authorization = self.load()

        self.assertTrue(ROLLBACK.device_matches(100, 101, authorization))
        self.assertTrue(ROLLBACK.device_matches(101, 101, authorization))
        self.assertFalse(ROLLBACK.device_matches(100, 102, authorization))
        self.assertFalse(ROLLBACK.device_matches(99, 101, authorization))

    def test_device_match_without_authorization_requires_exact_identity(self):
        self.assertTrue(ROLLBACK.device_matches(100, 100))
        self.assertFalse(ROLLBACK.device_matches(100, 101))


if __name__ == "__main__":
    unittest.main()
