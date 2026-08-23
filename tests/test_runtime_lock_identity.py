import importlib.util
import os
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "runtime_lock_identity.py"
SPEC = importlib.util.spec_from_file_location("runtime_lock_identity", SCRIPT)
IDENTITY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(IDENTITY)


class RuntimeLockIdentityTests(unittest.TestCase):
    def test_path_and_descriptor_report_the_same_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "runtime.lock"
            path.write_bytes(b"")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                descriptor = IDENTITY.descriptor_identity(fd)
            finally:
                os.close(fd)

            self.assertEqual(IDENTITY.path_identity(path), descriptor)
            if IDENTITY.sys.platform == "darwin":
                self.assertRegex(
                    descriptor,
                    r"^darwin-volume-object-v1:[0-9a-f]{32}:[1-9][0-9]*:[0-9]+$",
                )
            else:
                self.assertRegex(
                    descriptor,
                    r"^linux-device-inode-v1:[0-9]+:[1-9][0-9]*$",
                )

    def test_replacement_file_has_a_different_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / "runtime.lock"
            replacement = root / "replacement.lock"
            path.write_bytes(b"")
            replacement.write_bytes(b"")
            original = IDENTITY.path_identity(path)

            os.replace(replacement, path)

            self.assertNotEqual(IDENTITY.path_identity(path), original)

    def test_unsupported_platform_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "runtime.lock"
            path.write_bytes(b"")
            fd = os.open(path, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(
                    OSError, "unsupported runtime-lock platform"
                ):
                    IDENTITY.descriptor_identity(fd, platform="unsupported")
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
