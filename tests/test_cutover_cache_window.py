import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "cutover-cache-window.py"
SPEC = importlib.util.spec_from_file_location("cutover_cache_window", SCRIPT)
WINDOW = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(WINDOW)


class CutoverCacheWindowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.directory.name)
        self.paygate = self.root / "paygate"
        self.paygate.write_bytes(b"candidate")
        self.paygate.chmod(0o500)
        self.acceptance = self.root / "acceptance.json"
        self.acceptance_document = {
            "schema": "paygate-cutover-acceptance-v2",
            "candidate_identity": {},
            "cutover_session_id": "a" * 32,
            "phase": "preinstall-recording",
            "checkpoints": [
                {"gate": gate}
                for gate in (
                    "fixture-oracle-pass",
                    "rust-product-tests-pass",
                    "candidate-doctor-pass",
                    "invoice-approved",
                    "invoice-pass",
                    "request-approved",
                )
            ],
        }
        self.acceptance.write_text(json.dumps(self.acceptance_document))
        self.url = "https://paygate.example/resource?item=1"
        self.credential = {
            "id": "credential-1",
            "scope": {
                "namespace": "default",
                "requestKey": WINDOW.request_key("GET", self.url),
                "originHost": "paygate.example:443",
                "service": "reference",
                "protocol": "Payment",
                "payerBackend": "breez",
                "policyHash": "b" * 64,
            },
            "authorization": "[REDACTED_CREDENTIAL]",
            "createdAt": 1_100,
            "expiresAt": 5_000,
            "maxUses": None,
            "useCount": 1,
            "lastRejectedAt": None,
        }
        self.listing = {"ok": True, "credentials": [self.credential]}

    def tearDown(self):
        self.directory.cleanup()

    def build(self, *, now=1_200, minimum=600):
        return WINDOW.build_state(
            paygate=self.paygate,
            acceptance_path=self.acceptance,
            listing=self.listing,
            method="GET",
            url=self.url,
            profile="default",
            issued_after_epoch=1_000,
            minimum_remaining_seconds=minimum,
            now_epoch=now,
        )

    def install_acceptance(self):
        document = dict(self.acceptance_document)
        document["phase"] = "installed"
        self.acceptance.write_text(json.dumps(document))

    def test_capture_binds_exact_credential_candidate_session_and_deadline(self):
        state = self.build()

        self.assertEqual(state["credentialId"], "credential-1")
        self.assertEqual(
            state["candidateSha256"], WINDOW.safe_binary_hash(self.paygate)
        )
        self.assertEqual(state["candidatePath"], str(self.paygate.resolve()))
        self.assertEqual(state["cutoverSessionId"], "a" * 32)
        self.assertEqual(state["mustStartPostRebootByEpoch"], 4_400)

    def test_capture_rejects_window_without_safety_margin(self):
        with self.assertRaisesRegex(WINDOW.WindowError, "does not leave enough time"):
            self.build(now=4_400)

    def test_capture_rejects_credential_from_before_live_request(self):
        self.credential["createdAt"] = 999

        with self.assertRaisesRegex(WINDOW.WindowError, "uniquely identified"):
            self.build()

    def test_verify_accepts_bound_retrievable_credential_after_install(self):
        state = self.build()
        self.install_acceptance()

        result = WINDOW.validate_state(
            state=state,
            paygate=self.paygate,
            listing=self.listing,
            now_epoch=2_000,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["secondsUntilDeadline"], 2_400)

    def test_verify_accepts_installed_launcher_resolving_to_bound_candidate(self):
        state = self.build()
        self.install_acceptance()
        launcher = self.root / "launcher"
        launcher.symlink_to(self.paygate)

        result = WINDOW.validate_state(
            state=state,
            paygate=launcher,
            listing=self.listing,
            now_epoch=2_000,
        )

        self.assertTrue(result["ok"])

    def test_verify_rejects_candidate_drift(self):
        state = self.build()
        self.install_acceptance()
        self.paygate.chmod(0o700)
        self.paygate.write_bytes(b"replacement")
        self.paygate.chmod(0o500)

        with self.assertRaisesRegex(WINDOW.WindowError, "does not match"):
            WINDOW.validate_state(
                state=state,
                paygate=self.paygate,
                listing=self.listing,
                now_epoch=2_000,
            )

    def test_verify_rejects_missing_keyring_credential(self):
        state = self.build()
        self.install_acceptance()

        with self.assertRaisesRegex(WINDOW.WindowError, "not retrievable"):
            WINDOW.validate_state(
                state=state,
                paygate=self.paygate,
                listing={"ok": True, "credentials": []},
                now_epoch=2_000,
            )

    def test_verify_rejects_scope_drift_for_same_credential_id(self):
        state = self.build()
        self.install_acceptance()
        changed = {**self.credential, "scope": dict(self.credential["scope"])}
        changed["scope"]["policyHash"] = "c" * 64

        with self.assertRaisesRegex(WINDOW.WindowError, "not retrievable"):
            WINDOW.validate_state(
                state=state,
                paygate=self.paygate,
                listing={"ok": True, "credentials": [changed]},
                now_epoch=2_000,
            )

    def test_verify_rejects_expired_hard_deadline_before_request(self):
        state = self.build()
        self.install_acceptance()

        with self.assertRaisesRegex(WINDOW.WindowError, "deadline has passed"):
            WINDOW.validate_state(
                state=state,
                paygate=self.paygate,
                listing=self.listing,
                now_epoch=4_400,
            )

    def test_state_file_is_owner_read_only_and_cannot_be_replaced(self):
        output = self.root / "window.json"
        state = self.build()

        WINDOW.write_state(output, state)

        self.assertEqual(output.stat().st_mode & 0o777, 0o400)
        loaded = WINDOW.safe_json(output, "cache-window state", required_mode=0o400)
        self.assertEqual(loaded, state)
        with self.assertRaisesRegex(WINDOW.WindowError, "already exists"):
            WINDOW.write_state(output, state)

    def test_state_file_refuses_group_or_world_writable_parent(self):
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)

        with self.assertRaisesRegex(WINDOW.WindowError, "parent is unsafe"):
            WINDOW.write_state(unsafe / "window.json", self.build())

    def test_runbook_has_live_commitment_and_both_window_checks(self):
        runbook = (
            pathlib.Path(__file__).parents[1]
            / "docs"
            / "minimal-rust-cutover-runbook.md"
        ).read_text()

        self.assertIn("COMPLETE_INSTALL_REBOOT_AND_VERIFY_NOW", runbook)
        self.assertIn("one uninterrupted live-cutover phase", runbook)
        self.assertIn("cutover-cache-window.py capture", runbook)
        self.assertIn("cutover-cache-window.py verify", runbook)
        self.assertIn("--minimum-remaining-seconds 600", runbook)
        self.assertIn("preserve its\nowner-only, redacted JSON trace", runbook)

    def test_cli_capture_and_post_install_verify_round_trip(self):
        now = int(time.time())
        self.credential["createdAt"] = now
        self.credential["expiresAt"] = now + 3_600
        fake = self.root / "fake-paygate"
        fake.write_text(
            f"#!{sys.executable}\nimport json\nprint(json.dumps({self.listing!r}))\n"
        )
        fake.chmod(0o500)
        state = self.root / "window.json"
        capture = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "capture",
                "--paygate",
                str(fake),
                "--acceptance",
                str(self.acceptance),
                "--output",
                str(state),
                "--url",
                self.url,
                "--issued-after-epoch",
                str(now - 1),
                "--confirm",
                WINDOW.LIVE_COMMITMENT,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(capture.returncode, 0, capture.stderr)
        self.assertEqual(state.stat().st_mode & 0o777, 0o400)
        self.install_acceptance()
        launcher = self.root / "launcher"
        launcher.symlink_to(fake)

        verify = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "verify",
                "--paygate",
                str(launcher),
                "--state",
                str(state),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertTrue(json.loads(verify.stdout)["ok"])

    def test_cli_refuses_capture_without_live_commitment(self):
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "capture",
                "--paygate",
                str(self.paygate),
                "--acceptance",
                str(self.acceptance),
                "--output",
                str(self.root / "window.json"),
                "--url",
                self.url,
                "--issued-after-epoch",
                "1000",
                "--confirm",
                "NOT_READY",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("live cutover commitment is required", result.stderr)


if __name__ == "__main__":
    unittest.main()
