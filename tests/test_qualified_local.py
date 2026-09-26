"""Observed local role confinement, real authentication and real consequences."""

import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.qualified_local import cleanup_credentials, retain_receipt, run_qualification
from scripts.local_demo import GOOD_ARTIFACT
from scripts.dev_cluster import DevCluster
from hobnail.credentials import CredentialError


class QualifiedLocalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = run_qualification()
        if cls.receipt["status"] != "passed":
            raise AssertionError({"failure": cls.receipt.get("failure"), "receipt": cls.receipt["receipt"]})
        cls.root = Path(cls.receipt["retained_root"])
        cls.checks = cls.receipt["checks"]

    def test_every_reachable_login_requires_authentication_and_peers_are_confined(self):
        self.assertTrue(self.checks["administrator_requires_scram"])
        roles = self.checks["role_boundaries"]
        self.assertEqual(set(roles), {"worker", "registrar", "approver", "verifier", "adapter",
                                     "observer", "auditor", "credential_provider"})
        for role, observed in roles.items():
            with self.subTest(role=role):
                self.assertTrue(observed["session_authenticated"])
                self.assertEqual(7, observed["peer_reads_denied"])
                self.assertTrue(observed["administrator_denied"])
                self.assertTrue(observed["administrator_wrong_password_denied"])
                self.assertTrue(observed["other_network_denied"])
                self.assertRegex(observed["profile_fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual("local all all scram-sha-256\nhost all all all reject\n",
                         (self.root / "data/pg_hba.conf").read_text())
        rotated = self.checks["runtime_verifier_credential"]
        self.assertTrue(rotated["password_authenticated"])
        self.assertTrue(rotated["worker_file_read_denied"])
        self.assertEqual("CREDENTIAL_SCOPE", rotated["worker_profile_denial"]["code"])
        self.assertTrue(rotated["revoked_login_denied"])
        self.assertEqual({"credential_denied": True, "database_socket_denied": True},
                         self.checks["candidate_parser_actual_denials"])

    def test_destination_is_written_and_read_by_separate_confined_roles(self):
        flow = self.checks["workflow"]
        self.assertTrue(flow["acceptance"]["data"]["accepted"])
        self.assertEqual("attempted", flow["dispatch"]["data"]["state"])
        self.assertEqual("complete", flow["observation"]["data"]["state"])
        self.assertEqual("FORBIDDEN", flow["worker_verification_denial"]["code"])
        actual = (self.root / "published/accepted.json").read_bytes()
        self.assertEqual(GOOD_ARTIFACT, actual)
        self.assertEqual(hashlib.sha256(actual).hexdigest(), flow["artifact_sha256"])
        self.assertTrue(self.checks["parent_observed_no_forbidden_effects"])
        self.assertEqual(b"owned-boundary-marker", (self.root / "published/controlled-marker").read_bytes())
        self.assertTrue(self.checks["production_adapter_probe_refused"])

    def test_failed_and_stale_work_cannot_create_a_confined_effect(self):
        negative = self.checks["negative_workflows"]
        self.assertEqual("CHECK_FAILED", negative["bad_acceptance"]["code"])
        self.assertEqual("CHECK_FAILED", negative["bad_effect"]["code"])
        self.assertEqual("INPUT_STALE", negative["stale_dispatch"]["code"])
        self.assertFalse((self.root / "published/stale.json").exists())
        self.assertEqual(GOOD_ARTIFACT, (self.root / "published/accepted.json").read_bytes())

    def test_executed_code_is_read_only_without_bytecode_or_credential_output(self):
        package = self.root / "runtime/hobnail"
        self.assertFalse(list(package.rglob("*.pyc")))
        for source in package.rglob("*.py"):
            self.assertEqual(0o400, stat.S_IMODE(source.stat().st_mode))
            relative = source.relative_to(package)
            self.assertEqual(source.read_bytes(), (ROOT / "src/hobnail" / relative).read_bytes())
        text = Path(self.receipt["receipt"]).read_text()
        log = (self.root / "server.log").read_text()
        for config in (self.root / "services").glob("*/*.json"):
            secret = json.loads(config.read_text())["connection"]["password"]
            self.assertFalse(secret in text or secret in log, "credential material appeared; content withheld")
            self.assertEqual(0o600, stat.S_IMODE(config.stat().st_mode))
        self.assertNotIn("SCRAM-SHA-256$", log)

    def test_authority_is_revoked_and_owned_runtime_stopped_with_receipt_retained(self):
        self.assertTrue(self.checks["all_runtime_credentials_revoked"])
        self.assertTrue(self.receipt["runtime_stopped"])
        self.assertFalse(DevCluster.from_path(self.root).is_running())
        self.assertEqual(self.receipt, json.loads(Path(self.receipt["receipt"]).read_text()))
        self.assertTrue(self.receipt["assumptions"])


class QualificationFailureHandlingTests(unittest.TestCase):
    """Synthetic cleanup exceptions, separate from the real qualification above."""

    def test_failed_revoke_preserves_primary_failure_and_attempts_every_lease(self):
        calls = []

        class Provider:
            def revoke(self, reference):
                calls.append(reference)
                if reference == "first":
                    raise CredentialError("controlled provider outage")
                return SimpleNamespace(result="confirmed", active_sessions=0)

        primary = {"type": "QualificationError", "reason": "original_failure"}
        receipt = {"status": "failed", "failure": primary.copy(), "checks": {}}
        leases = [SimpleNamespace(principal=name, lease_ref=name) for name in ("first", "second")]
        cleanup_credentials(Provider(), leases, receipt)
        self.assertEqual(["first", "second"], calls)
        self.assertEqual(primary, receipt["failure"])
        self.assertFalse(receipt["checks"]["all_runtime_credentials_revoked"])
        self.assertEqual("second", receipt["checks"]["credential_cleanup"][1]["principal"])
        self.assertTrue(receipt["checks"]["credential_cleanup"][1]["confirmed"])

    def test_status_and_ownership_failures_still_persist_a_failed_receipt_elsewhere(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-receipt-probe-") as directory:
            original = Path(directory)

            class UnavailableCluster:
                root = original

                def is_running(self):
                    raise OSError("controlled status failure")

                def _check_owner(self):
                    raise OSError("controlled ownership failure")

            primary = {"type": "QualificationError", "reason": "original_failure"}
            receipt = {"status": "failed", "failure": primary.copy(), "checks": {}}
            retain_receipt(UnavailableCluster(), receipt)
            self.assertEqual(primary, receipt["failure"])
            self.assertIsNone(receipt["runtime_stopped"])
            self.assertFalse((original / "qualification.json").exists())
            saved = Path(receipt["receipt"])
            self.assertEqual(receipt, json.loads(saved.read_text()))
            self.assertEqual("failed", receipt["status"])
            self.assertEqual({"runtime_status", "receipt_persistence"},
                             {entry["stage"] for entry in receipt["cleanup_failures"]})


if __name__ == "__main__":
    unittest.main()
