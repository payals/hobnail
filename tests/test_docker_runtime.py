"""Actual Docker qualification; missing release configuration is a hard error."""

import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts import qualified_docker as qualification


class DockerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configuration = qualification.release_configuration(os.environ.get("HOBNAIL_DOCKER_RELEASE_CONFIG"))
        cls.receipt = qualification.run_qualification(**configuration)
        if cls.receipt["status"] != "passed":
            raise AssertionError({"failure": cls.receipt.get("failure"), "receipt": cls.receipt["receipt"]})
        cls.checks = cls.receipt["checks"]

    def test_actual_roles_authenticate_separately_and_restrict_kernel_authority(self):
        logins = set()
        for role in qualification.ROLES:
            own = self.checks[role + "-self"]["facts"]
            self.assertEqual(own["uid"], qualification.UIDS[role])
            self.assertEqual(own["proc_status"]["NoNewPrivs"], 1)
            self.assertEqual(own["proc_status"]["Seccomp"], 2)
            self.assertTrue(all(int(own["proc_status"][field], 16) == 0 for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")))
            login = self.checks[role + "-sql_boundary"]["facts"]["identity_and_privileges"]["session_user"]
            logins.add(login)
            self.assertEqual(self.checks[role + "-wrong-password"], {"error": "PasswordAuthenticationFailed"})
            held = self.checks[role + "-peer-holder-ready"]
            self.assertTrue(held["ready_response"]["ready"])
            peer = self.checks[role + "-peer"]["facts"]
            self.assertEqual(peer["host_pid"], held["host_pid"])
            self.assertNotEqual(peer["host_pid"], peer["own_pid"])
            self.assertTrue(all(peer[name]["outcome"] in {"absent", "denied"} for name in ("config", "environment", "descriptors")))
        self.assertEqual(len(logins), 8)
        self.assertEqual(self.checks["unknown-principal-api-refused"]["code"], "UNAUTHENTICATED")
        self.assertEqual(self.checks["worker-adapter-claim-denied"]["code"], "FORBIDDEN")
        self.assertEqual(self.checks["worker-adapter-effect-before"]["data"], self.checks["worker-adapter-effect-after"]["data"])
        self.assertEqual(self.checks["worker-adapter-budget-before"]["data"], self.checks["worker-adapter-budget-after"]["data"])

    def test_exact_effect_and_changed_stale_nonadmitted_consequences(self):
        self.assertTrue(self.checks["candidate-accepted"]["data"]["accepted"])
        self.assertEqual(self.checks["accepted-observation"]["data"]["state"], "complete")
        self.assertEqual(self.checks["changed-observation"]["data"]["state"], "control_failure")
        self.assertEqual(self.checks["nonadmitted-effect-denied"]["code"], "MISSING_CHECKS")
        self.assertEqual(self.checks["wrong-content-verification"]["code"], "CHECK_FAILED")
        self.assertEqual(self.checks["stale-dispatch"]["code"], "INPUT_STALE")
        files = self.checks["destination-final"]["facts"]
        self.assertEqual(files["accepted.json"]["sha256"], hashlib.sha256(qualification.GOOD_ARTIFACT).hexdigest())
        for name in ("stale.json", "never-admitted.json", "qualification-worker-denied"):
            self.assertEqual(files[name]["outcome"], "absent")

    def test_uncertain_dispatch_requires_reconciliation_without_duplicate_or_budget_reset(self):
        self.assertEqual(self.checks["uncertain-dispatch-response-discarded"]["seeded_fault"], "adapter_response_discarded")
        self.assertIn(self.checks["uncertain-pending"]["data"]["state"], {"dispatched", "attempted", "uncertain", "reconcile"})
        self.assertEqual(self.checks["uncertain-redispatch-denied"]["code"], "RECONCILIATION_REQUIRED")
        self.assertEqual(self.checks["uncertain-reconciled"]["data"]["state"], "complete")
        self.assertEqual(self.checks["uncertain-destination-before"], self.checks["uncertain-destination-after"])
        self.assertEqual(self.checks["uncertain-budget-before"]["data"], self.checks["uncertain-budget-after"]["data"])

    def test_nonfixture_source_inventory_is_observed_and_audit_chain_is_verified(self):
        delivered = self.checks["source-inventory-delivery"]
        raw = Path(delivered["path"]).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), delivered["sha256"])
        self.assertEqual(json.loads(raw), self.checks["source-inventory-registrar"])
        self.assertEqual(json.loads(raw), self.checks["source-inventory-worker"])
        self.assertEqual(self.checks["source-inventory-observation"]["data"]["state"], "complete")
        verified = self.checks["audit-verified"]
        self.assertGreater(verified["verified_events"], 0)
        self.assertEqual(verified["checkpoint"]["sequence"], verified["verified_events"])
        self.assertFalse(verified["externally_anchored"])
        self.assertTrue(self.receipt["assertions"]["audit-delivered-source-inventory"])

    def test_real_lifetime_is_exhausted_without_shortening_the_profile(self):
        self.assertEqual(self.checks["declared-qualification-limits"]["runtime_lifetime"], 180)
        self.assertGreaterEqual(self.checks["lifetime-credential-exhaustion-wait"]["elapsed_seconds"], 180)
        self.assertEqual(self.checks["lifetime-credential-kernel-refused"]["code"], "CREDENTIAL_SCOPE")
        self.assertEqual(self.checks["lifetime-credential-provider-refused"], {"error": "CredentialError"})
        self.assertEqual(self.checks["lifetime-credential-expired-login"], {"error": "PasswordAuthenticationFailed"})
        self.assertEqual(self.checks["lifetime-credential-exhausted-renewal"]["code"], "CREDENTIAL_EXPIRED")
        self.assertEqual(self.checks["lifetime-credential-revoked"]["result"], "confirmed")

    def test_actual_parser_and_credential_retirement_leave_no_running_owned_resources(self):
        parser = self.checks["parser-boundaries"]
        self.assertTrue(parser["scratch_positive"])
        self.assertEqual(parser["configuration"]["outcome"], "absent")
        self.assertTrue(all(value["outcome"] == "policy_denied" for value in parser["sockets"].values()))
        for command in ("sleep_timeout", "stdout_overflow", "stderr_overflow"):
            stage = "parser-limit-" + command
            process = self.checks[stage + "-containers"]
            self.assertEqual(len(process), 1)
            self.assertRegex(process[0]["id"], r"^[0-9a-f]{64}$")
            self.assertEqual(process[0]["state"], "removed")
            self.assertIs(type(process[0]["exit_code"]), int)
            if command == "sleep_timeout":
                self.assertEqual(self.checks[stage], {"error": "TransportTimeout"})
                self.assertTrue(process[0]["cleanup_observed_state"]["running"])
                self.assertGreater(process[0]["cleanup_observed_state"]["pid"], 0)
                self.assertNotEqual(process[0]["exit_code"], 0)
            else:
                self.assertNotEqual(self.checks[stage]["returncode"], 0)
                self.assertEqual(self.checks[stage]["diagnostic"], "output_limit")
        self.assertEqual(self.checks["runtime-credential-revoked"]["result"], "confirmed")
        for prefix in ("runtime-credential", "expiry-credential"):
            self.assertTrue(self.checks[prefix + "-held-ready"]["ready_response"]["ready"])
            self.assertTrue(self.checks[prefix + "-held-termination"]["terminated"])
            self.assertNotEqual(self.checks[prefix + "-held-termination"]["exit_code"], 0)
            self.assertLess(self.checks[prefix + "-held-elapsed"], 55)
            self.assertEqual(self.checks[prefix + "-backend-final"]["active_sessions"], 0)
        self.assertEqual(self.checks["expiry-credential-expired-new-login"], {"error": "PasswordAuthenticationFailed"})
        self.assertTrue(self.checks["expiry-credential-existing-session-remains"]["target_waiting"])
        self.assertTrue(self.checks["all_runtime_credentials_revoked"])
        retired = self.checks["credential_retirement"]
        self.assertEqual(len({entry["login"] for entry in retired}), 12)
        self.assertTrue(all(entry["confirmed"] and entry["active_sessions"] == 0 and entry["login_enabled"] is False for entry in retired))
        self.assertTrue(self.receipt["runtime_stopped"])
        self.assertFalse(self.receipt["cleanup_failures"])
        self.assertTrue(all(state == "removed" for state in self.checks["runtime-close"]["container_states"]))
        self.assertEqual(self.checks["runtime-close"]["administrator_retirement"],
                         {"result": "confirmed", "login_enabled": False, "other_client_sessions": 0})
        self.assertEqual(json.loads(Path(self.receipt["receipt"]).read_text()), self.receipt)


if __name__ == "__main__":
    unittest.main()
