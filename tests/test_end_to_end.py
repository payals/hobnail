"""Real maintained CLI workflow: no passing-verdict fixtures or provider mocks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.dev_cluster import DevCluster
from scripts.local_demo import BAD_ARTIFACT, GOOD_ARTIFACT, TRUSTED_INPUT, run_demo


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.receipt = run_demo()
        if cls.receipt["run_status"] != "completed":
            raise AssertionError(json.dumps({"failure": cls.receipt.get("failure"),
                                             "evidence_file": cls.receipt.get("evidence_file")}))
        cls.scenarios = {item["scenario"]: item for item in cls.receipt["scenarios"]}
        cls.root = Path(cls.receipt["retained_root"])
        cls.output = Path(cls.receipt["output_root"])

    def test_exact_work_passes_real_validator_and_has_independently_observed_file(self) -> None:
        happy = self.scenarios["happy"]
        self.assertTrue(happy["stages"]["acceptance"]["ok"])
        self.assertEqual(happy["stages"]["acceptance"]["status"], "accepted")
        self.assertEqual({row["check_id"]: row["result"] for row in happy["evidence"]["checks"]},
                         {"metrics": "pass", "shape": "pass"})
        self.assertEqual(happy["effect"]["state"], "complete")
        self.assertEqual(happy["stages"]["dispatch"]["data"]["state"], "attempted")
        self.assertEqual(happy["stages"]["independent_observation"]["data"]["state"], "complete")
        self.assertEqual({row["verifier"] for row in happy["evidence"]["checks"]}, {"demo-verifier"})
        self.assertEqual(happy["effect"]["requested_by"], "demo-worker")
        self.assertEqual({row["principal"] for row in happy["effect"]["reports"] if row["kind"] == "dispatch"}, {"demo-adapter"})
        self.assertEqual({row["principal"] for row in happy["effect"]["reports"] if row["kind"] == "observation"}, {"demo-observer"})
        self.assertEqual((self.output / "happy.json").read_bytes(), GOOD_ARTIFACT)
        self.assertEqual(happy["consequence"]["digest"], hashlib.sha256(GOOD_ARTIFACT).hexdigest())
        self.assertEqual(happy["trusted_input_digest"], hashlib.sha256(TRUSTED_INPUT).hexdigest())
        self.assertTrue(happy["evidence"]["current_eligible"])

    def test_bad_content_preserves_failed_check_and_produces_no_file(self) -> None:
        bad = self.scenarios["bad_content"]
        self.assertFalse(bad["stages"]["acceptance"]["ok"])
        self.assertEqual(bad["stages"]["acceptance"]["code"], "CHECK_FAILED")
        self.assertEqual(bad["stages"]["effect_request"]["code"], "CHECK_FAILED")
        checks = {row["check_id"]: row for row in bad["evidence"]["checks"]}
        self.assertEqual(checks["metrics"]["result"], "fail")
        self.assertEqual(checks["shape"]["result"], "pass")
        self.assertEqual(bad["evidence"]["acceptances"], [])
        self.assertFalse(bad["evidence"]["current_eligible"])
        self.assertEqual(bad["artifact_digest"], hashlib.sha256(BAD_ARTIFACT).hexdigest())
        self.assertFalse(bad["consequence"]["exists"])
        self.assertFalse((self.output / "bad_content.json").exists())

    def test_advanced_input_blocks_reserved_effect_and_preserves_historical_acceptance(self) -> None:
        stale = self.scenarios["stale_input"]
        self.assertTrue(stale["stages"]["acceptance"]["ok"])
        self.assertTrue(stale["stages"]["effect_request"]["ok"])
        self.assertEqual(stale["stages"]["dispatch"]["code"], "INPUT_STALE")
        self.assertEqual(stale["stages"]["current_acceptance"]["code"], "INPUT_STALE")
        self.assertFalse(stale["evidence"]["current_eligible"])
        self.assertEqual(len(stale["evidence"]["acceptances"]), 1)
        self.assertEqual({row["result"] for row in stale["evidence"]["checks"]}, {"pass"})
        self.assertEqual(stale["effect"]["state"], "reserved")
        self.assertIsNone(stale["effect"]["dispatched_at"])
        self.assertFalse((self.output / "stale_input.json").exists())

    def test_actual_dynamic_credentials_and_restricted_child_limits_are_reported(self) -> None:
        stages = self.receipt["stages"]
        self.assertEqual(stages["worker_privileged_profile"]["code"], "CREDENTIAL_SCOPE")
        self.assertTrue(stages["dynamic_verifier_credential"]["password_authenticated"])
        self.assertEqual(stages["dynamic_verifier_credential"]["role"], "verifier")
        self.assertEqual(stages["revoke_dynamic_verifier"], {"result": "confirmed", "active_sessions": 0,
                                                            "login_enabled": False, "new_login_denied": True})
        probe = stages["restricted_child_probe"]["observations"]
        for name in ("external_read_denied", "external_write_denied", "network_connect_denied",
                     "network_effect_absent", "external_write_absent", "marker_unchanged",
                     "parent_marker_environment_absent", "credential_environment_absent"):
            self.assertIs(probe[name], True, name)
        self.assertFalse(self.receipt["qualification"]["production_os_authority_separation"])
        self.assertTrue(stages["check_secret_absence"]["passwords_and_verifiers_absent_from_statement_log"])
        self.assertTrue(stages["check_secret_absence"]["passwords_absent_from_evidence"])

    def test_audit_and_failure_receipts_survive_after_owned_runtime_stops(self) -> None:
        self.assertTrue(self.receipt["runtime_stopped"])
        self.assertFalse(DevCluster.from_path(self.root).is_running())
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertTrue((self.root / "server.log").is_file())
        retained = json.loads(Path(self.receipt["evidence_file"]).read_text())
        self.assertEqual(retained, self.receipt)
        self.assertEqual(stat.S_IMODE(Path(self.receipt["evidence_file"]).stat().st_mode), 0o600)
        audit = retained["stages"]["audit"]
        self.assertTrue(audit["chain_valid"])
        refusals = [event["event"] for event in audit["events"] if event["event"]["ok"] is False]
        self.assertTrue(any(item["operation"] == "credential.request" and item["code"] == "CREDENTIAL_SCOPE" for item in refusals))
        self.assertTrue(any(item["operation"] == "candidate.accept" and item["code"] == "CHECK_FAILED" for item in refusals))
        self.assertTrue(any(item["code"] == "INPUT_STALE" for item in refusals))


if __name__ == "__main__":
    unittest.main()
