"""A developer-owned contract and arbitrary input names on the maintained runner."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.dev_cluster import DevCluster
from scripts.native_application import NativeApplication, NativeApplicationError
from hobnail.deployment import NativeConsumer


class NativeApplicationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hbn-app-output-", dir="/tmp")
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name).resolve()
        self.consumer = NativeConsumer.file(self.output)
        self.artifact = b'{"available":7,"label":"caller-owned report"}'
        self.source = b'{"stock":7}'

    def document(self, application):
        principals = application.principals
        return {"schema_version": 1, "description": "An application-owned warehouse report",
            "access": {"workers": [principals["worker"]], "verifiers": [principals["verifier"]],
                       "observers": [principals["observer"]], "adapters": {"release": [principals["adapter"]]}},
            "subject": {"media_type": "application/json", "max_bytes": 1048576},
            "sources": [{"name": "warehouse", "registrars": [principals["registrar"]], "require_current": True}],
            "checks": [{"id": "quantity", "plugin": "json.equals", "plugin_digest": application.plugin_digests["json.equals"],
                        "parameters": {"source": "warehouse", "pairs": [{"artifact": "/available", "input": "/stock"}]},
                        "max_age_seconds": 300}],
            "actions": [{"name": "release", "plugin": "file.publish", "plugin_digest": application.plugin_digests["file.publish"],
                         "target": "warehouse-report.json", "arguments": {}, "max_age_seconds": 300}],
            "budgets": {"verification": 2, "effects": 1}, "expires_at": "2099-01-01T00:00:00Z"}

    def assert_retired(self, application):
        receipt = application.receipt
        self.assertTrue(receipt["runtime_stopped"], receipt)
        self.assertTrue(receipt["checks"]["all_runtime_credentials_revoked"], receipt)
        self.assertTrue(receipt["checks"]["generated_credentials_absent_from_receipt_and_log"], receipt)
        self.assertFalse(DevCluster.from_path(receipt["retained_root"]).is_running())
        self.assertEqual(receipt, json.loads(Path(receipt["receipt"]).read_text()))
        for stage in receipt["stages"]:
            self.assertNotEqual(stage["state"], "started", stage)
        with self.assertRaises(NativeApplicationError):
            application.worker_client

    def test_caller_contract_arbitrary_source_and_exact_observed_publication(self):
        app = NativeApplication("warehouse-workflow", self.consumer, sources=("warehouse",))
        with app:
            document = self.document(app)
            original = copy.deepcopy(document)
            worker_denial = app.worker_client.call("contract.activate", {
                "contract_id": "warehouse-workflow", "version": 1, "expected_active_version": None})
            self.assertFalse(worker_denial["ok"])
            self.assertEqual(worker_denial["code"], "FORBIDDEN")
            approval = app.approve(document)
            self.assertTrue(approval["ok"], approval)
            receipt = app.run(document=document, inputs={"warehouse": self.source}, artifact=self.artifact, action="release")
            self.assertEqual(receipt["status"], "completed", receipt)
            self.assertEqual(document, original)
            self.assertFalse(receipt["qualified"])
            stages = {stage["stage"]: stage for stage in receipt["stages"]}
            self.assertEqual(stages["register_input:warehouse"]["result"]["data"]["digest"], hashlib.sha256(self.source).hexdigest())
            self.assertEqual(stages["register_artifact"]["result"]["data"]["digest"], hashlib.sha256(self.artifact).hexdigest())
            self.assertEqual(stages["independent_observation"]["result"]["data"]["state"], "complete")
            self.assertEqual(receipt["approved_policy_digest"], approval["data"]["policy_digest"])
        self.assert_retired(app)
        self.assertEqual((self.output / "warehouse-report.json").read_bytes(), self.artifact)

    def test_run_requires_explicit_owner_approval(self):
        with NativeApplication("unapproved-workflow", self.consumer, sources=("warehouse",)) as app:
            receipt = app.run(document=self.document(app), inputs={"warehouse": self.source}, artifact=self.artifact, action="release")
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["failure"]["code"], "OWNER_APPROVAL_REQUIRED")
            self.assertFalse(any(stage["stage"] == "register_artifact" for stage in receipt["stages"]))
        self.assert_retired(app)
        self.assertFalse((self.output / "warehouse-report.json").exists())

    def test_mutating_caller_document_after_approval_does_not_mutate_approved_policy(self):
        with NativeApplication("immutable-owner-contract", self.consumer, sources=("warehouse",)) as app:
            document = self.document(app)
            app.approve(document)
            document["budgets"]["effects"] = 999
            receipt = app.run(document=document, inputs={"warehouse": self.source}, artifact=self.artifact, action="release")
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["failure"]["code"], "APPROVED_CONTRACT_CHANGED")
            self.assertFalse(any(stage["stage"] == "register_artifact" for stage in receipt["stages"]))
        self.assert_retired(app)
        self.assertFalse((self.output / "warehouse-report.json").exists())

    def test_custom_mandatory_plugin_refuses_before_policy_proposal(self):
        with NativeApplication("unsupported-custom", self.consumer, sources=("warehouse",)) as app:
            document = self.document(app)
            document["checks"][0].update(plugin="custom:owner-check", plugin_digest="a" * 64, parameters={})
            with self.assertRaises(NativeApplicationError) as caught:
                app.approve(document)
            self.assertEqual(caught.exception.code, "UNSUPPORTED_CAPABILITY")
            self.assertFalse(any(stage["stage"] == "propose_owner_contract" for stage in app.receipt["stages"]))
        self.assert_retired(app)
        self.assertEqual(app.receipt["status"], "failed")

    def test_changed_input_names_and_bad_content_cannot_publish(self):
        with NativeApplication("invalid-source-set", self.consumer, sources=("warehouse",)) as app:
            document = self.document(app)
            app.approve(document)
            receipt = app.run(document=document, inputs={"orders": self.source}, artifact=self.artifact, action="release")
            self.assertEqual(receipt["failure"]["code"], "INVALID_APPLICATION_BYTES")
        self.assert_retired(app)
        self.assertFalse((self.output / "warehouse-report.json").exists())
        with NativeApplication("failed-quantity", self.consumer, sources=("warehouse",)) as refused:
            document = self.document(refused)
            refused.approve(document)
            receipt = refused.run(document=document, inputs={"warehouse": self.source}, artifact=b'{"available":99}', action="release")
            self.assertEqual(receipt["status"], "refused", receipt)
            failure = next(stage for stage in receipt["stages"] if stage["stage"] == "independent_verification")
            self.assertEqual(failure["result"]["code"], "CHECK_FAILED")
            self.assertFalse(any(stage["stage"] == "reserve_effect" for stage in receipt["stages"]))
        self.assert_retired(refused)
        self.assertFalse((self.output / "warehouse-report.json").exists())

    def test_failure_preserves_stage_retires_roles_and_never_exports_exception_secret(self):
        with NativeApplication("controlled-failure", self.consumer, sources=("warehouse",)) as app:
            document = self.document(app)
            app.approve(document)
            generated = app._leases[0].password.reveal()
            with patch("scripts.native_application.verify_candidate", side_effect=RuntimeError(generated)):
                receipt = app.run(document=document, inputs={"warehouse": self.source}, artifact=self.artifact, action="release")
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["failure"], {"stage": "independent_verification", "kind": "RuntimeError"})
            self.assertFalse(generated in canonical_receipt(receipt))
        self.assert_retired(app)
        self.assertFalse(generated in Path(app.receipt["receipt"]).read_text())
        self.assertFalse((self.output / "warehouse-report.json").exists())

    def test_observed_mismatch_remains_control_failure_instead_of_uncertainty(self):
        with NativeApplication("observed-control-failure", self.consumer, sources=("warehouse",)) as app:
            document = self.document(app)
            app.approve(document)
            observer = app._endpoints["observer"]
            observe = observer.observe

            def change_owned_target_before_observation(effect_id):
                (self.output / "warehouse-report.json").write_bytes(b'{"available":999}')
                return observe(effect_id)

            with patch.object(observer, "observe", side_effect=change_owned_target_before_observation):
                receipt = app.run(document=document, inputs={"warehouse": self.source}, artifact=self.artifact, action="release")
            self.assertEqual(receipt["status"], "control_failure", receipt)
            self.assertEqual(receipt["effect_state"], "control_failure")
            stage = next(item for item in receipt["stages"] if item["stage"] == "independent_observation")
            self.assertEqual(stage["result"]["data"]["state"], "control_failure")
        self.assert_retired(app)
        self.assertEqual((self.output / "warehouse-report.json").read_bytes(), b'{"available":999}')

    def test_both_receipt_write_failures_preserve_primary_caller_failure(self):
        app = NativeApplication("double-persistence-failure", self.consumer, sources=("warehouse",))
        (self.output / "server.log").write_text("synthetic log without credentials")
        app._cluster = SimpleNamespace(root=self.output, is_running=lambda: False, _check_owner=lambda: None)
        original = ValueError("controlled caller failure")
        with patch.object(app, "_persist", side_effect=OSError("controlled storage failure")) as persist:
            self.assertIs(app.__exit__(ValueError, original, None), False)
        self.assertEqual(persist.call_count, 2)
        self.assertEqual(app.receipt["failure"], {"stage": "caller", "kind": "ValueError"})
        self.assertEqual(app.receipt["status"], "failed")
        self.assertIsNone(app.receipt["receipt"])
        self.assertEqual({item["stage"] for item in app.receipt["cleanup_failures"]},
                         {"receipt_persistence", "fallback_receipt_persistence"})


def canonical_receipt(receipt):
    return json.dumps(receipt, sort_keys=True)


if __name__ == "__main__":
    unittest.main()
