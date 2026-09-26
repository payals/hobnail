"""Actual SDK/controller/custom-plugin path, independent of test-authored verdicts."""

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

from kernel_support import KernelCase, ROOT

sys.path.insert(0, str(ROOT / "src"))
from hobnail.client import Client, Connection, PsqlTransport
from hobnail.verifier import verify_candidate


class RuntimePipelineTests(KernelCase):
    def test_registered_custom_plugin_requires_protected_implementation_map(self):
        def client(role):
            return Client(PsqlTransport(Connection(str(self.cluster.socket_dir), self.cluster.database,
                self.logins[role][0], sslmode="disable"), psql=str(self.cluster.bin_dir / "psql")))

        with tempfile.TemporaryDirectory(prefix="hobnail-custom-pipeline-") as directory:
            script = Path(directory).resolve() / "check.py"
            script.write_text("import json,sys\nr=json.load(sys.stdin)\n"
                              "content=json.loads(bytes.fromhex(r['content_hex']))\n"
                              "print(json.dumps({'result':'pass' if content['orders']==2 else 'fail',"
                              "'detail':{'check':'orders'}}))\n")
            script.chmod(0o600)
            digest = hashlib.sha256(script.read_bytes()).hexdigest()
            plugin = client("approver").require("plugin.register", {
                "plugin_id": "custom:orders", "version": 1, "kind": "validator",
                "manifest": {"implementation": digest, "input_media_types": ["application/json"],
                    "parameters": {}, "capabilities": ["read_artifact"],
                    "result_semantics": "independent deterministic domain check", "execution_backend": "isolated-json"}})
            self.document["checks"].append({"id": "custom", "plugin": "custom:orders",
                "plugin_digest": plugin["data"]["plugin_digest"], "parameters": {}, "max_age_seconds": 300})
            client("worker").require("contract.propose", {"contract_id": self.cid, "version": 2,
                                                          "document": self.document})
            client("approver").require("contract.activate", {"contract_id": self.cid, "version": 2,
                "expected_active_version": 1})
            first = self.submit("unconfigured")
            result = verify_candidate(client("verifier"), first["candidate_id"])
            self.assertFalse(result["ok"])
            self.assertEqual("CHECK_FAILED", result["code"])
            state = self.ok("worker", "candidate.get", {"candidate_id": first["candidate_id"]})
            self.assertEqual("inconclusive", next(r["result"] for r in state["results"] if r["check_id"] == "custom"))
            second = self.submit("configured")
            result = verify_candidate(client("verifier"), second["candidate_id"], plugins={digest: script})
            self.assertTrue(result["ok"], result)
            self.assertEqual("accepted", result["status"])


if __name__ == "__main__":
    unittest.main()
