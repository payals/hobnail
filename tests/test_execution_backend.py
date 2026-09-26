"""Explicit trusted backend selection preserves verifier authority semantics."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from hobnail.isolation import ChildResult, IsolationUnavailable, implementation_snapshot
from hobnail.validators import evaluate, implementation_digest
from hobnail.verifier import verify_candidate


class ExecutionBackendTests(unittest.TestCase):
    def test_explicit_backend_is_used_without_native_fallback(self):
        runner = Mock(return_value=ChildResult(0, '{"result":"pass","detail":{}}', ""))
        with patch("hobnail.validators.run_implementation", side_effect=AssertionError("native fallback")):
            result = evaluate(b'{"v":1}', "json.required_fields", {"pointers": ["/v"]}, implementation_runner=runner)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(runner.call_count, 1)
        source, digest, payload = runner.call_args.args
        self.assertEqual(source.name, "_validator_worker.py")
        self.assertEqual(digest, implementation_digest())
        self.assertEqual(json.loads(payload)["content_hex"], b'{"v":1}'.hex())

    def test_unavailable_backend_and_invalid_result_do_not_fall_back_or_pass(self):
        for runner, expected in (
            ("candidate-selected-backend", "inconclusive"),
            (Mock(side_effect=IsolationUnavailable("controlled backend refusal")), "inconclusive"),
            (Mock(return_value=ChildResult(0, '{"result":"pass","detail":{},"extra":true}', "")), "error")):
            with self.subTest(expected=expected), patch("hobnail.validators.run_implementation", side_effect=AssertionError("fallback")):
                self.assertEqual(evaluate(b"{}", "json.required_fields", {"pointers": []}, implementation_runner=runner)["result"], expected)

    def test_shared_snapshot_binds_exact_bytes_and_refuses_alias_and_digest_change(self):
        with tempfile.TemporaryDirectory(prefix="hbn-backend-", dir="/tmp") as directory:
            root = Path(directory).resolve(); source = root / "implementation.py"
            content = b'print("owned source")\n'; source.write_bytes(content); source.chmod(0o600)
            digest = hashlib.sha256(content).hexdigest()
            with implementation_snapshot(source, digest) as snapshot:
                self.assertNotEqual(snapshot, source)
                self.assertEqual(snapshot.read_bytes(), content)
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o400)
                source.write_bytes(b'print("changed")\n')
                self.assertEqual(snapshot.read_bytes(), content)
            self.assertFalse(snapshot.exists())
            with self.assertRaises(IsolationUnavailable), implementation_snapshot(source, digest):
                pass
            alias = root / "alias.py"; alias.symlink_to(source)
            with self.assertRaises(IsolationUnavailable), implementation_snapshot(alias, hashlib.sha256(source.read_bytes()).hexdigest()):
                pass

    def test_verifier_retains_claim_identity_record_and_database_acceptance(self):
        content = b'{"v":1}'; digest = hashlib.sha256(content).hexdigest()
        claim = {"artifact": {"content_hex": content.hex(), "digest": digest}, "inputs": {},
            "token": "controlled-lease", "generation": 7, "binding_digest": "a" * 64,
            "checks": [{"id": "shape", "plugin": "json.required_fields", "parameters": {"pointers": ["/v"]},
                        "plugin_digest": "b" * 64, "manifest": {"implementation": implementation_digest(), "execution_backend": "isolated-json"}}]}
        client = Mock(); client.call.side_effect = [
            {"ok": True, "data": claim}, {"ok": True}, {"ok": False, "code": "INPUT_STALE"}]
        runner = Mock(return_value=ChildResult(0, '{"result":"pass","detail":{}}', ""))
        self.assertEqual(verify_candidate(client, 17, implementation_runner=runner), {"ok": False, "code": "INPUT_STALE"})
        operation, payload = client.call.call_args_list[1].args
        self.assertEqual(operation, "verification.record")
        self.assertEqual((payload["token"], payload["generation"], payload["binding_digest"]), ("controlled-lease", 7, "a" * 64))
        self.assertEqual(client.call.call_args_list[2].args, ("candidate.accept", {"candidate_id": 17}))
        self.assertEqual(runner.call_count, 1)


if __name__ == "__main__":
    unittest.main()
