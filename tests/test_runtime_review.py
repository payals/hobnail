"""Independent regressions for exact consequence and deterministic checks."""
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hobnail.effects import EffectBoundaryError, FileObserver, FilePublisher, dispatch_file
from hobnail.validators import evaluate


class RuntimeReviewTests(unittest.TestCase):
    def test_observer_refuses_inode_that_is_no_longer_the_target(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-observer-race-") as directory:
            root = Path(directory).resolve()
            content = b"accepted bytes"
            digest = hashlib.sha256(content).hexdigest()
            FilePublisher(root).publish("target", content, digest)
            replacement = root / "replacement"
            replacement.write_bytes(b"different work")
            actual_fstat = os.fstat
            observations = 0

            def replace_after_read(fd):
                nonlocal observations
                result = actual_fstat(fd)
                if stat.S_ISREG(result.st_mode):
                    observations += 1
                    if observations == 2:
                        os.replace(replacement, root / "target")
                return result

            with patch("hobnail.effects.os.fstat", side_effect=replace_after_read):
                observed = FileObserver(root).observe("target", digest)
            self.assertEqual((root / "target").read_bytes(), b"different work")
            self.assertEqual(observed["outcome"], "unknown")

    def test_unmatched_adapter_manifest_cannot_reach_dispatch(self):
        content = b"approved"
        calls = []

        class Client:
            def call(self, operation, payload):
                calls.append(operation)
                if operation == "effect.claim":
                    return {"ok": True, "status": "claimed", "event_id": 1, "data": {
                        "token": "token", "generation": 1, "target": "target", "args": {},
                        "artifact": {"content_hex": content.hex(), "digest": hashlib.sha256(content).hexdigest()},
                        "action": {"plugin": "file.publish", "manifest": {
                            "implementation": "0" * 64, "execution_backend": "unregistered-backend"}}}}
                return {"ok": True, "status": "ok", "event_id": 2, "data": {}}

        class Publisher:
            plugin_id = "file.publish"

            def publish(self, *args):
                return {"must_not_be_called": True}

        with self.assertRaises(EffectBoundaryError):
            dispatch_file(Client(), 1, Publisher())
        self.assertEqual(calls, ["effect.claim"])

    def test_json_comparison_does_not_round_unequal_decimal_values_into_a_pass(self):
        result = evaluate(b'{"n":0.10000000000000001}', "json.equals", {
            "source": "source", "pairs": [{"artifact": "/n", "input": "/n"}]},
            inputs={"source": b'{"n":0.1}'})
        self.assertEqual(result["result"], "fail")


if __name__ == "__main__":
    unittest.main()
