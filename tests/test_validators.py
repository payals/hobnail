import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hobnail.isolation import run_restricted
from hobnail.validators import evaluate


class ValidatorTests(unittest.TestCase):
    def test_exact_content_and_required_fields(self):
        content = b'{"ok":true}'
        self.assertEqual("pass", evaluate(content, "bytes.sha256", {
            "expected": hashlib.sha256(content).hexdigest()})["result"])
        self.assertEqual("fail", evaluate(content + b" ", "bytes.sha256", {
            "expected": hashlib.sha256(content).hexdigest()})["result"])
        self.assertEqual("pass", evaluate(content, "json.required_fields", {"pointers": ["/ok"]})["result"])
        self.assertEqual("fail", evaluate(content, "json.required_fields", {"pointers": ["/missing"]})["result"])

    def test_bad_json_and_unknown_plugin_do_not_pass(self):
        self.assertEqual("error", evaluate(b"not json", "json.required_fields", {"pointers": ["/x"]})["result"])
        self.assertEqual("inconclusive", evaluate(b"", "candidate.python", {})["result"])
        self.assertEqual("fail", evaluate(b'{"ok":true}', "json.equals", {
            "source": "source", "pairs": [{"artifact": "/ok", "input": "/ok"}]},
            inputs={"source": b'{"ok":1}'})["result"])

    def test_json_pointer_and_strict_parse(self):
        self.assertEqual("pass", evaluate(b'{"a/b":[null]}', "json.required_fields", {
            "pointers": ["/a~1b/0"]})["result"])
        self.assertEqual("pass", evaluate(b'{"n":1.0}', "json.equals", {
            "source": "source", "pairs": [{"artifact": "/n", "input": "/n"}]},
            inputs={"source": b'{"n":1}'})["result"])
        for malformed in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}'):
            self.assertEqual("error", evaluate(malformed, "json.required_fields", {
                "pointers": ["/x"]})["result"])

    def test_custom_plugin_requires_registered_exact_implementation_and_strict_result(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-plugin-check-") as directory:
            script = Path(directory).resolve() / "reviewed.py"
            script.write_text(
                "import json, sys\n"
                "r=json.load(sys.stdin)\n"
                "print(json.dumps({'result':'pass' if bytes.fromhex(r['content_hex']) == b'expected' "
                "else 'fail','detail':{'check':'exact_bytes'}}))\n")
            script.chmod(0o600)
            digest = hashlib.sha256(script.read_bytes()).hexdigest()
            self.assertEqual("inconclusive", evaluate(b"expected", "custom:exact", {},
                expected_implementation=digest)["result"])
            self.assertEqual("pass", evaluate(b"expected", "custom:exact", {},
                expected_implementation=digest, plugins={digest: script})["result"])
            self.assertEqual("fail", evaluate(b"changed", "custom:exact", {},
                expected_implementation=digest, plugins={digest: script})["result"])
            script.write_text("print('{\"result\":\"fail\",\"result\":\"pass\",\"detail\":{}}')\n")
            self.assertEqual("inconclusive", evaluate(b"expected", "custom:exact", {},
                expected_implementation=digest, plugins={digest: script})["result"])
            changed_digest = hashlib.sha256(script.read_bytes()).hexdigest()
            self.assertEqual("error", evaluate(b"expected", "custom:exact", {},
                expected_implementation=changed_digest, plugins={changed_digest: script})["result"])

    def test_child_cannot_read_ungranted_file_write_outside_or_connect_socket(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-denial-probe-") as directory:
            root = Path(directory)
            secret = root / "synthetic.txt"
            secret.write_text("synthetic-only")
            output = root / "forbidden.txt"
            script = root / "probe.py"
            script.write_text(
                "import json, pathlib, socket\n"
                "results = {}\n"
                f"for name, op in [('read', lambda: pathlib.Path({str(secret)!r}).read_text()), "
                f"('write', lambda: pathlib.Path({str(output)!r}).write_text('bad')), "
                "('network', lambda: socket.create_connection(('127.0.0.1', 9), timeout=1))]:\n"
                " try: op(); results[name] = False\n"
                " except PermissionError: results[name] = True\n"
                "print(json.dumps(results))\n")
            result = run_restricted(script, "")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual({"read": True, "write": True, "network": True}, json.loads(result.stdout))
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
