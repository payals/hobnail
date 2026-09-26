import base64
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hobnail.client import Client, Connection, Denied, ProtocolError, PsqlTransport, TransportError, TransportTimeout, parse_json
from hobnail.cli import main


SUCCESS = {"ok": True, "status": "submitted", "data": {"candidate_id": 1}, "event_id": 1}
REFUSAL = {"ok": False, "status": "denied", "code": "MISSING_CHECKS", "detail": {"checks": ["a"]}, "event_id": 2}


class TransportTests(unittest.TestCase):
    def transport(self, **kwargs):
        connection = Connection(host="127.0.0.1", database="test", user="worker", password="runtime-secret", sslmode="disable")
        with patch("hobnail.client.shutil.which", return_value="/installed/psql"):
            return PsqlTransport(connection, **kwargs)

    def run_result(self, value=SUCCESS, returncode=0):
        return subprocess.CompletedProcess([], returncode, json.dumps(value), "sensitive server diagnostic")

    def test_untrusted_operation_and_payload_only_become_encoded_stdin_data(self):
        operation = "evil'); DROP TABLE all; -- \\! stolen\n"
        payload = {"text": "'); SELECT pg_read_file('/private'); \\! echo stolen\n☃"}
        with patch("hobnail.client.subprocess.run", return_value=self.run_result()) as run:
            result = self.transport().call(operation, payload)
        self.assertEqual(result, SUCCESS)
        args = run.call_args.args[0]
        kwargs = run.call_args.kwargs
        self.assertNotIn("shell", kwargs)
        self.assertIn("-X", args)
        self.assertIn("-w", args)
        self.assertNotIn("runtime-secret", str(args))
        self.assertNotIn(payload["text"], kwargs["input"])
        self.assertNotIn(operation, kwargs["input"])
        encoded = re.findall(r"decode\('([A-Za-z0-9+/=]*)','base64'\)", kwargs["input"])
        self.assertEqual(base64.b64decode(encoded[0]).decode(), operation)
        self.assertEqual(json.loads(base64.b64decode(encoded[1])), payload)
        self.assertEqual(kwargs["input"].count(";"), 1)
        self.assertEqual(kwargs["env"]["PGPASSWORD"], "runtime-secret")
        self.assertEqual(kwargs["env"]["PGPASSFILE"], os.devnull)
        self.assertEqual(kwargs["env"]["PGSERVICEFILE"], os.devnull)
        self.assertNotIn("HOME", kwargs["env"])
        self.assertNotIn("PGOPTIONS", kwargs["env"])
        self.assertNotIn("PGSERVICE", kwargs["env"])
        self.assertNotIn("DATABASE_URL", kwargs["env"])
        self.assertIn("passfile='/dev/null'", args[-1])

    def test_libpq_connection_values_are_quoted_not_connection_strings(self):
        connection = Connection(host="127.0.0.1", database="x' password='injected", user="worker", sslmode="disable")
        with patch("hobnail.client.shutil.which", return_value="/installed/psql"):
            transport = PsqlTransport(connection)
        with patch("hobnail.client.subprocess.run", return_value=self.run_result()) as run:
            transport.call("candidate.get", {"candidate_id": 1})
        conninfo = run.call_args.args[0][-1]
        self.assertIn("dbname='x\\' password=\\'injected'", conninfo)
        self.assertNotIn("password='injected'", conninfo)

    def test_password_is_not_in_connection_repr(self):
        self.assertNotIn("runtime-secret", repr(self.transport().connection))

    def test_timeout_preserves_unknown_outcome_and_does_not_retry(self):
        error = subprocess.TimeoutExpired(["/installed/psql"], 1, output="secret-output", stderr="secret-error")
        with patch("hobnail.client.subprocess.run", side_effect=error) as run:
            with self.assertRaises(TransportTimeout) as caught:
                self.transport(timeout=1).call("effect.dispatch", {"effect_id": 1})
        self.assertEqual(run.call_count, 1)
        self.assertIn("unknown", str(caught.exception))
        self.assertNotIn("secret", str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)

    def test_sql_or_connection_failure_is_not_a_recorded_denial(self):
        with patch("hobnail.client.subprocess.run", return_value=self.run_result(returncode=3)):
            with self.assertRaises(TransportError) as caught:
                self.transport().call("artifact.put", {})
        self.assertNotIn("sensitive", str(caught.exception))

    def test_denial_is_returned_normally_or_raised_explicitly(self):
        with patch("hobnail.client.subprocess.run", return_value=self.run_result(REFUSAL)):
            client = Client(self.transport())
            self.assertEqual(client.call("candidate.accept", {"candidate_id": 1}), REFUSAL)
            with self.assertRaises(Denied) as caught:
                client.require("candidate.accept", {"candidate_id": 1})
        self.assertEqual(caught.exception.response, REFUSAL)

    def test_malformed_multirow_duplicate_and_nonfinite_output_refuse(self):
        malformed = ["", "{}", "null", "true", '{"ok":true,"ok":false}', json.dumps(SUCCESS) + "\n" + json.dumps(SUCCESS),
                     '{"ok":true,"status":"yes","data":NaN,"event_id":1}']
        for value in malformed:
            with self.subTest(value=value):
                result = subprocess.CompletedProcess([], 0, value, "")
                with patch("hobnail.client.subprocess.run", return_value=result):
                    with self.assertRaises(ProtocolError):
                        self.transport().call("candidate.get", {})

    def test_non_json_input_does_not_start_process(self):
        with patch("hobnail.client.subprocess.run") as run:
            with self.assertRaises(ValueError):
                self.transport().call("candidate.get", {"candidate_id": float("nan")})
        run.assert_not_called()

    def test_verify_full_requires_explicit_root(self):
        with self.assertRaises(ValueError):
            Connection(host="db.example", database="test", user="worker", sslmode="verify-full")

    def test_invalid_timeout_and_port_rejected(self):
        for timeout in (-1, 0, float("inf"), float("nan"), True):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.transport(timeout=timeout)
        with self.assertRaises(ValueError):
            Connection(host="localhost", database="test", user="worker", port=True)

    def test_trusted_sql_is_stdin_only_and_returns_text(self):
        secret_sql = "SELECT 'internal-only';\n"
        result = subprocess.CompletedProcess([], 0, "value\n", "")
        with patch("hobnail.client.subprocess.run", return_value=result) as run:
            self.assertEqual(self.transport().execute_sql(secret_sql, sensitive=True), "value\n")
        self.assertEqual(run.call_args.kwargs["input"], secret_sql)
        self.assertNotIn(secret_sql, run.call_args.args[0])


class CliTests(unittest.TestCase):
    def test_bad_input_returns_machine_readable_error(self):
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO('{"secret":NaN}')), patch("sys.stdout", output):
            code = main(["validate"])
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(output.getvalue())["code"], "INVALID_REQUEST")
        self.assertNotIn("secret", output.getvalue())

    def test_discovery_does_not_activate_and_uses_only_supplied_bytes(self):
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO(json.dumps({"artifact_hex": b'{"a":1}'.hex()}))), patch("sys.stdout", output):
            code = main(["discover"])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(output.getvalue())["authoritative"])

    def test_unknown_argument_returns_json(self):
        output = io.StringIO()
        with patch("sys.stdout", output):
            code = main(["call", "x", "--password", "secret"])
        self.assertEqual(code, 4)
        self.assertNotIn("secret", output.getvalue())

    def test_numeric_overflow_cannot_enter_response_or_contract(self):
        for value in ("1e999", "-1e999", '{"nested":[1e999]}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_json(value)

    def test_number_precision_is_never_silently_changed(self):
        with self.assertRaises(ValueError):
            parse_json('{"n":0.10000000000000001}')
        self.assertEqual(parse_json('{"n":0.1}'), {"n": 0.1})
        self.assertEqual(parse_json('{"n":1e-10}'), {"n": 1e-10})

    def test_recorded_envelopes_require_positive_integer_event_id(self):
        for event_id in (None, "1", 0, -1, True):
            result = dict(SUCCESS, event_id=event_id)
            with self.subTest(event_id=event_id), patch("hobnail.client.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(result), "")):
                with self.assertRaises(ProtocolError):
                    TransportTests().transport().call("candidate.get", {})

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            parse_json('{"a":1,"a":2}')


if __name__ == "__main__":
    unittest.main()
