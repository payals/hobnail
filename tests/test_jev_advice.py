"""Optional advice mechanism checks; no model-quality or runtime qualification.

All model replies and keys below are synthetic. Network sockets are forbidden,
and transport stubs exercise only the adapter's boundaries and receipt behavior.
"""

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts import jev_advice


SYNTHETIC_KEY = "synthetic-test-key-never-a-real-credential"
EVIDENCE = {
    "claim": "The synthetic marker was created successfully.",
    "records": [
        {"source": "dispatcher", "action_id": "toy-1", "status": "acknowledged"},
        {"source": "independent observer", "action_id": "toy-1", "status": "unknown"},
    ],
}
CONTRACT = {
    "schema_version": 1,
    "description": "Synthetic independently checked report",
    "access": {"workers": ["worker"], "verifiers": ["verifier"],
               "observers": [], "adapters": {}},
    "subject": {"media_type": "application/json", "max_bytes": 4096},
    "sources": [{"name": "source", "registrars": ["registrar"], "require_current": True}],
    "checks": [{"id": "matches", "plugin": "json.equals", "plugin_digest": "a" * 64,
                "parameters": {"source": "source", "pairs": [{"artifact": "/value", "input": "/value"}]},
                "max_age_seconds": 60}],
    "actions": [],
    "budgets": {"verification": 10, "effects": 0},
    "expires_at": "2099-01-01T00:00:00Z",
}
CONTRACT_DOCUMENT = {
    "goal": "Produce a complete synthetic report while preserving existing behavior.",
    "contract": CONTRACT,
    "context": "Existing behavior: consumers can read the value field.",
}


def canonical_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def answer(choice="c", contract=False):
    options = "abcd" if contract else "abc"
    return {"type": "choice", "choice": choice,
            "probabilities": {key: 1.0 if key == choice else 0.0 for key in options},
            "confidence": 1.0}


def provider_response(kind="evidence"):
    questions = ["evidence"] if kind == "evidence" else [
        "integration", "behavior_preservation", "observed_outcomes", "independence"]
    return {"model": "typesafe/jev-1.13-20260917", "provider": "TypeSafe",
            "id": "synthetic-response", "answers": {
                key: answer(contract=kind == "contract") for key in questions},
            "usage": {"input_tokens": 100, "output_tokens": 40, "cost": 0.0000042}}


class Response(io.BytesIO):
    status = 200

    def getcode(self):
        return self.status


class JevAdviceTests(unittest.TestCase):
    def setUp(self):
        no_socket = patch("socket.socket", side_effect=AssertionError("network forbidden in advice tests"))
        no_socket.start()
        self.addCleanup(no_socket.stop)
        temporary = tempfile.TemporaryDirectory(prefix="hbn-jev-advice-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()

    def invoke(self, body=None, *, kind="evidence", exception=None, raw=None):
        document = copy.deepcopy(EVIDENCE if kind == "evidence" else CONTRACT_DOCUMENT)
        opener = Mock()
        if exception is not None:
            opener.open.side_effect = exception
        else:
            encoded = raw if raw is not None else json.dumps(
                provider_response(kind) if body is None else body).encode()
            opener.open.return_value = Response(encoded)
        with patch.object(jev_advice.urllib.request, "build_opener", return_value=opener) as build:
            receipt = jev_advice.run_advice(kind, document, live=True, api_key=SYNTHETIC_KEY)
        return receipt, opener, build

    def assert_advisory_only(self, receipt):
        self.assertTrue(receipt["advisory_only"])
        self.assertEqual(receipt["schema"], "hobnail-jev-advice-v1")
        for key in ("approved", "authorized", "accepted", "qualified", "passed", "complete"):
            self.assertNotIn(key, receipt)
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(receipt))

    def test_both_recipes_prepare_without_network_and_do_not_mutate_input(self):
        for kind, document in (("evidence", EVIDENCE), ("contract", CONTRACT_DOCUMENT)):
            original = copy.deepcopy(document)
            with self.subTest(kind=kind), patch.object(
                    jev_advice.urllib.request, "build_opener", side_effect=AssertionError("offline transport")):
                request = jev_advice.prepare_advice(kind, document)
                receipt = jev_advice.run_advice(kind, document)
            self.assertEqual(document, original)
            self.assertEqual(receipt["status"], "prepared")
            self.assertEqual(receipt["request"], request)
            self.assert_advisory_only(receipt)
            request["state"]["injected_after_prepare"] = True
            self.assertEqual(document, original)
        self.assertEqual(set(jev_advice.prepare_advice("evidence", EVIDENCE)["questions"]), {"evidence"})
        self.assertEqual(set(jev_advice.prepare_advice("contract", CONTRACT_DOCUMENT)["questions"]), {
            "integration", "behavior_preservation", "observed_outcomes", "independence"})

    def test_offline_ignores_existing_key_and_never_requests_authority(self):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": SYNTHETIC_KEY}), patch.object(
                jev_advice.urllib.request, "build_opener", side_effect=AssertionError("offline transport")):
            receipt = jev_advice.run_advice("evidence", EVIDENCE, api_key=SYNTHETIC_KEY)
        self.assertEqual(receipt["status"], "prepared")
        self.assertNotIn("answers", receipt)
        self.assert_advisory_only(receipt)

    def test_missing_or_invalid_live_key_refuses_without_network(self):
        for key in (None, "short", "invalid\nheader", 12):
            with self.subTest(key_type=type(key).__name__), patch.object(
                    jev_advice.urllib.request, "build_opener") as build:
                receipt = jev_advice.run_advice("evidence", EVIDENCE, live=True, api_key=key)
                build.assert_not_called()
            self.assertEqual(receipt["status"], "unavailable")
            self.assertNotIn("answers", receipt)
            self.assert_advisory_only(receipt)

    def test_key_embedded_in_input_is_neither_sent_nor_retained(self):
        document = copy.deepcopy(EVIDENCE)
        document["records"].append({"untrusted_text": SYNTHETIC_KEY})
        with patch.object(jev_advice.urllib.request, "build_opener") as build:
            receipt = jev_advice.run_advice("evidence", document, live=True, api_key=SYNTHETIC_KEY)
            build.assert_not_called()
        self.assertEqual(receipt["status"], "unavailable")
        self.assertTrue(receipt["advisory_only"])
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(receipt))
        self.assertNotIn("answers", receipt)

    def test_canonical_hashes_bind_input_request_and_rubric(self):
        document = copy.deepcopy(EVIDENCE)
        document["claim"] += " Café."
        receipt = jev_advice.run_advice("evidence", document)
        self.assertEqual(receipt["input_sha256"], canonical_digest(document))
        self.assertEqual(receipt["request_sha256"], canonical_digest(receipt["request"]))
        expected_rubric = {"id": receipt["rubric_id"],
                           "labels": {"a": "supported", "b": "contradicted", "c": "insufficient"},
                           "questions": receipt["request"]["questions"]}
        self.assertEqual(receipt["rubric_sha256"], canonical_digest(expected_rubric))
        reordered = {"records": document["records"], "claim": document["claim"]}
        again = jev_advice.run_advice("evidence", reordered)
        self.assertEqual(receipt["input_sha256"], again["input_sha256"])
        changed = copy.deepcopy(document)
        changed["records"][1]["status"] = "observed_success"
        different = jev_advice.run_advice("evidence", changed)
        self.assertNotEqual(receipt["input_sha256"], different["input_sha256"])
        self.assertNotEqual(receipt["request_sha256"], different["request_sha256"])

    def test_contract_recipe_runs_existing_structural_validation(self):
        for mutation in ("missing_checks", "unsupported_plugin", "approval_assertion"):
            document = copy.deepcopy(CONTRACT_DOCUMENT)
            if mutation == "missing_checks":
                document["contract"]["checks"] = []
            elif mutation == "unsupported_plugin":
                document["contract"]["checks"][0]["plugin"] = "shell.run"
            else:
                document["contract"]["approved"] = True
            with self.subTest(mutation=mutation), patch.object(
                    jev_advice.urllib.request, "build_opener") as build:
                with self.assertRaises(jev_advice.AdviceError):
                    jev_advice.run_advice("contract", document, live=True, api_key=SYNTHETIC_KEY)
                build.assert_not_called()

    def test_malformed_inputs_refuse_before_network(self):
        invalid = [("unknown", EVIDENCE), ("evidence", []), ("evidence", {"claim": "x"}),
                   ("evidence", {"claim": "", "records": []}),
                   ("evidence", {"claim": "x", "records": [], "endpoint": "https://example.invalid"}),
                   ("evidence", {"claim": "x", "records": [{"value": float("nan")}]}),
                   ("evidence", {"claim": "x" * 100000, "records": []}),
                   ("contract", {"contract": CONTRACT})]
        for kind, document in invalid:
            with self.subTest(kind=kind, shape=type(document).__name__), patch.object(
                    jev_advice.urllib.request, "build_opener") as build:
                with self.assertRaises(jev_advice.AdviceError):
                    jev_advice.run_advice(kind, document, live=True, api_key=SYNTHETIC_KEY)
                build.assert_not_called()

    def test_live_request_uses_fixed_endpoint_model_header_and_timeout(self):
        receipt, opener, build = self.invoke()
        self.assertEqual(receipt["status"], "advice")
        opener.open.assert_called_once()
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://openrouter.ai/api/alpha/decisions")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(json.loads(request.data)["model"], "typesafe/jev-1.13")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + SYNTHETIC_KEY)
        self.assertNotIn(SYNTHETIC_KEY.encode(), request.data)
        self.assertGreater(opener.open.call_args.kwargs["timeout"], 0)
        self.assertLessEqual(opener.open.call_args.kwargs["timeout"], 60)
        handlers = build.call_args.args
        self.assertTrue(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies == {} for h in handlers))
        self.assertTrue(any(isinstance(h, jev_advice._NoRedirect) for h in handlers))
        self.assert_advisory_only(receipt)

    def test_unknown_evidence_remains_insufficient_advice_without_pass_or_fail(self):
        receipt, _, _ = self.invoke()
        result = receipt["answers"]["evidence"]
        self.assertEqual(result["label"], "insufficient")
        self.assertEqual(result["choice"], "c")
        self.assertTrue(result["follow_up"])
        self.assert_advisory_only(receipt)
        self.assertEqual(receipt["request"]["state"]["records"][1]["status"], "unknown")

    def test_contract_answers_are_advice_and_leave_contract_bytes_unchanged(self):
        before = json.dumps(CONTRACT_DOCUMENT, sort_keys=True)
        receipt, _, _ = self.invoke(kind="contract")
        self.assertEqual(receipt["status"], "advice")
        self.assertEqual({a["label"] for a in receipt["answers"].values()}, {"unclear"})
        self.assertEqual(json.dumps(CONTRACT_DOCUMENT, sort_keys=True), before)
        self.assert_advisory_only(receipt)

    def test_response_shape_and_probability_failures_are_unavailable(self):
        mutations = {
            "missing_question": lambda b: b["answers"].pop("evidence"),
            "extra_question": lambda b: b["answers"].update(extra=answer()),
            "missing_choice": lambda b: b["answers"]["evidence"].pop("choice"),
            "unknown_choice": lambda b: b["answers"]["evidence"].update(choice="approved"),
            "wrong_type": lambda b: b["answers"]["evidence"].update(type="noul"),
            "missing_probability": lambda b: b["answers"]["evidence"]["probabilities"].pop("b"),
            "extra_probability": lambda b: b["answers"]["evidence"]["probabilities"].update(d=0),
            "nonfinite_probability": lambda b: b["answers"]["evidence"]["probabilities"].update(c=float("nan")),
            "negative_probability": lambda b: b["answers"]["evidence"]["probabilities"].update(a=-0.1),
            "probability_over_one": lambda b: b["answers"]["evidence"]["probabilities"].update(c=1.1),
            "string_probability": lambda b: b["answers"]["evidence"]["probabilities"].update(c="1.0"),
            "boolean_probability": lambda b: b["answers"]["evidence"]["probabilities"].update(c=True),
            "not_normalized": lambda b: b["answers"]["evidence"]["probabilities"].update(c=0.5),
            "not_argmax": lambda b: b["answers"]["evidence"].update(choice="a"),
            "missing_confidence": lambda b: b["answers"]["evidence"].pop("confidence"),
            "nonfinite_confidence": lambda b: b["answers"]["evidence"].update(confidence=float("inf")),
            "confidence_over_one": lambda b: b["answers"]["evidence"].update(confidence=1.1),
            "missing_model": lambda b: b.pop("model"),
            "invalid_model": lambda b: b.update(model=[]),
            "different_model": lambda b: b.update(model="typesafe/jev-1.12-20260901"),
            "missing_usage": lambda b: b.pop("usage"),
            "boolean_tokens": lambda b: b["usage"].update(input_tokens=True),
            "negative_cost": lambda b: b["usage"].update(cost=-1),
        }
        for name, mutate in mutations.items():
            body = provider_response()
            mutate(body)
            with self.subTest(mutation=name):
                receipt, opener, _ = self.invoke(body)
                self.assertEqual(receipt["status"], "unavailable")
                self.assertTrue(receipt["error_code"])
                self.assertNotIn("answers", receipt)
                opener.open.assert_called_once()
                self.assert_advisory_only(receipt)

    def test_malformed_duplicate_and_oversized_json_are_unavailable(self):
        normal = json.dumps(provider_response()).encode()
        duplicate = normal.replace(b'"model":', b'"model": "typesafe/other", "model":', 1)
        for raw in (b"not json", b"[]", duplicate, b" " * 262145):
            with self.subTest(size=len(raw)):
                receipt, opener, _ = self.invoke(raw=raw)
                self.assertEqual(receipt["status"], "unavailable")
                self.assertNotIn("answers", receipt)
                opener.open.assert_called_once()

    def test_http_and_timeout_failures_are_retained_without_retry_or_secret_echo(self):
        errors = [TimeoutError("raw-error " + SYNTHETIC_KEY),
                  urllib.error.URLError("raw-error " + SYNTHETIC_KEY),
                  urllib.error.HTTPError("https://example.invalid/" + SYNTHETIC_KEY,
                                         429, "raw-error " + SYNTHETIC_KEY,
                                         {}, io.BytesIO(SYNTHETIC_KEY.encode()))]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                receipt, opener, _ = self.invoke(exception=error)
                self.assertEqual(receipt["status"], "unavailable")
                self.assertTrue(receipt["error_code"])
                self.assertNotIn("raw-error", json.dumps(receipt))
                self.assertNotIn("answers", receipt)
                self.assert_advisory_only(receipt)
                opener.open.assert_called_once()

    def test_redirect_handler_refuses_even_same_origin_redirects(self):
        handler = jev_advice._NoRedirect()
        request = urllib.request.Request("https://openrouter.ai/api/alpha/decisions")
        for location in ("https://example.invalid/collector", "https://openrouter.ai/other"):
            with self.subTest(location=location):
                try:
                    result = handler.redirect_request(request, io.BytesIO(), 302,
                                                      "Found", {}, location)
                except urllib.error.HTTPError:
                    continue
                self.assertIsNone(result)

    def test_provider_cannot_echo_the_key_through_metadata(self):
        for field in ("provider", "id", "unexpected_metadata"):
            body = provider_response()
            body[field] = "echo:" + SYNTHETIC_KEY
            with self.subTest(field=field):
                receipt, opener, _ = self.invoke(body)
                self.assertEqual(receipt["status"], "unavailable")
                self.assert_advisory_only(receipt)
                opener.open.assert_called_once()

    def write_input(self, kind="evidence", raw=None):
        path = self.directory / "input.json"
        data = json.dumps(EVIDENCE if kind == "evidence" else CONTRACT_DOCUMENT).encode() if raw is None else raw
        path.write_bytes(data)
        return path, data

    def cli(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = jev_advice.main(args)
        self.assertNotIn(SYNTHETIC_KEY, stdout.getvalue() + stderr.getvalue())
        return code, stdout.getvalue(), stderr.getvalue()

    def test_cli_both_offline_recipes_produce_private_source_bound_receipts(self):
        for kind in ("evidence", "contract"):
            source, raw = self.write_input(kind)
            output = self.directory / (kind + ".json")
            with self.subTest(kind=kind), patch.object(
                    jev_advice.urllib.request, "build_opener", side_effect=AssertionError("offline transport")):
                code, stdout, _ = self.cli([kind, "--input", str(source), "--output", str(output)])
            self.assertEqual(code, 0)
            receipt = json.loads(output.read_text())
            self.assertEqual(receipt["status"], "prepared")
            self.assertEqual(receipt["source_input_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertNotIn(EVIDENCE["claim"], stdout)
            self.assert_advisory_only(receipt)

    def test_cli_refuses_existing_and_symlink_outputs_before_spend(self):
        source, _ = self.write_input()
        existing = self.directory / "existing.json"
        existing.write_bytes(b"preserve another session's receipt")
        link = self.directory / "link.json"
        link.symlink_to(existing)
        dangling = self.directory / "dangling.json"
        dangling.symlink_to(self.directory / "absent.json")
        for output in (existing, link, dangling):
            with self.subTest(output=output.name), patch.dict(
                    os.environ, {"OPENROUTER_API_KEY": SYNTHETIC_KEY}), patch.object(
                    jev_advice.urllib.request, "build_opener") as build:
                code, _, _ = self.cli(["evidence", "--input", str(source),
                                       "--output", str(output), "--live"])
                self.assertEqual(code, 2)
                build.assert_not_called()
            self.assertEqual(existing.read_bytes(), b"preserve another session's receipt")
        self.assertTrue(link.is_symlink())
        self.assertTrue(dangling.is_symlink())

    def test_cli_refuses_aliased_output_parent_before_spend(self):
        source, _ = self.write_input()
        actual = self.directory / "actual"
        actual.mkdir()
        alias = self.directory / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": SYNTHETIC_KEY}), patch.object(
                jev_advice.urllib.request, "build_opener") as build:
            code, _, _ = self.cli(["evidence", "--input", str(source),
                                   "--output", str(alias / "receipt.json"), "--live"])
        self.assertEqual(code, 2)
        build.assert_not_called()
        self.assertEqual(list(actual.iterdir()), [])

    def test_cli_input_alias_and_fifo_refuse_without_waiting_or_spending(self):
        source, _ = self.write_input()
        alias = self.directory / "input-link.json"
        alias.symlink_to(source)
        fifo = self.directory / "input-fifo"
        os.mkfifo(fifo, 0o600)
        for path in (alias, fifo):
            with self.subTest(path=path.name), patch.dict(
                    os.environ, {"OPENROUTER_API_KEY": SYNTHETIC_KEY}), patch.object(
                    jev_advice.urllib.request, "build_opener") as build:
                code, _, _ = self.cli(["evidence", "--input", str(path),
                                       "--output", str(self.directory / "blocked.json"), "--live"])
                self.assertEqual(code, 2)
                build.assert_not_called()
        self.assertFalse((self.directory / "blocked.json").exists())

    def test_cli_reserves_private_output_before_network_and_does_not_print_inputs(self):
        source, _ = self.write_input()
        output = self.directory / "live.json"
        opener = Mock()
        def request_once(*_args, **_kwargs):
            self.assertTrue(output.is_file())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            return Response(json.dumps(provider_response()).encode())
        opener.open.side_effect = request_once
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": SYNTHETIC_KEY}), patch.object(
                jev_advice.urllib.request, "build_opener", return_value=opener):
            code, stdout, stderr = self.cli(["evidence", "--input", str(source),
                                            "--output", str(output), "--live"])
        self.assertEqual(code, 0)
        opener.open.assert_called_once()
        self.assertNotIn(EVIDENCE["claim"], stdout + stderr)
        self.assertEqual(json.loads(output.read_text())["status"], "advice")
        self.assert_advisory_only(json.loads(output.read_text()))

    def test_cli_unavailable_receipt_survives_failed_call_and_cannot_be_overwritten(self):
        source, _ = self.write_input()
        output = self.directory / "failed.json"
        opener = Mock()
        opener.open.side_effect = TimeoutError(SYNTHETIC_KEY)
        args = ["evidence", "--input", str(source), "--output", str(output), "--live"]
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": SYNTHETIC_KEY}), patch.object(
                jev_advice.urllib.request, "build_opener", return_value=opener):
            code, _, _ = self.cli(args)
            self.assertEqual(code, 1)
            retained = output.read_bytes()
            self.assertEqual(json.loads(retained)["status"], "unavailable")
            again, _, _ = self.cli(args)
            self.assertEqual(again, 2)
        opener.open.assert_called_once()
        self.assertEqual(output.read_bytes(), retained)
        self.assert_advisory_only(json.loads(retained))

    def test_cli_duplicate_input_keys_refuse_before_spend(self):
        source, _ = self.write_input(raw=b'{"claim":"one","claim":"two","records":[]}')
        output = self.directory / "duplicate.json"
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": SYNTHETIC_KEY}), patch.object(
                jev_advice.urllib.request, "build_opener") as build:
            code, _, _ = self.cli(["evidence", "--input", str(source),
                                   "--output", str(output), "--live"])
        self.assertEqual(code, 2)
        build.assert_not_called()

    def test_both_recipes_cannot_instantiate_core_clients_or_run_commands(self):
        with patch("hobnail.client.Client", side_effect=AssertionError("core client forbidden")), patch(
                "subprocess.run", side_effect=AssertionError("commands forbidden")):
            for kind in ("evidence", "contract"):
                with self.subTest(kind=kind):
                    receipt, _, _ = self.invoke(kind=kind)
                    self.assertEqual(receipt["status"], "advice")
                    self.assert_advisory_only(receipt)


if __name__ == "__main__":
    unittest.main()
