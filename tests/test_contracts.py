import copy
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hobnail.contracts import ContractError, coverage_report, discover, validate_contract


def contract():
    return {
        "schema_version": 1,
        "description": "An independently checked report",
        "access": {"workers": ["worker"], "verifiers": ["verifier"], "observers": ["observer"], "adapters": {"publish": ["adapter"]}},
        "subject": {"media_type": "application/json", "max_bytes": 1048576},
        "sources": [{"name": "orders", "registrars": ["registrar"], "require_current": True}],
        "checks": [{"id": "metrics", "plugin": "json.equals", "plugin_digest": "a" * 64,
                    "parameters": {"source": "orders", "pairs": [{"artifact": "/orders", "input": "/orders"}]}, "max_age_seconds": 60}],
        "actions": [{"name": "publish", "plugin": "file.publish", "plugin_digest": "b" * 64,
                     "target": "reports/current.json", "arguments": {}, "max_age_seconds": 60}],
        "budgets": {"verification": 10, "effects": 5, "research": 10},
        "expires_at": "2099-01-01T00:00:00Z",
    }


class ContractTests(unittest.TestCase):
    def test_expiry_uses_the_kernel_canonical_utc_wire_format(self):
        for expiry in ("2099-01-01T00:00:00Z", "2099-01-01T00:00:00.123456Z"):
            doc = contract(); doc["expires_at"] = expiry
            self.assertEqual(validate_contract(doc)["expires_at"], expiry)
        for expiry in ("2099-01-01T00:00:00+00:00", "2099-01-01T00:00:00-00:00",
                       "2099-01-01T00:00:00.1234567Z", "2099-01-01 00:00:00Z"):
            doc = contract(); doc["expires_at"] = expiry
            with self.subTest(expiry=expiry), self.assertRaises(ContractError):
                validate_contract(doc)

    def test_valid_contract_roundtrip_is_independent_and_does_not_claim_approval(self):
        original = contract()
        result = validate_contract(original, for_activation=True)
        self.assertEqual(result, original)
        result["access"]["workers"].append("someone-else")
        self.assertEqual(original["access"]["workers"], ["worker"])
        coverage = coverage_report(original)
        self.assertTrue(coverage["supported"])
        self.assertFalse(coverage["qualified"])
        self.assertTrue(any(item["status"] == "external" for item in coverage["requirements"]))

    def test_unknown_mandatory_plugin_refuses_and_coverage_preserves_failure(self):
        doc = contract()
        doc["checks"][0]["plugin"] = "shell.run"
        doc["checks"][0]["parameters"] = {"command": "do-not-run"}
        with self.assertRaises(ContractError) as caught:
            validate_contract(doc)
        self.assertEqual(caught.exception.code, "UNSUPPORTED_CAPABILITY")
        coverage = coverage_report(doc)
        self.assertFalse(coverage["supported"])
        self.assertEqual(coverage["requirements"][0]["status"], "unsupported")

    def test_closed_shapes_reject_llm_or_user_safety_assertions(self):
        for key in ("approved", "isolation", "safe", "ignore_previous", "instructions"):
            doc = contract()
            doc[key] = True
            with self.subTest(key=key), self.assertRaises(ContractError):
                validate_contract(doc)
        doc = contract()
        doc["checks"][0]["advisory"] = True
        with self.assertRaises(ContractError):
            validate_contract(doc)

    def test_missing_empty_and_duplicate_checks_refuse(self):
        for checks in ([], None):
            doc = contract()
            doc["checks"] = checks
            with self.subTest(checks=checks), self.assertRaises(ContractError):
                validate_contract(doc)
        doc = contract()
        doc["checks"].append(copy.deepcopy(doc["checks"][0]))
        with self.assertRaises(ContractError):
            validate_contract(doc)

    def test_bool_and_float_are_not_integer_budget(self):
        for invalid in (True, 1.0, -1, 1000000001, None):
            doc = contract()
            doc["budgets"]["verification"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ContractError):
                validate_contract(doc)

    def test_nonfinite_json_and_missing_source_refuse(self):
        doc = contract()
        doc["budgets"]["research"] = float("inf")
        with self.assertRaises(ContractError):
            validate_contract(doc)
        doc = contract()
        doc["checks"][0]["parameters"]["source"] = "unknown"
        with self.assertRaises(ContractError):
            validate_contract(doc)

    def test_invalid_pointer_escapes_and_duplicates_refuse(self):
        for pointers in (["x"], ["/~"], ["/~2"], ["/a", "/a"]):
            doc = contract()
            doc["checks"][0]["plugin"] = "json.required_fields"
            doc["checks"][0]["parameters"] = {"pointers": pointers}
            with self.subTest(pointers=pointers), self.assertRaises(ContractError):
                validate_contract(doc)
        doc["checks"][0]["parameters"] = {"pointers": ["", "/a~1b", "/~0"]}
        validate_contract(doc)

    def test_path_escape_and_arguments_are_not_approved_actions(self):
        for target in ("/tmp/file", "../file", "x/../../file", "x//file", "x/./file", "x\\file"):
            doc = contract()
            doc["actions"][0]["target"] = target
            with self.subTest(target=target), self.assertRaises(ContractError):
                validate_contract(doc)
        doc = contract()
        doc["actions"][0]["arguments"] = {"command": "extra behavior"}
        with self.assertRaises(ContractError):
            validate_contract(doc)

    def test_pointer_and_target_limits_count_utf8_bytes(self):
        doc = contract()
        doc["checks"][0]["parameters"]["pairs"][0]["artifact"] = "/" + "é" * 1024
        with self.assertRaises(ContractError):
            validate_contract(doc)
        doc = contract()
        doc["actions"][0]["target"] = "é" * 513
        with self.assertRaises(ContractError):
            validate_contract(doc)

    def test_activation_checks_expiry_without_preventing_historical_inspection(self):
        doc = contract()
        doc["expires_at"] = "2020-01-01T00:00:00Z"
        validate_contract(doc)
        with self.assertRaises(ContractError):
            validate_contract(doc, for_activation=True, now=datetime(2021, 1, 1, tzinfo=timezone.utc))
        doc["expires_at"] = "2099-01-01T00:00:00"
        with self.assertRaises(ContractError):
            validate_contract(doc)

    def test_identity_arrays_and_access_must_match_actions(self):
        doc = contract()
        doc["access"]["verifiers"] = ["v", "v"]
        with self.assertRaises(ContractError):
            validate_contract(doc)
        doc = contract()
        doc["access"]["adapters"]["extra"] = ["adapter"]
        with self.assertRaises(ContractError):
            validate_contract(doc)
        doc = contract()
        doc["access"]["observers"] = []
        with self.assertRaises(ContractError):
            validate_contract(doc)

    def test_discovery_is_deterministic_and_does_not_select_only_passing_fields(self):
        artifact = b'{"orders":2,"a/b":null}'
        inputs = {"orders": b'{"orders":9,"a/b":false}'}
        first = discover(artifact, inputs)
        self.assertEqual(first, discover(artifact, inputs))
        self.assertFalse(first["authoritative"])
        comparisons = [x for x in first["suggestions"] if x["plugin"] == "json.equals"]
        self.assertEqual(comparisons[0]["parameters"]["pairs"],
                         [{"artifact": "/a~1b", "input": "/a~1b"}, {"artifact": "/orders", "input": "/orders"}])
        with self.assertRaises(ContractError):
            validate_contract(first)

    def test_discovery_duplicate_keys_cannot_yield_json_check(self):
        suggestions = discover(b'{"a":1,"a":2}')["suggestions"]
        self.assertEqual([x["plugin"] for x in suggestions], ["bytes.sha256"])


if __name__ == "__main__":
    unittest.main()
