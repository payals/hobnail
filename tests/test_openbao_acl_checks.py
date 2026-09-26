"""Pure checker orchestration only; these are not live OpenBao ACL evidence."""
from pathlib import Path
from types import SimpleNamespace
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from scripts.openbao_acl_checks import ACLCheckFailure, run_acl_checks
from hobnail.credentials import Secret


class ACLCheckerTests(unittest.TestCase):
    def setUp(self):
        self.main = SimpleNamespace(lease_ref="database/creds/hobnail-worker/synthetic-main-ref")
        self.foreign = SimpleNamespace(lease_ref="database/creds/hobnail-negative-control/synthetic-foreign-ref")
        self.token = Secret("synthetic-token-do-not-export")
        self.states = {
            self.main.lease_ref: {"oid": 101, "expires_at": "2099-01-01T00:00:00Z", "login_enabled": True, "active_sessions": 1, "valid": True},
            self.foreign.lease_ref: {"oid": 102, "expires_at": "2099-01-01T00:00:00Z", "login_enabled": True, "active_sessions": 1, "valid": True},
        }
        self.calls = []
        outer = self
        class Runtime:
            def request(self, method, path, payload=None, *, token=None, expectedstatuses=()):
                outer.calls.append((method, path, payload, token, expectedstatuses))
                return SimpleNamespace(status=403, body={"errors": ["synthetic-private-response"]})
        self.runtime = Runtime()

    def snapshot(self, lease):
        # Return the same mutable fixture object deliberately: the checker must
        # copy the before snapshot so an in-place change cannot be concealed.
        return self.states[lease.lease_ref]

    def run_checks(self):
        return run_acl_checks(self.runtime, self.token, self.main, self.foreign, self.snapshot)

    def test_complete_matrix_uses_exact_denial_status_and_exports_no_material(self):
        evidence = self.run_checks()
        self.assertEqual(evidence["status"], "passed")
        self.assertEqual(len(evidence["cases"]), 24)
        self.assertTrue(all(call[3] is self.token and call[4] == (403,) for call in self.calls))
        self.assertEqual(self.calls[0][2], {"lease_id": self.foreign.lease_ref, "increment": 60})
        self.assertEqual(self.calls[1][2], {"lease_id": self.foreign.lease_ref, "sync": True})
        payloads = [call[2] for call in self.calls]
        self.assertIn({"lease_id": self.main.lease_ref, "increment": 121}, payloads)
        self.assertIn({"lease_id": self.main.lease_ref, "sync": False}, payloads)
        self.assertTrue(all(not call[1].startswith("/v1/database/config/") or call[0] == "GET" for call in self.calls))
        serialized = json.dumps(evidence)
        for value in (self.main.lease_ref, self.foreign.lease_ref, self.token.reveal(), "synthetic-private-response"):
            self.assertFalse(value in serialized)
        self.assertFalse(evidence["configuration_mutations_tested"])

    def test_duration_string_cases_exercise_prefix_increment_and_parameter_constraints(self):
        evidence = self.run_checks()
        self.assertEqual(
            [(row["case"], call[0], call[1], call[2])
             for row, call in zip(evidence["cases"][21:], self.calls[21:])],
            [
                ("renew_foreign_existing_duration_wrong_prefix", "PUT", "/v1/sys/leases/renew",
                 {"lease_id": self.foreign.lease_ref, "increment": "60s"}),
                ("renew_excess_duration_increment", "PUT", "/v1/sys/leases/renew",
                 {"lease_id": self.main.lease_ref, "increment": "121s"}),
                ("renew_duration_extra_parameter", "PUT", "/v1/sys/leases/renew",
                 {"lease_id": self.main.lease_ref, "increment": "60s", "unexpected": True}),
            ],
        )

    def test_duration_string_case_success_cannot_hide_behind_prior_numeric_denials(self):
        expected_cases = ("renew_foreign_existing_duration_wrong_prefix",
                          "renew_excess_duration_increment", "renew_duration_extra_parameter")
        request = self.runtime.request
        for index, name in enumerate(expected_cases, start=22):
            with self.subTest(case=name):
                self.calls.clear()
                def success_at_target(*args, **kwargs):
                    response = request(*args, **kwargs)
                    return SimpleNamespace(status=204) if len(self.calls) == index else response
                self.runtime.request = success_at_target
                with self.assertRaises(ACLCheckFailure) as caught:
                    self.run_checks()
                rows = caught.exception.evidence["cases"]
                self.assertEqual(len(rows), index)
                self.assertTrue(all(row["passed"] for row in rows[:-1]))
                self.assertEqual(rows[-1]["case"], name)
                self.assertEqual(rows[-1]["failure"], "expected_exact_http_403")
                self.assertTrue(rows[-1]["main_unchanged"] and rows[-1]["foreign_unchanged"])

    def test_exact_403_with_changed_expiry_is_a_failure_and_preserves_evidence(self):
        request = self.runtime.request
        def changed(*args, **kwargs):
            response = request(*args, **kwargs)
            self.states[self.foreign.lease_ref]["expires_at"] = "2099-01-02T00:00:00Z"
            return response
        self.runtime.request = changed
        with self.assertRaises(ACLCheckFailure) as caught:
            self.run_checks()
        evidence = caught.exception.evidence
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["cases"][0]["http_status"], 403)
        self.assertFalse(evidence["cases"][0]["foreign_unchanged"])
        self.assertEqual(len(self.calls), 1)

    def test_natural_expiry_and_missing_held_session_refuse_before_request(self):
        for key, value in (("valid", False), ("active_sessions", 0), ("login_enabled", False)):
            with self.subTest(field=key):
                original = self.states[self.foreign.lease_ref][key]
                self.states[self.foreign.lease_ref][key] = value
                with self.assertRaises(ACLCheckFailure) as caught:
                    self.run_checks()
                self.assertFalse(caught.exception.evidence["cases"][0]["request_attempted"])
                self.assertEqual(self.calls, [])
                self.states[self.foreign.lease_ref][key] = original

    def test_unexpected_success_still_takes_after_snapshot_and_never_passes(self):
        self.runtime.request = lambda *args, **kwargs: SimpleNamespace(status=204)
        with self.assertRaises(ACLCheckFailure) as caught:
            self.run_checks()
        row = caught.exception.evidence["cases"][0]
        self.assertEqual(row["http_status"], 204)
        self.assertTrue(row["main_unchanged"] and row["foreign_unchanged"])
        self.assertEqual(row["failure"], "expected_exact_http_403")

    def test_runtime_exception_is_sanitized_and_cannot_count_as_denial(self):
        def error(*args, **kwargs):
            failure = RuntimeError(self.token.reveal() + " " + self.foreign.lease_ref)
            failure.status = 403
            raise failure
        self.runtime.request = error
        with self.assertRaises(ACLCheckFailure) as caught:
            self.run_checks()
        row = caught.exception.evidence["cases"][0]
        self.assertEqual(row["failure"], "request_or_response_failed")
        self.assertEqual(row["http_status"], 403)
        self.assertNotIn(self.token.reveal(), str(caught.exception))
        self.assertNotIn(self.foreign.lease_ref, json.dumps(caught.exception.evidence))
        self.assertTrue(row["foreign_unchanged"])

    def test_invalid_extra_or_boolean_integer_snapshot_fields_refuse(self):
        original = dict(self.states[self.main.lease_ref])
        for changed in ({**original, "password": "not-exported"}, {**original, "oid": True},
                        {**original, "expires_at": "2099-01-01T00:00:00"}):
            with self.subTest(fields=tuple(changed)):
                self.states[self.main.lease_ref] = changed
                with self.assertRaises(ACLCheckFailure):
                    self.run_checks()
                self.assertEqual(self.calls, [])

    def test_distinct_lease_references_cannot_share_one_observed_role(self):
        self.states[self.foreign.lease_ref]["oid"] = self.states[self.main.lease_ref]["oid"]
        with self.assertRaises(ACLCheckFailure) as caught:
            self.run_checks()
        self.assertEqual(caught.exception.evidence["cases"][0]["failure"], "lease_fixtures_share_one_role_identity")
        self.assertEqual(self.calls, [])

    def test_change_between_cases_is_not_adopted_as_a_new_baseline(self):
        reads = 0
        def delayed(lease):
            nonlocal reads
            reads += 1
            if reads == 5:
                self.states[self.foreign.lease_ref]["expires_at"] = "2099-01-02T00:00:00Z"
            return self.snapshot(lease)
        with self.assertRaises(ACLCheckFailure) as caught:
            run_acl_checks(self.runtime, self.token, self.main, self.foreign, delayed)
        self.assertTrue(caught.exception.evidence["cases"][0]["passed"])
        self.assertEqual(caught.exception.evidence["cases"][1]["failure"], "fixture_state_changed_between_cases")
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
