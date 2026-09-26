"""Cleanup mechanism tests only: no OpenBao/PostgreSQL runtime is constructed.

Qualification objects are allocated with __new__ and receive explicit owned
filesystem fixtures and fake lifecycle/client objects. Passing these cases is
not live-provider qualification or evidence about port 18200.
"""

import copy
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.qualified_openbao import Qualification, QualificationError
from hobnail.credentials import Secret


class OwnedRuntimeFixture:
    def __init__(self, root):
        self.root = root
        root.mkdir(mode=0o700)
        for directory in ("logs", "audit", "receipts"):
            (root / directory).mkdir(mode=0o700)
        self.identity = (root.stat().st_dev, root.stat().st_ino)
        self._root_token = None
        self._root_revoked = True
        self._sensitive_values = set()
        self.stop_result = True
        self.stop_error = None
        self.stop_calls = 0
        self.requests = []
        self.events = []
        self.issued_tokens = ()
        self.revoke_error = None
        self.token_error = None
        self.owner_token_errors = {}
        self.root_revoke_error = None

    def _check_owner(self):
        current = self.root.stat()
        if (current.st_dev, current.st_ino) != self.identity:
            raise OSError("owned fixture identity changed")

    def request(self, method, path, payload=None, *, token=None, expectedstatuses=(200, 204)):
        self.requests.append((method, path, copy.deepcopy(payload), expectedstatuses))
        self.events.append({"kind": "request", "method": method, "path": path,
                            "payload": copy.deepcopy(payload), "token": token, "expectedstatuses": expectedstatuses})
        if path == "/v1/sys/leases/revoke" and self.revoke_error is not None:
            raise self.revoke_error
        if path == "/v1/auth/token/revoke-self" and self.token_error is not None and token == self.token_error:
            raise OSError("controlled token retirement failure")
        if path == "/v1/auth/token/revoke" and payload["token"] in self.owner_token_errors:
            raise self.owner_token_errors[payload["token"]]
        return SimpleNamespace(status=expectedstatuses[0], body={})

    @property
    def root_token(self):
        if self._root_token is None:
            raise RuntimeError("unit root token is unavailable")
        return self._root_token

    def revoke_root(self):
        self.events.append({"kind": "root_retirement"})
        if self.root_revoke_error is not None:
            raise self.root_revoke_error
        self._root_revoked = True
        return {"revoked": True}

    def stop(self):
        self.stop_calls += 1
        if self.stop_error is not None:
            raise self.stop_error
        return self.stop_result


class OwnedClusterFixture:
    def __init__(self, root):
        self.root = root
        root.mkdir(mode=0o700)
        self.running = True
        self.stop_error = None
        self.stop_result = True
        self.stop_calls = 0

    def stop(self):
        self.stop_calls += 1
        if self.stop_error is not None:
            raise self.stop_error
        if self.stop_result:
            self.running = False
        return self.stop_result

    def is_running(self):
        return self.running


class BrokerFixture:
    def __init__(self, results=None):
        self.results = results or {}
        self.calls = []

    def reconcile_request(self, identifier):
        self.calls.append(identifier)
        result = self.results.get(identifier, "confirmed")
        if isinstance(result, Exception):
            raise result
        return SimpleNamespace(result=result)


class BootstrapFixture:
    def __init__(self, leases, *, inventory_error=None, results=None):
        self.leases = leases
        self.inventory_error = inventory_error
        self.results = results or {}
        self.calls = []

    def inventory(self):
        if self.inventory_error is not None:
            raise self.inventory_error
        return self.leases

    def revoke(self, reference):
        self.calls.append(reference)
        result = self.results.get(reference, "confirmed")
        if isinstance(result, Exception):
            raise result
        return SimpleNamespace(result=result)


class ProcessFixture:
    def __init__(self, failure=None):
        self.failure = failure
        self.running = True
        self.terminated = False
        self.waited = False
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        if failure == "close":
            class FailedClose:
                closed = False
                def close(self):
                    raise OSError("controlled stream-close failure")
            self.stdout = FailedClose()

    def poll(self):
        if self.failure == "poll":
            raise OSError("controlled poll failure")
        return None if self.running else 0

    def terminate(self):
        if self.failure == "terminate":
            raise OSError("controlled terminate failure")
        self.running = False
        self.terminated = True

    def wait(self, timeout):
        self.waited = True
        if self.failure == "wait":
            raise TimeoutError("controlled wait failure")
        return 0


class OpenBaoQualificationCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hbn-qualified-bao-unit-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.counter = 0
        for target in ("OpenBaoRuntime", "DevCluster"):
            forbidden = patch("scripts.qualified_openbao." + target,
                              side_effect=AssertionError("real runtime construction forbidden in unit test"))
            self.addCleanup(forbidden.stop)
            constructor = forbidden.start()
            self.addCleanup(constructor.assert_not_called)

    def qualification(self):
        self.counter += 1
        q = Qualification.__new__(Qualification)
        q.runtime = OwnedRuntimeFixture(self.root / ("runtime-" + str(self.counter)))
        q.cluster = OwnedClusterFixture(q.runtime.root / "postgres")
        q.admin = None
        q.bootstrap = None
        q.bootstrap_leases = []
        q.issuers = []
        q.groups = []
        q.held = []
        q.observer_leases = {}
        q.observer_retired = set()
        q.stage = "unit-fixture"
        q.receipt = {"schema": "unit-cleanup-mechanism-only", "status": "passed", "qualified": False,
                     "checks": {}, "cleanup": []}
        q.saved_receipts = []
        def capture_save():
            q.saved_receipts.append(copy.deepcopy(q.receipt))
            Qualification.save(q)
        q.save = capture_save
        return q

    def group(self, states, results=None):
        broker = BrokerFixture(results)
        return {"name": "synthetic-group", "requests": list(states), "broker": broker,
                "bridge": SimpleNamespace(data=lambda identifier: states[identifier])}

    def entry(self, q, stage):
        matches = [row for row in q.receipt["cleanup"] if row["stage"] == stage]
        self.assertEqual(len(matches), 1, (stage, q.receipt))
        return matches[0]

    def assert_failed_and_stopped_attempted(self, q):
        # The first real save follows cleanup and precedes the separate live-log
        # and required-check gates. This pins cleanup failure itself, without
        # inventing successful PostgreSQL/OpenBao evidence for our fake runtime.
        self.assertEqual(q.saved_receipts[0]["status"], "failed")
        self.assertEqual(q.receipt["status"], "failed")
        self.assertFalse(q.receipt["qualified"])
        self.assertEqual(q.runtime.stop_calls, 1)
        self.assertEqual(q.cluster.stop_calls, 1)

    def test_confirmed_cleanup_persists_but_fake_runtime_cannot_qualify_live_use(self):
        q = self.qualification()
        q.cleanup()
        self.assertEqual(q.saved_receipts[0]["status"], "passed")
        self.assertTrue(self.entry(q, "openbao_stop")["confirmed"])
        self.assertTrue(self.entry(q, "postgres_stop")["confirmed"])
        self.assertEqual(q.receipt["status"], "failed")
        self.assertFalse(q.receipt["qualified"])
        self.assertTrue(q.receipt["missing_checks"])
        self.assertEqual(json.loads((q.runtime.root / "receipts/qualification.json").read_text()), q.receipt)

    def test_request_failures_do_not_stop_later_retirement_or_runtime_cleanup(self):
        q = self.qualification()
        states = {number: {"state": "bound", "provider_cleanup": "pending"} for number in (1, 2, 3)}
        group = self.group(states, {1: RuntimeError("synthetic-sensitive-detail"), 2: "pending", 3: "confirmed"})
        q.groups = [group]
        q.cleanup()
        self.assertEqual(group["broker"].calls, [1, 2, 3])
        self.assertFalse(self.entry(q, "request_retirement_1")["confirmed"])
        self.assertFalse(self.entry(q, "request_retirement_2")["confirmed"])
        self.assertTrue(self.entry(q, "request_retirement_3")["confirmed"])
        self.assertNotIn("synthetic-sensitive-detail", json.dumps(q.receipt))
        self.assert_failed_and_stopped_attempted(q)

    def test_unknown_external_reference_stays_unconfirmed_without_observer_retirement(self):
        q = self.qualification()
        state = {"state": "closed", "provider_cleanup": "unavailable", "login_enabled": False, "active_sessions": 0}
        group = self.group({1: state})
        q.groups = [group]
        q.cleanup()
        self.assertEqual(group["broker"].calls, [])
        self.assertEqual(state["provider_cleanup"], "unavailable")
        self.assertFalse(self.entry(q, "request_retirement_1")["confirmed"])
        self.assert_failed_and_stopped_attempted(q)

    def test_separate_observation_does_not_rewrite_unknown_broker_metadata(self):
        q = self.qualification()
        state = {"state": "closed", "provider_cleanup": "unavailable", "login_enabled": False, "active_sessions": 0}
        group = self.group({1: state})
        q.groups = [group]
        q.observer_retired.add(1)
        q.cleanup()
        self.assertTrue(self.entry(q, "request_retirement_1")["confirmed"])
        self.assertEqual(q.saved_receipts[0]["status"], "passed")
        self.assertEqual(state["provider_cleanup"], "unavailable")
        self.assertEqual(group["broker"].calls, [])

    def test_observer_retirement_never_substitutes_for_disabled_login_and_zero_sessions(self):
        for enabled, sessions in ((True, 0), (False, 1)):
            with self.subTest(enabled=enabled, sessions=sessions):
                q = self.qualification()
                group = self.group({1: {"state": "closed", "provider_cleanup": "unavailable",
                                        "login_enabled": enabled, "active_sessions": sessions}})
                q.groups = [group]
                q.observer_retired.add(1)
                q.cleanup()
                self.assertFalse(self.entry(q, "request_retirement_1")["confirmed"])
                self.assert_failed_and_stopped_attempted(q)

    def test_failed_external_observer_cleanup_does_not_confirm_reference_or_skip_other_requests(self):
        q = self.qualification()
        group = self.group({1: {"state": "closed", "provider_cleanup": "unavailable",
                                "login_enabled": False, "active_sessions": 0},
                            2: {"state": "bound", "provider_cleanup": "pending"}})
        group["token"] = Secret("synthetic-unit-token")
        q.groups = [group]
        q.observer_leases[1] = (group, "synthetic-reference")
        q.runtime.revoke_error = OSError("controlled observer retirement failure")
        q.cleanup()
        self.assertNotIn(1, q.observer_retired)
        self.assertFalse(self.entry(q, "separate_observer_retirement_1")["confirmed"])
        self.assertFalse(self.entry(q, "request_retirement_1")["confirmed"])
        self.assertEqual(group["broker"].calls, [2])
        self.assertTrue(self.entry(q, "request_retirement_2")["confirmed"])
        self.assert_failed_and_stopped_attempted(q)

    def test_bootstrap_inventory_failure_preserves_known_lease_retirement_attempts(self):
        q = self.qualification()
        leases = [SimpleNamespace(principal=name, lease_ref=name) for name in ("first", "second")]
        q.admin = SimpleNamespace()
        q.bootstrap_leases = leases
        q.bootstrap = BootstrapFixture([], inventory_error=OSError("controlled inventory outage"),
                                       results={"first": RuntimeError("controlled first revoke failure")})
        q.cleanup()
        self.assertEqual(q.bootstrap.calls, ["first", "second"])
        self.assertFalse(self.entry(q, "bootstrap_inventory")["confirmed"])
        self.assertFalse(self.entry(q, "bootstrap_retirement_first")["confirmed"])
        self.assertTrue(self.entry(q, "bootstrap_retirement_second")["confirmed"])
        self.assert_failed_and_stopped_attempted(q)

    def test_token_root_and_issuer_failures_do_not_skip_later_authorities(self):
        q = self.qualification()
        first_token, second_token = Secret("first-token"), Secret("second-token")
        q.groups = [{"name": "first", "token": first_token},
                    {"name": "second", "token": second_token}]
        q.runtime.token_error = first_token
        q.runtime._root_token = Secret("synthetic-root-token")
        q.runtime._root_revoked = False
        q.runtime.root_revoke_error = OSError("controlled root retirement failure")
        queries = []
        class Admin:
            def execute_sql(self, sql):
                queries.append(sql)
                if "first_issuer" in sql:
                    raise OSError("controlled issuer retirement failure")
                return "t"
        q.admin = Admin()
        q.issuers = ["first_issuer", "second_issuer"]
        q.cleanup()
        self.assertFalse(self.entry(q, "token_retirement_first")["confirmed"])
        self.assertTrue(self.entry(q, "token_retirement_second")["confirmed"])
        self.assertFalse(self.entry(q, "root_token_retirement")["confirmed"])
        self.assertFalse(self.entry(q, "issuer_retirement_first_issuer")["confirmed"])
        self.assertTrue(self.entry(q, "issuer_retirement_second_issuer")["confirmed"])
        self.assertEqual(len([sql for sql in queries if "second_issuer" in sql]), 3)
        self.assert_failed_and_stopped_attempted(q)

    def test_orphan_minted_token_uses_owner_revoke_before_root_retirement(self):
        q = self.qualification()
        owner, orphan = Secret("synthetic-owner-token"), Secret("synthetic-orphan-token")
        q.runtime._root_token = owner
        q.runtime._root_revoked = False
        q.runtime.issued_tokens = (orphan,)
        q.cleanup()
        requests = [row for row in q.runtime.events if row["kind"] == "request"]
        self.assertEqual([row["path"] for row in requests], ["/v1/auth/token/revoke", "/v1/auth/token/revoke-self"])
        self.assertIs(requests[0]["token"], owner)
        self.assertEqual(requests[0]["payload"], {"token": orphan.reveal()})
        self.assertEqual(requests[0]["expectedstatuses"], (200, 204))
        self.assertIs(requests[1]["token"], orphan)
        self.assertEqual(requests[1]["expectedstatuses"], (403,))
        self.assertEqual(q.runtime.events[-1]["kind"], "root_retirement")
        self.assertTrue(self.entry(q, "custodied_token_retirement_1")["confirmed"])
        self.assertTrue(self.entry(q, "root_token_retirement")["confirmed"])
        self.assertEqual(q.saved_receipts[0]["status"], "passed")
        for token in (owner, orphan):
            self.assertNotIn(token.reveal(), json.dumps(q.receipt))

    def test_failed_orphan_cleanup_still_retires_later_token_root_and_runtimes(self):
        q = self.qualification()
        first, second = Secret("synthetic-orphan-first"), Secret("synthetic-orphan-second")
        owner = Secret("synthetic-owner-token")
        q.runtime._root_token = owner
        q.runtime._root_revoked = False
        q.runtime.issued_tokens = (first, second)
        q.runtime.owner_token_errors[first.reveal()] = OSError("controlled orphan retirement failure")
        q.cleanup()
        owner_calls = [row for row in q.runtime.events if row.get("path") == "/v1/auth/token/revoke"]
        self.assertEqual([row["payload"]["token"] for row in owner_calls], [first.reveal(), second.reveal()])
        self.assertTrue(all(row["token"] is owner for row in owner_calls))
        self.assertEqual(q.runtime.events[-1]["kind"], "root_retirement")
        self.assertFalse(self.entry(q, "custodied_token_retirement_1")["confirmed"])
        self.assertTrue(self.entry(q, "custodied_token_retirement_2")["confirmed"])
        self.assertTrue(self.entry(q, "root_token_retirement")["confirmed"])
        self.assert_failed_and_stopped_attempted(q)

    def test_already_retired_group_token_is_not_repeated_through_custody(self):
        q = self.qualification()
        grouped = Secret("synthetic-grouped-token")
        q.groups = [{"name": "grouped", "token": grouped}]
        q.runtime.issued_tokens = (Secret(grouped.reveal()),)
        q.runtime._root_token = Secret("synthetic-owner-token")
        q.runtime._root_revoked = False
        q.cleanup()
        self.assertTrue(self.entry(q, "token_retirement_grouped")["confirmed"])
        self.assertFalse(any(row.get("path") == "/v1/auth/token/revoke" for row in q.runtime.events))
        self.assertFalse(any(row["stage"].startswith("custodied_token_retirement_") for row in q.receipt["cleanup"]))
        self.assertTrue(self.entry(q, "root_token_retirement")["confirmed"])
        self.assertEqual(q.saved_receipts[0]["status"], "passed")

    def test_inventory_does_not_drop_known_leases_when_it_adds_an_orphan(self):
        q = self.qualification()
        leases = [SimpleNamespace(principal=name, lease_ref=name) for name in ("first", "second", "orphan")]
        q.admin = SimpleNamespace()
        q.bootstrap_leases = leases[:2]
        q.bootstrap = BootstrapFixture([leases[0], leases[2]])
        q.cleanup()
        self.assertCountEqual(q.bootstrap.calls, ["first", "second", "orphan"])

    def test_unconfirmed_or_failed_runtime_stop_invalidates_qualification(self):
        for failure in ("bao_false", "bao_error", "postgres_false", "postgres_error"):
            with self.subTest(failure=failure):
                q = self.qualification()
                if failure == "bao_false":
                    q.runtime.stop_result = False
                elif failure == "bao_error":
                    q.runtime.stop_error = OSError("controlled stop failure")
                elif failure == "postgres_false":
                    q.cluster.stop_result = False
                else:
                    q.cluster.stop_error = OSError("controlled stop failure")
                q.cleanup()
                self.assert_failed_and_stopped_attempted(q)
                self.assertFalse(self.entry(q, "openbao_stop" if failure.startswith("bao") else "postgres_stop")["confirmed"])

    def test_held_process_errors_do_not_abort_remaining_owned_cleanup(self):
        for failure in ("poll", "terminate", "wait", "close"):
            with self.subTest(failure=failure):
                q = self.qualification()
                first, second = ProcessFixture(failure), ProcessFixture()
                q.held = [first, second]
                q.cleanup()
                self.assertTrue(second.terminated)
                self.assertTrue(second.waited)
                self.assertTrue(second.stdout.closed and second.stderr.closed)
                self.assert_failed_and_stopped_attempted(q)

    def test_primary_pipeline_failure_survives_a_cleanup_process_error(self):
        q = self.qualification()
        q.held = [ProcessFixture("terminate"), ProcessFixture()]
        def fail_setup():
            q.stage = "controlled-primary-stage"
            raise QualificationError("controlled_primary_failure")
        q.setup = fail_setup
        q.run_checks = lambda: self.fail("run_checks must not run after setup failure")
        receipt = q.run()
        self.assertEqual(receipt["failure"]["stage"], "controlled-primary-stage")
        self.assertEqual(receipt["failure"]["type"], "QualificationError")
        self.assertEqual(receipt["failure"]["check"], "controlled_primary_failure")
        self.assert_failed_and_stopped_attempted(q)


if __name__ == "__main__":
    unittest.main()
