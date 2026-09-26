"""Inert first-party Docker qualification fixtures; never execute Docker."""

from contextlib import contextmanager
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts import qualified_docker as qualification


def load(name):
    specification = importlib.util.spec_from_file_location("docker_qualification_test_" + name, ROOT / "docker" / (name + ".py"))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


PROBE = load("probe")
PARSER = load("parser_probe")


class DockerQualificationUnitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hobnail-docker-qualification-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)

    def test_missing_release_configuration_is_an_error_not_a_skip(self):
        with self.assertRaisesRegex(RuntimeError, "required"):
            qualification.release_configuration(None)

    def test_release_configuration_is_closed_private_and_duplicate_safe(self):
        path = self.root / "release.json"
        value = {"parser_archive": "/released/parser.tar", "runtime_archive": "/released/runtime.tar",
                 "expected_engine": "reviewed-version", "expected_kernel": "reviewed-kernel"}
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        self.assertEqual(qualification.release_configuration(path), value)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            qualification.release_configuration(path)
        path.chmod(0o600)
        path.write_text(json.dumps({**value, "password": "forbidden"}))
        with self.assertRaises(ValueError):
            qualification.release_configuration(path)
        path.write_text('{"parser_archive":"first","parser_archive":"second"}')
        with self.assertRaises(ValueError):
            qualification.release_configuration(path)
        path.unlink()
        path.symlink_to(self.root / "missing")
        with self.assertRaises((ValueError, FileNotFoundError)):
            qualification.release_configuration(path)

    def test_receipt_retains_intention_observation_and_failure_before_raising(self):
        record = qualification.Recorder(self.root)
        def observed():
            persisted = json.loads(record.path.read_text())
            self.assertEqual(persisted["events"][-1], {"stage": "controlled", "state": "intended"})
            return {"actual": "unexpected"}
        result = record.step("controlled", observed)
        with self.assertRaises(qualification.QualificationError):
            record.check("controlled", result == {"actual": "expected"})
        persisted = json.loads(record.path.read_text())
        self.assertEqual(persisted["checks"]["controlled"], {"actual": "unexpected"})
        self.assertFalse(persisted["assertions"]["controlled"])
        with self.assertRaises(ValueError):
            record.step("controlled", lambda: {"actual": "replacement"})

    def test_receipt_redacts_credentials_material_and_sql_bodies(self):
        record = qualification.Recorder(self.root)
        secret = "owned-test-secret-which-must-not-appear"
        record.secrets.append(secret)
        record.step("redaction", lambda: {"nested": ["prefix " + secret], "password": secret,
                                          "content_hex": "private-bytes", "sql": "private SQL", "sql_output": "private SQL output",
                                          secret: "key must also be redacted"})
        text = record.path.read_text()
        for excluded in (secret, "private-bytes", "private SQL"):
            self.assertNotIn(excluded, text)
        self.assertEqual(stat.S_IMODE(record.path.stat().st_mode), 0o600)
        with self.assertRaises(RuntimeError):
            record.step("error", lambda: (_ for _ in ()).throw(RuntimeError(secret)))
        self.assertNotIn(secret, record.path.read_text())
        self.assertEqual(json.loads(record.path.read_text())["checks"]["error"], {"error": "RuntimeError"})

    def test_cleanup_preserves_primary_failure_and_attempts_every_lease(self):
        record = qualification.Recorder(self.root)
        record.receipt.update(status="failed", failure={"type": "QualificationError", "reason": "first_failure"})
        leases = [SimpleNamespace(principal="docker-worker", role="worker", login=name, lease_ref=name,
                                  request_id=number, profile="owned", expires_at="future", credential_id=None)
                  for number, name in enumerate(("first", "second"), 1)]
        calls = []
        class Provider:
            provider_id = "owned-provider"
            def inventory(self):
                return leases
            def revoke(self, reference):
                calls.append(reference)
                if reference == "first":
                    raise RuntimeError("controlled refusal")
                from hobnail.credentials import CredentialObservation
                return CredentialObservation(reference, "confirmed", False, 0, "observed", "controlled")
        qualification.retire_owned(SimpleNamespace(providers=[Provider()]), record, {})
        self.assertEqual(calls, ["first", "second"])
        self.assertEqual(record.receipt["failure"], {"type": "QualificationError", "reason": "first_failure"})
        self.assertFalse(record.receipt["checks"]["all_runtime_credentials_revoked"])
        self.assertTrue(record.receipt["checks"]["credential_retirement"][1]["confirmed"])

    def test_provider_is_registered_before_issuance_can_lose_its_response(self):
        record = qualification.Recorder(self.root)
        runtime = SimpleNamespace(providers=[], admin=Mock(), run_id="owned-run")
        known = {}
        class Provider:
            provider_id = "owned-provider"
            def __init__(self, *args, **kwargs):
                pass
            def issue(self, request):
                self_test.assertIn(self, runtime.providers)
                self_test.assertIn(self.provider_id, known)
                raise RuntimeError("issuance outcome unknown")
        self_test = self
        with patch.object(qualification, "PostgresCredentialProvider", Provider), self.assertRaises(RuntimeError):
            qualification.bootstrap(runtime, record, known)
        self.assertEqual(record.receipt["checks"]["bootstrap-registrar"], {"error": "RuntimeError"})

    def test_cleanup_runs_even_when_every_receipt_write_fails(self):
        record = qualification.Recorder(self.root)
        operation = Mock(return_value={"retired": True})
        with patch.object(record, "persist", side_effect=OSError("controlled disk failure")):
            result = qualification.cleanup_step(record, "must-run", operation)
        operation.assert_called_once_with()
        self.assertEqual(result, {"retired": True})
        self.assertEqual(record.receipt["checks"]["must-run"], result)
        self.assertTrue(record.receipt["cleanup_failures"])

    def test_operation_failure_survives_failed_error_recording(self):
        record = qualification.Recorder(self.root)
        original = RuntimeError("original operation")
        with patch.object(record, "persist", side_effect=[None, OSError("disk failed")]):
            with self.assertRaises(RuntimeError) as caught:
                record.step("failure", lambda: (_ for _ in ()).throw(original))
        self.assertIs(caught.exception, original)
        self.assertEqual(record.receipt["checks"]["failure"], {"error": "RuntimeError"})

    def test_partial_inventory_cannot_omit_a_known_issued_login(self):
        from hobnail.credentials import CredentialObservation
        record = qualification.Recorder(self.root)
        lease = SimpleNamespace(principal="worker", role="worker", login="known-login", lease_ref="known-ref",
                                request_id=1, profile="profile", expires_at="future", credential_id=None)
        provider = SimpleNamespace(provider_id="owned", inventory=Mock(return_value=[]),
            revoke=Mock(return_value=CredentialObservation("known-ref", "confirmed", False, 0, "observed", "controlled")))
        qualification.retire_owned(SimpleNamespace(providers=[provider]), record, {"owned": [lease]})
        provider.revoke.assert_called_once_with("known-ref")
        self.assertFalse(record.receipt["checks"]["all_runtime_credentials_revoked"])
        self.assertEqual(record.receipt["cleanup_failures"][0]["stage"], "credential_inventory_incomplete")

    def test_success_requires_completed_retirement_and_shutdown(self):
        record = qualification.Recorder(self.root)
        record.receipt["assertions"]["observed"] = True
        record.receipt["status"] = "cleanup_pending"
        record.receipt["checks"]["all_runtime_credentials_revoked"] = False
        record.receipt["runtime_stopped"] = True
        self.assertEqual(qualification.final_status(record, True), "failed")
        record.receipt["checks"]["all_runtime_credentials_revoked"] = True
        record.receipt["runtime_stopped"] = False
        self.assertEqual(qualification.final_status(record, True), "failed")
        record.receipt["runtime_stopped"] = True
        record.receipt["checks"]["runtime-close"] = {
            "container_states": ["removed"], "administrator_retirement": {
                "result": "confirmed", "login_enabled": False, "other_client_sessions": 0}}
        self.assertEqual(qualification.final_status(record, True), "passed")
        self.assertEqual(qualification.final_status(record, False), "failed")
        record.receipt["checks"]["runtime-close"]["administrator_retirement"]["other_client_sessions"] = False
        self.assertEqual(qualification.final_status(record, True), "failed")
        record.receipt["checks"]["runtime-close"]["administrator_retirement"]["other_client_sessions"] = 0
        record.receipt["checks"]["runtime-close"]["container_states"] = ["running"]
        self.assertEqual(qualification.final_status(record, True), "failed")

    def parser_runtime(self, corrupt=None):
        from hobnail.client import TransportTimeout
        from hobnail.isolation import ChildResult
        containers = {"earlier-owned": {"id": "0" * 64, "state": "removed"}}
        def probe(script, payload, *, timeout):
            command = json.loads(payload)["command"]
            self.assertEqual(script, ROOT / "docker/parser_probe.py")
            self.assertEqual(timeout, 2 if command == "sleep_timeout" else 10)
            number = len(containers)
            value = {"id": f"{number:064x}", "policy": {"role": "parser"}, "state": "removed",
                     "cleanup_observed_state": {"running": command == "sleep_timeout", "pid": 1234,
                                                "exit_code": 0},
                     "exit_code": 130 if command == "sleep_timeout" else 0}
            if corrupt is not None:
                corrupt(command, value)
            containers["probe-" + str(number)] = value
            if command == "sleep_timeout":
                raise TransportTimeout("controlled timeout")
            return ChildResult(-9, "", "output_limit")
        return SimpleNamespace(containers=containers, probe_parser=probe)

    def test_parser_limits_require_actual_timeout_and_removed_exact_containers(self):
        record = qualification.Recorder(self.root)
        qualification.qualify_parser_limits(self.parser_runtime(), record)
        self.assertTrue(all(record.receipt["assertions"].values()))
        for command in ("sleep_timeout", "stdout_overflow", "stderr_overflow"):
            observed = record.receipt["checks"]["parser-limit-" + command + "-containers"]
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0]["state"], "removed")
            self.assertIs(type(observed[0]["exit_code"]), int)
        self.assertEqual(record.receipt["checks"]["parser-limit-stdout_overflow-containers"][0]["exit_code"], 0)

    def test_parser_timeout_cannot_pass_without_started_process_or_actual_reaping(self):
        corruptions = {
            "never-started": lambda value: value["cleanup_observed_state"].update(running=False),
            "not-removed": lambda value: value.update(state="running"),
            "missing-exit": lambda value: value.pop("exit_code"),
            "old-id": lambda value: value.update(id="0" * 64),
        }
        for name, mutate in corruptions.items():
            with self.subTest(name=name):
                directory = self.root / name
                directory.mkdir(mode=0o700)
                record = qualification.Recorder(directory)
                runtime = self.parser_runtime(lambda command, value: mutate(value))
                with self.assertRaises(qualification.QualificationError):
                    qualification.qualify_parser_limits(runtime, record)
                self.assertEqual(record.receipt["checks"]["parser-limit-sleep_timeout"], {"error": "TransportTimeout"})
                self.assertTrue(record.receipt["checks"]["parser-limit-sleep_timeout-containers"])

    def test_parser_overflow_requires_observed_exit_even_if_container_is_gone(self):
        record = qualification.Recorder(self.root)
        def remove_exit(command, value):
            if command == "stdout_overflow":
                value.pop("exit_code")
        with self.assertRaises(qualification.QualificationError):
            qualification.qualify_parser_limits(self.parser_runtime(remove_exit), record)
        self.assertEqual(record.receipt["checks"]["parser-limit-stdout_overflow"]["diagnostic"], "output_limit")
        self.assertFalse(record.receipt["assertions"]["parser-limit-stdout_overflow-removed"])

    def test_failed_primary_and_fallback_storage_preserve_unpersisted_result(self):
        record = qualification.Recorder(self.root)
        primary = {"type": "QualificationError", "reason": "original_failure"}
        record.receipt["failure"] = primary.copy()
        with patch.object(record, "persist", side_effect=OSError("first storage failure")), patch.object(qualification.tempfile, "mkdtemp", side_effect=OSError("fallback storage failure")):
            retained = qualification.retain_result(record)
        self.assertEqual(retained.receipt["failure"], primary)
        self.assertEqual(retained.receipt["status"], "failed")
        self.assertIsNone(retained.receipt["receipt"])
        self.assertFalse(retained.receipt["receipt_persisted"])
        self.assertEqual(retained.receipt["cleanup_failures"][-1]["stage"], "fallback_receipt_persistence")

    def test_constructor_and_all_storage_failures_return_without_runtime_execution(self):
        with patch.object(qualification, "DockerRuntime", side_effect=ValueError("primary constructor failure")), patch.object(qualification.tempfile, "mkdtemp", side_effect=OSError("all storage unavailable")):
            result = qualification.run_qualification(parser_archive="explicit", runtime_archive="explicit",
                expected_engine="explicit", expected_kernel="explicit")
        self.assertEqual(result["failure"], {"type": "ValueError", "reason": "runtime_failure"})
        self.assertFalse(result["receipt_persisted"])
        self.assertIsNone(result["receipt"])

    def test_backend_observation_is_bound_to_one_owned_login_pid_and_sleep(self):
        admin = Mock()
        expected = {"login_enabled": True, "unexpired": False, "active_sessions": 1, "target_waiting": True}
        admin.execute_sql.return_value = json.dumps(expected)
        login = "hn_" + "a" * 32
        self.assertEqual(qualification.backend_state(admin, login, 1234), expected)
        sql = admin.execute_sql.call_args.args[0]
        self.assertIn("pid=1234", sql)
        self.assertIn("r.rolname='" + login + "'", sql)
        self.assertIn("wait_event='PgSleep'", sql)
        self.assertIn("SELECT pg_sleep(120);", sql)
        with self.assertRaises(ValueError):
            qualification.backend_state(admin, "not_an_owned_login", 1234)
        with self.assertRaises(ValueError):
            qualification.backend_state(admin, login, True)
        self.assertEqual(admin.execute_sql.call_count, 1)

    def test_backend_poll_retains_pending_observations_and_fails_at_deadline(self):
        record = qualification.Recorder(self.root)
        runtime = SimpleNamespace(admin=Mock())
        with patch.object(qualification, "backend_state", return_value={"target_waiting": False}), patch.object(qualification.time, "monotonic", side_effect=[0.0, 0.0, 2.0]):
            with self.assertRaises(qualification.QualificationError):
                qualification.wait_backend(runtime, record, "login", 1, "backend-deadline", lambda value: value["target_waiting"], timeout=1)
        self.assertEqual(record.receipt["checks"]["backend-deadline-0"], {"target_waiting": False})
        self.assertFalse(record.receipt["assertions"]["backend-deadline"])

    def test_late_true_backend_response_cannot_pass_a_declared_deadline(self):
        record = qualification.Recorder(self.root)
        runtime = SimpleNamespace(admin=Mock())
        with patch.object(qualification, "backend_state", return_value={"target_waiting": True}) as observe, patch.object(qualification.time, "monotonic", side_effect=[0.0, 0.25, 2.0]):
            with self.assertRaises(qualification.QualificationError):
                qualification.wait_backend(runtime, record, "login", 1, "late-backend", lambda value: value["target_waiting"], timeout=1)
        self.assertEqual(observe.call_args.kwargs, {"timeout": 0.75})
        self.assertTrue(record.receipt["checks"]["late-backend-0"]["target_waiting"])
        self.assertFalse(record.receipt["checks"]["late-backend-timing-0"]["within_deadline"])
        self.assertFalse(record.receipt["assertions"]["late-backend"])

    def test_successful_child_exit_cannot_mimic_revocation_termination(self):
        from hobnail.credentials import CredentialObservation
        record = qualification.Recorder(self.root)
        lease = SimpleNamespace(login="hn_" + "a" * 32, credential_id=1)
        @contextmanager
        def holder(endpoint):
            yield {"host_pid": 1234, "container_id": "owned", "ready_response": {
                "ready": True, "login": lease.login, "backend_pid": 4567, "psql_pid": 2},
                "wait_terminated": lambda: {"terminated": True, "exit_code": 0}}
        runtime = SimpleNamespace(hold_sql_endpoint=holder)
        requester = Mock()
        requester.call.return_value = {"ok": True, "status": "recorded", "data": {}}
        broker = Mock()
        broker.revoke_requested.return_value = CredentialObservation("owned", "confirmed", False, 0, "observed", "controlled")
        with patch.object(qualification, "wait_backend"), self.assertRaises(qualification.QualificationError):
            qualification.retire_held_session(runtime, record, Mock(), requester, broker, lease, 1, prefix="controlled")
        self.assertEqual(record.receipt["checks"]["controlled-held-termination"]["exit_code"], 0)
        self.assertFalse(record.receipt["assertions"]["controlled-held-termination"])

    def test_unsupported_families_and_inconclusive_sql_cannot_qualify(self):
        sockets = {name: {"outcome": "denied", "errno": errno.EPERM} for name in ("AF_INET", "AF_INET6", "AF_ALG", "AF_VSOCK")}
        sockets.update(AF_UNIX={"outcome": "created"}, postgres_socket={"outcome": "connected"})
        sockets["kernel_entrypoints"] = {name: {"outcome": "denied", "errno": errno.EPERM}
                                         for name in ("io_uring_setup", "io_uring_enter", "io_uring_register")}
        sockets["kernel_entrypoints"]["socketcall"] = {"outcome": "not_in_abi", "architecture": "aarch64"}
        response = {"command": "socket_families", "role": "worker", "facts": sockets}
        self.assertTrue(all(qualification.role_assertions("worker", "login", "socket_families", response).values()))
        sockets["AF_ALG"] = {"outcome": "unsupported_family", "errno": errno.EAFNOSUPPORT}
        self.assertFalse(qualification.role_assertions("worker", "login", "socket_families", response)["AF_ALG"])
        for number in (errno.ENOSYS, errno.EBADF):
            sockets["kernel_entrypoints"]["io_uring_setup"] = {"outcome": "denied", "errno": number}
            self.assertFalse(qualification.role_assertions("worker", "login", "socket_families", response)["kernel_entrypoints"])
        sql = {"identity_and_privileges": {"session_user": "login", "current_user": "login", "audit_select": False, "audit_update": False, "owner_member": False},
               "audit_read": {"outcome": "privilege_denied", "sqlstate": "42501"},
               "audit_write": {"outcome": "privilege_denied", "sqlstate": "42501"},
               "owner_role": {"outcome": "privilege_denied", "sqlstate": "42501"},
               "admin_with_role_password": {"outcome": "password_authentication_failed"}}
        response = {"command": "sql_boundary", "role": "worker", "facts": sql}
        self.assertTrue(all(qualification.role_assertions("worker", "login", "sql_boundary", response).values()))
        sql["audit_write"] = {"outcome": "refused_unclassified", "error": "TransportError"}
        self.assertFalse(qualification.role_assertions("worker", "login", "sql_boundary", response)["audit_write"])
        sql["identity_and_privileges"]["audit_select"] = True
        self.assertFalse(qualification.role_assertions("worker", "login", "sql_boundary", response)["catalog_permissions"])
        sql["admin_with_role_password"] = {"outcome": "inconclusive", "error": "TransportTimeout"}
        self.assertFalse(qualification.role_assertions("worker", "login", "sql_boundary", response)["admin_authentication"])

    def test_contract_uses_independent_principals_and_fixed_targets(self):
        value = qualification.contract({name: str(index) * 64 for index, name in enumerate(("json.equals", "json.required_fields", "file.publish"), 1)})
        self.assertEqual(value["access"]["workers"], ["docker-worker"])
        self.assertEqual(value["access"]["verifiers"], ["docker-verifier"])
        self.assertEqual(value["sources"][0]["registrars"], ["docker-registrar"])
        self.assertEqual({action["target"] for action in value["actions"]}, {"accepted.json", "changed.json", "stale.json", "never-admitted.json", "uncertain.json"})
        self.assertEqual(value["budgets"], {"verification": 8, "effects": 8})

    def test_source_inventory_uses_git_blobs_independently_of_snapshot_and_archive_bytes(self):
        repository, snapshot = self.root / "repository", self.root / "snapshot"
        repository.mkdir()
        snapshot.mkdir()
        archive = self.root / "archive"
        archive.write_bytes(b"inert reviewed archive fixture")
        lock = {"rootfs": [{"flavor": "parser", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "size": archive.stat().st_size}]}
        members = {"src/hobnail/client.py": b"committed source fixture\n", "docker/images.lock.json": json.dumps(lock).encode()}
        for relative, content in members.items():
            for root in (repository, snapshot):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        (repository / "ignored-private.txt").write_bytes(b"outside selected source")
        environment = {**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                       "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        for arguments in (("init", "-q"), ("add", "."), ("-c", "core.hooksPath=/dev/null", "commit", "-qm", "inert fixture")):
            subprocess.run(["git", *arguments], cwd=repository, env=environment, capture_output=True, check=True)
        (repository / "src/hobnail/client.py").write_bytes(b"uncommitted live bytes")
        runtime = SimpleNamespace(snapshot=snapshot, archives={"parser": archive})
        with patch.object(qualification, "ROOT", repository):
            expected = qualification.registered_source_inventory()
            actual = qualification.produced_source_inventory(runtime, expected["source_commit"])
            self.assertEqual(actual, expected)
            self.assertEqual(len(expected["files"]), 2)
            (snapshot / "src/hobnail/client.py").write_bytes(b"tampered retained snapshot")
            self.assertNotEqual(qualification.produced_source_inventory(runtime, expected["source_commit"]), expected)
            self.assertEqual(qualification.registered_source_inventory(), expected)
            archive.write_bytes(b"different actual archive")
            self.assertNotEqual(qualification.produced_source_inventory(runtime, expected["source_commit"])["images"], expected["images"])

    def test_source_inventory_refuses_snapshot_alias(self):
        snapshot = self.root / "snapshot"
        snapshot.mkdir()
        outside = self.root / "outside"
        outside.write_text("unrelated")
        (snapshot / "alias.py").symlink_to(outside)
        with self.assertRaisesRegex(qualification.QualificationError, "source_snapshot_alias"):
            qualification.produced_source_inventory(SimpleNamespace(snapshot=snapshot, archives={}), "a" * 40)

    def audit_page(self):
        event = {"sequence": 1, "operation": "effect.observe", "request": {"effect_id": 7, "content_hex": {"redacted": True}},
                 "response": {"data": {"state": "complete"}}}
        canonical = json.dumps(event)
        digest = hashlib.sha256(bytes(32) + canonical.encode()).hexdigest()
        return {"head": {"sequence": 1, "hash": digest}, "chain_valid": False,
                "events": [{"seq": 1, "event": event, "event_canonical": canonical,
                            "previous_hash": "0" * 64, "hash": digest}]}

    def test_audit_verifies_canonical_bytes_instead_of_trusting_server_chain_flag(self):
        from hobnail.audit import verify_page
        record = qualification.Recorder(self.root)
        auditor = Mock()
        auditor.require.return_value = {"ok": True, "data": self.audit_page()}
        qualification.verify_audit(record, auditor, 7)
        self.assertTrue(record.receipt["assertions"]["audit-delivered-source-inventory"])
        self.assertFalse(record.receipt["checks"]["audit-verified"]["externally_anchored"])
        proof = json.loads(record.path.read_text())["checks"]["audit-canonical-proof"][0]
        for row in proof["events"]:
            row["event"] = json.loads(row["event_canonical"])
        self.assertTrue(verify_page(proof).complete)

    def test_audit_tampering_and_missing_actual_delivery_fail_independently(self):
        from hobnail.audit import AuditError
        for name in ("tamper", "wrong-effect"):
            with self.subTest(name=name):
                root = self.root / name
                root.mkdir(mode=0o700)
                record = qualification.Recorder(root)
                page = self.audit_page()
                page["chain_valid"] = True
                if name == "tamper":
                    page["events"][0]["event_canonical"] += " "
                auditor = Mock()
                auditor.require.return_value = {"ok": True, "data": page}
                with self.assertRaises(AuditError if name == "tamper" else qualification.QualificationError):
                    qualification.verify_audit(record, auditor, 8)

    def uncertain_fixture(self, mutation):
        worker, adapter, observer = Mock(), Mock(), Mock()
        artifact = b"owned exact consequence"
        pending = {"effect_id": 9, "state": "attempted", "dispatched_at": "same-dispatch", "reports": [{"kind": "dispatch"}]}
        final = {**pending, "state": "complete"}
        budget = {"budgets": {"effects": {"cap": 8, "used": 2, "remaining": 6}}}
        after_budget = json.loads(json.dumps(budget))
        if mutation == "budget":
            after_budget["budgets"]["effects"]["used"] = 0
        worker.call.side_effect = [{"ok": True, "data": data} for data in ({"effect_id": 9}, budget, pending, final, after_budget)]
        adapter.dispatch.side_effect = [{"ok": True, "data": {"state": "attempted"}}, {"ok": False, "code": "RECONCILIATION_REQUIRED"}]
        observer.observe.return_value = {"ok": True, "data": {"state": "complete"}}
        endpoints = {"worker": SimpleNamespace(client=lambda: worker), "adapter": adapter, "observer": observer}
        before = {"sha256": hashlib.sha256(artifact).hexdigest(), "size": len(artifact), "device": 1, "inode": 2, "mtime_ns": 3, "ctime_ns": 4}
        after = {**before, "inode": 99} if mutation == "duplicate" else before.copy()
        runtime = SimpleNamespace(probe=Mock(side_effect=[{"facts": {"uncertain.json": value}} for value in (before, after)]))
        return runtime, endpoints, artifact

    def test_lost_adapter_response_reconciles_same_effect_without_budget_or_inode_change(self):
        record = qualification.Recorder(self.root)
        runtime, endpoints, artifact = self.uncertain_fixture(None)
        qualification.qualify_uncertain(runtime, record, endpoints, 1, artifact)
        self.assertTrue(all(record.receipt["assertions"].values()))
        self.assertEqual(endpoints["adapter"].dispatch.call_count, 2)
        self.assertTrue(all(call.args == (9,) for call in endpoints["adapter"].dispatch.call_args_list))

    def test_uncertain_reconciliation_refuses_duplicate_consequence_or_reset_budget(self):
        for mutation in ("duplicate", "budget"):
            with self.subTest(mutation=mutation):
                root = self.root / mutation
                root.mkdir(mode=0o700)
                record = qualification.Recorder(root)
                runtime, endpoints, artifact = self.uncertain_fixture(mutation)
                with self.assertRaises(qualification.QualificationError):
                    qualification.qualify_uncertain(runtime, record, endpoints, 1, artifact)

    def test_real_wait_cannot_return_before_declared_elapsed_time(self):
        with patch.object(qualification.time, "monotonic", side_effect=[110.0, 279.0, 280.0, 280.1]), patch.object(qualification.time, "sleep") as sleep:
            result = qualification._wait_real_elapsed(100.0, qualification.RUNTIME_LIFETIME)
        self.assertGreaterEqual(result["elapsed_seconds"], 180)
        self.assertEqual([call.args for call in sleep.call_args_list], [(1,), (1,)])

    def test_lifetime_control_uses_unchanged_cap_and_both_independent_refusals(self):
        from dataclasses import replace
        from datetime import datetime, timedelta, timezone
        from hobnail.client import Connection, PasswordAuthenticationFailed
        from hobnail.credentials import CredentialError, CredentialLease, CredentialObservation, Secret
        base = datetime.now(timezone.utc)
        at = lambda seconds: (base + timedelta(seconds=seconds)).isoformat()
        lease = CredentialLease(1, qualification.PROFILE, "docker-verifier", "verifier", "owned",
            "hn_" + "a" * 32, at(0), at(120), True, Secret("controlled-owned-fixture"), 10)
        requester = Mock()
        def request(operation, payload):
            if operation == "credential.renew_requested" and payload["ttl_seconds"] in (120, 1):
                return {"ok": False, "code": "CREDENTIAL_SCOPE" if payload["ttl_seconds"] == 120 else "CREDENTIAL_EXPIRED"}
            return {"ok": True, "data": {"request_id": 1}}
        requester.call.side_effect = request
        endpoint = Mock()
        endpoint.client.return_value.call.return_value = {"ok": True, "data": {}}
        endpoint.call.side_effect = PasswordAuthenticationFailed("controlled refusal")
        runtime = SimpleNamespace(endpoint=Mock(return_value=endpoint))
        bootstrap = SimpleNamespace(client=lambda: requester, connection=Connection("/run/postgresql", "hobnail", "bootstrap"))
        provider = SimpleNamespace(provider_id="owned", renew=Mock(side_effect=CredentialError("controlled refusal")))
        broker = SimpleNamespace(provider=provider, issue_request=Mock(return_value=lease),
            renew_requested=Mock(return_value=replace(lease, expires_at=at(175))),
            revoke_requested=Mock(return_value=CredentialObservation("owned", "confirmed", False, 0, at(181), "controlled")))
        states = [{"observed_at": at(63), "expires_at": at(120), "login_enabled": True, "unexpired": True},
                  {"observed_at": at(63), "expires_at": at(120), "login_enabled": True, "unexpired": True},
                  {"observed_at": at(181), "expires_at": at(175), "login_enabled": True, "unexpired": False}]
        record = qualification.Recorder(self.root)
        known = {"owned": []}
        with patch.object(qualification, "credential_clock", side_effect=states), patch.object(qualification, "_wait_real_elapsed",
                side_effect=lambda started, minimum: {"elapsed_seconds": minimum, "required_seconds": minimum}):
            qualification.qualify_lifetime(runtime, record, bootstrap, broker, known, 9)
        provider.renew.assert_called_once_with("owned", 120)
        self.assertEqual(record.receipt["checks"]["lifetime-credential-exhaustion-wait"]["required_seconds"], 181)
        self.assertEqual(known["owned"], [lease])
        self.assertTrue(all(record.receipt["assertions"].values()))


class DockerProbeUnitTests(unittest.TestCase):
    def test_closed_probe_requests_never_accept_generic_paths_sql_or_commands(self):
        for role, request in (("worker", {"command": "files", "path": "/outside"}),
                              ("worker", {"command": "sql_boundary", "sql": "SELECT 1"}),
                              ("worker", {"command": "change_accepted"}),
                              ("adapter", {"command": "destination"}),
                              ("worker", {"command": "hold", "seconds": 31}),
                              ("worker", {"command": "peer", "host_pid": True}),
                              ("admin", {"command": "sql_boundary"})):
            with self.subTest(role=role, request=request), self.assertRaises(ValueError):
                PROBE.validate_request(role, request)

    def test_hold_requires_actual_identity_and_emits_exact_ready_frame(self):
        connection = SimpleNamespace(user="owned_login")
        output = io.StringIO()
        with patch.object(PROBE, "PsqlTransport") as transport, patch.object(PROBE.time, "sleep") as sleep:
            transport.return_value.execute_sql.return_value = '{"login":"owned_login"}'
            self.assertEqual(PROBE.hold(connection, 3, output), 0)
            sleep.assert_called_once_with(3)
        self.assertEqual(json.loads(output.getvalue()), {"ready": True, "login": "owned_login"})
        with patch.object(PROBE, "PsqlTransport") as transport, patch.object(PROBE.time, "sleep") as sleep:
            transport.return_value.execute_sql.return_value = '{"login":"wrong_login"}'
            with self.assertRaises(ValueError):
                PROBE.hold(connection, 3, io.StringIO())
            sleep.assert_not_called()

    def test_peer_opens_only_fixed_proc_paths_and_never_reads_contents(self):
        with patch.object(PROBE.os, "open", side_effect=FileNotFoundError(errno.ENOENT, "body withheld")) as opened, patch.object(PROBE.os, "kill", side_effect=ProcessLookupError(errno.ESRCH, "absent")) as signal:
            result = PROBE.peer(123456)
        self.assertEqual([call.args[0] for call in opened.call_args_list],
                         ["/proc/123456/root/scratch/config.json", "/proc/123456/environ", "/proc/123456/fd",
                          "/proc/123456/root/scratch/config.json", "/proc/123456/root/scratch/../scratch/config.json"])
        signal.assert_called_once_with(123456, PROBE.signal.SIGCONT)
        for name in ("config", "environment", "descriptors", "config_write_open", "config_traversal", "signal_continue"):
            self.assertEqual(result[name]["outcome"], "absent")
        self.assertNotIn("body withheld", json.dumps(result))

    def test_socket_error_categories_do_not_convert_absence_to_denial(self):
        for number, expected in ((errno.EPERM, "denied"), (errno.EAFNOSUPPORT, "unsupported_family"),
                                  (errno.ENOENT, "absent"), (errno.ECONNREFUSED, "error")):
            self.assertEqual(PROBE.failure(OSError(number, "private error body"))["outcome"], expected)
            self.assertNotIn("private error body", json.dumps(PROBE.failure(OSError(number, "private error body"))))

    def test_parser_request_is_fixed_and_unsupported_socket_is_not_a_denial(self):
        PARSER.read_request(io.BytesIO(b'{"command":"parser_boundaries","host_canary":"/tmp/hbn-docker-fixture/supervisor-canary","peer_pid":123456}'))
        for value in (b'{"command":"parser_boundaries","script":"outside"}',
                      b'{"command":"parser_boundaries","command":"parser_boundaries"}', b"x" * 1025):
            with self.assertRaises(ValueError):
                PARSER.read_request(io.BytesIO(value))
        observed = PARSER.attempt(lambda: (_ for _ in ()).throw(OSError(errno.EAFNOSUPPORT, "private")))
        self.assertEqual(observed, {"outcome": "other_error", "errno": errno.EAFNOSUPPORT})

    def test_fixed_parser_limit_commands_have_no_caller_selected_bounds(self):
        for command in ("sleep_timeout", "stdout_overflow", "stderr_overflow"):
            self.assertEqual(PARSER.read_request(io.BytesIO(json.dumps({"command": command}).encode())), command)
            for key in ("seconds", "bytes", "script"):
                with self.assertRaises(ValueError):
                    PARSER.read_request(io.BytesIO(json.dumps({"command": command, key: 1}).encode()))
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(PARSER.time, "sleep") as sleep, patch.object(PARSER, "inspect") as inspect:
            self.assertEqual(PARSER.main(io.BytesIO(b'{"command":"sleep_timeout"}'), output, errors), 0)
            sleep.assert_called_once_with(30)
            inspect.assert_not_called()
        self.assertEqual(output.getvalue(), "")
        for command in ("stdout_overflow", "stderr_overflow"):
            output, errors = io.StringIO(), io.StringIO()
            self.assertEqual(PARSER.main(io.BytesIO(json.dumps({"command": command}).encode()), output, errors), 0)
            self.assertEqual(len(output.getvalue()), 65536 if command == "stdout_overflow" else 0)
            self.assertEqual(len(errors.getvalue()), 65536 if command == "stderr_overflow" else 0)

    def test_held_backend_pid_requires_one_bounded_decimal_line(self):
        for content, expected in ((b"12345\n", 12345), (b"1\n", None), (b"12\n34\n", None),
                                  (b"1234567890123\n", None), (b"", None)):
            with self.subTest(content=content):
                read, write = os.pipe()
                os.write(write, content)
                os.close(write)
                with os.fdopen(read, "rb", buffering=0) as stream:
                    process = SimpleNamespace(stdout=stream)
                    if expected is None:
                        with self.assertRaises(ValueError):
                            PROBE.held_backend_pid(process, time.monotonic() + 1)
                    else:
                        self.assertEqual(PROBE.held_backend_pid(process, time.monotonic() + 1), expected)

    def test_sql_hold_reports_only_natural_nonzero_exit_and_uses_fixed_child_authority(self):
        from hobnail.client import Connection
        secret = "controlled-owned-password-" + "x" * 30
        connection = Connection("/run/postgresql", "hobnail", "hn_" + "a" * 32, password=secret, sslmode="disable")
        statement = b"SELECT pg_backend_pid();\nSELECT pg_sleep(120);\n"
        with tempfile.TemporaryDirectory(prefix="hobnail-sql-hold-fixture-") as temporary:
            for outcome in (2, 0, "timeout"):
                with self.subTest(outcome=outcome):
                    child = Mock(pid=2)
                    child.stdin.write.return_value = len(statement)
                    if outcome == "timeout":
                        child.poll.side_effect = [None, None]
                        child.wait.side_effect = [subprocess.TimeoutExpired("fixed-child", 50), -9]
                    else:
                        child.poll.side_effect = [None, outcome]
                        child.wait.side_effect = [outcome, outcome]
                    output = io.StringIO()
                    with patch.object(PROBE.owned, "SCRATCH", Path(temporary)), patch.object(PROBE.subprocess, "Popen", return_value=child) as create, patch.object(PROBE, "held_backend_pid", return_value=12345):
                        status = PROBE.hold_sql(connection, output)
                    lines = [json.loads(line) for line in output.getvalue().splitlines()]
                    self.assertEqual(lines[0], {"ready": True, "login": connection.user, "backend_pid": 12345, "psql_pid": 2})
                    if outcome == 2:
                        self.assertEqual(status, 0)
                        self.assertEqual(lines[1], {"terminated": True, "exit_code": 2})
                    else:
                        self.assertEqual(status, 1)
                        self.assertEqual(len(lines), 1)
                    if outcome == "timeout":
                        child.kill.assert_called_once_with()
                    child.stdin.write.assert_called_once_with(statement)
                    self.assertEqual(create.call_args.args[0][0], "/usr/local/bin/psql")
                    self.assertNotIn(secret, str(create.call_args.args))
                    self.assertEqual(set(create.call_args.kwargs["env"]), {"LC_ALL", "PGPASSFILE", "PGSERVICEFILE", "PGSYSCONFDIR", "PGPASSWORD"})
                    self.assertEqual(create.call_args.kwargs["env"]["PGPASSWORD"], secret)
                    self.assertNotIn(secret, output.getvalue())


if __name__ == "__main__":
    unittest.main()
