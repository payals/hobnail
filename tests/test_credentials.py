"""Real owned PostgreSQL role probes and explicitly separate OpenBao protocol tests."""
from __future__ import annotations

from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from scripts.dev_cluster import DevCluster
from hobnail.client import Client, Connection, PsqlTransport, TransportError
from hobnail.credentials import (CredentialBroker, CredentialError, CredentialProfile, CredentialRequest,
                                  OpenBaoCredentialProvider, PostgresCredentialProvider, Secret)


class NativeCredentialTests(unittest.TestCase):
    """No provider mocks: password auth, live sessions, expiry and revocation."""

    sequence = itertools.count(1000)

    @classmethod
    def setUpClass(cls) -> None:
        cls.cluster = DevCluster()
        try:
            cls.cluster.start()
            cls.cluster.psql("CREATE ROLE hobnail_owner NOLOGIN; GRANT CREATE ON DATABASE hobnail_test TO hobnail_owner;")
            cls.cluster.psql("SET ROLE hobnail_owner;\n" + (ROOT / "migrations/001_hobnail.sql").read_text())
            cls.cluster.psql("SET ROLE hobnail_owner;\n" + (ROOT / "migrations/002_credentials.sql").read_text())
            # This is a newly created, session-owned cluster. Strengthen its
            # generated trust configuration for real password/expiry probes.
            (cls.cluster.data_dir / "pg_hba.conf").write_text(
                "local all postgres trust\nlocal all all scram-sha-256\n", encoding="utf-8")
            cls.cluster.psql("ALTER SYSTEM SET log_statement='all';")
            cls.cluster.psql("SELECT pg_reload_conf();")
            for _ in range(30):
                if cls.cluster.psql("SHOW log_statement").stdout.strip() == "all":
                    break
                time.sleep(0.02)
            else:
                raise AssertionError("owned cluster statement logging did not activate")
            cls.admin = PsqlTransport(Connection(str(cls.cluster.socket_dir), cls.cluster.database,
                                                  "postgres", port=cls.cluster.port, sslmode="disable"),
                                      psql=str(cls.cluster.bin_dir / "psql"))
        except BaseException:
            cls.cluster.stop()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.cluster.stop()

    def setUp(self) -> None:
        self.profile = CredentialProfile("worker", frozenset({"worker-a"}), "worker", 60, 120, True)
        self.provider = PostgresCredentialProvider(self.admin, provider_id="native-provider", profiles={"worker": self.profile})

    def request(self, ttl: int = 30) -> CredentialRequest:
        return CredentialRequest(next(self.sequence), "worker", "worker-a", "worker", ttl)

    def transport(self, lease, *, password: str | None = None) -> PsqlTransport:
        return PsqlTransport(replace(self.admin.connection, user=lease.login,
                                    password=lease.password.reveal() if password is None else password),
                             psql=self.admin.psql)

    def active_session(self, lease) -> subprocess.Popen:
        env = {"LC_ALL": "C", "PGPASSFILE": os.devnull, "PGSERVICEFILE": os.devnull,
               "PGSYSCONFDIR": str(self.cluster.root), "PGPASSWORD": lease.password.reveal()}
        process = subprocess.Popen([self.admin.psql, "-X", "-w", "-q", "-t", "-A", "-h",
                                    str(self.cluster.socket_dir), "-p", str(self.cluster.port), "-U",
                                    lease.login, "-d", self.cluster.database, "-c", "SELECT pg_sleep(30)"],
                                   env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(100):
            if self.provider.observe(lease.lease_ref).active_sessions == 1:
                return process
            if process.poll() is not None:
                process.communicate()
                self.fail("synthetic active session did not connect")
            time.sleep(0.01)
        process.terminate()
        process.communicate(timeout=5)
        self.fail("synthetic active session was not observed")

    def test_fresh_password_authentication_exact_grants_and_no_privileged_attributes(self) -> None:
        lease = self.provider.issue(self.request())
        self.assertTrue(lease.created_at.endswith("+00:00"))
        self.assertTrue(lease.issued_payload()["expires_at"].endswith("Z"))
        self.assertEqual(self.transport(lease).execute_sql("SELECT session_user").strip(), lease.login)
        with self.assertRaises(TransportError):
            self.transport(lease, password="deliberately-wrong").execute_sql("SELECT 1")
        fields = self.admin.execute_sql(
            "SELECT rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,"
            "(SELECT count(*) FROM pg_auth_members WHERE member=r.oid),"
            "has_schema_privilege(rolname,'hobnail','USAGE'),"
            "has_function_privilege(rolname,'hobnail.api(text,jsonb)','EXECUTE') "
            f"FROM pg_roles r WHERE rolname='{lease.login}'").strip()
        self.assertEqual(fields, "f|f|f|f|f|0|t|t")
        with self.assertRaises(TransportError):
            self.transport(lease).execute_sql("SELECT * FROM hobnail.principals")
        with self.assertRaises(TransportError):
            self.transport(lease).execute_sql("SET ROLE hobnail_owner")
        self.assertEqual(self.provider.revoke(lease.lease_ref).result, "confirmed")

    def test_principal_role_profile_and_ttl_are_owner_scoped_before_issue(self) -> None:
        request = self.request()
        for bad in (replace(request, principal="worker-b"), replace(request, role="verifier"),
                    replace(request, profile="verifier"), replace(request, ttl_seconds=61)):
            with self.subTest(request=bad), self.assertRaises(CredentialError):
                self.provider.issue(bad)
        self.assertFalse(any(item.request_id == request.request_id for item in self.provider.inventory()))

    def test_issue_retry_reuses_material_and_changed_scope_refuses(self) -> None:
        request = self.request()
        lease = self.provider.issue(request)
        self.assertIs(self.provider.issue(request), lease)
        with self.assertRaises(CredentialError):
            self.provider.issue(replace(request, ttl_seconds=20))
        self.provider.revoke(lease.lease_ref)
        with self.assertRaises(CredentialError):
            self.provider.issue(request)

    def test_renewal_is_bounded_and_revocation_prevents_renewal(self) -> None:
        lease = self.provider.issue(self.request(10))
        renewed = self.provider.renew(lease.lease_ref, 30)
        self.assertGreater(renewed.expires_at, lease.expires_at)
        with self.assertRaises(CredentialError):
            self.provider.renew(lease.lease_ref, 5)
        with self.assertRaises(CredentialError):
            self.provider.renew(lease.lease_ref, 61)
        narrowed = replace(self.profile, max_ttl_seconds=30, max_lifetime_seconds=30)
        strict = PostgresCredentialProvider(self.admin, provider_id="native-provider", profiles={"worker": narrowed})
        with self.assertRaises(CredentialError):
            strict.renew(lease.lease_ref, 30)
        self.provider.revoke(lease.lease_ref)
        with self.assertRaises(CredentialError):
            self.provider.renew(lease.lease_ref, 10)

    def test_expiry_denies_new_authentication_but_existing_session_needs_revocation(self) -> None:
        lease = self.provider.issue(self.request(2))
        process = self.active_session(lease)
        try:
            self.admin.execute_sql("SELECT pg_sleep(2.1)")
            with self.assertRaises(TransportError):
                self.transport(lease).execute_sql("SELECT 1")
            before = self.provider.observe(lease.lease_ref)
            self.assertEqual(before.result, "pending")
            self.assertEqual(before.active_sessions, 1)
            after = self.provider.revoke(lease.lease_ref)
            self.assertEqual((after.result, after.login_enabled, after.active_sessions), ("confirmed", False, 0))
            process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0)
            with self.assertRaises(TransportError):
                self.transport(lease).execute_sql("SELECT 1")
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)

    def test_restart_recovers_only_safe_metadata_and_can_revoke_active_sessions(self) -> None:
        request = self.request()
        lease = self.provider.issue(request)
        process = self.active_session(lease)
        restarted = PostgresCredentialProvider(self.admin, provider_id="native-provider", profiles={"worker": self.profile})
        try:
            recovered = next(item for item in restarted.inventory() if item.lease_ref == lease.lease_ref)
            self.assertIsNone(recovered.password)
            with self.assertRaises(CredentialError):
                restarted.issue(request)
            self.assertEqual(restarted.revoke(lease.lease_ref).result, "confirmed")
            process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0)
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)

    def test_no_arbitrary_login_or_other_provider_revocation(self) -> None:
        lease = self.provider.issue(self.request())
        other = PostgresCredentialProvider(self.admin, provider_id="other-provider", profiles={"worker": self.profile})
        for bad in ("postgres", "pg:postgres:" + "a" * 32, lease.lease_ref[:-1] + ("a" if lease.lease_ref[-1] != "a" else "b")):
            with self.subTest(reference=bad), self.assertRaises(CredentialError):
                self.provider.revoke(bad)
        with self.assertRaises(CredentialError):
            other.revoke(lease.lease_ref)
        self.assertEqual(self.transport(lease).execute_sql("SELECT 1").strip(), "1")
        self.provider.revoke(lease.lease_ref)

    def test_secret_absent_from_repr_payload_recovery_metadata_and_statement_log(self) -> None:
        lease = self.provider.issue(self.request())
        secret = lease.password.reveal()
        self.assertNotIn(secret, repr(lease))
        self.assertNotIn(secret, str(lease.password))
        self.assertNotIn(secret, json.dumps(lease.issued_payload()))
        self.assertNotIn(secret, repr(self.provider.inventory()))
        log = (self.cluster.root / "server.log").read_text()
        self.assertIn("COPY pg_temp.hobnail_credential_material", log)
        self.assertIn("CREATE ROLE %I LOGIN", log)
        self.assertNotIn(secret, log)
        self.assertNotIn("SCRAM-SHA-256$4096:", log)
        self.provider.revoke(lease.lease_ref)

    def test_kernel_broker_issuance_renewal_and_revoke_use_actual_restricted_logins(self) -> None:
        worker_profile = CredentialProfile("broker-worker", frozenset({"broker-worker-principal"}), "worker", 60, 120, True)
        provider_profile = CredentialProfile("bootstrap-provider", frozenset({"broker-provider"}), "credential_provider", 60, 120)
        bootstrap = PostgresCredentialProvider(self.admin, provider_id="test-bootstrap", profiles={
            worker_profile.name: worker_profile, provider_profile.name: provider_profile})
        worker_lease = bootstrap.issue(CredentialRequest(1, worker_profile.name, "broker-worker-principal", "worker", 60))
        provider_lease = bootstrap.issue(CredentialRequest(2, provider_profile.name, "broker-provider", "credential_provider", 60))
        owner = Client(self.admin)
        for lease in (worker_lease, provider_lease):
            owner.require("principal.bind", {"login": lease.login, "principal": lease.principal, "role": lease.role,
                                              "contracts": [], "sources": [], "profiles": [worker_profile.name]})
        owner.require("credential.profile", {"profile": worker_profile.name, "provider": "broker-provider",
                                               "principals": ["broker-worker-principal"], "role": "worker",
                                               "max_ttl_seconds": 60, "max_lifetime_seconds": 120, "renewable": True,
                                               "capabilities": ["dynamic_postgres", "renewal", "revocation", "active_session_termination"]})
        worker = Client(self.transport(worker_lease))
        backend = PostgresCredentialProvider(self.admin, provider_id="broker-provider", profiles={worker_profile.name: worker_profile})
        broker = CredentialBroker(Client(self.transport(provider_lease)), backend)
        request = worker.require("credential.request", {"profile": worker_profile.name, "ttl_seconds": 10,
                                                          "idempotency_key": "broker-first"})["data"]
        issued = broker.issue_request(request["request_id"])
        self.assertIsInstance(issued.credential_id, int)
        rotated = Client(self.transport(issued))
        self.assertTrue(rotated.require("artifact.put", {"content_hex": "7b7d", "media_type": "application/json"})["ok"])
        with self.assertRaises(CredentialError):
            broker.issue_request(request["request_id"])
        self.assertEqual(self.transport(issued).execute_sql("SELECT 1").strip(), "1")
        with self.assertRaises(CredentialError):
            broker.revoke_requested(issued.credential_id)
        worker.require("credential.renew_requested", {"credential_id": issued.credential_id, "ttl_seconds": 30})
        renewed = broker.renew_requested(issued.credential_id)
        self.assertEqual(renewed.credential_id, issued.credential_id)
        self.assertGreater(renewed.expires_at, issued.expires_at)
        worker.require("credential.revoke_requested", {"credential_id": issued.credential_id})
        observation = broker.revoke_requested(issued.credential_id)
        self.assertEqual(observation.result, "confirmed")
        with self.assertRaises(TransportError):
            rotated.call("artifact.put", {"content_hex": "7b7d", "media_type": "application/json"})
        self.assertEqual(worker.require("credential.get", {"credential_id": issued.credential_id})["data"]["state"], "revoked")
        bootstrap.revoke(worker_lease.lease_ref)
        bootstrap.revoke(provider_lease.lease_ref)


class OpenBaoProtocolTests(unittest.TestCase):
    """Synthetic HTTP protocol only. These tests do not qualify OpenBao itself."""

    def setUp(self) -> None:
        self.calls = []
        self.responses = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.respond()

            def do_PUT(self):
                self.respond()

            def respond(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                outer.calls.append((self.command, self.path, self.headers.get("X-Vault-Token"), json.loads(body) if body else None))
                status, headers, value = outer.responses.pop(0)
                self.send_response(status)
                for key, val in headers.items():
                    self.send_header(key, val)
                self.end_headers()
                if value is not None:
                    self.wfile.write(json.dumps(value).encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.address = f"http://127.0.0.1:{self.server.server_port}"
        self.profile = CredentialProfile("worker", frozenset({"worker-a"}), "worker", 60, 120, True, "worker-role")
        self.provider = OpenBaoCredentialProvider(address=self.address, token=Secret("synthetic-controller-token"),
                                                  provider_id="openbao-provider", profiles={"worker": self.profile},
                                                  allow_insecure_loopback=True)
        self.request = CredentialRequest(1, "worker", "worker-a", "worker", 30)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def issued(self, duration=20):
        self.responses.append((200, {}, {"lease_id": "database/creds/worker-role/opaque", "lease_duration": duration,
                                        "renewable": True, "data": {"username": "synthetic_worker", "password": "synthetic-issued-secret"}}))
        return self.provider.issue(self.request)

    def test_issue_renew_revoke_reports_pending_until_downstream_observation(self) -> None:
        lease = self.issued()
        self.assertEqual(self.calls[0][:2], ("GET", "/v1/database/creds/worker-role"))
        self.assertNotIn("synthetic-issued-secret", repr(lease))
        self.responses.append((200, {}, {"lease_id": lease.lease_ref, "lease_duration": 30, "renewable": True}))
        self.assertGreater(self.provider.renew(lease.lease_ref, 30).expires_at, lease.expires_at)
        self.responses.append((204, {}, None))
        observation = self.provider.revoke(lease.lease_ref)
        self.assertEqual(observation.result, "pending")
        self.assertIsNone(observation.active_sessions)
        self.assertNotIn("confirmed_revocation", self.provider.capabilities)

    def test_scope_and_arbitrary_reference_denial_before_network(self) -> None:
        with self.assertRaises(CredentialError):
            self.provider.issue(replace(self.request, principal="worker-b"))
        with self.assertRaises(CredentialError):
            self.provider.revoke("database/creds/privileged/other")
        self.assertEqual(self.calls, [])

    def test_backend_oversized_ttl_requests_revocation_and_refuses_delivery(self) -> None:
        self.responses.extend([(200, {}, {"lease_id": "database/creds/worker-role/opaque", "lease_duration": 60,
                                         "renewable": True, "data": {"username": "synthetic_worker", "password": "synthetic-secret"}}),
                               (204, {}, None)])
        with self.assertRaises(CredentialError):
            self.provider.issue(self.request)
        self.assertEqual(self.calls[1][:2], ("PUT", "/v1/sys/leases/revoke"))

    def test_backend_cannot_redirect_issuance_or_cleanup_to_another_profile(self) -> None:
        self.responses.append((200, {}, {"lease_id": "database/creds/privileged/other", "lease_duration": 20,
                                        "renewable": True, "data": {"username": "privileged", "password": "synthetic"}}))
        with self.assertRaises(CredentialError):
            self.provider.issue(self.request)
        self.assertEqual(len(self.calls), 1)

    def test_redirect_is_not_followed_and_errors_do_not_reveal_response_secrets(self) -> None:
        self.responses.append((302, {"Location": self.address + "/redirected"}, None))
        with self.assertRaises(CredentialError):
            self.provider.issue(self.request)
        self.assertEqual(len(self.calls), 1)
        self.responses.append((403, {}, {"errors": ["synthetic-secret-in-error"]}))
        with self.assertRaises(CredentialError) as caught:
            self.provider.issue(self.request)
        self.assertNotIn("synthetic-secret-in-error", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_secure_origin_and_exact_backend_role_validation(self) -> None:
        for address in ("http://example.org", "https://user:pass@example.org", "https://example.org/path", "https://example.org?token=x"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                OpenBaoCredentialProvider(address=address, token=Secret("synthetic"), provider_id="bao", profiles={"worker": self.profile})
        with self.assertRaises(ValueError):
            replace(self.profile, backend_role="../privileged")


if __name__ == "__main__":
    unittest.main()
