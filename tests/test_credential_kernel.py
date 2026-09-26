"""Credential/control-plane integration against fresh PostgreSQL identities.

These probes use synthetic credentials and owned clusters. They establish SQL
authority and provider consequences, not OS-user or network containment.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from hobnail.client import Client, Connection, Denied, PsqlTransport
from hobnail.credentials import (
    CredentialBroker, CredentialError, CredentialProfile, CredentialRequest,
    PostgresCredentialProvider,
)
from scripts.dev_cluster import DevCluster
from scripts.install import install


class CredentialKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cluster = DevCluster()
        self.cluster.start()
        self.addCleanup(self.cluster.stop)
        install(f"host={self.cluster.socket_dir} port={self.cluster.port} "
                f"dbname={self.cluster.database} user=postgres sslmode=disable",
                psql=str(self.cluster.bin_dir / "psql"))
        self.connection = Connection(str(self.cluster.socket_dir), self.cluster.database,
                                     "postgres", port=self.cluster.port, sslmode="disable")
        self.admin_transport = PsqlTransport(self.connection, psql=str(self.cluster.bin_dir / "psql"))
        self.admin = Client(self.admin_transport)
        self.cluster.psql("CREATE ROLE cworker LOGIN; CREATE ROLE cprovider LOGIN; CREATE ROLE capprover LOGIN;")
        for login, principal, role in (
            ("cworker", "worker", "worker"),
            ("cprovider", "provider", "credential_provider"),
            ("capprover", "approver", "approver"),
        ):
            self.admin.require("principal.bind", {
                "login": login, "principal": principal, "role": role,
                "contracts": ["reports"], "sources": [], "profiles": ["worker-basic"],
            })
        self.profile_document = {
            "profile": "worker-basic", "provider": "provider", "principals": ["worker"],
            "role": "worker", "max_ttl_seconds": 60, "max_lifetime_seconds": 180,
            "renewable": True,
            "capabilities": ["dynamic_postgres", "renewal", "revocation", "active_session_termination"],
        }
        self.admin.require("credential.profile", self.profile_document)
        self.worker = self.client("cworker")
        self.provider_client = self.client("cprovider")
        self.approver = self.client("capprover")
        self.profile = CredentialProfile("worker-basic", frozenset({"worker"}), "worker", 60, 180, True)
        self.provider = PostgresCredentialProvider(self.admin_transport, provider_id="provider",
                                                   profiles={"worker-basic": self.profile})
        self.broker = CredentialBroker(self.provider_client, self.provider)
        # Base test identities use local trust; freshly issued workload logins
        # must authenticate with their actual synthetic SCRAM credential.
        (self.cluster.data_dir / "pg_hba.conf").write_text(
            "local all postgres,cworker,cprovider,capprover trust\n"
            "local all all scram-sha-256\n", encoding="utf-8")
        self.cluster.psql("SELECT pg_reload_conf();")

    def client(self, login: str, password: str | None = None) -> Client:
        return Client(PsqlTransport(replace(self.connection, user=login, password=password),
                                    psql=str(self.cluster.bin_dir / "psql")))

    def request(self, key: str = "first", ttl: int = 15) -> int:
        return self.worker.require("credential.request", {
            "profile": "worker-basic", "ttl_seconds": ttl, "idempotency_key": key,
        })["data"]["request_id"]

    def issued(self, key: str = "first", ttl: int = 15):
        request_id = self.request(key, ttl)
        lease = self.broker.issue_request(request_id)
        data = self.provider_client.require("credential.request.get", {"request_id": request_id})["data"]
        self.assertEqual(data["credential_id"], lease.credential_id)
        return lease

    def assertDenied(self, client: Client, operation: str, payload: dict, code: str) -> dict:
        response = client.call(operation, payload)
        self.assertFalse(response["ok"], response)
        self.assertEqual(response["code"], code, response)
        self.assertGreater(response["event_id"], 0)
        return response

    def test_profile_authority_request_scope_and_idempotency(self) -> None:
        self.assertDenied(self.worker, "credential.profile", self.profile_document, "FORBIDDEN")
        self.assertDenied(self.admin, "credential.profile", self.profile_document, "VERSION_CONFLICT")
        payload = {"profile": "worker-basic", "ttl_seconds": 61, "idempotency_key": "excess"}
        self.assertDenied(self.worker, "credential.request", payload, "CREDENTIAL_SCOPE")
        payload.update(ttl_seconds=15, idempotency_key="stable")
        request = self.worker.require("credential.request", payload)
        replay = self.worker.require("credential.request", payload)
        self.assertEqual(request["data"], replay["data"])
        self.assertNotEqual(request["event_id"], replay["event_id"])
        self.assertDenied(self.worker, "credential.request", dict(payload, ttl_seconds=16), "IDEMPOTENCY_CONFLICT")
        self.assertDenied(self.approver, "credential.request", dict(payload, idempotency_key="other"), "CREDENTIAL_SCOPE")
        self.assertDenied(self.worker, "credential.request.get", {"request_id": request["data"]["request_id"]}, "FORBIDDEN")

    def test_native_broker_maps_rotations_to_same_principal_and_renews(self) -> None:
        lease = self.issued()
        self.assertIsNotNone(lease.password)
        worker = self.client(lease.login, lease.password.reveal())
        metadata = worker.require("credential.get", {"credential_id": lease.credential_id})["data"]
        self.assertEqual(metadata["principal"], "worker")
        self.assertEqual(metadata["role"], "worker")
        self.assertEqual(metadata["state"], "active")
        self.assertDenied(worker, "credential.profile", self.profile_document, "FORBIDDEN")
        self.worker.require("credential.renew_requested", {"credential_id": lease.credential_id, "ttl_seconds": 40})
        pending = self.provider_client.require("credential.get", {"credential_id": lease.credential_id})["data"]
        self.assertEqual(pending["renewal_ttl"], 40)
        renewed = self.broker.renew_requested(lease.credential_id)
        self.assertEqual(renewed.credential_id, lease.credential_id)
        self.assertGreater(datetime.fromisoformat(renewed.expires_at), datetime.fromisoformat(lease.expires_at))
        observed = self.provider_client.require("credential.get", {"credential_id": lease.credential_id})["data"]
        self.assertIsNone(observed["renewal_ttl"])
        second = self.issued("rotation")
        self.assertNotEqual(second.login, lease.login)
        self.assertEqual(second.principal, lease.principal)
        with self.assertRaises(CredentialError):
            self.broker.issue_request(lease.request_id)

    def test_unproven_role_and_direct_table_grant_cannot_be_registered(self) -> None:
        request_id = self.request()
        lease = self.provider.issue(CredentialRequest(request_id, "worker-basic", "worker", "worker", 15))
        self.cluster.psql(f'GRANT SELECT ON hobnail.credential_requests TO "{lease.login}";')
        self.assertDenied(self.provider_client, "credential.issued", lease.issued_payload(), "CREDENTIAL_SCOPE")
        self.cluster.psql(f'REVOKE SELECT ON hobnail.credential_requests FROM "{lease.login}";')
        self.cluster.psql(f'COMMENT ON ROLE "{lease.login}" IS NULL;')
        self.assertDenied(self.provider_client, "credential.issued", lease.issued_payload(), "CREDENTIAL_SCOPE")

    def test_issued_scope_is_derived_and_reuse_is_refused(self) -> None:
        lease = self.issued()
        self.assertDenied(self.provider_client, "credential.issued", lease.issued_payload(), "ALREADY_RECORDED")
        other_request = self.request("second")
        altered = dict(lease.issued_payload(), request_id=other_request)
        self.assertDenied(self.provider_client, "credential.issued", altered, "CREDENTIAL_SCOPE")
        altered = dict(lease.issued_payload(), role="approver")
        self.assertDenied(self.provider_client, "credential.issued", altered, "INVALID_REQUEST")

    def test_renewal_requires_real_role_expiry_and_a_pending_request(self) -> None:
        lease = self.issued()
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
        payload = {"credential_id": lease.credential_id, "expires_at": expiry}
        self.assertDenied(self.provider_client, "credential.renewed", payload, "INVALID_REQUEST")
        self.worker.require("credential.renew_requested", {"credential_id": lease.credential_id, "ttl_seconds": 40})
        self.assertDenied(self.provider_client, "credential.renewed", payload, "CREDENTIAL_SCOPE")
        self.broker.renew_requested(lease.credential_id)
        self.assertDenied(self.worker, "credential.renew_requested", {"credential_id": lease.credential_id, "ttl_seconds": 61}, "CREDENTIAL_SCOPE")

    def test_revocation_records_pending_failure_and_real_downstream_consequence(self) -> None:
        lease = self.issued()
        credential = {"credential_id": lease.credential_id}
        confirmed = dict(credential, result="confirmed", receipt={"claim": "revoked"})
        self.assertDenied(self.provider_client, "credential.revoked", confirmed, "INVALID_REQUEST")
        self.worker.require("credential.revoke_requested", credential)
        worker = self.client(lease.login, lease.password.reveal())
        self.assertDenied(worker, "credential.get", credential, "UNAUTHENTICATED")
        self.assertDenied(self.provider_client, "credential.revoked", confirmed, "REVOCATION_PENDING")
        result = self.provider_client.require("credential.revoked", dict(credential, result="failed", receipt={"reason": "controlled outage"}))
        self.assertEqual(result["data"]["state"], "revocation_failed")
        # A retry is a fresh explicit request; failure is not erased.
        self.worker.require("credential.revoke_requested", credential)
        observed = self.broker.revoke_requested(lease.credential_id)
        self.assertEqual(observed.result, "confirmed")
        self.assertFalse(observed.login_enabled)
        self.assertEqual(observed.active_sessions, 0)
        current = self.provider_client.require("credential.get", credential)["data"]
        self.assertEqual(current["state"], "revoked")
        evidence = self.cluster.psql("SET ROLE hobnail_owner; SELECT detail->>'result' FROM hobnail.credential_events "
                                     f"WHERE credential_id={lease.credential_id} AND operation='credential.revoked' ORDER BY id;").stdout.splitlines()
        self.assertEqual(evidence, ["failed", "confirmed"])

    def test_expiry_denies_an_already_connected_transaction(self) -> None:
        lease = self.issued(ttl=3)
        transport = self.client(lease.login, lease.password.reveal()).transport
        # The connection is admitted while its SCRAM credential is valid;
        # the API checks wall-clock expiry after that connection already exists.
        sql = ("BEGIN; SELECT pg_sleep(3.1); SELECT hobnail.api('credential.get',"
               f"jsonb_build_object('credential_id',{lease.credential_id})); COMMIT;")
        result = json.loads(transport.execute_sql(sql).strip())
        self.assertEqual(result["code"], "UNAUTHENTICATED")
        self.assertFalse(result["ok"])

    def test_qualification_records_are_append_only_evidence_not_authority(self) -> None:
        payload = {
            "configuration_digest": "a" * 64,
            "checks": [{"id": "worker.cannot-write", "result": "pass", "evidence": {"probe": "actual restricted login"}}],
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        }
        self.assertDenied(self.worker, "qualification.record", payload, "FORBIDDEN")
        result = self.approver.require("qualification.record", payload)
        self.assertFalse(result["data"]["grants_authority"])
        duplicate = dict(payload, checks=payload["checks"] * 2)
        self.assertDenied(self.approver, "qualification.record", duplicate, "INVALID_REQUEST")
        records = self.worker.require("qualification.get", {"configuration_digest": "a" * 64})["data"]
        self.assertFalse(records["grants_authority"])
        self.assertEqual(len(records["records"]), 1)
        self.assertFalse(records["records"][0]["expired"])
        refused = self.cluster.psql("SET ROLE hobnail_owner; UPDATE hobnail.qualifications SET recorded_by='changed';", check=False)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("immutable_record", refused.stderr)


if __name__ == "__main__":
    unittest.main()
