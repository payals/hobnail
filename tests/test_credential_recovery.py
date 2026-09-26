"""Transport-loss recovery against real committed credential operations."""

import unittest

import test_credential_kernel as fixture
from hobnail.client import TransportError
from hobnail.credentials import CredentialBroker, CredentialRequest, PostgresCredentialProvider


class LostReply:
    def __init__(self, client, operation):
        self.client, self.operation = client, operation
        self.lost = False

    def require(self, operation, payload):
        result = self.client.require(operation, payload)
        if operation == self.operation and not self.lost:
            self.lost = True
            raise TransportError("controlled loss after real commit")
        return result


class CredentialRecoveryTests(unittest.TestCase):
    setUp = fixture.CredentialKernelTests.setUp
    client = fixture.CredentialKernelTests.client
    request = fixture.CredentialKernelTests.request

    def test_lost_registration_reply_reconciles_real_revocation_and_metadata(self):
        request = self.request()
        broker = CredentialBroker(LostReply(self.provider_client, "credential.issued"), self.provider)
        with self.assertRaises(TransportError):
            broker.issue_request(request)
        issued = self.provider_client.require("credential.request.get", {"request_id": request})["data"]
        state = self.provider_client.require("credential.get", {"credential_id": issued["credential_id"]})["data"]
        self.assertEqual("revoked", state["state"])
        self.assertEqual("confirmed", self.provider.observe(state["lease_ref"]).result)

    def test_lost_renewal_reply_reconciles_real_revocation_and_metadata(self):
        lease = self.broker.issue_request(self.request())
        self.worker.require("credential.renew_requested", {"credential_id": lease.credential_id, "ttl_seconds": 30})
        broker = CredentialBroker(LostReply(self.provider_client, "credential.renewed"), self.provider)
        with self.assertRaises(TransportError):
            broker.renew_requested(lease.credential_id)
        state = self.provider_client.require("credential.get", {"credential_id": lease.credential_id})["data"]
        self.assertEqual("revoked", state["state"])
        self.assertEqual("confirmed", self.provider.observe(lease.lease_ref).result)

    def test_restart_can_reconcile_issued_but_unregistered_native_credential(self):
        request = self.request()
        lease = self.provider.issue(CredentialRequest(request, "worker-basic", "worker", "worker", 15))
        restarted = PostgresCredentialProvider(self.admin_transport, provider_id="provider",
                                              profiles={"worker-basic": self.profile})
        broker = CredentialBroker(self.provider_client, restarted)
        observation = broker.reconcile_request(request)
        self.assertEqual("confirmed", observation.result)
        self.assertEqual("confirmed", restarted.observe(lease.lease_ref).result)
        self.assertFalse(self.provider_client.require("credential.request.get", {"request_id": request})["data"]["issued"])

    def test_repeating_completed_revocation_observes_without_rewriting_history(self):
        lease = self.broker.issue_request(self.request())
        self.worker.require("credential.revoke_requested", {"credential_id": lease.credential_id})
        first = self.broker.revoke_requested(lease.credential_id)
        second = self.broker.revoke_requested(lease.credential_id)
        self.assertEqual("confirmed", first.result)
        self.assertEqual("confirmed", second.result)
        records = self.cluster.psql("SELECT count(*) FROM hobnail.credential_events "
            f"WHERE credential_id={lease.credential_id} AND operation='credential.revoked'")
        self.assertEqual("1", records.stdout.strip())


if __name__ == "__main__":
    unittest.main()
