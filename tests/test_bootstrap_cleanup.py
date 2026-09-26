"""Real generated-role recovery after controlled bootstrap failures."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.dev_cluster import DevCluster
from scripts.install import install
from scripts.local_demo import _bootstrap
from hobnail.client import Client, Connection, PsqlTransport
from hobnail.credentials import CredentialError, CredentialProfile, CredentialRequest, PostgresCredentialProvider


class BootstrapCleanupTests(unittest.TestCase):
    def setUp(self):
        self.cluster = DevCluster()
        self.cluster.start()
        self.addCleanup(self.cluster.stop)
        install(f"host={self.cluster.socket_dir} port={self.cluster.port} dbname={self.cluster.database} user=postgres",
                psql=str(self.cluster.bin_dir / "psql"))
        self.admin = PsqlTransport(Connection(str(self.cluster.socket_dir), self.cluster.database, "postgres", sslmode="disable"),
                                   psql=str(self.cluster.bin_dir / "psql"))

    def test_later_binding_failure_revokes_owned_roles_and_preserves_other_issuer(self):
        other = PostgresCredentialProvider(self.admin, provider_id="separate-owner", profiles={
            "other": CredentialProfile("other", frozenset({"other"}), "worker")})
        existing = other.issue(CredentialRequest(1, "other", "other", "worker", 60))
        original = Client.require
        bindings = []

        def fail_second(client, operation, payload=None):
            if operation == "principal.bind":
                bindings.append(payload["login"])
                if len(bindings) == 2:
                    raise RuntimeError("controlled second binding failure")
            return original(client, operation, payload)

        try:
            with patch.object(Client, "require", fail_second):
                with self.assertRaisesRegex(RuntimeError, "controlled second binding failure"):
                    _bootstrap(self.cluster, self.admin, ["bootstrap-case"])
            self.assertEqual(2, len(bindings))
            for login in bindings:
                self.assertEqual("f", self.cluster.psql(f"SELECT rolcanlogin FROM pg_roles WHERE rolname='{login}'").stdout.strip())
            self.assertEqual("active", other.observe(existing.lease_ref).result)
        finally:
            other.revoke(existing.lease_ref)

    def test_committed_issue_with_lost_reply_is_recovered_from_owned_metadata(self):
        original = PostgresCredentialProvider._json

        def lose_reply(provider, sql, **kwargs):
            result = original(provider, sql, **kwargs)
            if "CREATE TEMP TABLE hobnail_credential_material" in sql:
                raise CredentialError("controlled lost issuance reply")
            return result

        with patch.object(PostgresCredentialProvider, "_json", lose_reply):
            with self.assertRaisesRegex(CredentialError, "controlled lost issuance reply"):
                _bootstrap(self.cluster, self.admin, ["bootstrap-case"])
        counts = self.cluster.psql("SELECT count(*),count(*) FILTER (WHERE rolcanlogin) FROM pg_roles WHERE rolname ~ '^hn_[0-9a-f]{32}$'")
        self.assertEqual("1|0", counts.stdout.strip())


if __name__ == "__main__":
    unittest.main()
