"""Trusted catalog names stay authoritative in sessions with temporary tables."""
from pathlib import Path
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.dev_cluster import DevCluster
from scripts.install import install
from hobnail.client import Connection, PsqlTransport


class CatalogResolutionTests(unittest.TestCase):
    def setUp(self):
        self.cluster = DevCluster()
        self.cluster.start()
        self.addCleanup(self.cluster.stop)
        self.dsn = f"host={self.cluster.socket_dir} port=5432 dbname={self.cluster.database} user=postgres sslmode=disable"
        install(self.dsn, psql=str(self.cluster.bin_dir / "psql"))
        self.cluster.psql("CREATE ROLE catalog_worker LOGIN")
        self.actor = PsqlTransport(Connection(str(self.cluster.socket_dir), self.cluster.database,
            "catalog_worker", sslmode="disable"), psql=str(self.cluster.bin_dir / "psql"))

    def test_temporary_catalog_name_cannot_change_administrative_refusal(self):
        # The request is deliberately malformed: even if an authorization bug
        # reappears, this probe cannot bind a principal or create a profile.
        result = self.actor.execute_sql("""CREATE TEMP TABLE pg_roles(rolname name,rolsuper boolean);
INSERT INTO pg_roles VALUES(session_user,true);
GRANT SELECT ON pg_roles TO hobnail_owner;
SELECT hobnail.api('credential.profile','{}'::jsonb);
""")
        response = json.loads(result.strip())
        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "FORBIDDEN")
        self.assertGreater(response["event_id"], 0)
        self.assertEqual(self.cluster.psql("SELECT count(*) FROM hobnail.credential_profiles").stdout.strip(), "0")

    def test_every_nested_function_pins_temp_last_and_reinstall_keeps_checksums(self):
        rows = self.cluster.psql("""SELECT count(*) FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='hobnail'
AND NOT coalesce(p.proconfig @> ARRAY['search_path=pg_catalog, hobnail, pg_temp'],false)""")
        self.assertEqual(rows.stdout.strip(), "0")
        before = self.cluster.psql("SELECT version,sha256 FROM hobnail.migrations ORDER BY version").stdout
        install(self.dsn, psql=str(self.cluster.bin_dir / "psql"))
        after = self.cluster.psql("SELECT version,sha256 FROM hobnail.migrations ORDER BY version").stdout
        self.assertEqual(after, before)
        self.assertEqual(len(before.strip().splitlines()), 4)

    def test_caller_temp_table_does_not_block_valid_worker_identity(self):
        binding = {"login": "catalog_worker", "principal": "catalog-worker", "role": "worker",
                   "contracts": [], "sources": [], "profiles": []}
        self.cluster.psql("SELECT hobnail.api('principal.bind','" + json.dumps(binding) + "'::jsonb)")
        result = self.actor.execute_sql("""CREATE TEMP TABLE pg_roles(unrelated_column int);
GRANT SELECT ON pg_roles TO hobnail_owner;
SELECT hobnail.api('candidate.submit','{}'::jsonb);
""")
        # Passing identity checks reaches the ordinary request validator, which
        # rejects the intentionally incomplete payload without source changes.
        response = json.loads(result.strip())
        self.assertEqual(response["code"], "INVALID_REQUEST")
        self.assertGreater(response["event_id"], 0)


if __name__ == "__main__":
    unittest.main()
