"""Credential retirement counts authenticated sessions, not server daemons."""
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.dev_cluster import DevCluster
from scripts.qualified_local import secure_admin
from scripts.qualified_openbao import retire_reference_administrator
from hobnail.client import Connection, PsqlTransport, TransportError


class AdministratorRetirementTests(unittest.TestCase):
    def setUp(self):
        self.cluster = DevCluster()
        self.cluster.start()
        self.addCleanup(self.cluster.stop)
        self.admin = secure_admin(self.cluster, PsqlTransport(Connection(str(self.cluster.socket_dir),
            self.cluster.database, "postgres", sslmode="disable"), psql=str(self.cluster.bin_dir / "psql")))

    def test_background_launcher_is_not_a_credential_session_and_login_is_disabled(self):
        count = self.admin.execute_sql("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename='postgres' "
            "AND backend_type='logical replication launcher'").strip()
        self.assertEqual(count, "1")
        self.assertTrue(retire_reference_administrator(self.admin))
        with self.assertRaises(TransportError):
            self.admin.execute_sql("SELECT 1")

    def test_actual_existing_administrator_client_prevents_confirmation(self):
        environment = self.cluster._environment()
        environment["PGPASSWORD"] = self.admin.connection.password
        process = subprocess.Popen([self.admin.psql, "-X", "-w", "-h", str(self.cluster.socket_dir), "-p", "5432",
            "-U", "postgres", "-d", self.cluster.database, "-c", "SELECT pg_sleep(30)"], env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                count = self.admin.execute_sql("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename='postgres' "
                    "AND backend_type='client backend' AND pid<>pg_backend_pid()").strip()
                if count == "1":
                    break
                self.assertIsNone(process.poll())
                time.sleep(.01)
            else:
                self.fail("owned administrator client did not connect")
            self.assertFalse(retire_reference_administrator(self.admin))
            self.assertIsNone(process.poll())
            with self.assertRaises(TransportError):
                self.admin.execute_sql("SELECT 1")
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
