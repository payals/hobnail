"""Real lifecycle and connection-isolation probes; no OS-isolation claim."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.dev_cluster import ClusterError, DevCluster, MARKER


class DevClusterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cluster = DevCluster()
        try:
            cls.cluster.start()
        except BaseException:
            cls.cluster.stop()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.cluster.stop()

    def test_connections_ignore_inherited_credentials_and_network_destinations(self) -> None:
        with patch.dict(os.environ, {
            "PGHOST": "invalid.example", "PGPORT": "1", "PGUSER": "wrong_user",
            "PGDATABASE": "wrong_database", "PGPASSWORD": "synthetic-not-a-secret",
            "PGSERVICE": "missing_service", "PGPASSFILE": "/nonexistent/passwords",
            "PGSERVICEFILE": "/nonexistent/services", "PGOPTIONS": "-c transaction_read_only=on",
        }):
            result = self.cluster.psql(
                "SELECT session_user, current_database(), inet_server_addr() IS NULL;"
                "SHOW listen_addresses; SHOW unix_socket_permissions;"
            )
        self.assertEqual(result.stdout.splitlines(), ["postgres|hobnail_test|t", "", "0700"])
        self.assertEqual(stat.S_IMODE(self.cluster.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.cluster.socket_dir.stat().st_mode), 0o700)

    def test_distinct_database_connections_have_distinct_session_users(self) -> None:
        self.cluster.psql("CREATE ROLE probe_worker LOGIN; CREATE ROLE probe_verifier LOGIN;")
        self.assertEqual(self.cluster.psql("SELECT session_user", user="probe_worker").stdout.strip(), "probe_worker")
        self.assertEqual(self.cluster.psql("SELECT session_user", user="probe_verifier").stdout.strip(), "probe_verifier")
        denied = self.cluster.psql("SET ROLE probe_verifier", user="probe_worker", check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("permission denied", denied.stderr)

    def test_database_creation_and_connection_string_injection_refusal(self) -> None:
        self.cluster.create_database("probe_database")
        self.assertEqual(self.cluster.psql("SELECT current_database()", database="probe_database").stdout.strip(), "probe_database")
        with self.assertRaises(ValueError):
            self.cluster.psql("SELECT 1", database="host=invalid.example dbname=postgres")

    def test_stop_refuses_unowned_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hbn-unowned-") as directory:
            sentinel = Path(directory) / "sentinel"
            sentinel.write_text("preserve me", encoding="utf-8")
            with self.assertRaises(ClusterError):
                DevCluster.from_path(directory)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me")
        self.assertTrue(self.cluster.is_running())

    def test_stop_refuses_pidfile_pointing_at_an_unrelated_process(self) -> None:
        pretender = DevCluster()
        pretender.data_dir.mkdir(mode=0o700)
        (pretender.data_dir / "postmaster.pid").write_text(
            f"{os.getpid()}\n{pretender.data_dir}\n1\n{pretender.port}\n{pretender.socket_dir}\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ClusterError, "outside this owned cluster"):
            pretender.stop()
        self.assertTrue(self.cluster.is_running())

    def test_exception_stops_only_its_cluster_and_preserves_logs(self) -> None:
        failing = DevCluster()
        with self.assertRaisesRegex(RuntimeError, "deliberate failure"):
            with failing:
                self.assertTrue(failing.is_running())
                self.assertEqual(DevCluster.from_path(failing.root).status()["pid"], failing.status()["pid"])
                raise RuntimeError("deliberate failure")
        self.assertFalse(failing.is_running())
        self.assertTrue((failing.root / "server.log").is_file())
        self.assertTrue((failing.data_dir / "PG_VERSION").is_file())
        self.assertTrue(self.cluster.is_running())
        attached = DevCluster.from_path(failing.root)
        self.assertFalse(attached.stop())
        self.assertEqual(json.loads((failing.root / MARKER).read_text())["root"], str(failing.root))

    def test_cli_lifecycle_and_restart_preserve_created_data(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts" / "dev_cluster.py"
        created = subprocess.run(
            [sys.executable, str(script), "create"], capture_output=True, text=True, check=True,
        )
        details = json.loads(created.stdout)
        attached = DevCluster.from_path(details["root"])
        try:
            attached.psql("CREATE TABLE preserved (value integer); INSERT INTO preserved VALUES (42)")
            stopped = subprocess.run(
                [sys.executable, str(script), "stop", str(attached.root)],
                capture_output=True, text=True, check=True,
            )
            self.assertFalse(json.loads(stopped.stdout)["running"])
            attached.start()
            self.assertEqual(attached.psql("SELECT value FROM preserved").stdout.strip(), "42")
        finally:
            attached.stop()


if __name__ == "__main__":
    unittest.main()
