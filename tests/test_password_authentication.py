"""Distinguish actual password rejection from unavailable connection evidence."""

from dataclasses import replace
from pathlib import Path
import secrets
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from hobnail.client import Connection, PasswordAuthenticationFailed, PsqlTransport, TransportError, TransportTimeout
from scripts.dev_cluster import DevCluster
from scripts.qualified_local import QualificationError, secure_admin


class PasswordClassificationTests(unittest.TestCase):
    def transport(self):
        with patch("hobnail.client.shutil.which", return_value="/reviewed/psql"):
            return PsqlTransport(Connection("explicit-server", "owned-database", "generated-role", sslmode="disable"))

    def test_only_actual_fatal_password_rejection_gets_redacted_subtype(self):
        diagnostic = ('psql: error: connection to server on socket "/private/runtime/socket" failed: '
                      'FATAL:  password authentication failed for user "generated-role"\n')
        result = subprocess.CompletedProcess([], 2, "", diagnostic)
        with patch("hobnail.client.subprocess.run", return_value=result), self.assertRaises(PasswordAuthenticationFailed) as caught:
            self.transport().execute_sql("SELECT session_user")
        self.assertEqual(str(caught.exception), "PostgreSQL rejected password authentication")
        self.assertNotIn("private", str(caught.exception))
        self.assertNotIn("generated-role", str(caught.exception))

    def test_outage_tls_unknown_locale_and_query_errors_are_not_password_denials(self):
        failures = [
            (2, "psql: error: connection timed out\n"),
            (2, "psql: error: SSL certificate verify failed\n"),
            (2, "FATAL:  no pg_hba.conf entry for host\n"),
            (2, "FATAL:  password authentication failed for user unquoted\n"),
            (2, 'ERROR: password authentication failed for user "generated-role"\n'),
            (3, 'FATAL:  password authentication failed for user "generated-role"\n'),
            (2, 'NOTICE: FATAL:  password authentication failed for user "generated-role"\n'),
        ]
        for status, stderr in failures:
            with self.subTest(stderr=stderr), patch("hobnail.client.subprocess.run",
                    return_value=subprocess.CompletedProcess([], status, "", stderr)):
                with self.assertRaises(TransportError) as caught:
                    self.transport().execute_sql("SELECT session_user")
                self.assertNotIsInstance(caught.exception, PasswordAuthenticationFailed)

    def test_process_timeout_remains_unknown_and_does_not_retry(self):
        with patch("hobnail.client.subprocess.run", side_effect=subprocess.TimeoutExpired([], 1)) as run:
            with self.assertRaises(TransportTimeout):
                self.transport().execute_sql("SELECT session_user")
            self.assertEqual(run.call_count, 1)


class ActualPasswordAuthenticationTests(unittest.TestCase):
    def test_bootstrap_transport_failure_cannot_satisfy_its_negative_control(self):
        with DevCluster() as cluster:
            transport = PsqlTransport(Connection(str(cluster.socket_dir), cluster.database, "postgres", sslmode="disable"),
                                      psql=str(cluster.bin_dir / "psql"))
            original = PsqlTransport.execute_sql
            attempts = []
            def unavailable(instance, sql, **kwargs):
                if sql == "SELECT session_user":
                    attempts.append(sql)
                    raise TransportError("controlled connection outage")
                return original(instance, sql, **kwargs)
            with patch.object(PsqlTransport, "execute_sql", unavailable):
                with self.assertRaisesRegex(QualificationError, "administrator_authentication_inconclusive"):
                    secure_admin(cluster, transport)
            self.assertEqual(len(attempts), 1)

    def test_real_scram_wrong_password_and_stopped_server_are_distinct(self):
        with DevCluster() as cluster:
            transport = PsqlTransport(Connection(str(cluster.socket_dir), cluster.database, "postgres", sslmode="disable"),
                                      psql=str(cluster.bin_dir / "psql"))
            admin = secure_admin(cluster, transport)
            wrong = PsqlTransport(replace(admin.connection, password=secrets.token_urlsafe(36)), psql=admin.psql)
            with self.assertRaises(PasswordAuthenticationFailed):
                wrong.execute_sql("SELECT session_user")
            self.assertEqual(admin.execute_sql("SELECT session_user").strip(), "postgres")
            cluster.stop()
            with self.assertRaises(TransportError) as caught:
                wrong.execute_sql("SELECT session_user")
            self.assertNotIsInstance(caught.exception, PasswordAuthenticationFailed)


if __name__ == "__main__":
    unittest.main()
