"""Actual owned local child checks for opt-in bounded PostgreSQL transport I/O."""
from pathlib import Path
import os
import sys
import tempfile
import unittest

from hobnail.client import Connection, PasswordAuthenticationFailed, PsqlTransport, TransportOutputLimit, TransportTimeout


class BoundedClientTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="hbn-client-limits-")).resolve()
        self.root.chmod(0o700)
        self.pid = self.root / "pid"

    def command(self, body, *, timeout=2, limit=1024):
        script = self.root / "owned-psql-fixture"
        script.write_text("#!" + sys.executable + "\nimport os,sys,time\nfrom pathlib import Path\n"
                          + "Path(" + repr(str(self.pid)) + ").write_text(str(os.getpid()))\n" + body)
        script.chmod(0o700)
        return PsqlTransport(Connection("/explicit-owned-fixture", "fixture", "worker", sslmode="disable"),
                             psql=str(script), timeout=timeout, max_output_bytes=limit)

    def assert_reaped(self):
        pid = int(self.pid.read_text())
        with self.assertRaises(ChildProcessError): os.waitpid(pid, os.WNOHANG)
        with self.assertRaises(ProcessLookupError): os.kill(pid, 0)

    def test_complete_stdout_and_stderr_are_drained_with_explicit_input(self):
        transport = self.command("payload=sys.stdin.read()\nsys.stderr.write('bounded diagnostic')\nsys.stdout.write(payload)\n")
        self.assertEqual(transport.execute_sql("SELECT synthetic;\n"), "SELECT synthetic;\n")
        self.assert_reaped()

    def test_stdout_overflow_kills_and_reaps_actual_owned_child(self):
        transport = self.command("sys.stdout.write('private-output-'*100000)\nsys.stdout.flush()\ntime.sleep(60)\n", limit=128)
        with self.assertRaises(TransportOutputLimit) as caught: transport.execute_sql("SELECT synthetic;")
        self.assertNotIn("private-output", str(caught.exception))
        self.assert_reaped()

    def test_stderr_overflow_is_bounded_and_redacted(self):
        transport = self.command("sys.stderr.write('private-error-'*100000)\nsys.stderr.flush()\ntime.sleep(60)\n")
        with self.assertRaises(TransportOutputLimit) as caught: transport.execute_sql("SELECT synthetic;")
        self.assertNotIn("private-error", str(caught.exception))
        self.assert_reaped()

    def test_timeout_kills_and_reaps_actual_owned_child(self):
        transport = self.command("time.sleep(60)\n", timeout=0.5)
        with self.assertRaises(TransportTimeout): transport.execute_sql("SELECT synthetic;")
        self.assert_reaped()

    def test_blocked_stdin_is_covered_by_the_same_deadline(self):
        transport = self.command("time.sleep(60)\n", timeout=0.5)
        with self.assertRaises(TransportTimeout): transport.execute_sql("x" * (2 * 1024 * 1024))
        self.assert_reaped()

    def test_bounded_password_rejection_keeps_typed_semantics(self):
        transport = self.command("sys.stderr.write('FATAL:  password authentication failed for user \\\"fixture\\\"\\n')\nsys.exit(2)\n")
        with self.assertRaises(PasswordAuthenticationFailed): transport.execute_sql("SELECT 1;")
        self.assert_reaped()

    def test_limit_requires_an_exact_bounded_integer(self):
        for value in (True, 0, -1, "1024", 1.5, 64 * 1024 * 1024 + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                PsqlTransport(Connection("/fixture", "fixture", "worker", sslmode="disable"),
                              psql=sys.executable, max_output_bytes=value)


if __name__ == "__main__":
    unittest.main()
