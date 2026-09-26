"""Resource and exact-implementation probes using synthetic reviewed scripts."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hobnail.isolation import IsolationUnavailable, run_implementation, run_restricted


class PluginRuntimeTests(unittest.TestCase):
    def run_script(self, code, payload="", **kwargs):
        with tempfile.TemporaryDirectory(prefix="hobnail-plugin-probe-") as directory:
            source = Path(directory).resolve() / "plugin.py"
            source.write_text(code, encoding="utf-8")
            source.chmod(0o600)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            return run_implementation(source, digest, payload, **kwargs)

    def test_stdout_and_stderr_overflow_are_bounded_failures(self):
        for stream in ("stdout", "stderr"):
            for count in (32769, 1000000):
                with self.subTest(stream=stream, count=count):
                    result = self.run_script(f"import sys\nsys.{stream}.write('x' * {count})\n")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "output_limit")

    def test_full_output_pipes_and_maximum_input_do_not_deadlock(self):
        result = self.run_script(
            "import sys\n"
            "sys.stdout.write('o' * 32000); sys.stdout.flush()\n"
            "sys.stderr.write('e' * 32768); sys.stderr.flush()\n"
            "value = sys.stdin.buffer.read()\n"
            "sys.stdout.write(str(len(value)))\n", "x" * 36_000_000)
        self.assertEqual(result.returncode, 0, result.stderr[:100])
        self.assertEqual(result.stdout, "o" * 32000 + "36000000")
        self.assertEqual(result.stderr, "e" * 32768)

    def test_timeout_kills_and_reaps_owned_process(self):
        actual_popen = subprocess.Popen
        processes = []

        def record_process(*args, **kwargs):
            process = actual_popen(*args, **kwargs)
            if args and args[0][0] == "/usr/bin/sandbox-exec":
                processes.append(process)
                self.assertTrue(kwargs["close_fds"])
                self.assertTrue(kwargs["start_new_session"])
            return process

        with patch("hobnail.isolation.subprocess.Popen", side_effect=record_process):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_script("import time\ntime.sleep(10)\n", timeout=0.2)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())

    def test_snapshot_executes_approved_bytes_after_original_changes(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-plugin-snapshot-") as directory:
            source = Path(directory).resolve() / "plugin.py"
            approved = b"print('approved')\n"
            source.write_bytes(approved)
            source.chmod(0o600)
            digest = hashlib.sha256(approved).hexdigest()
            actual_run = run_restricted
            snapshots = []

            def mutate_original(snapshot, payload, **kwargs):
                snapshots.append(Path(snapshot))
                self.assertNotEqual(Path(snapshot), source)
                self.assertEqual(Path(snapshot).read_bytes(), approved)
                self.assertEqual(stat.S_IMODE(Path(snapshot).stat().st_mode), 0o400)
                source.write_bytes(b"print('changed')\n")
                return actual_run(snapshot, payload, **kwargs)

            with patch("hobnail.isolation.run_restricted", side_effect=mutate_original):
                result = run_implementation(source, digest, "")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "approved\n")
            self.assertFalse(snapshots[0].exists())
            self.assertEqual(source.read_text(), "print('changed')\n")

    def test_snapshot_is_not_writable_or_readable_via_original_source_path(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-plugin-boundary-") as directory:
            root = Path(directory).resolve()
            source = root / "plugin.py"
            code = (
                "import json, pathlib\n"
                "result = {}\n"
                f"for name, operation in [('source', lambda: pathlib.Path({str(source)!r}).read_bytes()), "
                "('snapshot', lambda: pathlib.Path(__file__).write_text('changed'))]:\n"
                " try: operation(); result[name] = False\n"
                " except PermissionError: result[name] = True\n"
                "pathlib.Path('scratch').write_text('allowed')\n"
                "result['scratch'] = pathlib.Path('scratch').read_text() == 'allowed'\n"
                "print(json.dumps(result))\n"
            )
            source.write_text(code)
            source.chmod(0o600)
            result = run_implementation(source, hashlib.sha256(source.read_bytes()).hexdigest(), "")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {"source": True, "snapshot": True, "scratch": True})
            self.assertEqual(source.read_text(), code)

    def test_digest_alias_permissions_and_oversized_sources_fail_before_execution(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-plugin-source-") as directory:
            root = Path(directory).resolve()
            source = root / "plugin.py"
            source.write_text("print('approved')\n")
            source.chmod(0o600)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            with self.assertRaises(IsolationUnavailable):
                run_implementation(source, "0" * 64, "")
            alias = root / "alias.py"
            alias.symlink_to(source)
            with self.assertRaises(IsolationUnavailable):
                run_implementation(alias, digest, "")
            source.chmod(0o666)
            with self.assertRaises(IsolationUnavailable):
                run_implementation(source, digest, "")
            source.chmod(0o600)
            source.write_bytes(b"x" * 1_048_577)
            with self.assertRaises(IsolationUnavailable):
                run_implementation(source, digest, "")

    def test_non_utf8_output_and_oversized_payload_cannot_enter_controller_json(self):
        result = self.run_script("import sys\nsys.stdout.buffer.write(b'\\xff')\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "invalid_output_encoding")
        with self.assertRaises(ValueError):
            self.run_script("print('unused')\n", "x" * 36_000_001)


if __name__ == "__main__":
    unittest.main()
