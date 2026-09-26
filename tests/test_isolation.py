"""Actual macOS sandbox effects, using only synthetic files and owned sockets.

Socket allocation is not network access. Every network assertion attempts a
real effect against a listener owned by this test and checks that no effect
arrived. These probes do not establish a general hostile-code sandbox.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hobnail.isolation import IsolationUnavailable, run_restricted


class IsolationTests(unittest.TestCase):
    def run_script(self, source, payload=None):
        with tempfile.TemporaryDirectory(prefix="hbn-sandbox-script-") as directory:
            script = Path(directory) / "probe.py"
            script.write_text(source, encoding="utf-8")
            result = run_restricted(script, json.dumps(payload or {}))
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

    def test_controlled_child_parses_data_without_parent_environment_or_handles(self):
        with tempfile.TemporaryFile() as parent_file:
            parent_file.write(b"synthetic-parent-only")
            parent_file.seek(0)
            os.set_inheritable(parent_file.fileno(), True)
            with patch.dict(os.environ, {"HOBNAIL_SYNTHETIC_SECRET": "synthetic-parent-only"}):
                result = self.run_script(
                    "import hashlib, json, os, sys\n"
                    "request = json.load(sys.stdin)\n"
                    "try: os.read(request['fd'], 1); inherited = True\n"
                    "except OSError: inherited = False\n"
                    "print(json.dumps({'digest': hashlib.sha256(request['value'].encode()).hexdigest(), "
                    "'environment_visible': 'HOBNAIL_SYNTHETIC_SECRET' in os.environ, "
                    "'handle_inherited': inherited, 'site_loaded': 'site' in sys.modules}))\n",
                    {"fd": parent_file.fileno(), "value": "controlled-data"},
                )
        self.assertEqual(result, {
            "digest": hashlib.sha256(b"controlled-data").hexdigest(),
            "environment_visible": False, "handle_inherited": False, "site_loaded": False,
        })

    def test_synthetic_credentials_writes_symlinks_and_forks_are_denied(self):
        with tempfile.TemporaryDirectory(prefix="hbn-sandbox-synthetic-") as directory:
            root = Path(directory)
            credentials = root / "synthetic-home" / ".ssh"
            credentials.mkdir(parents=True)
            secret = credentials / "synthetic-key"
            secret.write_text("synthetic-parent-only", encoding="utf-8")
            output = root / "forbidden-output"
            result = self.run_script(
                "import json, os, pathlib, sys\n"
                "request = json.load(sys.stdin); results = {}\n"
                "link = pathlib.Path('escape'); link.symlink_to(request['secret'])\n"
                "operations = {\n"
                " 'read': lambda: pathlib.Path(request['secret']).read_bytes(),\n"
                " 'metadata': lambda: pathlib.Path(request['secret']).stat(),\n"
                " 'write': lambda: pathlib.Path(request['output']).write_text('forbidden'),\n"
                " 'symlink_read': lambda: link.read_bytes(),\n"
                " 'symlink_write': lambda: link.write_text('forbidden'),\n"
                " 'change_validator': lambda: pathlib.Path(__file__).write_text('forbidden'),\n"
                "}\n"
                "for name, operation in operations.items():\n"
                " try: operation(); results[name] = False\n"
                " except PermissionError: results[name] = True\n"
                "try:\n"
                " pid = os.fork()\n"
                " if pid == 0: os._exit(0)\n"
                " os.waitpid(pid, 0); results['fork'] = False\n"
                "except PermissionError: results['fork'] = True\n"
                "print(json.dumps(results))\n",
                {"secret": str(secret), "output": str(output)},
            )
            self.assertEqual(result, {name: True for name in (
                "read", "metadata", "write", "symlink_read", "symlink_write", "change_validator", "fork",
            )})
            self.assertFalse(output.exists())
            self.assertEqual(secret.read_text(encoding="utf-8"), "synthetic-parent-only")

    def test_actual_tcp_udp_and_unix_effects_are_denied(self):
        with tempfile.TemporaryDirectory(prefix="hbn-net-", dir="/tmp") as directory:
            unix_path = str(Path(directory) / "owned.sock")
            with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp, \
                    socket.socket(socket.AF_UNIX) as unix:
                tcp.bind(("127.0.0.1", 0)); tcp.listen(1)
                udp.bind(("127.0.0.1", 0))
                unix.bind(unix_path); unix.listen(1)
                for listener in (tcp, udp, unix):
                    listener.settimeout(0.05)
                result = self.run_script(
                    "import json, socket, sys\n"
                    "request = json.load(sys.stdin); results = {}\n"
                    "with socket.socket() as channel:\n"
                    " results['socket_allocated'] = True\n"
                    " try: channel.connect(('127.0.0.1', request['tcp'])); results['tcp_denied'] = False\n"
                    " except PermissionError: results['tcp_denied'] = True\n"
                    "with socket.socket(type=socket.SOCK_DGRAM) as channel:\n"
                    " try: channel.sendto(b'synthetic-probe', ('127.0.0.1', request['udp'])); results['udp_denied'] = False\n"
                    " except PermissionError: results['udp_denied'] = True\n"
                    "with socket.socket(socket.AF_UNIX) as channel:\n"
                    " try: channel.connect(request['unix']); results['unix_denied'] = False\n"
                    " except PermissionError: results['unix_denied'] = True\n"
                    "print(json.dumps(results))\n",
                    {"tcp": tcp.getsockname()[1], "udp": udp.getsockname()[1], "unix": unix_path},
                )
                self.assertEqual(result, {
                    "socket_allocated": True, "tcp_denied": True, "udp_denied": True, "unix_denied": True,
                })
                with self.assertRaises(TimeoutError):
                    tcp.accept()
                with self.assertRaises(TimeoutError):
                    udp.recvfrom(100)
                with self.assertRaises(TimeoutError):
                    unix.accept()

    def test_parent_signaling_and_process_inspection_are_denied(self):
        # Positive control: this process can inspect its own synthetic process
        # information and signal itself with signal zero (no signal is sent).
        os.kill(os.getpid(), 0)
        proc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        buffer = ctypes.create_string_buffer(512)
        self.assertGreater(proc.proc_pidinfo(os.getpid(), 3, 0, buffer, len(buffer)), 0)
        result = self.run_script(
            "import ctypes, json, os, sys\n"
            "parent = json.load(sys.stdin)['parent']; results = {}\n"
            "try: os.kill(parent, 0); results['signal_denied'] = False\n"
            "except PermissionError: results['signal_denied'] = True\n"
            "proc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)\n"
            "buffer = ctypes.create_string_buffer(512)\n"
            "results['pidinfo_denied'] = proc.proc_pidinfo(parent, 3, 0, buffer, len(buffer)) == 0 and ctypes.get_errno() == 1\n"
            "system = ctypes.CDLL('/usr/lib/libSystem.B.dylib')\n"
            "task = ctypes.c_uint.in_dll(system, 'mach_task_self_').value\n"
            "port = ctypes.c_uint(0)\n"
            "status = system.task_for_pid(task, parent, ctypes.byref(port))\n"
            "results['task_port_denied'] = status != 0\n"
            "if status == 0: system.mach_port_deallocate(task, port.value)\n"
            "print(json.dumps(results))\n",
            {"parent": os.getpid()},
        )
        self.assertEqual(result, {"signal_denied": True, "pidinfo_denied": True, "task_port_denied": True})

    def test_unsupported_backend_fails_closed(self):
        with patch("hobnail.isolation.platform.system", return_value="unsupported"):
            with self.assertRaises(IsolationUnavailable):
                run_restricted(__file__, "{}")


if __name__ == "__main__":
    unittest.main()
