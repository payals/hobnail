"""Actual service sandbox boundaries using only task-created files and listeners."""
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hobnail.isolation import IsolationUnavailable
from hobnail.service_isolation import ServicePolicy, run_service


class ServiceIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hbn-svc-", dir="/tmp")
        self.root = Path(self.temporary.name).resolve()
        self.script = self.root / "service.py"
        self.script.write_text("print('unused')\n")
        self.config = self.root / "own.json"
        self.config.write_text('{"synthetic":"own-credential"}')
        self.config.chmod(0o600)
        self.peer = self.root / "peer.json"
        self.peer.write_text('{"synthetic":"peer-credential"}')
        self.peer.chmod(0o600)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir(mode=0o700)
        self.socket_path = self.root / "allowed.sock"
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.socket_path))
        self.listener.listen(1)
        self.listener.settimeout(0.1)
        self.policy = ServicePolicy("worker", self.script, self.config, self.scratch, self.socket_path)

    def tearDown(self):
        self.listener.close()
        self.temporary.cleanup()

    def run_script(self, code, payload=None, **changes):
        self.script.write_text(code)
        result = run_service(replace(self.policy, **changes), json.dumps(payload or {}))
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_exact_unix_socket_works_while_sibling_and_tcp_are_denied(self):
        sibling_path = self.root / "sibling.sock"
        with socket.socket(socket.AF_UNIX) as sibling, socket.socket() as tcp:
            sibling.bind(str(sibling_path)); sibling.listen(1); sibling.settimeout(0.05)
            tcp.bind(("127.0.0.1", 0)); tcp.listen(1); tcp.settimeout(0.05)
            result = self.run_script(
                "import json,socket,sys\n"
                "p=json.load(sys.stdin); result={}\n"
                "with socket.socket(socket.AF_UNIX) as c:\n"
                " c.connect(p['allowed']); c.sendall(b'allowed'); result['allowed']=True\n"
                "for name,family,address in [('sibling',socket.AF_UNIX,p['sibling']),"
                "('tcp',socket.AF_INET,('127.0.0.1',p['tcp']))]:\n"
                " with socket.socket(family) as c:\n"
                "  try: c.connect(address); result[name]=False\n"
                "  except PermissionError: result[name]=True\n"
                "print(json.dumps(result))\n",
                {"allowed": str(self.socket_path), "sibling": str(sibling_path), "tcp": tcp.getsockname()[1]})
            self.assertEqual(result, {"allowed": True, "sibling": True, "tcp": True})
            connection, _ = self.listener.accept()
            with connection:
                self.assertEqual(connection.recv(100), b"allowed")
            with self.assertRaises(TimeoutError): sibling.accept()
            with self.assertRaises(TimeoutError): tcp.accept()

    def test_own_config_read_scratch_write_peer_files_and_parent_inspection_denied(self):
        output = self.root / "forbidden"
        with patch.dict(os.environ, {"HOBNAIL_SYNTHETIC_SECRET": "parent-only"}):
            result = self.run_script(
                "import ctypes,json,os,pathlib,sys\n"
                "p=json.load(sys.stdin); result={}\n"
                "result['own']=json.loads(pathlib.Path(sys.argv[1]).read_text())['synthetic']=='own-credential'\n"
                "pathlib.Path('scratch-value').write_text('allowed'); result['scratch']=True\n"
                "for name,op in [('peer_read',lambda:pathlib.Path(p['peer']).read_text()),"
                "('peer_write',lambda:pathlib.Path(p['peer']).write_text('forbidden')),"
                "('outside_write',lambda:pathlib.Path(p['output']).write_text('forbidden')),"
                "('own_write',lambda:pathlib.Path(sys.argv[1]).write_text('forbidden')),"
                "('parent_signal',lambda:os.kill(p['parent'],0))]:\n"
                " try: op(); result[name]=False\n"
                " except PermissionError: result[name]=True\n"
                "lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True); b=ctypes.create_string_buffer(512)\n"
                "result['parent_info']=lib.proc_pidinfo(p['parent'],3,0,b,len(b))==0 and ctypes.get_errno()==1\n"
                "result['environment']='HOBNAIL_SYNTHETIC_SECRET' not in os.environ and 'PGPASSWORD' not in os.environ\n"
                "print(json.dumps(result))\n",
                {"peer": str(self.peer), "output": str(output), "parent": os.getpid()})
        self.assertTrue(all(result.values()), result)
        self.assertEqual(self.peer.read_text(), '{"synthetic":"peer-credential"}')
        self.assertEqual(self.config.read_text(), '{"synthetic":"own-credential"}')
        self.assertFalse(output.exists())
        self.assertEqual((self.scratch / "scratch-value").read_text(), "allowed")

    def test_observer_read_and_adapter_write_are_distinct_actual_rights(self):
        destination = self.root / "destination"
        destination.mkdir(mode=0o700)
        (destination / "file").write_text("before")
        code = (
            "import json,pathlib,sys\n"
            "p=json.load(sys.stdin); f=pathlib.Path(p['file']); result={'read':f.read_text()}\n"
            "try: f.write_text('after'); result['write']=True\n"
            "except PermissionError: result['write']=False\n"
            "print(json.dumps(result))\n")
        observed = self.run_script(code, {"file": str(destination / "file")}, role="observer", read_paths=(destination,))
        self.assertEqual(observed, {"read": "before", "write": False})
        self.assertEqual((destination / "file").read_text(), "before")
        published = self.run_script(code, {"file": str(destination / "file")}, role="adapter", write_roots=(destination,))
        self.assertEqual(published, {"read": "before", "write": True})
        self.assertEqual((destination / "file").read_text(), "after")

    def test_spawned_python_keeps_peer_denial_and_other_executable_refuses(self):
        result = self.run_script(
            "import json,subprocess,sys\n"
            "p=json.load(sys.stdin)\n"
            "code='import pathlib,sys\\ntry:pathlib.Path(sys.argv[1]).read_text();print(0)\\nexcept PermissionError:print(1)'\n"
            "child=subprocess.run([sys.executable,'-I','-S','-c',code,p['peer']],capture_output=True,text=True)\n"
            "result={'peer_denied':child.returncode==0 and child.stdout.strip()=='1'}\n"
            "try: subprocess.run(['/bin/sh','-c','exit 0'],check=True); result['shell_denied']=False\n"
            "except PermissionError: result['shell_denied']=True\n"
            "print(json.dumps(result))\n", {"peer": str(self.peer)})
        self.assertEqual(result, {"peer_denied": True, "shell_denied": True})

    def test_exact_installed_psql_and_its_reviewed_dependencies_can_execute(self):
        executable = shutil.which("psql")
        self.assertIsNotNone(executable, "the project requires installed PostgreSQL tools")
        executable = Path(executable).resolve()
        result = self.run_script(
            "import json,subprocess,sys\n"
            "p=json.load(sys.stdin)\n"
            "child=subprocess.run([p['psql'],'--version'],capture_output=True,text=True)\n"
            "print(json.dumps({'started':child.returncode==0,'postgresql':'PostgreSQL' in child.stdout}))\n",
            {"psql": str(executable)}, executables=(executable,))
        self.assertEqual(result, {"started": True, "postgresql": True})

    def test_service_output_can_exceed_parser_cap_but_stderr_remains_bounded(self):
        self.script.write_text("print('x'*40000)\n")
        result = run_service(self.policy, "{}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout), 40001)
        self.script.write_text("import sys\nsys.stderr.write('x'*32769)\n")
        result = run_service(self.policy, "{}")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "output_limit")
        self.script.write_text("import sys\nsys.stdout.buffer.write(b'x'*36000001)\n")
        result = run_service(self.policy, "{}")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "output_limit")

    def test_alias_and_overlapping_authority_refuse_before_start(self):
        alias = self.root / "alias.json"
        alias.symlink_to(self.config)
        for policy in (replace(self.policy, config=alias), replace(self.policy, write_roots=(self.root,)),
                       replace(self.policy, scratch=self.root)):
            with self.subTest(policy=policy), self.assertRaises(IsolationUnavailable):
                run_service(policy, "{}")


if __name__ == "__main__":
    unittest.main()
