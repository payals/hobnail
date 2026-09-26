"""Portable supervisor fault checks. No Docker daemon or image is executed."""

import copy
from contextlib import contextmanager
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts import docker_runtime as module
from scripts import docker_faults
from hobnail.client import Connection, TransportTimeout
from hobnail.isolation import ChildResult, IsolationUnavailable


class DockerSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hobnail-supervisor-test-")
        self.root = Path(self.temporary.name).resolve()
        runtime = module.DockerRuntime.__new__(module.DockerRuntime)
        runtime.root = self.root
        runtime.receipt_dir = self.root / "receipts"
        runtime.receipt_dir.mkdir(mode=0o700)
        runtime.run_id = "a" * 32
        runtime.docker = "/synthetic-not-executed/docker"
        runtime.daemon = "unix:///var/run/docker.sock"
        runtime.config_dir = self.root / "empty-config"
        runtime.images = {}
        runtime.volumes = {}
        runtime.containers = {}
        runtime.events = []
        runtime.active = True
        runtime.closed = False
        runtime.admin = None
        runtime.providers = []
        runtime._output_threads = []
        runtime.database_output = {"stdout": bytearray(), "stderr": bytearray()}
        runtime.database_output_overflow = False
        runtime._sensitive = set()
        runtime.ownership = {"run_id": runtime.run_id, "images": runtime.images,
                             "volumes": runtime.volumes, "containers": runtime.containers, "events": runtime.events}
        self.runtime = runtime

    def tearDown(self):
        self.temporary.cleanup()

    def test_fault_control_loses_only_a_completed_create_reply_once(self):
        runtime = docker_faults._FaultRuntime.__new__(docker_faults._FaultRuntime)
        runtime.lose_create_reply = True
        runtime._event = Mock()
        with patch.object(module.DockerRuntime, "_cli", return_value="a" * 64) as real_operation:
            with self.assertRaises(docker_faults.InjectedDockerFault):
                runtime._cli(["container", "create", "reviewed-fixture"])
            real_operation.assert_called_once()
            self.assertFalse(runtime.lose_create_reply)
            runtime._event.assert_called_once_with("qualification-created-reply-lost", container_id="a" * 64)
            self.assertEqual(runtime._cli(["container", "create", "reviewed-fixture"]), "a" * 64)

    def test_fault_control_does_not_claim_loss_before_live_readiness(self):
        runtime = docker_faults._FaultRuntime.__new__(docker_faults._FaultRuntime)
        runtime.lose_ready_reply = True
        runtime._event = Mock()
        @contextmanager
        def malformed(endpoint):
            raise module.DockerError("held peer positive control failed")
            yield
        with patch.object(module.DockerRuntime, "hold_endpoint", side_effect=malformed):
            with self.assertRaisesRegex(module.DockerError, "positive control failed"):
                with runtime.hold_endpoint(object()):
                    self.fail("malformed readiness was accepted")
            self.assertTrue(runtime.lose_ready_reply)
            runtime._event.assert_not_called()
        held = {"container_id": "a" * 64, "host_pid": 17, "ready_response": {"ready": True, "login": "synthetic"}}
        @contextmanager
        def validated(endpoint):
            yield held
        with patch.object(module.DockerRuntime, "hold_endpoint", side_effect=validated):
            with self.assertRaises(docker_faults.InjectedDockerFault):
                with runtime.hold_endpoint(object()):
                    self.fail("validated response was not lost")
            self.assertFalse(runtime.lose_ready_reply)
            runtime._event.assert_called_once_with("qualification-ready-reply-lost", container_id="a" * 64,
                                                   running=True, pid=17, ready_response=held["ready_response"])

    def test_import_uses_verified_bytes_even_if_release_path_changes(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                release = self.root / ("released-" + str(replacement))
                release.mkdir(mode=0o700)
                archive = release / "inert-fixture.tar"
                original = b"inert controlled archive fixture, never imported\n"
                archive.write_bytes(original)
                archive.chmod(0o400)
                digest = hashlib.sha256(original).hexdigest()
                image = "sha256:" + "b" * 64
                self.runtime.lock = {"rootfs": [{"flavor": "parser", "sha256": digest, "size": len(original)}]}
                self.runtime.archives = {"parser": archive}
                def import_response(arguments, *, payload, timeout):
                    self.assertEqual(arguments[-1], "-")
                    self.assertNotIn(str(archive), arguments)
                    if replacement:
                        other = release / "replacement"
                        other.write_bytes(b"changed path")
                        other.replace(archive)
                    else:
                        archive.chmod(0o600)
                        archive.write_bytes(b"changed file contents")
                    self.assertEqual(payload, original)
                    return image
                self.runtime._cli = Mock(side_effect=import_response)
                self.runtime._json = Mock(return_value={"Id": image, "Architecture": "arm64", "Os": "linux",
                    "Labels": {"org.hobnail.run": self.runtime.run_id, "org.hobnail.rootfs": digest},
                    "RootFS": {"Layers": ["sha256:" + digest]}})
                self.runtime._import_images()
                self.assertEqual(self.runtime.images["parser"], image)

    def test_preexisting_volume_is_never_adopted(self):
        name = "hobnail-" + self.runtime.run_id + "-data"
        self.runtime._cli = Mock(return_value=name)
        with self.assertRaisesRegex(module.DockerError, "pre-existing"):
            self.runtime._volume("data")
        self.assertEqual(self.runtime.volumes, {})
        self.assertEqual(self.runtime._cli.call_count, 1)

    def test_lost_volume_reply_records_owned_resource_and_preserves_failure(self):
        name = "hobnail-" + self.runtime.run_id + "-data"
        self.runtime._cli = Mock(side_effect=["", module.DockerError("synthetic lost reply")])
        self.runtime._json = Mock(return_value={"Name": name, "Driver": "local", "Options": None,
            "Labels": {"org.hobnail.run": self.runtime.run_id}, "Scope": "local"})
        with self.assertRaisesRegex(module.DockerError, "synthetic lost reply"):
            self.runtime._volume("data")
        self.assertTrue(self.runtime.volumes["data"]["created"])
        self.assertTrue(self.runtime.volumes["data"]["recovered_after_lost_response"])

    def test_custom_and_changed_validator_implementations_refuse_before_launch(self):
        digest = "c" * 64
        self.runtime.ownership["source"] = {"src/hobnail/_validator_worker.py": digest}
        self.runtime._execute_script = Mock(return_value=ChildResult(0, "{}", ""))
        request = {"content_hex": "7b7d", "plugin_id": "json.required_fields", "parameters": {"pointers": []}, "inputs": {}}
        with self.assertRaises(IsolationUnavailable):
            self.runtime.run_implementation(Path("not-read"), "d" * 64, json.dumps(request))
        with self.assertRaises(IsolationUnavailable):
            self.runtime.run_implementation(Path("not-read"), digest, json.dumps({**request, "plugin_id": "custom:changed"}))
        self.runtime._execute_script.assert_not_called()
        self.runtime.run_implementation(Path("inert-source-argument"), digest, json.dumps(request))
        self.runtime._execute_script.assert_called_once()

    def test_timeout_is_not_replaced_by_cleanup_error(self):
        self.runtime._create = Mock(return_value={"id": "e" * 64})
        self.runtime._remove = Mock(side_effect=module.DockerError("synthetic cleanup failure"))
        with patch.object(module, "_bounded_child", side_effect=subprocess.TimeoutExpired("synthetic", 1)):
            with self.assertRaises(TransportTimeout) as caught:
                self.runtime._run({"role": "worker"}, "{}", timeout=1)
        self.assertIn("Owned role process cleanup is incomplete.", caught.exception.__notes__)

    def test_output_overflow_stops_the_still_running_owned_container(self):
        record = {"id": "e" * 64}
        self.runtime._create = Mock(return_value=record)
        self.runtime.inspect_owned = Mock(return_value={"State": {"Running": True, "ExitCode": 0}})
        self.runtime._remove = Mock()
        failure = ChildResult(-9, "", "output_limit")
        with patch.object(module, "_bounded_child", return_value=failure):
            result = self.runtime._run({"role": "parser"}, "{}")
        self.assertEqual(result, failure)
        self.runtime._remove.assert_called_once_with(record)

    def test_known_id_cannot_be_reported_removed_when_only_renamed(self):
        record = {"name": "old-owned-name", "id": "e" * 64, "state": "created"}
        self.runtime._cli = Mock(return_value=record["id"])
        self.runtime.inspect_owned = Mock(side_effect=module.DockerError("synthetic identity mismatch"))
        with self.assertRaisesRegex(module.DockerError, "identity mismatch"):
            self.runtime._remove(record)
        self.assertIn("id=" + record["id"], self.runtime._cli.call_args.args[0])
        self.assertEqual(record["state"], "created")

    def test_cleanup_attempts_every_lease_then_retires_admin_before_stop(self):
        leases = [SimpleNamespace(login="owned_one", lease_ref="one"), SimpleNamespace(login="owned_two", lease_ref="two")]
        provider = Mock()
        provider.inventory.return_value = leases
        provider.revoke.side_effect = [ValueError("synthetic failure"), SimpleNamespace(result="confirmed", login_enabled=False, active_sessions=0)]
        self.runtime.providers = [provider]
        self.runtime.admin = Mock()
        order = []
        def admin(sql, **options):
            order.append("admin-retired")
            self.assertTrue(sql.startswith("ALTER ROLE postgres NOLOGIN;"))
            self.assertIn("backend_type='client backend'", sql)
            self.assertIn("pid<>pg_backend_pid()", sql)
            return '{"login_enabled":false,"other_client_sessions":0}'
        self.runtime.admin.execute_sql.side_effect = admin
        self.runtime.containers["database"] = {"state": "created"}
        self.runtime._remove = Mock(side_effect=lambda *args, **kwargs: order.append("stopped"))
        with self.assertRaises(module.DockerError):
            self.runtime.close()
        self.assertEqual([call.args[0] for call in provider.revoke.call_args_list], ["one", "two"])
        self.assertEqual(order, ["admin-retired", "stopped"])
        self.assertEqual(self.runtime.ownership["administrator_retirement"]["result"], "confirmed")
        self.assertEqual(self.runtime.ownership["status"], "cleanup-unconfirmed")

    def test_failed_evidence_storage_does_not_skip_owned_cleanup(self):
        self.runtime._persist_record = Mock(side_effect=OSError("synthetic storage failure"))
        self.runtime.containers["database"] = {"state": "created"}
        self.runtime._remove = Mock()
        self.runtime.admin = Mock()
        self.runtime.admin.execute_sql.return_value = '{"login_enabled":false,"other_client_sessions":0}'
        with patch.object(module.os, "open", side_effect=OSError("synthetic diagnostic write failure")):
            with self.assertRaises(module.DockerError):
                self.runtime.close()
        self.runtime._remove.assert_called_once()
        self.runtime.admin.execute_sql.assert_called_once()
        self.assertTrue(self.runtime.closed)
        self.assertFalse(self.runtime.active)
        self.assertEqual(self.runtime.ownership["status"], "cleanup-unconfirmed")
        self.assertIn("cleanup-receipt-persistence-failed", self.runtime.ownership["cleanup_failures"])

    def test_admin_api_uses_existing_core_sql_framing(self):
        endpoint = Mock(role="admin", connection=Connection(host="/run/postgresql", database="hobnail",
            user="postgres", password="synthetic-owned-password", sslmode="disable"))
        endpoint.request.return_value = {"sql_output": json.dumps({"ok": True, "status": "ok", "data": {}, "event_id": 1})}
        result = module.DockerAdminTransport(endpoint).call("principal.bind", {"login": "x'; SELECT 1; --"})
        self.assertTrue(result["ok"])
        sent = endpoint.request.call_args.args[0]
        self.assertEqual(sent["command"], "sql")
        self.assertIn("SELECT hobnail.api(convert_from(decode('", sent["sql"])
        self.assertNotIn("x'; SELECT 1; --", sent["sql"])

    def test_container_policy_rejects_extra_authority_before_start(self):
        policy = {"image": "sha256:" + "f" * 64, "uid": 10003, "role": "worker", "ipc": "none",
                  "pids": 32, "memory": 512 * 1024 * 1024, "shm": 64 * 1024 * 1024,
                  "command": ["-I", "-S", "-B", "/opt/hobnail/docker/role.py"], "mounts": [],
                  "profile": json.loads((ROOT / "docker/seccomp-role-arm64.json").read_text())}
        record = {"name": "owned-synthetic-container", "id": "9" * 64, "policy": policy}
        identity = {"Id": record["id"], "Name": "/" + record["name"], "Image": policy["image"],
                    "Labels": {"org.hobnail.run": self.runtime.run_id}, "State": {"Running": False, "ExitCode": 0}}
        valid = {"Id": record["id"], "Name": identity["Name"], "Image": policy["image"], "Mounts": [],
            "Config": {"Labels": identity["Labels"], "User": "10003:10003", "Entrypoint": ["/usr/local/bin/python3.14"],
                       "Cmd": policy["command"], "Env": ["TMPDIR=/scratch", "LANG=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin"],
                       "OpenStdin": True, "StdinOnce": True, "Tty": False},
            "HostConfig": {"Privileged": False, "ReadonlyRootfs": True, "NetworkMode": "none", "PidMode": "",
                "IpcMode": "none", "CgroupnsMode": "private", "UsernsMode": "", "CapAdd": None, "CapDrop": ["ALL"],
                "Memory": policy["memory"], "MemorySwap": policy["memory"], "PidsLimit": 32, "NanoCpus": 1_000_000_000, "PortBindings": {},
                "Runtime": "runc", "UTSMode": "", "RestartPolicy": {"Name": "no"}, "LogConfig": {"Type": "none"},
                "SecurityOpt": ["no-new-privileges", "seccomp=" + json.dumps(policy["profile"])], "GroupAdd": ["20000"],
                "Tmpfs": {target: "rw,nosuid,nodev,noexec,size=67108864,mode=0700,uid=10003,gid=10003" for target in ("/scratch", "/tmp")},
                "ShmSize": policy["shm"]}}
        self.runtime._json = Mock(side_effect=[identity, [valid]])
        self.runtime.inspect_owned(record)
        # Engine 29.8.0 was observed returning the same three exact values in
        # different orders. Order grants no authority; extra/duplicate values do.
        for environment in itertools.permutations(valid["Config"]["Env"]):
            reordered = copy.deepcopy(valid)
            reordered["Config"]["Env"] = list(environment)
            self.runtime._json = Mock(side_effect=[identity, [reordered]])
            self.runtime.inspect_owned(record)
        changes = [("HostConfig", "Devices", [{"PathOnHost": "/dev/synthetic"}]),
                   ("HostConfig", "ExtraHosts", ["synthetic:host-gateway"]),
                   ("HostConfig", "IpcMode", "private"), ("HostConfig", "UTSMode", "host"),
                   ("HostConfig", "GroupAdd", ["20000", "0"]),
                   ("HostConfig", "SecurityOpt", ["no-new-privileges", "seccomp=" + json.dumps(policy["profile"]), "apparmor=unconfined"]),
                   ("Config", "Env", valid["Config"]["Env"] + ["PGPASSWORD=synthetic"]),
                   ("Config", "Env", ["TMPDIR=/scratch", "LANG=C.UTF-8", "LANG=C.UTF-8"]),
                   ("Config", "Tty", True)]
        for section, key, value in changes:
            with self.subTest(section=section, key=key):
                changed = copy.deepcopy(valid)
                changed[section][key] = value
                self.runtime._json = Mock(side_effect=[identity, [changed]])
                with self.assertRaises(module.DockerError):
                    self.runtime.inspect_owned(record)


if __name__ == "__main__":
    unittest.main()
