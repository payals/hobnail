#!/usr/bin/env python3
"""Explicit Docker supervisor for fresh, privately owned Hobnail resources.

Only the trusted host supervisor can use this module. It never supplies the
daemon socket to workloads. Reviewed archive release and daemon qualification
are operator responsibilities; this helper has no approval override flag.
"""

from __future__ import annotations

from dataclasses import replace
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hobnail.client import (Client, Connection, PasswordAuthenticationFailed, ProtocolError,
                            PsqlTransport, TransportError, TransportTimeout, canonical_json, parse_json,
                            validate_envelope)
from hobnail.isolation import ChildResult, IsolationUnavailable, _bounded_child, _kill_owned_child, implementation_snapshot
from hobnail.validators import BUILTINS


UIDS = {"admin": 70, "registrar": 10001, "approver": 10002, "worker": 10003,
        "verifier": 10004, "credential_provider": 10005, "adapter": 10006,
        "observer": 10007, "auditor": 10008, "parser": 10009, "database": 70}
_ID = re.compile(r"[0-9a-f]{64}")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
_INPUT = 36_000_000
_CONTAINER_ENV = {"TMPDIR=/scratch", "LANG=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin"}
_RETIRE_ADMIN_SQL = """ALTER ROLE postgres NOLOGIN;
DO $retire_admin$
DECLARE r record; deadline timestamptz := clock_timestamp() + interval '5 seconds';
BEGIN
 FOR r IN SELECT pid FROM pg_catalog.pg_stat_activity
          WHERE usename='postgres' AND backend_type='client backend' AND pid<>pg_backend_pid()
 LOOP PERFORM pg_catalog.pg_terminate_backend(r.pid); END LOOP;
 LOOP
  PERFORM pg_catalog.pg_stat_clear_snapshot();
  EXIT WHEN NOT EXISTS(SELECT FROM pg_catalog.pg_stat_activity
       WHERE usename='postgres' AND backend_type='client backend' AND pid<>pg_backend_pid());
  IF clock_timestamp() >= deadline THEN RAISE EXCEPTION 'administrator client retirement timed out'; END IF;
  PERFORM pg_catalog.pg_sleep(0.05);
 END LOOP;
END $retire_admin$;
SELECT json_build_object('login_enabled',(SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname='postgres'),
 'other_client_sessions',(SELECT count(*) FROM pg_catalog.pg_stat_activity
 WHERE usename='postgres' AND backend_type='client backend' AND pid<>pg_backend_pid()));
"""


class DockerError(RuntimeError):
    """A Docker lifecycle or policy check failed; resource state needs review."""


class DockerEndpoint:
    """One fixed role capability, constructed only by the trusted supervisor."""

    def __init__(self, runtime, role, connection, *, consumer=False):
        if role not in UIDS or role in {"parser", "database"}:
            raise ValueError("unsupported service role")
        if consumer != (role in {"adapter", "observer"}):
            raise ValueError("consumer capability does not match role")
        self.runtime, self.role, self.connection, self.consumer = runtime, role, connection, consumer

    def _config(self):
        connection = {"host": self.connection.host, "database": self.connection.database,
                      "user": self.connection.user, "port": self.connection.port,
                      "password": self.connection.password, "sslmode": self.connection.sslmode,
                      "connect_timeout": self.connection.connect_timeout}
        config = {"role": self.role, "connection": connection, "psql": "/usr/local/bin/psql"}
        if self.consumer:
            config["consumer"] = {"plugin": "file.publish", "root": "/destination"}
        return config

    def request(self, request, *, timeout=30):
        frame = canonical_json({"config": self._config(), "request": request})
        child = self.runtime.run_role(self.role, frame, timeout=timeout)
        if child.returncode:
            raise TransportError("role process exited without an authoritative result")
        try:
            response = parse_json(child.stdout)
        except (TypeError, ValueError):
            raise ProtocolError("role process returned invalid JSON") from None
        if not isinstance(response, dict):
            raise ProtocolError("role process returned a non-object")
        if "service_error" in response:
            if response == {"service_error": "PasswordAuthenticationFailed"}:
                raise PasswordAuthenticationFailed("PostgreSQL rejected password authentication")
            raise TransportError("role process refused its operation")
        return response

    def call(self, operation, payload):
        return validate_envelope(self.request({"command": "api", "operation": operation, "payload": payload}))

    def client(self):
        return Client(self)

    def dispatch(self, effect_id):
        if self.role != "adapter":
            raise ValueError("dispatch requires the configured adapter endpoint")
        return validate_envelope(self.request({"command": "file.dispatch", "effect_id": effect_id}))

    def observe(self, effect_id):
        if self.role != "observer":
            raise ValueError("observation requires the configured observer endpoint")
        return validate_envelope(self.request({"command": "file.observe", "effect_id": effect_id}))


class DockerAdminTransport(PsqlTransport):
    """Trusted bootstrap/provider SQL only; never handed to a worker."""

    def __init__(self, endpoint):
        if endpoint.role != "admin":
            raise ValueError("administrative transport requires an admin endpoint")
        self.endpoint = endpoint
        self.connection = endpoint.connection

    def execute_sql(self, sql, *, sensitive=False, timeout=60):
        response = self.endpoint.request({"command": "sql", "sql": sql}, timeout=timeout)
        if set(response) != {"sql_output"} or not isinstance(response["sql_output"], str):
            raise ProtocolError("administrative role returned an invalid SQL response")
        return response["sql_output"]

class DockerRuntime:
    """Own a fresh cluster, reviewed code snapshot and explicit role containers.

    Archive paths must refer to already authorized release copies outside the
    quarantine. Initialization does not import images or start a process.
    ``expected_engine`` and ``expected_kernel`` freeze the reviewed local daemon;
    matching strings alone do not establish security or authorize an upgrade.
    """

    def __init__(self, *, parser_archive, runtime_archive, expected_engine, expected_kernel,
                 docker=None, base_dir="/tmp", daemon="unix:///var/run/docker.sock"):
        if daemon != "unix:///var/run/docker.sock":
            raise ValueError("this configuration supports only the reviewed local Docker socket")
        command = shutil.which(str(docker or "docker"))
        if command is None:
            raise DockerError("reviewed Docker CLI is unavailable")
        self.docker = str(Path(command).resolve(strict=True))
        self.daemon = daemon
        if not all(isinstance(value, str) and value and "\x00" not in value
                   for value in (expected_engine, expected_kernel)):
            raise ValueError("explicit reviewed engine and kernel versions are required")
        self.expected_engine, self.expected_kernel = expected_engine, expected_kernel
        self.archives = {"parser": Path(parser_archive).absolute(), "runtime": Path(runtime_archive).absolute()}
        self.lock = parse_json((ROOT / "docker/images.lock.json").read_text())
        self.run_id = uuid.uuid4().hex
        self.root = Path(tempfile.mkdtemp(prefix="hbn-docker-", dir=base_dir)).resolve()
        self.root.chmod(0o700)
        if any(character in str(self.root) for character in (",", "\n", "\r", "\x00")):
            raise ValueError("runtime path cannot be represented as an exact Docker mount")
        self.config_dir = self.root / "docker-config"
        self.config_dir.mkdir(mode=0o700)
        # Keep journal storage separate from transport scratch. A journal I/O
        # failure must not disable the temporary input streams used to revoke
        # credentials and stop already-owned containers.
        self.receipt_dir = self.root / "receipts"
        self.receipt_dir.mkdir(mode=0o700)
        self.snapshot = self.root / "source"
        self.profile_dir = self.root / "profiles"
        self.profile_dir.mkdir(mode=0o700)
        self.images = {}
        self.volumes = {}
        self.containers = {}
        self.providers = []
        self.admin = None
        self.active = False
        self.closed = False
        self.database_container = None
        self.database_output = {"stdout": bytearray(), "stderr": bytearray()}
        self.database_output_overflow = False
        self._output_threads = []
        self._sensitive = set()
        self.events = []
        self.ownership = {"run_id": self.run_id, "images": self.images, "volumes": self.volumes,
                          "containers": self.containers, "events": self.events, "status": "prepared"}
        self._persist()

    def _persist(self):
        try:
            self._persist_record()
        except OSError:
            if not getattr(self, "_closing", False):
                raise
            # Cleanup must keep attempting its already-owned revocations/stops
            # when evidence storage fails. The failure remains fatal to a
            # qualification result and is retained in memory for the caller's
            # independently handled fallback receipt.
            self._cleanup_storage_failure = True
            self.ownership["persistence_failed_during_cleanup"] = True

    def _persist_record(self):
        path = self.receipt_dir / "ownership.json"
        temporary = self.receipt_dir / (".ownership-" + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(canonical_json(self.ownership) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)

    def _event(self, operation, **data):
        self.events.append({"operation": operation, **data})
        self._persist()

    def _cli(self, arguments, *, payload=b"", timeout=30, limit=32768):
        args = [self.docker, "--config", str(self.config_dir), "--host", self.daemon, *arguments]
        child = _bounded_child(args, payload, directory=str(self.root), timeout=timeout,
                               stdout_limit=limit, stderr_limit=32768)
        if child.returncode:
            # Do not retain arbitrary diagnostics or stdin: they can include
            # runtime material. These facts distinguish command failure from a
            # successful empty response without suppressing the failed attempt.
            self.events.append({"operation": "docker-cli-failed", "command": arguments[:2],
                                "exit_code": child.returncode, "stderr_bytes": len(child.stderr.encode()),
                                "diagnostic": child.stderr if child.stderr in {"output_limit", "invalid_output_encoding"}
                                else "docker-command-error"})
            self._persist()
            raise DockerError("owned Docker operation failed; inspect retained resource state")
        return child.stdout.strip()

    def _json(self, arguments, *, limit=1_048_576):
        return parse_json(self._cli(arguments, limit=limit))

    def _snapshot(self):
        self.snapshot.mkdir(mode=0o700)
        files = sorted((ROOT / "src/hobnail").rglob("*.py"))
        files += [ROOT / "scripts/install.py", *sorted((ROOT / "migrations").glob("[0-9][0-9][0-9]_*.sql"))]
        files += [ROOT / "scripts" / name for name in ("docker_runtime.py", "qualified_docker.py", "docker_faults.py")]
        files += [ROOT / "docker" / name for name in ("role.py", "database.py", "psql_owned.py", "probe.py", "parser_probe.py")]
        files += [ROOT / "docker/images.lock.json", *sorted((ROOT / "docker").glob("seccomp-*-arm64.json"))]
        hashes = {}
        for source in files:
            if source.resolve(strict=True) != source or not source.is_file():
                raise DockerError("reviewed runtime source must be a canonical regular file")
            relative = source.relative_to(ROOT)
            target = self.snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            data = source.read_bytes()
            target.write_bytes(data)
            target.chmod(0o555 if source.name == "psql_owned.py" else 0o444)
            hashes[relative.as_posix()] = hashlib.sha256(data).hexdigest()
        for directory in sorted((path for path in self.snapshot.rglob("*") if path.is_dir()), reverse=True):
            directory.chmod(0o555)
        self.snapshot.chmod(0o555)
        for profile in self.lock["profiles"]:
            content = (ROOT / "docker" / profile["path"]).read_bytes()
            if hashlib.sha256(content).hexdigest() != profile["sha256"]:
                raise DockerError("reviewed profile digest differs from its lock")
            path = self.profile_dir / profile["path"]
            path.write_bytes(content)
            path.chmod(0o444)
        self.ownership["source"] = hashes
        self._persist()

    def _import_images(self):
        quarantine = (Path.home() / ".codex/quarantine").resolve()
        for record in self.lock["rootfs"]:
            kind, expected = record["flavor"], record["sha256"]
            path = self.archives[kind]
            if path.resolve(strict=True) != path or path.is_relative_to(quarantine) or not path.is_file():
                raise DockerError("use a canonical authorized release copy outside quarantine")
            parent = path.parent.stat()
            if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
                raise DockerError("released archive requires an owner-controlled parent directory")
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o022
                        or info.st_size != record["size"]):
                    raise DockerError("released archive ownership, permissions or size differs")
                content = stream.read(record["size"] + 1)
                after = os.fstat(stream.fileno())
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if identity(info) != identity(after) or len(content) != record["size"]:
                raise DockerError("released archive changed during verification")
            if hashlib.sha256(content).hexdigest() != expected:
                raise DockerError("released archive digest differs from the reviewed lock")
            if not _IMAGE.fullmatch("sha256:" + expected):
                raise DockerError("released archive ownership, permissions or size differs")
            self._event("image-import-intended", flavor=kind, rootfs_sha256=expected)
            try:
                image = self._cli(["image", "import", "--platform", "linux/arm64",
                                   "--change", f"LABEL org.hobnail.run={self.run_id}",
                                   "--change", f"LABEL org.hobnail.rootfs={expected}", "-"],
                                  payload=content, timeout=60)
            except BaseException as primary:
                # An import can commit before the CLI response is lost. Record
                # only images matching this unique run and exact rootfs label.
                try:
                    found = self._cli(["image", "ls", "--quiet", "--no-trunc", "--filter",
                                       f"label=org.hobnail.run={self.run_id}", "--filter",
                                       f"label=org.hobnail.rootfs={expected}"]).splitlines()
                    if len(set(found)) == 1 and _IMAGE.fullmatch(found[0]):
                        self.images[kind] = found[0]
                        self._persist()
                except Exception:
                    primary.add_note("Owned image import reconciliation is incomplete.")
                raise
            if not _IMAGE.fullmatch(image):
                raise DockerError("Docker did not return an exact imported image ID")
            self.images[kind] = image
            self._persist()
            facts = self._json(["image", "inspect", "--format",
                               '{"Id":{{json .Id}},"Architecture":{{json .Architecture}},"Os":{{json .Os}},'
                               '"Labels":{{json .Config.Labels}},"RootFS":{{json .RootFS}}}', image])
            if (facts["Id"] != image or facts["Architecture"] != "arm64" or facts["Os"] != "linux"
                    or facts["Labels"].get("org.hobnail.run") != self.run_id
                    or facts["Labels"].get("org.hobnail.rootfs") != expected
                    or facts["RootFS"].get("Layers") != ["sha256:" + expected]):
                raise DockerError("imported image differs from the reviewed root filesystem")

    def _volume(self, name):
        value = f"hobnail-{self.run_id}-{name}"
        existing = self._cli(["volume", "ls", "--format", "{{.Name}}", "--filter", "name=" + value]).splitlines()
        if value in existing:
            raise DockerError("refusing a pre-existing volume with the intended name")
        self.volumes[name] = {"name": value, "created": False, "prior_absence_observed": True}
        self._persist()
        try:
            created = self._cli(["volume", "create", "--label", f"org.hobnail.run={self.run_id}", value])
        except BaseException as primary:
            try:
                self._inspect_volume(name)
                self.volumes[name].update(created=True, recovered_after_lost_response=True)
                self._persist()
            except Exception:
                primary.add_note("Owned volume creation remains unconfirmed.")
            raise
        if created != value:
            raise DockerError("Docker returned an unexpected volume")
        self.volumes[name]["created"] = True
        self._persist()
        self._inspect_volume(name)
        return value

    def _inspect_volume(self, name):
        record = self.volumes[name]
        facts = self._json(["volume", "inspect", "--format",
                           '{"Name":{{json .Name}},"Driver":{{json .Driver}},"Options":{{json .Options}},'
                           '"Labels":{{json .Labels}},"Scope":{{json .Scope}}}', record["name"]])
        if (not record.get("prior_absence_observed") or facts["Name"] != record["name"]
                or facts["Driver"] != "local" or facts["Options"] not in (None, {})
                or facts["Labels"] != {"org.hobnail.run": self.run_id} or facts["Scope"] != "local"):
            raise DockerError("volume identity or driver authority differs")
        return facts

    def policy(self, role, *, script=None):
        if role not in UIDS:
            raise ValueError("unknown role")
        parser = role == "parser"
        kind = "parser" if parser else "runtime"
        profile = "database" if role == "database" else "parser" if parser else "role"
        profile_path = self.profile_dir / f"seccomp-{profile}-arm64.json"
        mounts = []
        if parser:
            if script is None:
                raise ValueError("parser requires an immutable reviewed implementation")
            mounts.append({"type": "bind", "source": str(script), "target": "/implementation.py", "read_only": True})
        else:
            mounts.append({"type": "bind", "source": str(self.snapshot), "target": "/opt/hobnail", "read_only": True})
            mounts.append({"type": "volume", "source": self.volumes["socket"]["name"],
                           "target": "/run/postgresql", "read_only": role != "database"})
            if role == "database":
                mounts.append({"type": "volume", "source": self.volumes["data"]["name"],
                               "target": "/var/lib/postgresql", "read_only": False})
            if role in {"adapter", "observer"}:
                mounts.append({"type": "volume", "source": self.volumes["destination"]["name"],
                               "target": "/destination", "read_only": role == "observer"})
        return {"role": role, "uid": UIDS[role], "image": self.images[kind], "mounts": mounts,
                "profile_path": str(profile_path), "profile": parse_json(profile_path.read_text()),
                "pids": 64 if role == "database" else 32, "memory": 512 * 1024 * 1024,
                "ipc": "private" if role == "database" else "none", "shm": 64 * 1024 * 1024,
                "command": ["-I", "-S", "-B", "/implementation.py" if parser else
                            "/opt/hobnail/docker/database.py" if role == "database" else "/opt/hobnail/docker/role.py"]}

    def _create(self, policy):
        for mount in policy["mounts"]:
            if mount["type"] == "volume":
                name = next(key for key, record in self.volumes.items() if record["name"] == mount["source"])
                self._inspect_volume(name)
        self.assert_snapshot()
        name = f"hobnail-{self.run_id}-{policy['role']}-{uuid.uuid4().hex[:8]}"
        record = {"name": name, "id": None, "policy": policy, "state": "intended"}
        self.containers[name] = record
        self._persist()
        uid = policy["uid"]
        args = ["container", "create", "--pull", "never", "-i", "--name", name, "--label", f"org.hobnail.run={self.run_id}",
                "--read-only", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
                "--security-opt", "seccomp=" + policy["profile_path"], "--user", f"{uid}:{uid}",
                "--pids-limit", str(policy["pids"]), "--memory", str(policy["memory"]), "--cpus", "1",
                "--memory-swap", str(policy["memory"]),
                "--ipc", policy["ipc"], "--shm-size", str(policy["shm"]), "--runtime", "runc",
                "--cgroupns", "private", "--restart", "no", "--log-driver", "none",
                "--stop-signal", "SIGINT", "--stop-timeout", "5", "--env", "TMPDIR=/scratch",
                "--env", "LANG=C.UTF-8", "--env", "PATH=/usr/local/bin:/usr/bin:/bin",
                "--entrypoint", "/usr/local/bin/python3.14"]
        for target in ("/scratch", "/tmp"):
            args += ["--tmpfs", f"{target}:rw,nosuid,nodev,noexec,size=67108864,mode=0700,uid={uid},gid={uid}"]
        if policy["role"] != "parser":
            args += ["--group-add", "20000"]
        if policy["role"] in {"adapter", "observer"}:
            args += ["--group-add", "20001"]
        for mount in policy["mounts"]:
            value = f"type={mount['type']},src={mount['source']},dst={mount['target']}"
            args += ["--mount", value + (",readonly" if mount["read_only"] else "")]
        args += [policy["image"], *policy["command"]]
        try:
            identity = self._cli(args)
            if not _ID.fullmatch(identity):
                raise DockerError("Docker returned an invalid container identity")
            record.update(id=identity, state="created")
            self._persist()
            self.inspect_owned(record)
            return record
        except BaseException as primary:
            try:
                self._remove(record, tolerate_missing=True)
            except Exception:
                primary.add_note("Owned container creation cleanup is incomplete.")
            raise

    def inspect_owned(self, record, *, validate_policy=True):
        policy = record["policy"]
        facts = self._json(["container", "inspect", "--format",
                           '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
                           '"Labels":{{json .Config.Labels}},"State":{{json .State}}}', record["id"] or record["name"]])
        if (facts["Name"] != "/" + record["name"] or facts["Image"] != policy["image"]
                or facts["Labels"].get("org.hobnail.run") != self.run_id
                or (record["id"] is not None and facts["Id"] != record["id"])):
            raise DockerError("container does not match the ownership journal")
        record["id"] = facts["Id"]
        if not validate_policy:
            return facts
        facts = self._json(["container", "inspect", record["id"]])[0]
        host, config = facts["HostConfig"], facts["Config"]
        environment = config.get("Env") or []
        exact_environment = len(environment) == len(_CONTAINER_ENV) and set(environment) == _CONTAINER_ENV
        if (facts["Name"] != "/" + record["name"] or facts["Image"] != policy["image"]
                or config.get("Labels", {}).get("org.hobnail.run") != self.run_id
                or config.get("User") != f"{policy['uid']}:{policy['uid']}"
                or config.get("Entrypoint") != ["/usr/local/bin/python3.14"]
                or config.get("Cmd") != policy["command"] or host.get("Privileged")
                or not host.get("ReadonlyRootfs") or host.get("NetworkMode") != "none"
                or host.get("PidMode") not in ("", "private") or host.get("IpcMode") != policy["ipc"]
                or host.get("CgroupnsMode") != "private" or host.get("UsernsMode") not in ("", "private")
                or host.get("CapAdd") or host.get("CapDrop") != ["ALL"]
                or host.get("Memory") != policy["memory"] or host.get("MemorySwap") != policy["memory"]
                or host.get("PidsLimit") != policy["pids"]
                or host.get("NanoCpus") != 1_000_000_000 or host.get("PortBindings")
                or host.get("Devices") or host.get("DeviceRequests") or host.get("DeviceCgroupRules")
                or host.get("VolumesFrom") or host.get("Links") or host.get("ExtraHosts") or host.get("Binds")
                or host.get("Runtime") != "runc" or host.get("UTSMode") != ""
                or host.get("RestartPolicy", {}).get("Name") != "no"
                or not exact_environment
                or not config.get("OpenStdin") or not config.get("StdinOnce") or config.get("Tty")
                or host.get("LogConfig", {}).get("Type") != "none"):
            # Retain nonsecret metadata so a refused policy can be diagnosed
            # after its stopped container is removed. Never retain Env values.
            self._event("container-policy-refused", role=policy["role"], observation={
                "user": config.get("User"), "entrypoint_matches": config.get("Entrypoint") == ["/usr/local/bin/python3.14"],
                "command_matches": config.get("Cmd") == policy["command"],
                "environment_matches": exact_environment,
                "environment_names": [item.split("=", 1)[0] for item in config.get("Env", [])],
                "environment_exact_unordered": len(config.get("Env", [])) == 3 and set(config.get("Env", [])) ==
                    {"TMPDIR=/scratch", "LANG=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin"},
                "open_stdin": config.get("OpenStdin"), "stdin_once": config.get("StdinOnce"), "tty": config.get("Tty"),
                "privileged": host.get("Privileged"), "readonly_root": host.get("ReadonlyRootfs"),
                "network": host.get("NetworkMode"), "pid": host.get("PidMode"), "ipc": host.get("IpcMode"),
                "cgroup_namespace": host.get("CgroupnsMode"), "user_namespace": host.get("UsernsMode"),
                "cap_add": host.get("CapAdd"), "cap_drop": host.get("CapDrop"),
                "memory": host.get("Memory"), "memory_swap": host.get("MemorySwap"), "pids_limit": host.get("PidsLimit"),
                "nano_cpus": host.get("NanoCpus"), "runtime": host.get("Runtime"), "uts": host.get("UTSMode"),
                "extra_devices": bool(host.get("Devices") or host.get("DeviceRequests") or host.get("DeviceCgroupRules")),
                "extra_mounts_or_links": bool(host.get("VolumesFrom") or host.get("Links") or host.get("ExtraHosts") or host.get("Binds")),
                "published_ports": bool(host.get("PortBindings")), "restart": host.get("RestartPolicy", {}).get("Name"),
                "log_driver": host.get("LogConfig", {}).get("Type")})
            raise DockerError("container identity or authority differs from the intended policy")
        options = host.get("SecurityOpt") or []
        if len(options) != 2 or not any(value in {"no-new-privileges", "no-new-privileges=true"} for value in options):
            raise DockerError("container lacks no-new-privileges")
        seccomp = [value.split("=", 1)[1] for value in options if value.startswith("seccomp=")]
        if len(seccomp) != 1 or parse_json(seccomp[0]) != policy["profile"]:
            raise DockerError("container seccomp policy differs from the reviewed profile")
        actual = {(mount["Type"], mount.get("Name") if mount["Type"] == "volume" else mount["Source"],
                   mount["Destination"], not mount["RW"]) for mount in facts["Mounts"] if mount["Type"] in {"bind", "volume"}}
        expected = {(m["type"], m["source"], m["target"], m["read_only"]) for m in policy["mounts"]}
        if actual != expected:
            raise DockerError("container mount authority differs from the intended policy")
        if any(mount.get("Propagation", "") not in ("", "rprivate") for mount in facts["Mounts"]):
            raise DockerError("container has shared mount propagation")
        groups = ["20000"] if policy["role"] != "parser" else []
        if policy["role"] in {"adapter", "observer"}:
            groups.append("20001")
        if (host.get("GroupAdd") or []) != groups:
            raise DockerError("container supplementary groups differ")
        uid = policy["uid"]
        expected_tmpfs = {target: f"rw,nosuid,nodev,noexec,size=67108864,mode=0700,uid={uid},gid={uid}"
                          for target in ("/scratch", "/tmp")}
        if host.get("Tmpfs") != expected_tmpfs or host.get("ShmSize") != policy["shm"]:
            raise DockerError("container scratch authority or bounds differ")
        record["id"] = facts["Id"]
        return facts

    def _remove(self, record, *, tolerate_missing=False):
        selector = "id=" + record["id"] if record["id"] is not None else "name=^/" + record["name"] + "$"
        identities = self._cli(["container", "ls", "--all", "--no-trunc", "--quiet",
                                "--filter", selector]).splitlines()
        if not identities:
            if record["id"] is None:
                record["state"] = "create-unconfirmed"
                raise DockerError("container creation outcome remains unconfirmed")
            record["state"] = "removed"
            self._persist()
            return
        facts = self.inspect_owned(record, validate_policy=False)
        record["cleanup_observed_state"] = {"running": facts["State"]["Running"],
                                             "pid": facts["State"].get("Pid"),
                                             "exit_code": facts["State"]["ExitCode"]}
        if facts["State"]["Running"]:
            self._cli(["container", "stop", "--time", "5", record["id"]], timeout=15)
            facts = self.inspect_owned(record, validate_policy=False)
        record["exit_code"] = facts["State"]["ExitCode"]
        self._cli(["container", "rm", record["id"]])
        record["state"] = "removed"
        self._persist()

    def _run(self, policy, payload, *, timeout=30, stdout_limit=_INPUT):
        if not isinstance(payload, str) or len(payload.encode()) > _INPUT:
            raise ValueError("container input exceeds the 36 MB UTF-8 bound")
        if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not 0 < timeout <= 60:
            raise ValueError("container timeout must be within (0,60]")
        record = self._create(policy)
        primary = None
        try:
            args = [self.docker, "--config", str(self.config_dir), "--host", self.daemon,
                    "container", "start", "--attach", "--interactive", record["id"]]
            child = _bounded_child(args, payload.encode(), directory=str(self.root), timeout=timeout,
                                   stdout_limit=stdout_limit, stderr_limit=32768)
            facts = self.inspect_owned(record)
            if child.returncode:
                self._event("role-response-unavailable", role=policy["role"], cli_exit_code=child.returncode,
                            container_running=facts["State"]["Running"])
                return child
            if facts["State"]["Running"]:
                raise DockerError("one-shot role process did not exit")
            self._event("role-finished", role=policy["role"], exit_code=facts["State"]["ExitCode"])
            return ChildResult(facts["State"]["ExitCode"] or child.returncode, child.stdout, child.stderr)
        except BaseException as error:
            primary = error
            if isinstance(error, subprocess.TimeoutExpired):
                primary = TransportTimeout("role timed out; reconcile its operation before retrying")
                raise primary from None
            raise
        finally:
            try:
                self._remove(record)
            except Exception:
                if primary is None:
                    raise
                primary.add_note("Owned role process cleanup is incomplete.")

    def run_role(self, role, payload, *, timeout=30):
        if not self.active and not (getattr(self, "_closing", False) and role == "admin"):
            raise DockerError("Docker runtime is not active")
        if self.database_output_overflow and not (getattr(self, "_closing", False) and role == "admin"):
            raise DockerError("database output exceeded its retained evidence bound")
        return self._run(self.policy(role), payload, timeout=timeout)

    def assert_snapshot(self):
        for relative, expected in self.ownership.get("source", {}).items():
            path = self.snapshot / relative
            if path.resolve(strict=True) != path or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise DockerError("protected runtime source changed after snapshot")
        for profile in self.lock["profiles"]:
            if hashlib.sha256((self.profile_dir / profile["path"]).read_bytes()).hexdigest() != profile["sha256"]:
                raise DockerError("protected profile changed after review")

    def endpoint(self, role, connection):
        if (connection.host != "/run/postgresql" or connection.port != 5432
                or connection.sslmode != "disable" or connection.password is None):
            raise ValueError("role connection must use the exact owned SCRAM socket")
        self._sensitive.add(connection.password)
        return DockerEndpoint(self, role, connection, consumer=role in {"adapter", "observer"})

    def run_implementation(self, script, expected_digest, payload, *, timeout=10):
        if not self.active:
            raise IsolationUnavailable("explicit Docker runtime is unavailable")
        reviewed = self.ownership.get("source", {}).get("src/hobnail/_validator_worker.py")
        try:
            request = parse_json(payload)
        except (TypeError, ValueError):
            raise IsolationUnavailable("Docker accepts only the reviewed built-in validator request") from None
        if (expected_digest != reviewed or not isinstance(request, dict)
                or set(request) != {"content_hex", "plugin_id", "parameters", "inputs"}
                or request.get("plugin_id") not in BUILTINS):
            raise IsolationUnavailable("this Docker configuration does not qualify custom implementations")
        return self._execute_script(script, expected_digest, payload, timeout=timeout)

    def _execute_script(self, script, expected_digest, payload, *, timeout=10):
        with implementation_snapshot(script, expected_digest) as snapshot:
            directory = self.root / ("implementation-" + uuid.uuid4().hex)
            directory.mkdir(mode=0o700)
            target = directory / "implementation.py"
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(snapshot.read_bytes())
                stream.flush()
                os.fsync(stream.fileno())
            # Only the parser receives this exact read-only bind. The private
            # host parent excludes other users; the guest nonroot UID can read.
            target.chmod(0o444)
            return self._run(self.policy("parser", script=target), payload, timeout=timeout, stdout_limit=32768)

    def probe_parser(self, script, payload, *, timeout=10):
        """Run only the frozen first-party qualification probe, never a plugin."""
        reviewed = self.ownership.get("source", {}).get("docker/parser_probe.py")
        if not self.active or not reviewed:
            raise IsolationUnavailable("reviewed parser qualification probe is unavailable")
        if hashlib.sha256(Path(script).read_bytes()).hexdigest() != reviewed:
            raise IsolationUnavailable("parser probe differs from the frozen qualification code")
        return self._execute_script(script, reviewed, payload, timeout=timeout)

    def _probe_policy(self, endpoint):
        if endpoint.runtime is not self or endpoint.role in {"admin", "database", "parser"}:
            raise ValueError("qualification requires an owned runtime role")
        policy = self.policy(endpoint.role)
        policy["command"] = ["-I", "-S", "-B", "/opt/hobnail/docker/probe.py"]
        return policy

    def probe(self, endpoint, request, *, timeout=30):
        if not self.active:
            raise DockerError("runtime is not active")
        child = self._run(self._probe_policy(endpoint), canonical_json({"config": endpoint._config(), "request": request}),
                          timeout=timeout, stdout_limit=32768)
        if child.returncode:
            raise DockerError("qualification probe failed")
        result = parse_json(child.stdout)
        if not isinstance(result, dict) or "probe_error" in result or "service_error" in result:
            raise DockerError("qualification probe returned an invalid result")
        return result

    @contextmanager
    def hold_endpoint(self, endpoint):
        """Hold a positive peer credential/process control during refusal probes."""
        with self._hold_endpoint(endpoint, sql_session=False) as held:
            yield held

    @contextmanager
    def hold_sql_endpoint(self, endpoint):
        """Hold an actual authenticated psql backend for lifecycle qualification."""
        with self._hold_endpoint(endpoint, sql_session=True) as held:
            yield held

    @contextmanager
    def _hold_endpoint(self, endpoint, *, sql_session):
        policy = self._probe_policy(endpoint)
        record = self._create(policy)
        process = None
        primary = None
        try:
            request = {"command": "hold_sql"} if sql_session else {"command": "hold", "seconds": 30}
            frame = canonical_json({"config": endpoint._config(), "request": request}).encode()
            with tempfile.TemporaryFile(dir=self.root) as source:
                source.write(frame)
                source.seek(0)
                process = subprocess.Popen([self.docker, "--config", str(self.config_dir), "--host", self.daemon,
                    "container", "start", "--attach", "--interactive", record["id"]], stdin=source,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
                    cwd=self.root, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                buffers = {"stdout": bytearray(), "stderr": bytearray()}
                deadline = time.monotonic() + 15
                with selectors.DefaultSelector() as selection:
                    for channel, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                        os.set_blocking(channel.fileno(), False)
                        selection.register(channel, selectors.EVENT_READ, name)
                    while b"\n" not in buffers["stdout"]:
                        if time.monotonic() >= deadline or not selection.get_map():
                            raise DockerError("held peer did not establish readiness")
                        for key, _ in selection.select(0.1):
                            chunk = os.read(key.fileobj.fileno(), 4096)
                            if not chunk:
                                selection.unregister(key.fileobj)
                                continue
                            buffers[key.data].extend(chunk)
                            if len(buffers[key.data]) > 32768:
                                raise DockerError("held peer exceeded its output bound")
                ready = parse_json(buffers["stdout"].split(b"\n", 1)[0].decode())
                facts = self.inspect_owned(record)
                expected_keys = {"ready", "login", "backend_pid", "psql_pid"} if sql_session else {"ready", "login"}
                if (not isinstance(ready, dict) or set(ready) != expected_keys or ready.get("ready") is not True
                        or ready.get("login") != endpoint.connection.user
                        or sql_session and any(type(ready[key]) is not int or ready[key] <= 0 for key in ("backend_pid", "psql_pid"))
                        or not facts["State"]["Running"] or facts["State"]["Pid"] <= 0):
                    raise DockerError("held peer positive control failed")
                pending = bytearray(buffers["stdout"].split(b"\n", 1)[1])
                termination = []
                def wait_terminated(*, timeout=15):
                    if not sql_session or termination or not 0 < timeout <= 30:
                        raise ValueError("invalid SQL termination observation")
                    deadline = time.monotonic() + timeout
                    with selectors.DefaultSelector() as selection:
                        selection.register(process.stdout, selectors.EVENT_READ, "stdout")
                        selection.register(process.stderr, selectors.EVENT_READ, "stderr")
                        while b"\n" not in pending:
                            if time.monotonic() >= deadline or not selection.get_map():
                                raise DockerError("held SQL client did not report termination")
                            for key, _ in selection.select(0.1):
                                chunk = os.read(key.fileobj.fileno(), 4096)
                                if not chunk:
                                    selection.unregister(key.fileobj)
                                    continue
                                target = pending if key.data == "stdout" else buffers["stderr"]
                                target.extend(chunk)
                                if len(target) > 32768:
                                    raise DockerError("held SQL client exceeded its output bound")
                    response = parse_json(pending.split(b"\n", 1)[0].decode())
                    if (not isinstance(response, dict) or set(response) != {"terminated", "exit_code"}
                            or response["terminated"] is not True or type(response["exit_code"]) is not int
                            or response["exit_code"] == 0):
                        raise DockerError("held SQL client did not confirm a failed/reaped connection")
                    process.wait(timeout=5)
                    observed = self.inspect_owned(record)
                    if observed["State"]["Running"] or observed["State"]["ExitCode"] != 0 or process.returncode != 0:
                        raise DockerError("SQL lifecycle observer did not exit cleanly")
                    termination.append(response)
                    return response
                held = {"host_pid": facts["State"]["Pid"], "container_id": record["id"], "ready_response": ready}
                if sql_session:
                    held["wait_terminated"] = wait_terminated
                yield held
                after = self.inspect_owned(record)
                if sql_session:
                    if not termination or after["State"]["Running"] or after["State"]["ExitCode"] != 0:
                        raise DockerError("held SQL lifecycle was not independently reconciled")
                    self._event("held-sql-child-reaped", role=endpoint.role, exit_code=termination[0]["exit_code"])
                else:
                    if not after["State"]["Running"] or after["State"]["Pid"] != facts["State"]["Pid"]:
                        raise DockerError("held peer ended before the refusal observation completed")
                    self._event("held-peer-observed-alive", role=endpoint.role)
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                self._remove(record)
            except Exception:
                if primary is None:
                    raise
                primary.add_note("Held peer cleanup is incomplete.")
            finally:
                if process is not None:
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        _kill_owned_child(process)
                    process.stdout.close()
                    process.stderr.close()

    def start(self):
        if self.active or self.closed:
            raise DockerError("runtime cannot be started twice")
        try:
            server = self._json(["version", "--format", '{"Version":{{json .Server.Version}}}'])
            info = self._json(["info", "--format",
                               '{"KernelVersion":{{json .KernelVersion}},"Architecture":{{json .Architecture}}}'])
            if server["Version"] != self.expected_engine or info["KernelVersion"] != self.expected_kernel or info["Architecture"] not in {"aarch64", "arm64"}:
                raise DockerError("local daemon differs from the explicitly reviewed runtime")
            self.ownership["daemon"] = {"engine": server["Version"], "kernel": info["KernelVersion"], "architecture": info["Architecture"]}
            self._snapshot()
            self._import_images()
            for name in ("socket", "data", "destination"):
                self._volume(name)
            password = secrets.token_urlsafe(36)
            self._sensitive.add(password)
            connection = Connection(host="/run/postgresql", database="postgres", user="postgres", password=password, sslmode="disable")
            self.admin = DockerAdminTransport(self.endpoint("admin", connection))
            self.database_container = self._create(self.policy("database"))
            # The database entrypoint consumes one bounded JSON line and execs
            # postgres. A detached start plus explicit stdin attachment keeps
            # the password out of Docker environment and command metadata.
            self._cli(["container", "start", self.database_container["id"]])
            args = [self.docker, "--config", str(self.config_dir), "--host", self.daemon,
                    "container", "attach", "--sig-proxy=false", self.database_container["id"]]
            source = self.root / ".database-start-input"
            source.write_text(canonical_json({"admin_password": password}) + "\n")
            source.chmod(0o600)
            stream = source.open("rb")
            self.database_attachment = subprocess.Popen(args, stdin=stream, stdout=subprocess.PIPE,
                                                        stderr=subprocess.PIPE, close_fds=True,
                                                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, start_new_session=True)
            stream.close()
            source.unlink()
            def retain_output(channel, name):
                while chunk := channel.read(4096):
                    available = 32768 - len(self.database_output[name])
                    self.database_output[name].extend(chunk[:available])
                    if len(chunk) > available:
                        self.database_output_overflow = True
                channel.close()
            for channel, name in ((self.database_attachment.stdout, "stdout"),
                                  (self.database_attachment.stderr, "stderr")):
                thread = threading.Thread(target=retain_output, args=(channel, name), daemon=True)
                thread.start()
                self._output_threads.append(thread)
            self.active = True
            deadline = time.monotonic() + 45
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DockerError("owned database did not become ready")
                try:
                    if self.admin.execute_sql("SELECT session_user;", timeout=min(remaining, 10)).strip() != "postgres":
                        raise DockerError("administrative session identity differs")
                    if time.monotonic() > deadline:
                        raise DockerError("database readiness observation exceeded its deadline")
                    break
                except TransportError:
                    if time.monotonic() >= deadline:
                        raise DockerError("owned database did not become ready") from None
                    time.sleep(0.2)
            wrong = self.endpoint("admin", replace(connection, password=secrets.token_urlsafe(36)))
            try:
                wrong.request({"command": "sql", "sql": "SELECT 1;"})
            except PasswordAuthenticationFailed:
                self._event("admin-scram", correct_password=True, wrong_password_rejected=True)
            else:
                raise DockerError("actual wrong-password rejection was not established")
            self.admin.execute_sql("CREATE DATABASE hobnail;")
            self.admin = DockerAdminTransport(self.endpoint("admin", replace(connection, database="hobnail")))
            installation = self.admin.endpoint.request({"command": "install"}, timeout=60)
            if installation.get("installed") is not True or installation.get("protocol") != 1:
                raise DockerError("maintained installer did not confirm installation")
            self.ownership["installation"] = installation
            self.ownership["status"] = "active"
            self._persist()
            return self
        except BaseException as primary:
            try:
                self.close()
            except Exception:
                primary.add_note("Owned Docker cleanup is incomplete; retain the ownership journal.")
            raise

    def close(self):
        if self.closed:
            if self.ownership.get("cleanup_failures"):
                raise DockerError("prior cleanup remains unconfirmed")
            return
        failures = []
        self._closing = True
        self._cleanup_storage_failure = False
        retirement = self.ownership.setdefault("credential_retirement", [])
        for provider in self.providers:
            try:
                leases = provider.inventory()
            except Exception:
                failures.append("credential-inventory-failed")
                continue
            for lease in leases:
                try:
                    observation = provider.revoke(lease.lease_ref)
                    retirement.append({"login": lease.login, "lease_ref": lease.lease_ref,
                                       "result": observation.result, "login_enabled": observation.login_enabled,
                                       "active_sessions": observation.active_sessions})
                    if (observation.result != "confirmed" or observation.login_enabled is not False
                            or observation.active_sessions != 0):
                        failures.append("credential-retirement-unconfirmed")
                except Exception as error:
                    retirement.append({"login": lease.login, "lease_ref": lease.lease_ref,
                                       "result": "unconfirmed", "error_type": type(error).__name__})
                    failures.append("credential-retirement-failed")
                self._persist()
        if self.admin is not None:
            try:
                result = parse_json(self.admin.execute_sql(_RETIRE_ADMIN_SQL, sensitive=True, timeout=20).strip())
                if (not isinstance(result, dict) or set(result) != {"login_enabled", "other_client_sessions"}
                        or result["login_enabled"] is not False or type(result["other_client_sessions"]) is not int
                        or result["other_client_sessions"] != 0):
                    raise DockerError("administrator retirement was not confirmed")
                self.ownership["administrator_retirement"] = {"result": "confirmed", **result}
            except Exception as error:
                self.ownership["administrator_retirement"] = {"result": "unconfirmed", "error_type": type(error).__name__}
                failures.append("administrator-retirement-unconfirmed")
            self._persist()
        for record in list(self.containers.values()):
            if record["state"] == "removed":
                continue
            try:
                self._remove(record, tolerate_missing=True)
            except Exception:
                failures.append("container-cleanup-failed")
        attachment = getattr(self, "database_attachment", None)
        if attachment is not None:
            try:
                try:
                    attachment.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _kill_owned_child(attachment)
            except Exception:
                failures.append("database-attachment-reap-unconfirmed")
        for thread in self._output_threads:
            thread.join(timeout=2)
            if thread.is_alive():
                failures.append("database-output-drain-unconfirmed")
        # Retain bounded, structured startup failures rather than discarding
        # them. PostgreSQL's unrelated raw diagnostics remain private and are
        # not serialized into public receipts or exceptions.
        self.ownership["database_output"] = {name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                                             for name, value in self.database_output.items()}
        self.ownership["database_output"]["limit_exceeded"] = self.database_output_overflow
        for name, value in self.database_output.items():
            diagnostic = value.decode("utf-8", errors="replace")
            for secret in sorted(self._sensitive, key=len, reverse=True):
                diagnostic = diagnostic.replace(secret, "[redacted]")
            diagnostic = re.sub(r"SCRAM-SHA-256\$[^\s'\";]+", "[redacted-scram]", diagnostic)
            path = self.root / ("database-" + name + ".log")
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "w") as stream:
                    stream.write(diagnostic)
            except OSError:
                failures.append("database-diagnostic-persistence-failed")
        for line in self.database_output["stdout"].decode("utf-8", errors="replace").splitlines():
            try:
                detail = parse_json(line)
                if isinstance(detail, dict) and set(detail) <= {"database_error", "stage", "returncode", "timeout_seconds", "diagnostics"}:
                    self.ownership["database_startup_failure"] = detail
            except ValueError:
                pass
        if self.database_output_overflow:
            failures.append("database-output-limit")
        for name in self.volumes:
            try:
                self._inspect_volume(name)
                self.volumes[name]["created"] = True
            except Exception:
                failures.append("volume-ownership-unconfirmed")
        self.active, self.closed = False, True
        if self._cleanup_storage_failure:
            failures.append("cleanup-receipt-persistence-failed")
        self.ownership["status"] = "cleanup-unconfirmed" if failures else "stopped-owned-volumes-retained"
        self.ownership["cleanup_failures"] = failures
        self._persist()
        if self._cleanup_storage_failure and "cleanup-receipt-persistence-failed" not in failures:
            failures.append("cleanup-receipt-persistence-failed")
            self.ownership["status"] = "cleanup-unconfirmed"
        self._closing = False
        if failures:
            raise DockerError("owned Docker cleanup is incomplete")

    def __enter__(self):
        return self.start()

    def __exit__(self, kind, error, traceback):
        try:
            self.close()
        except Exception:
            if error is None:
                raise
            error.add_note("Owned Docker cleanup is incomplete; inspect the private ownership journal.")
        return False
