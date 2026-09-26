"""Inert first-party entrypoint fixtures; these do not qualify Docker isolation."""

import importlib.util
import errno
import io
import json
import os
from pathlib import Path
import stat
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    specification = importlib.util.spec_from_file_location("docker_test_" + name, ROOT / "docker" / (name + ".py"))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


ROLE = load("role")
OWNED = ROLE.owned
DATABASE = load("database")
PROBE = load("probe")
PARSER = load("parser_probe")
SECRET = "fixture_private_password_" + "x" * 24
ENVELOPE = {"ok": True, "status": "observed", "event_id": 1, "data": {"fixture": True}}
CANARY = "/private/tmp/hbn-docker-owned-fixture/supervisor-canary"


def config(role="worker"):
    result = {"role": role, "psql": OWNED.PSQL,
              "connection": {"host": "/run/postgresql", "database": "hobnail", "user": "postgres" if role == "admin" else "fixture_login",
                             "port": 5432, "sslmode": "disable", "password": SECRET, "connect_timeout": 5}}
    if role in {"adapter", "observer"}:
        result["consumer"] = {"plugin": "file.publish", "root": "/destination"}
    return result


class RoleTests(unittest.TestCase):
    def setUp(self):
        self.identities = patch.dict(OWNED.ROLE_UIDS, {name: os.getuid() for name in OWNED.ROLE_UIDS})
        self.identities.start()
        self.addCleanup(self.identities.stop)

    def test_frame_duplicate_extra_and_oversize_inputs_refuse(self):
        for raw in (b'{"config":{},"config":{},"request":{}}', b'{"config":{},"request":{},"extra":true}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ROLE.read_frame(io.BytesIO(raw))
        with patch.object(ROLE, "FRAME_LIMIT", 4), self.assertRaises(ValueError):
            ROLE.read_frame(io.BytesIO(b"12345"))
        value = {"config": config(), "request": {"command": "api", "operation": "candidate.get", "payload": {"candidate_id": 1}}}
        self.assertEqual(ROLE.read_frame(io.BytesIO(json.dumps(value).encode())), value)

    def test_closed_commands_roles_and_exact_shapes(self):
        rejected = [("worker", {"command": "sql", "sql": "SELECT 1"}),
                    ("worker", {"command": "install"}), ("admin", {"command": "api", "operation": "x", "payload": {}}),
                    ("worker", {"command": "file.dispatch", "effect_id": 1}),
                    ("adapter", {"command": "file.observe", "effect_id": 1}),
                    ("observer", {"command": "file.observe", "effect_id": True}),
                    ("worker", {"command": "execute", "args": []}),
                    ("worker", {"command": "api", "operation": "x", "payload": {}, "role": "admin"}),
                    ("adapter", {"command": "file.dispatch", "effect_id": 1, "destination": "/elsewhere"})]
        for role, request in rejected:
            with self.subTest(role=role, request=request), self.assertRaises(ValueError):
                ROLE.validate_request(role, request)

    def test_inventory_probe_is_fixed_read_only_observer_authority(self):
        PROBE.validate_request("observer", {"command": "source_inventory"})
        for role in ("worker", "adapter", "verifier", "admin"):
            with self.subTest(role=role), self.assertRaises(ValueError):
                PROBE.validate_request(role, {"command": "source_inventory"})
        for extra in ({"path": "/other"}, {"target": "accepted.json"}, {"content": "replacement"}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                PROBE.validate_request("observer", {"command": "source_inventory", **extra})

    def test_configuration_confines_identity_socket_executable_and_consumer(self):
        cases = [{**config(), "psql": "/bin/sh"}, {**config(), "role": "root"},
                 {**config(), "consumer": {"plugin": "file.publish", "root": "/destination"}},
                 {**config("adapter"), "consumer": {"plugin": "file.publish", "root": "/tmp"}}]
        for key, value in (("host", "localhost"), ("port", 5433), ("database", "host=elsewhere"),
                           ("sslrootcert", "/personal/secret"), ("password", "short"), ("connect_timeout", True)):
            case = config()
            case["connection"][key] = value
            cases.append(case)
        for value in cases:
            with self.subTest(value={k: v for k, v in value.items() if k != "connection"}), self.assertRaises(ValueError):
                OWNED.validate_config(value)
        with patch.object(OWNED.os, "geteuid", return_value=os.getuid() + 1), self.assertRaises(ValueError):
            OWNED.validate_config(config())

    def test_api_preserves_wire_envelope_and_does_not_gain_sql(self):
        transport = Mock()
        transport.call.return_value = ENVELOPE
        with patch.object(ROLE, "PsqlTransport", return_value=transport) as constructor:
            result = ROLE.handle(config(), {"command": "api", "operation": "candidate.get", "payload": {"candidate_id": 1}})
        self.assertEqual(result, ENVELOPE)
        self.assertEqual(constructor.call_args.kwargs, {"psql": "/usr/local/bin/psql"})
        transport.execute_sql.assert_not_called()

    def test_fixed_consumer_ownership_and_admin_routes(self):
        with patch.object(ROLE, "PsqlTransport"), patch.object(ROLE, "dispatch_file", return_value=ENVELOPE) as dispatch:
            self.assertEqual(ROLE.handle(config("adapter"), {"command": "file.dispatch", "effect_id": 4}), ENVELOPE)
            publisher = dispatch.call_args.args[2]
            self.assertEqual((publisher.root, publisher.observer_group), (Path("/destination"), 20001))
        with patch.object(ROLE, "PsqlTransport"), patch.object(ROLE, "observe_file", return_value=ENVELOPE) as observe:
            ROLE.handle(config("observer"), {"command": "file.observe", "effect_id": 4})
            observer = observe.call_args.args[2]
            self.assertEqual((observer.root, observer.adapter_owner_uid), (Path("/destination"), 10006))
        with patch.object(ROLE, "PsqlTransport") as transport:
            transport.return_value.execute_sql.return_value = "1\n"
            self.assertEqual(ROLE.handle(config("admin"), {"command": "sql", "sql": "SELECT 1"}), {"sql_output": "1\n"})
            transport.return_value.execute_sql.assert_called_once_with("SELECT 1", sensitive=True)
        with patch.object(ROLE, "install_kernel", return_value={"installed": True}) as install:
            self.assertEqual(ROLE.handle(config("admin"), {"command": "install"}), {"installed": True})
            self.assertEqual(install.call_args.args[0].user, "postgres")

    def test_failure_preserves_type_without_credential_or_error_body(self):
        from hobnail.client import PasswordAuthenticationFailed
        source = io.BytesIO(json.dumps({"config": config(), "request": {"command": "api", "operation": "x", "payload": {}}}).encode())
        output = io.StringIO()
        with patch.object(OWNED, "write_config") as write, patch.object(ROLE, "handle", side_effect=PasswordAuthenticationFailed(SECRET)), patch.object(ROLE.tempfile, "tempdir"), patch.object(ROLE.os, "umask"):
            self.assertEqual(ROLE.main(source, output), 0)
            write.assert_called_once()
        self.assertEqual(json.loads(output.getvalue()), {"service_error": "PasswordAuthenticationFailed"})
        self.assertNotIn(SECRET, output.getvalue())


class QualificationBoundaryTests(unittest.TestCase):
    def test_canary_and_peer_requests_are_closed_to_owned_fixed_probes(self):
        PROBE.validate_request("worker", {"command": "host_boundary", "host_canary": CANARY})
        parser_request = {"command": "parser_boundaries", "host_canary": CANARY, "peer_pid": 123456}
        self.assertEqual(PARSER.read_payload(io.BytesIO(json.dumps(parser_request).encode())), parser_request)
        invalid_paths = ("/etc/passwd", "/tmp/hbn-docker-a/../supervisor-canary", "/tmp/hbn-docker-a/config.json",
                         "/tmp/hbn-docker-a/supervisor-canary\n", "/tmp/hbn-docker-a/supervisor-canary/child", True)
        for path in invalid_paths:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    PROBE.validate_request("worker", {"command": "host_boundary", "host_canary": path})
                with self.assertRaises(ValueError):
                    PARSER.read_payload(io.BytesIO(json.dumps({**parser_request, "host_canary": path}).encode()))
        for request in ({"command": "parser_boundaries"}, {**parser_request, "peer_pid": True},
                        {**parser_request, "peer_pid": 1}, {**parser_request, "peer_pid": 2**31},
                        {**parser_request, "path": "/outside"}):
            with self.subTest(request=request), self.assertRaises(ValueError):
                PARSER.read_payload(io.BytesIO(json.dumps(request).encode()))
        with self.assertRaises(ValueError):
            PROBE.validate_request("worker", {"command": "host_boundary", "host_canary": CANARY, "path": "/outside"})

    def test_write_open_never_changes_existing_file_bytes_and_creation_is_retained(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-probe-access-") as temporary:
            root = Path(temporary)
            existing = root / "existing"
            existing.write_bytes(b"nonsecret owned canary")
            for module in (PROBE, PARSER):
                with self.subTest(module=module.__name__):
                    result = module.open_access(existing, write=True)
                    self.assertEqual(existing.read_bytes(), b"nonsecret owned canary")
                    if module is PROBE:
                        self.assertEqual(result, {"outcome": "writable"})
                    created = root / module.__name__
                    module.open_access(created, write=True, create=True)
                    self.assertTrue(created.exists())
                    self.assertEqual(created.read_bytes(), b"")
                    self.assertEqual(stat.S_IMODE(created.stat().st_mode), 0o600)

    def test_host_probe_uses_only_fixed_nonsecret_paths_and_bounded_socket(self):
        with patch.object(PROBE, "open_access", return_value={"outcome": "absent"}) as opened, patch.object(PROBE, "connect_fixed", return_value={"outcome": "absent"}) as connected:
            observed = PROBE.host_boundary(CANARY)
        self.assertEqual([call.args[0] for call in opened.call_args_list], [CANARY, CANARY, "/scratch/.." + CANARY,
            "/qualification-outside-scratch", "/scratch/../qualification-outside-traversal",
            "/scratch/../../var/lib/postgresql/data/PG_VERSION", "/var/lib/postgresql/data/PG_VERSION"])
        connected.assert_called_once_with("/var/run/docker.sock")
        self.assertEqual(set(observed), {"host_read", "host_write_open", "host_traversal", "daemon_socket", "outside_write",
                                        "outside_traversal_write", "server_data_traversal", "server_data_write_open"})

    def test_parser_attempts_real_peer_access_signal_and_fork_without_reading_contents(self):
        with patch.object(PARSER, "open_access", side_effect=FileNotFoundError(errno.ENOENT, "private")) as opened, patch.object(PARSER, "connect_fixed", side_effect=PermissionError(errno.EPERM, "private")), patch.object(PARSER.os, "stat", side_effect=FileNotFoundError(errno.ENOENT, "private")), patch.object(PARSER.os, "kill", side_effect=ProcessLookupError(errno.ESRCH, "private")) as sent, patch.object(PARSER.os, "fork", side_effect=PermissionError(errno.EPERM, "private")) as forked:
            result = PARSER.boundary_paths(CANARY, 123456)
        self.assertEqual(result["postgres_socket"], {"outcome": "absent", "errno": errno.ENOENT})
        self.assertEqual(result["fork"], {"outcome": "policy_denied", "errno": errno.EPERM})
        sent.assert_called_once_with(123456, PARSER.signal.SIGCONT)
        forked.assert_called_once_with()
        self.assertIn("/proc/123456/root/scratch/../scratch/config.json", [call.args[0] for call in opened.call_args_list])
        self.assertNotIn("private", json.dumps(result))
        with patch.object(PARSER.os, "fork", return_value=4321), patch.object(PARSER.os, "waitpid", return_value=(4321, 0)) as waited:
            result = PARSER.fork_probe()
        self.assertEqual(result, {"outcome": "created", "child_reaped": True, "status": 0})
        waited.assert_called_once_with(4321, 0)

    def test_kernel_syscalls_are_architecture_gated_fixed_and_close_unexpected_fd(self):
        for module in (PROBE, PARSER):
            with self.subTest(module=module.__name__):
                with patch.object(module.sys, "platform", "darwin"), patch.object(module.platform, "machine", return_value="arm64"), patch.object(module.ctypes, "CDLL") as library:
                    self.assertEqual(module.kernel_entrypoints(), {"architecture": "arm64", "outcome": "unsupported_architecture"})
                    library.assert_not_called()
                library = Mock()
                arguments = []
                def syscall(number, *args):
                    arguments.append((number.value, args))
                    module.ctypes.set_errno(errno.EPERM)
                    return -1
                library.syscall.side_effect = syscall
                with patch.object(module.sys, "platform", "linux"), patch.object(module.platform, "machine", return_value="aarch64"), patch.object(module.ctypes, "CDLL", return_value=library):
                    result = module.kernel_entrypoints()
                self.assertEqual([number for number, _ in arguments], [425, 426, 427])
                self.assertEqual(arguments[0][1][0].value, 1)
                self.assertEqual(module.ctypes.sizeof(arguments[0][1][1]._obj), 120)
                self.assertEqual(bytes(arguments[0][1][1]._obj), bytes(120))
                self.assertEqual(arguments[1][1][0].value, -1)
                self.assertEqual(arguments[2][1][0].value, -1)
                self.assertEqual(result["socketcall"], {"outcome": "not_in_abi", "architecture": "aarch64"})
                self.assertTrue(all(result[name]["errno"] == errno.EPERM for name in ("io_uring_setup", "io_uring_enter", "io_uring_register")))
                library.syscall.side_effect = [17, -1, -1]
                with patch.object(module.sys, "platform", "linux"), patch.object(module.platform, "machine", return_value="aarch64"), patch.object(module.ctypes, "CDLL", return_value=library), patch.object(module.os, "close") as close:
                    result = module.kernel_entrypoints()
                close.assert_called_once_with(17)
                self.assertEqual(result["io_uring_setup"], {"outcome": "created"})

    def test_sql_boundary_emits_only_actual_42501_and_transport_failures_propagate(self):
        from hobnail.client import Connection, PasswordAuthenticationFailed, TransportError
        connection = Connection("/run/postgresql", "hobnail", "fixture_login")
        identity = {"session_user": "fixture_login", "current_user": "fixture_login", "audit_select": False,
                    "audit_update": False, "owner_member": False}
        outcomes = {name: {"outcome": "privilege_denied", "sqlstate": "42501"}
                    for name in ("audit_read", "audit_write", "owner_role")}
        transport, administrator = Mock(), Mock()
        transport.execute_sql.side_effect = [json.dumps(identity), json.dumps(outcomes)]
        administrator.execute_sql.side_effect = PasswordAuthenticationFailed("private")
        with patch.object(PROBE, "PsqlTransport", side_effect=[transport, administrator]):
            result = PROBE.sql_boundary(connection)
        self.assertEqual(result["audit_write"], outcomes["audit_write"])
        statement = transport.execute_sql.call_args_list[1].args[0]
        self.assertIn("UPDATE hobnail.audit SET seq=seq WHERE false", statement)
        self.assertEqual(statement.count("EXCEPTION WHEN insufficient_privilege"), 3)
        self.assertNotIn("WHEN OTHERS", statement)
        self.assertTrue(statement.startswith("BEGIN;"))
        self.assertTrue(statement.endswith("ROLLBACK;"))
        transport.execute_sql.side_effect = [json.dumps(identity), TransportError("private")]
        with patch.object(PROBE, "PsqlTransport", return_value=transport), self.assertRaises(TransportError):
            PROBE.sql_boundary(connection)


class OwnedConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hobnail-entrypoint-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name).resolve()
        self.scratch.chmod(0o700)
        for attribute, value in (("SCRATCH", self.scratch), ("ROLE_UIDS", {name: os.getuid() for name in OWNED.ROLE_UIDS})):
            change = patch.object(OWNED, attribute, value)
            change.start()
            self.addCleanup(change.stop)

    def test_config_exclusive_bounded_owned_and_no_follow(self):
        value = config("admin")
        OWNED.write_config(value)
        path = self.scratch / "config.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(OWNED.read_config(), value)
        with self.assertRaises(FileExistsError):
            OWNED.write_config(value)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            OWNED.read_config()
        path.chmod(0o600)
        os.link(path, self.scratch / "second-link")
        with self.assertRaises(ValueError):
            OWNED.read_config()
        (self.scratch / "second-link").unlink()
        path.unlink()
        path.symlink_to(self.scratch / "absent")
        with self.assertRaises(OSError):
            OWNED.read_config()

    def test_changed_or_oversize_configuration_refuses(self):
        OWNED.write_config(config("admin"))
        path = self.scratch / "config.json"
        path.write_bytes(b"x" * (OWNED.CONFIG_LIMIT + 1))
        with self.assertRaises(ValueError):
            OWNED.read_config()
        path.write_text(json.dumps(config("admin")))
        original = OWNED.os.stat
        def different(name, *args, **kwargs):
            result = original(name, *args, **kwargs)
            if name == "config.json":
                return Mock(st_dev=result.st_dev, st_ino=result.st_ino + 1, st_size=result.st_size,
                            st_mtime_ns=result.st_mtime_ns, st_ctime_ns=result.st_ctime_ns)
            return result
        with patch.object(OWNED.os, "stat", side_effect=different), self.assertRaises(ValueError):
            OWNED.read_config()

    def installer_call(self):
        temporary = self.scratch / "hobnail-install-abcdefgh"
        temporary.mkdir(mode=0o700)
        environment = {"LC_ALL": "C", "PGPASSFILE": "/dev/null", "PGSERVICEFILE": "/dev/null", "PGSYSCONFDIR": str(temporary)}
        fields = {"host": "/run/postgresql", "port": "5432", "dbname": "hobnail", "user": "postgres", "sslmode": "disable", "connect_timeout": "5",
                  "passfile": "/dev/null", "application_name": "hobnail-installer", "gssencmode": "disable",
                  "sslcert": str(temporary / "absent.crt"), "sslkey": str(temporary / "absent.key"),
                  "sslrootcert": str(temporary / "absent-root.crt"), "sslcrl": str(temporary / "absent-crl.pem"), "sslcrldir": str(temporary)}
        args = ["-X", "-q", "-A", "-t", "-w", "--dbname", " ".join(f"{key}='{value}'" for key, value in fields.items())]
        return args, environment

    def test_wrapper_adds_only_owned_password_and_preserves_exact_argv(self):
        args, environment = self.installer_call()
        result = OWNED.installer_environment(args, environment, config("admin"))
        self.assertEqual(result, {**environment, "PGPASSWORD": SECRET})
        OWNED.write_config(config("admin"))
        with patch.object(OWNED.sys, "argv", ["owned-psql", *args]), patch.dict(OWNED.os.environ, environment, clear=True), patch.object(OWNED.os, "execve") as execute:
            self.assertEqual(OWNED.main(), 0)
        execute.assert_called_once_with(OWNED.PSQL, [OWNED.PSQL, *args], result)
        self.assertNotIn(SECRET, str(execute.call_args.args[:2]))

    def test_actual_installer_arguments_pass_the_owned_wrapper(self):
        value = config("admin")
        connection = OWNED.validate_config(value)
        def controlled_psql(arguments, **keywords):
            self.assertEqual(arguments[0], str(ROOT / "docker/psql_owned.py"))
            self.assertEqual(OWNED.installer_environment(arguments[1:], keywords["env"], value)["PGPASSWORD"], SECRET)
            self.assertNotIn(SECRET, keywords["input"])
            self.assertIn("Applied migration", keywords["input"])
            return Mock(returncode=0, stdout='{"installed":true,"protocol":1,"migrations":[]}\n')
        with patch.object(ROLE.tempfile, "tempdir", str(self.scratch)), patch.object(subprocess, "run", side_effect=controlled_psql) as execute:
            receipt = ROLE.install_kernel(connection)
        self.assertEqual(receipt["installed"], True)
        self.assertEqual(execute.call_count, 1)

    def test_wrapper_rejects_changed_dsn_flags_environment_and_certificate(self):
        args, environment = self.installer_call()
        cases = [([*args, "-c", "SELECT 1"], environment),
                 ([*args[:-1], args[-1].replace("dbname='hobnail'", "dbname='other'")], environment),
                 ([*args[:-1], args[-1] + " user='postgres'"], environment),
                 (args, {**environment, "PGOPTIONS": "-c role=postgres"}),
                 (args, {**environment, "PGPASSWORD": SECRET})]
        for arguments, env in cases:
            with self.subTest(arguments=arguments[:6], keys=list(env)), self.assertRaises(ValueError):
                OWNED.installer_environment(arguments, env, config("admin"))
        with self.assertRaises(ValueError):
            OWNED.installer_environment(args, environment, config())
        (Path(environment["PGSYSCONFDIR"]) / "absent.crt").write_bytes(b"inert")
        with self.assertRaises(ValueError):
            OWNED.installer_environment(args, environment, config("admin"))


class DatabaseTests(unittest.TestCase):
    def test_strict_bootstrap_frame_and_redacted_failure(self):
        self.assertEqual(DATABASE.read_password(io.BytesIO(json.dumps({"admin_password": SECRET}).encode())), SECRET)
        for source in (b'{"admin_password":"short"}', b'{"admin_password":"x","admin_password":"y"}',
                       json.dumps({"admin_password": SECRET, "data": "/elsewhere"}).encode(), b"x" * 1025):
            with self.subTest(source=source[:20]), self.assertRaises(ValueError):
                DATABASE.read_password(io.BytesIO(source))
        output = io.StringIO()
        with patch.object(DATABASE, "start", side_effect=RuntimeError(SECRET)), patch.object(DATABASE.os, "umask"):
            self.assertEqual(DATABASE.main(io.BytesIO(json.dumps({"admin_password": SECRET}).encode()), output), 1)
        self.assertEqual(json.loads(output.getvalue()), {"database_error": "RuntimeError"})
        self.assertNotIn(SECRET, output.getvalue())
        output = io.StringIO()
        with patch.object(DATABASE, "start", side_effect=DATABASE.DatabaseInitializationFailed(17)), patch.object(DATABASE.os, "umask"):
            DATABASE.main(io.BytesIO(json.dumps({"admin_password": SECRET}).encode()), output)
        self.assertEqual(json.loads(output.getvalue()), {"database_error": "DatabaseInitializationFailed", "stage": "initdb", "returncode": 17})

    def test_fresh_initdb_scram_and_fixed_server_exec_without_secret_argv(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-database-fixture-") as temporary:
            root = Path(temporary).resolve()
            data, scratch, socket = (root / name for name in ("parent", "scratch", "socket"))
            for path in (data, scratch, socket):
                path.mkdir(mode=0o700)
            socket.chmod(0o770)
            # BSD temporary directories can inherit their parent's group. The
            # fixture must provision the declared socket group explicitly.
            os.chown(socket, -1, os.getgid())
            with patch.object(DATABASE, "DATA_PARENT", data), patch.object(DATABASE, "SCRATCH", scratch), patch.object(DATABASE, "SOCKET", socket), patch.object(DATABASE, "DATABASE_UID", os.getuid()), patch.object(DATABASE, "SOCKET_GROUP", os.getgid()), patch.object(DATABASE.os, "getgroups", return_value=[os.getgid()]), patch.object(DATABASE, "initialize") as initialize, patch.object(DATABASE.os, "execve") as execute:
                def check_password(*args, **kwargs):
                    path = scratch / DATABASE.PASSWORD_NAME
                    self.assertEqual(path.read_text(), SECRET + "\n")
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    return Mock(returncode=0)
                initialize.side_effect = check_password
                DATABASE.start(SECRET)
                argv = initialize.call_args.args[0]
                self.assertIn("--auth-local=scram-sha-256", argv)
                self.assertIn("--auth-host=reject", argv)
                self.assertIn("--no-clean", argv)
                self.assertNotIn(SECRET, str(initialize.call_args))
                self.assertFalse((scratch / DATABASE.PASSWORD_NAME).exists())
                executable, server_args, environment = execute.call_args.args
                self.assertEqual(executable, "/usr/local/bin/postgres")
                for flag in ("listen_addresses=", "unix_socket_permissions=0770", "io_method=sync", "log_min_error_statement=panic", "password_encryption=scram-sha-256"):
                    self.assertIn(flag, server_args)
                self.assertNotIn(SECRET, str(execute.call_args))
                self.assertNotIn("PGPASSWORD", environment)
                with self.assertRaises(FileExistsError):
                    DATABASE.start(SECRET)
                self.assertEqual(initialize.call_count, 1)

    def test_directory_refuses_a_different_socket_group(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-socket-group-") as temporary:
            socket = Path(temporary).resolve()
            socket.chmod(0o770)
            with patch.object(DATABASE, "DATABASE_UID", os.getuid()):
                with self.assertRaisesRegex(ValueError, "authority differs"):
                    DATABASE.directory(socket, 0o770, socket.stat().st_gid + 1)

    def test_real_inert_child_failure_is_bounded_and_redacted(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-init-diagnostic-") as temporary:
            root = Path(temporary).resolve()
            material = root / "synthetic.txt"
            material.write_text(SECRET)
            script = root / "inert.py"
            script.write_text("import pathlib,sys\nvalue=pathlib.Path(sys.argv[1]).read_text()\n"
                              "sys.stderr.write('controlled failure '+value+' SCRAM-SHA-256$synthetic-material\\n')\n"
                              "raise SystemExit(17)\n")
            with self.assertRaises(DATABASE.DatabaseInitializationFailed) as caught:
                DATABASE.initialize([sys.executable, "-I", "-S", str(script), str(material)],
                                    {"LC_ALL": "C"}, redact=lambda raw: DATABASE._redact(raw, SECRET))
            self.assertEqual(caught.exception.returncode, 17)
            diagnostic = caught.exception.diagnostics["stderr"]
            self.assertIn("controlled failure", diagnostic)
            self.assertNotIn(SECRET, diagnostic)
            self.assertNotIn("synthetic-material", diagnostic)
            self.assertLessEqual(len(diagnostic), 2048)

    def test_real_inert_child_overflow_preserves_limit_failure(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-init-overflow-") as temporary:
            script = Path(temporary) / "inert.py"
            script.write_text("import sys\nsys.stderr.write('x'*65536)\n")
            with self.assertRaises(DATABASE.DatabaseInitializationFailed) as caught:
                DATABASE.initialize([sys.executable, "-I", "-S", str(script)], {"LC_ALL": "C"}, redact=lambda raw: "unused")
            self.assertEqual(caught.exception.diagnostics, {"reason": "output_limit"})


if __name__ == "__main__":
    unittest.main()
