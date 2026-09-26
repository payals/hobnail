#!/usr/local/bin/python3.14 -ISB
"""Closed, synthetic Docker qualification diagnostics; not a production service.

The trusted supervisor runs this entrypoint under the same role policy as
``role.py``. Requests select fixed probes and one validated owned canary path,
never caller-chosen SQL, code, or content.
Results describe observations rather than asserting qualification success.
"""

from __future__ import annotations

from dataclasses import replace
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from hobnail.client import (PasswordAuthenticationFailed, PsqlTransport,
                            TransportError, TransportTimeout, _literal, canonical_json, parse_json)
from hobnail.effects import FilePublisher

specification = importlib.util.spec_from_file_location("hobnail_docker_probe_owned_psql", ROOT / "docker/psql_owned.py")
owned = importlib.util.module_from_spec(specification)
specification.loader.exec_module(owned)

FRAME_LIMIT = 36_000_000
FILE_LIMIT = 1_048_576
DESTINATION = Path("/destination")
DESTINATION_NAMES = ("accepted.json", "stale.json", "never-admitted.json",
                     "qualification-worker-denied", "changed.json", "uncertain.json",
                     "docker-source-inventory.json")
CHANGED_CONTENT = b"qualification-changed-by-protected-adapter"
COMMANDS = frozenset({"self", "files", "socket_families", "sql_boundary",
                      "destination", "source_inventory", "change_accepted", "hold", "hold_sql", "peer", "host_boundary"})


def validate_canary(value):
    if (not isinstance(value, str) or len(value) > 200 or
            re.fullmatch(r"/(?:private/)?tmp/hbn-docker-[a-z0-9_-]+/supervisor-canary", value) is None):
        raise ValueError("invalid owned supervisor canary")
    return value


def validate_request(role, request):
    if (not isinstance(request, dict) or not isinstance(request.get("command"), str)
            or request["command"] not in COMMANDS):
        raise ValueError("unsupported qualification request")
    command = request["command"]
    if command == "hold":
        if (set(request) != {"command", "seconds"} or type(request["seconds"]) is not int
                or not 1 <= request["seconds"] <= 30):
            raise ValueError("invalid qualification hold bound")
    elif command == "peer":
        if (set(request) != {"command", "host_pid"} or type(request["host_pid"]) is not int
                or not 1 < request["host_pid"] <= 2**31 - 1 or request["host_pid"] == os.getpid()):
            raise ValueError("invalid qualification peer identity")
    elif command == "host_boundary":
        if set(request) != {"command", "host_canary"}:
            raise ValueError("invalid host boundary fields")
        validate_canary(request["host_canary"])
    elif set(request) != {"command"}:
        raise ValueError("unsupported qualification request fields")
    if (command == "sql_boundary" and role == "admin"
            or command in {"destination", "source_inventory"} and role != "observer"
            or command == "change_accepted" and role != "adapter"):
        raise ValueError("qualification request differs from role authority")


def read_frame(stream):
    raw = stream.read(FRAME_LIMIT + 1)
    if not isinstance(raw, bytes) or len(raw) > FRAME_LIMIT:
        raise ValueError("request frame exceeds its byte limit")
    frame = parse_json(raw.decode("utf-8"))
    if not isinstance(frame, dict) or set(frame) != {"config", "request"}:
        raise ValueError("an exact configuration/request frame is required")
    owned.validate_config(frame["config"])
    validate_request(frame["config"]["role"], frame["request"])
    return frame


def failure(error):
    number = error.errno if isinstance(error, OSError) else None
    category = {errno.EPERM: "denied", errno.EACCES: "denied",
                errno.ENOENT: "absent", errno.ESRCH: "absent", errno.EROFS: "read_only",
                errno.EEXIST: "already_exists", errno.EAFNOSUPPORT: "unsupported_family",
                errno.EPROTONOSUPPORT: "unsupported_protocol"}.get(number, "error")
    return {"outcome": category, "errno": number,
            "errno_name": errno.errorcode.get(number), "error": type(error).__name__}


def process_facts():
    required = {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
                "NoNewPrivs", "Seccomp"}
    fields = {}
    with open("/proc/self/status", "rb") as stream:
        raw = stream.read(16_385)
    if len(raw) > 16_384:
        raise ValueError("process status exceeds its byte limit")
    for line in raw.decode("ascii").splitlines():
        name, separator, value = line.partition(":")
        if name not in required | {"Seccomp_filters"}:
            continue
        if not separator or name in fields:
            raise ValueError("process status has repeated fields")
        value = value.strip()
        if name.startswith("Cap"):
            if not re.fullmatch(r"[0-9a-f]{1,32}", value):
                raise ValueError("process capability status is malformed")
            fields[name] = value
        else:
            pieces = value.split()
            if any(not re.fullmatch(r"[0-9]+", piece) for piece in pieces):
                raise ValueError("process identity status is malformed")
            numbers = [int(piece) for piece in pieces]
            if name in {"Uid", "Gid"}:
                if len(numbers) != 4:
                    raise ValueError("process identity status has the wrong shape")
                fields[name] = numbers
            elif name == "Groups":
                fields[name] = numbers
            else:
                if len(numbers) != 1:
                    raise ValueError("process policy status has the wrong shape")
                fields[name] = numbers[0]
    if not required <= fields.keys():
        raise ValueError("process policy status is incomplete")
    return {"uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(), "egid": os.getegid(),
            "groups": sorted(os.getgroups()), "proc_status": fields}


def read_fixed(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("probe path is not a regular file")
            stream.read(1)
        return {"outcome": "readable"}
    except (OSError, ValueError) as error:
        return failure(error)


def files(config):
    try:
        if owned.read_config() != config:
            raise ValueError("owned configuration changed")
        own = {"outcome": "readable"}
    except (OSError, ValueError) as error:
        own = failure(error)
    results = {"own_config": own, "peer_config": read_fixed("/peer/config.json"),
               "server_data": read_fixed("/var/lib/postgresql/data/PG_VERSION")}
    if config["role"] in {"worker", "observer"}:
        try:
            descriptor = os.open(DESTINATION / "qualification-worker-denied",
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(b"qualification-unexpected-write\n")
                stream.flush()
                os.fsync(stream.fileno())
            # An unexpectedly created file is evidence, retained for the owned
            # runtime's reconciliation. Never remove or overwrite a prior file.
            results["destination_write"] = {"outcome": "written"}
        except OSError as error:
            results["destination_write"] = failure(error)
    return results


def socket_families():
    results = {}
    # Fixed Linux ABI numbers avoid mistaking a missing Python enum for a
    # policy denial. An unsupported kernel family is reported separately.
    for name, family, kind in (("AF_INET", 2, socket.SOCK_STREAM),
                               ("AF_INET6", 10, socket.SOCK_STREAM),
                               ("AF_ALG", 38, socket.SOCK_SEQPACKET),
                               ("AF_VSOCK", 40, socket.SOCK_STREAM)):
        try:
            with socket.socket(family, kind):
                results[name] = {"outcome": "created"}
        except OSError as error:
            results[name] = failure(error)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            results["AF_UNIX"] = {"outcome": "created"}
            try:
                stream.settimeout(2)
                stream.connect("/run/postgresql/.s.PGSQL.5432")
                results["postgres_socket"] = {"outcome": "connected"}
            except OSError as error:
                results["postgres_socket"] = failure(error)
    except OSError as error:
        results["AF_UNIX"] = failure(error)
        results["postgres_socket"] = {"outcome": "not_attempted"}
    results["kernel_entrypoints"] = kernel_entrypoints()
    return results


def kernel_entrypoints():
    """Benign fixed Linux AArch64 calls; no generic syscall interface.

    Numbers: Linux v7.0 scripts/syscall.tbl, native common/64 table. The
    io_uring_params layout in include/uapi/linux/io_uring.h is 120 bytes.
    AArch64 uses direct socket syscalls and has no socketcall entrypoint.
    """
    architecture = platform.machine()
    if sys.platform != "linux" or architecture != "aarch64":
        return {"architecture": architecture, "outcome": "unsupported_architecture"}
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    parameters = (ctypes.c_uint64 * 15)()  # Zeroed, aligned 120-byte struct.
    calls = (("io_uring_setup", 425, (ctypes.c_uint(1), ctypes.byref(parameters))),
             ("io_uring_enter", 426, (ctypes.c_int(-1), ctypes.c_uint(0), ctypes.c_uint(0), ctypes.c_uint(0), ctypes.c_void_p(), ctypes.c_size_t(0))),
             ("io_uring_register", 427, (ctypes.c_int(-1), ctypes.c_uint(0), ctypes.c_void_p(), ctypes.c_uint(0))))
    results = {"socketcall": {"outcome": "not_in_abi", "architecture": architecture}}
    for name, number, arguments in calls:
        ctypes.set_errno(0)
        value = libc.syscall(ctypes.c_long(number), *arguments)
        if value == -1:
            results[name] = failure(OSError(ctypes.get_errno(), "fixed syscall refusal"))
        else:
            if name == "io_uring_setup":
                os.close(value)
            results[name] = {"outcome": "created" if name == "io_uring_setup" else "allowed"}
    return results


def open_access(path, *, write=False, directory=False, create=False):
    """Test access without reading content or writing existing bytes."""
    flags = (os.O_WRONLY if write else os.O_RDONLY) | os.O_NONBLOCK | os.O_NOFOLLOW
    if write:
        flags |= os.O_APPEND
    if directory:
        flags |= os.O_DIRECTORY
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
                raise ValueError("probe path has unexpected kind")
        finally:
            os.close(descriptor)
        return {"outcome": "created" if create else "writable" if write else "readable"}
    except (OSError, ValueError) as error:
        return failure(error)


def connect_fixed(path):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(2)
            channel.connect(path)
        return {"outcome": "connected"}
    except OSError as error:
        return failure(error)


def host_boundary(host_canary):
    validate_canary(host_canary)
    return {"host_read": open_access(host_canary), "host_write_open": open_access(host_canary, write=True),
            "host_traversal": open_access("/scratch/.." + host_canary),
            "daemon_socket": connect_fixed("/var/run/docker.sock"),
            "outside_write": open_access("/qualification-outside-scratch", write=True, create=True),
            "outside_traversal_write": open_access("/scratch/../qualification-outside-traversal", write=True, create=True),
            "server_data_traversal": open_access("/scratch/../../var/lib/postgresql/data/PG_VERSION"),
            "server_data_write_open": open_access("/var/lib/postgresql/data/PG_VERSION", write=True)}


def peer(host_pid):
    results = {"host_pid": host_pid, "own_pid": os.getpid()}
    for name, suffix, directory, write in (("config", "root/scratch/config.json", False, False),
            ("environment", "environ", False, False), ("descriptors", "fd", True, False),
            ("config_write_open", "root/scratch/config.json", False, True),
            ("config_traversal", "root/scratch/../scratch/config.json", False, False)):
        results[name] = open_access(f"/proc/{host_pid}/{suffix}", write=write, directory=directory)
    try:
        os.kill(host_pid, signal.SIGCONT)
        results["signal_continue"] = {"outcome": "signalled"}
    except OSError as error:
        results["signal_continue"] = failure(error)
    return results


def hold(connection, seconds, output):
    transport = PsqlTransport(connection, psql=owned.PSQL)
    identity = parse_json(transport.execute_sql(
        "SELECT pg_catalog.json_build_object('login', session_user);", sensitive=True).strip())
    if identity != {"login": connection.user}:
        raise ValueError("held role failed its database identity check")
    output.write(canonical_json({"ready": True, "login": connection.user}) + "\n")
    output.flush()
    try:
        time.sleep(seconds)
    except Exception:
        # Readiness has already been emitted. Preserve a failed hold through
        # the exit status rather than emitting a second JSON frame.
        return 1
    return 0


def held_backend_pid(process, deadline):
    """Read only the first bounded decimal result, without blocking readline."""
    content = bytearray()
    os.set_blocking(process.stdout.fileno(), False)
    with selectors.DefaultSelector() as selection:
        selection.register(process.stdout, selectors.EVENT_READ)
        while b"\n" not in content:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportTimeout("held SQL did not produce a backend identity")
            for key, _ in selection.select(remaining):
                try:
                    chunk = os.read(key.fileobj.fileno(), 13 - len(content))
                except BlockingIOError:
                    continue
                if not chunk:
                    raise ValueError("held SQL ended before a backend identity")
                content.extend(chunk)
                if len(content) > 12:
                    raise ValueError("held SQL identity exceeds its byte limit")
    if not re.fullmatch(rb"[1-9][0-9]{0,9}\n", content):
        raise ValueError("held SQL returned an invalid backend identity")
    backend_pid = int(content[:-1])
    if not 1 < backend_pid <= 2**31 - 1:
        raise ValueError("held SQL returned an invalid backend PID")
    return backend_pid


def reap_held_sql(process, deadline):
    """Stop only this owned child; forced cleanup is never termination evidence."""
    try:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=max(0, deadline - time.monotonic()))
    finally:
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()


def hold_sql(connection, output):
    """Hold one real session for independently observed credential revocation.

    The parent must match the backend identity to pg_stat_activity before
    revocation, then observe NOLOGIN and zero sessions. A nonzero psql exit
    alone cannot establish that revocation caused the termination.
    """
    started = time.monotonic()
    operation_deadline, cleanup_deadline = started + 50, started + 55
    readiness_attempted = False
    try:
        with tempfile.TemporaryDirectory(prefix="hobnail-held-psql-", dir=owned.SCRATCH) as private:
            options = {
                "host": connection.host, "port": str(connection.port), "dbname": connection.database,
                "user": connection.user, "connect_timeout": str(connection.connect_timeout),
                "sslmode": "disable", "passfile": os.devnull,
                "application_name": "hobnail-qualification-hold", "gssencmode": "disable",
                "sslcert": os.devnull, "sslkey": os.devnull,
                "sslrootcert": str(Path(private) / "no-root.crt"),
                "sslcrl": str(Path(private) / "no-crl.pem"), "sslcrldir": private,
            }
            environment = {"LC_ALL": "C", "PGPASSFILE": os.devnull,
                           "PGSERVICEFILE": os.devnull, "PGSYSCONFDIR": private,
                           "PGPASSWORD": connection.password}
            arguments = [owned.PSQL, "-X", "-w", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
                         "-v", "VERBOSITY=terse", "-P", "pager=off", "--dbname",
                         " ".join(f"{key}={_literal(value)}" for key, value in options.items())]
            process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, env=environment,
                                       close_fds=True, bufsize=0)
            try:
                if type(process.pid) is not int or not 1 < process.pid <= 2**31 - 1:
                    raise ValueError("held SQL returned an invalid child identity")
                statement = b"SELECT pg_backend_pid();\nSELECT pg_sleep(120);\n"
                if process.stdin.write(statement) != len(statement):
                    raise ValueError("held SQL did not receive the complete fixed request")
                process.stdin.close()
                backend_pid = held_backend_pid(process, min(operation_deadline, started + 10))
                if process.poll() is not None:
                    raise ValueError("held SQL ended before readiness")
                readiness_attempted = True
                output.write(canonical_json({"ready": True, "login": connection.user,
                                             "backend_pid": backend_pid, "psql_pid": process.pid}) + "\n")
                output.flush()
                remaining = operation_deadline - time.monotonic()
                if remaining <= 0:
                    raise TransportTimeout("held SQL exceeded its observation deadline")
                exit_code = process.wait(timeout=remaining)
                if type(exit_code) is not int or exit_code == 0:
                    raise ValueError("held SQL did not terminate with a failure")
            finally:
                reap_held_sql(process, cleanup_deadline)
        # This record follows a natural nonzero child exit and successful reap,
        # never our timeout/cleanup kill. The parent establishes its cause.
        output.write(canonical_json({"terminated": True, "exit_code": exit_code}) + "\n")
        output.flush()
        return 0
    except Exception as error:
        if not readiness_attempted:
            output.write(canonical_json({"service_error": type(error).__name__}) + "\n")
            output.flush()
        return 1


def sql_boundary(connection):
    transport = PsqlTransport(connection, psql=owned.PSQL)
    facts = parse_json(transport.execute_sql("""SELECT pg_catalog.json_build_object(
      'session_user', session_user, 'current_user', current_user,
      'audit_select', pg_catalog.has_table_privilege(current_user, 'hobnail.audit', 'SELECT'),
      'audit_update', pg_catalog.has_table_privilege(current_user, 'hobnail.audit', 'UPDATE'),
      'owner_member', pg_catalog.pg_has_role(current_user, 'hobnail_owner', 'MEMBER'));
    """, sensitive=True).strip())
    if (not isinstance(facts, dict) or set(facts) != {"session_user", "current_user", "audit_select", "audit_update", "owner_member"}
            or facts["session_user"] != connection.user or facts["current_user"] != connection.user
            or any(type(facts[key]) is not bool for key in ("audit_select", "audit_update", "owner_member"))):
        raise ValueError("database identity evidence differs from the explicit connection")
    results = {"identity_and_privileges": facts}
    # Catch only PostgreSQL's actual insufficient_privilege condition. A
    # transport failure or unrelated SQL error cannot mint denial evidence.
    observed = parse_json(transport.execute_sql("""BEGIN;
DO $probe$ DECLARE result jsonb := '{}'::jsonb; BEGIN
  BEGIN
    PERFORM count(*) FROM hobnail.audit;
    result := result || jsonb_build_object('audit_read',jsonb_build_object('outcome','succeeded'));
  EXCEPTION WHEN insufficient_privilege THEN
    result := result || jsonb_build_object('audit_read',jsonb_build_object('outcome','privilege_denied','sqlstate',SQLSTATE));
  END;
  BEGIN
    UPDATE hobnail.audit SET seq=seq WHERE false;
    result := result || jsonb_build_object('audit_write',jsonb_build_object('outcome','succeeded'));
  EXCEPTION WHEN insufficient_privilege THEN
    result := result || jsonb_build_object('audit_write',jsonb_build_object('outcome','privilege_denied','sqlstate',SQLSTATE));
  END;
  BEGIN
    EXECUTE 'SET LOCAL ROLE hobnail_owner';
    result := result || jsonb_build_object('owner_role',jsonb_build_object('outcome','succeeded'));
  EXCEPTION WHEN insufficient_privilege THEN
    result := result || jsonb_build_object('owner_role',jsonb_build_object('outcome','privilege_denied','sqlstate',SQLSTATE));
  END;
  PERFORM pg_catalog.set_config('hobnail.qualification_probe',result::text,true);
END $probe$;
SELECT pg_catalog.current_setting('hobnail.qualification_probe');
ROLLBACK;""", sensitive=True).strip())
    if not isinstance(observed, dict) or set(observed) != {"audit_read", "audit_write", "owner_role"}:
        raise ValueError("SQL boundary result has an unexpected shape")
    results.update(observed)
    try:
        administrator = PsqlTransport(replace(connection, user="postgres"), psql=owned.PSQL)
        administrator.execute_sql("SELECT 1;", sensitive=True)
        results["admin_with_role_password"] = {"outcome": "authenticated"}
    except PasswordAuthenticationFailed:
        results["admin_with_role_password"] = {"outcome": "password_authentication_failed"}
    except TransportError as error:
        results["admin_with_role_password"] = {"outcome": "inconclusive", "error": type(error).__name__}
    return results


def destination_record(name, *, include_content=False):
    if name not in DESTINATION_NAMES:
        raise ValueError("unsupported qualification destination")
    directory = os.open(DESTINATION, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root = os.fstat(directory)
        if root.st_uid != 10006 or root.st_mode & 0o022:
            raise ValueError("destination authority differs from the protected adapter")
        descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size > FILE_LIMIT):
                raise ValueError("destination is not a bounded private regular file")
            content = stream.read(FILE_LIMIT + 1)
            after = os.fstat(stream.fileno())
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            if (identity(before) != identity(after) or identity(after) != identity(current)
                    or len(content) != before.st_size):
                raise ValueError("destination changed during observation")
            result = {"outcome": "present", "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content), "uid": before.st_uid, "gid": before.st_gid,
                    "mode": f"{stat.S_IMODE(before.st_mode):04o}",
                    "device": before.st_dev, "inode": before.st_ino,
                    "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns}
            if include_content:
                result["content_hex"] = content.hex()
            return result
    finally:
        os.close(directory)


def destination():
    results = {}
    for name in DESTINATION_NAMES:
        try:
            results[name] = destination_record(name)
        except (OSError, ValueError) as error:
            results[name] = failure(error)
    return results


def change_accepted():
    before = destination_record("changed.json")
    if before["uid"] != 10006 or before["gid"] != 20001 or before["mode"] != "0640":
        raise ValueError("existing qualification artifact has unexpected authority")
    digest = hashlib.sha256(CHANGED_CONTENT).hexdigest()
    FilePublisher(DESTINATION, observer_group=20001).publish("changed.json", CHANGED_CONTENT, digest)
    return {"outcome": "changed", "sha256": digest, "size": len(CHANGED_CONTENT)}


def handle(config, request):
    connection = owned.validate_config(config)
    validate_request(config["role"], request)
    command = request["command"]
    if command == "self":
        facts = process_facts()
    elif command == "files":
        facts = files(config)
    elif command == "socket_families":
        facts = socket_families()
    elif command == "sql_boundary":
        facts = sql_boundary(connection)
    elif command == "destination":
        facts = destination()
    elif command == "source_inventory":
        facts = destination_record("docker-source-inventory.json", include_content=True)
    elif command == "change_accepted":
        facts = change_accepted()
    elif command == "peer":
        facts = peer(request["host_pid"])
    elif command == "host_boundary":
        facts = host_boundary(request["host_canary"])
    else:
        raise ValueError("streaming hold requires the qualification entrypoint")
    return {"command": command, "role": config["role"], "facts": facts}


def main(stream=None, output=None):
    stream = sys.stdin.buffer if stream is None else stream
    output = sys.stdout if output is None else output
    try:
        os.umask(0o077)
        tempfile.tempdir = str(owned.SCRATCH)
        frame = read_frame(stream)
        owned.write_config(frame["config"])
        if frame["request"]["command"] == "hold":
            return hold(owned.validate_config(frame["config"]), frame["request"]["seconds"], output)
        if frame["request"]["command"] == "hold_sql":
            return hold_sql(owned.validate_config(frame["config"]), output)
        response = handle(frame["config"], frame["request"])
        output.write(canonical_json(response) + "\n")
    except Exception as error:
        output.write(json.dumps({"service_error": type(error).__name__}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
