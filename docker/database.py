#!/usr/local/bin/python3.14 -ISB
"""Initialize and exec one fresh, socket-only PostgreSQL server as UID 70."""

from __future__ import annotations

from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import selectors
import time

DATABASE_UID = 70
SOCKET_GROUP = 20000
DATA_PARENT = Path("/var/lib/postgresql")
DATA_NAME = "data"
SOCKET = Path("/run/postgresql")
SCRATCH = Path("/scratch")
PASSWORD_NAME = "initdb-password"
INITDB = "/usr/local/bin/initdb"
POSTGRES = "/usr/local/bin/postgres"


class DatabaseInitializationFailed(RuntimeError):
    def __init__(self, returncode, diagnostics=None):
        self.returncode = returncode
        self.diagnostics = diagnostics or {}
        super().__init__("fresh initialization failed")


def _redact(raw, password):
    text = raw.decode("utf-8", errors="replace")
    # A killed producer can leave a final partial token. Remove known prefixes
    # before truncating the diagnostic, as well as complete SCRAM material.
    for length in range(len(password), 3, -1):
        text = text.replace(password[:length], "[redacted]")
    text = re.sub(r"SCRAM-SHA-256\$[^\s'\";]*", "[redacted-scram]", text)
    return text[:2048]


def initialize(arguments, environment, *, redact):
    """Bound both initdb streams; never discard the first failure's cause."""
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + 120
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, close_fds=True)
    try:
        with selectors.DefaultSelector() as selection:
            for channel, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(channel.fileno(), False)
                selection.register(channel, selectors.EVENT_READ, name)
            while selection.get_map():
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired("owned-initdb", 120)
                for key, _ in selection.select(min(0.1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selection.unregister(key.fileobj)
                        continue
                    outputs[key.data].extend(chunk)
                    if len(outputs[key.data]) > 8192:
                        raise DatabaseInitializationFailed(None, {"reason": "output_limit"})
        process.wait(timeout=max(0, deadline - time.monotonic()))
        if process.returncode:
            raise DatabaseInitializationFailed(process.returncode,
                {name: redact(bytes(value)) for name, value in outputs.items()})
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
        process.stderr.close()


def read_password(stream):
    raw = stream.read(1025)
    if not isinstance(raw, bytes) or len(raw) > 1024:
        raise ValueError("invalid bootstrap frame")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate bootstrap field")
            result[key] = value
        return result
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    if (not isinstance(value, dict) or set(value) != {"admin_password"}
            or not isinstance(value["admin_password"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", value["admin_password"])):
        raise ValueError("invalid bootstrap credential")
    return value["admin_password"]


def directory(path, mode, group=None):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("runtime directory is not canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (info.st_uid != DATABASE_UID or stat.S_IMODE(info.st_mode) != mode
                or group is not None and info.st_gid != group):
            raise ValueError("runtime directory authority differs")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def start(password):
    if os.getuid() != DATABASE_UID or os.geteuid() != DATABASE_UID or SOCKET_GROUP not in os.getgroups():
        raise ValueError("database identity differs from its fixed policy")
    with ExitStack() as descriptors:
        parent = directory(DATA_PARENT, 0o700)
        descriptors.callback(os.close, parent)
        scratch = directory(SCRATCH, 0o700)
        descriptors.callback(os.close, scratch)
        socket = directory(SOCKET, 0o770, SOCKET_GROUP)
        descriptors.callback(os.close, socket)
        # mkdir refuses an existing or partially initialized directory, including links.
        os.mkdir(DATA_NAME, 0o700, dir_fd=parent)
        descriptor = os.open(PASSWORD_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=scratch)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write((password + "\n").encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        environment = {"PATH": "/usr/local/bin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
                       "TMPDIR": str(SCRATCH), "PGSYSCONFDIR": str(SCRATCH)}
        try:
            initialize([INITDB, "-D", str(DATA_PARENT / DATA_NAME), "--username=postgres",
                "--auth-local=scram-sha-256", "--auth-host=reject", "--encoding=UTF8", "--locale=C",
                "--no-instructions", "--no-clean", "--pwfile=" + str(SCRATCH / PASSWORD_NAME)],
                environment, redact=lambda value: _redact(value, password))
        finally:
            os.unlink(PASSWORD_NAME, dir_fd=scratch)
    options = ["listen_addresses=", "unix_socket_directories=" + str(SOCKET),
               "unix_socket_group=" + str(SOCKET_GROUP), "unix_socket_permissions=0770",
               "port=5432", "timezone=UTC", "jit=off", "io_method=sync", "max_connections=32",
               "shared_buffers=16MB", "password_encryption=scram-sha-256", "log_statement=none",
               "log_min_error_statement=panic", "log_parameter_max_length=0", "log_parameter_max_length_on_error=0"]
    arguments = [POSTGRES, "-D", str(DATA_PARENT / DATA_NAME)]
    for option in options:
        arguments.extend(["-c", option])
    os.execve(POSTGRES, arguments, environment)


def main(stream=None, output=None):
    stream = sys.stdin.buffer if stream is None else stream
    output = sys.stdout if output is None else output
    try:
        os.umask(0o077)
        start(read_password(stream))
        return 0
    except Exception as error:
        response = {"database_error": type(error).__name__}
        if isinstance(error, DatabaseInitializationFailed):
            response.update(stage="initdb", returncode=error.returncode)
            if error.diagnostics:
                response["diagnostics"] = error.diagnostics
        elif isinstance(error, subprocess.TimeoutExpired):
            response.update(stage="initdb", timeout_seconds=120)
        output.write(json.dumps(response) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
