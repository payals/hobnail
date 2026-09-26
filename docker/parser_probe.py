#!/usr/local/bin/python3.14 -ISB
"""Fixed qualification-only parser diagnostics; no archive, HTTP or DNS path."""

import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import sys
import time

COMMANDS = frozenset({"parser_boundaries", "sleep_timeout", "stdout_overflow", "stderr_overflow"})
SLEEP_SECONDS = 30
OVERFLOW_BYTES = 65_536


def read_payload(stream):
    raw = stream.read(1025)
    if not isinstance(raw, bytes) or len(raw) > 1024:
        raise ValueError("invalid parser probe frame")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate probe field")
            result[key] = value
        return result
    request = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    if (not isinstance(request, dict)
            or not isinstance(request.get("command"), str) or request["command"] not in COMMANDS):
        raise ValueError("unsupported parser probe")
    if request["command"] == "parser_boundaries":
        if (set(request) != {"command", "host_canary", "peer_pid"} or type(request["peer_pid"]) is not int
                or not 1 < request["peer_pid"] <= 2**31 - 1 or request["peer_pid"] == os.getpid()):
            raise ValueError("invalid parser boundary identity")
        validate_canary(request["host_canary"])
    elif set(request) != {"command"}:
        raise ValueError("unsupported parser probe fields")
    return request


def read_request(stream):
    return read_payload(stream)["command"]


def validate_canary(value):
    if (not isinstance(value, str) or len(value) > 200 or
            re.fullmatch(r"/(?:private/)?tmp/hbn-docker-[a-z0-9_-]+/supervisor-canary", value) is None):
        raise ValueError("invalid owned supervisor canary")


def attempt(action):
    try:
        action()
        return {"outcome": "allowed"}
    except OSError as error:
        outcome = {errno.EPERM: "policy_denied", errno.EACCES: "policy_denied",
                   errno.ENOENT: "absent", errno.ESRCH: "absent", errno.EROFS: "read_only"}.get(error.errno, "other_error")
        return {"outcome": outcome, "errno": error.errno}


def channel(family):
    kind = socket.SOCK_SEQPACKET if family == 38 else socket.SOCK_STREAM
    with socket.socket(family, kind):
        pass


def source_write():
    descriptor = os.open("/implementation.py", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    os.close(descriptor)


def open_access(path, *, write=False, directory=False, create=False):
    flags = (os.O_WRONLY if write else os.O_RDONLY) | os.O_NONBLOCK | os.O_NOFOLLOW
    if write:
        flags |= os.O_APPEND
    if directory:
        flags |= os.O_DIRECTORY
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    os.close(descriptor)


def connect_fixed(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(2)
        channel.connect(path)


def kernel_entrypoints():
    """Fixed Linux v7.0 scripts/syscall.tbl AArch64 native entrypoints only."""
    architecture = platform.machine()
    if sys.platform != "linux" or architecture != "aarch64":
        return {"architecture": architecture, "outcome": "unsupported_architecture"}
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # io_uring.h: ten u32 values and two 40-byte ring-offset structures.
    parameters = (ctypes.c_uint64 * 15)()
    calls = (("io_uring_setup", 425, (ctypes.c_uint(1), ctypes.byref(parameters))),
             ("io_uring_enter", 426, (ctypes.c_int(-1), ctypes.c_uint(0), ctypes.c_uint(0), ctypes.c_uint(0), ctypes.c_void_p(), ctypes.c_size_t(0))),
             ("io_uring_register", 427, (ctypes.c_int(-1), ctypes.c_uint(0), ctypes.c_void_p(), ctypes.c_uint(0))))
    results = {"socketcall": {"outcome": "not_in_abi", "architecture": architecture}}
    for name, number, arguments in calls:
        ctypes.set_errno(0)
        value = libc.syscall(ctypes.c_long(number), *arguments)
        if value == -1:
            observed_errno = ctypes.get_errno()
            results[name] = {"outcome": "policy_denied" if observed_errno in {errno.EPERM, errno.EACCES} else "other_error",
                             "errno": observed_errno}
        else:
            if name == "io_uring_setup":
                os.close(value)
            results[name] = {"outcome": "created" if name == "io_uring_setup" else "allowed"}
    return results


def fork_probe():
    try:
        child = os.fork()
    except OSError as error:
        return {"outcome": "policy_denied" if error.errno in {errno.EPERM, errno.EACCES} else "other_error", "errno": error.errno}
    if child == 0:
        os._exit(0)
    waited, status = os.waitpid(child, 0)
    return {"outcome": "created", "child_reaped": waited == child and os.WIFEXITED(status), "status": status}


def boundary_paths(host_canary, peer_pid):
    result = {"host_read": attempt(lambda: open_access(host_canary)),
              "host_write_open": attempt(lambda: open_access(host_canary, write=True)),
              "host_traversal": attempt(lambda: open_access("/scratch/.." + host_canary)),
              "daemon_socket": attempt(lambda: connect_fixed("/var/run/docker.sock")),
              "outside_write": attempt(lambda: open_access("/qualification-outside-scratch", write=True, create=True)),
              "outside_traversal_write": attempt(lambda: open_access("/scratch/../qualification-outside-traversal", write=True, create=True)),
              "server_data_traversal": attempt(lambda: open_access("/scratch/../../var/lib/postgresql/data/PG_VERSION")),
              "server_data_write_open": attempt(lambda: open_access("/var/lib/postgresql/data/PG_VERSION", write=True)),
              "destination": attempt(lambda: open_access("/destination/accepted.json")),
              "database_data": attempt(lambda: open_access("/var/lib/postgresql/data/PG_VERSION")),
              "postgres_socket": attempt(lambda: os.stat("/run/postgresql/.s.PGSQL.5432", follow_symlinks=False))}
    peer = {"host_pid": peer_pid, "own_pid": os.getpid()}
    for name, suffix, directory, write in (("config", "root/scratch/config.json", False, False),
            ("environment", "environ", False, False), ("descriptors", "fd", True, False),
            ("config_write_open", "root/scratch/config.json", False, True),
            ("config_traversal", "root/scratch/../scratch/config.json", False, False)):
        peer[name] = attempt(lambda suffix=suffix, directory=directory, write=write:
            open_access(f"/proc/{peer_pid}/{suffix}", write=write, directory=directory))
    peer["signal_continue"] = attempt(lambda: os.kill(peer_pid, signal.SIGCONT))
    result["peer"] = peer
    result["fork"] = fork_probe()
    return result


def inspect(request):
    source = Path("/implementation.py")
    with source.open("rb") as stream:
        readable = bool(stream.read(1))
    result = {"uid": os.getuid(), "own_implementation_readable": readable,
              "credential_environment_absent": "PGPASSWORD" not in os.environ}
    descriptor = os.open("/scratch/positive-control", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(b"owned-parser-control")
    result["scratch_positive"] = Path("/scratch/positive-control").read_bytes() == b"owned-parser-control"
    def configuration_read():
        descriptor = os.open("/scratch/config.json", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        os.close(descriptor)
    result["configuration"] = attempt(configuration_read)
    result["source_write"] = attempt(source_write)
    result["sockets"] = {str(family): attempt(lambda family=family: channel(family)) for family in (1, 2, 10, 38, 40)}
    result["kernel_entrypoints"] = kernel_entrypoints()
    result.update(boundary_paths(request["host_canary"], request["peer_pid"]))
    return result


def main(stream=None, output=None, error_output=None):
    stream = sys.stdin.buffer if stream is None else stream
    output = sys.stdout if output is None else output
    error_output = sys.stderr if error_output is None else error_output
    try:
        request = read_payload(stream)
        command = request["command"]
        if command == "sleep_timeout":
            time.sleep(SLEEP_SECONDS)
        elif command in {"stdout_overflow", "stderr_overflow"}:
            target = output if command == "stdout_overflow" else error_output
            target.write("x" * OVERFLOW_BYTES)
            target.flush()
        else:
            output.write(json.dumps(inspect(request), sort_keys=True) + "\n")
        return 0
    except Exception as error:
        output.write(json.dumps({"probe_error": type(error).__name__}) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
