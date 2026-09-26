#!/usr/local/bin/python3.14 -ISB
"""Fixed administrative psql bridge for the unchanged transactional installer."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from hobnail.client import Connection, canonical_json, parse_json

SCRATCH = Path("/scratch")
CONFIG_NAME = "config.json"
CONFIG_LIMIT = 16_384
PSQL = "/usr/local/bin/psql"
ROLE_UIDS = {"admin": 70, "registrar": 10001, "approver": 10002, "worker": 10003,
             "verifier": 10004, "credential_provider": 10005, "adapter": 10006,
             "observer": 10007, "auditor": 10008}


def validate_config(value):
    if (not isinstance(value, dict) or not {"role", "connection", "psql"} <= value.keys()
            or value.keys() - {"role", "connection", "psql", "consumer"}):
        raise ValueError("invalid configuration fields")
    role = value["role"]
    if not isinstance(role, str) or role not in ROLE_UIDS or value["psql"] != PSQL:
        raise ValueError("unsupported role or executable")
    if os.getuid() != ROLE_UIDS[role] or os.geteuid() != ROLE_UIDS[role]:
        raise ValueError("configuration does not match process identity")
    document = value["connection"]
    allowed = {"host", "database", "user", "port", "password", "sslmode", "sslrootcert", "connect_timeout"}
    if (not isinstance(document, dict) or not {"host", "database", "user", "password"} <= document.keys()
            or document.keys() - allowed):
        raise ValueError("invalid connection fields")
    if (document["host"] != "/run/postgresql" or document.get("port", 5432) != 5432
            or document.get("sslmode", "disable") != "disable" or document.get("sslrootcert") is not None):
        raise ValueError("connection is outside the fixed socket")
    for key in ("database", "user"):
        if not isinstance(document[key], str) or not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", document[key]):
            raise ValueError("invalid database identity")
    password = document["password"]
    if not isinstance(password, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", password):
        raise ValueError("invalid explicit credential")
    connection = Connection(**{**document, "sslmode": "disable"})
    if connection.connect_timeout > 120:
        raise ValueError("connection timeout exceeds installer bound")
    if role == "admin" and connection.user != "postgres":
        raise ValueError("administrator login differs from bootstrap identity")
    if role in {"adapter", "observer"}:
        if value.get("consumer") != {"plugin": "file.publish", "root": "/destination"}:
            raise ValueError("consumer differs from the fixed destination")
    elif "consumer" in value:
        raise ValueError("role has no consumer authority")
    if len(canonical_json(value).encode("utf-8")) > CONFIG_LIMIT:
        raise ValueError("configuration exceeds its byte limit")
    return connection


def private_directory(path=SCRATCH):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("private directory is not canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("private directory has unsafe ownership or mode")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def write_config(value):
    validate_config(value)
    content = canonical_json(value).encode("utf-8")
    directory = private_directory(SCRATCH)
    try:
        descriptor = os.open(CONFIG_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(directory)


def read_config():
    directory = private_directory(SCRATCH)
    try:
        descriptor = os.open(CONFIG_NAME, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 0 < before.st_size <= CONFIG_LIMIT):
                raise ValueError("configuration is not a bounded private file")
            raw = stream.read(CONFIG_LIMIT + 1)
            after = os.fstat(stream.fileno())
            current = os.stat(CONFIG_NAME, dir_fd=directory, follow_symlinks=False)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            if identity(before) != identity(after) or identity(after) != identity(current) or len(raw) != before.st_size:
                raise ValueError("configuration changed during reading")
    finally:
        os.close(directory)
    value = parse_json(raw.decode("utf-8"))
    validate_config(value)
    return value


def _conninfo(value):
    """Parse the installer's exact quoted keyword grammar, without libpq."""
    if not isinstance(value, str) or len(value) > 8192 or "\x00" in value:
        raise ValueError("invalid installer connection")
    fields = {}
    position = 0
    pattern = re.compile(r"([a-z_]+)='((?:[^'\\]|\\['\\])*)'(?: |$)")
    while position < len(value):
        match = pattern.match(value, position)
        if match is None or match[1] in fields:
            raise ValueError("invalid or repeated connection field")
        fields[match[1]] = re.sub(r"\\(['\\])", r"\1", match[2])
        position = match.end()
    return fields


def installer_environment(arguments, environment, config):
    connection = validate_config(config)
    if config["role"] != "admin":
        raise ValueError("only the administrator may invoke the installer bridge")
    if (len(arguments) != 7 or list(arguments[:6]) != ["-X", "-q", "-A", "-t", "-w", "--dbname"]):
        raise ValueError("unsupported installer arguments")
    if (set(environment) != {"LC_ALL", "PGPASSFILE", "PGSERVICEFILE", "PGSYSCONFDIR"}
            or environment["LC_ALL"] != "C" or environment["PGPASSFILE"] != "/dev/null"
            or environment["PGSERVICEFILE"] != "/dev/null"):
        raise ValueError("installer environment differs from the closed environment")
    temporary = Path(environment["PGSYSCONFDIR"])
    if temporary.parent != SCRATCH or not re.fullmatch(r"hobnail-install-[a-z0-9_]{8}", temporary.name):
        raise ValueError("installer directory is outside private scratch")
    descriptor = private_directory(temporary)
    os.close(descriptor)
    expected = {"host": connection.host, "port": str(connection.port), "dbname": connection.database,
                "user": connection.user, "sslmode": "disable", "connect_timeout": str(connection.connect_timeout),
                "passfile": "/dev/null", "application_name": "hobnail-installer", "gssencmode": "disable",
                "sslcert": str(temporary / "absent.crt"), "sslkey": str(temporary / "absent.key"),
                "sslrootcert": str(temporary / "absent-root.crt"), "sslcrl": str(temporary / "absent-crl.pem"),
                "sslcrldir": str(temporary)}
    if _conninfo(arguments[6]) != expected:
        raise ValueError("installer connection differs from the owned configuration")
    for name in ("absent.crt", "absent.key", "absent-root.crt", "absent-crl.pem"):
        if os.path.lexists(temporary / name):
            raise ValueError("installer certificate path is not absent")
    return {**environment, "PGPASSWORD": connection.password}


def main():
    try:
        config = read_config()
        environment = installer_environment(sys.argv[1:], dict(os.environ), config)
        os.execve(PSQL, [PSQL, *sys.argv[1:]], environment)
        return 0
    except Exception:
        # psql/installer error bodies and connection data never leave this bridge.
        sys.stderr.write("owned installer connection refused\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
