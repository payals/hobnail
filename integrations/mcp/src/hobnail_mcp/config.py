"""Read only the explicitly named private worker configuration."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat

from hobnail.client import Client, Connection, PsqlTransport, parse_json
from hobnail.contracts import IDENTIFIER

from .adapter import MAX_RESPONSE_BYTES, StartupRefused, WorkerAdapter


@dataclass(frozen=True, repr=False)
class WorkerConfiguration:
    connection: Connection
    psql: str
    timeout_seconds: int
    expected_principal: str

    def adapter(self) -> WorkerAdapter:
        return WorkerAdapter(Client(PsqlTransport(self.connection, psql=self.psql, timeout=self.timeout_seconds,
                             max_output_bytes=MAX_RESPONSE_BYTES)),
                             expected_principal=self.expected_principal)


def load_configuration(path: str | Path) -> WorkerConfiguration:
    """No environment, libpq service, personal auth or default config discovery."""
    try:
        path = Path(path).absolute()
        if path.resolve(strict=True) != path or not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("canonical POSIX file required")
        parent = path.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise ValueError("private owner-controlled parent required")
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                    or before.st_mode & 0o077 or not 0 < before.st_size <= 16384):
                raise ValueError("private regular configuration required")
            raw = stream.read(16385)
            after = os.fstat(stream.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if len(raw) != before.st_size or identity(before) != identity(after) or identity(after) != identity(path.stat()):
            raise ValueError("configuration changed")
        value = parse_json(raw.decode("utf-8"))
        fields = {"schema_version", "role", "expected_principal", "connection", "psql", "timeout_seconds", "owned_development"}
        if (type(value) is not dict or set(value) != fields or type(value["schema_version"]) is not int
                or value["schema_version"] != 1 or value["role"] != "worker"
                or not isinstance(value["expected_principal"], str)
                or IDENTIFIER.fullmatch(value["expected_principal"]) is None
                or type(value["owned_development"]) is not bool
                or type(value["timeout_seconds"]) is not int or not 1 <= value["timeout_seconds"] <= 120):
            raise ValueError("closed worker configuration required")
        connection = value["connection"]
        required = {"host", "port", "database", "user", "password", "sslmode", "connect_timeout"}
        if (type(connection) is not dict or not required <= connection.keys()
                or connection.keys() - required - {"sslrootcert"}
                or not isinstance(connection["password"], str) or not 1 <= len(connection["password"]) <= 1024
                or "\x00" in connection["password"]):
            raise ValueError("explicit connection required")
        host = connection["host"]
        # libpq interprets comma-separated host lists (including empty entries).
        # They must not turn a permitted Unix/loopback value into a fallback
        # remote connection or an ambient default socket.
        if (not isinstance(host, str) or not host or "," in host or "\x00" in host
                or any(character.isspace() for character in host)):
            raise ValueError("one explicit unambiguous database endpoint required")
        if value["owned_development"]:
            if (not (host.startswith("/") or host in {"127.0.0.1", "::1"})
                    or connection["sslmode"] != "disable" or connection.get("sslrootcert") is not None):
                raise ValueError("owned development requires explicit local connection")
        elif (connection["sslmode"] != "verify-full" or not connection.get("sslrootcert")
              or host.startswith(("/", "@"))):
            raise ValueError("verified TLS and explicit trusted root required")
        if connection.get("sslrootcert") is not None:
            root = Path(connection["sslrootcert"]).absolute()
            if root.resolve(strict=True) != root or not root.is_file():
                raise ValueError("canonical certificate required")
        executable = Path(value["psql"])
        if (not executable.is_absolute() or executable.resolve(strict=True) != executable
                or not executable.is_file() or not os.access(executable, os.X_OK)):
            raise ValueError("canonical reviewed executable required")
        return WorkerConfiguration(Connection(**connection), str(executable), value["timeout_seconds"], value["expected_principal"])
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, RecursionError):
        raise StartupRefused("INVALID_WORKER_CONFIGURATION") from None
