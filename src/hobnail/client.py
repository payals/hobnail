"""Language-neutral JSON API over one short-lived, explicit psql connection.

No ambient libpq credentials, psql startup files, service definitions, or shell
are used. Every call commits independently. Transport errors are deliberately
separate from recorded denials: a lost response can leave a committed operation.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from decimal import Decimal
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import tempfile
import time
from typing import Any, Mapping, Protocol


class TransportError(RuntimeError):
    """The response is unavailable; the server's commit outcome may be unknown."""


class TransportTimeout(TransportError):
    """The client killed and reaped its connection after the configured deadline."""


class TransportOutputLimit(TransportError):
    """A bounded client killed/reaped its child without an authoritative reply."""


def _stop_owned_child(process: subprocess.Popen) -> None:
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        raise TransportError("psql child cleanup is unconfirmed; operation outcome is unknown") from None


def _bounded_psql(arguments, sql, environment, timeout, stdout_limit):
    """Capture bounded pipe bytes with a deadline covering writes and reads.

    No preexec_fn, shell, credential discovery or retry. Only this Popen child's
    PID is killed; PostgreSQL transaction outcome remains unknown on interruption.
    """
    payload = sql.encode("utf-8")
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, bufsize=0)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    offset = 0
    try:
        with selectors.DefaultSelector() as selector:
            for name, stream in (("stdin", process.stdin), ("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                if name == "stdin" and not payload:
                    stream.close()
                else:
                    selector.register(stream, selectors.EVENT_WRITE if name == "stdin" else selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(arguments, timeout)
                for key, _ in selector.select(remaining):
                    if key.data == "stdin":
                        try:
                            offset += os.write(key.fd, payload[offset:offset + 65536])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            offset = len(payload)
                        if offset == len(payload):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        try:
                            block = os.read(key.fd, 65536)
                        except BlockingIOError:
                            continue
                        if not block:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        limit = stdout_limit if key.data == "stdout" else 65536
                        if len(buffers[key.data]) + len(block) > limit:
                            raise TransportOutputLimit("psql output exceeded its configured bound; operation outcome is unknown")
                        buffers[key.data].extend(block)
            process.wait(timeout=max(0, deadline - time.monotonic()))
        try:
            stdout = buffers["stdout"].decode("utf-8")
        except UnicodeError:
            raise TransportError("psql returned invalid UTF-8; operation outcome is unknown") from None
        return subprocess.CompletedProcess(arguments, process.returncode, stdout, buffers["stderr"].decode("utf-8", errors="replace"))
    except subprocess.TimeoutExpired:
        _stop_owned_child(process)
        raise TransportTimeout("psql timed out; operation outcome is unknown; reconcile before retrying") from None
    except BaseException:
        _stop_owned_child(process)
        raise
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


class PasswordAuthenticationFailed(TransportError):
    """psql reported an actual password rejection, with diagnostics redacted.

    This identifies an authentication failure, not a policy denial or proof
    about earlier operations. Other connection failures remain inconclusive.
    """


class ProtocolError(TransportError):
    """The endpoint returned something other than a valid Hobnail envelope."""


class Denied(RuntimeError):
    """A durable, server-recorded policy denial."""

    def __init__(self, response: Mapping[str, Any]):
        self.response = dict(response)
        self.code = str(response["code"])
        super().__init__(f"{self.code}: {response['detail']}")


@dataclass(frozen=True)
class Connection:
    """Explicit connection target. Passwords must be supplied by the caller.

    ``sslmode=require`` encrypts TCP traffic but does not establish server
    identity. Use ``verify-full`` with an explicitly supplied trusted root for
    production TCP connections. Local owned test clusters can use ``disable``.
    """

    host: str
    database: str
    user: str
    port: int = 5432
    password: str | None = field(default=None, repr=False)
    sslmode: str = "require"
    sslrootcert: str | None = None
    connect_timeout: int = 5

    def __post_init__(self) -> None:
        for name in ("host", "database", "user"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError(f"{name} must be an explicit nonempty string without NUL")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        if type(self.connect_timeout) is not int or not 1 <= self.connect_timeout <= 3600:
            raise ValueError("connect_timeout must be an integer between 1 and 3600")
        if self.sslmode not in {"disable", "require", "verify-ca", "verify-full"}:
            raise ValueError("sslmode must be disable, require, verify-ca, or verify-full")
        if self.sslmode in {"verify-ca", "verify-full"} and not self.sslrootcert:
            raise ValueError("certificate verification requires an explicit sslrootcert")
        if self.password is not None and (not isinstance(self.password, str) or "\x00" in self.password):
            raise ValueError("password must be a string without NUL")
        if self.sslrootcert is not None and (not isinstance(self.sslrootcert, str) or not self.sslrootcert or "\x00" in self.sslrootcert):
            raise ValueError("sslrootcert must be an explicit path without NUL")


class Transport(Protocol):
    def call(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]: ...


def canonical_json(value: Any) -> str:
    """Stable UTF-8 JSON for local artifacts; reject NaN and non-JSON objects."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _literal(value: str) -> str:
    """Quote a libpq keyword value, not an SQL value or shell argument."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(text: str) -> Any:
    def invalid_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant: {value}")
    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("JSON number exceeds finite float range")
        if Decimal(value) != Decimal(str(number)):
            raise ValueError("JSON number cannot round-trip without losing precision")
        return number
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=invalid_constant, parse_float=finite_float)


def validate_envelope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or type(value.get("ok")) is not bool:
        raise ProtocolError("server response is missing a boolean ok field")
    if not isinstance(value.get("status"), str) or not value["status"]:
        raise ProtocolError("server response is missing a status")
    if type(value.get("event_id")) is not int or value["event_id"] < 1:
        raise ProtocolError("server response is missing a valid event_id")
    if value["ok"]:
        if "data" not in value or value["status"] == "denied":
            raise ProtocolError("successful response is malformed")
    elif value["status"] != "denied" or not isinstance(value.get("code"), str) or not isinstance(value.get("detail"), dict):
        raise ProtocolError("denial response is malformed")
    return value


class PsqlTransport:
    """Run installed psql with safe encoded data on stdin and no retry behavior."""

    def __init__(self, connection: Connection, *, psql: str = "psql", timeout: float = 30.0,
                 max_output_bytes: int | None = None):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        executable = shutil.which(psql)
        if executable is None:
            raise ValueError("installed psql executable was not found")
        if max_output_bytes is not None and (type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 64 * 1024 * 1024):
            raise ValueError("max_output_bytes must be within 1 byte and 64 MiB")
        self.connection = connection
        self.psql = str(Path(executable).absolute())
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

    def call(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(operation, str) or not operation or "\x00" in operation:
            raise ValueError("operation must be a nonempty string without NUL")
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a JSON object")
        encoded_operation = base64.b64encode(operation.encode("utf-8")).decode("ascii")
        encoded_payload = base64.b64encode(canonical_json(dict(payload)).encode("utf-8")).decode("ascii")
        if len(encoded_payload) > 24 * 1024 * 1024:
            raise ValueError("payload exceeds the 18 MiB request limit")
        sql = (
            "SELECT hobnail.api(convert_from(decode('" + encoded_operation + "','base64'),'UTF8'),"
            "convert_from(decode('" + encoded_payload + "','base64'),'UTF8')::jsonb);\n"
        )
        output = self.execute_sql(sql)
        try:
            value = parse_json(output.strip())
        except (ValueError, TypeError) as exc:
            raise ProtocolError("psql did not return exactly one JSON response") from None
        return validate_envelope(value)

    def execute_sql(self, sql: str, *, sensitive: bool = False) -> str:
        """Execute trusted internal SQL, never arbitrary application/user input.

        This is for the separately privileged credential provider. It is not
        exposed by the CLI. All errors are redacted regardless of ``sensitive``;
        callers must separately ensure server statement logging is appropriate.
        SQL travels only over stdin, not process arguments. No retry is made.
        """
        if not isinstance(sql, str) or "\x00" in sql:
            raise ValueError("SQL must be trusted text without NUL")
        c = self.connection
        with tempfile.TemporaryDirectory(prefix="hobnail-psql-") as home:
            options = {
                "host": c.host, "port": str(c.port), "dbname": c.database, "user": c.user,
                "connect_timeout": str(c.connect_timeout), "sslmode": c.sslmode,
                "passfile": os.devnull, "application_name": "hobnail-sdk",
                "gssencmode": "disable", "sslcert": os.devnull, "sslkey": os.devnull,
                "sslrootcert": str(Path(home) / "no-root.crt"), "sslcrl": str(Path(home) / "no-crl.pem"),
                "sslcrldir": home,
            }
            if c.sslrootcert:
                options["sslrootcert"] = str(Path(c.sslrootcert).absolute())
            # Explicit null certificate paths prevent libpq consulting personal
            # ~/.postgresql even on platforms that resolve HOME through passwd.
            # libpq ignores absent client certificates; /dev/null is only used
            # with SSL disabled below, because it is not a valid certificate.
            if c.sslmode != "disable":
                options["sslcert"] = str(Path(home) / "no-client.crt")
                options["sslkey"] = str(Path(home) / "no-client.key")
            env = {
                "LC_ALL": "C", "PGPASSFILE": os.devnull,
                "PGSERVICEFILE": os.devnull, "PGSYSCONFDIR": home,
            }
            if c.password is not None:
                env["PGPASSWORD"] = c.password
            args = [
                self.psql, "-X", "-w", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
                "-v", "VERBOSITY=terse", "-P", "pager=off", "--dbname",
                " ".join(f"{key}={_literal(value)}" for key, value in options.items()),
            ]
            try:
                if self.max_output_bytes is None:
                    result = subprocess.run(args, input=sql, text=True, encoding="utf-8", capture_output=True,
                                            timeout=self.timeout, env=env, check=False)
                else:
                    result = _bounded_psql(args, sql, env, self.timeout, self.max_output_bytes)
            except subprocess.TimeoutExpired as exc:
                raise TransportTimeout("psql timed out; operation outcome is unknown; reconcile before retrying") from None
            except OSError as exc:
                raise TransportError("psql could not start; no API response was received") from None
        if result.returncode:
            # Error text may contain connection details or server-provided data.
            # Do not echo it or put runtime credentials into logs/exceptions.
            if result.returncode == 2 and re.search(
                r'^(?:psql: error: [^\r\n]*: )?FATAL:[ \t]+password authentication failed for user "[^"\r\n]+"$',
                result.stderr, re.MULTILINE,
            ):
                raise PasswordAuthenticationFailed("PostgreSQL rejected password authentication")
            raise TransportError(f"psql exited with status {result.returncode}; operation outcome is unknown")
        return result.stdout


class Client:
    def __init__(self, transport: Transport):
        self.transport = transport

    def call(self, operation: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Return success or recorded denial; do not silently raise or retry."""
        return validate_envelope(self.transport.call(operation, {} if payload is None else payload))

    def require(self, operation: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Return a success envelope, or raise Denied containing the full receipt."""
        result = self.call(operation, payload)
        if not result["ok"]:
            raise Denied(result)
        return result

    def propose_contract(self, contract_id: str, version: int, document: Mapping[str, Any]) -> dict[str, Any]:
        from .contracts import validate_contract
        validate_contract(document)
        return self.call("contract.propose", {"contract_id": contract_id, "version": version, "document": dict(document)})

    def activate_contract(self, contract_id: str, version: int, *, expected_active_version: int | None) -> dict[str, Any]:
        return self.call("contract.activate", {"contract_id": contract_id, "version": version,
                                                "expected_active_version": expected_active_version})

    def put_artifact(self, content: bytes, *, media_type: str) -> dict[str, Any]:
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        return self.call("artifact.put", {"content_hex": content.hex(), "media_type": media_type})

    def put_input(self, contract_id: str, source: str, version: int, content: bytes, *, media_type: str,
                  expected_current: int | None) -> dict[str, Any]:
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        return self.call("input.put", {"contract_id": contract_id, "source": source, "version": version,
                                       "content_hex": content.hex(), "media_type": media_type,
                                       "expected_current": expected_current})

    def submit(self, contract_id: str, artifact_id: int, inputs: Mapping[str, int], *, idempotency_key: str) -> dict[str, Any]:
        return self.call("candidate.submit", {"contract_id": contract_id, "artifact_id": artifact_id,
                                              "inputs": dict(inputs), "idempotency_key": idempotency_key})

    def candidate(self, candidate_id: int) -> dict[str, Any]:
        return self.call("candidate.get", {"candidate_id": candidate_id})

    def claim_verification(self, candidate_id: int, *, lease_seconds: int = 60) -> dict[str, Any]:
        return self.call("verification.claim", {"candidate_id": candidate_id, "lease_seconds": lease_seconds})

    def record_verification(self, candidate_id: int, *, token: str, generation: int, binding_digest: str,
                            check_id: str, plugin_digest: str, result: str, detail: Mapping[str, Any]) -> dict[str, Any]:
        return self.call("verification.record", {"candidate_id": candidate_id, "token": token,
                         "generation": generation, "binding_digest": binding_digest, "check_id": check_id,
                         "plugin_digest": plugin_digest, "result": result, "detail": dict(detail)})

    def accept(self, candidate_id: int) -> dict[str, Any]:
        return self.call("candidate.accept", {"candidate_id": candidate_id})

    def request_effect(self, candidate_id: int, action: str, args: Mapping[str, Any], *, idempotency_key: str) -> dict[str, Any]:
        return self.call("effect.request", {"candidate_id": candidate_id, "action": action, "args": dict(args),
                                            "idempotency_key": idempotency_key})

    def effect(self, effect_id: int) -> dict[str, Any]:
        return self.call("effect.get", {"effect_id": effect_id})

    def cancel_effect(self, effect_id: int) -> dict[str, Any]:
        return self.call("effect.cancel", {"effect_id": effect_id})

    def export_audit(self, *, after: int = 0, limit: int = 1000) -> dict[str, Any]:
        return self.call("audit.export", {"after": after, "limit": limit})
