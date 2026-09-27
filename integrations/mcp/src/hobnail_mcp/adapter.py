"""Closed worker operations, independent of the optional MCP framework.

The trusted launcher fixes the connection and expected stable principal. Tool
arguments cannot select an operation, credential, executable or service role.
Database envelopes remain authoritative; adapter failures never mint event IDs.
"""
from __future__ import annotations

from copy import deepcopy
import re
import threading
from typing import Any

from hobnail.client import Client, TransportError, canonical_json, parse_json
from hobnail.contracts import IDENTIFIER

MAX_ID = 9223372036854775807
MAX_ARTIFACT_BYTES = 1048576
MAX_REQUEST_BYTES = 2300000
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
OPERATIONS = {
    "get_contract": "contract.get",
    "put_artifact": "artifact.put",
    "submit_candidate": "candidate.submit",
    "get_candidate": "candidate.get",
    "request_effect": "effect.request",
    "get_effect": "effect.get",
    "cancel_effect": "effect.cancel",
}


class StartupRefused(RuntimeError):
    """A fixed safe startup code, never a raw configuration/transport error."""


def _identifier(value: Any) -> None:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ValueError("identifier")


def _integer(value: Any, maximum: int = MAX_ID) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("integer")


def _fields(value: Any, required: set[str], optional: set[str] = frozenset()) -> None:
    if type(value) is not dict or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("fields")


def validated_payload(name: str, arguments: Any) -> dict[str, Any]:
    """Check the exact public shape before any database operation occurs."""
    if name not in OPERATIONS:
        raise ValueError("tool")
    if name == "get_contract":
        _fields(arguments, {"contract_id"}, {"version"})
        _identifier(arguments["contract_id"])
        if arguments.get("version") is not None:
            _integer(arguments["version"], 2147483647)
    elif name == "put_artifact":
        _fields(arguments, {"content_hex", "media_type"})
        encoded, media_type = arguments["content_hex"], arguments["media_type"]
        if (not isinstance(encoded, str) or len(encoded) > 2 * MAX_ARTIFACT_BYTES
                or re.fullmatch(r"(?:[0-9a-f]{2})*", encoded) is None
                or not isinstance(media_type, str) or not 1 <= len(media_type) <= 128
                or "\x00" in media_type):
            raise ValueError("artifact")
    elif name == "submit_candidate":
        _fields(arguments, {"contract_id", "artifact_id", "inputs", "idempotency_key"})
        _identifier(arguments["contract_id"])
        _identifier(arguments["idempotency_key"])
        _integer(arguments["artifact_id"])
        inputs = arguments["inputs"]
        if type(inputs) is not dict or not 1 <= len(inputs) <= 16:
            raise ValueError("inputs")
        for source, snapshot_id in inputs.items():
            _identifier(source)
            _integer(snapshot_id)
    elif name == "request_effect":
        _fields(arguments, {"candidate_id", "action", "args", "idempotency_key"})
        _integer(arguments["candidate_id"])
        _identifier(arguments["action"])
        _identifier(arguments["idempotency_key"])
        if type(arguments["args"]) is not dict or len(canonical_json(arguments["args"]).encode("utf-8")) > 16384:
            raise ValueError("args")
    else:
        field = "candidate_id" if name == "get_candidate" else "effect_id"
        _fields(arguments, {field})
        _integer(arguments[field])
    encoded = canonical_json(arguments)
    if len(encoded.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise ValueError("request size")
    # Freeze mutable dictionaries and reject non-finite/lossy JSON values using
    # the core parser, before a thread or transport can observe their contents.
    result = parse_json(encoded)
    if name == "get_contract" and result.get("version") is None:
        result.pop("version", None)
    return result


def _unknown(operation: str, payload: dict, code: str) -> dict:
    reference = {key: payload[key] for key in ("candidate_id", "effect_id", "idempotency_key") if key in payload}
    return {"ok": False, "status": "transport_error", "origin": "adapter", "code": code,
            "outcome": "unknown", "operation": operation, "reference": reference,
            "retry": "Reconcile the original operation; do not change its idempotency key or blindly redispatch."}


class WorkerAdapter:
    """One fixed authenticated worker; no credential or identity switching."""

    def __init__(self, client: Client, *, expected_principal: str):
        try:
            _identifier(expected_principal)
        except (ValueError, TypeError):
            raise StartupRefused("INVALID_EXPECTED_PRINCIPAL") from None
        try:
            identity = client.call("session.get", {})
        except Exception:
            raise StartupRefused("IDENTITY_UNAVAILABLE") from None
        if not identity["ok"]:
            if identity.get("code") in {"UNKNOWN_OPERATION", "UNSUPPORTED_OPERATION"}:
                raise StartupRefused("PROTOCOL_UPGRADE_REQUIRED") from None
            raise StartupRefused("IDENTITY_REFUSED") from None
        data = identity["data"]
        if (type(data) is not dict or set(data) != {"principal_id", "role", "contracts", "valid_until"}
                or data["role"] != "worker" or data["principal_id"] != expected_principal
                or type(data["contracts"]) is not list
                or any(not isinstance(item, str) or IDENTIFIER.fullmatch(item) is None for item in data["contracts"])):
            raise StartupRefused("WORKER_IDENTITY_MISMATCH") from None
        self._client = client
        self.identity = deepcopy(data)
        self._slots = threading.BoundedSemaphore(4)

    def invoke(self, name: str, arguments: Any) -> dict:
        try:
            payload = validated_payload(name, arguments)
        except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
            return {"ok": False, "status": "invalid", "origin": "adapter", "code": "INVALID_REQUEST",
                    "detail": "Invalid tool name or arguments; no database operation was attempted."}
        operation = OPERATIONS[name]
        if not self._slots.acquire(blocking=False):
            return {"ok": False, "status": "busy", "origin": "adapter", "code": "CONCURRENCY_LIMIT",
                    "outcome": "not_attempted", "detail": "Four database calls are already active; this call was not attempted."}
        try:
            result = self._client.call(operation, payload)
            if len(canonical_json(result).encode("utf-8")) > MAX_RESPONSE_BYTES:
                return _unknown(operation, payload, "RESPONSE_TOO_LARGE")
            return result
        except TransportError as error:
            return _unknown(operation, payload, type(error).__name__)
        except Exception:
            # An unexpected exception after entering the transport cannot prove
            # that a mutation did not commit. Preserve uncertainty and redact it.
            return _unknown(operation, payload, "ADAPTER_FAILURE")
        finally:
            self._slots.release()
