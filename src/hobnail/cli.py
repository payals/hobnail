"""JSON-in/JSON-out operator CLI. Authentication is always explicit."""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Sequence

from .client import Client, Connection, PsqlTransport, TransportError, canonical_json, parse_json
from .contracts import ContractError, coverage_report, discover, validate_contract


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="hobnail", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    call = commands.add_parser("call", help="Send a JSON payload from stdin to one database API operation")
    call.add_argument("operation")
    call.add_argument("--host", required=True)
    call.add_argument("--database", required=True)
    call.add_argument("--user", required=True)
    call.add_argument("--port", type=int, default=5432)
    call.add_argument("--sslmode", choices=("disable", "require", "verify-ca", "verify-full"), default="require")
    call.add_argument("--sslrootcert")
    call.add_argument("--password-env", help="Explicit name of an environment variable holding a runtime password")
    call.add_argument("--timeout", type=float, default=30)
    call.add_argument("--connect-timeout", type=int, default=5)
    call.add_argument("--psql", default="psql", help="Path to a reviewed installed psql executable")
    validate = commands.add_parser("validate", help="Validate a complete contract supplied as stdin JSON")
    validate.add_argument("--activation", action="store_true", help="Also reject expired contracts")
    commands.add_parser("coverage", help="Report supported checks and still-required qualification evidence")
    commands.add_parser("discover", help="Suggest checks from {artifact_hex,inputs_hex?} supplied on stdin")
    return parser


def _read_input() -> Any:
    content = sys.stdin.read(24 * 1024 * 1024 + 1)
    if len(content) > 24 * 1024 * 1024:
        raise ValueError("stdin JSON exceeds the 24 MiB limit")
    return parse_json(content)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        payload = _read_input()
        if args.command == "call":
            if not isinstance(payload, dict):
                raise ValueError("API payload must be an object")
            password = None
            if args.password_env is not None:
                if args.password_env not in os.environ:
                    raise ValueError("the explicitly selected password environment variable is absent")
                password = os.environ[args.password_env]
            connection = Connection(host=args.host, database=args.database, user=args.user, port=args.port,
                                    password=password, sslmode=args.sslmode, sslrootcert=args.sslrootcert,
                                    connect_timeout=args.connect_timeout)
            result = Client(PsqlTransport(connection, psql=args.psql, timeout=args.timeout)).call(args.operation, payload)
            code = 0 if result["ok"] else 2
        elif args.command == "validate":
            result = {"ok": True, "status": "valid", "document": validate_contract(payload, for_activation=args.activation),
                      "approved": False, "qualified": False}
            code = 0
        elif args.command == "coverage":
            result = coverage_report(payload)
            code = 0 if result["supported"] else 2
        else:
            if not isinstance(payload, dict) or not {"artifact_hex"}.issubset(payload) or set(payload) - {"artifact_hex", "inputs_hex"}:
                raise ValueError("discovery requires {artifact_hex, inputs_hex?}")
            if not isinstance(payload["artifact_hex"], str) or not isinstance(payload.get("inputs_hex", {}), dict):
                raise ValueError("discovery content must use hexadecimal strings")
            content = bytes.fromhex(payload["artifact_hex"])
            inputs = {}
            for name, value in payload.get("inputs_hex", {}).items():
                if not isinstance(value, str):
                    raise ValueError("input content must use hexadecimal strings")
                inputs[name] = bytes.fromhex(value)
            result = discover(content, inputs)
            code = 0
    except ContractError as exc:
        result = {"ok": False, "status": "invalid", "code": exc.code, "path": exc.path, "detail": exc.detail}
        code = 4
    except TransportError as exc:
        result = {"ok": False, "status": "transport_error", "code": type(exc).__name__, "detail": str(exc),
                  "outcome": "unknown", "retry": "reconcile before any mutating retry"}
        code = 3
    except (ValueError, TypeError, UnicodeError, RecursionError):
        # Invalid input can contain secrets or untrusted control characters.
        result = {"ok": False, "status": "invalid", "code": "INVALID_REQUEST", "detail": "invalid command arguments or JSON input"}
        code = 4
    print(canonical_json(result))
    return code
