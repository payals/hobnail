"""Fixed-worker stdio server; import FastMCP only after environment isolation."""
from __future__ import annotations

import argparse
import asyncio
from copy import deepcopy
import json
import logging
import os
import sys
import tempfile

from hobnail.client import canonical_json
from .adapter import MAX_ID, OPERATIONS, StartupRefused, WorkerAdapter
from .config import load_configuration
from .stdio import bounded_stdin

_framework_state: dict[str, str] | None = None


def framework_environment(home: str) -> None:
    """No dotenv, ambient settings, credential caches or telemetry discovery."""
    os.environ.clear()
    os.environ.update({"PATH": os.defpath, "LANG": "C.UTF-8", "FASTMCP_ENV_FILE": os.devnull,
                       "FASTMCP_HOME": home, "FASTMCP_TELEMETRY_MODE": "off",
                       "FASTMCP_LOG_ENABLED": "false", "FASTMCP_ENABLE_RICH_LOGGING": "false",
                       "FASTMCP_ENABLE_RICH_TRACEBACKS": "false", "FASTMCP_CHECK_FOR_UPDATES": "off",
                       "OTEL_SDK_DISABLED": "true"})
    logging.disable(logging.CRITICAL)
    global _framework_state
    _framework_state = dict(os.environ)


def tool_schemas() -> dict:
    identifier = {"type": "string", "pattern": r"^[A-Za-z0-9_.:/-]{1,128}$", "minLength": 1, "maxLength": 128}
    integer = {"type": "integer", "minimum": 1, "maximum": MAX_ID}
    definitions = {
        "get_contract": ({"contract_id": identifier, "version": {"anyOf": [{"type": "integer", "minimum": 1, "maximum": 2147483647}, {"type": "null"}]}}, ["contract_id"]),
        "put_artifact": ({"content_hex": {"type": "string", "pattern": "^([0-9a-f]{2})*$", "maxLength": 2097152},
                          "media_type": {"type": "string", "minLength": 1, "maxLength": 128}}, ["content_hex", "media_type"]),
        "submit_candidate": ({"contract_id": identifier, "artifact_id": integer, "idempotency_key": identifier,
                              "inputs": {"type": "object", "minProperties": 1, "maxProperties": 16,
                                         "propertyNames": identifier, "additionalProperties": integer}},
                             ["contract_id", "artifact_id", "inputs", "idempotency_key"]),
        "get_candidate": ({"candidate_id": integer}, ["candidate_id"]),
        "request_effect": ({"candidate_id": integer, "action": identifier, "args": {"type": "object"},
                            "idempotency_key": identifier}, ["candidate_id", "action", "args", "idempotency_key"]),
        "get_effect": ({"effect_id": integer}, ["effect_id"]),
        "cancel_effect": ({"effect_id": integer}, ["effect_id"]),
    }
    return {name: {"type": "object", "properties": deepcopy(properties), "required": required,
                   "additionalProperties": False} for name, (properties, required) in definitions.items()}


def create_server(adapter: WorkerAdapter):
    """Called only inside the launcher after framework_environment()."""
    if _framework_state is None or dict(os.environ) != _framework_state:
        raise StartupRefused("UNSAFE_FRAMEWORK_ENVIRONMENT")
    if any(name == "fastmcp" or name.startswith("fastmcp.") for name in sys.modules):
        raise StartupRefused("FRAMEWORK_ALREADY_IMPORTED")
    from fastmcp import FastMCP
    from fastmcp.tools.base import Tool, ToolResult
    from pydantic import PrivateAttr

    class WorkerTool(Tool):
        _worker: WorkerAdapter = PrivateAttr()

        async def run(self, arguments: dict) -> ToolResult:
            result = await asyncio.to_thread(self._worker.invoke, self.name, arguments)
            # Explicit compact text avoids framework pretty-print amplification.
            # The same complete receipt remains in structuredContent.
            return ToolResult(content=canonical_json(result), structured_content=result, is_error=not result["ok"])

    server = FastMCP("Hobnail worker", version="0.1.0", strict_input_validation=True,
                     mask_error_details=True, on_duplicate="error")
    descriptions = {
        "get_contract": "Read the scoped contract and its approval state. This read is audited.",
        "put_artifact": "Register exact lowercase-hex bytes, at most 1 MiB. Registration is not acceptance and is not idempotent.",
        "submit_candidate": "Submit registered artifact and input snapshot IDs using a persistent caller key. Submission is not acceptance.",
        "get_candidate": "Read current eligibility and recorded independent evidence. This read is audited.",
        "request_effect": "Request the exact approved action using a persistent caller key. Reservation is not dispatch or completion.",
        "get_effect": "Read current dispatch and independent observation state. Reconcile uncertain effects; never blindly redispatch.",
        "cancel_effect": "Request cancellation of an existing effect. Cancellation cannot undo an already dispatched action.",
    }
    for name, schema in tool_schemas().items():
        tool = WorkerTool(name=name, description=descriptions[name], parameters=schema,
                          output_schema={"type": "object", "properties": {"ok": {"type": "boolean"}, "status": {"type": "string"}},
                                         "required": ["ok", "status"]})
        tool._worker = adapter
        server.add_tool(tool)
    return server


class _Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise StartupRefused("INVALID_LAUNCH_ARGUMENTS")


def main(argv=None) -> int:
    parser = _Arguments(description="Worker-only stdio MCP. Explicit private configuration; no remote listener.")
    parser.add_argument("--config", required=True, help="canonical private worker configuration path")
    serving = False
    try:
        arguments = parser.parse_args(argv)
        configuration = load_configuration(arguments.config)
        adapter = configuration.adapter()
        with tempfile.TemporaryDirectory(prefix="hobnail-mcp-") as directory:
            framework_environment(directory)
            server = create_server(adapter)
            serving = True
            with bounded_stdin() as state:
                server.run(transport="stdio", show_banner=False, log_level="CRITICAL")
            if state.error is not None:
                raise StartupRefused(state.error)
        return 0
    except StartupRefused as error:
        code = str(error)
    except ModuleNotFoundError:
        code = "OPTIONAL_DEPENDENCY_UNAVAILABLE"
    except KeyboardInterrupt:
        return 130
    except Exception:
        code = "SERVER_FAILURE"
    print(json.dumps({"status": "server_refused" if serving else "startup_refused", "code": code}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
