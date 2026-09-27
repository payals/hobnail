"""Real FastMCP stdio against an explicitly synthetic transport, on POSIX.

No database or protected-role qualification is claimed here. The test-only
server script is generated in an owned retained directory; production startup
has no fixture mode, alternate transport or authentication bypass.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "integrations/mcp/src")]
from hobnail_mcp.adapter import OPERATIONS
from hobnail_mcp.client import MCPClientError, WorkerMCPClient
from hobnail_mcp.stdio import MAX_INPUT_FRAME


HARNESS = r'''
import json, os, sys, subprocess, time, threading
from pathlib import Path
sys.path[:0] = SOURCE_PATHS
from hobnail.client import Client, TransportTimeout
from hobnail_mcp.adapter import MAX_RESPONSE_BYTES, WorkerAdapter
from hobnail_mcp.server import create_server, framework_environment
from hobnail_mcp.stdio import bounded_stdin

root = Path(sys.argv[1])
def audit(event, arguments):
    blocked = event == "socket.connect"
    if event == "open" and arguments and isinstance(arguments[0], (str, bytes)):
        blocked = Path(os.fsdecode(arguments[0])).name in {".env", ".netrc", ".pgpass"}
    if blocked:
        descriptor = os.open(root / "forbidden-observation.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump({"event": event}, stream)
        raise PermissionError("owned fixture refused unexpected configuration or network access")
sys.addaudithook(audit)

class SyntheticTransport:
    def __init__(self): self.event = 0
    def call(self, operation, payload):
        self.event += 1
        if operation == "session.get":
            data = {"principal_id": "fixture-worker", "role": "worker", "contracts": ["fixture"], "valid_until": None}
        elif payload.get("contract_id") == "transport-timeout":
            raise TransportTimeout("synthetic-private-exception-value")
        elif payload.get("contract_id") == "refused":
            return {"ok": False, "status": "denied", "event_id": self.event, "code": "SCOPE_MISMATCH", "detail": {}}
        elif payload.get("contract_id") == "oversized-response":
            data = {"value": "x" * MAX_RESPONSE_BYTES}
        elif payload.get("contract_id") == "stderr-flood":
            sys.stderr.write("synthetic-stderr-flood" * 100000)
            sys.stderr.flush()
            time.sleep(60)
            data = {}
        elif payload.get("contract_id") == "response-before-stderr":
            def late_flood():
                for _ in range(500):
                    if (root / "release-stderr").exists():
                        sys.stderr.write("synthetic-late-stderr" * 100000)
                        sys.stderr.flush()
                        return
                    time.sleep(0.01)
            threading.Thread(target=late_flood, daemon=False).start()
            data = {"fixture_only": True, "response_before_stderr": True}
        elif payload.get("contract_id") == "early-leader-exit":
            child = "import os,time;from pathlib import Path;Path(" + repr(str(root / "descendant.pid")) + ").write_text(str(os.getpid()));os.close(1);os.close(2);time.sleep(60)"
            subprocess.Popen([sys.executable, "-I", "-B", "-c", child], close_fds=True)
            for _ in range(100):
                if (root / "descendant.pid").exists(): break
                time.sleep(0.01)
            os._exit(0)
        else:
            data = {"fixture_only": True, "operation": operation, "payload": payload}
        return {"ok": True, "status": "ok", "event_id": self.event, "data": data}

framework_environment(str(root))
server = create_server(WorkerAdapter(Client(SyntheticTransport()), expected_principal="fixture-worker"))
with bounded_stdin() as state:
    server.run(transport="stdio", show_banner=False, log_level="CRITICAL")
if state.error is not None:
    print(json.dumps({"status": "server_refused", "code": state.error}), file=sys.stderr)
    raise SystemExit(2)
'''


class FixtureClient(WorkerMCPClient):
    def _command(self):
        return [self.python, "-I", "-B", str(self.config_path.parent / "fixture-server.py"), str(self.config_path.parent)]


class MCPProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="hbn-mcp-protocol-")).resolve()
        self.root.chmod(0o700)
        paths = [str(ROOT / "src"), str(ROOT / "integrations/mcp/src")]
        (self.root / "fixture-server.py").write_text(textwrap.dedent(HARNESS).replace("SOURCE_PATHS", repr(paths)))
        (self.root / "fixture.json").write_text("{}")
        self.dotenv = self.root / ".env"
        self.dotenv.write_text("FASTMCP_TELEMETRY_MODE=invalid-owned-trap\n")
        self.dotenv.chmod(0o000)
        self.clients = []

    async def asyncTearDown(self):
        for client in self.clients:
            await client.close()
        self.dotenv.chmod(0o600)
        # Retain actual framework failures, stderr and inert fixture source.
        (self.root / "scope.json").write_text(json.dumps({"test": self.id(), "scope": "real stdio, synthetic transport only",
            "database_qualified": False, "processes": [{"pid": item.pid, "closed": item.closed, "returncode": item.returncode,
                                                         "protocol": item.negotiated_version} for item in self.clients]}, indent=2))

    def client(self, protocol="2025-11-25"):
        client = FixtureClient(self.root / "fixture.json", log_path=self.root / f"stderr-{len(self.clients)}.txt",
            protocol_version=protocol, timeout_seconds=15,
            environment={"FASTMCP_ENV_FILE": str(self.dotenv), "FASTMCP_TELEMETRY_MODE": "invalid-owned-trap",
                         "FASTMCP_TRANSPORT": "http", "FASTMCP_PORT": "not-an-integer",
                         "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:1"})
        self.clients.append(client)
        return client

    async def exercise(self, protocol):
        client = self.client(protocol)
        async with client:
            tools = await client.list_tools()
            self.assertEqual({tool["name"] for tool in tools}, set(OPERATIONS))
            self.assertTrue(all(tool["inputSchema"]["additionalProperties"] is False for tool in tools))
            result = await client.call_tool("get_contract", {"contract_id": "fixture"})
            self.assertEqual(result["data"]["payload"], {"contract_id": "fixture"})
            content = b' {"value":7,"escape":"\\u0061"}\n'
            artifact = await client.call_tool("put_artifact", {"content_hex": content.hex(), "media_type": "application/json"})
            self.assertEqual(artifact["data"]["payload"]["content_hex"], content.hex())
            denied = await client.call_tool("get_contract", {"contract_id": "refused"})
            self.assertEqual(denied["code"], "SCOPE_MISMATCH")
            self.assertTrue(client.last_is_error)
            unknown = await client.call_tool("get_contract", {"contract_id": "transport-timeout"})
            self.assertEqual(unknown["outcome"], "unknown")
            self.assertEqual(unknown["code"], "TransportTimeout")
            self.assertNotIn("event_id", unknown)
            self.assertNotIn("synthetic-private-exception-value", json.dumps(unknown))
            oversized = await client.call_tool("get_contract", {"contract_id": "oversized-response"})
            self.assertEqual(oversized["code"], "RESPONSE_TOO_LARGE")
            self.assertEqual(oversized["outcome"], "unknown")
            self.assertNotIn("event_id", oversized)
            for name, arguments in (("api", {"operation": "contract.activate"}),
                                    ("get_candidate", {"candidate_id": True}),
                                    ("get_candidate", {"candidate_id": "1"}),
                                    ("get_candidate", {"candidate_id": 1, "role": "approver"})):
                try:
                    malformed = await client.call_raw(name, arguments)
                    self.assertTrue(malformed.get("isError"), str(self.root))
                except MCPClientError as error:
                    self.assertEqual(error.code, "MCP_PROTOCOL_ERROR", str(self.root))
        self.assertEqual(client.negotiated_version, protocol)
        self.assertEqual(client.returncode, 0, str(self.root))
        self.assertTrue(client.closed)
        self.assertFalse((self.root / "forbidden-observation.json").exists(), str(self.root))
        self.assertNotIn("synthetic-private-exception-value", client.log_path.read_text())

    async def test_real_legacy_stdio_fixed_surface_and_redacted_results(self):
        await self.exercise("2025-11-25")

    async def test_real_modern_stdio_fixed_surface_and_redacted_results(self):
        await self.exercise("2026-07-28")

    async def rejected_frame(self, content, code):
        client = self.client()
        async with client:
            self.assertEqual(len(await client.list_tools()), 7)
            try:
                client._process.stdin.write(content)
                await asyncio.wait_for(client._process.stdin.drain(), timeout=5)
            except (BrokenPipeError, ConnectionResetError):
                pass
            await asyncio.wait_for(client._process.wait(), timeout=10)
        self.assertEqual(client.returncode, 2, str(self.root))
        error = json.loads(client.log_path.read_text())
        self.assertEqual(error, {"status": "server_refused", "code": code})
        self.assertTrue(client.closed)

    async def test_oversize_wire_frame_refuses_before_framework_parse(self):
        await self.rejected_frame(b'{"x":"' + b'a'*MAX_INPUT_FRAME + b'"}\n', "STDIO_FRAME_TOO_LARGE")

    async def test_duplicate_json_keys_refuse_before_framework_collapse(self):
        await self.rejected_frame(b'{"jsonrpc":"2.0","id":9,"id":10,"method":"tools/list","params":{}}\n', "STDIO_INVALID_JSON")

    async def test_stderr_is_bounded_and_overflow_retires_owned_group(self):
        client = self.client()
        async with client:
            self.assertEqual(len(await client.list_tools()), 7)
            with self.assertRaises(MCPClientError) as caught:
                await client.call_tool("get_contract", {"contract_id": "stderr-flood"})
            self.assertEqual(caught.exception.code, "MCP_STDERR_LIMIT", str(self.root))
        self.assertTrue(client.closed)
        self.assertTrue(client.group_retired)
        self.assertLessEqual(client.log_path.stat().st_size, 65536)
        with self.assertRaises(ProcessLookupError): os.killpg(client.pid, 0)

    async def test_early_leader_exit_does_not_leave_owned_descendant(self):
        client = self.client()
        async with client:
            self.assertEqual(len(await client.list_tools()), 7)
            with self.assertRaises(MCPClientError) as caught:
                await client.call_tool("get_contract", {"contract_id": "early-leader-exit"})
            self.assertEqual(caught.exception.code, "MCP_SERVER_EXITED", str(self.root))
        self.assertTrue(client.closed, str(self.root))
        self.assertTrue(client.group_retired, str(self.root))
        descendant = int((self.root / "descendant.pid").read_text())
        with self.assertRaises(ProcessLookupError): os.kill(descendant, 0)
        with self.assertRaises(ProcessLookupError): os.killpg(client.pid, 0)

    async def test_successful_response_cannot_hide_later_stderr_capture_failure(self):
        client = self.client()
        received = None
        with self.assertRaises(MCPClientError) as caught:
            async with client:
                received = await client.call_tool("get_contract", {"contract_id": "response-before-stderr"})
                self.assertTrue(received["data"]["response_before_stderr"])
                (self.root / "release-stderr").write_text("the response was actually received")
                await asyncio.wait_for(asyncio.shield(client._stderr_task), timeout=5)
        self.assertEqual(caught.exception.code, "MCP_STDERR_LIMIT", str(self.root))
        self.assertIsNotNone(received)
        self.assertTrue(received["ok"])
        self.assertTrue(client.closed)
        self.assertTrue(client.group_retired)
        self.assertLessEqual(client.log_path.stat().st_size, 65536)


if __name__ == "__main__":
    unittest.main()
