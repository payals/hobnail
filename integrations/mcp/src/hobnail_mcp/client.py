"""Bounded stdlib stdio client for Hobnail's owned qualification workflows.

This is not a general MCP SDK. It implements discovery/initialization, tool
listing/calling and owned subprocess shutdown only. It imports no FastMCP or
credential-discovery library. A cancelled or timed-out call may have committed.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import signal
import sys

from hobnail.client import ProtocolError, canonical_json, parse_json, validate_envelope

MAX_FRAME = 36_000_000
MAX_STDERR = 65536
VERSIONS = {"2025-11-25", "2026-07-28"}


class MCPClientError(RuntimeError):
    def __init__(self, code: str, *, rpc_code=None, outcome="unknown"):
        self.code, self.rpc_code, self.outcome = code, rpc_code, outcome
        super().__init__(code)


class WorkerMCPClient:
    def __init__(self, config_path, *, log_path, python=sys.executable, source_root=None,
                 timeout_seconds=120, protocol_version="2025-11-25", environment=None):
        if protocol_version not in VERSIONS:
            raise ValueError("unsupported explicitly selected MCP protocol")
        if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 300:
            raise ValueError("bounded client timeout required")
        # Keep the supplied spelling: the server itself must reject aliases,
        # rather than the test client silently canonicalizing an unsafe config.
        self.config_path = Path(config_path).absolute()
        self.log_path = Path(log_path).absolute()
        if self.log_path.parent.resolve(strict=True) != self.log_path.parent:
            raise ValueError("canonical existing log directory required")
        self.python = str(Path(python).absolute())
        self.source_root = Path(source_root).resolve(strict=True) if source_root is not None else None
        self.timeout_seconds = timeout_seconds
        self.protocol_version = protocol_version
        self.negotiated_version = None
        self.last_is_error = False
        self.closed = False
        self.pid = None
        self.returncode = None
        self.group_retired = False
        self.cleanup_errors = []
        self._process = None
        self._log = None
        self._stderr_task = None
        self._stderr_failure = None
        self._poisoned = False
        self._sequence = 0
        self._lock = asyncio.Lock()
        # Test callers may supply deliberately hostile *nonsecret* settings to
        # demonstrate the server's own scrub. Ordinary launch inherits nothing.
        self._environment = {"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
        if environment is not None:
            self._environment.update(environment)

    def _meta(self):
        return {"io.modelcontextprotocol/protocolVersion": self.protocol_version,
                "io.modelcontextprotocol/clientInfo": {"name": "hobnail-owned-worker-client", "version": "0.1.0"},
                "io.modelcontextprotocol/clientCapabilities": {}}

    def _command(self):
        command = [self.python, "-I", "-B"]
        if self.source_root is None:
            command += ["-m", "hobnail_mcp"]
        else:
            paths = [str(self.source_root / "src"), str(self.source_root / "integrations/mcp/src")]
            command += ["-c", "import sys;sys.path[:0]=" + repr(paths) + ";from hobnail_mcp.server import main;raise SystemExit(main())"]
        command += ["--config", str(self.config_path)]
        return command

    async def _negotiate(self):
        if self.protocol_version == "2025-11-25":
            response = await self._request("initialize", {"protocolVersion": self.protocol_version, "capabilities": {},
                "clientInfo": {"name": "hobnail-owned-worker-client", "version": "0.1.0"}})
            if (response.get("protocolVersion") != self.protocol_version
                    or type(response.get("capabilities")) is not dict or "tools" not in response["capabilities"]):
                raise MCPClientError("NEGOTIATION_MISMATCH", outcome="not_sent")
            await self._write({"jsonrpc": "2.0", "method": "notifications/initialized"})
        else:
            response = await self._request("server/discover", {})
            versions = response.get("supportedVersions")
            if type(versions) is not list or any(not isinstance(value, str) for value in versions) or self.protocol_version not in versions:
                raise MCPClientError("NEGOTIATION_MISMATCH", outcome="not_sent")
        if self.protocol_version == "2026-07-28":
            meta = response.get("_meta")
            info = meta.get("io.modelcontextprotocol/serverInfo") if type(meta) is dict else None
        else:
            info = response.get("serverInfo")
        if type(info) is not dict or not isinstance(info.get("name"), str) or not isinstance(info.get("version"), str):
            raise MCPClientError("INVALID_SERVER_INFO", outcome="not_sent")
        self.negotiated_version = self.protocol_version

    async def __aenter__(self):
        if self._process is not None or self.closed:
            raise MCPClientError("CLIENT_CANNOT_RESTART", outcome="not_sent")
        descriptor = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self._log = os.fdopen(descriptor, "wb")
        try:
            self._process = await asyncio.create_subprocess_exec(*self._command(), stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=self.config_path.parent,
                env=self._environment, start_new_session=True, limit=MAX_FRAME + 1)
            self.pid = self._process.pid
            self._stderr_task = asyncio.create_task(self._capture_stderr())
            await self._negotiate()
            return self
        except BaseException as error:
            await self._retire_after_error(error)
            raise

    def _signal_group(self, signum):
        if self.pid is not None:
            try:
                os.killpg(self.pid, signum)
            except ProcessLookupError:
                pass

    def _group_exists(self):
        if self.pid is None:
            return False
        try:
            os.killpg(self.pid, 0)
            return True
        except ProcessLookupError:
            return False

    async def _capture_stderr(self):
        retained = 0
        try:
            while block := await self._process.stderr.read(65536):
                permitted = min(len(block), MAX_STDERR - retained)
                if permitted:
                    self._log.write(block[:permitted])
                    self._log.flush()
                    retained += permitted
                if permitted != len(block) and self._stderr_failure is None:
                    self._stderr_failure = "MCP_STDERR_LIMIT"
                    self._poisoned = True
                    self._signal_group(signal.SIGKILL)
        except OSError:
            self._stderr_failure = "MCP_LOG_FAILURE"
            self._poisoned = True
            self._signal_group(signal.SIGKILL)

    async def _retire_after_error(self, error):
        self._poisoned = True
        try:
            await self.close()
        except Exception as cleanup:
            code = cleanup.code if isinstance(cleanup, MCPClientError) else type(cleanup).__name__
            if code == self._stderr_failure and self.closed and isinstance(error, MCPClientError) and error.code == code:
                return
            self.cleanup_errors.append(code)
            error.add_note("Owned MCP shutdown reported an additional failure; retained lifecycle state must be inspected.")

    async def _write(self, message):
        data = canonical_json(message).encode("utf-8") + b"\n"
        if len(data) > 2_400_000:
            raise MCPClientError("REQUEST_TOO_LARGE", outcome="not_sent")
        async with asyncio.timeout(self.timeout_seconds):
            self._process.stdin.write(data)
            await self._process.stdin.drain()

    async def _request(self, method, params):
        async with self._lock:
            if self._poisoned or self.closed:
                raise MCPClientError("CLIENT_RETIRED", outcome="not_sent")
            self._sequence += 1
            request_id = self._sequence
            params = dict(params)
            if self.protocol_version == "2026-07-28":
                params["_meta"] = self._meta()
            try:
                async with asyncio.timeout(self.timeout_seconds):
                    await self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
                    for _ in range(64):
                        line = await self._process.stdout.readline()
                        if not line:
                            if self._stderr_task is not None:
                                await asyncio.wait_for(asyncio.shield(self._stderr_task), timeout=1)
                            raise self._startup_error()
                        if len(line) > MAX_FRAME:
                            raise MCPClientError("RESPONSE_TOO_LARGE")
                        response = parse_json(line.decode("utf-8"))
                        if type(response) is not dict or response.get("jsonrpc") != "2.0":
                            raise MCPClientError("INVALID_MCP_ENVELOPE")
                        if "id" not in response and isinstance(response.get("method"), str):
                            continue
                        if type(response.get("id")) is not int or response["id"] != request_id:
                            raise MCPClientError("RESPONSE_ID_MISMATCH")
                        if "error" in response:
                            error = response["error"]
                            if (set(response) != {"jsonrpc", "id", "error"} or type(error) is not dict
                                    or type(error.get("code")) is not int):
                                raise MCPClientError("INVALID_MCP_ERROR")
                            raise MCPClientError("MCP_PROTOCOL_ERROR", rpc_code=error["code"])
                        if set(response) - {"jsonrpc", "id", "result"} or type(response.get("result")) is not dict:
                            raise MCPClientError("INVALID_MCP_RESULT")
                        if self.protocol_version == "2026-07-28" and response["result"].get("resultType") != "complete":
                            raise MCPClientError("UNSUPPORTED_MCP_RESULT_TYPE")
                        if self._stderr_failure is not None:
                            raise MCPClientError(self._stderr_failure)
                        return response["result"]
                    raise MCPClientError("EXCESSIVE_NOTIFICATIONS")
            except asyncio.CancelledError as error:
                try:
                    async with asyncio.timeout(1):
                        await self._write({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": request_id}})
                except Exception:
                    pass
                await self._retire_after_error(error)
                raise
            except TimeoutError:
                error = MCPClientError("MCP_TIMEOUT")
                await self._retire_after_error(error)
                raise error from None
            except (ValueError, UnicodeError, OSError, ConnectionError):
                error = MCPClientError("MCP_TRANSPORT_FAILURE")
                await self._retire_after_error(error)
                raise error from None
            except MCPClientError as error:
                if error.code not in {"MCP_PROTOCOL_ERROR", "REQUEST_TOO_LARGE"}:
                    await self._retire_after_error(error)
                raise

    def _startup_error(self):
        if self._stderr_failure is not None:
            return MCPClientError(self._stderr_failure)
        try:
            self._log.flush()
            with self.log_path.open("rb") as stream:
                raw = stream.read(4097)
            if len(raw) <= 4096:
                error = parse_json(raw.decode())
                allowed = {"INVALID_WORKER_CONFIGURATION", "INVALID_EXPECTED_PRINCIPAL", "IDENTITY_UNAVAILABLE",
                           "IDENTITY_REFUSED", "PROTOCOL_UPGRADE_REQUIRED", "WORKER_IDENTITY_MISMATCH",
                           "OPTIONAL_DEPENDENCY_UNAVAILABLE", "INVALID_LAUNCH_ARGUMENTS", "SERVER_FAILURE",
                           "UNSAFE_FRAMEWORK_ENVIRONMENT", "FRAMEWORK_ALREADY_IMPORTED", "STDIO_FRAME_TOO_LARGE",
                           "STDIO_INVALID_JSON", "STDIO_TRUNCATED_FRAME", "STDIO_INPUT_FAILURE", "STDIO_READER_NOT_RETIRED"}
                if (type(error) is dict and set(error) == {"status", "code"}
                        and error["status"] in {"startup_refused", "server_refused"} and error["code"] in allowed):
                    return MCPClientError(error["code"], outcome="not_sent" if error["status"] == "startup_refused" and self.negotiated_version is None else "unknown")
        except Exception:
            pass
        return MCPClientError("MCP_SERVER_EXITED")

    async def list_tools(self):
        result = await self._request("tools/list", {})
        if type(result.get("tools")) is not list or result.get("nextCursor") is not None:
            return await self._invalid_result("INVALID_TOOL_LIST")
        names = []
        for tool in result["tools"]:
            if (type(tool) is not dict or not isinstance(tool.get("name"), str)
                    or type(tool.get("inputSchema")) is not dict or tool["inputSchema"].get("type") != "object"):
                return await self._invalid_result("INVALID_TOOL_LIST")
            names.append(tool["name"])
        if len(names) != len(set(names)):
            return await self._invalid_result("DUPLICATE_TOOL")
        return result["tools"]

    async def call_raw(self, name, arguments):
        result = await self._request("tools/call", {"name": name, "arguments": arguments})
        if type(result.get("isError", False)) is not bool or type(result.get("content")) is not list:
            return await self._invalid_result("INVALID_TOOL_RESULT")
        if any(type(item) is not dict or item.get("type") != "text" or not isinstance(item.get("text"), str)
               for item in result["content"]):
            return await self._invalid_result("UNSUPPORTED_TOOL_CONTENT")
        self.last_is_error = result.get("isError", False)
        return result

    async def call_tool(self, name, arguments):
        result = await self.call_raw(name, arguments)
        envelope = result.get("structuredContent")
        if type(envelope) is not dict or type(envelope.get("ok")) is not bool or not isinstance(envelope.get("status"), str):
            if self.last_is_error:
                raise MCPClientError("MCP_TOOL_ERROR")
            return await self._invalid_result("INVALID_HOBNAIL_RESULT")
        if self.last_is_error != (not envelope["ok"]):
            return await self._invalid_result("TOOL_STATUS_MISMATCH")
        if "origin" not in envelope:
            try:
                validate_envelope(envelope)
            except ProtocolError:
                return await self._invalid_result("INVALID_HOBNAIL_ENVELOPE")
        elif envelope["origin"] != "adapter" or envelope["ok"] is not False or "event_id" in envelope:
            return await self._invalid_result("INVALID_ADAPTER_ENVELOPE")
        return envelope

    async def _invalid_result(self, code):
        error = MCPClientError(code)
        await self._retire_after_error(error)
        raise error

    async def close(self):
        if self.closed:
            return
        try:
            if self._process is not None:
                if self._process.stdin is not None:
                    self._process.stdin.close()
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=5)
                except TimeoutError:
                    self._signal_group(signal.SIGTERM)
                    try:
                        await asyncio.wait_for(self._process.wait(), timeout=5)
                    except TimeoutError:
                        self._signal_group(signal.SIGKILL)
                        await asyncio.wait_for(self._process.wait(), timeout=5)
                self.returncode = self._process.returncode
                # Leader exit alone is insufficient: it may have left children
                # in the exact new process group this client created.
                if self._group_exists():
                    self._signal_group(signal.SIGTERM)
                    for _ in range(50):
                        if not self._group_exists(): break
                        await asyncio.sleep(0.02)
                if self._group_exists():
                    self._signal_group(signal.SIGKILL)
                    for _ in range(100):
                        if not self._group_exists(): break
                        await asyncio.sleep(0.02)
                self.group_retired = not self._group_exists()
                if not self.group_retired:
                    raise MCPClientError("MCP_CLEANUP_UNCONFIRMED")
                if self._stderr_task is not None:
                    await asyncio.wait_for(self._stderr_task, timeout=5)
            else:
                self.group_retired = True
        finally:
            if self._log is not None:
                self._log.close()
            self.closed = self.group_retired and (self._process is None or self._process.returncode is not None)
        if self._stderr_failure is not None:
            raise MCPClientError(self._stderr_failure)

    async def __aexit__(self, kind, value, traceback):
        try:
            await self.close()
        except Exception:
            if value is None:
                raise
            value.add_note("Owned MCP shutdown reported an additional failure; retained lifecycle state must be inspected.")
