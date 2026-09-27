"""Framework-independent worker boundary and private configuration checks."""
from __future__ import annotations

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "integrations/mcp/src"))
from hobnail.client import Client, TransportTimeout
from hobnail_mcp.adapter import MAX_RESPONSE_BYTES, OPERATIONS, StartupRefused, WorkerAdapter
from hobnail_mcp.config import load_configuration
from hobnail_mcp.client import MCPClientError, WorkerMCPClient
from hobnail_mcp.server import create_server, framework_environment, tool_schemas
from hobnail_mcp.stdio import InputState, pump_frames


def identity(role="worker", principal="test-worker"):
    return {"ok": True, "status": "ok", "event_id": 1,
            "data": {"principal_id": principal, "role": role, "contracts": ["report"], "valid_until": None}}


class RecordingTransport:
    def __init__(self, response=None, *, session=None):
        self.response = response or {"ok": True, "status": "submitted", "event_id": 2, "data": {"candidate_id": 7}}
        self.session = identity() if session is None else session
        self.calls = []

    def call(self, operation, payload):
        self.calls.append((operation, deepcopy(payload)))
        result = self.session if operation == "session.get" else self.response
        if isinstance(result, Exception):
            raise result
        return deepcopy(result)


class WorkerAdapterTests(unittest.TestCase):
    def setUp(self):
        self.transport = RecordingTransport()
        self.adapter = WorkerAdapter(Client(self.transport), expected_principal="test-worker")

    def test_only_seven_worker_tools_and_exact_identity_probe(self):
        self.assertEqual(set(OPERATIONS), {"get_contract", "put_artifact", "submit_candidate", "get_candidate",
                                           "request_effect", "get_effect", "cancel_effect"})
        self.assertEqual(self.transport.calls, [("session.get", {})])

    def test_wrong_role_principal_unbound_and_old_server_refuse_startup(self):
        denied = {"ok": False, "status": "denied", "event_id": 1, "code": "UNAUTHENTICATED", "detail": {}}
        cases = [(identity("approver"), "WORKER_IDENTITY_MISMATCH"),
                 (identity(principal="another-worker"), "WORKER_IDENTITY_MISMATCH"),
                 (denied, "IDENTITY_REFUSED"),
                 ({**denied, "code": "UNKNOWN_OPERATION"}, "PROTOCOL_UPGRADE_REQUIRED"),
                 (TransportTimeout("synthetic-secret"), "IDENTITY_UNAVAILABLE")]
        for session, expected in cases:
            with self.subTest(expected=expected), self.assertRaisesRegex(StartupRefused, "^" + expected + "$"):
                WorkerAdapter(Client(RecordingTransport(session=session)), expected_principal="test-worker")

    def test_bytes_and_caller_idempotency_key_are_unchanged(self):
        content = b' {"n": 7, "label": "\\u0061"}\n'
        self.adapter.invoke("put_artifact", {"content_hex": content.hex(), "media_type": "application/json"})
        self.assertEqual(self.transport.calls[-1], ("artifact.put", {"content_hex": content.hex(), "media_type": "application/json"}))
        arguments = {"contract_id": "report", "artifact_id": 3, "inputs": {"warehouse": 4}, "idempotency_key": "persistent-key"}
        self.adapter.invoke("submit_candidate", arguments)
        arguments["inputs"]["warehouse"] = 999
        self.assertEqual(self.transport.calls[-1][1]["inputs"], {"warehouse": 4})
        self.assertEqual(self.transport.calls[-1][1]["idempotency_key"], "persistent-key")

    def test_business_denials_and_control_failure_preserve_original_envelope(self):
        for result in ({"ok": False, "status": "denied", "event_id": 19, "code": "INPUT_STALE", "detail": {}},
                       {"ok": True, "status": "control_failure", "event_id": 20, "data": {"state": "control_failure"}}):
            self.transport.response = result
            self.assertEqual(self.adapter.invoke("get_effect", {"effect_id": 4}), result)

    def test_lost_reply_returns_unknown_without_retries_or_fake_event(self):
        self.transport.response = TransportTimeout("synthetic-secret-and-host")
        result = self.adapter.invoke("request_effect", {"candidate_id": 7, "action": "publish", "args": {}, "idempotency_key": "same-key"})
        self.assertEqual(len(self.transport.calls), 2)
        self.assertEqual(result["outcome"], "unknown")
        self.assertEqual(result["reference"], {"candidate_id": 7, "idempotency_key": "same-key"})
        self.assertNotIn("event_id", result)
        self.assertNotIn("synthetic-secret", json.dumps(result))

    def test_unexpected_post_dispatch_failure_is_unknown_and_redacted(self):
        self.transport.response = RuntimeError("synthetic-secret")
        result = self.adapter.invoke("cancel_effect", {"effect_id": 4})
        self.assertEqual(result["outcome"], "unknown")
        self.assertEqual(result["code"], "ADAPTER_FAILURE")
        self.assertNotIn("synthetic-secret", json.dumps(result))

    def test_oversized_response_is_unknown_not_truncated_success(self):
        self.transport.response = {"ok": True, "status": "ok", "event_id": 2, "data": {"large": "x" * MAX_RESPONSE_BYTES}}
        response = self.adapter.invoke("get_candidate", {"candidate_id": 8})
        self.assertEqual(response["code"], "RESPONSE_TOO_LARGE")
        self.assertEqual(response["outcome"], "unknown")
        self.assertEqual(response["reference"], {"candidate_id": 8})
        self.assertNotIn("event_id", response)
        self.assertNotIn("large", response)

    def test_malformed_and_extra_fields_never_reach_transport(self):
        cases = [("api", {"op": "contract.activate", "payload": {}}),
                 ("get_candidate", {"candidate_id": True}), ("get_candidate", {"candidate_id": "1"}),
                 ("get_candidate", {"candidate_id": 1, "role": "approver"}),
                 ("get_effect", {"effect_id": 0}), ("get_effect", {"effect_id": 2**63}),
                 ("get_contract", {"contract_id": "x", "version": False}),
                 ("put_artifact", {"content_hex": "FF", "media_type": "text/plain"}),
                 ("put_artifact", {"content_hex": "f", "media_type": "text/plain"}),
                 ("put_artifact", {"path": "/private/path", "media_type": "text/plain"}),
                 ("put_artifact", {"content_hex": "00" * (1048576 + 1), "media_type": "text/plain"}),
                 ("submit_candidate", {"contract_id": "x", "artifact_id": 1, "inputs": {"x": True}, "idempotency_key": "key"}),
                 ("request_effect", {"candidate_id": 1, "action": "x", "args": {"a": float("nan")}, "idempotency_key": "key"}),
                 ("request_effect", {"candidate_id": 1, "action": "x", "args": {"a": "x"*16384}, "idempotency_key": "key"})]
        for name, arguments in cases:
            with self.subTest(name=name):
                result = self.adapter.invoke(name, arguments)
                self.assertEqual(result["code"], "INVALID_REQUEST")
                self.assertNotIn("event_id", result)
        self.assertEqual(self.transport.calls, [("session.get", {})])

    def test_cancellation_is_only_existing_effect_request(self):
        self.adapter.invoke("cancel_effect", {"effect_id": 12})
        self.assertEqual(self.transport.calls[-1], ("effect.cancel", {"effect_id": 12}))

    def test_runtime_expiry_is_not_replaced_with_new_credentials(self):
        self.transport.response = {"ok": False, "status": "denied", "event_id": 3, "code": "UNAUTHENTICATED", "detail": {}}
        self.assertEqual(self.adapter.invoke("get_candidate", {"candidate_id": 1})["code"], "UNAUTHENTICATED")
        self.assertEqual([name for name, _ in self.transport.calls], ["session.get", "candidate.get"])

    def test_four_active_database_calls_bound_and_extra_call_not_attempted(self):
        entered, release = threading.Event(), threading.Event()
        count, lock = [0], threading.Lock()

        def blocked(operation, payload):
            with lock:
                count[0] += 1
                if count[0] == 4: entered.set()
            release.wait(timeout=2)
            return {"ok": True, "status": "ok", "event_id": 2, "data": {}}

        self.transport.call = blocked
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(self.adapter.invoke, "get_candidate", {"candidate_id": 1}) for _ in range(4)]
            try:
                self.assertTrue(entered.wait(timeout=1))
                busy = self.adapter.invoke("get_candidate", {"candidate_id": 1})
                self.assertEqual(busy["code"], "CONCURRENCY_LIMIT")
                self.assertEqual(busy["outcome"], "not_attempted")
                self.assertNotIn("event_id", busy)
                self.assertEqual(count[0], 4)
            finally:
                release.set()
            self.assertTrue(all(future.result()["ok"] for future in futures))


class WorkerConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.path = self.root / "worker.json"
        self.document = {"schema_version": 1, "role": "worker", "expected_principal": "test-worker",
                         "connection": {"host": "/explicit/socket", "port": 15432, "database": "synthetic",
                                        "user": "synthetic-worker", "password": "synthetic-fixture-only", "sslmode": "disable", "connect_timeout": 5},
                         "psql": str(Path(sys.executable).resolve()), "timeout_seconds": 30, "owned_development": True}

    def tearDown(self):
        self.directory.cleanup()

    def write(self, document=None):
        self.path.write_text(json.dumps(self.document if document is None else document))
        self.path.chmod(0o600)

    def test_only_explicit_private_config_and_no_secret_representation(self):
        self.write()
        value = load_configuration(self.path)
        self.assertEqual(value.connection.user, "synthetic-worker")
        self.assertNotIn("synthetic-fixture-only", repr(value))
        self.assertNotIn("synthetic-fixture-only", repr(value.connection))

    def test_permissions_symlink_hardlink_and_ambiguous_fields_refuse(self):
        self.write()
        self.path.chmod(0o644)
        with self.assertRaises(StartupRefused): load_configuration(self.path)
        self.path.chmod(0o600)
        alias = self.root / "alias.json"
        alias.symlink_to(self.path)
        with self.assertRaises(StartupRefused): load_configuration(alias)
        hardlink = self.root / "hardlink.json"
        os.link(self.path, hardlink)
        with self.assertRaises(StartupRefused): load_configuration(self.path)
        hardlink.unlink()
        self.path.write_text('{"role":"worker","role":"approver"}')
        with self.assertRaises(StartupRefused): load_configuration(self.path)

    def test_nonlocal_plaintext_and_unverified_tls_refuse(self):
        for host, mode, development in (("db.example", "disable", True), ("db.example", "require", False),
                                        ("db.example", "verify-full", False), ("127.0.0.1", "disable", False)):
            self.document["connection"].update(host=host, sslmode=mode)
            self.document["owned_development"] = development
            self.write()
            with self.subTest(host=host, mode=mode), self.assertRaises(StartupRefused): load_configuration(self.path)

    def test_wrong_role_extra_config_and_missing_password_refuse(self):
        for change in ({"role": "approver"}, {"role": "worker", "command": "arbitrary"}, {"timeout_seconds": True}):
            value = deepcopy(self.document); value.update(change); self.write(value)
            with self.assertRaises(StartupRefused): load_configuration(self.path)
        value = deepcopy(self.document); del value["connection"]["password"]; self.write(value)
        with self.assertRaises(StartupRefused): load_configuration(self.path)

    def test_libpq_host_lists_cannot_escape_owned_local_mode(self):
        for host in ("/socket,remote.example", "127.0.0.1,remote.example", ",", "/socket,", "", " /socket", "/socket\n"):
            self.document["connection"]["host"] = host
            self.write()
            with self.subTest(host=host), self.assertRaises(StartupRefused): load_configuration(self.path)

    def test_normal_tls_mode_rejects_socket_and_ambient_default_forms(self):
        certificate = self.root / "explicit-root.crt"
        certificate.write_text("synthetic fixture; never used for authentication")
        self.document["owned_development"] = False
        self.document["connection"].update(sslmode="verify-full", sslrootcert=str(certificate))
        for host in ("/socket", "@abstract", "", "db.example,", ",db.example"):
            self.document["connection"]["host"] = host
            self.write()
            with self.subTest(host=host), self.assertRaises(StartupRefused): load_configuration(self.path)
        self.document["connection"]["host"] = "db.example"
        self.write()
        self.assertEqual(load_configuration(self.path).connection.sslmode, "verify-full")


class FrameworkBootstrapTests(unittest.TestCase):
    def test_unsafe_public_factory_refuses_before_third_party_import(self):
        with patch.dict(os.environ, {"FASTMCP_ENV_FILE": "must-not-read.env"}, clear=True), patch("builtins.__import__") as imported:
            with self.assertRaisesRegex(StartupRefused, "^UNSAFE_FRAMEWORK_ENVIRONMENT$"):
                create_server(None)
            imported.assert_not_called()

    def test_environment_is_closed_before_optional_import(self):
        # Patch process logging too: this test must not silence its own runner.
        with patch.dict(os.environ, {"FASTMCP_ENV_FILE": "private.env", "FASTMCP_AUTH": "hostile",
                                     "FASTMCP_TELEMETRY_MODE": "native", "PGPASSWORD": "synthetic",
                                     "OTEL_EXPORTER_OTLP_ENDPOINT": "https://must-not-contact.invalid"}, clear=True), patch("logging.disable"):
            framework_environment("/explicit/owned/scratch")
            self.assertEqual(os.environ["FASTMCP_ENV_FILE"], os.devnull)
            self.assertEqual(os.environ["FASTMCP_TELEMETRY_MODE"], "off")
            self.assertEqual(os.environ["FASTMCP_CHECK_FOR_UPDATES"], "off")
            self.assertEqual(os.environ["OTEL_SDK_DISABLED"], "true")
            self.assertNotIn("PGPASSWORD", os.environ)
            self.assertNotIn("FASTMCP_AUTH", os.environ)
            self.assertNotIn("OTEL_EXPORTER_OTLP_ENDPOINT", os.environ)

    def test_schema_inventory_is_closed_and_matches_worker_inventory(self):
        schemas = tool_schemas()
        self.assertEqual(set(schemas), set(OPERATIONS))
        self.assertTrue(all(value["additionalProperties"] is False for value in schemas.values()))
        self.assertEqual(schemas["put_artifact"]["properties"]["content_hex"]["maxLength"], 2097152)
        self.assertEqual(schemas["get_candidate"]["properties"]["candidate_id"]["type"], "integer")


class OptionalDistributionTests(unittest.TestCase):
    def test_wheel_declares_real_dependencies_license_and_console_entry(self):
        specification = importlib.util.spec_from_file_location("hobnail_mcp_test_build", ROOT / "integrations/mcp/build_backend.py")
        backend = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(backend)
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / backend.build_wheel(directory)
            with zipfile.ZipFile(wheel) as archive:
                metadata = archive.read("hobnail_mcp-0.1.0.dist-info/METADATA").decode()
                self.assertIn("Requires-Dist: hobnail==0.3.0\n", metadata)
                self.assertIn("Requires-Dist: fastmcp-slim[server]==4.0.5\n", metadata)
                self.assertEqual(archive.read("hobnail_mcp-0.1.0.dist-info/entry_points.txt"),
                                 b"[console_scripts]\nhobnail-mcp = hobnail_mcp.server:main\n")
                self.assertEqual(archive.read("hobnail_mcp-0.1.0.dist-info/licenses/LICENSE"), (ROOT / "LICENSE").read_bytes())
                self.assertIn("hobnail_mcp/server.py", archive.namelist())
                self.assertIn("hobnail_mcp/client.py", archive.namelist())
            original = wheel.read_bytes()
            backend.build_wheel(directory)
            self.assertEqual(wheel.read_bytes(), original)


class ClientWireValidationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name).resolve()
        self.client = WorkerMCPClient(root / "explicit-config.json", log_path=root / "stderr.txt")
        self.writes = []
        self.reader = asyncio.StreamReader()

        class Writer:
            def write(inner, content):
                self.writes.append(content)

            async def drain(inner):
                pass

            def close(inner):
                pass

        async def wait():
            self.client._process.returncode = 0
            return 0

        self.client._process = SimpleNamespace(stdin=Writer(), stdout=self.reader, returncode=None, wait=wait)

    async def asyncTearDown(self):
        self.directory.cleanup()

    def feed(self, result, *, request_id=1):
        self.reader.feed_data((json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n").encode())

    async def test_wrong_response_id_refuses_instead_of_adopting_other_work(self):
        self.feed({"tools": []}, request_id=2)
        with self.assertRaisesRegex(MCPClientError, "^RESPONSE_ID_MISMATCH$"):
            await self.client.list_tools()

    async def test_business_denial_is_error_marked_but_receipt_is_retained(self):
        envelope = {"ok": False, "status": "denied", "event_id": 8, "code": "CHECK_FAILED", "detail": {}}
        self.feed({"isError": True, "content": [{"type": "text", "text": json.dumps(envelope)}], "structuredContent": envelope})
        self.assertEqual(await self.client.call_tool("get_candidate", {"candidate_id": 1}), envelope)
        self.assertTrue(self.client.last_is_error)

    async def test_status_mismatch_refuses_and_retires_connection(self):
        self.feed({"isError": False, "content": [], "structuredContent": {"ok": False, "status": "denied"}})
        with self.assertRaisesRegex(MCPClientError, "^TOOL_STATUS_MISMATCH$"):
            await self.client.call_tool("get_candidate", {"candidate_id": 1})
        self.assertTrue(self.client.closed)
        with self.assertRaisesRegex(MCPClientError, "^CLIENT_RETIRED$"):
            await self.client.call_tool("get_candidate", {"candidate_id": 1})
        self.assertEqual(len(self.writes), 1)

    async def test_fake_authority_refuses(self):
        self.feed({"isError": False, "content": [], "structuredContent": {"ok": True, "status": "complete", "data": {}}})
        with self.assertRaisesRegex(MCPClientError, "^INVALID_HOBNAIL_ENVELOPE$"):
            await self.client.call_tool("get_effect", {"effect_id": 1})

    async def test_timeout_never_resends_mutating_request(self):
        self.client.timeout_seconds = 0.01
        with self.assertRaises(MCPClientError) as caught:
            await self.client.call_tool("cancel_effect", {"effect_id": 1})
        self.assertEqual(caught.exception.code, "MCP_TIMEOUT")
        self.assertEqual(caught.exception.outcome, "unknown")
        self.assertEqual(len(self.writes), 1)
        self.assertTrue(self.client.closed)
        with self.assertRaisesRegex(MCPClientError, "^CLIENT_RETIRED$"):
            await self.client.call_tool("cancel_effect", {"effect_id": 1})
        self.assertEqual(len(self.writes), 1)

    async def test_blocked_pipe_write_is_inside_timeout(self):
        async def blocked_drain():
            await asyncio.Event().wait()
        self.client._process.stdin.drain = blocked_drain
        self.client.timeout_seconds = 0.01
        with self.assertRaisesRegex(MCPClientError, "^MCP_TIMEOUT$"):
            await self.client.call_tool("cancel_effect", {"effect_id": 1})
        self.assertEqual(len(self.writes), 1)


class WireFrameBoundaryTests(unittest.TestCase):
    def pump(self, value, limit=1024):
        source, sender = os.pipe()
        receiver, destination = os.pipe()
        os.set_blocking(destination, False)
        state, stop = InputState(), threading.Event()
        thread = threading.Thread(target=pump_frames, args=(source, destination, state, stop), kwargs={"limit": limit})
        thread.start()
        try:
            os.write(sender, value)
            os.close(sender)
            sender = None
            result = bytearray()
            while block := os.read(receiver, 65536):
                result.extend(block)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            return bytes(result), state.error
        finally:
            stop.set()
            thread.join(timeout=2)
            for descriptor in (source, sender, receiver):
                if descriptor is not None: os.close(descriptor)

    def test_original_bytes_forward_only_for_complete_bounded_frames(self):
        value = b'{ "id": 1, "payload": "\\u0061" }\n{"id":2}\n'
        self.assertEqual(self.pump(value), (value, None))

    def test_oversize_frame_is_not_partially_forwarded(self):
        result, error = self.pump(b'{"x":"' + b'a'*300 + b'"}\n', limit=128)
        self.assertEqual(result, b'')
        self.assertEqual(error, "STDIO_FRAME_TOO_LARGE")

    def test_duplicate_nonfinite_lossy_invalid_utf8_and_truncated_json_refuse(self):
        for value in (b'{"id":1,"id":2}\n', b'{"x":NaN}\n', b'{"x":1.00000000000000000001}\n', b'{"x":"\xff"}\n'):
            with self.subTest(value=value):
                self.assertEqual(self.pump(value), (b'', "STDIO_INVALID_JSON"))
        self.assertEqual(self.pump(b'{"id":1}'), (b'', "STDIO_TRUNCATED_FRAME"))


if __name__ == "__main__":
    unittest.main()
