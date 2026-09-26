"""Authorized exact OpenBao runtime and separate controlled HTTPS client fixtures.

Only fresh task-owned state and generated reference credentials are used. The
fixed reference port is owned exclusively during this suite and released at exit.
No preexisting service, configuration, trust store or quarantine file is changed.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.openbao_runtime import (
    ADDRESS, MAX_RESPONSE, PORT, REFERENCE_HCL, REVIEWED_SHA256,
    OpenBaoRuntime, OpenBaoRuntimeError,
)


def reviewed_source():
    value = os.environ.get("HOBNAIL_REVIEWED_OPENBAO_BINARY")
    if not value:
        raise RuntimeError("set HOBNAIL_REVIEWED_OPENBAO_BINARY to the explicitly approved reviewed artifact; no test is skipped")
    return Path(value).absolute()


class OpenBaoRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = OpenBaoRuntime(source_binary=reviewed_source())
        cls.addClassCleanup(cls.retire)
        cls.source_before = reviewed_source().stat()
        cls.start = cls.runtime.start()
        cls.initialization = cls.runtime.initialize()
        first = cls.runtime.request("POST", "/v1/sys/unseal", {"key": cls.runtime._unseal_keys[0].reveal()})
        if first.body.get("sealed") is not True or first.body.get("progress") != 1:
            raise AssertionError("one share incorrectly unsealed threshold-two reference")
        cls.runtime.unseal()
        print("OpenBao runtime evidence retained:", cls.runtime.root)

    @classmethod
    def retire(cls):
        try:
            if cls.runtime.pid is not None:
                try:
                    cls.runtime.unseal()
                    cls.runtime.revoke_root()
                finally:
                    if not cls.runtime.check_secret_exclusion():
                        raise AssertionError("generated secret appeared in owned evidence; value withheld")
        finally:
            if not cls.runtime.stop():
                raise AssertionError("owned OpenBao process did not stop")

    def test_exact_reference_bytes_tls_and_real_three_two_initialization(self):
        runtime = self.runtime
        self.assertEqual(self.start.status, 501)
        self.assertIs(self.start.body.get("initialized"), False)
        self.assertIs(self.start.body.get("sealed"), True)
        self.assertTrue(self.initialization == {"initialized": True, "shares": 3, "threshold": 2},
                        "safe initialization summary mismatched; contents withheld")
        self.assertEqual(runtime.config_file.read_text(), REFERENCE_HCL)
        document = (ROOT / "docs/OPENBAO-REFERENCE.md").read_text()
        declared = document.split('```hcl\n', 1)[1].split('\n```', 1)[0] + "\n"
        self.assertEqual(REFERENCE_HCL, declared)
        self.assertFalse((runtime.root / "postgres").exists())
        with runtime.binary.open("rb") as stream:
            self.assertEqual(hashlib.file_digest(stream, "sha256").hexdigest(), REVIEWED_SHA256)
        self.assertEqual(reviewed_source().stat().st_mode & 0o777, 0o400)
        self.assertEqual(reviewed_source().stat().st_mtime_ns, self.source_before.st_mtime_ns)
        self.assertEqual(runtime.binary.stat().st_mode & 0o777, 0o500)
        status = runtime.request("GET", "/v1/sys/seal-status")
        self.assertIs(status.body.get("sealed"), False)
        self.assertEqual(status.body.get("t"), 2)
        self.assertEqual(status.body.get("n"), 3)
        root = runtime.request("GET", "/v1/auth/token/lookup-self", token=runtime.root_token)
        self.assertEqual(root.status, 200)
        self.assertTrue(runtime.root_token.reveal() not in repr(root), "HTTP response repr exposed credential; value withheld")
        self.assertTrue(runtime.root_token.reveal() not in repr(runtime.root_token), "secret repr exposed credential; value withheld")

    def test_missing_invalid_tokens_are_actual_forbidden_and_audit_is_active(self):
        runtime = self.runtime
        for token in (None, "synthetic-invalid-token"):
            response = runtime.request("GET", "/v1/sys/mounts", token=token, expectedstatuses=(403,))
            self.assertEqual(response.status, 403)
        permitted = runtime.request("GET", "/v1/sys/mounts", token=runtime.root_token)
        self.assertEqual(permitted.status, 200)
        audit = runtime.request("GET", "/v1/sys/audit", token=runtime.root_token)
        self.assertTrue(isinstance(audit.body.get("data"), dict))
        self.assertTrue(any(item.get("type") == "file" for item in audit.body["data"].values()))
        self.assertTrue((runtime.root / "audit/openbao.json").is_file())
        self.assertEqual((runtime.root / "audit/openbao.json").stat().st_mode & 0o777, 0o600)
        self.assertTrue(runtime.check_secret_exclusion(), "generated secret detected; values withheld")

    def test_plaintext_and_untrusted_ca_cannot_be_positive_tls_controls(self):
        with socket.create_connection(("127.0.0.1", PORT), timeout=3) as channel:
            channel.sendall(b"GET /v1/sys/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            answer = channel.recv(1024)
        self.assertTrue(answer.startswith(b"HTTP/1.0 400") or answer.startswith(b"HTTP/1.1 400"),
                        "plaintext did not receive the expected HTTPS refusal")
        wrong_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        wrong_context.minimum_version = ssl.TLSVersion.TLSv1_3
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=wrong_context))
        with self.assertRaises(urllib.error.URLError) as caught:
            opener.open(ADDRESS + "/v1/sys/health", timeout=3)
        self.assertIsInstance(caught.exception.reason, ssl.SSLCertVerificationError)
        self.assertEqual(self.runtime.request("GET", "/v1/sys/health").status, 200)

    def test_reference_port_collision_preserves_other_listener(self):
        runtime = self.runtime
        runtime.stop()
        try:
            with socket.socket() as other:
                other.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                other.bind(("127.0.0.1", PORT)); other.listen(1)
                with self.assertRaises(OpenBaoRuntimeError) as caught:
                    runtime.start()
                self.assertEqual(caught.exception.code, "REFERENCE_PORT_UNAVAILABLE")
                with socket.create_connection(("127.0.0.1", PORT), timeout=2):
                    connection, _ = other.accept()
                    connection.close()
        finally:
            runtime.start()
            runtime.unseal()

    def test_restart_preserves_owned_state_and_requires_retained_unseal_material(self):
        runtime = self.runtime
        previous_pid = runtime.pid
        runtime.stop()
        health = runtime.start()
        self.assertNotEqual(runtime.pid, previous_pid)
        self.assertIs(health.body.get("initialized"), True)
        self.assertIs(health.body.get("sealed"), True)
        self.assertEqual(runtime.unseal(), {"sealed": False})
        self.assertEqual(runtime.request("GET", "/v1/auth/token/lookup-self", token=runtime.root_token).status, 200)
        with self.assertRaises(OpenBaoRuntimeError) as caught:
            runtime.initialize()
        self.assertEqual(caught.exception.code, "INITIALIZATION_ALREADY_RECORDED")

    def test_transport_rejects_redirects_and_oversized_body_without_external_effect(self):
        # Separate fixture runtime/receipt: this HTTPS server is deliberately not
        # presented as OpenBao execution or included in its startup evidence.
        runtime = self.runtime
        runtime.stop()
        fixture = OpenBaoRuntime(source_binary=reviewed_source())
        fixture.receipt["scope"] = "controlled HTTPS client fixture; OpenBao binary was not started"
        reached = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def do_GET(self):
                if self.path == "/v1/redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{sink.getsockname()[1]}/should-not-arrive")
                    self.end_headers()
                elif self.path == "/v1/large":
                    self.send_response(200)
                    self.send_header("Content-Length", str(MAX_RESPONSE + 1))
                    self.end_headers()
                    try:
                        self.wfile.write(b"x" * (MAX_RESPONSE + 1))
                    except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                        pass  # The expected bounded client closes this response.
                else:
                    reached.append(self.path)
                    self.send_response(404); self.end_headers()

        class Server(HTTPServer):
            allow_reuse_address = True

        server = None
        try:
            with socket.socket() as sink:
                sink.bind(("127.0.0.1", 0)); sink.listen(1); sink.settimeout(0.05)
                server = Server(("127.0.0.1", PORT), Handler)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.load_cert_chain(fixture.root / "tls/server-chain.pem", fixture.root / "tls/server-key.pem")
                server.socket = context.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                with self.assertRaises(OpenBaoRuntimeError) as caught:
                    fixture.request("GET", "/v1/redirect", token="synthetic-redirect-token")
                self.assertEqual(caught.exception.status, 302)
                with self.assertRaises(TimeoutError): sink.accept()
                with self.assertRaises(OpenBaoRuntimeError) as caught:
                    fixture.request("GET", "/v1/large")
                self.assertEqual(caught.exception.code, "RESPONSE_TOO_LARGE")
                self.assertFalse(reached)
                server.shutdown(); thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
        finally:
            if server is not None:
                server.server_close()
            fixture.stop()
            runtime.start(); runtime.unseal()

    def test_z_root_revocation_is_observed_then_secrets_stay_out_of_logs(self):
        self.assertEqual(self.runtime.revoke_root(), {"revoked": True, "lookup_status": 403})
        self.assertEqual(self.runtime.request("GET", "/v1/auth/token/lookup-self", token=self.runtime.root_token,
                                             expectedstatuses=(403,)).status, 403)
        self.assertTrue(self.runtime.check_secret_exclusion(), "generated secret detected; values withheld")


class ArtifactRefusalTests(unittest.TestCase):
    def test_noncanonical_or_changed_artifact_never_reaches_execution(self):
        with tempfile.TemporaryDirectory(prefix="hbn-bao-bad-source-", dir="/tmp") as directory:
            root = Path(directory).resolve()
            alias = root / "alias"
            alias.symlink_to(reviewed_source())
            with self.assertRaises(OpenBaoRuntimeError) as caught:
                OpenBaoRuntime(source_binary=alias)
            self.assertEqual(caught.exception.code, "NONCANONICAL_ARTIFACT_PATH")
            changed = root / "changed"
            shutil.copyfile(reviewed_source(), changed)
            changed.chmod(0o600)
            with changed.open("r+b") as stream:
                first = stream.read(1)
                stream.seek(0); stream.write(bytes([first[0] ^ 1]))
            changed.chmod(0o400)
            with self.assertRaises(OpenBaoRuntimeError) as caught:
                OpenBaoRuntime(source_binary=changed)
            self.assertEqual(caught.exception.code, "ARTIFACT_HASH_MISMATCH")


class RuntimeFailureTests(unittest.TestCase):
    """Controlled I/O faults; no OpenBao process or fixed-port listener starts."""

    @classmethod
    def setUpClass(cls):
        cls.runtime = OpenBaoRuntime(source_binary=reviewed_source())
        cls.runtime.receipt["scope"] = "controlled custody and launch-failure fixtures; no OpenBao server started"
        cls.addClassCleanup(cls.runtime.stop)

    def test_initialization_custody_survives_receipt_write_failure(self):
        runtime = self.runtime
        body = {"root_token": "synthetic-custody-token", "keys_base64": ["synthetic-share-1", "synthetic-share-2", "synthetic-share-3"]}

        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit): return json.dumps(body).encode()

        opener = MagicMock()
        opener.open.return_value = Response()
        with patch.object(runtime, "_opener", opener), patch.object(runtime, "_save_receipt", side_effect=OSError("controlled receipt storage outage")):
            with self.assertRaises(OpenBaoRuntimeError) as caught:
                runtime.initialize()
        self.assertEqual(caught.exception.code, "RECEIPT_PERSISTENCE_FAILED")
        self.assertEqual(opener.open.call_count, 1, "initialization must not be retried after a received response")
        self.assertTrue(runtime.root_token.reveal() == body["root_token"], "initialization token custody lost; contents withheld")
        self.assertEqual(len(runtime._unseal_keys), 3)
        self.assertIsNotNone(runtime.last_response)
        self.assertTrue(runtime.last_response.body == body, "received response custody lost; contents withheld")
        self.assertTrue(all(value not in json.dumps(runtime.receipt) for value in [body["root_token"], *body["keys_base64"]]),
                        "custody fixture secrets entered evidence; contents withheld")

    def test_post_spawn_receipt_failure_reaps_the_owned_child_and_preserves_error(self):
        runtime = self.runtime
        actual_popen = __import__("subprocess").Popen
        children = []

        def owned_first_party_child(arguments, **kwargs):
            child = actual_popen([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
            children.append(child)
            return child

        # The port check is a test fixture only; the real18200 port remains owned
        # by the separate qualification process and is never touched here.
        with patch("scripts.openbao_runtime.socket.socket"), \
                patch("scripts.openbao_runtime.subprocess.Popen", side_effect=owned_first_party_child), \
                patch.object(runtime, "_save_receipt", side_effect=OSError("controlled receipt storage outage")):
            with self.assertRaisesRegex(OSError, "controlled receipt storage outage"):
                runtime.start()
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll(), "the owned child survived the startup evidence failure")
        self.assertTrue(runtime.receipt["runtime_stopped"])

    def test_created_token_custody_survives_receipt_failure_and_later_responses(self):
        runtime = self.runtime
        generated = "synthetic-orphan-custody-token"

        class Response:
            def __init__(self, body, status=200): self.body, self.status = body, status
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit): return json.dumps(self.body).encode()

        opener = MagicMock()
        opener.open.side_effect = [Response({"auth": {"client_token": generated}}), Response({"initialized": True}),
                                   Response({"errors": ["permission denied"]}, 403)]
        with patch.object(runtime, "_opener", opener):
            with patch.object(runtime, "_save_receipt", side_effect=OSError("controlled receipt storage outage")):
                with self.assertRaises(OpenBaoRuntimeError) as caught:
                    runtime.request("POST", "/v1/auth/token/create", {"no_parent": True})
            self.assertEqual(caught.exception.code, "RECEIPT_PERSISTENCE_FAILED")
            runtime.request("GET", "/v1/sys/init")
            denied = runtime.request("POST", "/v1/auth/token/create", {}, expectedstatuses=(403,))
            self.assertEqual(denied.status, 403)
        self.assertTrue(any(token.reveal() == generated for token in runtime.issued_tokens),
                        "created token was lost after a later response; value withheld")
        self.assertTrue(generated not in repr(runtime.issued_tokens), "token custody repr leaked its value")
        self.assertTrue(generated not in json.dumps(runtime.receipt), "token custody entered public evidence")

    def test_generated_leaf_passes_production_strict_verification_on_owned_ephemeral_listener(self):
        runtime = self.runtime
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.minimum_version = server.maximum_version = ssl.TLSVersion.TLSv1_3
        server.load_cert_chain(runtime.root / "tls/server-chain.pem", runtime.root / "tls/server-key.pem")
        errors = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0)); listener.listen(2); listener.settimeout(5)

            def serve():
                try:
                    for _ in range(2):
                        channel, _ = listener.accept()
                        with server.wrap_socket(channel, server_side=True) as protected:
                            if protected.recv(1) != b"x": raise RuntimeError("controlled handshake payload mismatch")
                            protected.sendall(b"ok")
                except Exception as error:
                    errors.append(type(error).__name__)

            thread = threading.Thread(target=serve, daemon=True); thread.start()
            provider_context = ssl.create_default_context(cafile=str(runtime.ca_file))
            for context in (runtime._context, provider_context):
                self.assertTrue(context.verify_flags & ssl.VERIFY_X509_STRICT)
                with socket.create_connection(listener.getsockname(), timeout=5) as channel:
                    with context.wrap_socket(channel, server_hostname="127.0.0.1") as protected:
                        protected.sendall(b"x")
                        self.assertEqual(protected.recv(2), b"ok")
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertFalse(errors, errors)

    def test_unexpected_successful_token_creation_is_retained_while_assertion_fails(self):
        runtime = self.runtime
        generated = "synthetic-unexpected-created-token"

        class Response:
            status = 201
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit): return json.dumps({"auth": {"client_token": generated}}).encode()

        opener = MagicMock()
        opener.open.return_value = Response()
        with patch.object(runtime, "_opener", opener), patch.object(runtime, "_save_receipt", side_effect=OSError("controlled evidence failure")):
            with self.assertRaises(OpenBaoRuntimeError) as caught:
                runtime.request("POST", "/v1/auth/token/create", {"no_parent": True}, expectedstatuses=(403,))
        self.assertEqual(caught.exception.code, "UNEXPECTED_HTTP_STATUS")
        self.assertEqual(caught.exception.status, 201)
        self.assertTrue(any(token.reveal() == generated for token in runtime.issued_tokens),
                        "unexpected created token custody lost; value withheld")
        self.assertTrue(generated not in json.dumps(runtime.receipt), "unexpected token entered evidence; value withheld")


if __name__ == "__main__":
    unittest.main()
