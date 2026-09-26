"""Owned OpenBao 2.6.2 reference runtime for the explicitly authorized trial.

This copies only the reviewed Darwin-arm64 bytes; it never installs globally or
modifies quarantine originals. Initialization material stays in trusted object
memory. Same-object restart is supported; separate human key custody, persistent
recovery custody and deployment qualification are not established by this helper.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from hobnail.client import canonical_json, parse_json
from hobnail.credentials import Secret

REVIEWED_SHA256 = "d476d17e81a35e6d70dd7e86a8ab2a3664313525118f1f1cfe0130e7a2b95f3a"
REVIEWED_SIZE = 193769394
ADDRESS = "https://127.0.0.1:18200"
PORT = 18200
MAX_RESPONSE = 8 * 1024 * 1024

REFERENCE_HCL = '''storage "file" {
  path = "./state"
}

listener "tcp" {
  address = "127.0.0.1:18200"
  tls_cert_file = "./tls/server-chain.pem"
  tls_key_file = "./tls/server-key.pem"
  tls_min_version = "tls13"
  tls_max_version = "tls13"
  disable_unauthed_rekey_endpoints = true
  disable_unauthed_generate_root_endpoints = true
}

api_addr = "https://127.0.0.1:18200"
disable_clustering = true
ui = false
plugin_auto_download = false
plugin_auto_register = false
raw_storage_endpoint = false
introspection_endpoint = false
allow_unauthenticated_workflows = false
unsafe_allow_api_audit_creation = false
allow_audit_log_prefixing = false
default_lease_ttl = "15m"
max_lease_ttl = "15m"
log_level = "info"
log_format = "json"

telemetry {
  prometheus_retention_time = "0s"
  disable_hostname = true
}

audit "file" "hobnail-reference" {
  options {
    file_path = "./audit/openbao.json"
    mode = "0600"
    log_raw = "false"
    hmac_accessor = "true"
  }
}
'''


class OpenBaoRuntimeError(RuntimeError):
    """Safe stage/code only; no response body, token or key is included."""
    def __init__(self, code: str, *, status: int | None = None):
        self.code = code
        self.status = status
        super().__init__(code if status is None else f"{code} (HTTP {status})")


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    body: dict | list | None = field(repr=False)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _write_new(path: Path, content: str | bytes, mode: int = 0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content.encode() if isinstance(content, str) else content)
        stream.flush()
        os.fsync(stream.fileno())


def _hash_file(path: Path, *, expected_mode: int | None = None):
    supplied = path.absolute()
    if supplied.resolve(strict=True) != supplied:
        raise OpenBaoRuntimeError("NONCANONICAL_ARTIFACT_PATH")
    descriptor = os.open(supplied, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1
                or before.st_mode & 0o022 or before.st_size != REVIEWED_SIZE
                or (expected_mode is not None and stat.S_IMODE(before.st_mode) != expected_mode)):
            raise OpenBaoRuntimeError("ARTIFACT_IDENTITY_OR_PERMISSIONS")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after):
            raise OpenBaoRuntimeError("ARTIFACT_CHANGED_DURING_REVIEW")
    if digest != REVIEWED_SHA256:
        raise OpenBaoRuntimeError("ARTIFACT_HASH_MISMATCH")
    return digest


class OpenBaoRuntime:
    def __init__(self, *, source_binary: str | Path, base_dir: str | Path = "/tmp"):
        self.source_binary = Path(source_binary).absolute()
        _hash_file(self.source_binary, expected_mode=0o400)
        self.root = Path(tempfile.mkdtemp(prefix="hbn-bao-", dir=base_dir)).resolve()
        self.root.chmod(0o700)
        if re.search(r"[\s\x00-\x1f\x7f]", str(self.root)) or len(os.fsencode(self.root / "postgres/socket/.s.PGSQL.5432")) >= 100:
            raise OpenBaoRuntimeError("UNSUPPORTED_OWNED_ROOT_PATH")
        self._owner_nonce = secrets.token_hex(16)
        self._process: subprocess.Popen | None = None
        self._generation = 0
        self._root_token: Secret | None = None
        self._unseal_keys: tuple[Secret, ...] = ()
        self._sensitive_values: set[str] = set()
        self._root_revoked = False
        self._initialization_capture = False
        self._last_response: HTTPResponse | None = None
        self._issued_tokens: dict[str, Secret] = {}
        self.ca_file = self.root / "tls/ca.pem"
        self.binary = self.root / "bin/bao"
        self.config_file = self.root / "config/bao.hcl"
        self.receipt = {"root": str(self.root), "artifact_sha256": REVIEWED_SHA256, "address": ADDRESS,
                        "events": [], "runtime_stopped": True, "qualified": False,
                        "custody": "Shares and root token remain separate redacted objects in trusted supervisor memory; separate human custody is not demonstrated."}
        _write_new(self.root / ".hobnail-openbao.json", canonical_json({"format": "hobnail-openbao-owned-v1",
                   "root": str(self.root), "uid": os.geteuid(), "nonce": self._owner_nonce}))
        for directory in ("bin", "config", "tls", "state", "audit", "logs", "tmp", "receipts"):
            (self.root / directory).mkdir(mode=0o700)
        descriptor = os.open(self.source_binary, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            output = os.open(self.binary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
            with os.fdopen(output, "wb") as target:
                while block := source.read(1024 * 1024):
                    target.write(block)
                target.flush()
                os.fsync(target.fileno())
        _hash_file(self.binary, expected_mode=0o500)
        _write_new(self.config_file, REFERENCE_HCL)
        self._config_digest = hashlib.sha256(REFERENCE_HCL.encode()).hexdigest()
        self.receipt["configuration_sha256"] = self._config_digest
        self._tls()
        self._context = ssl.create_default_context(cafile=str(self.ca_file))
        self._context.minimum_version = ssl.TLSVersion.TLSv1_3
        self._context.maximum_version = ssl.TLSVersion.TLSv1_3
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                                   urllib.request.HTTPSHandler(context=self._context))
        self._event("prepare", "completed")

    @property
    def address(self):
        return ADDRESS

    @property
    def pid(self):
        return self._process.pid if self._process is not None and self._process.poll() is None else None

    @property
    def root_token(self):
        if self._root_token is None:
            raise OpenBaoRuntimeError("NOT_INITIALIZED")
        return self._root_token

    @property
    def last_response(self):
        """Last parsed response, retained in memory even if receipt I/O failed."""
        return self._last_response

    @property
    def issued_tokens(self):
        """Created token custody for supervisor cleanup, never serialized."""
        return tuple(self._issued_tokens.values())

    def _event(self, operation, result, **fields):
        self.receipt["events"].append({"operation": operation, "result": result,
            "at": datetime.now(timezone.utc).isoformat(), **fields})
        self._save_receipt()

    def _save_receipt(self):
        self._check_owner()
        path = self.root / "receipts/runtime.json"
        temporary = self.root / "receipts" / (".runtime-" + secrets.token_hex(8))
        _write_new(temporary, canonical_json(self.receipt))
        os.replace(temporary, path)

    def _check_owner(self):
        try:
            information = self.root.lstat()
            marker_path = self.root / ".hobnail-openbao.json"
            marker_info = marker_path.lstat()
            if (not stat.S_ISDIR(information.st_mode) or information.st_uid != os.geteuid()
                    or stat.S_IMODE(information.st_mode) != 0o700 or self.root.resolve() != self.root
                    or not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != os.geteuid()
                    or stat.S_IMODE(marker_info.st_mode) != 0o600 or marker_info.st_size > 8192):
                raise ValueError("ownership")
            marker = json.loads(marker_path.read_text())
            if marker != {"format": "hobnail-openbao-owned-v1", "root": str(self.root), "uid": os.geteuid(), "nonce": self._owner_nonce}:
                raise ValueError("marker")
        except (OSError, ValueError, TypeError):
            raise OpenBaoRuntimeError("OWNED_RUNTIME_IDENTITY_CHANGED") from None

    def _tls(self):
        directory = self.root / "tls"
        ca_config = """[req]
prompt = no
distinguished_name = dn
x509_extensions = ca_extensions
[dn]
CN = Hobnail Reference CA
[ca_extensions]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
"""
        leaf_config = """[req]
prompt = no
distinguished_name = dn
req_extensions = request_extensions
[dn]
CN = 127.0.0.1
[request_extensions]
subjectAltName = IP:127.0.0.1
[server_extensions]
subjectAltName = IP:127.0.0.1
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
"""
        _write_new(directory / "ca.cnf", ca_config)
        _write_new(directory / "server.cnf", leaf_config)
        commands = [
            ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca-key.pem", "-out", "ca.pem", "-days", "2", "-sha256", "-config", "ca.cnf"],
            ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "server-key.pem", "-out", "server.csr", "-sha256", "-config", "server.cnf"],
            ["x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca-key.pem", "-set_serial", str(secrets.randbits(128)),
             "-out", "server-chain.pem", "-days", "2", "-sha256", "-extfile", "server.cnf", "-extensions", "server_extensions"],
        ]
        for command in commands:
            result = subprocess.run(["/usr/bin/openssl", *command], cwd=directory, capture_output=True, timeout=30,
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(self.root / "tmp")}, check=False)
            if result.returncode:
                raise OpenBaoRuntimeError("TLS_ARTIFACT_GENERATION_FAILED")
        for path in directory.iterdir():
            path.chmod(0o600)

    def request(self, method: str, path: str, payload=None, token: Secret | str | None = None,
                expectedstatuses=(200,), *, timeout: float = 10) -> HTTPResponse:
        if method not in {"GET", "POST", "PUT", "DELETE", "LIST", "HEAD"} or not isinstance(path, str) or not re.fullmatch(r"/v1/[A-Za-z0-9_./-]+", path):
            raise OpenBaoRuntimeError("INVALID_HTTP_REQUEST")
        if "/../" in path or "/./" in path or "//" in path:
            raise OpenBaoRuntimeError("INVALID_HTTP_PATH")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise OpenBaoRuntimeError("INVALID_HTTP_TIMEOUT")
        if not isinstance(expectedstatuses, (tuple, list, set)) or not expectedstatuses or any(type(status) is not int for status in expectedstatuses):
            raise OpenBaoRuntimeError("INVALID_EXPECTED_HTTP_STATUSES")
        bearer = token.reveal() if isinstance(token, Secret) else token
        if bearer is not None:
            if not isinstance(bearer, str) or not bearer or re.search(r"[\x00-\x20\x7f]", bearer):
                raise OpenBaoRuntimeError("INVALID_EXPLICIT_TOKEN")
            self._sensitive_values.add(bearer)
        if any(secret in path for secret in self._sensitive_values):
            raise OpenBaoRuntimeError("SECRET_IN_HTTP_PATH")
        data = None if payload is None else canonical_json(payload).encode()
        if data is not None and len(data) > MAX_RESPONSE:
            raise OpenBaoRuntimeError("REQUEST_TOO_LARGE")
        self._remember_sensitive(payload)
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if bearer is not None:
            headers["X-Vault-Token"] = bearer
        request = urllib.request.Request(self.address + path, method=method, data=data, headers=headers)
        try:
            try:
                response = self._opener.open(request, timeout=timeout)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status = response.status
                raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise OpenBaoRuntimeError("RESPONSE_TOO_LARGE")
            if status not in expectedstatuses and not 200 <= status < 300:
                self._event("http", "unexpected", method=method, path=path, status=status)
                raise OpenBaoRuntimeError("UNEXPECTED_HTTP_STATUS", status=status)
            body = None if not raw else parse_json(raw.decode("utf-8"))
            if body is not None and not isinstance(body, (dict, list)):
                raise OpenBaoRuntimeError("INVALID_HTTP_RESPONSE")
        except OpenBaoRuntimeError:
            raise
        except (OSError, urllib.error.URLError, ValueError, UnicodeError, TimeoutError):
            raise OpenBaoRuntimeError("TLS_OR_HTTP_TRANSPORT_FAILED") from None
        self._remember_sensitive(body)
        result = HTTPResponse(status, body)
        self._last_response = result
        if 200 <= status < 300 and method in {"POST", "PUT"} and (path in {"/v1/auth/token/create", "/v1/auth/token/create-orphan"}
                or path.startswith("/v1/auth/token/create/")):
            auth = body.get("auth") if isinstance(body, dict) else None
            value = auth.get("client_token") if isinstance(auth, dict) else None
            if not isinstance(value, str) or not value:
                raise OpenBaoRuntimeError("TOKEN_RESPONSE_CUSTODY_INVALID")
            self._issued_tokens.setdefault(value, Secret(value))
        if self._initialization_capture and method == "POST" and path == "/v1/sys/init":
            self._capture_initialization(body)
        try:
            self._event("http", "expected" if status in expectedstatuses else "unexpected", method=method, path=path, status=status)
        except Exception:
            if status not in expectedstatuses:
                error = OpenBaoRuntimeError("UNEXPECTED_HTTP_STATUS", status=status)
                error.add_note("Response custody was preserved; local receipt persistence failed.")
                raise error from None
            raise OpenBaoRuntimeError("RECEIPT_PERSISTENCE_FAILED", status=status) from None
        if status not in expectedstatuses:
            raise OpenBaoRuntimeError("UNEXPECTED_HTTP_STATUS", status=status)
        return result

    def _remember_sensitive(self, value, key=None):
        sensitive = {"root_token", "client_token", "password", "private_key", "key", "keys", "keys_base64", "token"}
        if isinstance(value, dict):
            for name, item in value.items():
                self._remember_sensitive(item, name)
        elif isinstance(value, list):
            for item in value:
                self._remember_sensitive(item, key)
        elif isinstance(value, str) and value and key in sensitive:
            self._sensitive_values.add(value)

    def start(self, *, timeout: float = 20):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise OpenBaoRuntimeError("INVALID_START_TIMEOUT")
        self._check_owner()
        if self._process is not None and self._process.poll() is None:
            raise OpenBaoRuntimeError("ALREADY_RUNNING")
        _hash_file(self.binary, expected_mode=0o500)
        if self.config_file.is_symlink() or hashlib.sha256(self.config_file.read_bytes()).hexdigest() != self._config_digest:
            raise OpenBaoRuntimeError("REFERENCE_CONFIGURATION_CHANGED")
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", PORT))
            except OSError:
                raise OpenBaoRuntimeError("REFERENCE_PORT_UNAVAILABLE") from None
        self._generation += 1
        stdout_path = self.root / "logs" / f"server-{self._generation}.stdout"
        stderr_path = self.root / "logs" / f"server-{self._generation}.stderr"
        stdout_fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        stderr_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(stdout_fd, "wb") as stdout, os.fdopen(stderr_fd, "wb") as stderr:
            self._process = subprocess.Popen([str(self.binary), "server", "-config=./config/bao.hcl"], cwd=self.root,
                stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL, close_fds=True, start_new_session=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(self.root / "tmp")})
        self.receipt["runtime_stopped"] = False
        try:
            self._event("start", "spawned", generation=self._generation, pid=self._process.pid)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    self.receipt["runtime_stopped"] = True
                    self._event("start", "process_exit", returncode=self._process.returncode)
                    raise OpenBaoRuntimeError("REFERENCE_SERVER_START_FAILED")
                try:
                    health = self.request("GET", "/v1/sys/health", expectedstatuses=(200, 429, 501, 503), timeout=0.5)
                    if not isinstance(health.body, dict) or health.body.get("version") != "2.6.2":
                        raise OpenBaoRuntimeError("OBSERVED_VERSION_MISMATCH")
                    self._event("start", "ready", generation=self._generation, initialized=health.body.get("initialized"), sealed=health.body.get("sealed"))
                    return health
                except OpenBaoRuntimeError as error:
                    if error.code != "TLS_OR_HTTP_TRANSPORT_FAILED":
                        raise
                time.sleep(0.05)
            raise OpenBaoRuntimeError("REFERENCE_SERVER_START_TIMEOUT")
        except BaseException as primary:
            try:
                self._stop_process()
            except Exception as cleanup_error:
                primary.add_note("Owned OpenBao cleanup failed: " + type(cleanup_error).__name__)
            try:
                self._event("start", "failed", kind=type(primary).__name__)
            except Exception:
                primary.add_note("Failure receipt persistence was unavailable; in-memory evidence remains.")
            raise

    def stop(self):
        self._check_owner()
        self._stop_process()
        self._event("stop", "confirmed" if self.receipt["runtime_stopped"] else "unconfirmed",
                    generation=self._generation)
        return self.receipt["runtime_stopped"]

    def _stop_process(self):
        # The Popen handle was created by this object; no PID is adopted from a
        # file. Cleanup can still retire that child if evidence persistence fails.
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        self.receipt["runtime_stopped"] = process is None or process.poll() is not None

    def initialize(self):
        if self._root_token is not None or self._unseal_keys:
            raise OpenBaoRuntimeError("INITIALIZATION_ALREADY_RECORDED")
        self._initialization_capture = True
        try:
            self.request("POST", "/v1/sys/init", {"secret_shares": 3, "secret_threshold": 2})
        finally:
            self._initialization_capture = False
        seal = self.request("GET", "/v1/sys/seal-status")
        if not isinstance(seal.body, dict) or seal.body.get("t") != 2 or seal.body.get("n") != 3 or seal.body.get("sealed") is not True:
            raise OpenBaoRuntimeError("INITIALIZED_SEAL_PARAMETERS_MISMATCH")
        self._event("initialize", "recorded", shares=3, threshold=2)
        return {"initialized": True, "shares": 3, "threshold": 2}

    def _capture_initialization(self, body):
        # Capture irreversible initialization material before fallible local
        # receipt writes. A persistence failure still propagates to the caller.
        if (not isinstance(body, dict) or not isinstance(body.get("root_token"), str)
                or not isinstance(body.get("keys_base64"), list) or len(body["keys_base64"]) != 3
                or any(not isinstance(key, str) or not key for key in body["keys_base64"])):
            raise OpenBaoRuntimeError("INVALID_INITIALIZATION_RESPONSE")
        self._root_token = Secret(body["root_token"])
        self._unseal_keys = tuple(Secret(key) for key in body["keys_base64"])

    def unseal(self):
        if len(self._unseal_keys) != 3:
            raise OpenBaoRuntimeError("UNSEAL_MATERIAL_UNAVAILABLE")
        response = None
        for key in self._unseal_keys[:2]:
            response = self.request("POST", "/v1/sys/unseal", {"key": key.reveal()})
        if not isinstance(response.body, dict) or response.body.get("sealed") is not False:
            raise OpenBaoRuntimeError("SERVER_DID_NOT_UNSEAL")
        self._event("unseal", "confirmed")
        return {"sealed": False}

    def revoke_root(self):
        if self._root_token is None:
            raise OpenBaoRuntimeError("ROOT_TOKEN_UNAVAILABLE")
        if not self._root_revoked:
            self.request("POST", "/v1/auth/token/revoke-self", {}, self._root_token, expectedstatuses=(200, 204))
        denied = self.request("GET", "/v1/auth/token/lookup-self", token=self._root_token, expectedstatuses=(403,))
        self._root_revoked = True
        self._event("root_token", "revocation_observed", status=denied.status)
        return {"revoked": True, "lookup_status": denied.status}

    def check_secret_exclusion(self):
        paths = [*sorted((self.root / "logs").glob("server-*")), *sorted((self.root / "audit").glob("*.json")),
                 self.root / "receipts/runtime.json"]
        clear = True
        for path in paths:
            data = path.read_bytes()
            if any(secret.encode() in data for secret in self._sensitive_values) or re.search(rb"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----", data):
                clear = False
        self._event("secret_output", "absent" if clear else "detected", files_checked=len(paths))
        return clear
