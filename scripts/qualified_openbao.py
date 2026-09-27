"""Real OpenBao reference qualification in new, explicitly authorized infrastructure.

The supervisor is trusted and owns all generated credentials. This is a bounded
native macOS qualification, not production storage, human key custody, Docker,
or live application activation. Failures and private runtime data are retained.
"""
from __future__ import annotations

from dataclasses import replace
import argparse
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.dev_cluster import DevCluster
from scripts.install import install
from scripts.openbao_runtime import OpenBaoRuntime, REVIEWED_SHA256, _write_new
from scripts.qualified_local import secure_admin, require
from scripts.qualified_local import QualificationError, configure_endpoints, qualification_probe
from hobnail.client import Client, Connection, Denied, PasswordAuthenticationFailed, PsqlTransport, TransportError, canonical_json
from hobnail.credentials import (CredentialBroker, CredentialError, CredentialProfile, CredentialRequest,
    OpenBaoCredentialProvider, PostgresCredentialProvider, PostgresExternalBridge, Secret, _scram,
    configure_openbao_postgres)


def policy(backend_role):
    # Same complete four-path ACL as the frozen reference, including typed
    # parameter restrictions. No default policy or observer privilege is added.
    return '''path "database/creds/ROLE" { capabilities = ["read"] }
path "sys/leases/renew" {
  capabilities = ["update"]
  required_parameters = ["lease_id", "increment"]
  allowed_parameters = { "lease_id" = ["database/creds/ROLE/*"], "increment" = ["60s", "120s"] }
}
path "sys/leases/revoke" {
  capabilities = ["update"]
  required_parameters = ["lease_id", "sync"]
  allowed_parameters = { "lease_id" = ["database/creds/ROLE/*"], "sync" = [true] }
}
path "auth/token/revoke-self" { capabilities = ["update"] }
'''.replace("ROLE", backend_role)


def retire_reference_administrator(admin):
    """Disable the generated login and observe actual authenticated clients.

    PostgreSQL's logical replication launcher also reports usename=postgres;
    it is a server background process, not a session using this credential.
    The separately required owned-cluster stop retires those server processes.
    """
    return admin.execute_sql("ALTER ROLE postgres NOLOGIN; SELECT NOT rolcanlogin AND "
        "NOT EXISTS(SELECT FROM pg_catalog.pg_stat_activity WHERE usename='postgres' "
        "AND backend_type='client backend' AND pid<>pg_backend_pid()) "
        "FROM pg_catalog.pg_roles WHERE rolname='postgres'").strip() == "t"


class ObservedProvider(OpenBaoCredentialProvider):
    """Observe real calls without replacing the production HTTP/bridge path."""
    def __init__(self, *, runtime, **kwargs):
        super().__init__(**kwargs)
        self.runtime = runtime
        self.get_count = 0
        self.discard_next_issue = False
        self.discarded_reference = None
        self.pre_activation = []

    def issue(self, request):
        self._issuing_request = request.request_id
        return super().issue(request)

    def _request(self, method, path, payload=None):
        if method == "GET" and path.startswith("database/creds/"):
            self.get_count += 1
        result = super()._request(method, path, payload)
        self.runtime._remember_sensitive(result)
        if method == "GET" and path.startswith("database/creds/"):
            witness = self.bridge.data(self._issuing_request)
            require(witness["login_enabled"] is False and witness["role_matches"] is True
                    and witness["state"] == "created" and witness["login"] == result["data"]["username"], "inactive_actual_creation_witness")
            self.pre_activation.append({"request_id": self._issuing_request, "role_oid": witness["role_oid"],
                "login_enabled": False, "state": witness["state"]})
        if self.discard_next_issue and method == "GET":
            self.discard_next_issue = False
            # Only the trusted final-cleanup observer retains this. Neither
            # broker recovery nor its bridge receives the discarded response.
            self.discarded_reference = result["lease_id"]
            raise CredentialError("controlled response loss after actual issuance")
        return result


class LostBindingReply:
    def __init__(self, client):
        self.client = client
        self.lost = False

    def require(self, operation, payload):
        result = self.client.require(operation, payload)
        if operation == "credential.issued" and not self.lost:
            self.lost = True
            raise TransportError("controlled response loss after actual binding commit")
        return result


class Qualification:
    def __init__(self, *, source_binary):
        self.runtime = OpenBaoRuntime(source_binary=source_binary)
        self.cluster = DevCluster(root=self.runtime.root / "postgres", socket_name="socket", database="hobnail_reference")
        self.admin = None
        self.bootstrap = None
        self.bootstrap_leases = []
        self.issuers = []
        self.groups = []
        self.held = []
        self.observer_leases = {}
        self.observer_retired = set()
        self.receipt = {"schema": "hobnail-openbao-live-v1", "status": "running", "qualified": False,
            "root": str(self.runtime.root), "artifact_sha256": REVIEWED_SHA256,
            "reference_design_commit": "7622044", "checks": {}, "cleanup": [],
            "limits": ["Native macOS only; Docker not qualified", "Trusted same-user supervisor",
                "Single-node file backend, not production storage", "No separate human share custody or memory-locking claim",
                "Controlled faults are explicitly injected around actual operations", "No live application activation"]}
        self.stage = "allocated"
        self.receipt["source_identity"] = self.source_identity()
        self.receipt["configuration_sha256"] = hashlib.sha256(self.runtime.config_file.read_bytes()).hexdigest()
        self.save()

    def source_identity(self):
        paths = [*sorted((ROOT / "src/hobnail").glob("*.py")), *sorted((ROOT / "migrations").glob("*.sql")),
                 *[ROOT / "scripts" / name for name in ("qualified_openbao.py", "openbao_runtime.py", "openbao_acl_checks.py",
                    "dev_cluster.py", "install.py", "qualified_local.py", "_role_probe.py")]]
        return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}

    def save(self):
        self.runtime._check_owner()
        path = self.runtime.root / "receipts/qualification.json"
        temporary = path.with_name(".qualification-" + secrets.token_hex(8))
        _write_new(temporary, canonical_json(self.receipt))
        os.replace(temporary, path)

    def check(self, name, result):
        self.receipt["checks"][name] = result
        self.save()

    def client(self, login, password):
        return Client(PsqlTransport(replace(self.admin.connection, user=login, password=password), psql=self.admin.psql))

    def setup(self):
        self.stage = "postgres_setup"
        self.cluster.start()
        install(f"host={self.cluster.socket_dir} port=5432 dbname=hobnail_reference user=postgres sslmode=disable",
                psql=str(self.cluster.bin_dir / "psql"))
        self.admin = secure_admin(self.cluster, PsqlTransport(Connection(str(self.cluster.socket_dir),
            self.cluster.database, "postgres", sslmode="disable"), psql=str(self.cluster.bin_dir / "psql")))
        self.runtime._remember_sensitive({"password": self.admin.connection.password})
        require(self.admin.execute_sql("SHOW log_statement").strip() == "all", "actual_statement_logging_not_enabled")
        owner = Client(self.admin)
        specs = [("reference-worker", "worker", "reference-worker"),
                 ("reference-provider", "credential_provider", "reference-worker"),
                 ("reference-negative-worker", "worker", "reference-negative"),
                 ("reference-negative-provider", "credential_provider", "reference-negative"),
                 ("reference-verifier", "verifier", "reference-verifier"),
                 ("reference-verifier-provider", "credential_provider", "reference-verifier")]
        # Separate finite native verifier fixture gives privileged-profile denial
        # an existing target and an independently credentialed positive control.
        profiles = {principal: CredentialProfile(principal, frozenset({principal}), role, 900, 900)
                    for principal, role, _ in specs}
        self.bootstrap = PostgresCredentialProvider(self.admin, provider_id="reference-bootstrap-" + secrets.token_hex(8), profiles=profiles)
        self.clients = {}
        for number, (principal, role, scope) in enumerate(specs, 1):
            lease = self.bootstrap.issue(CredentialRequest(number, principal, principal, role, 900))
            self.bootstrap_leases.append(lease)
            self.runtime._remember_sensitive({"password": lease.password.reveal()})
            owner.require("principal.bind", {"login": lease.login, "principal": principal, "role": role,
                "contracts": [], "sources": [], "profiles": [scope]})
            self.clients[principal] = self.client(lease.login, lease.password.reveal())
            require(self.clients[principal].transport.execute_sql("SELECT session_user").strip() == lease.login, "bootstrap_auth")
        owner.require("credential.profile", {"profile": "reference-verifier", "provider": "reference-verifier-provider",
            "principals": ["reference-verifier"], "role": "verifier", "max_ttl_seconds": 120,
            "max_lifetime_seconds": 240, "renewable": False, "capabilities": ["dynamic_postgres"]})
        for name, principal, provider_id, issuer, backend, connection, policy_name in (
            ("reference-worker", "reference-worker", "reference-provider", "hbn_bao_reference", "hobnail-worker", "hobnail-reference", "hobnail-reference-provider"),
            ("reference-negative", "reference-negative-worker", "reference-negative-provider", "hbn_bao_negative", "hobnail-negative-control", "hobnail-negative-control", "hobnail-negative-provider")):
            profile = CredentialProfile(name, frozenset({principal}), "worker", 120, 240, True, backend_role=backend)
            owner.require("credential.profile", {"profile": name, "provider": provider_id, "principals": [principal],
                "role": "worker", "max_ttl_seconds": 120, "max_lifetime_seconds": 240, "renewable": True,
                "capabilities": ["dynamic_postgres", "renewal", "revocation", "active_session_termination"]})
            password = Secret(secrets.token_urlsafe(36))
            self.runtime._remember_sensitive({"password": password.reveal()})
            self.issuers.append(issuer)
            # Issuers are freshly created, unbound, unprivileged logins. COPY
            # prevents password/verifier data appearing in statement text.
            self.admin.execute_sql(f'BEGIN; CREATE ROLE "{issuer}" LOGIN; CREATE TEMP TABLE issuer_auth(v text) ON COMMIT DROP;\n'
                'COPY issuer_auth FROM STDIN;\n' + _scram(password.reveal()) + '\n\\.\n'
                f"DO $set$ DECLARE v text; BEGIN SELECT issuer_auth.v INTO STRICT v FROM issuer_auth; EXECUTE format('ALTER ROLE {issuer} PASSWORD %L',v); END $set$; COMMIT;", sensitive=True)
            require(self.client(issuer, password.reveal()).transport.execute_sql("SELECT session_user").strip() == issuer, "issuer_auth")
            templates = configure_openbao_postgres(self.admin, profile=name, issuer_login=issuer, backend_role=backend, issuance_ttl_seconds=60)
            self.groups.append({"name": name, "principal": principal, "provider_id": provider_id, "profile": profile,
                "issuer": issuer, "password": password, "backend": backend, "connection": connection,
                "policy": policy_name, "templates": templates, "requests": []})
        socket_only = self.admin.execute_sql("SHOW listen_addresses").strip() == ""
        require(socket_only, "postgres_tcp_listener_not_permitted")
        self.check("postgres", {"all_logins_scram": True, "socket_only": socket_only,
            "database": self.cluster.database, "privileged_fixture": "separate native reference-verifier; no added Bao privileges"})
        self.stage = "openbao_bootstrap"
        self.runtime.start()
        self.runtime.initialize()
        self.runtime.unseal()
        self.tls_controls()
        self.http("POST", "sys/mounts/database", {"type": "database", "config": {"default_lease_ttl": "60s", "max_lease_ttl": "240s"}})
        for group in self.groups:
            templates = group["templates"]
            self.http("POST", "database/config/" + group["connection"], {
                "plugin_name": "postgresql-database-plugin", "allowed_roles": [group["backend"]], "verify_connection": True,
                "username": group["issuer"], "password": group["password"].reveal(), "username_template": templates["username_template"],
                "connection_url": f"host={self.cluster.socket_dir} port=5432 dbname=hobnail_reference user={{{{username}}}} password={{{{password}}}} sslmode=disable",
                "max_open_connections": 1, "max_idle_connections": 1, "max_connection_lifetime": "60s"})
            role = {key: [templates[key]] for key in ("creation_statements", "renew_statements", "revocation_statements", "rollback_statements")}
            role.update(db_name=group["connection"], default_ttl="60s", max_ttl="240s")
            self.http("POST", "database/roles/" + group["backend"], role)
            self.http("PUT", "sys/policies/acl/" + group["policy"], {"policy": policy(group["backend"])})
            token = self.http("POST", "auth/token/create", {"policies": [group["policy"]], "no_default_policy": True,
                "no_parent": True, "renewable": False, "ttl": "15m", "explicit_max_ttl": "15m",
                "display_name": group["policy"], "num_uses": 0, "type": "service"}).body["auth"]
            group["token"] = Secret(token["client_token"])
            require(token["policies"] == [group["policy"]] and token["renewable"] is False, "scoped_token_authority")
            group["bridge"] = PostgresExternalBridge(self.admin, self.clients[group["provider_id"]])
            self.new_broker(group)
        self.inventory_and_configuration_controls()
        self.check("root_token", self.runtime.revoke_root())

    def http(self, method, path, payload=None):
        return self.runtime.request(method, "/v1/" + path, payload, token=self.runtime.root_token, expectedstatuses=(200, 204))

    def new_broker(self, group):
        group["provider"] = ObservedProvider(runtime=self.runtime, address=self.runtime.address, token=group["token"],
            provider_id=group["provider_id"], profiles={group["name"]: group["profile"]}, ca_file=str(self.runtime.ca_file), bridge=group["bridge"])
        group["broker"] = CredentialBroker(self.clients[group["provider_id"]], group["provider"])

    def inventory_and_configuration_controls(self):
        mounts = self.http("GET", "sys/mounts").body["data"]
        require(set(mounts) == {"sys/", "identity/", "cubbyhole/", "database/"}, "unexpected_application_mount")
        auth = self.http("GET", "sys/auth").body["data"]
        require(set(auth) == {"token/"}, "unexpected_auth_engine")
        catalog = self.http("GET", "sys/plugins/catalog/database/postgresql-database-plugin").body["data"]
        require(catalog.get("builtin") is True, "postgres_plugin_not_builtin")
        audit = self.http("GET", "sys/audit").body["data"]
        require(len(audit) == 1 and next(iter(audit.values()))["type"] == "file", "audit_inventory")
        network = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-p", str(self.runtime.pid), "-i"], capture_output=True, text=True, check=False)
        require(network.returncode == 0, "network_inventory_unavailable")
        rows = network.stdout.splitlines()[1:]
        require(len(rows) == 1 and "127.0.0.1:18200 (LISTEN)" in rows[0], "unexpected_network_socket")
        self.check("inventory", {"mounts": sorted(mounts), "auth": sorted(auth), "postgres_plugin": catalog,
            "audit_types": [row["type"] for row in audit.values()], "observed_ip_sockets": ["127.0.0.1:18200 LISTEN"],
            "network_scope": "point-in-time process socket inventory, not continuous packet capture"})
        group = self.groups[0]
        targets = ["sys/policies/acl/" + group["policy"], "database/roles/" + group["backend"],
                   "database/config/" + group["connection"], "sys/plugins/catalog/database/postgresql-database-plugin"]
        controls = []
        for target in targets:
            before = self.http("GET", target).body
            result = self.runtime.request("PUT", "/v1/" + target, {"qualification_forbidden_mutation": True},
                token=group["token"], expectedstatuses=(403,))
            after = self.http("GET", target).body
            # Request IDs differ per read; only actual target data is compared.
            require(before["data"] == after["data"], "forbidden_configuration_changed")
            controls.append({"target": target, "status": result.status, "unchanged": True})
        self.check("existing_configuration_denials", controls)
        for token in (None, Secret("synthetic-invalid-token")):
            self.runtime.request("GET", "/v1/database/config/" + group["connection"], token=token, expectedstatuses=(403,))
        self.check("token_negatives", {"missing": 403, "invalid": 403})

    def tls_controls(self):
        trusted = ssl.create_default_context(cafile=self.runtime.ca_file)
        with socket.create_connection(("127.0.0.1", 18200), timeout=3) as raw:
            with trusted.wrap_socket(raw, server_hostname="127.0.0.1") as secure:
                require(secure.version() == "TLSv1.3", "observed_tls_version")
        for label, context in (("untrusted_ca", ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)),
                               ("tls12", ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))):
            if label == "tls12":
                context.load_verify_locations(cafile=self.runtime.ca_file)
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            try:
                with socket.create_connection(("127.0.0.1", 18200), timeout=3) as raw:
                    with context.wrap_socket(raw, server_hostname="127.0.0.1"):
                        pass
            except ssl.SSLError:
                pass
            else:
                raise QualificationError(label + "_not_refused")
        with socket.create_connection(("127.0.0.1", 18200), timeout=3) as raw:
            raw.sendall(b"GET /v1/sys/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            response = raw.recv(2048)
            require(response.startswith(b"HTTP/1.0 400") or response.startswith(b"HTTP/1.1 400"), "plaintext_not_rejected")
        self.check("tls", {"trusted_ca_and_ip_san": True, "version": "TLSv1.3", "untrusted_ca_refused": True,
            "tls12_refused": True, "plaintext_http_status": 400})

    def request(self, group, key):
        identifier = self.clients[group["principal"]].require("credential.request", {
            "profile": group["name"], "ttl_seconds": 60, "idempotency_key": key})["data"]["request_id"]
        group["requests"].append(identifier)
        return identifier

    def issue(self, group, key):
        lease = group["broker"].issue_request(self.request(group, key))
        self.runtime._remember_sensitive({"password": lease.password.reveal()})
        return lease

    def snapshot(self, lease):
        return json.loads(self.admin.execute_sql(f"SET TIME ZONE 'UTC'; SELECT json_build_object('oid',r.oid::bigint,'expires_at',r.rolvaliduntil,"
            "'login_enabled',r.rolcanlogin,'valid',r.rolvaliduntil>clock_timestamp(),'active_sessions',"
            f"(SELECT count(*) FROM pg_stat_activity WHERE usesysid=r.oid)) FROM pg_roles r WHERE rolname='{lease.login}'").strip())

    def authenticate(self, lease):
        actor = self.client(lease.login, lease.password.reveal())
        require(actor.transport.execute_sql("SELECT session_user").strip() == lease.login, "credential_positive_authentication")
        try:
            self.client(lease.login, "synthetic-wrong-password").transport.execute_sql("SELECT session_user")
        except PasswordAuthenticationFailed:
            return actor
        raise CredentialError("wrong password was accepted")

    def hold(self, lease):
        environment = self.cluster._environment()
        environment["PGPASSWORD"] = lease.password.reveal()
        process = subprocess.Popen([self.admin.psql, "-X", "-w", "-q", "-t", "-A", "-h", str(self.cluster.socket_dir),
            "-p", "5432", "-U", lease.login, "-d", self.cluster.database, "-c", "SELECT pg_sleep(240)"],
            env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.held.append(process)
        for _ in range(100):
            if self.snapshot(lease)["active_sessions"] == 1:
                return process
            require(process.poll() is None, "held_session_failed")
            time.sleep(.02)
        raise CredentialError("held session unavailable")

    def run_checks(self):
        from scripts.openbao_acl_checks import run_acl_checks
        main, foreign = self.groups
        self.stage = "issuance_and_acl"
        lease = self.issue(main, "main-positive")
        other = self.issue(foreign, "foreign-positive")
        actor = self.authenticate(lease)
        self.authenticate(other)
        state = actor.require("credential.get", {"credential_id": lease.credential_id})["data"]
        require(state["principal"] == "reference-worker" and state["role"] == "worker", "principal_binding")
        held = self.hold(lease)
        self.hold(other)
        self.clients[main["principal"]].require("credential.renew_requested", {"credential_id": lease.credential_id, "ttl_seconds": 60})
        first_renewal = main["broker"].renew_requested(lease.credential_id)
        require(self.snapshot(lease)["expires_at"] == first_renewal.expires_at, "allowed_sixty_second_renewal")
        self.check("lease_acl", run_acl_checks(self.runtime, main["token"], lease, other, self.snapshot))
        self.authenticate(other)
        denied = actor.call("credential.request", {"profile": "reference-verifier", "ttl_seconds": 60, "idempotency_key": "privileged-denial"})
        require(not denied["ok"] and denied["code"] == "CREDENTIAL_SCOPE", "privileged_profile_denial")
        positive = self.clients["reference-verifier"].require("credential.request", {
            "profile": "reference-verifier", "ttl_seconds": 60, "idempotency_key": "privileged-positive"})
        self.check("privileged_profile", {"worker_code": denied["code"], "verifier_request_id": positive["data"]["request_id"],
            "scope": "existing native verifier profile and independently authenticated requester; no Bao verifier issuance"})
        before = self.snapshot(lease)
        self.clients[main["principal"]].require("credential.renew_requested", {"credential_id": lease.credential_id, "ttl_seconds": 120})
        renewed = main["broker"].renew_requested(lease.credential_id)
        after = self.snapshot(lease)
        require(before["oid"] == after["oid"] and after["expires_at"] == renewed.expires_at, "renewal_actual_identity_expiry")
        require(datetime.fromisoformat(renewed.expires_at) <= datetime.fromisoformat(lease.created_at) + timedelta(seconds=240), "renewal_lifetime_ceiling")
        self.check("issuance_and_renewal", {"principal": state["principal"], "request_id": lease.request_id,
            "credential_id": lease.credential_id, "role_oid": after["oid"], "created_at": lease.created_at,
            "initial_expiry": lease.expires_at, "renewed_expiry": renewed.expires_at, "actual_scram_positive_and_negative": True,
            "allowed_increment_wire_values": ["60s", "120s"], "integer_ttl_api_values": [60, 120]})
        self.check("inactive_creation_witness", main["provider"].pre_activation)
        self.worker_isolation(actor, main)
        # Observe the real bridge immediately before its termination query. Its
        # preceding separate SQL call has already committed NOLOGIN.
        real_admin = main["bridge"].admin
        observations = []
        outer = self
        class ObserveTermination:
            def __getattr__(self, name):
                return getattr(real_admin, name)
            def execute_sql(self, sql, **kwargs):
                if sql.startswith("SELECT pg_terminate_backend"):
                    observations.append(outer.snapshot(lease))
                return real_admin.execute_sql(sql, **kwargs)
        main["bridge"].admin = ObserveTermination()
        self.clients[main["principal"]].require("credential.revoke_requested", {"credential_id": lease.credential_id})
        try:
            observation = main["broker"].revoke_requested(lease.credential_id)
        finally:
            main["bridge"].admin = real_admin
        require(len(observations) == 1 and observations[0]["login_enabled"] is False
                and observations[0]["active_sessions"] == 1, "nologin_commit_precedes_termination")
        require(observation.result == "confirmed" and observation.active_sessions == 0, "synchronous_revocation")
        require(held.wait(timeout=5) != 0, "existing_session_not_terminated")
        try:
            actor.transport.execute_sql("SELECT 1")
        except TransportError:
            require(self.snapshot(lease)["login_enabled"] is False, "new_login_denial_independent_state")
        else:
            raise CredentialError("revoked login authenticated")
        self.check("revocation", {"confirmed": True, "active_sessions": 0, "existing_session_terminated": True,
            "new_login_denied": True, "login_enabled": False, "committed_nologin_before_termination": True})
        self.check("foreign_retirement", {"confirmed": foreign["broker"].reconcile_request(other.request_id).result == "confirmed"})
        require(self.receipt["checks"]["foreign_retirement"]["confirmed"], "foreign_retirement")
        lifetime = self.issue(main, "original-lifetime")
        self.clients[main["principal"]].require("credential.renew_requested", {"credential_id": lifetime.credential_id, "ttl_seconds": 120})
        main["broker"].renew_requested(lifetime.credential_id)
        self.fault_checks(main)
        self.lifetime_ceiling(main, lifetime)

    def lifetime_ceiling(self, group, lease):
        self.stage = "original_lifetime_ceiling"
        # Keep the actual lease alive with a valid renewal, then cross the
        # original 240-second ceiling with another 120-second request. Neither
        # wall clock, timestamps nor frozen profile limits are shortened.
        worker = self.clients[group["principal"]]
        worker.require("credential.renew_requested", {"credential_id": lease.credential_id, "ttl_seconds": 120})
        group["broker"].renew_requested(lease.credential_id)
        threshold = datetime.fromisoformat(lease.created_at) + timedelta(seconds=121)
        while datetime.now(timezone.utc) < threshold:
            time.sleep(.25)
        before = self.snapshot(lease)
        require(before["valid"] is True and before["login_enabled"] is True, "lifetime_probe_not_active")
        actor = self.authenticate(lease)
        denied = worker.call("credential.renew_requested", {"credential_id": lease.credential_id, "ttl_seconds": 120})
        require(not denied["ok"] and denied["code"] == "CREDENTIAL_SCOPE", "original_lifetime_ceiling_not_refused")
        require(self.snapshot(lease) == before, "lifetime_denial_changed_actual_role")
        require(actor.transport.execute_sql("SELECT session_user").strip() == lease.login, "lifetime_denial_positive_control")
        require(group["broker"].reconcile_request(lease.request_id).result == "confirmed", "lifetime_probe_retirement")
        self.check("original_lifetime_ceiling", {"original_created_at": lease.created_at, "maximum_lifetime_seconds": 240,
            "requested_extension_seconds": 120, "request_after_original_age_seconds": 121,
            "denial_code": denied["code"], "actual_oid_expiry_unchanged": True, "positive_authentication_after_denial": True})

    def worker_isolation(self, actor, main):
        destination = self.cluster.root / "boundary-destination"
        destination.mkdir(mode=0o700)
        endpoints = configure_endpoints(self.cluster, {"worker": actor, "credential_provider": self.clients[main["provider_id"]]}, destination)
        # Exact production worker profile; files are existing owned targets and
        # network target is the actual live TLS listener, never a missing path.
        peer = endpoints["credential_provider"].policy.config
        targets = [peer, self.runtime.config_file, self.runtime.root / "tls/server-key.pem"]
        before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in targets]
        result = qualification_probe(endpoints["worker"], {"files": [str(path) for path in targets],
            "tcp_port": 18200, "admin_connection": True})
        require(all(row == {"readable": False, "reason": "permission_denied"} for row in result["files"])
            and result["tcp_denied"] is True and result["administrator_without_password_denied"] is True
            and result["administrator_with_role_password_denied"] is True, "worker_native_boundary")
        require(before == [hashlib.sha256(path.read_bytes()).hexdigest() for path in targets], "worker_targets_changed")
        self.check("native_worker_boundary", {"peer_config_read_denied": True, "bao_config_and_key_read_denied": True,
            "actual_bao_port_denied": True, "administrator_authentication_denied": True, "targets_unchanged": True})

    def fault_checks(self, group):
        self.stage = "serialization_and_delayed_creation"
        first = self.request(group, "prepared-first")
        second = self.request(group, "prepared-second")
        def prepare(identifier):
            try:
                group["bridge"].prepare(identifier)
                return identifier, True
            except Denied:
                return identifier, False
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(prepare, (first, second)))
        require(sum(success for _, success in outcomes) == 1, "concurrent_profile_not_serialized")
        first = next(identifier for identifier, success in outcomes if success)
        second = next(identifier for identifier, success in outcomes if not success)
        require(group["broker"].reconcile_request(first).result == "pending", "witnessless_attempt_not_pending")
        try:
            group["bridge"].prepare(second)
        except Denied:
            pass
        else:
            raise QualificationError("recovery_unfenced_missing_witness")
        late = self.runtime.request("GET", "/v1/database/creds/" + group["backend"], token=group["token"]).body
        self.observer_leases[first] = (group, late["lease_id"])
        witness = group["bridge"].data(first)
        require(witness["login"] == late["data"]["username"] and witness["login_enabled"] is False, "late_creation_reassigned")
        require(group["broker"].reconcile_request(first).result == "pending", "late_unknown_reference_not_pending")
        self.runtime.request("PUT", "/v1/sys/leases/revoke", {"lease_id": late["lease_id"], "sync": True},
            token=group["token"], expectedstatuses=(200, 204))
        self.observer_retired.add(first)
        second_lease = group["broker"].issue_request(second)
        require(group["broker"].reconcile_request(second).result == "confirmed", "serialized_second_retirement")
        self.check("delayed_creation", {"original_request_id": first, "second_request_id": second,
            "simultaneous_preparations": 2, "prepared_winners": 1,
            "profile_fenced_before_and_after_reconciliation": True, "late_witness_assigned_to_original": True,
            "late_role_never_enabled": True, "unknown_reference_stays_pending": True,
            "separate_observer_retired_actual_lease": True, "second_issue_only_after_original_closed": True})
        self.stage = "hook_drift"
        identifier = self.request(group, "drift-refusal")
        count = group["provider"].get_count
        self.admin.execute_sql("GRANT EXECUTE ON FUNCTION hobnail_external.create_role(text,text,timestamptz) TO PUBLIC")
        try:
            try:
                group["broker"].issue_request(identifier)
            except CredentialError:
                pass
            else:
                raise QualificationError("hook_drift_not_refused")
        finally:
            self.admin.execute_sql("REVOKE EXECUTE ON FUNCTION hobnail_external.create_role(text,text,timestamptz) FROM PUBLIC")
        group["bridge"].verify_hooks()
        require(group["provider"].get_count == count, "drift_request_reached_openbao")
        # No attempt exists, so the same legitimate pending request can proceed
        # only after restoring the actual fixture grants and reviewing inventory.
        group["broker"].issue_request(identifier)
        require(group["broker"].reconcile_request(identifier).result == "confirmed", "restored_hook_positive_control")
        self.check("hook_drift", {"actual_public_grant_refused_before_http": True,
            "original_grant_restored": True, "positive_control_after_restore": True})
        self.stage = "lost_responses"
        identifier = self.request(group, "lost-binding")
        broker = CredentialBroker(LostBindingReply(self.clients[group["provider_id"]]), group["provider"])
        try:
            broker.issue_request(identifier)
        except TransportError:
            pass
        else:
            raise CredentialError("binding response was not discarded")
        data = group["bridge"].data(identifier)
        require(data["state"] == "closed" and data["provider_cleanup"] == "confirmed" and data["login_enabled"] is False, "lost_binding_cleanup")
        self.check("lost_binding_response", {"request_id": identifier, "state": data["state"], "provider_cleanup": data["provider_cleanup"]})
        identifier = self.request(group, "lost-http")
        provider = group["provider"]
        count = provider.get_count
        provider.discard_next_issue = True
        try:
            group["broker"].issue_request(identifier)
        except CredentialError:
            pass
        else:
            raise CredentialError("HTTP response was not discarded")
        if provider.discarded_reference is not None:
            self.observer_leases[identifier] = (group, provider.discarded_reference)
        data = group["bridge"].data(identifier)
        require((data["state"], data["login_enabled"], data["provider_cleanup"]) == ("closed", False, "unavailable"), "lost_http_authority")
        require(group["broker"].reconcile_request(identifier).result == "pending", "unknown_external_reference_must_remain_pending")
        try:
            group["broker"].issue_request(identifier)
        except CredentialError:
            pass
        else:
            raise CredentialError("lost issuance was redispatched")
        require(provider.get_count == count + 1, "lost_http_issued_more_than_once")
        self.check("lost_http_response", {"request_id": identifier, "actual_issuances": 1, "login_enabled": False,
            "broker_recovery": "pending", "provider_cleanup": "unavailable", "redispatch_refused": True})
        # Separate test-supervisor cleanup, not broker reconciliation evidence.
        self.runtime.request("PUT", "/v1/sys/leases/revoke", {"lease_id": provider.discarded_reference, "sync": True},
            token=group["token"], expectedstatuses=(200, 204))
        self.observer_retired.add(identifier)
        self.check("lost_http_fixture_retirement", {"external_lease_retired_by_separate_observer": True,
            "broker_record_remains_unavailable": group["bridge"].data(identifier)["provider_cleanup"] == "unavailable"})
        self.stage = "actual_server_restart"
        lease = self.issue(group, "restart")
        self.runtime.stop()
        unavailable = group["broker"].reconcile_request(lease.request_id)
        require(unavailable.result == "pending" and unavailable.login_enabled is False
                and unavailable.active_sessions == 0, "provider_outage_not_pending")
        self.runtime.start()
        self.runtime.unseal()
        self.new_broker(group)
        require(group["broker"].reconcile_request(lease.request_id).result == "confirmed", "restart_reconciliation")
        require(group["provider"].get_count == 0, "restart_reissued_credential")
        self.check("restart", {"same_file_backend": True, "retained_memory_unseal": True,
            "outage_reconciliation": "pending", "authority_disabled_during_outage": True,
            "fresh_provider_object": True, "existing_credential_reconciled": True, "new_issuances": 0})
        self.queued_protocol_check(group)
        self.stage = "natural_expiry"
        expired = self.issue(group, "natural-expiry")
        held = self.hold(expired)
        self.authenticate(expired)
        deadline = time.monotonic() + 70
        while self.snapshot(expired)["valid"]:
            require(time.monotonic() < deadline, "actual_database_expiry_not_observed")
            time.sleep(.25)
        before = self.snapshot(expired)
        require(before["active_sessions"] == 1 and held.poll() is None, "expiry_did_not_preserve_existing_session")
        try:
            self.client(expired.login, expired.password.reveal()).transport.execute_sql("SELECT 1")
        except TransportError:
            pass
        else:
            raise QualificationError("expired_login_authenticated")
        require(group["broker"].reconcile_request(expired.request_id).result == "confirmed", "expired_session_cleanup")
        require(held.wait(timeout=5) != 0, "expired_session_not_terminated")
        self.check("natural_expiry", {"actual_expiry": expired.expires_at, "new_login_denied": True,
            "existing_session_survived_expiry": True, "explicit_reconciliation_terminated_session": True})

    def queued_protocol_check(self, group):
        """Inject 202 around an actual completed HTTP exchange, labelled as such.

        Main ACL remains sync:true. This establishes conservative handling of an
        ambiguous transport status, not that this OpenBao server queued revoke.
        """
        self.stage = "controlled_202_protocol"
        lease = self.issue(group, "controlled-202")
        self.clients[group["principal"]].require("credential.revoke_requested", {"credential_id": lease.credential_id})
        provider = group["provider"]
        original = provider._opener
        observed_statuses = []
        class QueuedResponse:
            status = 202
            def __init__(self, response):
                self.response = response
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.response.close()
            def read(self, *args):
                return self.response.read(*args)
        class QueuedTransport:
            def open(self, request, **kwargs):
                response = original.open(request, **kwargs)
                if request.full_url.endswith("/v1/sys/leases/revoke"):
                    observed_statuses.append(response.status)
                    return QueuedResponse(response)
                return response
        provider._opener = QueuedTransport()
        try:
            observed = group["broker"].revoke_requested(lease.credential_id)
        finally:
            provider._opener = original
        require(observed_statuses and all(status in (200, 204) for status in observed_statuses)
                and observed.result == "pending", "controlled_202_not_pending")
        metadata = self.clients[group["provider_id"]].require("credential.get", {"credential_id": lease.credential_id})["data"]
        require(metadata["state"] != "revoked", "controlled_202_claimed_final_revocation")
        require(group["broker"].reconcile_request(lease.request_id).result == "confirmed", "controlled_202_eventual_cleanup")
        self.check("controlled_202_protocol", {"injected_response_status": 202, "actual_server_statuses": observed_statuses,
            "broker_result": "pending", "kernel_state_before_reconciliation": metadata["state"],
            "subsequent_unmodified_exchange_confirmed": True, "server_queued_revocation_claimed": False})

    def cleanup(self):
        def attempt(stage, operation):
            try:
                require(operation() is not False, stage)
                self.receipt["cleanup"].append({"stage": stage, "confirmed": True})
            except Exception as error:
                self.receipt["status"] = "failed"
                self.receipt["cleanup"].append({"stage": stage, "confirmed": False, "error": type(error).__name__})
        # Fault-observer references remain separate from broker metadata. Retire
        # them even if a check failed before its planned observer cleanup step.
        for identifier, (group, reference) in self.observer_leases.items():
            if identifier not in self.observer_retired:
                def retire_observed(identifier=identifier, group=group, reference=reference):
                    self.runtime.request("PUT", "/v1/sys/leases/revoke", {"lease_id": reference, "sync": True},
                        token=group["token"], expectedstatuses=(200, 204))
                    self.observer_retired.add(identifier)
                attempt("separate_observer_retirement_" + str(identifier), retire_observed)
        for group in self.groups:
            if "broker" in group:
                for identifier in group["requests"]:
                    def retire(group=group, identifier=identifier):
                        data = group["bridge"].data(identifier)
                        # Unknown-reference fault evidence deliberately stays
                        # pending; require no downstream authority and separately
                        # observed fixture retirement instead of forging metadata.
                        if data["state"] == "closed" and data["provider_cleanup"] == "unavailable":
                            return (data["login_enabled"] is False and data["active_sessions"] == 0
                                    and identifier in self.observer_retired)
                        return group["broker"].reconcile_request(identifier).result == "confirmed"
                    attempt("request_retirement_" + str(identifier), retire)
            if "token" in group:
                def retire_token(group=group):
                    self.runtime.request("POST", "/v1/auth/token/revoke-self", {}, token=group["token"], expectedstatuses=(200, 204))
                    self.runtime.request("POST", "/v1/auth/token/revoke-self", {}, token=group["token"], expectedstatuses=(403,))
                    group["token_retired"] = True
                attempt("token_retirement_" + group["name"], retire_token)
        retired = {group["token"].reveal() for group in self.groups if group.get("token_retired")}
        for number, token in enumerate(getattr(self.runtime, "issued_tokens", ()), 1):
            if token.reveal() in retired:
                continue
            def retire_custodied(token=token):
                if self.runtime._root_token is not None and not self.runtime._root_revoked:
                    # A token minted before a setup/receipt failure may have
                    # failed its authority assertion. Use the bootstrap owner,
                    # not an assumed revoke-self permission, for that case.
                    self.runtime.request("POST", "/v1/auth/token/revoke", {"token": token.reveal()},
                        token=self.runtime.root_token, expectedstatuses=(200, 204))
                else:
                    self.runtime.request("POST", "/v1/auth/token/revoke-self", {}, token=token, expectedstatuses=(200, 204, 403))
                self.runtime.request("POST", "/v1/auth/token/revoke-self", {}, token=token, expectedstatuses=(403,))
            attempt("custodied_token_retirement_" + str(number), retire_custodied)
        if self.runtime._root_token is not None and not self.runtime._root_revoked:
            attempt("root_token_retirement", self.runtime.revoke_root)
        if self.admin is not None:
            for issuer in self.issuers:
                def retire_issuer(issuer=issuer):
                    self.admin.execute_sql(f'ALTER ROLE "{issuer}" NOLOGIN;')
                    self.admin.execute_sql(f"SELECT pg_terminate_backend(pid,5000) FROM pg_stat_activity WHERE usename='{issuer}';")
                    return self.admin.execute_sql(f"SELECT NOT rolcanlogin AND NOT EXISTS(SELECT FROM pg_stat_activity WHERE usename='{issuer}') FROM pg_roles WHERE rolname='{issuer}'").strip() == "t"
                attempt("issuer_retirement_" + issuer, retire_issuer)
            if self.bootstrap is not None:
                # Inventory includes any issuance whose response was lost.
                inventory = []
                attempt("bootstrap_inventory", lambda: inventory.extend(self.bootstrap.inventory()))
                recoverable = {lease.lease_ref: lease for lease in [*self.bootstrap_leases, *inventory]}
                for lease in recoverable.values():
                    attempt("bootstrap_retirement_" + lease.principal,
                        lambda lease=lease: self.bootstrap.revoke(lease.lease_ref).result == "confirmed")
            attempt("generated_administrator_retirement", lambda: retire_reference_administrator(self.admin))
        for process in self.held:
            def terminate_owned(process=process):
                if process.poll() is None:
                    process.terminate()
            attempt("owned_session_terminate", terminate_owned)
            attempt("owned_session_exit", lambda process=process: process.wait(timeout=5) is not None)
            for stream in (process.stdout, process.stderr):
                if stream:
                    attempt("owned_session_stream_close", stream.close)
        attempt("openbao_stop", self.runtime.stop)
        attempt("postgres_stop", lambda: self.cluster.stop() or not self.cluster.is_running())
        attempt("intermediate_receipt_persistence", self.save)
        def logs_clear():
            pg_log = self.cluster.root / "server.log"
            audit_log = self.runtime.root / "audit/openbao.json"
            server_logs = list(self.runtime.root.joinpath("logs").glob("server-*"))
            require(pg_log.is_file() and pg_log.stat().st_size > 0 and audit_log.is_file()
                and audit_log.stat().st_size > 0 and server_logs
                and any(path.stat().st_size > 0 for path in server_logs), "expected_nonempty_logs_missing")
            pg_data = pg_log.read_bytes()
            require(b"hobnail_external.create_role" in pg_data and b"COPY pg_temp.hobnail_external_material" in pg_data,
                "actual_issuance_statement_evidence_missing")
            events = [json.loads(line) for line in audit_log.read_text().splitlines()]
            generated = [row for row in events if row.get("type") == "response"
                and row.get("request", {}).get("path", "").startswith("database/creds/")
                and "password" in row.get("response", {}).get("data", {})]
            require(generated and all(row["response"]["data"]["password"].startswith("hmac-sha256:") for row in generated),
                "actual_hmac_credential_audit_evidence_missing")
            paths = [pg_log, audit_log, *server_logs, *self.runtime.root.joinpath("receipts").glob("*.json")]
            for path in paths:
                data = path.read_bytes()
                if (b"SCRAM-SHA-256$4096:" in data or b"PRIVATE KEY-----" in data
                        or any(value.encode() in data for value in self.runtime._sensitive_values)):
                    return False
            require(self.runtime.check_secret_exclusion(), "runtime_secret_scan_failed")
            self.receipt["checks"]["secret_exclusion"] = {"clear": True, "files_checked": len(paths),
                "actual_hmac_credential_responses": len(generated),
                "channels": ["postgres_statement_log", "openbao_server", "openbao_hmac_audit", "receipts"]}
            return True
        attempt("generated_secret_exclusion", logs_clear)
        attempt("executed_source_unchanged", lambda: self.source_identity() == self.receipt["source_identity"])
        required_checks = {"postgres", "tls", "inventory", "existing_configuration_denials", "token_negatives", "root_token",
            "lease_acl", "privileged_profile", "issuance_and_renewal", "inactive_creation_witness", "native_worker_boundary",
            "revocation", "foreign_retirement", "delayed_creation", "hook_drift", "lost_binding_response", "lost_http_response",
            "lost_http_fixture_retirement", "restart", "controlled_202_protocol", "natural_expiry", "original_lifetime_ceiling", "secret_exclusion"}
        self.receipt["missing_checks"] = sorted(required_checks - self.receipt["checks"].keys())
        if self.receipt["missing_checks"]:
            self.receipt["status"] = "failed"
        self.receipt["qualified"] = self.receipt["status"] == "passed"
        try:
            self.save()
        except Exception as error:
            self.receipt["status"] = "failed"
            self.receipt["qualified"] = False
            self.receipt["cleanup"].append({"stage": "final_receipt_persistence", "confirmed": False,
                "error": type(error).__name__})

    def run(self):
        try:
            self.setup()
            self.run_checks()
            self.receipt["status"] = "passed"
        except Exception as error:
            self.receipt["status"] = "failed"
            self.receipt["failure"] = {"stage": self.stage, "type": type(error).__name__,
                "safe_code": getattr(error, "code", None)}
            if isinstance(error, QualificationError):
                self.receipt["failure"]["check"] = str(error)
            from scripts.openbao_acl_checks import ACLCheckFailure
            if isinstance(error, ACLCheckFailure):
                self.receipt["failure"]["acl_evidence"] = error.evidence
            import traceback
            self.receipt["failure"]["frames"] = [{"file": Path(frame.filename).name, "line": frame.lineno,
                "function": frame.name} for frame in traceback.extract_tb(error.__traceback__)]
            # Exception text can contain database or HTTP content; retain only
            # type/stage/code. Detailed source logs stay inside the private W.
        finally:
            self.cleanup()
        return self.receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-binary", required=True, help="Explicit owner-released reviewed read-only OpenBao binary")
    arguments = parser.parse_args()
    qualification = Qualification(source_binary=arguments.source_binary)
    print(json.dumps({"event": "qualification_started", "root": str(qualification.runtime.root)}), flush=True)
    result = qualification.run()
    print(json.dumps({"status": result["status"], "qualified": result["qualified"],
        "receipt": str(qualification.runtime.root / "receipts/qualification.json"),
        "completed_checks": sorted(result["checks"]), "failure": result.get("failure"),
        "missing_checks": result.get("missing_checks", []),
        "cleanup_failures": [row for row in result["cleanup"] if not row["confirmed"]]}, indent=2))
    raise SystemExit(0 if result["qualified"] else 1)
