#!/usr/bin/env python3
"""Qualify the explicitly released Docker artifacts against actual owned effects.

This is a controlled qualification workload, not a production deployment or a
benefit measurement. Missing release configuration is an error, never a skip.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.docker_runtime import DockerRuntime, UIDS
from scripts.docker_faults import qualify_lifecycle_faults, _unrelated
from hobnail.client import Client, Connection, canonical_json, parse_json
from hobnail.audit import export_verified
from hobnail.contracts import validate_contract
from hobnail.credentials import CredentialBroker, CredentialProfile, CredentialRequest, PostgresCredentialProvider
from hobnail.effects import implementation_digest as effect_digest
from hobnail.validators import implementation_digest as validator_digest
from hobnail.verifier import verify_candidate

ROLES = ("registrar", "approver", "worker", "verifier", "credential_provider", "adapter", "observer", "auditor")
CONTRACT_ID = "docker-inventory"
INVENTORY_CONTRACT_ID = "docker-source-inventory"
PROFILE = "docker-verifier-runtime"
BOOTSTRAP_TTL = 600
BOOTSTRAP_LIFETIME = 1200
RUNTIME_TTL = 60
RUNTIME_MAX_TTL = 120
RUNTIME_LIFETIME = 180
EXPIRY_TTL = 15
EXPIRY_POLL_SECONDS = 25
PARSER_TIMEOUT_SECONDS = 2
TRUSTED_INPUT = b'{"items":[{"sku":"hinge","quantity":3},{"sku":"bracket","quantity":5}],"period":"qualification-lot-1"}'
GOOD_ARTIFACT = b'{"items":[{"sku":"hinge","quantity":3},{"sku":"bracket","quantity":5}],"period":"qualification-lot-1","summary":"Eight counted parts"}'


class QualificationError(RuntimeError):
    pass


class Recorder:
    """Persist observations before checking them, excluding material and bodies."""

    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        info = self.root.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("qualification evidence requires an owned private directory")
        self.identity = (info.st_dev, info.st_ino)
        self.path = self.root / "docker-qualification.json"
        if os.path.lexists(self.path):
            raise ValueError("qualification receipt already exists")
        self.secrets = []
        self.receipt = {"status": "incomplete", "runtime_stopped": False, "checks": {}, "assertions": {},
                        "events": [], "cleanup_failures": [], "receipt": str(self.path),
                        "retained_root": str(self.root), "scope": "owned Linux arm64 Docker qualification",
                        "assumptions": ["The host supervisor and Docker daemon are trusted.",
                            "Only the locked artifacts, exact policy and reviewed built-in JSON parser are evaluated.",
                            "Seeded fixture controls are separate from the delivered current Docker source/image inventory; neither is held-out benefit evidence.",
                            "Session termination and expiry are checked against the exact held SQL backend, not a sleeping controller.",
                            "Independent registrar, approver, verifier, adapter and observer authority remains required."]}
        self.persist()

    @classmethod
    def unpersisted(cls):
        """Keep failure information available even when no storage can be made."""
        record = cls.__new__(cls)
        record.root = record.path = record.identity = None
        record.secrets = []
        record.receipt = {"status": "failed", "runtime_stopped": False, "checks": {}, "assertions": {},
                          "events": [], "cleanup_failures": [], "receipt": None, "receipt_persisted": False,
                          "retained_root": None, "scope": "Docker qualification failed before evidence storage",
                          "assumptions": []}
        return record

    def safe(self, value):
        if isinstance(value, dict):
            return {self.safe(str(key)): "[withheld]" if key in {"password", "content_hex", "sql", "sql_output"}
                    else self.safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.safe(item) for item in value]
        if isinstance(value, str):
            for secret in self.secrets:
                value = value.replace(secret, "[redacted]")
            return value
        if value is None or type(value) in (bool, int, float):
            return value
        raise TypeError("unsupported evidence value")

    def persist(self):
        if self.root is None:
            raise OSError("qualification evidence storage is unavailable")
        current = self.root.stat()
        if (self.root.resolve(strict=True) != self.root or (current.st_dev, current.st_ino) != self.identity
                or current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) != 0o700):
            raise ValueError("qualification evidence directory changed")
        temporary = self.root / (".qualification-" + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(canonical_json(self.safe(self.receipt)) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)

    def step(self, name, operation, *, summary=lambda result: result):
        if name in self.receipt["checks"]:
            raise ValueError("qualification stages are not retried or overwritten")
        self.receipt["events"].append({"stage": name, "state": "intended"})
        self.persist()
        try:
            result = operation()
        except Exception as error:
            self.receipt["checks"][name] = {"error": type(error).__name__}
            self.receipt["events"].append({"stage": name, "state": "error"})
            try:
                self.persist()
            except Exception as persistence:
                self.receipt["cleanup_failures"].append({"stage": "receipt_persistence", "during": name,
                                                         "type": type(persistence).__name__})
                error.add_note("Failure evidence persistence also failed; the original operation failure is preserved.")
            raise
        self.receipt["checks"][name] = summary(result)
        self.receipt["events"].append({"stage": name, "state": "observed"})
        self.persist()
        return result

    def check(self, name, condition):
        if name in self.receipt["assertions"]:
            raise ValueError("qualification assertions are not replaced")
        self.receipt["assertions"][name] = condition is True
        self.persist()
        if condition is not True:
            raise QualificationError(name)

    def api(self, name, client, operation, payload, *, denial=None):
        response = self.step(name, lambda: client.call(operation, payload))
        self.check(name, response.get("ok") is True if denial is None else
                   response.get("ok") is False and response.get("code") == denial)
        return response.get("data") if denial is None else response


def _lease(lease):
    return {"principal": lease.principal, "role": lease.role, "login": lease.login,
            "lease_ref": lease.lease_ref, "request_id": lease.request_id, "profile": lease.profile,
            "expires_at": lease.expires_at, "credential_id": lease.credential_id}


def _capture(operation):
    try:
        operation()
    except Exception as error:
        return {"error": type(error).__name__}
    return {"returned": True}


def cleanup_step(record, name, operation, *, summary=lambda result: result):
    """Evidence I/O must never prevent a required retirement or shutdown."""
    def persist():
        try:
            record.persist()
        except Exception as error:
            record.receipt["cleanup_failures"].append({"stage": "receipt_persistence", "during": name,
                                                     "type": type(error).__name__})
    record.receipt["events"].append({"stage": name, "state": "cleanup_intended"})
    persist()
    try:
        result = operation()
    except Exception as error:
        record.receipt["checks"][name] = {"error": type(error).__name__}
        record.receipt["events"].append({"stage": name, "state": "cleanup_error"})
        persist()
        raise
    record.receipt["checks"][name] = summary(result)
    record.receipt["events"].append({"stage": name, "state": "cleanup_observed"})
    persist()
    return result


def _plugins(record, approver):
    definitions = {
        "json.equals": ("validator", validator_digest(), "isolated-json", ["read_artifact", "read_inputs"],
                        {"source": "registered inventory source", "pairs": "exact JSON pointer pairs"}, "all exact typed inventory fields match"),
        "json.required_fields": ("validator", validator_digest(), "isolated-json", ["read_artifact"],
                                 {"pointers": "required inventory fields"}, "each named pointer resolves"),
        "file.publish": ("effect", effect_digest(), "local-file", ["write_target"], {}, "attempted exact-byte inventory publication"),
    }
    result = {}
    for plugin, (kind, implementation, backend, capabilities, parameters, semantics) in definitions.items():
        data = record.api("plugin-" + plugin, approver, "plugin.register", {
            "plugin_id": plugin, "version": 1, "kind": kind,
            "manifest": {"implementation": implementation, "input_media_types": ["application/json"],
                         "parameters": parameters, "capabilities": capabilities,
                         "result_semantics": semantics, "execution_backend": backend}})
        result[plugin] = data["plugin_digest"]
    return result


def contract(digests):
    actions = ("accepted", "changed", "stale", "never-admitted", "uncertain")
    document = {"schema_version": 1, "description": "Match separately registered inventory before exact-byte publication",
        "access": {"workers": ["docker-worker"], "verifiers": ["docker-verifier"],
                   "observers": ["docker-observer"], "adapters": {name: ["docker-adapter"] for name in actions}},
        "subject": {"media_type": "application/json", "max_bytes": 1048576},
        "sources": [{"name": "inventory", "registrars": ["docker-registrar"], "require_current": True}],
        "checks": [{"id": "inventory", "plugin": "json.equals", "plugin_digest": digests["json.equals"],
                    "parameters": {"source": "inventory", "pairs": [{"artifact": "/items", "input": "/items"},
                                                                        {"artifact": "/period", "input": "/period"}]},
                    "max_age_seconds": 300},
                   {"id": "shape", "plugin": "json.required_fields", "plugin_digest": digests["json.required_fields"],
                    "parameters": {"pointers": ["/items", "/period", "/summary"]}, "max_age_seconds": 300}],
        "actions": [{"name": name, "plugin": "file.publish", "plugin_digest": digests["file.publish"],
                     "target": name + ".json", "arguments": {}, "max_age_seconds": 300} for name in actions],
        "budgets": {"verification": 8, "effects": 8},
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")}
    validate_contract(document, for_activation=True)
    return document


def bootstrap(runtime, record, known):
    profiles = {"bootstrap-" + role: CredentialProfile("bootstrap-" + role, frozenset({"docker-" + role}), role, BOOTSTRAP_TTL, BOOTSTRAP_LIFETIME)
                for role in ROLES}
    provider = PostgresCredentialProvider(runtime.admin, provider_id="docker-bootstrap-" + runtime.run_id,
                                          profiles=profiles)
    runtime.providers.append(provider)  # Recovery can inventory an issuance whose response is lost.
    known[provider.provider_id] = []
    owner = Client(runtime.admin)
    endpoints = {}
    for request_id, role in enumerate(ROLES, 1):
        def issue(role=role, request_id=request_id):
            lease = provider.issue(CredentialRequest(request_id, "bootstrap-" + role, "docker-" + role, role, BOOTSTRAP_TTL))
            known[provider.provider_id].append(lease)
            record.secrets.append(lease.password.reveal())
            return lease
        lease = record.step("bootstrap-" + role, issue, summary=_lease)
        record.api("bind-" + role, owner, "principal.bind", {
            "login": lease.login, "principal": lease.principal, "role": role,
            "contracts": [] if role == "credential_provider" else [CONTRACT_ID, INVENTORY_CONTRACT_ID],
            "sources": ["inventory", "docker-source"] if role == "registrar" else [],
            "profiles": [PROFILE] if role in {"verifier", "credential_provider", "approver"} else []})
        connection = Connection(host="/run/postgresql", database="hobnail", user=lease.login,
                                password=lease.password.reveal(), sslmode="disable")
        endpoints[role] = runtime.endpoint(role, connection)
    return endpoints


def _policy_denied(value):
    return isinstance(value, dict) and value.get("outcome") in {"policy_denied", "denied"} and value.get("errno") in {1, 13}


def _unavailable(value):
    return (_policy_denied(value) or isinstance(value, dict) and
            ((value.get("outcome") == "absent" and value.get("errno") == 2)
             or (value.get("outcome") == "read_only" and value.get("errno") == 30)))


def kernel_entrypoints(value):
    return (isinstance(value, dict)
            and value.get("socketcall") == {"outcome": "not_in_abi", "architecture": "aarch64"}
            and all(_policy_denied(value.get(name, {})) and value[name].get("errno") == 1
                    for name in ("io_uring_setup", "io_uring_enter", "io_uring_register")))


def role_assertions(role, login, command, response):
    """Evaluate observations; absence and unsupported syscalls are not denials."""
    result = {"response": isinstance(response, dict) and set(response) == {"command", "role", "facts"}
              and response.get("command") == command and response.get("role") == role}
    facts = response.get("facts", {})
    if not result["response"] or not isinstance(facts, dict):
        return {"response": False}
    if command == "self":
        uid = UIDS[role]
        status = facts.get("proc_status", {})
        required_groups = {20000} | ({20001} if role in {"adapter", "observer"} else set())
        groups = facts.get("groups", [])
        result["identity"] = all(facts.get(key) == uid for key in ("uid", "euid", "gid", "egid"))
        result["proc_identity"] = status.get("Uid") == [uid] * 4 and status.get("Gid") == [uid] * 4
        result["groups"] = (isinstance(groups, list) and all(type(group) is int for group in groups)
                            and required_groups <= set(groups) <= required_groups | {uid}
                            and sorted(status.get("Groups", [])) == sorted(groups))
        try:
            result["capabilities"] = all(int(status.get(key, "invalid"), 16) == 0
                for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        except (ValueError, TypeError):
            result["capabilities"] = False
        result["kernel_restrictions"] = status.get("NoNewPrivs") == 1 and status.get("Seccomp") == 2
    elif command == "files":
        result["own_configuration"] = facts.get("own_config") == {"outcome": "readable"}
        # This path is deliberately not mounted. The live holder probe below
        # provides the separate positive control for an actual peer credential.
        result["unmounted_peer_path"] = facts.get("peer_config", {}).get("outcome") == "absent"
        server = facts.get("server_data", {})
        result["server_data_unavailable"] = _policy_denied(server) or server.get("outcome") == "absent"
        if role in {"worker", "observer"}:
            write = facts.get("destination_write", {})
            result["destination_write"] = _policy_denied(write) or write.get("outcome") == "read_only" and write.get("errno") == 30
    elif command == "socket_families":
        for family in ("AF_INET", "AF_INET6", "AF_ALG", "AF_VSOCK"):
            result[family] = _policy_denied(facts.get(family, {}))
        result["unix_positive"] = facts.get("AF_UNIX") == {"outcome": "created"}
        result["database_socket_positive"] = facts.get("postgres_socket") == {"outcome": "connected"}
        result["kernel_entrypoints"] = kernel_entrypoints(facts.get("kernel_entrypoints"))
    elif command == "sql_boundary":
        identity = facts.get("identity_and_privileges", {})
        result["authenticated_identity"] = identity.get("session_user") == login and identity.get("current_user") == login
        result["catalog_permissions"] = (identity.get("audit_select") is False
            and identity.get("audit_update") is False and identity.get("owner_member") is False)
        for name in ("audit_read", "audit_write", "owner_role"):
            result[name] = facts.get(name) == {"outcome": "privilege_denied", "sqlstate": "42501"}
        result["admin_authentication"] = facts.get("admin_with_role_password") == {"outcome": "password_authentication_failed"}
    elif command == "peer":
        result["distinct_pid"] = (type(facts.get("host_pid")) is int and type(facts.get("own_pid")) is int
                                  and facts["host_pid"] > 1 and facts["host_pid"] != facts["own_pid"])
        for name in ("config", "environment", "descriptors", "config_write_open", "config_traversal"):
            value = facts.get(name, {})
            result[name] = _policy_denied(value) or value.get("outcome") == "absent" and value.get("errno") == 2
        value = facts.get("signal_continue", {})
        result["signal_continue"] = _policy_denied(value) or value.get("errno") == 3 and value.get("outcome") == "absent"
    elif command == "host_boundary":
        for name in ("host_read", "host_write_open", "host_traversal", "daemon_socket", "outside_write",
                     "outside_traversal_write", "server_data_traversal", "server_data_write_open"):
            result[name] = _unavailable(facts.get(name, {}))
    else:
        raise ValueError("unsupported role observation")
    return result


def qualify_unknown_principal(runtime, record, known):
    provider = PostgresCredentialProvider(runtime.admin, provider_id="unbound-" + runtime.run_id,
        profiles={"unbound": CredentialProfile("unbound", frozenset({"docker-unbound"}), "worker",
                                                BOOTSTRAP_TTL, BOOTSTRAP_LIFETIME)})
    runtime.providers.append(provider)
    known[provider.provider_id] = []
    def issue():
        lease = provider.issue(CredentialRequest(1, "unbound", "docker-unbound", "worker", BOOTSTRAP_TTL))
        known[provider.provider_id].append(lease)
        record.secrets.append(lease.password.reveal())
        return lease
    lease = record.step("unknown-principal-issued", issue, summary=_lease)
    endpoint = runtime.endpoint("worker", replace(runtime.admin.connection,
        user=lease.login, password=lease.password.reveal()))
    positive = record.step("unknown-principal-sql-positive", lambda: runtime.probe(endpoint, {"command": "sql_boundary"}))
    identity = positive.get("facts", {}).get("identity_and_privileges", {})
    record.check("unknown-principal-authenticated", identity.get("session_user") == lease.login
                 and identity.get("current_user") == lease.login)
    record.api("unknown-principal-api-refused", endpoint.client(), "candidate.get", {"candidate_id": 1},
               denial="UNAUTHENTICATED")


def supervisor_canary(runtime, record):
    path = runtime.root / "supervisor-canary"
    content = b"owned supervisor qualification canary\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    before = path.stat(follow_symlinks=False)
    positive = record.step("supervisor-canary-positive", lambda: {"path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "uid": before.st_uid,
        "mode": stat.S_IMODE(before.st_mode), "device": before.st_dev, "inode": before.st_ino,
        "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns})
    record.check("supervisor-canary-positive", positive["sha256"] == hashlib.sha256(content).hexdigest()
                 and positive["uid"] == os.getuid() and positive["mode"] == 0o600)
    return path, before


def qualify_roles(runtime, record, endpoints, canary):
    for role, endpoint in endpoints.items():
        for command in ("self", "files", "socket_families", "sql_boundary"):
            result = record.step(role + "-" + command, lambda command=command: runtime.probe(endpoint, {"command": command}))
            for name, passed in role_assertions(role, endpoint.connection.user, command, result).items():
                record.check(role + "-" + command + "-" + name, passed)
        command = "host_boundary"
        result = record.step(role + "-" + command, lambda: runtime.probe(endpoint,
                              {"command": command, "host_canary": str(canary)}))
        for name, passed in role_assertions(role, endpoint.connection.user, command, result).items():
            record.check(role + "-" + command + "-" + name, passed)
        wrong = runtime.endpoint(role, replace(endpoint.connection, password=secrets.token_urlsafe(36)))
        result = record.step(role + "-wrong-password", lambda: _capture(lambda: wrong.call("candidate.get", {"candidate_id": 1})))
        record.check(role + "-wrong-password", result == {"error": "PasswordAuthenticationFailed"})
        peer = endpoints["observer" if role != "observer" else "worker"]
        with runtime.hold_endpoint(peer) as held:
            record.step(role + "-peer-holder-ready", lambda: held)
            record.check(role + "-peer-holder-ready", held.get("ready_response") == {"ready": True, "login": peer.connection.user})
            result = record.step(role + "-peer", lambda: runtime.probe(endpoint, {"command": "peer", "host_pid": held["host_pid"]}))
            # The holder positively reads its actual config and authenticates before
            # yielding. Missing proc paths here therefore measure namespace separation.
            record.check(role + "-peer-pid", result.get("facts", {}).get("host_pid") == held["host_pid"])
            for name, passed in role_assertions(role, endpoint.connection.user, "peer", result).items():
                record.check(role + "-peer-" + name, passed)
    refused = record.step("production-probe-refused", lambda: _capture(lambda: endpoints["adapter"].request({"command": "probe"})))
    record.check("production-probe-refused", refused == {"error": "TransportError"})


def qualify_parser(runtime, record, endpoints, canary):
    path = ROOT / "docker/parser_probe.py"
    positive = record.step("parser-destination-positive", lambda: runtime.probe(endpoints["observer"], {"command": "destination"}))
    record.check("parser-destination-positive", positive.get("facts", {}).get("accepted.json", {}).get("outcome") == "present")
    with runtime.hold_endpoint(endpoints["verifier"]) as held:
        record.step("parser-controller-positive", lambda: held)
        record.check("parser-controller-positive", held["ready_response"] ==
                     {"ready": True, "login": endpoints["verifier"].connection.user})
        child = record.step("parser-boundary-process", lambda: runtime.probe_parser(path, canonical_json({
            "command": "parser_boundaries", "host_canary": str(canary), "peer_pid": held["host_pid"]})),
            summary=lambda value: {"returncode": value.returncode, "stdout": value.stdout,
                                  "stderr_bytes": len(value.stderr.encode())})
    record.check("parser-process", child.returncode == 0)
    result = record.step("parser-boundaries", lambda: parse_json(child.stdout))
    record.check("parser-identity-and-positive-controls", result.get("uid") == UIDS["parser"]
                 and result.get("own_implementation_readable") is True and result.get("scratch_positive") is True
                 and result.get("credential_environment_absent") is True)
    record.check("parser-credentials-absent", result.get("configuration", {}).get("outcome") == "absent")
    record.check("parser-source-read-only", result.get("source_write", {}).get("outcome") in {"policy_denied", "read_only"})
    record.check("parser-socket-families", set(result.get("sockets", {})) == {"1", "2", "10", "38", "40"}
                 and all(_policy_denied(value) for value in result["sockets"].values()))
    record.check("parser-kernel-entrypoints", kernel_entrypoints(result.get("kernel_entrypoints")))
    for name in ("host_read", "host_write_open", "host_traversal", "daemon_socket", "outside_write",
                 "outside_traversal_write", "server_data_traversal", "server_data_write_open",
                 "destination", "database_data", "postgres_socket"):
        record.check("parser-" + name, _unavailable(result.get(name, {})))
    for name in ("config", "environment", "descriptors", "config_write_open", "config_traversal"):
        record.check("parser-peer-" + name, _unavailable(result.get("peer", {}).get(name, {})))
    signal = result.get("peer", {}).get("signal_continue", {})
    record.check("parser-peer-signal", _policy_denied(signal) or signal.get("outcome") == "absent" and signal.get("errno") == 3)
    record.check("parser-fork", _policy_denied(result.get("fork", {})))


def qualify_parser_mismatch(runtime, record):
    original = runtime.snapshot / "src/hobnail/_validator_worker.py"
    changed = runtime.root / "changed-validator.py"
    with changed.open("xb") as stream:
        stream.write(original.read_bytes() + b"\n")
    changed.chmod(0o400)
    digest = runtime.ownership["source"]["src/hobnail/_validator_worker.py"]
    payload = canonical_json({"content_hex": GOOD_ARTIFACT.hex(), "plugin_id": "json.required_fields",
                              "parameters": {"pointers": ["/summary"]}, "inputs": {}})
    previous = set(runtime.containers)
    before = record.step("parser-mismatch-results-before", lambda: int(runtime.admin.execute_sql("SELECT count(*) FROM hobnail.results;").strip()))
    # Administrative observation uses an ordinary one-shot role container.
    previous = set(runtime.containers)
    refused = record.step("parser-exact-script-mismatch", lambda: _capture(
        lambda: runtime.run_implementation(changed, digest, payload)))
    record.check("parser-exact-script-mismatch", refused == {"error": "IsolationUnavailable"}
                 and set(runtime.containers) == previous)
    after = record.step("parser-mismatch-results-after", lambda: int(runtime.admin.execute_sql("SELECT count(*) FROM hobnail.results;").strip()))
    record.check("parser-mismatch-no-evidence", before == after)


def qualify_parser_limits(runtime, record):
    """Bind timeout/overflow refusals to the exact observed, removed process."""
    path = ROOT / "docker/parser_probe.py"
    for command in ("sleep_timeout", "stdout_overflow", "stderr_overflow"):
        previous_names = set(runtime.containers)
        previous_ids = {item.get("id") for item in runtime.containers.values()}
        stage = "parser-limit-" + command
        def invoke(command=command):
            try:
                child = runtime.probe_parser(path, canonical_json({"command": command}),
                    timeout=PARSER_TIMEOUT_SECONDS if command == "sleep_timeout" else 10)
            except Exception as error:
                return {"error": type(error).__name__}
            return {"returncode": child.returncode, "stdout_bytes": len(child.stdout.encode()),
                    "stderr_bytes": len(child.stderr.encode()),
                    "diagnostic": child.stderr if child.stderr == "output_limit" else "other"}
        response = record.step(stage, invoke)
        def containers():
            return [{"name": name, "id": runtime.containers[name].get("id"),
                     "role": runtime.containers[name].get("policy", {}).get("role"),
                     "state": runtime.containers[name].get("state"),
                     "cleanup_observed_state": runtime.containers[name].get("cleanup_observed_state"),
                     "exit_code": runtime.containers[name].get("exit_code")}
                    for name in sorted(set(runtime.containers) - previous_names)]
        observed = record.step(stage + "-containers", containers)
        record.check(stage + "-one-container", len(observed) == 1)
        container = observed[0]
        record.check(stage + "-removed", isinstance(container["id"], str)
                     and re.fullmatch(r"[0-9a-f]{64}", container["id"]) is not None
                     and container["id"] not in previous_ids and container["role"] == "parser"
                     and container["state"] == "removed" and type(container["exit_code"]) is int)
        if command == "sleep_timeout":
            before = container.get("cleanup_observed_state") or {}
            record.check(stage + "-started-and-stopped", before.get("running") is True
                         and type(before.get("pid")) is int and before["pid"] > 0 and container["exit_code"] != 0)
            record.check(stage + "-refused", response == {"error": "TransportTimeout"})
        else:
            record.check(stage + "-refused", type(response.get("returncode")) is int
                         and response["returncode"] != 0 and response.get("diagnostic") == "output_limit")


def runtime_credential(runtime, record, endpoints, known):
    clients = {role: endpoint.client() for role, endpoint in endpoints.items()}
    record.api("runtime-credential-profile", Client(runtime.admin), "credential.profile", {
        "profile": PROFILE, "provider": "docker-credential_provider", "principals": ["docker-verifier"],
        "role": "verifier", "max_ttl_seconds": RUNTIME_MAX_TTL, "max_lifetime_seconds": RUNTIME_LIFETIME, "renewable": True,
        "capabilities": ["dynamic_postgres", "renewal", "revocation", "active_session_termination"]})
    record.api("worker-credential-scope-denied", clients["worker"], "credential.request", {
        "profile": PROFILE, "ttl_seconds": RUNTIME_TTL, "idempotency_key": "forbidden-verifier-profile"}, denial="CREDENTIAL_SCOPE")
    request = record.api("runtime-credential-request", clients["verifier"], "credential.request", {
        "profile": PROFILE, "ttl_seconds": RUNTIME_TTL, "idempotency_key": "owned-runtime-verifier"})
    provider = PostgresCredentialProvider(runtime.admin, provider_id="docker-credential_provider", profiles={
        PROFILE: CredentialProfile(PROFILE, frozenset({"docker-verifier"}), "verifier", RUNTIME_MAX_TTL, RUNTIME_LIFETIME, True)})
    runtime.providers.append(provider)
    known[provider.provider_id] = []
    broker = CredentialBroker(clients["credential_provider"], provider)
    def issue():
        lease = broker.issue_request(request["request_id"])
        known[provider.provider_id].append(lease)
        record.secrets.append(lease.password.reveal())
        return lease
    lease = record.step("runtime-credential-issued", issue, summary=_lease)
    endpoint = runtime.endpoint("verifier", replace(endpoints["verifier"].connection,
                                user=lease.login, password=lease.password.reveal()))
    endpoints["verifier"] = endpoint
    observed = record.step("runtime-credential-authentication", lambda: runtime.probe(endpoint, {"command": "sql_boundary"}))
    for name, passed in role_assertions("verifier", lease.login, "sql_boundary", observed).items():
        record.check("runtime-credential-login-" + name, passed)
    record.api("runtime-credential-renew-request", endpoint.client(), "credential.renew_requested", {
        "credential_id": lease.credential_id, "ttl_seconds": RUNTIME_MAX_TTL})
    renewed = record.step("runtime-credential-renewed", lambda: broker.renew_requested(lease.credential_id), summary=_lease)
    record.check("runtime-credential-renewed", datetime.fromisoformat(renewed.expires_at.replace("Z", "+00:00")) >
                 datetime.fromisoformat(lease.expires_at.replace("Z", "+00:00")))
    return broker, lease


def backend_state(admin, login, backend_pid, *, timeout=30):
    if not isinstance(login, str) or not re.fullmatch(r"hn_[0-9a-f]{32}", login) or type(backend_pid) is not int or backend_pid < 1:
        raise ValueError("held backend must have an exact owned provider identity")
    # Login and PID come from the owned issuer/actual psql readiness, never SQL
    # supplied by a candidate. No password or credential verifier is selected.
    sql = f"""SELECT json_build_object(
      'login_enabled', r.rolcanlogin, 'unexpired', r.rolvaliduntil > clock_timestamp(),
      'active_sessions', (SELECT count(*) FROM pg_stat_activity WHERE usename=r.rolname),
      'target_waiting', EXISTS(SELECT FROM pg_stat_activity WHERE usename=r.rolname
         AND pid={backend_pid} AND state='active' AND wait_event='PgSleep'
         AND btrim(query)='SELECT pg_sleep(120);'))
      FROM pg_roles r WHERE r.rolname='{login}';"""
    result = parse_json(admin.execute_sql(sql, sensitive=True, timeout=timeout).strip())
    if (not isinstance(result, dict) or set(result) != {"login_enabled", "unexpired", "active_sessions", "target_waiting"}
            or any(type(result[key]) is not bool for key in ("login_enabled", "unexpired", "target_waiting"))
            or type(result["active_sessions"]) is not int):
        raise QualificationError("held_backend_observation_invalid")
    return result


def wait_backend(runtime, record, login, backend_pid, stage, predicate, *, timeout):
    started = time.monotonic()
    deadline = started + timeout
    number = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            record.check(stage, False)
        result = record.step(stage + "-" + str(number),
                             lambda: backend_state(runtime.admin, login, backend_pid, timeout=remaining))
        completed = time.monotonic()
        record.step(stage + "-timing-" + str(number), lambda: {"elapsed_seconds": completed - started,
                                                               "within_deadline": completed <= deadline})
        if predicate(result) or completed >= deadline:
            record.check(stage, predicate(result) and completed <= deadline)
            return result
        number += 1
        time.sleep(0.1)


def retire_held_session(runtime, record, endpoint, requester, broker, lease, candidate_id, *, prefix, expire=False):
    started = time.monotonic()
    with runtime.hold_sql_endpoint(endpoint) as held:
        ready = record.step(prefix + "-held-ready", lambda: {key: held[key] for key in ("host_pid", "container_id", "ready_response")})
        details = ready.get("ready_response", {})
        record.check(prefix + "-held-ready", details.get("ready") is True and details.get("login") == lease.login
                     and type(details.get("backend_pid")) is int and details["backend_pid"] > 0
                     and type(details.get("psql_pid")) is int and details["psql_pid"] > 0)
        backend_pid = details["backend_pid"]
        wait_backend(runtime, record, lease.login, backend_pid, prefix + "-held-active",
                     lambda value: value["target_waiting"] and value["login_enabled"] and value["unexpired"]
                     and value["active_sessions"] == 1, timeout=5)
        if expire:
            wait_backend(runtime, record, lease.login, backend_pid, prefix + "-expired-while-held",
                         lambda value: value["target_waiting"] and value["login_enabled"] and not value["unexpired"]
                         and value["active_sessions"] == 1, timeout=EXPIRY_POLL_SECONDS)
            refused = record.step(prefix + "-expired-new-login", lambda: _capture(lambda: endpoint.call("candidate.get", {"candidate_id": candidate_id})))
            record.check(prefix + "-expired-new-login", refused == {"error": "PasswordAuthenticationFailed"})
            still_held = record.step(prefix + "-existing-session-remains", lambda: backend_state(runtime.admin, lease.login, backend_pid))
            record.check(prefix + "-existing-session-remains", still_held["target_waiting"] and still_held["active_sessions"] == 1)
        record.api(prefix + "-revoke-request", requester, "credential.revoke_requested", {"credential_id": lease.credential_id})
        observed = record.step(prefix + "-revoked", lambda: broker.revoke_requested(lease.credential_id), summary=asdict)
        record.check(prefix + "-revoked", observed.result == "confirmed" and observed.login_enabled is False and observed.active_sessions == 0)
        terminated = record.step(prefix + "-held-termination", held["wait_terminated"])
        elapsed = record.step(prefix + "-held-elapsed", lambda: time.monotonic() - started)
        record.check(prefix + "-held-termination", terminated.get("terminated") is True
                     and type(terminated.get("exit_code")) is int and terminated["exit_code"] != 0 and elapsed < 55)
        final = record.step(prefix + "-backend-final", lambda: backend_state(runtime.admin, lease.login, backend_pid))
        record.check(prefix + "-backend-final", final["login_enabled"] is False and final["active_sessions"] == 0
                     and final["target_waiting"] is False)
    refused = record.step(prefix + "-new-login-refused", lambda: _capture(lambda: endpoint.call("candidate.get", {"candidate_id": candidate_id})))
    record.check(prefix + "-new-login-refused", refused.get("error") in {"TransportError", "PasswordAuthenticationFailed"})


def qualify_expiry(runtime, record, endpoints, broker, known, candidate_id):
    requester = endpoints["verifier"].client()
    request = record.api("expiry-credential-request", requester, "credential.request", {
        "profile": PROFILE, "ttl_seconds": EXPIRY_TTL, "idempotency_key": "owned-expiry-verifier"})
    def issue():
        lease = broker.issue_request(request["request_id"])
        known[broker.provider.provider_id].append(lease)
        record.secrets.append(lease.password.reveal())
        return lease
    lease = record.step("expiry-credential-issued", issue, summary=_lease)
    endpoint = runtime.endpoint("verifier", replace(endpoints["verifier"].connection, user=lease.login,
                                password=lease.password.reveal()))
    retire_held_session(runtime, record, endpoint, requester, broker, lease, candidate_id,
                        prefix="expiry-credential", expire=True)


def credential_clock(runtime, login):
    if not isinstance(login, str) or re.fullmatch(r"hn_[0-9a-f]{32}", login) is None:
        raise ValueError("clock observation requires an exact owned login")
    sql = ("SELECT json_build_object('observed_at',clock_timestamp(),'expires_at',rolvaliduntil,"
           "'login_enabled',rolcanlogin,'unexpired',rolvaliduntil>clock_timestamp()) "
           "FROM pg_roles WHERE rolname='" + login + "';")
    value = parse_json(runtime.admin.execute_sql(sql, sensitive=True).strip())
    if (not isinstance(value, dict) or set(value) != {"observed_at", "expires_at", "login_enabled", "unexpired"}
            or any(type(value[key]) is not bool for key in ("login_enabled", "unexpired"))):
        raise QualificationError("credential_clock_invalid")
    for key in ("observed_at", "expires_at"):
        if datetime.fromisoformat(value[key]).tzinfo is None:
            raise QualificationError("credential_clock_not_utc")
    return value


def _wait_real_elapsed(started, minimum):
    while (remaining := started + minimum - time.monotonic()) > 0:
        time.sleep(min(remaining, 1))
    return {"elapsed_seconds": time.monotonic() - started, "required_seconds": minimum}


def qualify_lifetime(runtime, record, requester_endpoint, broker, known, candidate_id):
    """Use the real database and monotonic clocks; never shorten the 180s cap."""
    requester = requester_endpoint.client()
    request = record.api("lifetime-credential-request", requester, "credential.request", {
        "profile": PROFILE, "ttl_seconds": RUNTIME_MAX_TTL, "idempotency_key": "owned-lifetime-verifier"})
    def issue():
        lease = broker.issue_request(request["request_id"])
        known[broker.provider.provider_id].append(lease)
        record.secrets.append(lease.password.reveal())
        return lease
    lease = record.step("lifetime-credential-issued", issue, summary=_lease)
    started = time.monotonic()
    endpoint = runtime.endpoint("verifier", replace(requester_endpoint.connection, user=lease.login,
                                password=lease.password.reveal()))
    record.api("lifetime-credential-initial-login", endpoint.client(), "candidate.get", {"candidate_id": candidate_id})
    waited = record.step("lifetime-credential-scope-wait", lambda: _wait_real_elapsed(
        started, RUNTIME_LIFETIME - RUNTIME_MAX_TTL + 2))
    record.check("lifetime-credential-scope-real-time", waited["elapsed_seconds"] >= RUNTIME_LIFETIME - RUNTIME_MAX_TTL + 2)
    before = record.step("lifetime-credential-before-refusal", lambda: credential_clock(runtime, lease.login))
    record.check("lifetime-credential-active-at-refusal", before["login_enabled"] and before["unexpired"])
    record.api("lifetime-credential-kernel-refused", requester, "credential.renew_requested", {
        "credential_id": lease.credential_id, "ttl_seconds": RUNTIME_MAX_TTL}, denial="CREDENTIAL_SCOPE")
    refused = record.step("lifetime-credential-provider-refused", lambda:
        _capture(lambda: broker.provider.renew(lease.lease_ref, RUNTIME_MAX_TTL)))
    record.check("lifetime-credential-provider-refused", refused == {"error": "CredentialError"})
    after = record.step("lifetime-credential-after-refusal", lambda: credential_clock(runtime, lease.login))
    record.check("lifetime-credential-refusal-preserved-expiry", before["expires_at"] == after["expires_at"]
                 and after["login_enabled"] and after["unexpired"])
    # Extend close to the unchanged cap using an ordinary authorized TTL. Both
    # independent authorities still evaluate their actual current clock.
    deadline = datetime.fromisoformat(lease.created_at.replace("Z", "+00:00")) + timedelta(seconds=RUNTIME_LIFETIME)
    record.step("lifetime-credential-limit", lambda: {"provider_created_at": lease.created_at,
        "max_lifetime_seconds": RUNTIME_LIFETIME, "provider_deadline": deadline.isoformat(),
        "database_observed_at": after["observed_at"]})
    remaining = int((deadline - datetime.fromisoformat(after["observed_at"])).total_seconds()) - 5
    record.check("lifetime-credential-bounded-final-renewal", 1 <= remaining <= RUNTIME_MAX_TTL)
    record.api("lifetime-credential-final-renew-request", requester, "credential.renew_requested", {
        "credential_id": lease.credential_id, "ttl_seconds": remaining})
    renewed = record.step("lifetime-credential-final-renewal", lambda: broker.renew_requested(lease.credential_id), summary=_lease)
    record.check("lifetime-credential-final-expiry-bounded", datetime.fromisoformat(lease.expires_at.replace("Z", "+00:00"))
                 < datetime.fromisoformat(renewed.expires_at.replace("Z", "+00:00")) <= deadline)
    record.api("lifetime-credential-renewed-login", endpoint.client(), "candidate.get", {"candidate_id": candidate_id})
    waited = record.step("lifetime-credential-exhaustion-wait", lambda: _wait_real_elapsed(started, RUNTIME_LIFETIME + 1))
    state = record.step("lifetime-credential-exhausted", lambda: credential_clock(runtime, lease.login))
    record.check("lifetime-credential-real-exhaustion", waited["elapsed_seconds"] >= RUNTIME_LIFETIME
                 and datetime.fromisoformat(state["observed_at"]) >= deadline and not state["unexpired"])
    refused = record.step("lifetime-credential-expired-login", lambda:
        _capture(lambda: endpoint.call("candidate.get", {"candidate_id": candidate_id})))
    record.check("lifetime-credential-expired-login", refused == {"error": "PasswordAuthenticationFailed"})
    record.api("lifetime-credential-exhausted-renewal", requester, "credential.renew_requested", {
        "credential_id": lease.credential_id, "ttl_seconds": 1}, denial="CREDENTIAL_EXPIRED")
    record.api("lifetime-credential-revoke-request", requester, "credential.revoke_requested", {"credential_id": lease.credential_id})
    revoked = record.step("lifetime-credential-revoked", lambda: broker.revoke_requested(lease.credential_id), summary=asdict)
    record.check("lifetime-credential-revoked", revoked.result == "confirmed" and revoked.login_enabled is False and revoked.active_sessions == 0)


def qualify_uncertain(runtime, record, endpoints, candidate_id, artifact):
    """Seed a lost adapter reply, then reconcile the same actual consequence."""
    worker = endpoints["worker"].client()
    effect = record.api("uncertain-effect", worker, "effect.request", {
        "candidate_id": candidate_id, "action": "uncertain", "args": {},
        "idempotency_key": "uncertain"})["effect_id"]
    before = record.api("uncertain-budget-before", worker, "budget.get", {"contract_id": CONTRACT_ID})
    # Deliberately do not inspect the response: the controller lost it. The
    # subsequent independent API/file observations establish what happened.
    record.step("uncertain-dispatch-response-discarded", lambda: endpoints["adapter"].dispatch(effect),
                summary=lambda _: {"effect_id": effect, "seeded_fault": "adapter_response_discarded"})
    pending = record.api("uncertain-pending", worker, "effect.get", {"effect_id": effect})
    record.check("uncertain-pending-state", pending.get("state") in {"dispatched", "attempted", "uncertain", "reconcile"}
                 and pending.get("dispatched_at") is not None
                 and not any(row.get("kind") == "observation" for row in pending.get("reports", [])))
    destination_before = record.step("uncertain-destination-before", lambda:
        runtime.probe(endpoints["observer"], {"command": "destination"}))["facts"]["uncertain.json"]
    record.check("uncertain-actual-consequence", destination_before.get("sha256") == hashlib.sha256(artifact).hexdigest()
                 and destination_before.get("size") == len(artifact)
                 and all(type(destination_before.get(key)) is int for key in ("device", "inode", "mtime_ns", "ctime_ns")))
    retry = record.step("uncertain-redispatch-denied", lambda: endpoints["adapter"].dispatch(effect))
    record.check("uncertain-redispatch-denied", retry.get("ok") is False and retry.get("code") == "RECONCILIATION_REQUIRED")
    observed = record.step("uncertain-reconciled", lambda: endpoints["observer"].observe(effect))
    record.check("uncertain-reconciled", observed.get("ok") is True and observed.get("data", {}).get("state") == "complete")
    final = record.api("uncertain-final", worker, "effect.get", {"effect_id": effect})
    record.check("uncertain-same-dispatch", final.get("effect_id") == effect and final.get("state") == "complete"
                 and final.get("dispatched_at") == pending["dispatched_at"]
                 and sum(row.get("kind") == "dispatch" for row in final.get("reports", [])) == 1)
    destination_after = record.step("uncertain-destination-after", lambda:
        runtime.probe(endpoints["observer"], {"command": "destination"}))["facts"]["uncertain.json"]
    after = record.api("uncertain-budget-after", worker, "budget.get", {"contract_id": CONTRACT_ID})
    record.check("uncertain-no-duplicate-consequence", destination_after == destination_before)
    record.check("uncertain-budget-preserved", after == before and before["budgets"]["effects"]["used"] > 0)


def _inventory_path(path):
    return (path.startswith("src/hobnail/") and path.endswith(".py")
            or re.fullmatch(r"migrations/[0-9]{3}_[^/]+[.]sql", path) is not None
            or path in {"scripts/install.py", "scripts/docker_runtime.py", "scripts/qualified_docker.py",
                        "scripts/docker_faults.py", "docker/images.lock.json", "docker/role.py", "docker/database.py",
                        "docker/psql_owned.py", "docker/probe.py", "docker/parser_probe.py"}
            or re.fullmatch(r"docker/seccomp-[a-z]+-arm64[.]json", path) is not None)


def _git(*arguments):
    result = subprocess.run(["git", "--no-replace-objects", *arguments], cwd=ROOT,
                            env={key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
                            capture_output=True, timeout=30, check=False)
    if result.returncode:
        raise QualificationError("source_git_read_failed")
    return result.stdout


def registered_source_inventory():
    """Registrar facts come from Git blobs, never the worker's filesystem list."""
    commit = _git("rev-parse", "HEAD").decode("ascii").strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise QualificationError("source_commit_invalid")
    files = []
    lock = None
    for row in _git("ls-tree", "-r", "--full-tree", "-z", commit).split(b"\0"):
        if not row:
            continue
        header, encoded_path = row.split(b"\t", 1)
        path = encoded_path.decode("utf-8")
        if not _inventory_path(path):
            continue
        mode, kind, object_id = header.decode("ascii").split()
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise QualificationError("source_git_nonregular_member")
        content = _git("cat-file", "blob", object_id)
        files.append({"path": path, "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)})
        if path == "docker/images.lock.json":
            lock = parse_json(content.decode("utf-8"))
    if lock is None or not files:
        raise QualificationError("source_inventory_incomplete")
    return {"schema": "hobnail-docker-source-inventory-v1", "source_commit": commit,
            "files": sorted(files, key=lambda item: item["path"]),
            "images": sorted(({key: item[key] for key in ("flavor", "sha256", "size")}
                              for item in lock["rootfs"]), key=lambda item: item["flavor"])}


def produced_source_inventory(runtime, commit):
    """Worker facts enumerate retained snapshot bytes and actual archive bytes."""
    files = []
    for path in sorted(runtime.snapshot.rglob("*")):
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise QualificationError("source_snapshot_alias")
        if path.is_dir():
            continue
        if not path.is_file():
            raise QualificationError("source_snapshot_nonregular_member")
        content = path.read_bytes()
        files.append({"path": path.relative_to(runtime.snapshot).as_posix(),
                      "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)})
    images = []
    for flavor, path in sorted(runtime.archives.items()):
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise QualificationError("source_archive_nonregular")
            while block := stream.read(1024 * 1024):
                digest.update(block)
                size += len(block)
            after = os.fstat(stream.fileno())
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(path.stat()) or size != before.st_size:
            raise QualificationError("source_archive_changed")
        images.append({"flavor": flavor, "sha256": digest.hexdigest(), "size": size})
    return {"schema": "hobnail-docker-source-inventory-v1", "source_commit": commit, "files": files, "images": images}


def inventory_contract(digests):
    document = {"schema_version": 1, "description": "Deliver the actual Docker source and image inventory for release review",
        "access": {"workers": ["docker-worker"], "verifiers": ["docker-verifier"], "observers": ["docker-observer"],
                   "adapters": {"publish": ["docker-adapter"]}},
        "subject": {"media_type": "application/json", "max_bytes": 1048576},
        "sources": [{"name": "docker-source", "registrars": ["docker-registrar"], "require_current": True}],
        "checks": [{"id": "exact-inventory", "plugin": "json.equals", "plugin_digest": digests["json.equals"],
                    "parameters": {"source": "docker-source", "pairs": [{"artifact": "", "input": ""}]}, "max_age_seconds": 300}],
        "actions": [{"name": "publish", "plugin": "file.publish", "plugin_digest": digests["file.publish"],
                     "target": "docker-source-inventory.json", "arguments": {}, "max_age_seconds": 300}],
        "budgets": {"verification": 1, "effects": 1},
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")}
    validate_contract(document, for_activation=True)
    return document


def deliver_source_inventory(runtime, record, endpoints, digests):
    expected = record.step("source-inventory-registrar", registered_source_inventory)
    artifact = canonical_json(record.step("source-inventory-worker", lambda:
        produced_source_inventory(runtime, expected["source_commit"]))).encode()
    clients = {role: endpoint.client() for role, endpoint in endpoints.items()}
    record.api("source-inventory-proposed", clients["worker"], "contract.propose", {
        "contract_id": INVENTORY_CONTRACT_ID, "version": 1, "document": inventory_contract(digests)})
    record.api("source-inventory-activated", clients["approver"], "contract.activate", {
        "contract_id": INVENTORY_CONTRACT_ID, "version": 1, "expected_active_version": None})
    source = record.api("source-inventory-registered", clients["registrar"], "input.put", {
        "contract_id": INVENTORY_CONTRACT_ID, "source": "docker-source", "version": 1,
        "content_hex": canonical_json(expected).encode().hex(), "media_type": "application/json", "expected_current": None})
    blob = record.api("source-inventory-artifact", clients["worker"], "artifact.put", {
        "content_hex": artifact.hex(), "media_type": "application/json"})
    candidate = record.api("source-inventory-candidate", clients["worker"], "candidate.submit", {
        "contract_id": INVENTORY_CONTRACT_ID, "artifact_id": blob["artifact_id"],
        "inputs": {"docker-source": source["snapshot_id"]}, "idempotency_key": "source-inventory"})["candidate_id"]
    accepted = record.step("source-inventory-accepted", lambda: verify_candidate(clients["verifier"], candidate,
        implementation_runner=runtime.run_implementation))
    record.check("source-inventory-accepted", accepted.get("ok") is True and accepted.get("data", {}).get("accepted") is True)
    effect = record.api("source-inventory-effect", clients["worker"], "effect.request", {
        "candidate_id": candidate, "action": "publish", "args": {}, "idempotency_key": "source-inventory"})["effect_id"]
    dispatched = record.step("source-inventory-dispatch", lambda: endpoints["adapter"].dispatch(effect))
    record.check("source-inventory-dispatch", dispatched.get("ok") is True and dispatched.get("data", {}).get("state") == "attempted")
    observed = record.step("source-inventory-observation", lambda: endpoints["observer"].observe(effect))
    record.check("source-inventory-observation", observed.get("ok") is True and observed.get("data", {}).get("state") == "complete")
    actual = record.step("source-inventory-consumer-read", lambda: runtime.probe(endpoints["observer"], {"command": "source_inventory"}))["facts"]
    content = bytes.fromhex(actual["content_hex"])
    record.check("source-inventory-delivered-bytes", content == artifact
                 and actual.get("sha256") == hashlib.sha256(content).hexdigest() and actual.get("size") == len(content))
    path = record.root / "observed-docker-source-inventory.json"
    with path.open("xb") as stream:
        stream.write(content)
    path.chmod(0o600)
    record.step("source-inventory-delivery", lambda: {"path": str(path), "sha256": hashlib.sha256(content).hexdigest(),
        "bytes": len(content), "effect_id": effect, "source_commit": expected["source_commit"],
        "consumer": "release readiness review; later report consumption requires its own receipt"})
    return effect


def verify_audit(record, auditor, completed_effect):
    pages = []
    class Export:
        def require(self, operation, payload):
            response = auditor.require(operation, payload)
            pages.append(response["data"])
            return response
    verified = record.step("audit-verified", lambda: export_verified(Export()), summary=lambda value: {
        **asdict(value), "externally_anchored": value.externally_anchored})
    # The display event duplicates canonical bytes and is redacted again by
    # Recorder. Keep the original hashed text instead; replay reconstructs its
    # display event with parse_json before passing each page to verify_page.
    proof = [{"head": page["head"], "events": [{key: row[key] for key in
        ("seq", "event_canonical", "previous_hash", "hash")} for row in page["events"]]} for page in pages]
    record.check("audit-proof-retainable", record.safe(proof) == proof)
    record.step("audit-canonical-proof", lambda: proof)
    events = [row["event"] for page in pages for row in page["events"] if row["seq"] <= verified.checkpoint.sequence]
    record.check("audit-chain-complete", verified.verified_events > 0 and verified.start.sequence == 0
                 and verified.checkpoint.sequence == verified.verified_events)
    record.check("audit-delivered-source-inventory", any(event.get("operation") == "effect.observe"
        and event.get("request", {}).get("effect_id") == completed_effect
        and event.get("response", {}).get("data", {}).get("state") == "complete" for event in events))


def workflow(runtime, record, endpoints, trusted_input, artifact):
    clients = {role: endpoint.client() for role, endpoint in endpoints.items()}
    digests = _plugins(record, clients["approver"])
    document = contract(digests)
    record.api("contract-proposed", clients["worker"], "contract.propose", {"contract_id": CONTRACT_ID, "version": 1, "document": document})
    record.api("worker-activation-denied", clients["worker"], "contract.activate", {"contract_id": CONTRACT_ID, "version": 1, "expected_active_version": None}, denial="FORBIDDEN")
    record.api("contract-activated", clients["approver"], "contract.activate", {"contract_id": CONTRACT_ID, "version": 1, "expected_active_version": None})
    source = record.api("input-registered", clients["registrar"], "input.put", {"contract_id": CONTRACT_ID, "source": "inventory",
        "version": 1, "content_hex": trusted_input.hex(), "media_type": "application/json", "expected_current": None})
    def candidate(name, content):
        blob = record.api(name + "-artifact", clients["worker"], "artifact.put", {"content_hex": content.hex(), "media_type": "application/json"})
        return record.api(name + "-candidate", clients["worker"], "candidate.submit", {"contract_id": CONTRACT_ID,
            "artifact_id": blob["artifact_id"], "inputs": {"inventory": source["snapshot_id"]}, "idempotency_key": name})["candidate_id"]
    def request(name, identifier):
        return record.api(name + "-effect", clients["worker"], "effect.request", {"candidate_id": identifier,
            "action": name, "args": {}, "idempotency_key": name})["effect_id"]
    identifier = candidate("accepted", artifact)
    record.api("worker-verification-denied", clients["worker"], "verification.claim", {"candidate_id": identifier, "lease_seconds": 60}, denial="FORBIDDEN")
    record.api("nonadmitted-effect-denied", clients["worker"], "effect.request", {"candidate_id": identifier,
        "action": "never-admitted", "args": {}, "idempotency_key": "never-admitted"}, denial="MISSING_CHECKS")
    accepted = record.step("candidate-accepted", lambda: verify_candidate(clients["verifier"], identifier,
                                                                          implementation_runner=runtime.run_implementation))
    record.check("candidate-accepted", accepted.get("ok") is True and accepted.get("data", {}).get("accepted") is True)
    effect = request("accepted", identifier)
    claim_before = record.api("worker-adapter-effect-before", clients["worker"], "effect.get", {"effect_id": effect})
    budget_before = record.api("worker-adapter-budget-before", clients["worker"], "budget.get", {"contract_id": CONTRACT_ID})
    record.api("worker-adapter-claim-denied", clients["worker"], "effect.claim",
               {"effect_id": effect, "lease_seconds": 60}, denial="FORBIDDEN")
    claim_after = record.api("worker-adapter-effect-after", clients["worker"], "effect.get", {"effect_id": effect})
    budget_after = record.api("worker-adapter-budget-after", clients["worker"], "budget.get", {"contract_id": CONTRACT_ID})
    record.check("worker-adapter-denial-preserves-state", claim_before == claim_after and budget_before == budget_after)
    dispatched = record.step("accepted-dispatch", lambda: endpoints["adapter"].dispatch(effect))
    record.check("accepted-dispatch", dispatched.get("ok") is True and dispatched.get("data", {}).get("state") == "attempted")
    observed = record.step("accepted-observation", lambda: endpoints["observer"].observe(effect))
    record.check("accepted-observation", observed.get("ok") is True and observed.get("data", {}).get("state") == "complete")
    qualify_uncertain(runtime, record, endpoints, identifier, artifact)
    changed = request("changed", identifier)
    dispatched = record.step("changed-dispatch", lambda: endpoints["adapter"].dispatch(changed))
    record.check("changed-dispatch", dispatched.get("ok") is True and dispatched.get("data", {}).get("state") == "attempted")
    alteration = record.step("changed-protected-consequence", lambda: runtime.probe(endpoints["adapter"], {"command": "change_accepted"}))
    expected_changed = hashlib.sha256(b"qualification-changed-by-protected-adapter").hexdigest()
    record.check("changed-protected-consequence", alteration.get("facts", {}).get("outcome") == "changed"
                 and alteration.get("facts", {}).get("sha256") == expected_changed)
    observed = record.step("changed-observation", lambda: endpoints["observer"].observe(changed))
    record.check("changed-observation", observed.get("ok") is True and observed.get("data", {}).get("state") == "control_failure"
                 and observed.get("data", {}).get("control_failure") is True)
    invalid = parse_json(artifact.decode("utf-8"))
    invalid["items"] = [{"sku": "qualification-wrong-item", "quantity": 999}]
    bad_id = candidate("wrong-content", canonical_json(invalid).encode())
    rejected = record.step("wrong-content-verification", lambda: verify_candidate(clients["verifier"], bad_id,
                                                                                  implementation_runner=runtime.run_implementation))
    record.check("wrong-content-verification", rejected.get("ok") is False and rejected.get("code") == "CHECK_FAILED")
    record.api("wrong-content-effect-denied", clients["worker"], "effect.request", {"candidate_id": bad_id,
        "action": "never-admitted", "args": {}, "idempotency_key": "wrong-content"}, denial="CHECK_FAILED")
    stale = request("stale", identifier)
    replacement = parse_json(trusted_input.decode("utf-8"))
    replacement["period"] = str(replacement["period"]) + "-advanced"
    record.api("input-advanced", clients["registrar"], "input.put", {"contract_id": CONTRACT_ID, "source": "inventory",
        "version": 2, "content_hex": canonical_json(replacement).encode().hex(), "media_type": "application/json",
        "expected_current": source["snapshot_id"]})
    refused = record.step("stale-dispatch", lambda: endpoints["adapter"].dispatch(stale))
    record.check("stale-dispatch", refused.get("ok") is False and refused.get("code") == "INPUT_STALE")
    record.api("stale-acceptance-denied", clients["worker"], "candidate.accept", {"candidate_id": identifier}, denial="INPUT_STALE")
    destination = record.step("destination-final", lambda: runtime.probe(endpoints["observer"], {"command": "destination"}))
    files = destination.get("facts", {})
    for name in ("stale.json", "never-admitted.json", "qualification-worker-denied"):
        record.check("destination-absent-" + name, files.get(name, {}).get("outcome") == "absent"
                     and files.get(name, {}).get("errno") == 2)
    for name, digest, size in (("accepted.json", hashlib.sha256(artifact).hexdigest(), len(artifact)),
                               ("changed.json", expected_changed, len(b"qualification-changed-by-protected-adapter"))):
        expected = {"outcome": "present", "sha256": digest, "size": size, "uid": 10006, "gid": 20001, "mode": "0640"}
        record.check("destination-exact-" + name, all(files.get(name, {}).get(key) == value for key, value in expected.items()))
    return identifier, digests


def retire_owned(runtime, record, known):
    rows = []
    for number, provider in enumerate(runtime.providers):
        try:
            leases = cleanup_step(record, f"cleanup-inventory-{number}", provider.inventory, summary=lambda result: [_lease(item) for item in result])
        except Exception as error:
            record.receipt["cleanup_failures"].append({"stage": "credential_inventory", "provider": provider.provider_id, "type": type(error).__name__})
            leases = known.get(provider.provider_id, [])
        recorded = {lease.lease_ref: lease for lease in leases}
        missing = [lease for lease in known.get(provider.provider_id, []) if lease.lease_ref not in recorded]
        if missing:
            record.receipt["cleanup_failures"].append({"stage": "credential_inventory_incomplete",
                "provider": provider.provider_id, "missing_logins": [lease.login for lease in missing]})
            recorded.update((lease.lease_ref, lease) for lease in missing)
        leases = list(recorded.values())
        for lease in leases:
            row = {"principal": lease.principal, "login": lease.login, "confirmed": False}
            try:
                observed = cleanup_step(record, "cleanup-" + lease.login, lambda lease=lease: provider.revoke(lease.lease_ref), summary=asdict)
                row.update(confirmed=observed.result == "confirmed" and observed.login_enabled is False and observed.active_sessions == 0,
                           result=observed.result, login_enabled=observed.login_enabled, active_sessions=observed.active_sessions)
            except Exception as error:
                row["error"] = type(error).__name__
            rows.append(row)
            if not row["confirmed"]:
                record.receipt["cleanup_failures"].append({"stage": "credential_retirement", **row})
            record.receipt["checks"]["credential_retirement"] = rows
            try:
                record.persist()
            except Exception as error:
                record.receipt["cleanup_failures"].append({"stage": "receipt_persistence", "during": "credential_retirement",
                                                         "type": type(error).__name__})
    record.receipt["checks"]["all_runtime_credentials_revoked"] = bool(rows) and all(row["confirmed"] for row in rows) and not record.receipt["cleanup_failures"]
    try:
        record.persist()
    except Exception as error:
        record.receipt["cleanup_failures"].append({"stage": "receipt_persistence", "during": "credential_retirement",
                                                 "type": type(error).__name__})


def administrator_retired(value):
    return (isinstance(value, dict) and set(value) == {"result", "login_enabled", "other_client_sessions"}
            and value["result"] == "confirmed" and value["login_enabled"] is False
            and type(value["other_client_sessions"]) is int and value["other_client_sessions"] == 0)


def final_status(record, workflow_complete):
    """A completed workflow remains pending until every required cleanup binds."""
    return "passed" if (workflow_complete is True and "failure" not in record.receipt
        and record.receipt["runtime_stopped"] is True and not record.receipt["cleanup_failures"]
        and record.receipt["checks"].get("all_runtime_credentials_revoked") is True
        and administrator_retired(record.receipt["checks"].get("runtime-close", {}).get("administrator_retirement"))
        and record.receipt["checks"].get("runtime-close", {}).get("container_states")
        and all(state == "removed" for state in record.receipt["checks"]["runtime-close"]["container_states"])
        and record.receipt["assertions"] and all(record.receipt["assertions"].values())) else "failed"


def retain_result(record):
    try:
        record.persist()
        return record
    except Exception as error:
        record.receipt["status"] = "failed"
        record.receipt["cleanup_failures"].append({"stage": "receipt_persistence", "type": type(error).__name__})
    try:
        fallback = Recorder(Path(tempfile.mkdtemp(prefix="hobnail-docker-receipt-failure-")))
        fallback.secrets = record.secrets
        fallback.receipt.update(record.receipt)
        fallback.receipt.update(status="failed", receipt=str(fallback.path), receipt_persisted=True)
        fallback.persist()
        return fallback
    except Exception as error:
        # Do not claim that a new path contains the final result when both
        # evidence locations fail. The caller still receives the primary failure.
        record.receipt.update(status="failed", receipt=None, receipt_persisted=False)
        record.receipt["cleanup_failures"].append({"stage": "fallback_receipt_persistence", "type": type(error).__name__})
        return record


def run_qualification(*, parser_archive, runtime_archive, expected_engine, expected_kernel,
                      trusted_input=TRUSTED_INPUT, artifact=GOOD_ARTIFACT):
    runtime = None
    record = None
    known = {}
    workflow_complete = False
    unrelated_before = None
    try:
        for value in (trusted_input, artifact):
            if not isinstance(value, bytes) or not 0 < len(value) <= 1_048_576 or not isinstance(parse_json(value.decode("utf-8")), dict):
                raise ValueError("qualification inputs must be bounded explicit JSON object bytes")
        runtime = DockerRuntime(parser_archive=parser_archive, runtime_archive=runtime_archive,
                                expected_engine=expected_engine, expected_kernel=expected_kernel)
        record = Recorder(runtime.root)
        record.step("declared-qualification-limits", lambda: {"bootstrap_ttl": BOOTSTRAP_TTL,
            "bootstrap_lifetime": BOOTSTRAP_LIFETIME, "runtime_initial_ttl": RUNTIME_TTL,
            "runtime_max_ttl": RUNTIME_MAX_TTL, "runtime_lifetime": RUNTIME_LIFETIME,
            "expiry_ttl": EXPIRY_TTL, "expiry_poll_seconds": EXPIRY_POLL_SECONDS,
            "held_transport_seconds": 55, "held_query_sleep_seconds": 120,
            "parser_timeout_seconds": PARSER_TIMEOUT_SECONDS, "parser_sleep_seconds": 30,
            "parser_output_limit_bytes": 32768, "parser_overflow_probe_bytes": 65536})
        unrelated_before = record.step("unrelated-before-main-runtime", lambda: _unrelated(runtime))
        record.step("runtime-start", runtime.start, summary=lambda value: {"installation": value.ownership.get("installation"), "daemon": value.ownership.get("daemon")})
        record.secrets.append(runtime.admin.connection.password)
        record.step("exact-inputs", lambda: {"trusted_input_sha256": hashlib.sha256(trusted_input).hexdigest(),
                                             "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
                                             "source_hashes": runtime.ownership.get("source", {})})
        endpoints = bootstrap(runtime, record, known)
        bootstrap_verifier = endpoints["verifier"]
        canary, canary_before = supervisor_canary(runtime, record)
        qualify_unknown_principal(runtime, record, known)
        qualify_roles(runtime, record, endpoints, canary)
        qualify_parser_mismatch(runtime, record)
        limits_before = record.step("parser-limits-results-before", lambda:
            int(runtime.admin.execute_sql("SELECT count(*) FROM hobnail.results;").strip()))
        qualify_parser_limits(runtime, record)
        limits_after = record.step("parser-limits-results-after", lambda:
            int(runtime.admin.execute_sql("SELECT count(*) FROM hobnail.results;").strip()))
        record.check("parser-limits-no-evidence", limits_before == limits_after)
        broker, lease = runtime_credential(runtime, record, endpoints, known)
        candidate_id, digests = workflow(runtime, record, endpoints, trusted_input, artifact)
        qualify_expiry(runtime, record, endpoints, broker, known, candidate_id)
        record.api("runtime-credential-positive-before-revoke", endpoints["verifier"].client(), "candidate.get", {"candidate_id": candidate_id})
        retire_held_session(runtime, record, endpoints["verifier"], endpoints["verifier"].client(), broker, lease,
                            candidate_id, prefix="runtime-credential")
        record.api("other-login-positive-after-revoke", endpoints["worker"].client(), "candidate.get", {"candidate_id": candidate_id})
        # The short runtime lease has completed its held-session test. Use the
        # separately issued bootstrap verifier for the independent source work,
        # keeping that additional workload outside the 120s renewed lease.
        endpoints["verifier"] = bootstrap_verifier
        completed_effect = deliver_source_inventory(runtime, record, endpoints, digests)
        qualify_parser(runtime, record, endpoints, canary)
        verify_audit(record, endpoints["auditor"].client(), completed_effect)
        qualify_lifetime(runtime, record, bootstrap_verifier, broker, known, candidate_id)
        runtime.assert_snapshot()
        record.step("source-snapshot-final", lambda: {"unchanged": True})
        qualify_lifecycle_faults(record, {"parser_archive": parser_archive, "runtime_archive": runtime_archive,
            "expected_engine": expected_engine, "expected_kernel": expected_kernel})
        final_canary = record.step("supervisor-canary-final", lambda: {
            "sha256": hashlib.sha256(canary.read_bytes()).hexdigest(),
            "identity": [canary.stat().st_dev, canary.stat().st_ino, canary.stat().st_size,
                         canary.stat().st_mtime_ns, canary.stat().st_ctime_ns]})
        record.check("supervisor-canary-unchanged", final_canary["sha256"] ==
                     record.receipt["checks"]["supervisor-canary-positive"]["sha256"]
                     and final_canary["identity"] == [canary_before.st_dev, canary_before.st_ino,
                         canary_before.st_size, canary_before.st_mtime_ns, canary_before.st_ctime_ns])
        workflow_complete = True
        record.receipt["status"] = "cleanup_pending"
    except Exception as error:
        if record is None:
            try:
                root = Path(tempfile.mkdtemp(prefix="hobnail-docker-qualification-failure-"))
                root.chmod(0o700)
                record = Recorder(root)
            except Exception as storage:
                record = Recorder.unpersisted()
                record.receipt["cleanup_failures"].append({"stage": "initial_receipt_persistence", "type": type(storage).__name__})
        record.receipt["status"] = "failed"
        record.receipt["failure"] = {"type": type(error).__name__, "reason": str(error) if isinstance(error, QualificationError) else "runtime_failure"}
    finally:
        if record is not None:
            if runtime is not None:
                try:
                    retire_owned(runtime, record, known)
                except Exception as error:
                    record.receipt["cleanup_failures"].append({"stage": "credential_retirement", "type": type(error).__name__})
                try:
                    cleanup_step(record, "runtime-close", runtime.close, summary=lambda _: {"status": runtime.ownership.get("status"),
                        "cleanup_failures": runtime.ownership.get("cleanup_failures", []),
                        "administrator_retirement": runtime.ownership.get("administrator_retirement"),
                        "container_states": [item["state"] for item in runtime.containers.values()]})
                except Exception as error:
                    record.receipt["cleanup_failures"].append({"stage": "runtime_close", "type": type(error).__name__})
                record.receipt["runtime_stopped"] = runtime.closed and not runtime.active and runtime.ownership.get("status") == "stopped-owned-volumes-retained"
                if unrelated_before is not None:
                    try:
                        unrelated_after = cleanup_step(record, "unrelated-after-main-cleanup",
                                                       lambda: _unrelated(runtime, unrelated_before))
                        record.check("unrelated-main-runtime-preserved", unrelated_before == unrelated_after)
                    except Exception as error:
                        record.receipt["cleanup_failures"].append({"stage": "unrelated_main_readback",
                                                                 "type": type(error).__name__})
            record.receipt["status"] = final_status(record, workflow_complete)
            record = retain_result(record)
    return record.safe(record.receipt)


def release_configuration(path):
    if not path:
        raise RuntimeError("HOBNAIL_DOCKER_RELEASE_CONFIG is required; Docker qualification was not run")
    path = Path(path).absolute()
    if path.resolve(strict=True) != path:
        raise ValueError("release configuration must be a canonical explicit file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or info.st_mode & 0o077 or not 0 < info.st_size <= 16384):
            raise ValueError("release configuration must be a bounded owned private file")
        raw = stream.read(16385)
        after = os.fstat(stream.fileno())
        current = path.stat(follow_symlinks=False)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(raw) != info.st_size or identity(info) != identity(after) or identity(after) != identity(current):
            raise ValueError("release configuration changed")
    value = parse_json(raw.decode("utf-8"))
    fields = {"parser_archive", "runtime_archive", "expected_engine", "expected_kernel"}
    if not isinstance(value, dict) or set(value) != fields or any(not isinstance(item, str) or not item or "\x00" in item for item in value.values()):
        raise ValueError("release configuration requires exactly four nonsecret artifact/runtime fields")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parser-archive", required=True)
    parser.add_argument("--runtime-archive", required=True)
    parser.add_argument("--engine-version", required=True)
    parser.add_argument("--kernel-version", required=True)
    arguments = parser.parse_args(argv)
    result = run_qualification(parser_archive=arguments.parser_archive, runtime_archive=arguments.runtime_archive,
                               expected_engine=arguments.engine_version, expected_kernel=arguments.kernel_version)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
