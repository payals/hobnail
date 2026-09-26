#!/usr/bin/env python3
"""Run a complete synthetic Hobnail workflow on a fresh owned PostgreSQL 18.

    python3 scripts/local_demo.py
    python3 scripts/local_demo.py --scenario bad_content

The JSON receipt names actual acceptance, refusal and file consequences. The
cluster always stops; its private data directory, logs, outputs and receipt stay
available for inspection. No existing database or user credentials are used.
One trusted demo controller holds the synthetic service credentials; distinct
SQL identities and restricted parser children do not establish a production
deployment's OS authority separation.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from scripts.dev_cluster import DevCluster
from scripts.install import install
from hobnail.client import Client, Connection, PsqlTransport, TransportError, canonical_json, parse_json
from hobnail.contracts import IDENTIFIER, validate_contract
from hobnail.credentials import CredentialBroker, CredentialProfile, CredentialRequest, PostgresCredentialProvider
from hobnail.effects import FileObserver, FilePublisher, dispatch_file, observe_file
from hobnail.effects import implementation_digest as effect_digest
from hobnail.isolation import run_restricted
from hobnail.validators import implementation_digest as validator_digest
from hobnail.verifier import verify_candidate


SCENARIOS = ("happy", "bad_content", "stale_input")
TRUSTED_INPUT = b'{"orders":2,"period":"synthetic-period"}'
GOOD_ARTIFACT = b'{"orders":2,"period":"synthetic-period","summary":"Two observed orders"}'
BAD_ARTIFACT = b'{"orders":999,"period":"synthetic-period","summary":"Unsupported order count"}'


class DemoError(RuntimeError):
    """A named demo expectation failed; detailed retained receipts are separate."""


def _checked(response: dict[str, Any], stage: str) -> dict[str, Any]:
    if not response["ok"]:
        raise DemoError(stage)
    return response["data"]


def _probe_restricted_child(root: Path) -> dict[str, Any]:
    """Exercise effects against only fixtures and a listener this demo owns."""
    marker = root / "synthetic-parent-marker.txt"
    marker.write_text("synthetic-parent-only", encoding="utf-8")
    output = root / "child-must-not-create.txt"
    script = root / "restricted_child_probe.py"
    script.write_text(
        "import json, os, pathlib, socket, sys\n"
        "request=json.load(sys.stdin); result={}\n"
        "for name, operation in {\n"
        " 'external_read_denied': lambda: pathlib.Path(request['marker']).read_bytes(),\n"
        " 'external_write_denied': lambda: pathlib.Path(request['output']).write_text('forbidden'),\n"
        "}.items():\n"
        " try: operation(); result[name]=False\n"
        " except PermissionError: result[name]=True\n"
        "with socket.socket() as channel:\n"
        " try: channel.connect(('127.0.0.1',request['port'])); result['network_connect_denied']=False\n"
        " except PermissionError: result['network_connect_denied']=True\n"
        "result['parent_marker_environment_absent']='HOBNAIL_DEMO_SYNTHETIC_MARKER' not in os.environ\n"
        "result['credential_environment_absent']='PGPASSWORD' not in os.environ\n"
        "print(json.dumps(result))\n", encoding="utf-8")
    os.chmod(script, 0o600)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.05)
        previous = os.environ.get("HOBNAIL_DEMO_SYNTHETIC_MARKER")
        os.environ["HOBNAIL_DEMO_SYNTHETIC_MARKER"] = "synthetic-parent-only"
        try:
            child = run_restricted(script, canonical_json({"marker": str(marker), "output": str(output),
                                                           "port": listener.getsockname()[1]}))
        finally:
            if previous is None:
                os.environ.pop("HOBNAIL_DEMO_SYNTHETIC_MARKER", None)
            else:
                os.environ["HOBNAIL_DEMO_SYNTHETIC_MARKER"] = previous
        if child.returncode:
            raise DemoError("restricted_child_probe_failed")
        result = parse_json(child.stdout)
        try:
            connection, _ = listener.accept()
            connection.close()
            network_effect_absent = False
        except TimeoutError:
            network_effect_absent = True
    result["external_write_absent"] = not output.exists()
    result["marker_unchanged"] = marker.read_text(encoding="utf-8") == "synthetic-parent-only"
    result["network_effect_absent"] = network_effect_absent
    expected = {"external_read_denied", "external_write_denied", "network_connect_denied",
                "parent_marker_environment_absent", "credential_environment_absent",
                "external_write_absent", "marker_unchanged", "network_effect_absent"}
    if set(result) != expected or any(value is not True for value in result.values()):
        raise DemoError("restricted_child_boundary_not_demonstrated")
    return {"backend": "macos-sandbox-exec", "observations": result,
            "scope": "bounded data parser; these named local effects only"}


def _enable_scram_and_statement_logging(cluster: DevCluster) -> None:
    # This file was generated by this invocation's private initdb. The sole
    # administrative bootstrap remains local; every runtime role uses SCRAM.
    (cluster.data_dir / "pg_hba.conf").write_text(
        "local all postgres trust\nlocal all all scram-sha-256\n", encoding="utf-8")
    cluster.psql("ALTER SYSTEM SET log_statement='all';")
    cluster.psql("SELECT pg_reload_conf();")
    for _ in range(50):
        if cluster.psql("SHOW log_statement").stdout.strip() == "all":
            return
        time.sleep(0.02)
    raise DemoError("owned_statement_logging_did_not_activate")


def _bootstrap(cluster: DevCluster, admin: PsqlTransport, contracts: list[str], *,
               sources: tuple[str, ...] = ("orders",), principal_prefix: str = "demo") -> tuple[dict[str, Client], Any, list[Any]]:
    if (not isinstance(principal_prefix, str) or not IDENTIFIER.fullmatch(principal_prefix)
            or len(principal_prefix) > 64 or not isinstance(sources, (tuple, list))
            or not 1 <= len(sources) <= 16
            or any(not isinstance(name, str) or not IDENTIFIER.fullmatch(name) for name in sources)
            or len(set(sources)) != len(sources)):
        raise ValueError("invalid explicit bootstrap principal or source scopes")
    roles = ("worker", "registrar", "approver", "verifier", "adapter", "observer", "auditor", "credential_provider")
    profiles = {"bootstrap-" + role: CredentialProfile("bootstrap-" + role,
                frozenset({principal_prefix + "-" + role}), role, 300, 600) for role in roles}
    # A unique issuer scope makes failure recovery specific to this bootstrap,
    # including an issuance that committed before its response was lost.
    provider = PostgresCredentialProvider(admin, provider_id=principal_prefix + "-bootstrap-" + secrets.token_hex(12), profiles=profiles)
    owner = Client(admin)
    clients: dict[str, Client] = {}
    leases = []
    try:
        for request_id, role in enumerate(roles, 1):
            principal = principal_prefix + "-" + role
            lease = provider.issue(CredentialRequest(request_id, "bootstrap-" + role, principal, role, 300))
            leases.append(lease)
            profile_scope = ["verifier-runtime"] if role in {"verifier", "credential_provider", "approver"} else []
            owner.require("principal.bind", {"login": lease.login, "principal": principal, "role": role,
                                              "contracts": [] if role == "credential_provider" else contracts,
                                              "sources": list(sources) if role == "registrar" else [], "profiles": profile_scope})
            transport = PsqlTransport(replace(admin.connection, user=lease.login, password=lease.password.reveal()), psql=admin.psql)
            # Positive password authentication control and actual session identity.
            if transport.execute_sql("SELECT session_user").strip() != lease.login:
                raise DemoError("runtime_identity_mismatch")
            clients[role] = Client(transport)
    except BaseException as primary:
        try:
            recoverable = provider.inventory()
        except Exception:
            primary.add_note("Bootstrap issuance inventory unavailable; credential cleanup is unconfirmed.")
            recoverable = leases
        for lease in recoverable:
            try:
                if provider.revoke(lease.lease_ref).result != "confirmed":
                    primary.add_note("One owned bootstrap credential has unconfirmed revocation.")
            except Exception:
                primary.add_note("One owned bootstrap credential could not be confirmed revoked.")
        raise
    return clients, provider, leases


def _plugins(approver: Client) -> dict[str, str]:
    digests = {}
    definitions = {
        "json.equals": ("validator", validator_digest(), "isolated-json", ["read_artifact", "read_inputs"],
                        {"source": "approved source name", "pairs": "exact JSON pointer pairs"}, "all exact typed values match"),
        "json.required_fields": ("validator", validator_digest(), "isolated-json", ["read_artifact"],
                                 {"pointers": "required JSON pointers"}, "each pointer resolves"),
        "file.publish": ("effect", effect_digest(), "local-file", ["write_target"], {}, "attempted exact-byte local publication"),
    }
    for plugin_id, (kind, implementation, backend, capabilities, parameters, semantics) in definitions.items():
        registered = approver.require("plugin.register", {
            "plugin_id": plugin_id, "version": 1, "kind": kind,
            "manifest": {"implementation": implementation, "input_media_types": ["application/json"],
                         "parameters": parameters, "capabilities": capabilities,
                         "result_semantics": semantics, "execution_backend": backend}})
        digests[plugin_id] = registered["data"]["plugin_digest"]
    return digests


def _contract(target: str, digests: dict[str, str]) -> dict[str, Any]:
    document = {
        "schema_version": 1,
        "description": "Compare synthetic report fields with independently registered orders before local publication",
        "access": {"workers": ["demo-worker"], "verifiers": ["demo-verifier"],
                   "observers": ["demo-observer"], "adapters": {"publish": ["demo-adapter"]}},
        "subject": {"media_type": "application/json", "max_bytes": 1048576},
        "sources": [{"name": "orders", "registrars": ["demo-registrar"], "require_current": True}],
        "checks": [
            {"id": "metrics", "plugin": "json.equals", "plugin_digest": digests["json.equals"],
             "parameters": {"source": "orders", "pairs": [{"artifact": "/orders", "input": "/orders"},
                                                              {"artifact": "/period", "input": "/period"}]},
             "max_age_seconds": 300},
            {"id": "shape", "plugin": "json.required_fields", "plugin_digest": digests["json.required_fields"],
             "parameters": {"pointers": ["/orders", "/period", "/summary"]}, "max_age_seconds": 300}],
        "actions": [{"name": "publish", "plugin": "file.publish", "plugin_digest": digests["file.publish"],
                     "target": target, "arguments": {}, "max_age_seconds": 300}],
        "budgets": {"verification": 5, "effects": 5},
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    }
    validate_contract(document, for_activation=True)
    return document


def _scenario(name: str, clients: dict[str, Client], digests: dict[str, str], output: Path,
              result: dict[str, Any]) -> dict[str, Any]:
    contract_id, target = "demo-" + name, name + ".json"
    result.update({"scenario": name, "contract_id": contract_id, "target": target, "stage": "contract", "stages": {}})
    document = _contract(target, digests)
    clients["worker"].require("contract.propose", {"contract_id": contract_id, "version": 1, "document": document})
    activated = clients["approver"].require("contract.activate", {"contract_id": contract_id, "version": 1,
                                                                  "expected_active_version": None})
    result["stages"]["activation"] = activated
    result["stage"] = "trusted_input"
    source = clients["registrar"].require("input.put", {"contract_id": contract_id, "source": "orders", "version": 1,
                                                        "content_hex": TRUSTED_INPUT.hex(), "media_type": "application/json",
                                                        "expected_current": None})["data"]
    content = BAD_ARTIFACT if name == "bad_content" else GOOD_ARTIFACT
    result["stage"] = "artifact_and_candidate"
    artifact = clients["worker"].require("artifact.put", {"content_hex": content.hex(), "media_type": "application/json"})["data"]
    candidate = clients["worker"].require("candidate.submit", {"contract_id": contract_id, "artifact_id": artifact["artifact_id"],
                                                                 "inputs": {"orders": source["snapshot_id"]},
                                                                 "idempotency_key": "candidate-" + name})["data"]
    result.update({"candidate_id": candidate["candidate_id"], "artifact_digest": artifact["digest"],
                   "trusted_input_digest": source["digest"], "stage": "verification"})
    acceptance = verify_candidate(clients["verifier"], candidate["candidate_id"])
    result["stages"]["acceptance"] = acceptance
    result["stage"] = "effect_request"
    request_payload = {"candidate_id": candidate["candidate_id"], "action": "publish", "args": {}, "idempotency_key": "publish-" + name}
    requested = clients["worker"].call("effect.request", request_payload)
    result["stages"]["effect_request"] = requested
    if name == "bad_content":
        if acceptance["ok"] or acceptance.get("code") != "CHECK_FAILED" or requested["ok"] or requested.get("code") != "CHECK_FAILED":
            raise DemoError("bad_content_did_not_refuse")
    else:
        _checked(acceptance, "exact_content_was_not_accepted")
        effect = _checked(requested, "protected_effect_was_not_reserved")
        effect_id = effect["effect_id"]
        result["effect_id"] = effect_id
        if name == "stale_input":
            result["stage"] = "input_advance"
            updated = clients["registrar"].require("input.put", {
                "contract_id": contract_id, "source": "orders", "version": 2,
                "content_hex": b'{"orders":3,"period":"synthetic-period"}'.hex(), "media_type": "application/json",
                "expected_current": source["snapshot_id"]})
            result["stages"]["input_advance"] = updated
        result["stage"] = "dispatch"
        dispatched = dispatch_file(clients["adapter"], effect_id, FilePublisher(output))
        result["stages"]["dispatch"] = dispatched
        if name == "stale_input":
            if dispatched["ok"] or dispatched.get("code") != "INPUT_STALE":
                raise DemoError("changed_input_did_not_block_dispatch")
            current = clients["worker"].call("candidate.accept", {"candidate_id": candidate["candidate_id"]})
            result["stages"]["current_acceptance"] = current
            if current["ok"] or current.get("code") != "INPUT_STALE":
                raise DemoError("changed_input_reused_acceptance")
        else:
            _checked(dispatched, "file_dispatch_failed")
            result["stage"] = "independent_observation"
            observed = observe_file(clients["observer"], effect_id, FileObserver(output))
            result["stages"]["independent_observation"] = observed
            if not observed["ok"] or observed["data"]["state"] != "complete":
                raise DemoError("independent_completion_not_observed")
        result["effect"] = clients["observer"].require("effect.get", {"effect_id": effect_id})["data"]
    current_candidate = clients["worker"].require("candidate.get", {"candidate_id": candidate["candidate_id"]})["data"]
    result["evidence"] = {"current_eligible": current_candidate["eligible"], "checks": current_candidate["results"],
                           "acceptances": current_candidate["acceptances"]}
    path = output / target
    result["consequence"] = {"exists": path.exists(), "digest": hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None,
                              "bytes": path.stat().st_size if path.exists() else 0}
    if name == "happy":
        if not path.is_file() or path.read_bytes() != content:
            raise DemoError("observed_file_differs_from_exact_accepted_artifact")
    elif path.exists():
        raise DemoError("refused_case_produced_a_file")
    result["expected_outcome_observed"] = True
    result["stage"] = "completed"
    return result


def run_demo(scenarios: tuple[str, ...] = SCENARIOS, *, base_dir: str | Path = "/tmp") -> dict[str, Any]:
    """Return only safe evidence; preserve unexpected failures and stop owned PG."""
    if not scenarios or len(set(scenarios)) != len(scenarios) or any(item not in SCENARIOS for item in scenarios):
        raise ValueError("choose unique supported scenarios")
    evidence: dict[str, Any] = {
        "protocol": 1, "run_status": "running", "scenarios": [], "stages": {},
        "qualification": {
            "scope": "synthetic local acceptance, exact file effects, named native child confinement and PostgreSQL credential enforcement",
            "production_os_authority_separation": False,
            "limits": ["One trusted demo controller holds all synthetic service credentials.",
                       "Distinct runtime calls use real SCRAM-authenticated SQL identities.",
                       "Candidate JSON is parsed in actual restricted child processes.",
                       "Administrator bootstrap and controllers share the current OS identity.",
                       "This does not establish production isolation, external-provider qualification or useful project outcomes."],
        },
    }
    cluster: DevCluster | None = None
    stage = "allocate_owned_cluster"
    try:
        cluster = DevCluster(base_dir=base_dir)
        evidence["retained_root"] = str(cluster.root)
        stage = "start_owned_cluster"
        cluster.start()
        stage = "install"
        evidence["stages"][stage] = install(
            f"host={cluster.socket_dir} port={cluster.port} dbname={cluster.database} user=postgres sslmode=disable",
            str(cluster.bin_dir / "psql"))
        stage = "restricted_child_probe"
        evidence["stages"][stage] = _probe_restricted_child(cluster.root)
        stage = "configure_owned_runtime"
        _enable_scram_and_statement_logging(cluster)
        admin = PsqlTransport(Connection(str(cluster.socket_dir), cluster.database, "postgres", port=cluster.port,
                                         sslmode="disable"), psql=str(cluster.bin_dir / "psql"))
        clients, bootstrap, bootstrap_leases = _bootstrap(cluster, admin, ["demo-" + name for name in scenarios])
        output = cluster.root / "outputs"
        output.mkdir(mode=0o700)
        evidence["output_root"] = str(output)
        stage = "dynamic_verifier_credential"
        verifier_profile = CredentialProfile("verifier-runtime", frozenset({"demo-verifier"}), "verifier", 120, 600, True)
        owner = Client(admin)
        owner.require("credential.profile", {"profile": verifier_profile.name, "provider": "demo-credential_provider",
                                               "principals": ["demo-verifier"], "role": "verifier", "max_ttl_seconds": 120,
                                               "max_lifetime_seconds": 600, "renewable": True,
                                               "capabilities": ["dynamic_postgres", "renewal", "revocation", "active_session_termination"]})
        forbidden = clients["worker"].call("credential.request", {"profile": "verifier-runtime", "ttl_seconds": 60,
                                                                   "idempotency_key": "worker-privileged-profile"})
        evidence["stages"]["worker_privileged_profile"] = forbidden
        if forbidden["ok"] or forbidden.get("code") != "CREDENTIAL_SCOPE":
            raise DemoError("worker_obtained_privileged_profile")
        requested = clients["verifier"].require("credential.request", {"profile": "verifier-runtime", "ttl_seconds": 120,
                                                                         "idempotency_key": "verifier-rotation"})
        native = PostgresCredentialProvider(admin, provider_id="demo-credential_provider", profiles={verifier_profile.name: verifier_profile})
        broker = CredentialBroker(clients["credential_provider"], native)
        verifier_lease = broker.issue_request(requested["data"]["request_id"])
        original_verifier = clients["verifier"]
        dynamic_transport = PsqlTransport(replace(admin.connection, user=verifier_lease.login,
                                                  password=verifier_lease.password.reveal()), psql=admin.psql)
        if dynamic_transport.execute_sql("SELECT session_user").strip() != verifier_lease.login:
            raise DemoError("dynamic_verifier_identity_mismatch")
        clients["verifier"] = Client(dynamic_transport)
        evidence["stages"][stage] = {"request_id": verifier_lease.request_id, "credential_id": verifier_lease.credential_id,
                                     "principal": verifier_lease.principal, "role": verifier_lease.role,
                                     "password_authenticated": True}
        stage = "register_plugins"
        digests = _plugins(clients["approver"])
        for name in scenarios:
            stage = "scenario:" + name
            result: dict[str, Any] = {}
            evidence["scenarios"].append(result)
            _scenario(name, clients, digests, output, result)
        stage = "revoke_dynamic_verifier"
        original_verifier.require("credential.revoke_requested", {"credential_id": verifier_lease.credential_id})
        observation = broker.revoke_requested(verifier_lease.credential_id)
        login_denied = False
        try:
            dynamic_transport.execute_sql("SELECT 1")
        except TransportError:
            login_denied = True
        evidence["stages"][stage] = {"result": observation.result, "active_sessions": observation.active_sessions,
                                     "login_enabled": observation.login_enabled, "new_login_denied": login_denied}
        if observation.result != "confirmed" or not login_denied:
            raise DemoError("dynamic_verifier_revocation_not_observed")
        stage = "audit"
        audit = clients["auditor"].require("audit.export", {"after": 0, "limit": 1000})["data"]
        evidence["stages"][stage] = audit
        if not audit["chain_valid"]:
            raise DemoError("audit_chain_failed")
        stage = "revoke_bootstrap_logins"
        for lease in bootstrap_leases:
            if bootstrap.revoke(lease.lease_ref).result != "confirmed":
                raise DemoError("bootstrap_revocation_not_confirmed")
        stage = "check_secret_absence"
        log = (cluster.root / "server.log").read_text(encoding="utf-8")
        serialized = canonical_json(evidence)
        secret_values = [lease.password.reveal() for lease in [*bootstrap_leases, verifier_lease]]
        absent = all(value not in log and value not in serialized for value in secret_values)
        absent = absent and "SCRAM-SHA-256$4096:" not in log
        evidence["stages"][stage] = {"passwords_and_verifiers_absent_from_statement_log": absent,
                                    "passwords_absent_from_evidence": all(value not in serialized for value in secret_values)}
        if not absent:
            raise DemoError("synthetic_credential_logging_detected")
        evidence["run_status"] = "completed"
    except Exception as error:
        evidence["run_status"] = "failed"
        # Class and named stage are sufficient to find retained logs; exception
        # messages can carry server content and are deliberately not emitted.
        evidence["failure"] = {"stage": stage, "kind": type(error).__name__}
    finally:
        if cluster is not None:
            try:
                cluster.stop()
                evidence["runtime_stopped"] = not cluster.is_running()
            except Exception as error:
                evidence["run_status"] = "failed"
                evidence["runtime_stopped"] = False
                evidence["cleanup_failure"] = {"kind": type(error).__name__}
            evidence["evidence_file"] = str(cluster.root / "evidence.json")
            with (cluster.root / "evidence.json").open("x", encoding="utf-8") as stream:
                os.chmod(stream.name, 0o600)
                json.dump(evidence, stream, sort_keys=True, indent=2, allow_nan=False)
                stream.write("\n")
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=(*SCENARIOS, "all"), default="all")
    args = parser.parse_args(argv)
    receipt = run_demo(SCENARIOS if args.scenario == "all" else (args.scenario,))
    print(json.dumps(receipt, sort_keys=True, allow_nan=False))
    return 0 if receipt["run_status"] == "completed" and receipt.get("runtime_stopped") else 1


if __name__ == "__main__":
    raise SystemExit(main())
