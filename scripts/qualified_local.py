#!/usr/bin/env python3
"""Qualify named native role processes in a new, entirely owned deployment.

All socket-accessible logins require SCRAM before role processes start. The
operator/supervisor and other unsandboxed processes of its OS user are trusted.
Live project controls and other PostgreSQL instances are never touched.
"""

from dataclasses import asdict, replace
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.dev_cluster import DevCluster
from scripts.install import install
from scripts.local_demo import _bootstrap, _plugins, _contract, GOOD_ARTIFACT, BAD_ARTIFACT, TRUSTED_INPUT
from hobnail.client import Client, Connection, PsqlTransport, PasswordAuthenticationFailed, TransportError, canonical_json
from hobnail.credentials import CredentialBroker, CredentialProfile, PostgresCredentialProvider, Secret, _scram
from hobnail.deployment import RoleEndpoint, endpoint
from hobnail.isolation import _bounded_child, _runtime, run_implementation
from hobnail.service_isolation import service_profile
from hobnail.verifier import verify_candidate


class QualificationError(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise QualificationError(reason)


def qualification_probe(role, request):
    """Use the exact production resource profile with fixed test-only code.

    No extra file, process or network grant is added for the probe. The code is
    supplied to the already allowed interpreter by the trusted qualification
    supervisor, never through the production role driver's command interface.
    """
    source = (ROOT / "scripts/_role_probe.py").read_text()
    arguments = ["/usr/bin/sandbox-exec", "-p", service_profile(role.policy), str(_runtime()[0]),
                 "-I", "-S", "-B", "-c", source, str(role.policy.config), str(role.policy.script.parent)]
    child = _bounded_child(arguments, canonical_json(request).encode(), directory=str(role.policy.scratch), timeout=30,
                           stdout_limit=36_000_000, stderr_limit=32768)
    require(child.returncode == 0, "qualification_probe_process")
    response = json.loads(child.stdout)
    require(isinstance(response, dict) and "probe_error" not in response, "qualification_probe_response")
    return response


def cleanup_credentials(provider, leases, receipt, broker=None):
    results = receipt["checks"].setdefault("credential_cleanup", [])
    for lease in leases:
        row = {"principal": lease.principal, "confirmed": False}
        try:
            observed = broker.reconcile_request(lease.request_id) if broker else provider.revoke(lease.lease_ref)
            row["confirmed"] = observed.result == "confirmed"
            row["active_sessions"] = observed.active_sessions
        except Exception as error:
            row["error"] = type(error).__name__
        results.append(row)
        if not row["confirmed"]:
            receipt["status"] = "failed"
            receipt.setdefault("cleanup_failures", []).append({"stage": "credential_revocation", **row})
    receipt["checks"]["all_runtime_credentials_revoked"] = bool(results) and all(row["confirmed"] for row in results)


def retain_receipt(cluster, receipt):
    try:
        receipt["runtime_stopped"] = not cluster.is_running()
    except Exception as error:
        receipt["runtime_stopped"] = None
        receipt["status"] = "failed"
        receipt.setdefault("cleanup_failures", []).append({"stage": "runtime_status", "type": type(error).__name__})
    if receipt["runtime_stopped"] is not True:
        receipt["status"] = "failed"
    try:
        cluster._check_owner()
        path = cluster.root / "qualification.json"
        receipt["receipt"] = str(path)
        with path.open("x") as stream:
            stream.write(json.dumps(receipt, indent=2) + "\n")
    except Exception as error:
        # Preserve the original failure without writing into an unowned or
        # replaced cluster directory. The fallback is newly and exclusively ours.
        receipt["status"] = "failed"
        receipt.setdefault("cleanup_failures", []).append({"stage": "receipt_persistence", "type": type(error).__name__})
        directory = Path(tempfile.mkdtemp(prefix="hobnail-qualification-failure-"))
        directory.chmod(0o700)
        path = directory / "qualification.json"
        receipt["receipt"] = str(path)
        with path.open("x") as stream:
            stream.write(json.dumps(receipt, indent=2) + "\n")


def secure_admin(cluster, transport):
    password = Secret(secrets.token_urlsafe(36))
    verifier = _scram(password.reveal())
    # Newly owned bootstrap only. COPY keeps authentication material out of
    # statement text/logging; the raw password never enters SQL or argv.
    transport.execute_sql("BEGIN; CREATE TEMP TABLE boot_auth(value text) ON COMMIT DROP;\n"
        "COPY boot_auth(value) FROM STDIN;\n" + verifier + "\n\\.\n"
        "DO $bootstrap$ DECLARE v text; BEGIN SELECT value INTO STRICT v FROM boot_auth; "
        "EXECUTE format('ALTER ROLE postgres PASSWORD %L',v); END $bootstrap$; COMMIT;", sensitive=True)
    admin = PsqlTransport(replace(transport.connection, password=password.reveal()), psql=transport.psql)
    (cluster.data_dir / "pg_hba.conf").write_text("local all all scram-sha-256\nhost all all all reject\n")
    admin.execute_sql("SELECT pg_reload_conf();")
    wrong = PsqlTransport(replace(admin.connection, password=secrets.token_urlsafe(36)), psql=admin.psql)
    for _ in range(100):
        try:
            wrong.execute_sql("SELECT session_user")
        except PasswordAuthenticationFailed:
            require(admin.execute_sql("SELECT session_user").strip() == "postgres", "administrator_positive_control")
            admin.execute_sql("ALTER SYSTEM SET log_statement='all';")
            admin.execute_sql("SELECT pg_reload_conf();")
            return admin
        except TransportError:
            raise QualificationError("administrator_authentication_inconclusive") from None
        # Until the requested HBA reload takes effect, bootstrap trust may still
        # accept either password. Only actual password rejection qualifies it.
        time.sleep(0.02)
    raise QualificationError("administrator_trust_not_removed")


def configure_endpoints(cluster, clients, destination):
    # First-party controller source is copied without bytecode caches. Role
    # profiles cannot write this snapshot, and Python runs with bytecode writes
    # disabled. Qualification fingerprints the bytes that actually execute.
    package = cluster.root / "runtime" / "hobnail"
    package.mkdir(parents=True, mode=0o700)
    source = ROOT / "src" / "hobnail"
    for original in sorted(source.rglob("*.py")):
        target = package / original.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(original.read_bytes())
    for directory in sorted([package, *[path for path in package.rglob("*") if path.is_dir()]], reverse=True):
        directory.chmod(0o500)
    service_root = cluster.root / "services"
    service_root.mkdir(mode=0o700)
    scratch_root = cluster.root / "scratch"
    scratch_root.mkdir(mode=0o700)
    endpoints = {}
    for role, client in clients.items():
        directory = service_root / role
        directory.mkdir(mode=0o700)
        scratch = scratch_root / role
        scratch.mkdir(mode=0o700)
        config = directory / "connection.json"
        value = {"role": role, "connection": asdict(client.transport.connection), "psql": client.transport.psql}
        permission = "write" if role == "adapter" else "read" if role == "observer" else "none"
        if permission != "none":
            value["destination"] = str(destination)
        descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(canonical_json(value))
        endpoints[role] = endpoint(role, config=config, scratch=scratch,
            socket_path=cluster.socket_dir / f".s.PGSQL.{cluster.port}",
            destination=destination if permission != "none" else None,
            permission=permission, psql=client.transport.psql, package_root=package)
    return endpoints


def run_qualification():
    cluster = DevCluster()
    receipt = {"status": "incomplete", "runtime_stopped": False, "checks": {},
               "retained_root": str(cluster.root), "assumptions": [
                   "Operator, bootstrap supervisor and other unsandboxed processes of this OS user are trusted.",
                   "Runtime roles use their enforced profiles; no live project acceptance controls are changed.",
                   "Candidate parsers run separately under the stricter existing data-validator profile."]}
    try:
        with cluster, ExitStack() as cleanup:
            dsn = f"host={cluster.socket_dir} port={cluster.port} dbname={cluster.database} user=postgres"
            install(dsn, psql=str(cluster.bin_dir / "psql"))
            transport = PsqlTransport(Connection(str(cluster.socket_dir), cluster.database, "postgres", sslmode="disable"),
                                      psql=str(cluster.bin_dir / "psql"))
            admin = secure_admin(cluster, transport)
            receipt["checks"]["administrator_requires_scram"] = True
            clients, provider, leases = _bootstrap(cluster, admin, ["native-report"])
            cleanup.callback(cleanup_credentials, provider, leases, receipt)
            destination = cluster.root / "published"
            destination.mkdir(mode=0o700)
            marker = destination / "controlled-marker"
            marker.write_bytes(b"owned-boundary-marker")
            endpoints = configure_endpoints(cluster, clients, destination)
            config_paths = {role: item.policy.config for role, item in endpoints.items()}
            digests = {role: hashlib.sha256(path.read_bytes()).hexdigest() for role, path in config_paths.items()}
            role_checks = {}
            listener_path = cluster.root / "sibling.sock"
            with socket.socket(socket.AF_UNIX) as sibling, socket.socket() as tcp:
                sibling.bind(str(listener_path)); sibling.listen(10); sibling.settimeout(0.05)
                tcp.bind(("127.0.0.1", 0)); tcp.listen(10); tcp.settimeout(0.05)
                for role, item in endpoints.items():
                    files = [config_paths[role], *[path for other, path in config_paths.items() if other != role]]
                    probe = {"command": "probe", "files": [str(path) for path in files], "admin_connection": True,
                             "unix_listener": str(listener_path), "tcp_port": tcp.getsockname()[1]}
                    if role in {"worker", "observer"}:
                        probe["marker"] = str(marker)
                    result = qualification_probe(item, probe)
                    require(result["session_user"] == clients[role].transport.connection.user, "wrong_role_session")
                    require(result["files"][0] == {"readable": True, "sha256": digests[role]}, "own_configuration_control")
                    require(all(row == {"readable": False, "reason": "permission_denied"} for row in result["files"][1:]),
                            "peer_configuration_access")
                    require(result["administrator_without_password_denied"] is True, "administrator_impersonation")
                    require(result["administrator_with_role_password_denied"] is True, "administrator_wrong_password")
                    require(result["other_socket_denied"] is True and result["tcp_denied"] is True, "network_scope")
                    if role in {"worker", "observer"}:
                        require(result["marker_write_denied"] is True, "destination_write_scope")
                    role_checks[role] = {"session_authenticated": True, "peer_reads_denied": len(files) - 1,
                                        "administrator_denied": True, "administrator_wrong_password_denied": True,
                                        "other_network_denied": True,
                                        "profile_fingerprint": item.configuration_fingerprint()}
                for listener in (sibling, tcp):
                    try:
                        connection, _ = listener.accept()
                        connection.close()
                        raise QualificationError("forbidden_network_effect_observed")
                    except TimeoutError:
                        pass
            require(marker.read_bytes() == b"owned-boundary-marker", "protected_marker_changed")
            try:
                endpoints["adapter"].request({"command": "probe", "marker": str(marker)})
            except TransportError:
                pass
            else:
                raise QualificationError("unguarded_adapter_probe_command")
            require(marker.read_bytes() == b"owned-boundary-marker", "unguarded_adapter_probe_effect")
            receipt["checks"]["production_adapter_probe_refused"] = True
            require(all(hashlib.sha256(path.read_bytes()).hexdigest() == digests[role]
                        for role, path in config_paths.items()), "configuration_changed")
            receipt["checks"]["role_boundaries"] = role_checks
            receipt["checks"]["parent_observed_no_forbidden_effects"] = True
            scoped = {role: item.client() for role, item in endpoints.items()}
            Client(admin).require("credential.profile", {
                "profile": "verifier-runtime", "provider": "demo-credential_provider", "principals": ["demo-verifier"],
                "role": "verifier", "max_ttl_seconds": 120, "max_lifetime_seconds": 240, "renewable": True,
                "capabilities": ["dynamic_postgres", "renewal", "revocation", "active_session_termination"]})
            worker_profile_denial = scoped["worker"].call("credential.request", {
                "profile": "verifier-runtime", "ttl_seconds": 120, "idempotency_key": "forbidden-verifier"})
            require(not worker_profile_denial["ok"] and worker_profile_denial["code"] == "CREDENTIAL_SCOPE", "privileged_profile_scope")
            runtime_request = scoped["verifier"].require("credential.request", {
                "profile": "verifier-runtime", "ttl_seconds": 120, "idempotency_key": "runtime-verifier"})
            issuer = PostgresCredentialProvider(admin, provider_id="demo-credential_provider", profiles={
                "verifier-runtime": CredentialProfile("verifier-runtime", frozenset({"demo-verifier"}),
                                                       "verifier", 120, 240, True)})
            broker = CredentialBroker(scoped["credential_provider"], issuer)
            runtime_lease = broker.issue_request(runtime_request["data"]["request_id"])
            cleanup.callback(cleanup_credentials, issuer, [runtime_lease], receipt, broker)
            rotated_config = config_paths["verifier"].parent / "rotated.json"
            connection = replace(clients["verifier"].transport.connection, user=runtime_lease.login,
                                 password=runtime_lease.password.reveal())
            descriptor = os.open(rotated_config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(canonical_json({"role": "verifier", "connection": asdict(connection), "psql": admin.psql}))
            endpoints["verifier"] = RoleEndpoint(replace(endpoints["verifier"].policy, config=rotated_config))
            scoped["verifier"] = endpoints["verifier"].client()
            probe = qualification_probe(endpoints["verifier"], {"files": [str(rotated_config)]})
            require(probe["session_user"] == runtime_lease.login and probe["files"][0]["readable"], "rotated_session")
            probe = qualification_probe(endpoints["worker"], {"files": [str(rotated_config)]})
            require(probe["files"] == [{"readable": False, "reason": "permission_denied"}], "rotated_credential_confinement")
            receipt["checks"]["runtime_verifier_credential"] = {
                "password_authenticated": True, "worker_profile_denial": worker_profile_denial,
                "worker_file_read_denied": True, "profile_fingerprint": endpoints["verifier"].configuration_fingerprint()}
            parser_probe = cluster.root / "parser-probe.py"
            parser_probe.write_text("import json,pathlib,socket,sys\nr=json.load(sys.stdin);out={}\n"
                "try: pathlib.Path(r['credential']).read_bytes();out['credential_denied']=False\n"
                "except PermissionError:out['credential_denied']=True\n"
                "with socket.socket(socket.AF_UNIX) as s:\n"
                " try:s.connect(r['socket']);out['database_socket_denied']=False\n"
                " except PermissionError:out['database_socket_denied']=True\n"
                "print(json.dumps(out))\n")
            parser_probe.chmod(0o400)
            parsed = run_implementation(parser_probe, hashlib.sha256(parser_probe.read_bytes()).hexdigest(),
                canonical_json({"credential": str(rotated_config), "socket": str(cluster.socket_dir / f".s.PGSQL.{cluster.port}")}))
            require(parsed.returncode == 0, "candidate_probe_process")
            parser_denials = json.loads(parsed.stdout)
            require(parser_denials == {"credential_denied": True, "database_socket_denied": True}, "candidate_credential_boundary")
            receipt["checks"]["candidate_parser_actual_denials"] = parser_denials
            plugins = _plugins(scoped["approver"])
            document = _contract("accepted.json", plugins)
            document["actions"].append({**document["actions"][0], "name": "stale", "target": "stale.json"})
            document["access"]["adapters"]["stale"] = ["demo-adapter"]
            scoped["worker"].require("contract.propose", {"contract_id": "native-report", "version": 1, "document": document})
            scoped["approver"].require("contract.activate", {"contract_id": "native-report", "version": 1,
                                                            "expected_active_version": None})
            inputs = scoped["registrar"].put_input("native-report", "orders", 1, TRUSTED_INPUT,
                                                    media_type="application/json", expected_current=None)
            require(inputs["ok"], "input_registration")
            artifact = scoped["worker"].put_artifact(GOOD_ARTIFACT, media_type="application/json")
            require(artifact["ok"], "artifact_registration")
            candidate = scoped["worker"].submit("native-report", artifact["data"]["artifact_id"],
                {"orders": inputs["data"]["snapshot_id"]}, idempotency_key="qualified-candidate")
            require(candidate["ok"], "candidate_submission")
            candidate_id = candidate["data"]["candidate_id"]
            denied = scoped["worker"].call("verification.claim", {"candidate_id": candidate_id, "lease_seconds": 60})
            require(not denied["ok"] and denied["code"] == "FORBIDDEN", "worker_verification_authority")
            accepted = verify_candidate(scoped["verifier"], candidate_id)
            require(accepted["ok"], "actual_verification")
            effect = scoped["worker"].require("effect.request", {"candidate_id": candidate_id,
                "action": "publish", "args": {}, "idempotency_key": "qualified-effect"})
            effect_id = effect["data"]["effect_id"]
            dispatched = endpoints["adapter"].dispatch(effect_id)
            require(dispatched["ok"] and dispatched["data"]["state"] == "attempted", "confined_dispatch")
            observed = endpoints["observer"].observe(effect_id)
            require(observed["ok"] and observed["data"]["state"] == "complete", "confined_observation")
            require((destination / "accepted.json").read_bytes() == GOOD_ARTIFACT, "exact_destination_bytes")
            receipt["checks"]["workflow"] = {"acceptance": accepted, "dispatch": dispatched, "observation": observed,
                "artifact_sha256": hashlib.sha256(GOOD_ARTIFACT).hexdigest(), "destination_bytes": len(GOOD_ARTIFACT),
                "worker_verification_denial": denied}
            bad_artifact = scoped["worker"].put_artifact(BAD_ARTIFACT, media_type="application/json")
            require(bad_artifact["ok"], "bad_artifact_registered")
            bad_candidate = scoped["worker"].submit("native-report", bad_artifact["data"]["artifact_id"],
                {"orders": inputs["data"]["snapshot_id"]}, idempotency_key="qualified-bad")
            require(bad_candidate["ok"], "bad_candidate_registered")
            failed = verify_candidate(scoped["verifier"], bad_candidate["data"]["candidate_id"])
            require(not failed["ok"] and failed["code"] == "CHECK_FAILED", "bad_content_refusal")
            bad_effect = scoped["worker"].call("effect.request", {"candidate_id": bad_candidate["data"]["candidate_id"],
                "action": "publish", "args": {}, "idempotency_key": "qualified-bad-effect"})
            require(not bad_effect["ok"] and bad_effect["code"] == "CHECK_FAILED", "bad_effect_refusal")
            stale = scoped["worker"].require("effect.request", {"candidate_id": candidate_id,
                "action": "stale", "args": {}, "idempotency_key": "qualified-stale-effect"})
            updated = scoped["registrar"].put_input("native-report", "orders", 2, TRUSTED_INPUT + b" ",
                media_type="application/json", expected_current=inputs["data"]["snapshot_id"])
            require(updated["ok"], "source_advance")
            stale_dispatch = endpoints["adapter"].dispatch(stale["data"]["effect_id"])
            require(not stale_dispatch["ok"] and stale_dispatch["code"] == "INPUT_STALE", "stale_dispatch_refusal")
            require(not (destination / "stale.json").exists(), "stale_effect_absent")
            require((destination / "accepted.json").read_bytes() == GOOD_ARTIFACT, "accepted_output_preserved")
            receipt["checks"]["negative_workflows"] = {"bad_acceptance": failed, "bad_effect": bad_effect,
                "stale_dispatch": stale_dispatch, "stale_output_absent": True, "accepted_output_unchanged": True}
            scoped["verifier"].require("credential.revoke_requested", {"credential_id": runtime_lease.credential_id})
            revoked = broker.revoke_requested(runtime_lease.credential_id)
            require(revoked.result == "confirmed", "runtime_verifier_revoke")
            try:
                endpoints["verifier"].client().call("candidate.get", {"candidate_id": candidate_id})
            except TransportError:
                receipt["checks"]["runtime_verifier_credential"]["revoked_login_denied"] = True
            else:
                raise QualificationError("revoked_role_still_connected")
            receipt["status"] = "passed"
    except Exception as error:
        receipt["status"] = "failed"
        receipt["failure"] = {"type": type(error).__name__, "reason": str(error) if isinstance(error, QualificationError) else "runtime_failure"}
    finally:
        retain_receipt(cluster, receipt)
    return receipt


if __name__ == "__main__":
    result = run_qualification()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "passed" else 1)
