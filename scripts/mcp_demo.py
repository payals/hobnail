#!/usr/bin/env python3
"""Real stdio MCP worker with separate protected native verification/effects.

Requires the reviewed optional package installed in this project's environment,
PostgreSQL 18 and macOS confinement. Creates only a fresh owned runtime. This
synthetic demo is not a reusable deployment qualification or persistent service.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src"), str(ROOT / "integrations/mcp/src")]

from hobnail.client import Connection, PsqlTransport, TransportError, canonical_json
from hobnail.verifier import verify_candidate
from hobnail_mcp.adapter import OPERATIONS
from hobnail_mcp.client import MCPClientError, WorkerMCPClient
from scripts.dev_cluster import DevCluster
from scripts.install import install
from scripts.local_demo import _bootstrap, _plugins
from scripts.qualified_local import cleanup_credentials, configure_endpoints, secure_admin

GOOD = b'{"available":7,"label":"Owned MCP demonstration"}\n'
BAD = b'{"available":99,"label":"Owned MCP demonstration"}\n'
TRUSTED = b'{"stock":7}'


class MCPDemoError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise MCPDemoError(code)


def document(name, plugins):
    return {"schema_version": 1, "description": "Compare exact report bytes to separately registered synthetic stock",
        "access": {"workers": ["mcp-worker"], "verifiers": ["mcp-verifier"], "observers": ["mcp-observer"],
                   "adapters": {"publish": ["mcp-adapter"]}},
        "subject": {"media_type": "application/json", "max_bytes": 1048576},
        "sources": [{"name": "warehouse", "registrars": ["mcp-registrar"], "require_current": True}],
        "checks": [{"id": "quantity", "plugin": "json.equals", "plugin_digest": plugins["json.equals"],
                    "parameters": {"source": "warehouse", "pairs": [{"artifact": "/available", "input": "/stock"}]},
                    "max_age_seconds": 300}],
        "actions": [{"name": "publish", "plugin": "file.publish", "plugin_digest": plugins["file.publish"],
                     "target": name + ".json", "arguments": {}, "max_age_seconds": 300}],
        "budgets": {"verification": 4, "effects": 4},
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")}


def write_worker_configuration(path, client, *, expected_principal="mcp-worker", timeout_seconds=30):
    value = {"schema_version": 1, "role": "worker", "expected_principal": expected_principal,
             "connection": asdict(client.transport.connection), "psql": str(Path(client.transport.psql).resolve()),
             "timeout_seconds": timeout_seconds, "owned_development": True}
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(canonical_json(value))


async def workflow(cluster, clients, endpoints, receipt, protocol_version, source_server):
    scoped = {role: service.client() for role, service in endpoints.items()}
    plugins = _plugins(scoped["approver"])
    sources = {}
    for name in ("happy", "bad", "stale", "cancel"):
        contract_id = "mcp-" + name
        scoped["worker"].propose_contract(contract_id, 1, document(name, plugins))
        activated = scoped["approver"].activate_contract(contract_id, 1, expected_active_version=None)
        require(activated["ok"], "independent_activation")
        sources[name] = scoped["registrar"].put_input(contract_id, "warehouse", 1, TRUSTED,
            media_type="application/json", expected_current=None)["data"]["snapshot_id"]
    config = cluster.root / "worker-mcp.json"
    write_worker_configuration(config, clients["worker"])
    dotenv = cluster.root / ".env"
    dotenv.write_text("FASTMCP_TELEMETRY_MODE=invalid-owned-read-trap\nFASTMCP_PORT=not-an-integer\n")
    dotenv.chmod(0o000)
    hostile = {"FASTMCP_ENV_FILE": str(dotenv), "FASTMCP_TELEMETRY_MODE": "invalid-owned-env-trap",
               "FASTMCP_TRANSPORT": "http", "FASTMCP_PORT": "not-an-integer",
               "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:1"}
    mcp = WorkerMCPClient(config, log_path=cluster.root / "mcp-stderr.txt", python=sys.executable,
                          source_root=ROOT if source_server else None, protocol_version=protocol_version,
                          environment=hostile)
    try:
        async with mcp:
            tools = await mcp.list_tools()
            require({tool["name"] for tool in tools} == set(OPERATIONS), "seven_worker_tools_only")
            require(all(tool["inputSchema"]["additionalProperties"] is False for tool in tools), "closed_tool_schemas")
            receipt["checks"]["stdio_protocol"] = mcp.negotiated_version
            receipt["checks"]["ambient_settings_did_not_override_stdio_or_prevent_start"] = True
            for name, arguments in (("api", {"op": "contract.activate", "payload": {}}),
                                    ("get_candidate", {"candidate_id": True}),
                                    ("get_candidate", {"candidate_id": "1"}),
                                    ("get_candidate", {"candidate_id": 1, "role": "approver"})):
                try:
                    response = await mcp.call_raw(name, arguments)
                    require(response.get("isError") is True, "malformed_tool_refusal")
                except MCPClientError as error:
                    require(error.code == "MCP_PROTOCOL_ERROR", "malformed_refusal_must_be_protocol")
            receipt["checks"]["malformed_and_privileged_tools_refused"] = True
            forbidden = await mcp.call_tool("get_contract", {"contract_id": "outside-worker-scope"})
            require(not forbidden["ok"] and forbidden["code"] == "SCOPE_MISMATCH", "contract_scope_refusal")
            receipt["checks"]["scope_refusal"] = forbidden
            for name in ("happy", "bad", "stale", "cancel"):
                record = {"name": name, "stage": "started"}
                receipt["scenarios"].append(record)
                content = BAD if name == "bad" else GOOD
                artifact = await mcp.call_tool("put_artifact", {"content_hex": content.hex(), "media_type": "application/json"})
                require(artifact["ok"] and artifact["data"]["digest"] == hashlib.sha256(content).hexdigest(), "exact_artifact_bytes")
                payload = {"contract_id": "mcp-" + name, "artifact_id": artifact["data"]["artifact_id"],
                           "inputs": {"warehouse": sources[name]}, "idempotency_key": name + "-submission"}
                submission = await mcp.call_tool("submit_candidate", payload)
                require(submission["ok"], "candidate_submission")
                candidate_id = submission["data"]["candidate_id"]
                replay = await mcp.call_tool("submit_candidate", payload)
                require(replay["ok"] and replay["data"] == submission["data"], "submission_same_key_replay")
                conflict = await mcp.call_tool("submit_candidate", {**payload, "artifact_id": artifact["data"]["artifact_id"] + 999})
                require(not conflict["ok"] and conflict["code"] == "IDEMPOTENCY_CONFLICT", "submission_key_conflict")
                effect_args = {"candidate_id": candidate_id, "action": "publish", "args": {}, "idempotency_key": name + "-effect"}
                missing = await mcp.call_tool("request_effect", effect_args)
                require(not missing["ok"] and missing["code"] == "MISSING_CHECKS", "missing_verification_refused")
                checked = verify_candidate(scoped["verifier"], candidate_id)
                record.update(submission=submission, replay=replay, conflict=conflict, missing_checks=missing, verification=checked)
                if name == "bad":
                    require(not checked["ok"] and checked["code"] == "CHECK_FAILED", "bad_bytes_refused")
                    refused = await mcp.call_tool("request_effect", effect_args)
                    require(not refused["ok"] and refused["code"] == "CHECK_FAILED", "bad_effect_refused")
                    record["effect"] = refused
                else:
                    require(checked["ok"] and checked["data"]["accepted"], "independent_verification")
                    effect = await mcp.call_tool("request_effect", effect_args)
                    require(effect["ok"], "effect_reservation")
                    effect_id = effect["data"]["effect_id"]
                    repeated = await mcp.call_tool("request_effect", effect_args)
                    require(repeated["ok"] and repeated["data"] == effect["data"], "effect_same_key_replay")
                    record.update(effect=effect, effect_replay=repeated)
                    if name == "stale":
                        updated = scoped["registrar"].put_input("mcp-stale", "warehouse", 2, TRUSTED + b" ",
                            media_type="application/json", expected_current=sources[name])
                        require(updated["ok"], "independent_input_advance")
                    if name == "cancel":
                        cancelled = await mcp.call_tool("cancel_effect", {"effect_id": effect_id})
                        require(cancelled["ok"] and cancelled["data"]["state"] == "cancelled", "existing_effect_cancelled")
                        record["cancellation"] = cancelled
                    dispatched = endpoints["adapter"].dispatch(effect_id)
                    record["dispatch"] = dispatched
                    if name == "happy":
                        require(dispatched["ok"] and dispatched["data"]["state"] == "attempted", "protected_dispatch")
                        observed = endpoints["observer"].observe(effect_id)
                        require(observed["ok"] and observed["data"]["state"] == "complete", "independent_observation")
                        status = await mcp.call_tool("get_effect", {"effect_id": effect_id})
                        require(status["ok"] and status["data"]["state"] == "complete", "worker_observes_real_state")
                        require((cluster.root / "published/happy.json").read_bytes() == GOOD, "actual_destination_bytes")
                        record.update(observation=observed, final_effect=status, output_sha256=hashlib.sha256(GOOD).hexdigest())
                    else:
                        expected = "INPUT_STALE" if name == "stale" else "CANCELLED"
                        require(not dispatched["ok"] and dispatched["code"] == expected, "protected_dispatch_refused")
                if name != "happy":
                    require(not (cluster.root / "published" / (name + ".json")).exists(), "refused_output_absent")
                record["stage"] = "completed"
            require((cluster.root / "published/happy.json").read_bytes() == GOOD, "happy_output_preserved")
    finally:
        receipt["checks"]["mcp_process"] = {"pid": mcp.pid, "closed": mcp.closed, "returncode": mcp.returncode,
                                            "protocol": mcp.negotiated_version}
        dotenv.chmod(0o600)
        require(dotenv.read_text() == "FASTMCP_TELEMETRY_MODE=invalid-owned-read-trap\nFASTMCP_PORT=not-an-integer\n", "dotenv_fixture_preserved")
        receipt["checks"]["owned_dotenv_unreadable_during_server_and_preserved"] = True
    require(mcp.closed and mcp.returncode == 0, "mcp_process_retired")


def run_demo(*, protocol_version="2025-11-25", source_server=False):
    receipt = {"schema": "hobnail-mcp-demo-v1", "status": "incomplete", "qualified": False,
               "scope": "synthetic MCP worker and separately protected native file workflow", "checks": {}, "scenarios": [],
               "runtime_stopped": False, "assumptions": ["Trusted operator/supervisor and host; worker MCP code is trusted.",
                    "No remote MCP, Windows, live-project activation, or production qualification."]}
    cluster = DevCluster()
    receipt["retained_root"] = str(cluster.root)
    receipt["receipt"] = str(cluster.root / "mcp-demo.json")
    stage = "start_owned_database"
    try:
        with cluster:
            stage = "install_protocol"
            install(f"host={cluster.socket_dir} port={cluster.port} dbname={cluster.database} user=postgres", psql=str(cluster.bin_dir / "psql"))
            admin = secure_admin(cluster, PsqlTransport(Connection(str(cluster.socket_dir), cluster.database, "postgres", sslmode="disable"), psql=str(cluster.bin_dir / "psql")))
            stage = "bootstrap_owned_roles"
            clients, provider, leases = _bootstrap(cluster, admin, ["mcp-" + name for name in ("happy", "bad", "stale", "cancel")], sources=("warehouse",), principal_prefix="mcp")
            try:
                destination = cluster.root / "published"
                destination.mkdir(mode=0o700)
                endpoints = configure_endpoints(cluster, clients, destination)
                stage = "actual_mcp_workflow"
                asyncio.run(workflow(cluster, clients, endpoints, receipt, protocol_version, source_server))
                receipt["status"] = "passed"
            finally:
                cleanup_credentials(provider, leases, receipt)
                secrets = [lease.password.reveal() for lease in leases]
                serialized = canonical_json(receipt)
                logs = "".join(path.read_text(errors="replace") for path in (cluster.root / "server.log", cluster.root / "mcp-stderr.txt") if path.exists())
                clean = all(secret not in serialized and secret not in logs for secret in secrets)
                receipt["checks"]["generated_passwords_absent_from_receipt_and_logs"] = clean
                if not clean:
                    receipt["status"] = "failed"
                if admin.execute_sql("ALTER ROLE postgres NOLOGIN; SELECT rolcanlogin FROM pg_roles WHERE rolname='postgres';").strip() != "f":
                    raise MCPDemoError("administrator_retirement_unconfirmed")
                receipt["checks"]["owned_administrator_nologin_before_stop"] = True
    except Exception as error:
        receipt["status"] = "failed"
        receipt["failure"] = {"stage": stage, "type": type(error).__name__}
        if isinstance(error, (MCPDemoError, MCPClientError)):
            receipt["failure"]["code"] = str(error)
    finally:
        try:
            receipt["runtime_stopped"] = not cluster.is_running()
        except Exception as error:
            receipt["cleanup_failure"] = {"type": type(error).__name__}
        if not receipt["runtime_stopped"]:
            receipt["status"] = "failed"
        descriptor = os.open(receipt["receipt"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(receipt, stream, indent=2, allow_nan=False); stream.write("\n")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol-version", choices=("2025-11-25", "2026-07-28"), default="2025-11-25")
    arguments = parser.parse_args(argv)
    result = run_demo(protocol_version=arguments.protocol_version)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
