"""Reusable fresh native application lifecycle, without a new policy format.

The caller is the trusted supervisor. It explicitly approves a full protocol-1
contract, then supplies exact input/artifact bytes for one protected workflow.
The context retires generated credentials, stops only its owned PostgreSQL
runtime and retains a private application receipt. This is not a daemon, a
persistent mission-budget namespace or a reusable deployment qualification seal.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import MappingProxyType
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.dev_cluster import DevCluster
from scripts.install import install
from scripts.local_demo import _bootstrap
from scripts.qualified_local import cleanup_credentials, configure_endpoints, secure_admin
from hobnail.client import Connection, PsqlTransport, canonical_json
from hobnail.contracts import ContractError, IDENTIFIER, validate_contract
from hobnail.deployment import NativeConsumer, endpoint
from hobnail.verifier import verify_candidate


class NativeApplicationError(RuntimeError):
    """A safe application lifecycle refusal, with no credential diagnostics."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _Refused(Exception):
    pass


class NativeApplication:
    def __init__(self, contract_id: str, consumer: NativeConsumer, *, sources: tuple[str, ...], base_dir: str | Path = "/tmp"):
        if not isinstance(contract_id, str) or not IDENTIFIER.fullmatch(contract_id):
            raise ValueError("contract_id must be a protocol identifier")
        if (not isinstance(consumer, NativeConsumer) or not isinstance(sources, tuple) or not 1 <= len(sources) <= 16
                or any(not isinstance(name, str) or not IDENTIFIER.fullmatch(name) for name in sources)
                or len(set(sources)) != len(sources)):
            raise ValueError("an explicit native consumer and unique source tuple are required")
        self.contract_id = contract_id
        self.consumer = consumer
        self.sources = sources
        self.base_dir = base_dir
        self._stack: ExitStack | None = None
        self._cluster: DevCluster | None = None
        self._admin = None
        self._leases = []
        self._active = False
        self._used = False
        self._approved = None
        self._endpoints = {}
        self._scoped = {}
        self._plugin_digests = {}
        roles = ("worker", "registrar", "approver", "verifier", "adapter", "observer", "auditor", "credential_provider")
        self._principals = {role: "application-" + role for role in roles}
        self.receipt = {"status": "incomplete", "contract_id": contract_id, "consumer": consumer.plugin,
                        "scope": "one fresh native application workflow", "qualified": False,
                        "checks": {}, "stages": [], "runtime_stopped": False,
                        "assumptions": ["The caller, bootstrap supervisor and other unsandboxed processes of its OS user are trusted.",
                                        "This fresh runtime does not reset or replace an existing mission's budgets or authority.",
                                        "Profile/source fingerprints are historical evidence, not reusable qualification seals."]}

    @property
    def principals(self):
        return MappingProxyType(self._principals)

    @property
    def plugin_digests(self):
        return MappingProxyType(self._plugin_digests)

    @property
    def worker_client(self):
        self._require_active()
        return self._scoped["worker"]

    def _require_active(self):
        if not self._active:
            raise NativeApplicationError("APPLICATION_NOT_ACTIVE")
        if "failure" in self.receipt:
            raise NativeApplicationError("APPLICATION_FAILED")

    def _failure(self, stage, error):
        failure = {"stage": stage, "kind": type(error).__name__}
        if isinstance(error, (NativeApplicationError, ContractError)):
            failure["code"] = error.code
        if getattr(error, "__notes__", None):
            failure["additional_failure_notes"] = len(error.__notes__)
        self.receipt.setdefault("failure", failure)
        self.receipt["status"] = "failed"

    def _stage(self, name, operation, *, envelope=False):
        entry = {"stage": name, "state": "started"}
        self.receipt["stages"].append(entry)
        try:
            result = operation()
        except BaseException as error:
            entry.update(state="error", kind=type(error).__name__)
            self._failure(name, error)
            raise
        if envelope:
            entry["result"] = result
            entry["state"] = "succeeded" if result["ok"] else "refused"
            if not result["ok"]:
                self.receipt["status"] = "refused"
                raise _Refused()
        else:
            entry["state"] = "succeeded"
        return result

    def __enter__(self):
        if self._stack is not None or self._cluster is not None:
            raise NativeApplicationError("APPLICATION_CANNOT_BE_RESTARTED")
        self._stack = ExitStack()
        try:
            self._cluster = self._stage("allocate_runtime", lambda: DevCluster(base_dir=self.base_dir))
            cluster = self._cluster
            self.receipt["retained_root"] = str(cluster.root)
            self._stage("start_runtime", lambda: self._stack.enter_context(cluster))
            self._stage("install_protocol", lambda: install(
                f"host={cluster.socket_dir} port={cluster.port} dbname={cluster.database} user=postgres",
                psql=str(cluster.bin_dir / "psql")))
            transport = PsqlTransport(Connection(str(cluster.socket_dir), cluster.database, "postgres", sslmode="disable"),
                                      psql=str(cluster.bin_dir / "psql"))
            self._admin = self._stage("require_scram_for_every_login", lambda: secure_admin(cluster, transport))
            clients, provider, self._leases = self._stage("bootstrap_explicit_source_scopes", lambda: _bootstrap(
                cluster, self._admin, [self.contract_id], sources=self.sources, principal_prefix="application"))
            self._stack.callback(cleanup_credentials, provider, self._leases, self.receipt)
            self._endpoints = self._stage("configure_confined_roles", lambda: self._configure(clients))
            self._scoped = {role: service.client() for role, service in self._endpoints.items()}
            self._stage("register_supported_manifests", self._register_plugins)
            self.receipt["profile_fingerprints"] = {role: service.configuration_fingerprint() for role, service in self._endpoints.items()}
            self._active = True
            self.receipt["status"] = "ready_for_owner_approval"
            return self
        except BaseException as error:
            self._failure("setup", error)
            self._shutdown()
            raise NativeApplicationError("SETUP_FAILED") from None

    def _configure(self, clients):
        cluster = self._cluster
        endpoints = configure_endpoints(cluster, clients, self.consumer.roots[0])
        for role in ("adapter", "observer"):
            previous = endpoints[role]
            value = {"role": role, "connection": asdict(clients[role].transport.connection),
                     "psql": clients[role].transport.psql, "consumer": self.consumer.document()}
            # configure_endpoints created these private files in this invocation;
            # no service has started yet and no preexisting user file is replaced.
            descriptor = os.open(previous.policy.config, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(canonical_json(value))
            endpoints[role] = endpoint(role, config=previous.policy.config, scratch=previous.policy.scratch,
                socket_path=previous.policy.socket_path, psql=clients[role].transport.psql,
                package_root=previous.policy.script.parent, consumer=self.consumer)
        return endpoints

    def _register_plugins(self):
        package = self._endpoints["worker"].policy.script.parent
        validator = hashlib.sha256((package / "_validator_worker.py").read_bytes()).hexdigest()
        effects = {"file.publish": ("effects.py", "local-file"), "git.commit": ("git_effects.py", "local-git"),
                   "research.promote": ("integrations/research.py", "research-registry")}
        filename, backend = effects[self.consumer.plugin]
        specifications = {
            "bytes.sha256": ("validator", validator, "isolated-json", {"expected": "approved SHA-256"}),
            "json.required_fields": ("validator", validator, "isolated-json", {"pointers": "required JSON pointers"}),
            "json.equals": ("validator", validator, "isolated-json", {"source": "approved source", "pairs": "exact pointer pairs"}),
            self.consumer.plugin: ("effect", hashlib.sha256((package / filename).read_bytes()).hexdigest(), backend, {}),
        }
        for plugin, (kind, implementation, execution_backend, parameters) in specifications.items():
            capabilities = ["read_artifact", "read_inputs"] if plugin == "json.equals" else ["read_artifact"] if kind == "validator" else ["write_target"]
            result = self._stage("register:" + plugin, lambda plugin=plugin, kind=kind, implementation=implementation,
                                 execution_backend=execution_backend, parameters=parameters, capabilities=capabilities:
                self._scoped["approver"].call("plugin.register", {"plugin_id": plugin, "version": 1, "kind": kind,
                    "manifest": {"implementation": implementation, "execution_backend": execution_backend,
                                 "input_media_types": ["application/json", "application/octet-stream", "text/plain"],
                                 "parameters": parameters, "capabilities": capabilities,
                                 "result_semantics": "mandatory exact declared check" if kind == "validator" else "attempted protected effect"}}),
                envelope=True)
            self._plugin_digests[plugin] = result["data"]["plugin_digest"]

    def _validate_document(self, document):
        document = validate_contract(document, for_activation=True)
        if {source["name"] for source in document["sources"]} != set(self.sources):
            raise NativeApplicationError("SOURCE_SCOPE_MISMATCH")
        for requirement in [*document["checks"], *document["actions"]]:
            plugin = requirement["plugin"]
            if plugin not in self._plugin_digests:
                raise NativeApplicationError("UNSUPPORTED_CAPABILITY")
            if requirement["plugin_digest"] != self._plugin_digests[plugin]:
                raise NativeApplicationError("PLUGIN_MISMATCH")
        if any(action["plugin"] != self.consumer.plugin for action in document["actions"]):
            raise NativeApplicationError("CONSUMER_MISMATCH")
        if self.consumer.plugin == "git.commit" and any(action["target"] not in dict(self.consumer.repositories) for action in document["actions"]):
            raise NativeApplicationError("CONSUMER_MISMATCH")
        return document

    def approve(self, document: Mapping[str, Any]):
        """Explicit trusted-owner step; worker artifact submission cannot call it."""
        self._require_active()
        if self._approved is not None:
            raise NativeApplicationError("POLICY_ALREADY_APPROVED")
        validated = self._stage("validate_owner_contract", lambda: self._validate_document(document))
        try:
            self._stage("propose_owner_contract", lambda: self._scoped["worker"].call("contract.propose", {
                "contract_id": self.contract_id, "version": 1, "document": validated}), envelope=True)
            result = self._stage("separate_owner_activation", lambda: self._scoped["approver"].activate_contract(
                self.contract_id, 1, expected_active_version=None), envelope=True)
        except _Refused:
            return self.receipt
        self._approved = canonical_json(validated)
        self.receipt["approved_policy_digest"] = result["data"]["policy_digest"]
        self.receipt["status"] = "approved"
        return result

    def run(self, *, document: Mapping[str, Any], inputs: Mapping[str, bytes], artifact: bytes, action: str):
        """Run one explicitly approved work item; never retry uncertain effects."""
        self._require_active()
        if self._used:
            raise NativeApplicationError("APPLICATION_ALREADY_USED")
        self._used = True
        try:
            def preflight():
                if self._approved is None:
                    raise NativeApplicationError("OWNER_APPROVAL_REQUIRED")
                validated = self._validate_document(document)
                if canonical_json(validated) != self._approved:
                    raise NativeApplicationError("APPROVED_CONTRACT_CHANGED")
                if (not isinstance(inputs, Mapping) or set(inputs) != set(self.sources)
                        or any(not isinstance(value, bytes) or len(value) > 1048576 for value in inputs.values())
                        or not isinstance(artifact, bytes) or len(artifact) > validated["subject"]["max_bytes"]):
                    raise NativeApplicationError("INVALID_APPLICATION_BYTES")
                selected = next((item for item in validated["actions"] if item["name"] == action), None)
                if selected is None:
                    raise NativeApplicationError("UNKNOWN_APPROVED_ACTION")
                return validated, selected
            validated, selected = self._stage("validate_exact_approved_work", preflight)
            source_ids = {}
            for name in self.sources:
                registered = self._stage("register_input:" + name, lambda name=name: self._scoped["registrar"].put_input(
                    self.contract_id, name, 1, inputs[name], media_type=validated["subject"]["media_type"], expected_current=None), envelope=True)
                source_ids[name] = registered["data"]["snapshot_id"]
            registered = self._stage("register_artifact", lambda: self.worker_client.put_artifact(
                artifact, media_type=validated["subject"]["media_type"]), envelope=True)
            candidate = self._stage("submit_candidate", lambda: self.worker_client.submit(self.contract_id,
                registered["data"]["artifact_id"], source_ids, idempotency_key="application-candidate"), envelope=True)
            candidate_id = candidate["data"]["candidate_id"]
            self._stage("independent_verification", lambda: verify_candidate(self._scoped["verifier"], candidate_id), envelope=True)
            effect = self._stage("reserve_effect", lambda: self.worker_client.request_effect(candidate_id, action,
                selected["arguments"], idempotency_key="application-effect"), envelope=True)
            effect_id = effect["data"]["effect_id"]
            self._stage("confined_dispatch", lambda: self._endpoints["adapter"].dispatch(effect_id), envelope=True)
            observed = self._stage("independent_observation", lambda: self._endpoints["observer"].observe(effect_id), envelope=True)
            state = observed["data"]["state"]
            self.receipt["effect_state"] = state
            self.receipt["status"] = {"complete": "completed", "control_failure": "control_failure",
                                      "failed": "failed"}.get(state, "reconciliation_required")
        except _Refused:
            pass
        except Exception as error:
            self._failure("application_run", error)
        return self.receipt

    def _shutdown(self):
        self._active = False
        if self._stack is not None:
            self.receipt["stages"].append({"stage": "retire_owned_authority_and_runtime", "state": "started"})
            try:
                self._stack.close()
                self.receipt["stages"][-1]["state"] = "succeeded" if self.receipt["checks"].get("all_runtime_credentials_revoked") else "unconfirmed"
            except BaseException as error:
                self.receipt["stages"][-1].update(state="error", kind=type(error).__name__)
                self.receipt.setdefault("cleanup_failures", []).append({"stage": "runtime_cleanup", "kind": type(error).__name__})
                self.receipt["status"] = "failed"
        if self._cluster is None:
            return
        try:
            self.receipt["runtime_stopped"] = not self._cluster.is_running()
        except Exception as error:
            self.receipt["runtime_stopped"] = None
            self.receipt.setdefault("cleanup_failures", []).append({"stage": "runtime_status", "kind": type(error).__name__})
        if self.receipt["runtime_stopped"] is not True:
            self.receipt["status"] = "failed"
        if self.receipt["status"] in {"approved", "ready_for_owner_approval"}:
            self.receipt["status"] = "incomplete"
        try:
            secret_values = [lease.password.reveal() for lease in self._leases if lease.password is not None]
            if self._admin is not None and self._admin.connection.password is not None:
                secret_values.append(self._admin.connection.password)
            serialized = canonical_json(self.receipt)
            log = (self._cluster.root / "server.log").read_text()
            clear = all(secret not in serialized and secret not in log for secret in secret_values)
            clear = clear and "SCRAM-SHA-256$" not in log
            self.receipt["checks"]["generated_credentials_absent_from_receipt_and_log"] = clear
            if not clear:
                self.receipt["status"] = "failed"
                # Keep the failure visible, but never publish a known generated
                # credential in the receipt. Do not rewrite the retained log.
                def redact(value):
                    if isinstance(value, str):
                        for secret in secret_values:
                            value = value.replace(secret, "[redacted-generated-credential]")
                        return value
                    if isinstance(value, dict):
                        return {redact(key): redact(item) for key, item in value.items()}
                    if isinstance(value, list):
                        return [redact(item) for item in value]
                    return value
                safe = redact(self.receipt)
                self.receipt.clear()
                self.receipt.update(safe)
        except Exception as error:
            self.receipt["status"] = "failed"
            self.receipt.setdefault("cleanup_failures", []).append({"stage": "credential_output_check", "kind": type(error).__name__})
        try:
            self._cluster._check_owner()
            self._persist(self._cluster.root / "application.json")
        except Exception as error:
            self.receipt["status"] = "failed"
            self.receipt.setdefault("cleanup_failures", []).append({"stage": "receipt_persistence", "kind": type(error).__name__})
            self.receipt["receipt"] = None
            try:
                fallback = Path(tempfile.mkdtemp(prefix="hobnail-application-failure-"))
                fallback.chmod(0o700)
                self._persist(fallback / "application.json")
            except Exception as fallback_error:
                self.receipt["receipt"] = None
                self.receipt.setdefault("cleanup_failures", []).append({
                    "stage": "fallback_receipt_persistence", "kind": type(fallback_error).__name__})

    def _persist(self, path):
        self.receipt["receipt"] = str(path)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(json.dumps(self.receipt, indent=2, allow_nan=False) + "\n")

    def __exit__(self, exception_type, exception, traceback):
        if exception is not None:
            self._failure("caller", exception)
        self._shutdown()
        return False
