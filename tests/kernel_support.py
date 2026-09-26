"""Independent protocol-test setup with real restricted PostgreSQL logins.

All data and identities are synthetic and belong to one disposable cluster.
Private socket trust establishes database authorization behavior, not operating
system or credential-provider isolation. Test-authored verdicts exercise the
kernel's acceptance boundary; they do not qualify a production evaluator.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.dev_cluster import DevCluster


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def api_sql(operation: str, payload: object) -> str:
    serialized = json.dumps(payload, allow_nan=False, separators=(",", ":"))
    return "SELECT hobnail.api(%s, %s::jsonb);" % (sql_literal(operation), sql_literal(serialized))


class KernelCase(unittest.TestCase):
    """Contract-derived assertions independent of the Python SDK transport."""

    @classmethod
    def setUpClass(cls) -> None:
        from scripts.install import install

        cls.cluster = DevCluster()
        cls.addClassCleanup(cls.cluster.stop)
        cls.cluster.start()
        dsn = (f"host={cls.cluster.socket_dir} port={cls.cluster.port} "
               f"dbname={cls.cluster.database} user=postgres")
        cls.installation = install(dsn, psql=str(cls.cluster.bin_dir / "psql"))
        cls.contract_ids = ["accept." + name + suffix for name in dir(cls)
                            if name.startswith("test_") for suffix in ("", ".other")]
        cls.logins = {
            "worker": ("accept_worker", "independent-worker", "worker"),
            "rotated": ("accept_rotated", "independent-worker", "worker"),
            "other_worker": ("accept_other_worker", "other-worker", "worker"),
            "registrar": ("accept_registrar", "independent-registrar", "registrar"),
            "verifier": ("accept_verifier", "independent-verifier", "verifier"),
            "approver": ("accept_approver", "independent-approver", "approver"),
            "adapter": ("accept_adapter", "independent-adapter", "adapter"),
            "observer": ("accept_observer", "independent-observer", "observer"),
            "auditor": ("accept_auditor", "independent-auditor", "auditor"),
            "self_verifier": ("accept_self_verifier", "independent-worker", "verifier"),
            "self_registrar": ("accept_self_registrar", "independent-worker", "registrar"),
            "self_observer": ("accept_self_observer", "independent-worker", "observer"),
            "adapter_observer": ("accept_adapter_observer", "independent-adapter", "observer"),
        }
        for login, principal, role in cls.logins.values():
            cls.cluster.psql(f'CREATE ROLE "{login}" LOGIN;')
            binding = {"login": login, "principal": principal, "role": role,
                       "contracts": cls.contract_ids, "sources": ["orders"], "profiles": []}
            response = cls.raw_api("postgres", "principal.bind", binding)
            if response.get("ok") is not True:
                raise AssertionError(f"synthetic principal setup refused: {response}")
        cls.cluster.psql("CREATE ROLE accept_unknown LOGIN;")
        cls.plugin_digests = {}
        for plugin, kind, file in (
                ("json.equals", "validator", "_validator_worker.py"),
                ("json.required_fields", "validator", "_validator_worker.py"),
                ("file.publish", "effect", "effects.py")):
            manifest = {
                "implementation": hashlib.sha256((ROOT / "src" / "hobnail" / file).read_bytes()).hexdigest(),
                "input_media_types": ["application/json"], "parameters": {},
                "capabilities": [], "result_semantics": "deterministic protocol probe",
                "execution_backend": "isolated-json" if kind == "validator" else "local-file",
            }
            response = cls.raw_api(cls.logins["approver"][0], "plugin.register",
                                   {"plugin_id": plugin, "version": 1, "kind": kind,
                                    "manifest": manifest})
            if response.get("ok") is not True:
                raise AssertionError(f"plugin registration refused: {response}")
            cls.plugin_digests[plugin] = response["data"]["plugin_digest"]

    @classmethod
    def raw_api(cls, login: str, operation: str, payload: object) -> dict:
        result = cls.cluster.psql(api_sql(operation, payload), user=login)
        rows = [line for line in result.stdout.splitlines() if line.strip()]
        if len(rows) != 1:
            raise AssertionError(f"expected one JSON API result, received {result.stdout!r}")
        return json.loads(rows[0])

    def api(self, role: str, operation: str, payload: object) -> dict:
        response = self.raw_api(self.logins[role][0], operation, payload)
        self.assertIs(type(response.get("ok")), bool, response)
        self.assertIs(type(response.get("event_id")), int, response)
        self.assertGreater(response["event_id"], 0)
        return response

    def ok(self, role: str, operation: str, payload: object) -> dict:
        response = self.api(role, operation, payload)
        self.assertTrue(response["ok"], (operation, response))
        self.assertIsInstance(response.get("data"), dict)
        return response["data"]

    def denied(self, role: str, operation: str, payload: object, code: str | None = None) -> dict:
        response = self.api(role, operation, payload)
        self.assertFalse(response["ok"], (operation, payload, response))
        self.assertEqual(response.get("status"), "denied")
        if code is not None:
            self.assertEqual(response.get("code"), code, response)
        else:
            self.assertIsInstance(response.get("code"), str)
        return response

    def setUp(self) -> None:
        self.cid = "accept." + self._testMethodName
        self.version = 1
        self.document = {
            "schema_version": 1, "description": "Independent kernel acceptance probes",
            "access": {"workers": ["independent-worker", "other-worker"],
                       "verifiers": ["independent-verifier"],
                       "observers": ["independent-observer"],
                       "adapters": {"publish": ["independent-adapter"]}},
            "subject": {"media_type": "application/json", "max_bytes": 1048576},
            "sources": [{"name": "orders", "registrars": ["independent-registrar"],
                         "require_current": True}],
            "checks": [
                {"id": "metrics", "plugin": "json.equals", "plugin_digest": self.plugin_digests["json.equals"],
                 "parameters": {"source": "orders", "pairs": [{"artifact": "/orders", "input": "/orders"}]},
                 "max_age_seconds": 300},
                {"id": "shape", "plugin": "json.required_fields", "plugin_digest": self.plugin_digests["json.required_fields"],
                 "parameters": {"pointers": ["/orders", "/period"]}, "max_age_seconds": 300},
            ],
            "actions": [{"name": "publish", "plugin": "file.publish",
                         "plugin_digest": self.plugin_digests["file.publish"],
                         "target": "reports/current.json", "arguments": {}, "max_age_seconds": 300}],
            "budgets": {"verification": 30, "effects": 20, "research": 10},
            "expires_at": "2099-01-01T00:00:00Z",
        }
        self.propose_activate(self.document, version=1, expected=None)
        self.content = b'{"orders":2,"period":"2026-09"}'
        self.source = self.put_input(1, self.content, expected=None)
        self.artifact = self.put_artifact(self.content)

    def propose_activate(self, document: dict, *, version: int, expected: int | None) -> dict:
        self.ok("worker", "contract.propose", {"contract_id": self.cid, "version": version, "document": document})
        return self.ok("approver", "contract.activate", {"contract_id": self.cid, "version": version,
                                                         "expected_active_version": expected})

    def amend(self, document: dict) -> None:
        self.propose_activate(document, version=self.version + 1, expected=self.version)
        self.version += 1
        self.document = copy.deepcopy(document)

    def put_artifact(self, content: bytes, role: str = "worker", media_type: str = "application/json") -> dict:
        return self.ok(role, "artifact.put", {"content_hex": content.hex(), "media_type": media_type})

    def put_input(self, version: int, content: bytes, *, expected: int | None, role: str = "registrar") -> dict:
        return self.ok(role, "input.put", {"contract_id": self.cid, "source": "orders", "version": version,
                      "content_hex": content.hex(), "media_type": "application/json", "expected_current": expected})

    def submission(self, key: str = "candidate", artifact: dict | None = None,
                   source: dict | None = None) -> dict:
        return {"contract_id": self.cid, "artifact_id": (artifact or self.artifact)["artifact_id"],
                "inputs": {"orders": (source or self.source)["snapshot_id"]},
                "idempotency_key": self.cid + ":" + key}

    def submit(self, key: str = "candidate", artifact: dict | None = None, source: dict | None = None) -> dict:
        return self.ok("worker", "candidate.submit", self.submission(key, artifact, source))

    def claim(self, candidate: dict, *, seconds: int = 60) -> dict:
        return self.ok("verifier", "verification.claim", {"candidate_id": candidate["candidate_id"],
                                                         "lease_seconds": seconds})

    def result_payload(self, candidate: dict, claim: dict, check: str = "metrics", result: str = "pass") -> dict:
        plugin = next(row["plugin_digest"] for row in self.document["checks"] if row["id"] == check)
        return {"candidate_id": candidate["candidate_id"], "token": claim["token"],
                "generation": claim["generation"], "binding_digest": claim["binding_digest"],
                "check_id": check, "plugin_digest": plugin, "result": result,
                "detail": {"probe": "independent_kernel_protocol"}}

    def record(self, candidate: dict, claim: dict, check: str = "metrics", result: str = "pass") -> dict:
        return self.ok("verifier", "verification.record", self.result_payload(candidate, claim, check, result))

    def passing_candidate(self, key: str = "candidate") -> dict:
        candidate = self.submit(key)
        claim = self.claim(candidate)
        self.assertEqual(bytes.fromhex(claim["artifact"]["content_hex"]), self.content)
        self.assertEqual(claim["artifact"]["digest"], hashlib.sha256(self.content).hexdigest())
        for check in self.document["checks"]:
            self.record(candidate, claim, check["id"])
        self.ok("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]})
        return candidate

    def request_effect(self, candidate: dict, key: str = "effect") -> dict:
        return self.ok("worker", "effect.request", {"candidate_id": candidate["candidate_id"], "action": "publish",
                                                     "args": {}, "idempotency_key": self.cid + ":" + key})

    def claim_effect(self, effect: dict, *, seconds: int = 60) -> dict:
        return self.ok("adapter", "effect.claim", {"effect_id": effect["effect_id"], "lease_seconds": seconds})

    @staticmethod
    def dispatch_payload(effect: dict, claim: dict) -> dict:
        return {"effect_id": effect["effect_id"], "token": claim["token"], "generation": claim["generation"]}

    def observe_payload(self, effect: dict, outcome: str = "complete", digest: str | None = None) -> dict:
        return {"effect_id": effect["effect_id"], "outcome": outcome,
                "artifact_digest": digest if digest is not None else self.artifact["digest"],
                "receipt": {"probe": "independent_consumer_read"}}
