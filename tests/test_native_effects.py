"""Real native Git/research/file consequences with independently confined roles.

Only new owned repositories, synthetic research records and an all-SCRAM private
PostgreSQL cluster are used. This does not activate a live project or study.
"""
from dataclasses import asdict
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.dev_cluster import DevCluster
from scripts.install import install
from scripts.local_demo import _bootstrap, _plugins
from scripts.qualified_local import configure_endpoints, qualification_probe, secure_admin
from hobnail.client import Connection, PsqlTransport, TransportError, canonical_json
from hobnail.deployment import NativeConsumer, endpoint
from hobnail.git_effects import GitBoundaryError, implementation_digest as git_digest
from hobnail.integrations.research import (
    ResearchIdentity, GuardDecision, implementation_digest as research_digest,
    promotion_artifact, request_promotion, reserve_research,
)
from hobnail.verifier import verify_candidate


class NativeEffectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cluster = DevCluster()
        cls.addClassCleanup(cls.cluster.stop)
        cls.cluster.start()
        install(f"host={cls.cluster.socket_dir} port={cls.cluster.port} dbname={cls.cluster.database} user=postgres",
                psql=str(cls.cluster.bin_dir / "psql"))
        transport = PsqlTransport(Connection(str(cls.cluster.socket_dir), cls.cluster.database, "postgres", sslmode="disable"),
                                  psql=str(cls.cluster.bin_dir / "psql"))
        cls.admin = secure_admin(cls.cluster, transport)
        ids = ["native." + name for name in dir(cls) if name.startswith("test_")]
        cls.clients, cls.provider, cls.leases = _bootstrap(cls.cluster, cls.admin, ids)
        cls.addClassCleanup(cls.revoke)
        cls.published = cls.cluster.root / "published"
        cls.published.mkdir(mode=0o700)
        cls.endpoints = configure_endpoints(cls.cluster, cls.clients, cls.published)
        cls.scoped = {name: item.client() for name, item in cls.endpoints.items()}
        cls.plugins = _plugins(cls.scoped["approver"])
        for name, implementation, backend in (("git.commit", git_digest(), "local-git"),
                                               ("research.promote", research_digest(), "research-registry")):
            registered = cls.scoped["approver"].require("plugin.register", {"plugin_id": name, "version": 1, "kind": "effect",
                "manifest": {"implementation": implementation, "input_media_types": ["application/json"],
                             "parameters": {}, "capabilities": ["exact_consumer"], "result_semantics": "attempted",
                             "execution_backend": backend}})
            cls.plugins[name] = registered["data"]["plugin_digest"]
        # Resolve Apple's existing real executable in the supervisor; the service
        # cannot execute xcrun or a general launcher to obtain new authority.
        cls.git = Path(subprocess.run(["/usr/bin/xcrun", "--find", "git"], check=True,
                        capture_output=True, text=True).stdout.strip()).resolve()
        print("Native effect evidence retained:", cls.cluster.root)

    @classmethod
    def revoke(cls):
        for lease in cls.leases:
            observed = cls.provider.revoke(lease.lease_ref)
            if observed.result != "confirmed":
                raise AssertionError("owned native role revocation was not confirmed")

    def setUp(self):
        self.cid = "native." + self._testMethodName
        self.root = self.cluster.root / self._testMethodName
        self.root.mkdir(mode=0o700)
        self.consumer_endpoints = {}

    def git_call(self, repo, *arguments):
        return subprocess.run([str(self.git), "-C", str(repo), *arguments], check=True,
                              capture_output=True, timeout=15).stdout

    def repository(self):
        repo = self.root / "repository"
        repo.mkdir(mode=0o700)
        self.git_call(repo, "init", "-q", "-b", "main")
        self.git_call(repo, "config", "user.name", "Hobnail Native Test")
        self.git_call(repo, "config", "user.email", "native-fixture@example.invalid")
        (repo / "result.txt").write_bytes(b"before\n")
        self.git_call(repo, "add", "result.txt")
        self.git_call(repo, "commit", "-qm", "Owned initial state")
        base = self.git_call(repo, "rev-parse", "HEAD").decode().strip()
        consumer = NativeConsumer.git({"fixture": repo}, executable=self.git)
        arguments = {"branch": "main", "base_commit": base, "paths": ["result.txt"], "message": "Admit exact native bytes"}
        content = canonical_json({"result.txt": b"after\n".hex()}).encode()
        return repo, consumer, arguments, content

    def configure(self, consumer):
        for role in ("adapter", "observer"):
            scratch = self.root / (role + "-scratch")
            scratch.mkdir(mode=0o700)
            config = self.root / (role + ".json")
            value = {"role": role, "connection": asdict(self.clients[role].transport.connection),
                     "psql": self.admin.psql, "consumer": consumer.document()}
            with config.open("x") as stream:
                os.chmod(stream.name, 0o600)
                stream.write(canonical_json(value))
            self.consumer_endpoints[role] = endpoint(role, config=config, scratch=scratch,
                socket_path=self.cluster.socket_dir / f".s.PGSQL.{self.cluster.port}", psql=self.admin.psql,
                package_root=self.endpoints[role].policy.script.parent, consumer=consumer)

    def contract(self, plugin, target, arguments):
        document = {"schema_version": 1,
            "access": {"workers": ["demo-worker"], "verifiers": ["demo-verifier"],
                       "observers": ["demo-observer"], "adapters": {"deliver": ["demo-adapter"]}},
            "subject": {"media_type": "application/json", "max_bytes": 1048576},
            "sources": [{"name": "orders", "registrars": ["demo-registrar"], "require_current": True}],
            "checks": [{"id": "exact-approved-record", "plugin": "json.equals", "plugin_digest": self.plugins["json.equals"],
                        "parameters": {"source": "orders", "pairs": [{"artifact": "", "input": ""}]}, "max_age_seconds": 300}],
            "actions": [{"name": "deliver", "plugin": plugin, "plugin_digest": self.plugins[plugin],
                         "target": target, "arguments": arguments, "max_age_seconds": 300}],
            "budgets": {"verification": 10, "effects": 10, "research": 4}, "expires_at": "2099-01-01T00:00:00Z"}
        self.scoped["worker"].propose_contract(self.cid, 1, document)
        activated = self.scoped["approver"].activate_contract(self.cid, 1, expected_active_version=None)
        self.assertTrue(activated["ok"], activated)
        self.arguments = arguments
        self.document = document

    def candidate(self, content, *, trusted=None):
        source = self.scoped["registrar"].put_input(self.cid, "orders", 1, content if trusted is None else trusted,
                    media_type="application/json", expected_current=None)
        self.assertTrue(source["ok"], source)
        self.source = source["data"]
        artifact = self.scoped["worker"].put_artifact(content, media_type="application/json")
        self.assertTrue(artifact["ok"], artifact)
        submitted = self.scoped["worker"].submit(self.cid, artifact["data"]["artifact_id"],
                    {"orders": self.source["snapshot_id"]}, idempotency_key=self.cid + ":candidate")
        self.assertTrue(submitted["ok"], submitted)
        self.candidate_id = submitted["data"]["candidate_id"]
        return verify_candidate(self.scoped["verifier"], self.candidate_id)

    def request(self, *, arguments=None):
        return self.scoped["worker"].request_effect(self.candidate_id, "deliver",
                self.arguments if arguments is None else arguments, idempotency_key=self.cid + ":delivery")

    def denied_writes(self, target):
        original = target.read_bytes()
        for role, service in (("worker", self.endpoints["worker"]), ("observer", self.consumer_endpoints["observer"])):
            result = qualification_probe(service, {"marker": str(target)})
            self.assertIs(result["marker_write_denied"], True, role)
            self.assertEqual(target.read_bytes(), original)

    def test_git_native_exact_commit_separate_observation_and_write_denials(self):
        repo, consumer, arguments, content = self.repository()
        self.configure(consumer)
        self.contract("git.commit", "fixture", arguments)
        self.denied_writes(repo / "result.txt")
        accepted = self.candidate(content)
        self.assertTrue(accepted["ok"], accepted)
        effect = self.request()
        self.assertTrue(effect["ok"], effect)
        effect_id = effect["data"]["effect_id"]
        dispatched = self.consumer_endpoints["adapter"].dispatch(effect_id)
        self.assertTrue(dispatched["ok"], dispatched)
        self.assertEqual(dispatched["data"]["state"], "attempted", dispatched)
        observed = self.consumer_endpoints["observer"].observe(effect_id)
        self.assertTrue(observed["ok"], observed)
        self.assertEqual(observed["data"]["state"], "complete", observed)
        self.assertEqual((repo / "result.txt").read_bytes(), b"after\n")
        self.assertEqual(self.git_call(repo, "rev-parse", "HEAD^").decode().strip(), arguments["base_commit"])
        self.assertEqual(self.git_call(repo, "status", "--porcelain"), b"")
        self.assertEqual(self.git_call(repo, "rev-list", "--count", "HEAD").strip(), b"2")
        again = self.consumer_endpoints["adapter"].dispatch(effect_id)
        self.assertFalse(again["ok"])
        self.assertEqual(again["code"], "RECONCILIATION_REQUIRED")
        self.assertEqual(self.git_call(repo, "rev-list", "--count", "HEAD").strip(), b"2")

    def test_git_nonadmitted_changed_arguments_and_stale_source_refuse(self):
        repo, consumer, arguments, content = self.repository()
        self.configure(consumer)
        self.contract("git.commit", "fixture", arguments)
        self.candidate(content)
        changed = self.request(arguments={**arguments, "message": "unauthorized different message"})
        self.assertFalse(changed["ok"])
        self.assertEqual(changed["code"], "ACTION_MISMATCH")
        effect = self.request()
        self.assertTrue(effect["ok"], effect)
        advanced = self.scoped["registrar"].put_input(self.cid, "orders", 2, content + b" ",
                    media_type="application/json", expected_current=self.source["snapshot_id"])
        self.assertTrue(advanced["ok"], advanced)
        dispatched = self.consumer_endpoints["adapter"].dispatch(effect["data"]["effect_id"])
        self.assertFalse(dispatched["ok"])
        self.assertEqual(dispatched["code"], "INPUT_STALE")
        self.assertEqual(self.git_call(repo, "rev-parse", "HEAD").decode().strip(), arguments["base_commit"])
        self.assertEqual((repo / "result.txt").read_bytes(), b"before\n")

    def test_git_changed_worktree_is_preserved_as_uncertain(self):
        repo, consumer, arguments, content = self.repository()
        self.configure(consumer)
        self.contract("git.commit", "fixture", arguments)
        self.candidate(content)
        effect = self.request()
        (repo / "result.txt").write_bytes(b"concurrent work\n")
        dispatched = self.consumer_endpoints["adapter"].dispatch(effect["data"]["effect_id"])
        self.assertTrue(dispatched["ok"], dispatched)
        self.assertEqual(dispatched["data"]["state"], "uncertain")
        self.assertEqual((repo / "result.txt").read_bytes(), b"concurrent work\n")
        self.assertEqual(self.git_call(repo, "rev-parse", "HEAD").decode().strip(), arguments["base_commit"])
        observation = self.consumer_endpoints["observer"].observe(effect["data"]["effect_id"])
        self.assertNotEqual(observation["data"]["state"], "complete")

    def test_git_global_controls_cannot_disappear_in_service_environment(self):
        repo, consumer, arguments, content = self.repository()
        xdg = self.root / "owned-xdg"
        (xdg / "git").mkdir(parents=True, mode=0o700)
        config = xdg / "git" / "config"
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}):
            self.configure(consumer)
            for declaration in (
                "[core]\n hooksPath = /owned/synthetic-hook-directory\n",
                "[filter \"controlled\"]\n clean = false\n",
                "[commit]\n gpgSign = true\n",
                "[include]\n path = /owned/synthetic-config\n",
            ):
                config.write_text(declaration)
                with self.subTest(declaration=declaration), self.assertRaises(GitBoundaryError):
                    endpoint("adapter", config=self.consumer_endpoints["adapter"].policy.config,
                        scratch=self.consumer_endpoints["adapter"].policy.scratch,
                        socket_path=self.consumer_endpoints["adapter"].policy.socket_path, psql=self.admin.psql,
                        package_root=self.endpoints["adapter"].policy.script.parent, consumer=consumer)
            config.write_text("")
            self.contract("git.commit", "fixture", arguments)
            self.assertTrue(self.candidate(content)["ok"])
            effect = self.request()
            self.assertTrue(effect["ok"], effect)
            config.write_text("[core]\n hooksPath = /owned/synthetic-hook-directory\n")
            with self.assertRaises(GitBoundaryError):
                self.consumer_endpoints["adapter"].request({"command": "git.dispatch", "effect_id": effect["data"]["effect_id"]})
            self.assertEqual(self.scoped["worker"].effect(effect["data"]["effect_id"])["data"]["state"], "reserved")
        self.assertEqual(self.git_call(repo, "rev-parse", "HEAD").decode().strip(), arguments["base_commit"])
        self.assertEqual((repo / "result.txt").read_bytes(), b"before\n")

    def test_git_new_path_default_global_attributes_refuse_before_dispatch(self):
        repo, consumer, arguments, _ = self.repository()
        arguments["paths"] = ["new-only.txt"]
        content = canonical_json({"new-only.txt": b"new content".hex()}).encode()
        xdg = self.root / "owned-xdg"
        (xdg / "git").mkdir(parents=True, mode=0o700)
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}):
            self.configure(consumer)
            self.contract("git.commit", "fixture", arguments)
            self.assertTrue(self.candidate(content)["ok"])
            effect = self.request()
            (xdg / "git" / "attributes").write_text("new-only.txt filter=controlled\n")
            with self.assertRaises(GitBoundaryError):
                self.consumer_endpoints["adapter"].dispatch(effect["data"]["effect_id"])
            self.assertEqual(self.scoped["worker"].effect(effect["data"]["effect_id"])["data"]["state"], "reserved")
        self.assertFalse((repo / "new-only.txt").exists())
        self.assertEqual(self.git_call(repo, "rev-parse", "HEAD").decode().strip(), arguments["base_commit"])

    def test_git_failed_exact_check_cannot_reserve_a_native_commit(self):
        repo, consumer, arguments, content = self.repository()
        self.configure(consumer)
        self.contract("git.commit", "fixture", arguments)
        bad = canonical_json({"result.txt": b"unapproved bytes".hex()}).encode()
        acceptance = self.candidate(bad, trusted=content)
        self.assertFalse(acceptance["ok"])
        self.assertEqual(acceptance["code"], "CHECK_FAILED")
        refused = self.request()
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["code"], "CHECK_FAILED")
        self.assertEqual(self.git_call(repo, "rev-parse", "HEAD").decode().strip(), arguments["base_commit"])
        self.assertEqual((repo / "result.txt").read_bytes(), b"before\n")

    def research(self):
        directory = self.root / "registry"
        directory.mkdir(mode=0o700)
        consumer = NativeConsumer.research(directory)
        self.configure(consumer)
        identity = ResearchIdentity.from_fingerprints(study="synthetic-native-study", protocol_digest="a" * 64,
            evaluator_digest="b" * 64, candidate_digest="c" * 64, consumed_inputs={"synthetic": "d" * 64},
            domain_identity_digest="e" * 64)
        target = identity.digest + ".json"
        self.contract("research.promote", target, {})
        admission = reserve_research(self.scoped["worker"], self.cid, identity,
            lambda identity, reservation: GuardDecision(True, identity.domain_identity_digest, "f" * 64, "synthetic_reserved"))
        self.assertTrue(admission.allowed)
        content = promotion_artifact(admission, evaluation_digest="1" * 64, outcome="pass")
        return directory, target, content, admission

    def test_research_native_create_only_observed_record_and_write_denials(self):
        directory, target, content, admission = self.research()
        marker = directory / "controlled-marker"
        marker.write_bytes(b"unchanged")
        self.denied_writes(marker)
        self.assertTrue(self.candidate(content)["ok"])
        effect = request_promotion(self.scoped["worker"], self.candidate_id, admission,
                                   evaluation_digest="1" * 64, action="deliver")
        self.assertTrue(effect["ok"], effect)
        dispatched = self.consumer_endpoints["adapter"].dispatch(effect["data"]["effect_id"])
        self.assertEqual(dispatched["data"]["state"], "attempted", dispatched)
        observed = self.consumer_endpoints["observer"].observe(effect["data"]["effect_id"])
        self.assertEqual(observed["data"]["state"], "complete", observed)
        self.assertEqual((directory / target).read_bytes(), content)
        self.assertEqual(marker.read_bytes(), b"unchanged")
        with self.assertRaises(TransportError):
            self.consumer_endpoints["observer"].request({"command": "research.dispatch", "effect_id": effect["data"]["effect_id"]})
        with self.assertRaises(TransportError):
            self.consumer_endpoints["adapter"].request({"command": "file.dispatch", "effect_id": effect["data"]["effect_id"]})
        self.assertEqual((directory / target).read_bytes(), content)

    def test_research_nonadmitted_and_stale_work_produce_no_record(self):
        directory, target, content, _ = self.research()
        changed = json.loads(content)
        changed["evaluation_digest"] = "2" * 64
        bad = canonical_json(changed).encode()
        refused = self.candidate(bad, trusted=content)
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["code"], "CHECK_FAILED")
        effect = self.request()
        self.assertFalse(effect["ok"])
        self.assertEqual(effect["code"], "CHECK_FAILED")
        self.assertFalse((directory / target).exists())

    def test_research_stale_registered_source_cannot_create_record(self):
        directory, target, content, _ = self.research()
        self.assertTrue(self.candidate(content)["ok"])
        effect = self.request()
        self.assertTrue(effect["ok"], effect)
        update = self.scoped["registrar"].put_input(self.cid, "orders", 2, content + b" ",
            media_type="application/json", expected_current=self.source["snapshot_id"])
        self.assertTrue(update["ok"], update)
        refused = self.consumer_endpoints["adapter"].dispatch(effect["data"]["effect_id"])
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["code"], "INPUT_STALE")
        self.assertFalse((directory / target).exists())

    def test_research_existing_different_record_is_preserved(self):
        directory, target, content, _ = self.research()
        self.candidate(content)
        effect = self.request()
        (directory / target).write_bytes(b"existing independent record")
        dispatched = self.consumer_endpoints["adapter"].dispatch(effect["data"]["effect_id"])
        self.assertEqual(dispatched["data"]["state"], "uncertain", dispatched)
        self.assertEqual((directory / target).read_bytes(), b"existing independent record")
        observed = self.consumer_endpoints["observer"].observe(effect["data"]["effect_id"])
        self.assertNotEqual(observed["data"]["state"], "complete")

    def test_legacy_file_route_still_dispatches_and_observes_exact_work(self):
        content = b'{"unchanged_interface":true}'
        self.contract("file.publish", "legacy.json", {})
        self.candidate(content)
        effect = self.request()
        self.assertEqual(self.endpoints["adapter"].dispatch(effect["data"]["effect_id"])["data"]["state"], "attempted")
        self.assertEqual(self.endpoints["observer"].observe(effect["data"]["effect_id"])["data"]["state"], "complete")
        self.assertEqual((self.published / "legacy.json").read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
