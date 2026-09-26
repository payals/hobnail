"""Actual local Git consequences and protected SQL lifecycle; no remote actions."""
from __future__ import annotations

import hashlib
import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from hobnail.client import Client, Connection, PsqlTransport, TransportError
from hobnail.git_effects import (
    GitBoundaryError, GitCommitter, GitObserver, _Repository,
    dispatch_git, implementation_digest, observe_git, validate_action,
)
from kernel_support import KernelCase


class GitFixture:
    def make_repo(self):
        directory = tempfile.TemporaryDirectory(prefix="hobnail-git-test-")
        self.addCleanup(directory.cleanup)
        self.repo = Path(directory.name).resolve() / "repository"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Hobnail Synthetic Fixture")
        self.git("config", "user.email", "hobnail-fixture@example.invalid")
        (self.repo / "a.txt").write_bytes(b"before\n")
        (self.repo / "untouched.txt").write_bytes(b"preserve\n")
        self.git("add", "a.txt", "untouched.txt")
        self.git("commit", "-qm", "fixture base")
        self.base = self.git("rev-parse", "HEAD").decode().strip()
        self.arguments = {"branch": "main", "base_commit": self.base,
                          "paths": ["a.txt", "new.txt"], "message": "Apply accepted maintenance"}
        self.bundle = {"a.txt": b"after\n".hex(), "new.txt": b"new exact bytes\x00\xff".hex()}
        self.content = json.dumps(self.bundle, sort_keys=True).encode()
        self.digest = hashlib.sha256(self.content).hexdigest()
        self.committer = GitCommitter({"fixture": self.repo})
        self.observer = GitObserver({"fixture": self.repo})
        self.binding = "a" * 64

    def git(self, *args, source=None):
        return subprocess.run(["git", "-C", str(self.repo), *args], input=source,
                              capture_output=True, check=True, timeout=15).stdout

    def commit(self):
        return self.committer.commit("fixture", self.content, self.digest, self.arguments,
                                     effect_id=1, binding_digest=self.binding)

    def observe(self):
        return self.observer.observe("fixture", self.content, self.digest, self.arguments,
                                     effect_id=1, binding_digest=self.binding)


class GitAdapterTests(GitFixture, unittest.TestCase):
    def setUp(self):
        self.make_repo()

    def test_commits_exact_tree_parent_message_and_preserves_configured_identity(self):
        untouched = (self.repo / "untouched.txt").stat()
        os.chmod(self.repo / "a.txt", 0o600)
        receipt = self.commit()
        head = self.git("rev-parse", "HEAD").decode().strip()
        self.assertEqual(head, receipt["commit"])
        self.assertEqual(self.git("rev-parse", "HEAD^{}").decode().strip(), head)
        self.assertEqual(self.git("rev-parse", "HEAD^").decode().strip(), self.base)
        self.assertEqual(self.git("show", "--format=%B", "--no-patch", "HEAD").decode().strip(), self.arguments["message"])
        self.assertEqual(self.git("show", "--format=%an <%ae>", "--no-patch", "HEAD").decode().strip(),
                         "Hobnail Synthetic Fixture <hobnail-fixture@example.invalid>")
        self.assertEqual((self.repo / "a.txt").read_bytes(), b"after\n")
        self.assertEqual((self.repo / "new.txt").read_bytes(), bytes.fromhex(self.bundle["new.txt"]))
        self.assertEqual(stat.S_IMODE((self.repo / "a.txt").stat().st_mode), 0o600)
        self.assertEqual((self.repo / "untouched.txt").stat().st_ino, untouched.st_ino)
        self.assertEqual((self.repo / "untouched.txt").stat().st_mtime_ns, untouched.st_mtime_ns)
        self.assertEqual(self.git("status", "--porcelain"), b"")
        self.assertEqual(self.observe()["outcome"], "complete")

    def test_repeat_reconciles_real_commit_without_a_duplicate(self):
        first = self.commit()
        second = self.commit()
        self.assertEqual(first["commit"], second["commit"])
        self.assertTrue(second["reconciled"])
        self.assertEqual(self.git("rev-list", "--count", "HEAD").strip(), b"2")

    def test_dirty_worktree_and_staged_changes_are_preserved(self):
        (self.repo / "untouched.txt").write_bytes(b"another session\n")
        self.git("add", "untouched.txt")
        original_index = (self.repo / ".git/index").read_bytes()
        with self.assertRaises(GitBoundaryError):
            self.commit()
        self.assertEqual((self.repo / ".git/index").read_bytes(), original_index)
        self.assertEqual((self.repo / "untouched.txt").read_bytes(), b"another session\n")
        self.assertEqual((self.repo / "a.txt").read_bytes(), b"before\n")
        self.assertEqual(self.git("rev-parse", "HEAD").decode().strip(), self.base)

    def test_wrong_base_and_branch_refuse_before_mutation(self):
        self.arguments["base_commit"] = "0" * 40
        with self.assertRaises(GitBoundaryError):
            self.commit()
        self.arguments.update(base_commit=self.base, branch="other")
        with self.assertRaises(GitBoundaryError):
            self.commit()
        self.assertEqual(self.git("status", "--porcelain"), b"")

    def test_executable_hook_refuses_without_executing_or_disabling_it(self):
        marker = self.repo.parent / "hook-executed"
        hook = self.repo / ".git/hooks/pre-commit"
        content = b"#!/bin/sh\nprintf ran > '" + os.fsencode(marker) + b"'\n"
        hook.write_bytes(content)
        hook.chmod(0o700)
        with self.assertRaises(GitBoundaryError):
            self.commit()
        self.assertFalse(marker.exists())
        self.assertEqual(hook.read_bytes(), content)
        self.assertTrue(os.access(hook, os.X_OK))

    def test_filter_and_attributes_refuse_without_running_filter(self):
        marker = self.repo.parent / "filter-executed"
        self.git("config", "filter.synthetic.clean", "touch " + str(marker))
        with self.assertRaises(GitBoundaryError):
            self.commit()
        self.assertFalse(marker.exists())
        self.git("config", "--unset", "filter.synthetic.clean")
        attributes = self.repo / ".gitattributes"
        attributes.write_text("*.txt text\n")
        self.git("add", ".gitattributes")
        self.git("commit", "-qm", "fixture attributes")
        self.arguments["base_commit"] = self.git("rev-parse", "HEAD").decode().strip()
        with self.assertRaises(GitBoundaryError):
            self.commit()

    def test_administrative_symlink_refuses_without_outside_writes(self):
        original = self.repo / ".git/objects"
        outside = self.repo.parent / "objects"
        original.rename(outside)
        original.symlink_to(outside, target_is_directory=True)
        before = sorted(str(path.relative_to(outside)) for path in outside.rglob("*"))
        with self.assertRaises(GitBoundaryError):
            self.commit()
        self.assertEqual(sorted(str(path.relative_to(outside)) for path in outside.rglob("*")), before)

    def test_packed_replace_refs_are_refused(self):
        tree = self.git("rev-parse", "HEAD^{tree}").decode().strip()
        replacement = self.git("commit-tree", tree, source=b"replacement fixture\n").decode().strip()
        self.git("replace", self.base, replacement)
        self.git("pack-refs", "--all", "--prune")
        with self.assertRaises(GitBoundaryError):
            self.commit()
        self.assertEqual((self.repo / "a.txt").read_bytes(), b"before\n")

    def test_existing_index_lock_belongs_to_other_writer_and_is_preserved(self):
        lock = self.repo / ".git/index.lock"
        lock.write_bytes(b"another session owns this lock")
        inode = lock.stat().st_ino
        with self.assertRaises(FileExistsError):
            self.commit()
        self.assertEqual(lock.read_bytes(), b"another session owns this lock")
        self.assertEqual(lock.stat().st_ino, inode)
        self.assertFalse((self.repo / ".git/hobnail-adapter.lock").exists())

    def test_path_escape_deletion_and_case_aliases_are_rejected(self):
        for paths in (["../outside"], [".git/config"], ["A.py", "a.py"], ["A/one", "a/two"], ["a", "a/b"]):
            with self.subTest(paths=paths):
                arguments = dict(self.arguments, paths=paths)
                content = json.dumps({path: "" for path in paths}).encode()
                with self.assertRaises(GitBoundaryError):
                    validate_action(arguments, content)
        with self.assertRaises(GitBoundaryError):
            validate_action(self.arguments, b'{"a.txt":null,"new.txt":""}')

    def test_compare_and_swap_preserves_actual_concurrent_commit(self):
        tree = self.git("rev-parse", "HEAD^{tree}").decode().strip()
        foreign = self.git("commit-tree", tree, "-p", self.base, source=b"another session\n").decode().strip()
        original = _Repository._run
        changed = False
        def race(repository, args, **kwargs):
            nonlocal changed
            if args[0] == "update-ref" and not changed:
                changed = True
                self.git("update-ref", "refs/heads/main", foreign, self.base)
            return original(repository, args, **kwargs)
        with patch.object(_Repository, "_run", race), self.assertRaises(GitBoundaryError):
            self.commit()
        self.assertTrue(changed)
        self.assertEqual(self.git("rev-parse", "HEAD").decode().strip(), foreign)
        self.assertEqual((self.repo / "a.txt").read_bytes(), b"before\n")
        self.assertTrue((self.repo / ".git/index.lock").exists())
        self.assertTrue((self.repo / ".git/hobnail-adapter.lock").exists())
        self.assertEqual(self.observe()["outcome"], "mismatch")

    def test_partial_worktree_failure_keeps_recovery_evidence_and_never_replays(self):
        original = os.replace
        def fail_second(source, destination, **kwargs):
            if Path(destination) == self.repo / "new.txt":
                raise OSError("controlled consumer write failure")
            return original(source, destination, **kwargs)
        with patch("hobnail.git_effects.os.replace", fail_second), self.assertRaises(OSError):
            self.commit()
        self.assertNotEqual(self.git("rev-parse", "HEAD").decode().strip(), self.base)
        self.assertEqual((self.repo / "a.txt").read_bytes(), b"after\n")
        self.assertFalse((self.repo / "new.txt").exists())
        self.assertTrue((self.repo / ".git/index.lock").exists())
        self.assertEqual(self.observe()["outcome"], "unknown")
        with self.assertRaises(GitBoundaryError):
            self.commit()
        self.assertEqual(self.git("rev-list", "--count", "HEAD").strip(), b"2")

    def test_matching_foreign_commit_is_not_attributed_to_this_effect(self):
        for path, value in self.bundle.items():
            (self.repo / path).write_bytes(bytes.fromhex(value))
        self.git("add", "a.txt", "new.txt")
        self.git("commit", "-qm", self.arguments["message"])
        self.assertEqual(self.observe()["outcome"], "unknown")

    def test_corrupt_journal_returns_unknown_without_exception(self):
        self.commit()
        journal = self.repo / ".git/hobnail-effects" / ("1-" + self.binding + ".jsonl")
        for row in ("[]\n", "1\n", "[" * 1500 + "]" * 1500):
            with self.subTest(row_type=row[:2]):
                journal.write_text(row)
                self.assertEqual(self.observe()["outcome"], "unknown")

    def test_large_valid_action_journal_remains_observable(self):
        self.arguments["paths"] = [f"file_{number:02d}_" + "x" * 208 for number in range(64)]
        self.arguments["message"] = "m" * 2048
        self.bundle = {path: b"accepted\n".hex() for path in self.arguments["paths"]}
        self.content = json.dumps(self.bundle, sort_keys=True).encode()
        self.digest = hashlib.sha256(self.content).hexdigest()
        self.assertLess(len(json.dumps(self.arguments).encode()), 16384)
        self.commit()
        journal = self.repo / ".git/hobnail-effects" / ("1-" + self.binding + ".jsonl")
        self.assertGreater(journal.stat().st_size, 65536)
        self.assertEqual(self.observe()["outcome"], "complete")


class GitKernelTests(GitFixture, KernelCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        response = cls.raw_api(cls.logins["approver"][0], "plugin.register", {
            "plugin_id": "git.commit", "version": 1, "kind": "effect",
            "manifest": {"implementation": implementation_digest(), "input_media_types": ["application/json"],
                         "parameters": {}, "capabilities": [], "result_semantics": "exact local commit",
                         "execution_backend": "local-git"},
        })
        if not response["ok"]:
            raise AssertionError(response)
        cls.git_plugin = response["data"]["plugin_digest"]

    def setUp(self):
        super().setUp()
        self.make_repo()
        self.document["actions"][0].update(plugin="git.commit", plugin_digest=self.git_plugin,
                                            target="fixture", arguments=self.arguments)
        self.document["checks"] = [{"id": "bundle", "plugin": "json.required_fields",
                                    "plugin_digest": self.plugin_digests["json.required_fields"],
                                    "parameters": {"pointers": ["/a.txt", "/new.txt"]}, "max_age_seconds": 300}]
        self.amend(self.document)
        self.artifact = self.put_artifact(self.content)

    def runtime(self, role):
        connection = Connection(str(self.cluster.socket_dir), self.cluster.database, self.logins[role][0],
                                port=self.cluster.port, sslmode="disable")
        return Client(PsqlTransport(connection, psql=str(self.cluster.bin_dir / "psql")))

    def accepted_effect(self):
        candidate = self.passing_candidate()
        effect = self.ok("worker", "effect.request", {"candidate_id": candidate["candidate_id"], "action": "publish",
                         "args": self.arguments, "idempotency_key": "git:" + self.cid})
        return candidate, effect["effect_id"]

    def test_real_kernel_dispatch_and_independent_observation(self):
        candidate, effect = self.accepted_effect()
        result = dispatch_git(self.runtime("adapter"), effect, self.committer)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["data"]["state"], "attempted")
        self.assertEqual((self.repo / "a.txt").read_bytes(), b"after\n")
        observed = observe_git(self.runtime("observer"), effect, self.observer)
        self.assertEqual(observed["data"]["state"], "complete")
        replay = dispatch_git(self.runtime("adapter"), effect, self.committer)
        self.assertEqual(replay["code"], "RECONCILIATION_REQUIRED")
        self.assertEqual(self.git("rev-list", "--count", "HEAD").strip(), b"2")

    def test_lost_report_response_reconciles_git_without_duplicate_commit(self):
        candidate, effect = self.accepted_effect()
        underlying = self.runtime("adapter")
        class LostResponse:
            def call(self, operation, payload):
                result = underlying.call(operation, payload)
                if operation == "effect.report":
                    raise TransportError("controlled lost response after actual report")
                return result
        with self.assertRaises(TransportError):
            dispatch_git(LostResponse(), effect, self.committer)
        result = observe_git(self.runtime("observer"), effect, self.observer)
        self.assertEqual(result["data"]["state"], "complete")
        self.assertEqual(dispatch_git(underlying, effect, self.committer)["code"], "RECONCILIATION_REQUIRED")
        self.assertEqual(self.git("rev-list", "--count", "HEAD").strip(), b"2")

    def test_case_aliases_are_denied_by_kernel_before_activation(self):
        for version, paths in enumerate((["NEW.py", "new.py"], ["Dir/a", "dir/b"]), start=3):
            with self.subTest(paths=paths):
                document = copy.deepcopy(self.document)
                document["actions"][0]["arguments"]["paths"] = paths
                self.denied("worker", "contract.propose", {
                    "contract_id": self.cid, "version": version, "document": document,
                }, "INVALID_REQUEST")


if __name__ == "__main__":
    unittest.main()
