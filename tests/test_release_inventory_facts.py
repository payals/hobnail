"""Git-object facts are independent of candidate working-tree contents."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.release_inventory_facts import REQUIRED_DOCUMENTS, ReleaseFactsError, collect_release_facts


class ReleaseFactsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hbn-facts-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.git("init", "--quiet", "--object-format=sha1")
        for name in REQUIRED_DOCUMENTS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("owned public fixture\n")
        (self.root / "pyproject.toml").write_text('''[project]
name="hobnail"
version="0.2.0"
requires-python=">=3.11"
license="MIT"
[project.scripts]
hobnail="hobnail.cli:main"
''')
        (self.root / "migrations").mkdir()
        (self.root / "migrations/001_first.sql").write_text("SELECT 1;\n")
        (self.root / "probe.sh").write_text("#!/bin/sh\nexit 0\n")
        (self.root / "probe.sh").chmod(0o755)
        self.commit = self.checkpoint()

    def git(self, *arguments):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}
        result = subprocess.run(["git", "-C", str(self.root), "-c", "core.hooksPath=/dev/null",
            "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", *arguments],
            env=env, capture_output=True, check=True)
        return result.stdout.decode().strip()

    def checkpoint(self):
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "Owned fixture")
        return self.git("rev-parse", "HEAD")

    def test_facts_bind_committed_bytes_modes_metadata_and_complete_count(self):
        facts = collect_release_facts(self.root, self.commit)
        self.assertEqual(facts["schema"], "hobnail-release-inventory-v1")
        self.assertEqual(facts["source_commit"], self.commit)
        entries = {entry["path"]: entry for entry in facts["files"]}
        self.assertEqual(entries["probe.sh"]["mode"], "100755")
        self.assertEqual(entries["migrations/001_first.sql"]["sha256"], hashlib.sha256(b"SELECT 1;\n").hexdigest())
        self.assertEqual(facts["counts"], {"files": len(entries), "bytes": sum(entry["bytes"] for entry in entries.values())})
        self.assertEqual(facts["package"]["entry_points"], {"hobnail": "hobnail.cli:main"})
        self.assertEqual(facts["required_documents"], list(REQUIRED_DOCUMENTS))

    def test_dirty_worktree_cannot_supply_expected_answers(self):
        before = collect_release_facts(self.root, self.commit)
        (self.root / "pyproject.toml").write_text("invalid producer metadata")
        (self.root / "migrations/001_first.sql").write_text("SELECT 999;")
        (self.root / "untracked.txt").write_text("not part of selected source")
        self.assertEqual(collect_release_facts(self.root, self.commit), before)

    def test_branch_name_and_tree_object_are_not_commit_authority(self):
        for reference in ("HEAD", self.git("rev-parse", "HEAD^{tree}")):
            with self.subTest(reference=reference), self.assertRaises(ReleaseFactsError):
                collect_release_facts(self.root, reference)

    def test_replace_ref_cannot_substitute_a_different_tree_for_selected_commit(self):
        original = collect_release_facts(self.root, self.commit)
        (self.root / "README.md").write_text("different replacement tree\n")
        replacement = self.checkpoint()
        self.git("replace", self.commit, replacement)
        self.assertEqual(collect_release_facts(self.root, self.commit), original)
        self.assertNotEqual(collect_release_facts(self.root, replacement)["files"], original["files"])

    def test_malformed_entrypoint_metadata_has_safe_refusal(self):
        (self.root / "pyproject.toml").write_text('''[project]
name="hobnail"
version="0.2.0"
requires-python=">=3.11"
license="MIT"
scripts="synthetic-invalid-value"
''')
        selected = self.checkpoint()
        with self.assertRaisesRegex(ReleaseFactsError, "project_metadata_invalid"):
            collect_release_facts(self.root, selected)

    def test_missing_promisor_object_refuses_without_running_configured_transport(self):
        # A task-owned harmless helper would create a marker if Git tried lazy
        # object retrieval. No network or real credential helper is configured.
        marker = self.root / "unexpected-transport"
        helper = self.root / "transport.sh"
        helper.write_text('#!/bin/sh\nprintf attempted > "' + str(marker) + '"\nexit 1\n')
        helper.chmod(0o700)
        self.git("config", "remote.owned.promisor", "true")
        self.git("config", "remote.owned.partialclonefilter", "blob:none")
        self.git("config", "remote.owned.url", "ext::" + str(helper))
        self.git("config", "protocol.ext.allow", "always")
        oid = self.git("rev-parse", self.commit + ":README.md")
        (self.root / ".git/objects" / oid[:2] / oid[2:]).unlink()
        with self.assertRaisesRegex(ReleaseFactsError, "git_object_read_failed"):
            collect_release_facts(self.root, self.commit)
        self.assertFalse(marker.exists())

    def test_missing_document_noncontiguous_migration_and_alias_refuse(self):
        (self.root / "SECURITY.md").unlink()
        absent = self.checkpoint()
        with self.assertRaisesRegex(ReleaseFactsError, "required_source_document_missing"):
            collect_release_facts(self.root, absent)
        (self.root / "SECURITY.md").write_text("owned public fixture\n")
        (self.root / "migrations/003_gap.sql").write_text("SELECT 3;\n")
        gap = self.checkpoint()
        with self.assertRaisesRegex(ReleaseFactsError, "migration_sequence_invalid"):
            collect_release_facts(self.root, gap)
        (self.root / "migrations/003_gap.sql").unlink()
        (self.root / "link").symlink_to("README.md")
        alias = self.checkpoint()
        with self.assertRaisesRegex(ReleaseFactsError, "unsupported_source_path_or_type"):
            collect_release_facts(self.root, alias)


if __name__ == "__main__":
    unittest.main()
