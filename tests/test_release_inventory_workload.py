"""Independent source facts, real native delivery, and narrow producer failures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.release_inventory_facts import collect_release_facts
from scripts.release_inventory_workload import (
    REQUIRED_DOCUMENTS, TARGET, WorkloadError, _native_case, producer_inventory, render_inventory, run_workload,
)


class ReleaseInventoryWorkloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hbn-inventory-test-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.snapshot = self.root / "snapshot"
        self.repository = self.root / "source"
        self.snapshot.mkdir()
        self.repository.mkdir()
        # These are explicit test data, not production expected values or a
        # producer-derived answer. The native test independently reads Git.
        self.contents = {path: ("Test document: " + path + "\n").encode() for path in REQUIRED_DOCUMENTS}
        self.contents.update({
            "pyproject.toml": b'[project]\nname="inventory-test"\nversion="0.4.2"\nrequires-python=">=3.11"\nlicense="MIT"\n[project.scripts]\nreport="example:main"\n',
            "migrations/001_create.sql": b"SELECT 1;\n",
            "migrations/002_extend.sql": b"SELECT 2;\n",
            "bin/check.sh": b"#!/bin/sh\nexit 0\n",
            ".hidden-source": b"included hidden source\n",
        })
        for directory in (self.snapshot, self.repository):
            for relative, content in self.contents.items():
                target = directory / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                target.chmod(0o755 if relative == "bin/check.sh" else 0o644)
        self._git("init", "--quiet")
        self._git("add", "--all")
        self._git("-c", "user.name=Inventory Fixture", "-c", "user.email=fixture@example.invalid",
                  "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "Owned fixture")
        self.commit = self._git("rev-parse", "HEAD").decode().strip()
        self.facts = collect_release_facts(self.repository, self.commit)
        self.facts_file = self.root / "facts.json"
        self.facts_file.write_text(json.dumps(self.facts, sort_keys=True))

    def _git(self, *arguments):
        result = subprocess.run(["git", "-C", str(self.repository), *arguments], capture_output=True, check=True,
            env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                 "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z",
                 "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"}, timeout=10)
        return result.stdout

    def test_complete_producer_matches_independent_immutable_git_facts(self):
        # Prove the expected source is the selected commit, not Git's mutable
        # working tree and not a second call to the filesystem producer.
        (self.repository / "README.md").write_text("uncommitted content must not become expected facts")
        observed = producer_inventory(self.snapshot, self.commit)
        self.assertEqual(observed, collect_release_facts(self.repository, self.commit))
        self.assertEqual(observed["counts"], {"files": len(self.contents), "bytes": sum(map(len, self.contents.values()))})
        entries = {entry["path"]: entry for entry in observed["files"]}
        self.assertEqual(entries["bin/check.sh"]["mode"], "100755")
        for path, content in self.contents.items():
            self.assertEqual(entries[path]["sha256"], hashlib.sha256(content).hexdigest())
            self.assertEqual(entries[path]["bytes"], len(content))

    def test_symlink_and_git_metadata_refused_instead_of_silently_excluded(self):
        (self.snapshot / "alias").symlink_to(self.snapshot / "README.md")
        with self.assertRaisesRegex(WorkloadError, "snapshot_nonregular_file"):
            producer_inventory(self.snapshot, self.commit)
        (self.snapshot / "alias").unlink()
        (self.snapshot / ".git").mkdir()
        with self.assertRaisesRegex(WorkloadError, "unsafe_snapshot_path"):
            producer_inventory(self.snapshot, self.commit)

    def test_missing_required_document_and_duplicate_migration_versions_refused(self):
        (self.snapshot / "SECURITY.md").unlink()
        with self.assertRaisesRegex(WorkloadError, "required_document_missing"):
            producer_inventory(self.snapshot, self.commit)
        (self.snapshot / "SECURITY.md").write_bytes(self.contents["SECURITY.md"])
        (self.snapshot / "migrations/002_collision.sql").write_bytes(b"SELECT 3;\n")
        with self.assertRaisesRegex(WorkloadError, "invalid_migration_versions"):
            producer_inventory(self.snapshot, self.commit)

    def test_source_mutations_change_inventory_instead_of_reusing_git_facts(self):
        (self.snapshot / "README.md").write_bytes(b"new content\n")
        (self.snapshot / "bin/check.sh").chmod(0o644)
        observed = producer_inventory(self.snapshot, self.commit)
        self.assertNotEqual(observed, self.facts)
        entry = next(entry for entry in observed["files"] if entry["path"] == "bin/check.sh")
        self.assertEqual(entry["mode"], "100644")

    def test_output_inside_snapshot_refused_before_any_write(self):
        output = self.snapshot / "new-output"
        with self.assertRaisesRegex(WorkloadError, "output_cannot_modify_snapshot"):
            run_workload(self.snapshot, self.commit, self.facts_file, output)
        self.assertFalse(output.exists())

    def test_file_limit_and_noncontiguous_migration_are_refused(self):
        with patch("scripts.release_inventory_workload.MAX_FILES", len(self.contents) - 1):
            with self.assertRaisesRegex(WorkloadError, "snapshot_file_count_exceeds_limit"):
                producer_inventory(self.snapshot, self.commit)
        (self.snapshot / "migrations/002_extend.sql").rename(self.snapshot / "migrations/003_gap.sql")
        with self.assertRaisesRegex(WorkloadError, "invalid_migration_versions"):
            producer_inventory(self.snapshot, self.commit)

    def test_html_contains_all_inventory_rows_and_escapes_source_values(self):
        inventory = copy.deepcopy(self.facts)
        inventory["package"]["name"] = '<script>alert("x")</script>'
        rendered = render_inventory(inventory)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        for entry in inventory["files"]:
            self.assertIn(entry["path"], rendered)
            self.assertIn(entry["sha256"], rendered)

    def test_failure_receipt_preserves_real_preflight_failure_without_raw_exception(self):
        self.facts_file.write_text("{broken JSON")
        output = self.root / "bad-facts"
        receipt = run_workload(self.snapshot, self.commit, self.facts_file, output)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["failure"], {"stage": "read_trusted_facts", "kind": "JSONDecodeError", "code": "runtime_failure"})
        self.assertEqual(json.loads((output / "workload-receipt.json").read_text()), receipt)
        self.assertEqual(receipt["cases"], [])
        self.assertFalse((output / "release-inventory.html").exists())

    def test_unconfirmed_native_cleanup_cannot_be_reported_as_delivered(self):
        # Mechanism-only failure injection: there is no native qualification
        # claim from this fake. The successful native path runs separately.
        class UnconfirmedApplication:
            def __init__(application, contract_id, consumer, *, sources):
                application.principals = {role: role for role in ("worker", "verifier", "registrar", "approver", "observer", "adapter")}
                application.plugin_digests = {plugin: "a" * 64 for plugin in ("json.equals", "json.required_fields", "file.publish")}
                application.receipt = {"status": "completed", "effect_state": "complete", "runtime_stopped": True,
                    "stages": [], "checks": {"all_runtime_credentials_revoked": False,
                    "generated_credentials_absent_from_receipt_and_log": True}}
            def __enter__(application):
                return application
            def __exit__(application, *arguments):
                return False
            def approve(application, document):
                return {"ok": True, "data": {"policy_digest": "a" * 64}}
            def run(application, **arguments):
                return application.receipt
        output = self.root / "unconfirmed-cleanup"
        with patch("scripts.release_inventory_workload.NativeApplication", UnconfirmedApplication):
            receipt = run_workload(self.snapshot, self.commit, self.facts_file, output)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["failure"]["code"], "native_retirement_unconfirmed")
        self.assertFalse(receipt["cases"][0]["native"]["checks"]["all_runtime_credentials_revoked"])
        self.assertEqual(receipt["cases"][0]["approval"]["ok"], True)
        self.assertFalse((output / "release-inventory.html").exists())
        self.assertEqual(json.loads((output / "workload-receipt.json").read_text()), receipt)

    def test_refused_control_with_dangling_alternate_output_is_not_reported_as_empty(self):
        destination = self.root / "refused-control"
        evidence = {"cases": []}
        with patch("scripts.release_inventory_workload.NativeApplication") as constructor:
            application = constructor.return_value
            application.__enter__.return_value = application
            application.principals = {role: role for role in ("worker", "verifier", "registrar", "approver", "observer", "adapter")}
            application.plugin_digests = {plugin: "a" * 64 for plugin in ("json.equals", "json.required_fields", "file.publish")}
            application.approve.return_value = {"ok": True}
            application.receipt = {"status": "refused", "runtime_stopped": True,
                "checks": {"all_runtime_credentials_revoked": True, "generated_credentials_absent_from_receipt_and_log": True},
                "stages": [{"stage": "independent_verification", "result": {"ok": False, "code": "CHECK_FAILED"}}]}
            application.run.side_effect = lambda **arguments: (destination / "unexpected").symlink_to("missing-target")
            with self.assertRaisesRegex(WorkloadError, "refused_control_produced_output"):
                _native_case("extra-field", b"{}", b"{}", destination, evidence)
        self.assertEqual(evidence["cases"][0]["output_files"], [])
        self.assertEqual(evidence["cases"][0]["output_entries"], ["unexpected"])

    def test_real_native_delivery_and_three_injected_refusals_retire_every_runtime(self):
        output = self.root / "delivery"
        receipt = run_workload(self.snapshot, self.commit, self.facts_file, output)
        self.assertEqual(receipt["status"], "completed", receipt)
        self.assertEqual(receipt["baseline"]["matches_independent_facts"], True)
        self.assertTrue(receipt["source_snapshot_unchanged"])
        self.assertEqual(json.loads((output / "published" / TARGET).read_bytes()), self.facts)
        self.assertEqual((output / "baseline.json").read_bytes(), (output / "published" / TARGET).read_bytes())
        self.assertEqual([case["name"] for case in receipt["cases"]],
                         ["accepted", "omitted-migration", "wrong-version", "extra-field"])
        for case in receipt["cases"]:
            native = case["native"]
            self.assertTrue(native["runtime_stopped"])
            self.assertTrue(native["checks"]["all_runtime_credentials_revoked"])
            self.assertTrue(native["checks"]["generated_credentials_absent_from_receipt_and_log"])
            self.assertNotIn("retained_root", native)
            self.assertNotIn("receipt", native)
            self.assertEqual(case["attempts"], 1)
            self.assertEqual(native["status"], "completed" if case["name"] == "accepted" else "refused")
            self.assertEqual(case["output_files"], [TARGET] if case["name"] == "accepted" else [])
        self.assertEqual(receipt["comparison"]["trusted_supervisor_contract_activations"], 4)
        self.assertIsNone(receipt["comparison"]["human_authoring_and_review_seconds"])
        self.assertEqual(receipt["automatic_retries"], 0)
        self.assertIn("pending_separate_release_operator_receipt", receipt["delivery"]["release_preflight_consumption"])
        self.assertEqual(json.loads((output / "workload-receipt.json").read_text()), receipt)
        self.assertNotIn(str(self.root), (output / "workload-receipt.json").read_text())


if __name__ == "__main__":
    unittest.main()
