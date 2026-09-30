"""Demo command-line output with controlled receipts; no PostgreSQL or native runtime."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts import dev_cluster, local_demo, native_application


def synthetic_receipt(root: Path) -> dict:
    """A receipt shaped like local_demo's, rooted in a directory the test created."""
    return {
        "protocol": 1, "run_status": "completed", "runtime_stopped": True, "stages": {"install": {"large": "x" * 4096}},
        "retained_root": str(root), "evidence_file": str(root / "evidence.json"),
        "output_root": str(root / "outputs"), "qualification": {"limits": ["synthetic"]},
        "scenarios": [
            {"scenario": "happy", "expected_outcome_observed": True, "consequence": {"exists": True}},
            {"scenario": "bad_content", "expected_outcome_observed": True, "consequence": {"exists": False}},
            {"scenario": "stale_input", "expected_outcome_observed": False, "consequence": {"exists": False}},
        ],
    }


def neutral_root(case: unittest.TestCase) -> Path:
    temporary = tempfile.TemporaryDirectory(prefix="demo-output-")
    case.addCleanup(temporary.cleanup)
    return Path(temporary.name).resolve()


class LocalDemoOutputTests(unittest.TestCase):
    def setUp(self):
        self.root = neutral_root(self)
        self.receipt = synthetic_receipt(self.root)

    def run_main(self, receipt, *argv):
        stdout = io.StringIO()
        with patch.object(local_demo, "run_demo", return_value=receipt) as run, redirect_stdout(stdout):
            code = local_demo.main(list(argv))
        return code, stdout.getvalue(), run

    def test_default_prints_a_short_summary_naming_the_retained_receipt(self):
        code, out, _ = self.run_main(self.receipt)
        self.assertEqual(code, 0)
        self.assertLess(len(out), 1200)
        self.assertNotIn("x" * 100, out)
        self.assertIn("Hobnail local demo: completed (runtime stopped)", out)
        self.assertIn("happy        expected_outcome_observed=true   destination written: yes", out)
        self.assertIn("stale_input  expected_outcome_observed=false  destination written: no", out)
        self.assertIn(f"Retained root: {self.root}\n", out)
        self.assertIn(f"Full receipt:  {self.root / 'evidence.json'}\n", out)

    def test_json_flag_keeps_the_complete_single_line_receipt(self):
        code, out, _ = self.run_main(self.receipt, "--json")
        self.assertEqual(code, 0)
        self.assertEqual(out.count("\n"), 1)
        self.assertEqual(json.loads(out), self.receipt)

    def test_failure_is_summarized_and_exit_code_is_unchanged(self):
        failed = {**self.receipt, "run_status": "failed", "failure": {"stage": "install", "kind": "ClusterError"},
                  "runtime_stopped": False, "cleanup_failure": {"kind": "ClusterError"}}
        code, out, _ = self.run_main(failed)
        self.assertEqual(code, 1)
        self.assertIn("Hobnail local demo: failed (runtime NOT confirmed stopped)", out)
        self.assertIn("Failure: stage install (ClusterError)", out)
        self.assertIn("Cleanup failure: ClusterError", out)

    def test_receipt_without_an_evidence_file_is_printed_in_full(self):
        early = {"protocol": 1, "run_status": "failed", "scenarios": [], "stages": {},
                 "failure": {"stage": "allocate_owned_cluster", "kind": "ClusterError"}}
        code, out, _ = self.run_main(early)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out), early)

    def test_scenario_selection_is_passed_through(self):
        _, _, run = self.run_main(self.receipt, "--scenario", "bad_content")
        run.assert_called_once_with(("bad_content",))


class NativeApplicationEntryPointTests(unittest.TestCase):
    def test_help_describes_library_use_and_the_runnable_example(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout), self.assertRaises(SystemExit) as caught:
            native_application.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("docs/NATIVE-APPLICATION.md", stdout.getvalue())
        self.assertIn(".venv/bin/python scripts/native_application.py", stdout.getvalue())

    def test_main_prints_the_example_result_and_maps_status_to_exit_code(self):
        for status, expected in (("completed", 0), ("refused", 1), ("failed", 1)):
            root = neutral_root(self)
            result = {"status": status, "receipt": str(root / "application.json"), "output": str(root / "warehouse-report.json")}
            stdout = io.StringIO()
            with self.subTest(status=status), patch.object(native_application, "run_example", return_value=result), redirect_stdout(stdout):
                self.assertEqual(native_application.main([]), expected)
                self.assertEqual(json.loads(stdout.getvalue()), result)

    def test_activation_refusal_prints_only_the_safe_code(self):
        stdout = io.StringIO()
        refusal = native_application.NativeApplicationError("owner_contract_activation_refused")
        with patch.object(native_application, "run_example", side_effect=refusal), redirect_stdout(stdout):
            self.assertEqual(native_application.main([]), 1)
        self.assertEqual(json.loads(stdout.getvalue()), {"status": "refused", "code": "owner_contract_activation_refused"})

    def test_runnable_example_matches_the_documented_contract(self):
        # A private checkout also carries the public overlay; an exported snapshot has only docs/.
        documents = [ROOT / "docs/NATIVE-APPLICATION.md", ROOT / "release/public-docs/docs/NATIVE-APPLICATION.md"]
        source = {line.strip() for line in (ROOT / "scripts/native_application.py").read_text().splitlines()}
        for document in (path for path in documents if path.exists()):
            with self.subTest(document=document.relative_to(ROOT).as_posix()):
                text = document.read_text()
                self.assertIn(".venv/bin/python scripts/native_application.py", text)
                examples = [body for body in re.findall(r"<<'PY'\n(.*?)\nPY\n", text, flags=re.DOTALL)
                            if "NativeApplication(" in body]
                self.assertEqual(len(examples), 1)
                example = examples[0]
                documented = example[example.index("output = Path("):example.index("approval = application.approve")]
                missing = [line.strip() for line in documented.splitlines() if line.strip() and line.strip() not in source]
                self.assertEqual(missing, [])


class PruneTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="prune-base-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()

    def root(self, name, *, pid=None, pidfile=False, marker_root=None, age_hours=48, initialized=True, started_at=None):
        root = self.base / name
        root.mkdir(mode=0o700)
        (root / "data").mkdir(mode=0o700)
        (root / "data" / "base.bin").write_bytes(b"d" * 4096)
        (root / "evidence.json").write_text("{}")
        if pidfile:
            (root / "data" / "postmaster.pid").write_text("123\n")
        marker = {"format": dev_cluster.FORMAT, "token": uuid.uuid4().hex, "uid": os.getuid(),
                  "root": marker_root or str(root), "database": "hobnail_test", "pid": pid, "started_at": started_at,
                  "initialized": initialized, "database_created": True, "socket_name": "sock"}
        path = root / dev_cluster.MARKER
        path.write_text(json.dumps(marker)); path.chmod(0o600)
        stamp = time.time() - age_hours * 3600
        for item in (path, root):
            os.utime(item, (stamp, stamp))
        return root

    def by_root(self, entries):
        return {Path(e["root"]).name: e for e in entries}

    def test_dry_run_lists_owned_stopped_roots_and_skips_everything_else(self):
        self.root("hbn-owned")
        self.root("hbn-running", pid=4242)
        self.root("hbn-pidfile", pidfile=True)
        self.root("hbn-foreign", marker_root="/elsewhere")
        (self.base / "hbn-unmarked").mkdir()
        (self.base / "hbn-link").symlink_to(self.base / "hbn-owned")
        self.root("other-owned")
        entries = self.by_root(dev_cluster.prune(self.base))
        self.assertEqual(set(entries), {"hbn-owned", "hbn-running", "hbn-pidfile", "hbn-foreign", "hbn-unmarked"})
        self.assertEqual(entries["hbn-owned"]["action"], "would_delete")
        self.assertGreaterEqual(entries["hbn-owned"]["bytes"], 4096)
        for name in ("hbn-running", "hbn-pidfile", "hbn-foreign", "hbn-unmarked"):
            self.assertEqual(entries[name]["action"], "skipped", name)
        self.assertTrue((self.base / "hbn-owned" / "data" / "base.bin").exists())

    def test_delete_removes_only_selected_roots(self):
        self.root("hbn-owned"); self.root("hbn-running", pid=4242); self.root("hbn-recent", age_hours=1)
        entries = self.by_root(dev_cluster.prune(self.base, delete=True, older_than_hours=24))
        self.assertEqual(entries["hbn-owned"]["action"], "deleted")
        self.assertEqual(entries["hbn-recent"]["action"], "skipped")
        self.assertFalse((self.base / "hbn-owned").exists())
        self.assertTrue((self.base / "hbn-running" / "data").exists())
        self.assertTrue((self.base / "hbn-recent" / "data").exists())

    def test_data_only_keeps_receipts_and_logs(self):
        root = self.root("hbn-owned")
        entries = self.by_root(dev_cluster.prune(self.base, delete=True, data_only=True))
        self.assertEqual(entries["hbn-owned"]["action"], "deleted_data")
        self.assertFalse((root / "data").exists())
        self.assertTrue((root / "evidence.json").exists())
        again = self.by_root(dev_cluster.prune(self.base, delete=True, data_only=True))
        self.assertEqual(again["hbn-owned"]["action"], "skipped")

    def test_in_use_roots_are_skipped_and_a_low_age_floor_needs_force(self):
        self.root("hbn-initializing", initialized=False)
        self.root("hbn-just-started", started_at=str(int(time.time()) - 60))
        self.root("hbn-garbled-start", started_at="not-a-time")
        self.root("hbn-fresh", age_hours=0.1)
        entries = self.by_root(dev_cluster.prune(self.base, delete=True))
        self.assertEqual({name: e["action"] for name, e in entries.items()},
                         {name: "skipped" for name in entries})
        with self.assertRaises(dev_cluster.ClusterError):
            dev_cluster.prune(self.base, older_than_hours=0)
        forced = self.by_root(dev_cluster.prune(self.base, older_than_hours=0, force=True))
        self.assertEqual(forced["hbn-fresh"]["action"], "would_delete")
        self.assertEqual(forced["hbn-initializing"]["action"], "skipped")

    def test_selected_bytes_reflect_data_only(self):
        root = self.root("hbn-owned")
        (root / "server.log").write_bytes(b"l" * 10000)
        stamp = time.time() - 48 * 3600
        os.utime(root, (stamp, stamp))
        reports = {}
        for flags in ([], ["--data-only"]):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(dev_cluster.main(["prune", "--base-dir", str(self.base), *flags]), 0)
            reports[bool(flags)] = json.loads(stdout.getvalue())["selected_bytes"]
        self.assertEqual(reports[True], 4096)
        self.assertGreaterEqual(reports[False], 4096 + 10000)

    def test_cli_refuses_a_low_age_floor_without_force(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(dev_cluster.main(["prune", "--base-dir", str(self.base), "--older-than-hours", "0.5", "--delete"]), 1)
        self.assertIn("--force", json.loads(stdout.getvalue())["error"])

    def test_cli_defaults_to_a_dry_run(self):
        self.root("hbn-owned")
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(dev_cluster.main(["prune", "--base-dir", str(self.base)]), 0)
        report = json.loads(stdout.getvalue())
        self.assertTrue(report["dry_run"])
        self.assertEqual([e["action"] for e in report["roots"]], ["would_delete"])
        self.assertTrue((self.base / "hbn-owned").exists())


if __name__ == "__main__":
    unittest.main()
