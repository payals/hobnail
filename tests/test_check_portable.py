"""Portable profile and anonymous-CI orchestration; no remote GitHub calls."""
import ast
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import check_portable


def checkout_source():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    source = workflow.split("          # BEGIN PUBLIC CHECKOUT\n", 1)[1].split("          # END PUBLIC CHECKOUT", 1)[0]
    return textwrap.dedent(source)


class PortableProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hbn-portable-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "tests").mkdir()
        for name in check_portable.SELECTED:
            (self.root / "tests" / name).write_text("# owned inventory fixture\n")

    def test_explicit_inventory_lists_selection_absence_and_reasons_without_running(self):
        (self.root / "tests/test_openbao_runtime.py").write_text("raise AssertionError('must not execute')\n")
        with patch.object(unittest.defaultTestLoader, "loadTestsFromNames", side_effect=AssertionError("unexpected execution")):
            report = check_portable.describe(self.root)
        self.assertEqual({Path(row["file"]).name for row in report["selected"]}, set(check_portable.SELECTED))
        self.assertTrue(all(row["selected"] and row["present"] and row["reason"] for row in report["selected"]))
        excluded = {Path(row["file"]).name: row for row in report["nonselected"]}
        self.assertTrue(excluded["test_openbao_runtime.py"]["present"])
        self.assertFalse(excluded["test_openbao_runtime.py"]["selected"])
        self.assertFalse(excluded["test_recovery.py"]["present"])
        self.assertEqual(report["unclassified"], [])

    def test_unknown_top_level_and_nested_modules_refuse(self):
        for relative in ("test_unreviewed.py", "testwithoutunderscore.py", "new/test_unreviewed.py"):
            path = self.root / "tests" / relative
            path.parent.mkdir(exist_ok=True)
            path.write_text("# unexplained addition\n")
            try:
                with self.subTest(path=relative), self.assertRaisesRegex(check_portable.PortableCheckError, "unclassified_test_files"):
                    check_portable.describe(self.root)
            finally:
                path.unlink()

    def test_missing_required_module_and_alias_refuse(self):
        path = self.root / "tests/test_client.py"
        path.unlink()
        with self.assertRaisesRegex(check_portable.PortableCheckError, "required_portable_tests_missing"):
            check_portable.describe(self.root)
        outside = self.root / "outside.py"
        outside.write_text("# owned alias target\n")
        path.symlink_to(outside)
        with self.assertRaisesRegex(check_portable.PortableCheckError, "not_regular_canonical"):
            check_portable.describe(self.root)

    def test_skips_expected_failures_and_actual_failures_never_count_as_pass(self):
        for outcome in ("pass", "skip", "expected", "fail"):
            def control(case):
                if outcome == "skip":
                    case.skipTest("controlled fixture skip")
                if outcome in {"expected", "fail"}:
                    case.fail("controlled fixture failure")
            if outcome == "expected":
                control = unittest.expectedFailure(control)
            fixture = type("ControlledOutcome", (unittest.TestCase,), {"test_control": control})
            def load(_names):
                return unittest.TestSuite([fixture("test_control")])
            with self.subTest(outcome=outcome), patch.object(unittest.defaultTestLoader, "loadTestsFromNames", side_effect=load), redirect_stderr(io.StringIO()):
                report = check_portable.run_profile(self.root)
            self.assertEqual(report["tests_run"], len(check_portable.SELECTED))
            self.assertEqual(report["status"], "passed" if outcome == "pass" else "failed")
            self.assertFalse(report["selection_changed_on_failure"])

    def test_empty_selected_module_refuses(self):
        with patch.object(unittest.defaultTestLoader, "loadTestsFromNames", return_value=unittest.TestSuite()):
            with self.assertRaisesRegex(check_portable.PortableCheckError, "selected_module_has_no_tests"):
                check_portable.run_profile(self.root)

    def test_changed_inventory_during_execution_fails_and_preserves_test_count(self):
        outer = self
        class ChangedInventory(unittest.TestCase):
            def runTest(self):
                (outer.root / "tests/test_unknown.py").write_text("# arrived during tests\n")
        with patch.object(unittest.defaultTestLoader, "loadTestsFromNames", side_effect=lambda _names: unittest.TestSuite([ChangedInventory()])), redirect_stderr(io.StringIO()):
            report = check_portable.run_profile(self.root)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["tests_run"], len(check_portable.SELECTED))
        self.assertFalse(report["test_inventory_unchanged"])
        self.assertIn("unclassified_test_files", report["inventory_error"])

    def test_receipt_is_exclusive_and_existing_or_aliased_targets_are_unchanged(self):
        path = self.root / "receipt.json"
        with patch.object(check_portable, "describe", return_value={"status": "listed"}), redirect_stdout(io.StringIO()):
            self.assertEqual(check_portable.main(["--list", "--receipt", str(path)]), 0)
        before = path.read_bytes()
        self.assertEqual(json.loads(before)["status"], "listed")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        alias = self.root / "alias.json"
        alias.symlink_to(path)
        for target in (path, alias):
            with self.subTest(target=target.name), patch.object(check_portable, "describe", side_effect=AssertionError("tests after receipt refusal")), redirect_stdout(io.StringIO()):
                self.assertEqual(check_portable.main(["--list", "--receipt", str(target)]), 1)
            self.assertEqual(path.read_bytes(), before)


class PublicWorkflowTests(unittest.TestCase):
    def execute_checkout(self, repository, revision, *, returned_revision=None, calls=None):
        if calls is None:
            calls = []
        def fake_git(arguments, **options):
            calls.append((arguments, options))
            output = (returned_revision or revision) if arguments[-2:] == ["rev-parse", "HEAD"] else ""
            return subprocess.CompletedProcess(arguments, 0, output, "")
        with tempfile.TemporaryDirectory(prefix="hbn-ci-checkout-", dir="/tmp") as directory:
            previous = Path.cwd()
            try:
                os.chdir(directory)
                with patch.dict(os.environ, {"GITHUB_REPOSITORY": repository, "GITHUB_SHA": revision,
                        "GITHUB_TOKEN": "synthetic-not-for-git", "GIT_CONFIG_COUNT": "5", "HTTPS_PROXY": "https://unused.invalid"}), \
                        patch("subprocess.run", side_effect=fake_git), redirect_stdout(io.StringIO()):
                    exec(compile(checkout_source(), "reviewed-ci-checkout", "exec"), {})
            finally:
                os.chdir(previous)
        return calls

    def test_bootstrap_rejects_noncanonical_inputs_before_git_execution(self):
        for repository, revision in (("owner/repo;echo-bad", "a" * 40), ("owner/../repo", "a" * 40),
                                     ("owner/..", "a" * 40), ("https://other.invalid/repo", "a" * 40),
                                     ("owner/repo", "main"), ("owner/repo", "a" * 40 + "\n")):
            calls = []
            with self.subTest(repository=repository, revision=revision):
                with self.assertRaises(SystemExit):
                    self.execute_checkout(repository, revision, calls=calls)
                self.assertEqual(calls, [])

    def test_bootstrap_uses_literal_public_https_exact_commit_and_clean_git_environment(self):
        calls = self.execute_checkout("owner/repo", "a" * 40)
        self.assertEqual(len(calls), 4)
        fetch = calls[1][0]
        self.assertEqual(fetch[-5:], ["fetch", "--no-tags", "--depth=1", "https://github.com/owner/repo.git", "a" * 40])
        for arguments, options in calls:
            self.assertEqual(arguments[0], "/usr/bin/git")
            self.assertIn("core.hooksPath=/dev/null", arguments)
            self.assertIn("credential.helper=", arguments)
            self.assertIn("protocol.allow=never", arguments)
            self.assertIn("http.followRedirects=false", arguments)
            self.assertIn("submodule.recurse=false", arguments)
            self.assertEqual(options["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
            self.assertEqual(options["env"]["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(options["env"]["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertEqual(options["env"]["GIT_NO_LAZY_FETCH"], "1")
            self.assertEqual(options["env"]["GIT_ALLOW_PROTOCOL"], "https")
            self.assertEqual(options["env"]["GIT_TERMINAL_PROMPT"], "0")
            self.assertNotIn("GITHUB_TOKEN", options["env"])
            self.assertNotIn("GIT_CONFIG_COUNT", options["env"])
            self.assertNotIn("HTTPS_PROXY", options["env"])
            self.assertNotIn("shell", options)
        with self.assertRaises(SystemExit):
            self.execute_checkout("owner/repo", "a" * 40, returned_revision="b" * 40)

    def test_workflow_stays_ephemeral_read_only_and_has_no_external_action_or_privileged_trigger(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        ast.parse(checkout_source())
        self.assertIn("on:\n  push:\n  pull_request:\n  workflow_dispatch:\n", workflow)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn("timeout-minutes: 10", workflow)
        self.assertIn("python3 -m venv --without-pip .venv", workflow)
        self.assertIn("env -i PATH=/usr/bin:/bin LANG=C.UTF-8 .venv/bin/python scripts/check_portable.py", workflow)
        self.assertIn(".venv/bin/python -m compileall -q", workflow)
        for forbidden in ("uses:", "pull_request_target", "workflow_run", "self-hosted", "secrets.",
                          "${{", "id-token:", "contents: write", "actions/cache", "git push"):
            self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
