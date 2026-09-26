"""Prepared maintenance boundary checks; no GitHub API or runtime activation."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import Mock, patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/security.yml"


def workflow_block(name):
    text = WORKFLOW.read_text()
    return textwrap.dedent(text.split("          # BEGIN " + name + "\n", 1)[1].split(
        "          # END " + name, 1)[0])


class MaintenancePolicyTests(unittest.TestCase):
    def test_ruleset_is_strict_and_does_not_invent_live_app_authority(self):
        ruleset = json.loads((ROOT / ".github/rulesets/main.json").read_text())
        self.assertEqual(set(ruleset), {"name", "target", "enforcement", "bypass_actors", "conditions", "rules"})
        self.assertEqual(ruleset["target"], "branch")
        self.assertEqual(ruleset["enforcement"], "active")
        self.assertEqual(ruleset["bypass_actors"], [])
        self.assertEqual(ruleset["conditions"]["ref_name"], {
            "include": ["refs/heads/main", "~DEFAULT_BRANCH"], "exclude": [],
        })
        rules = {row["type"]: row.get("parameters") for row in ruleset["rules"]}
        self.assertEqual(set(rules), {"deletion", "non_fast_forward", "required_linear_history", "pull_request", "required_status_checks"})
        self.assertEqual(rules["pull_request"], {
            "allowed_merge_methods": ["squash"], "dismiss_stale_reviews_on_push": True,
            "require_code_owner_review": True, "require_last_push_approval": True,
            "required_approving_review_count": 1, "required_review_thread_resolution": True,
        })
        self.assertEqual(rules["required_status_checks"], {
            "required_status_checks": [{"context": "portable"}, {"context": "security"}],
            "strict_required_status_checks_policy": True, "do_not_enforce_on_create": False,
        })
        settings = json.loads((ROOT / ".github/repository-settings.json").read_text())
        self.assertIs(settings["applied"], False)
        self.assertIs(settings["repository_settings"]["allow_auto_merge"], False)
        self.assertIs(settings["actions"]["can_approve_pull_request_reviews"], False)
        self.assertEqual(settings["maintenance_authority"]["automatic_merge"], "disabled")
        self.assertIn("REQUIRED live activation", settings["ruleset"]["integration_id_binding"])

    def test_required_security_job_has_unconditional_pr_path_and_no_write_or_action_dependency(self):
        workflow = WORKFLOW.read_text()
        self.assertIn("  pull_request:\n", workflow)
        self.assertIn("  push:\n", workflow)
        self.assertIn('    - cron: "37 6 * * 1"', workflow)
        self.assertIn("permissions: {}", workflow)
        self.assertIn("  security:\n    name: security\n", workflow)
        for forbidden in ("pull_request_target:", "workflow_run:", "uses:", "continue-on-error:",
                          "    if:", "paths-ignore:", "paths:", "secrets.", "github.token"):
            self.assertNotIn(forbidden, workflow)
        self.assertIn("--history", workflow)
        self.assertIn("--allowlist security/scan-allowlist.json --attribution-policy github-noreply", workflow)
        self.assertIn("--receipt ../security-scan.json", workflow)
        config = (ROOT / ".github/dependabot.yml").read_text()
        self.assertEqual(config.count("default-days: 7"), 2)
        self.assertIn("package-ecosystem: pip", config)
        self.assertIn("package-ecosystem: github-actions", config)
        self.assertNotIn("insecure-external-code-execution", config)
        self.assertNotIn("registries:", config)

    def checkout(self, repository="payals/hobnail", revision="a" * 40, *, returned=None, shallow=False, marker=None):
        calls = []
        public_marker = {"schema": "hobnail-public-source-v1", "profile": "public", "repository": "payals/hobnail"}
        def git(arguments, **options):
            calls.append((arguments, options))
            if "checkout" in arguments:
                (Path(options["cwd"]) / "PUBLIC-SOURCE.json").write_text(json.dumps(public_marker if marker is None else marker))
            if arguments[-2:] == ["rev-parse", "HEAD"]:
                output = returned or revision
            elif arguments[-2:] == ["rev-parse", "--is-shallow-repository"]:
                output = "true" if shallow else "false"
            else:
                output = ""
            return subprocess.CompletedProcess(arguments, 0, output, "")
        with tempfile.TemporaryDirectory(prefix="hbn-maintenance-", dir="/tmp") as directory:
            old = Path.cwd()
            try:
                os.chdir(directory)
                with patch.dict(os.environ, {"GITHUB_REPOSITORY": repository, "GITHUB_SHA": revision}, clear=True), \
                        patch("subprocess.run", side_effect=git), redirect_stdout(io.StringIO()):
                    exec(compile(workflow_block("SECURITY CHECKOUT"), str(WORKFLOW), "exec"), {})
            finally:
                os.chdir(old)
        return calls

    def test_checkout_fetches_exact_full_ancestry_without_credentials_hooks_or_replace_refs(self):
        calls = self.checkout()
        fetch = next(arguments for arguments, _ in calls if "fetch" in arguments)
        self.assertEqual(fetch[-4:], ["fetch", "--no-tags", "https://github.com/payals/hobnail.git", "a" * 40])
        self.assertFalse(any(argument.startswith(("--depth", "--filter", "--shallow")) for argument in fetch))
        for arguments, options in calls:
            self.assertIn("--no-replace-objects", arguments)
            self.assertIn("core.hooksPath=/dev/null", arguments)
            self.assertIn("credential.helper=", arguments)
            self.assertEqual(options["env"]["GIT_NO_LAZY_FETCH"], "1")
            self.assertEqual(options["env"]["GIT_ALLOW_PROTOCOL"], "https")
            self.assertNotIn("GITHUB_TOKEN", options["env"])
            self.assertEqual(options["stdin"], subprocess.DEVNULL)

    def test_checkout_refuses_wrong_repo_revision_shallow_history_and_private_marker(self):
        for arguments in ({"repository": "other/repo"}, {"revision": "main"}, {"returned": "b" * 40},
                          {"shallow": True}, {"marker": {"schema": "private-development-history"}}):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                self.checkout(**arguments)


class OptionalDependencyReviewTests(unittest.TestCase):
    def review(self, *, mode="enabled", event_name="pull_request", response=None, error=None, event=None, headers=None):
        if response is None:
            response = []
        event = event or {"pull_request": {"base": {"sha": "a" * 40, "repo": {"full_name": "payals/hobnail"}},
                                           "head": {"sha": "b" * 40}}}
        class Response:
            status = 200
            def __init__(self): self.headers = headers or {}
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, _limit): return json.dumps(response).encode()
        opener = Mock()
        opener.open.side_effect = error
        opener.open.return_value = Response()
        output = io.StringIO()
        with tempfile.TemporaryDirectory(prefix="hbn-dependency-review-", dir="/tmp") as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps(event))
            environment = {"DEPENDENCY_REVIEW_MODE": mode, "GITHUB_EVENT_NAME": event_name,
                           "GITHUB_REPOSITORY": "payals/hobnail", "GITHUB_EVENT_PATH": str(path)}
            with patch.dict(os.environ, environment, clear=True), \
                    patch("urllib.request.build_opener", return_value=opener), redirect_stdout(output), \
                    self.assertRaises(SystemExit) as caught:
                exec(compile(workflow_block("OPTIONAL DEPENDENCY REVIEW"), str(WORKFLOW), "exec"), {})
        return caught.exception.code, json.loads(output.getvalue()), opener

    @staticmethod
    def change(kind="added", vulnerabilities=None):
        return {"change_type": kind, "manifest": "pyproject.toml", "ecosystem": "pip",
                "name": "synthetic-package", "version": "1.0.0", "vulnerabilities": vulnerabilities or []}

    def test_disabled_and_non_pr_states_never_claim_a_completed_dependency_scan(self):
        for mode, event, expected in (("", "pull_request", "not_configured"),
                                      ("disabled", "pull_request", "not_configured"),
                                      ("enabled", "schedule", "not_applicable_to_event")):
            with self.subTest(expected=expected):
                code, result, opener = self.review(mode=mode, event_name=event)
                self.assertEqual(code, 0)
                self.assertEqual(result["status"], expected)
                opener.open.assert_not_called()

    def test_requested_comparison_is_exact_public_unauthenticated_and_vulnerable_addition_blocks(self):
        code, result, opener = self.review(response=[self.change(vulnerabilities=[{"severity": "high"}])])
        self.assertEqual((code, result["status"], result["added_vulnerability_records"]), (1, "blocked", 1))
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/payals/hobnail/dependency-graph/compare/" + "a" * 40 + "..." + "b" * 40)
        self.assertNotIn("Authorization", request.headers)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 20)
        self.assertNotIn("synthetic-package", json.dumps(result))

    def test_removal_or_empty_comparison_is_not_misreported_as_an_added_vulnerability(self):
        for response in ([], [self.change(kind="removed", vulnerabilities=[{"severity": "critical"}])]):
            code, result, _ = self.review(response=response)
            self.assertEqual(code, 0)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["added_vulnerability_records"], 0)

    def test_unavailable_or_malformed_evidence_fails_without_exposing_response(self):
        error = urllib.error.HTTPError("https://api.github.com", 403, "private response must not print", {}, io.BytesIO(b"private body"))
        for arguments, expected in (({"error": error}, "unavailable"),
                                    ({"error": TimeoutError("private endpoint")}, "unavailable"),
                                    ({"response": {"unexpected": "private body"}}, "invalid_api_evidence"),
                                    ({"response": [{"change_type": "added", "vulnerabilities": []}]}, "invalid_api_evidence"),
                                    ({"mode": "unexpected"}, "configuration_error")):
            with self.subTest(expected=expected):
                code, result, _ = self.review(**arguments)
                self.assertEqual(code, 1)
                self.assertEqual(result["status"], expected)
                self.assertNotIn("private", json.dumps(result))

    def test_untrusted_event_cannot_select_another_api_destination(self):
        event = {"pull_request": {"base": {"sha": "a" * 40, "repo": {"full_name": "attacker/other"}},
                                  "head": {"sha": "b" * 40}}}
        code, result, opener = self.review(event=event)
        self.assertEqual((code, result["status"]), (1, "event_evidence_invalid"))
        opener.open.assert_not_called()

    def test_clean_first_page_with_more_results_or_truncation_never_passes(self):
        for headers in ({"Link": '<https://api.github.com/next-page>; rel="next"'},
                        {"Content-Range": "items 0-0/99"}, {"X-GitHub-Truncated": "true"}):
            with self.subTest(headers=headers):
                code, result, opener = self.review(response=[], headers=headers)
                self.assertEqual((code, result["status"]), (1, "incomplete_api_evidence"))
                self.assertEqual(opener.open.call_count, 1)
                self.assertNotIn("next-page", json.dumps(result))
        code, result, _ = self.review(response=[], headers={"Content-Length": "999"})
        self.assertEqual((code, result["status"]), (1, "invalid_api_evidence"))


if __name__ == "__main__":
    unittest.main()
