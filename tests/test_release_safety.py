"""Redacted public-candidate/history gates with explicit synthetic fixtures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.release_safety import ReleaseScanError, load_allowlist, scan_bytes, scan_repository


class ReleaseSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hbn-scan-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.git("init", "--quiet", "--object-format=sha1")

    def git(self, *args, email="payals@users.noreply.github.com"):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}
        return subprocess.check_output(["git", "-C", str(self.root), "-c", "core.hooksPath=/dev/null",
            "-c", "user.name=payals", "-c", "user.email=" + email, *args], env=env, stderr=subprocess.DEVNULL).decode().strip()

    def commit(self, email="payals@users.noreply.github.com"):
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "Owned scan fixture", email=email)
        return self.git("rev-parse", "HEAD")

    def test_current_tree_success_does_not_hide_earlier_private_content(self):
        marker = b"/Users/" + b"synthetic-owner/private-project/evidence.json"
        (self.root / "report.md").write_bytes(marker)
        self.commit()
        (self.root / "report.md").write_text("public description")
        head = self.commit()
        self.assertEqual(scan_repository(self.root, head)["status"], "passed")
        history = scan_repository(self.root, head, history=True)
        self.assertEqual(history["status"], "blocked")
        self.assertEqual(history["commits_scanned"], 2)
        self.assertNotIn(marker.decode(), json.dumps(history))
        self.assertTrue(any(item["rule"] == "home_path" for item in history["findings"]))

    def test_commit_attribution_and_tracked_generated_files_block(self):
        (self.root / ".state").mkdir()
        (self.root / ".state/report.json").write_text("{}")
        private_email = "synthetic-person@institution.example.invalid"
        head = self.commit(email=private_email)
        report = scan_repository(self.root, head, history=True)
        self.assertEqual(report["status"], "blocked")
        self.assertNotIn(private_email, json.dumps(report))
        self.assertEqual({row["rule"] for row in report["findings"]}, {"unapproved_commit_email", "private_or_generated_path"})

    def test_shallow_and_grafted_history_cannot_hide_a_parent_finding(self):
        (self.root / "report.txt").write_text("/Users/" + "synthetic-owner/private-data")
        self.commit()
        (self.root / "report.txt").write_text("clean tip")
        head = self.commit()
        for name in ("shallow", "info/grafts"):
            metadata = self.root / ".git" / name
            metadata.write_text(head + "\n")
            try:
                with self.assertRaisesRegex(ReleaseScanError, "complete_ungrafted"):
                    scan_repository(self.root, head, history=True)
            finally:
                metadata.unlink()

    def test_sensitive_filename_is_scanned_and_location_never_emits_value(self):
        marker = "ghp_" + "q" * 36
        name = marker + ".txt"
        report = scan_bytes("tests/" + name, marker.encode())
        self.assertTrue(report)
        self.assertNotIn(marker, json.dumps(report))
        self.assertEqual(report[0]["path"], "<redacted-path>")
        (self.root / name).write_text("harmless content")
        head = self.commit()
        result = scan_repository(self.root, head, history=True)
        self.assertEqual(result["status"], "blocked")
        self.assertNotIn(marker, json.dumps(result))
        self.assertTrue(any(item["rule"] == "filename_github_token" for item in result["findings"]))

    def test_exact_fixture_allowance_cannot_hide_different_file_or_value(self):
        content = b'password = "synthetic-fixture-value"\n'
        match = scan_bytes("tests/owned.py", content)[0]
        allowlist = {(match["path"], match["rule"], match["match_sha256"]): "Synthetic fixture; no external account or real credential"}
        self.assertTrue(scan_bytes("tests/owned.py", content, allowlist=allowlist)[0]["allowed"])
        self.assertFalse(scan_bytes("src/runtime.py", content, allowlist=allowlist)[0]["allowed"])
        self.assertFalse(scan_bytes("tests/owned.py", content.replace(b"value", b"different"), allowlist=allowlist)[0]["allowed"])

    def test_known_signature_reports_hash_and_location_without_value(self):
        marker = ("ghp_" + "a" * 36).encode()
        report = scan_bytes("owned.txt", b"line one\n" + marker)
        self.assertEqual(report[0]["rule"], "github_token")
        self.assertEqual(report[0]["line"], 2)
        self.assertEqual(report[0]["match_sha256"], hashlib.sha256(marker).hexdigest())
        self.assertNotIn(marker.decode(), json.dumps(report))

    def test_generic_system_paths_are_not_private_evidence(self):
        self.assertEqual(scan_bytes("owned.txt", b"/private/tmp /tmp /usr/lib /System/Library"), [])
        self.assertTrue(scan_bytes("owned.txt", b"/private/tmp/" + b"hbn-owned-evidence/receipt.json"))

    def test_allowing_header_text_cannot_allow_a_complete_private_key_block(self):
        header = b"-----BEGIN " + b"PRIVATE KEY-----"
        end = b"-----END " + b"PRIVATE KEY-----"
        initial = scan_bytes("tests/owned.py", header)[0]
        allowances = {(initial["path"], initial["rule"], initial["match_sha256"]): "Nonsecret marker text used by an output-exclusion test"}
        full = header + b"\n" + b"QUJD" * 20 + b"\n" + end
        findings = scan_bytes("tests/owned.py", full, allowlist=allowances)
        self.assertTrue(any(item["rule"] == "private_key" and not item["allowed"] for item in findings))
        self.assertNotIn(full.decode(), json.dumps(findings))

    def test_credential_query_is_redacted(self):
        value = b"https://example.invalid/?access_token=" + b"synthetic-query-value"
        findings = scan_bytes("example.txt", value)
        self.assertTrue(any(item["rule"] == "credential_query" for item in findings))
        self.assertNotIn("synthetic-query-value", json.dumps(findings))

    def test_allowlist_refuses_wildcards_and_duplicates(self):
        path = self.root / "allow.json"
        entry = {"path": "tests/*", "rule": "credential_literal", "match_sha256": "a" * 64, "reason": "synthetic fixture only"}
        path.write_text(json.dumps({"schema": "hobnail-scan-allowlist-v1", "entries": [entry]}))
        with self.assertRaises(ReleaseScanError):
            load_allowlist(path)
        entry["path"] = "tests/example.py"
        path.write_text(json.dumps({"schema": "hobnail-scan-allowlist-v1", "entries": [entry, entry]}))
        with self.assertRaises(ReleaseScanError):
            load_allowlist(path)

    def test_public_collaboration_policy_is_explicit_and_never_admits_private_attribution(self):
        for index, address in enumerate(("123+contributor@users.noreply.github.com",
                "49699333+dependabot[bot]@users.noreply.github.com", "noreply@github.com",
                "synthetic-person@institution.example.invalid", "noreply@github.com.invalid")):
            (self.root / "public.txt").write_text(str(index))
            head = self.commit(email=address)
            self.assertEqual(scan_repository(self.root, head)["status"], "blocked")
            result = scan_repository(self.root, head, attribution_policy="github-noreply")
            self.assertEqual(result["status"], "passed" if index < 3 else "blocked")
            self.assertEqual(result["attribution_policy"], "github-noreply")
            self.assertNotIn(address, json.dumps(result))
        with self.assertRaisesRegex(ReleaseScanError, "unknown_attribution_policy"):
            scan_repository(self.root, head, attribution_policy="anything")


if __name__ == "__main__":
    unittest.main()
