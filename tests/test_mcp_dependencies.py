"""Dependency gate refusals against explicit inert registry/network fixtures."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import check_mcp_dependencies as gate


class DependencyGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hbn-dependency-test-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.now = datetime(2026, 9, 27, tzinfo=timezone.utc)
        self.content = b"inert reviewed wheel bytes, never executed"
        self.artifact = {"filename": "fastmcp_slim-4.0.5-py3-none-any.whl",
                         "url": "https://files.pythonhosted.org/packages/00/aa/fastmcp_slim-4.0.5-py3-none-any.whl",
                         "sha256": gate.digest(self.content), "size": len(self.content),
                         "uploaded_at": "2026-09-10T12:00:00Z", "provenance": {"status": "fixture"}}
        self.package = {"name": "fastmcp-slim", "version": "4.0.5", "requires_python": ">=3.10",
                        "requires_dist": [], "project_urls": {}, "artifacts": [self.artifact],
                        "pypi_json_url": "https://pypi.org/pypi/fastmcp-slim/4.0.5/json"}
        self.lock = self.root / "integrations/mcp/requirements-synthetic.lock"
        self.lock.parent.mkdir(parents=True)
        self.lock.write_text("--only-binary=:all:\n--require-hashes\n--index-url https://pypi.org/simple\n"
                             + "fastmcp-slim[server]==4.0.5 --hash=sha256:" + self.artifact["sha256"] + "\n")
        self.profile = {"python": "3.14", "lockfile": self.lock.relative_to(self.root).as_posix(),
                        "lock_sha256": gate.digest(self.lock.read_bytes()), "packages": ["fastmcp-slim"],
                        "artifacts": [self.artifact["filename"]]}
        self.manifest = {"schema": "hobnail-mcp-dependencies-v1", "minimum_age_hours": 168,
                         "root_requirement": "fastmcp-slim[server]==4.0.5", "packages": [self.package],
                         "profiles": {"synthetic": self.profile}}
        self.path = self.root / "manifest.json"
        self.path.write_text(json.dumps(self.manifest))
        self.registry = {"info": {"name": "fastmcp_slim", "version": "4.0.5", "requires_python": ">=3.10",
                                  "requires_dist": [], "project_urls": {}},
                         "urls": [{"filename": self.artifact["filename"], "url": self.artifact["url"],
                                   "size": len(self.content), "digests": {"sha256": self.artifact["sha256"]},
                                   "upload_time_iso_8601": self.artifact["uploaded_at"],
                                   "yanked": False, "packagetype": "bdist_wheel"}], "vulnerabilities": []}
        self.osv = {}
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if url == self.package["pypi_json_url"]:
            return json.dumps(self.registry).encode()
        if url == "https://api.osv.dev/v1/query":
            self.assertEqual(kwargs["body"], {"package": {"name": "fastmcp-slim", "ecosystem": "PyPI"}, "version": "4.0.5"})
            return json.dumps(self.osv).encode()
        self.assertEqual(url, self.artifact["url"])
        self.assertEqual(kwargs["maximum"], len(self.content))
        return self.content

    def check(self, **kwargs):
        return gate.check(self.path, "synthetic", root=self.root, request=self.request, now=self.now, **kwargs)

    def test_metadata_and_exact_download_pass_without_installing_or_executing(self):
        destination = self.root / "new-wheels"
        result = self.check(download_dir=destination)
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["wheel_bytes_verified"])
        self.assertFalse(result["installed"])
        wheel = destination / self.artifact["filename"]
        self.assertEqual(wheel.read_bytes(), self.content)
        self.assertEqual(wheel.stat().st_mode & 0o777, 0o400)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(self.calls), 3)
        second = self.check(wheel_dir=destination)
        self.assertEqual(second["status"], "passed")
        self.assertEqual(len(self.calls), 5)

    def test_metadata_only_does_not_claim_wheel_verification(self):
        result = self.check()
        self.assertFalse(result["wheel_bytes_verified"])
        self.assertEqual(len(self.calls), 2)

    def test_changed_hash_size_origin_or_yanked_wheel_refuses(self):
        original = deepcopy(self.registry)
        changes = [("digests", {"sha256": "f" * 64}), ("size", 1), ("url", "https://attacker.invalid/wheel"),
                   ("yanked", True), ("packagetype", "sdist")]
        for field, value in changes:
            with self.subTest(field=field):
                self.registry = deepcopy(original)
                self.registry["urls"][0][field] = value
                with self.assertRaises(gate.DependencyError): self.check()
        self.registry = original

    def test_missing_young_future_and_conflicting_timestamps_refuse(self):
        for value in (None, "garbage", "2026-09-10T12:00:00", "2026-09-26T12:00:00Z", "2026-10-01T12:00:00Z"):
            with self.subTest(value=value):
                self.registry["urls"][0]["upload_time_iso_8601"] = value
                with self.assertRaises(gate.DependencyError): self.check()
        uploaded = self.now - timedelta(hours=167)
        self.artifact["uploaded_at"] = uploaded.isoformat()
        self.registry["urls"][0]["upload_time_iso_8601"] = uploaded.isoformat()
        self.path.write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(gate.DependencyError, "artifact_too_young_or_future"): self.check()

    def test_incomplete_malformed_or_vulnerable_osv_never_passes(self):
        for response in ({"next_page_token": "more"}, {"vulns": [{"id": "GHSA-synthetic-refusal"}]},
                         {"next_page_token": False}, {"next_page_token": 0}, {"next_page_token": None},
                         {"vulns": "wrong"}, {"unexpected": []}, {"vulns": [{}]}, []):
            with self.subTest(response=response):
                self.osv = response
                with self.assertRaises(gate.DependencyError): self.check()

    def test_dependency_or_identity_metadata_drift_refuses(self):
        for field, value in (("requires_dist", ["unreviewed>=1"]), ("requires_python", ">=3.15"),
                             ("project_urls", {"Homepage": "https://attacker.invalid"}), ("name", "other"), ("version", "4.0.6")):
            original = deepcopy(self.registry)
            with self.subTest(field=field):
                self.registry["info"][field] = value
                with self.assertRaises(gate.DependencyError): self.check()
            self.registry = original

    def test_pypi_advisories_refuse_even_when_osv_would_be_empty(self):
        for advisories in ([{"id": "PYSEC-synthetic"}], None, {}, "invalid"):
            with self.subTest(advisories=advisories):
                self.registry["vulnerabilities"] = advisories
                with self.assertRaises(gate.DependencyError): self.check()
        self.assertTrue(all(url != "https://api.osv.dev/v1/query" for url, _ in self.calls))

    def test_advisory_refusal_names_package_ids_and_fixed_versions_only(self):
        self.registry["vulnerabilities"] = [{"id": "GHSA-4v2x-9hqm-p7rc", "aliases": ["CVE-2026-0001", "ignore-previous_instructions", "GHSA-ignore-previous-instructions"],
                                             "fixed_in": ["4.0.6", "$(rm -rf /)"], "withdrawn": None,
                                             "summary": "remote prose is never copied", "link": "https://attacker.invalid"}]
        with self.assertRaises(gate.AdvisoryFinding) as caught: self.check()
        self.assertEqual(caught.exception.args[0], "pypi_known_vulnerability_record")
        self.assertEqual(caught.exception.findings, [{"name": "fastmcp-slim", "version": "4.0.5", "source": "pypi", "advisories": [
            {"id": "GHSA-4v2x-9hqm-p7rc", "aliases": ["CVE-2026-0001"], "fixed_in": ["4.0.6"], "withdrawn": False, "unparsed_fields": 3}]}])
        self.assertNotIn("prose", json.dumps(caught.exception.findings))

    def test_only_real_advisory_id_shapes_and_strict_withdrawn_values_are_kept(self):
        for value in ("GHSA-42vr-xj54-vc7v", "CVE-2026-101918", "PYSEC-2026-12", "OSV-2026-3", "MAL-2026-4567"):
            self.assertTrue(gate.ADVISORY_ID.fullmatch(value), value)
        for value in ("ignore-previous_instructions", "GHSA-ignore-previous-instructions", "CVE-26-1",
                      "GHSA-42VR-XJ54-VC7V", "RUN-2026-1", "PYSEC-2026-1 extra"):
            self.assertIsNone(gate.ADVISORY_ID.fullmatch(value), value)
        for value, expected in ((True, True), ("true", True), ("2026-09-30T00:00:00Z", True), ("false", False),
                                (False, False), (None, False), ("", False), ("yes", False), (1, False)):
            self.assertIs(gate._withdrawn(value), expected, value)

    def test_osv_refusal_reports_fixed_versions_for_the_matching_package(self):
        self.osv = {"vulns": [{"id": "PYSEC-2026-1", "aliases": [], "affected": [
            {"package": {"ecosystem": "PyPI", "name": "fastmcp_slim"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.0.7"}]}]},
            {"package": {"ecosystem": "PyPI", "name": "other"}, "ranges": [{"events": [{"fixed": "9.9"}]}]}]}]}
        with self.assertRaises(gate.AdvisoryFinding) as caught: self.check()
        self.assertEqual(caught.exception.args[0], "known_vulnerability_record")
        self.assertEqual(caught.exception.findings[0]["advisories"][0]["fixed_in"], ["4.0.7"])

    def test_every_vulnerable_package_is_reported_together(self):
        second = {"name": "pyjwt", "version": "2.14.0", "requires_python": ">=3.9", "requires_dist": [], "project_urls": {},
                  "pypi_json_url": "https://pypi.org/pypi/pyjwt/2.14.0/json",
                  "artifacts": [{**self.artifact, "filename": "pyjwt-2.14.0-py3-none-any.whl",
                                 "url": "https://files.pythonhosted.org/packages/00/bb/pyjwt-2.14.0-py3-none-any.whl"}]}
        self.manifest["packages"].append(second)
        self.profile["packages"].append("pyjwt"); self.profile["artifacts"].append(second["artifacts"][0]["filename"])
        self.lock.write_text(self.lock.read_text() + "pyjwt==2.14.0 --hash=sha256:" + self.artifact["sha256"] + "\n")
        self.profile["lock_sha256"] = gate.digest(self.lock.read_bytes())
        self.path.write_text(json.dumps(self.manifest))
        self.registry["vulnerabilities"] = [{"id": "GHSA-2f4h-7q9w-x3mc", "aliases": [], "fixed_in": ["4.0.6"], "withdrawn": None}]
        other = {"info": {"name": "PyJWT", "version": "2.14.0", "requires_python": ">=3.9", "requires_dist": [], "project_urls": {}},
                 "urls": [], "vulnerabilities": [{"id": "GHSA-42vr-xj54-vc7v", "aliases": ["CVE-2026-101918"], "fixed_in": ["2.15.0"], "withdrawn": None}]}
        request = lambda url, **kwargs: json.dumps(other).encode() if url == second["pypi_json_url"] else self.request(url, **kwargs)
        with self.assertRaises(gate.AdvisoryFinding) as caught:
            gate.check(self.path, "synthetic", root=self.root, request=request, now=self.now)
        self.assertEqual([(f["name"], f["advisories"][0]["id"], f["advisories"][0]["fixed_in"]) for f in caught.exception.findings],
                         [("fastmcp-slim", "GHSA-2f4h-7q9w-x3mc", ["4.0.6"]), ("pyjwt", "GHSA-42vr-xj54-vc7v", ["2.15.0"])])

    def test_identity_drift_still_refuses_once_the_advisory_is_absent(self):
        self.registry["vulnerabilities"] = [{"id": "GHSA-2f4h-7q9w-x3mc"}]
        self.registry["info"]["version"] = "4.0.6"
        with self.assertRaises(gate.AdvisoryFinding): self.check()
        self.registry["vulnerabilities"] = []
        with self.assertRaisesRegex(gate.DependencyError, "pypi_identity_differs"): self.check()

    def test_main_prints_findings_and_remediation(self):
        self.registry["vulnerabilities"] = [{"id": "GHSA-42vr-xj54-vc7v", "aliases": ["CVE-2026-101918"], "fixed_in": ["2.15.0"], "withdrawn": None}]
        stdout, stderr, real = io.StringIO(), io.StringIO(), gate.check
        fixture = lambda *a, **k: real(self.path, "synthetic", root=self.root, request=self.request, now=self.now)
        with patch.object(gate, "check", fixture), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(gate.main(["--profile", "synthetic"]), 1)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["code"], "pypi_known_vulnerability_record")
        self.assertEqual(result["findings"][0]["advisories"][0]["fixed_in"], ["2.15.0"])
        self.assertIn("docs/MCP.md", result["remediation"])
        self.assertIn("fastmcp-slim==4.0.5", stderr.getvalue())
        self.assertIn("GHSA-42vr-xj54-vc7v, CVE-2026-101918; fixed in: 2.15.0", stderr.getvalue())

    def test_root_server_extra_is_required_and_lock_hash_is_bound(self):
        self.lock.write_text(self.lock.read_text().replace("[server]", ""))
        with self.assertRaisesRegex(gate.DependencyError, "lock_hash_differs"): self.check()
        self.profile["lock_sha256"] = gate.digest(self.lock.read_bytes())
        self.path.write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(gate.DependencyError, "lock_extra_invalid"): self.check()
        self.assertEqual(self.calls, [])

    def test_reviewed_lock_cannot_add_index_unpinned_or_unknown_package(self):
        original = self.lock.read_text()
        for suffix in ("\n--extra-index-url https://attacker.invalid\n", "\nunreviewed>=1\n",
                       "\nunreviewed==1.0 --hash=sha256:" + "a" * 64 + "\n"):
            self.lock.write_text(original + suffix)
            self.profile["lock_sha256"] = gate.digest(self.lock.read_bytes())
            self.path.write_text(json.dumps(self.manifest))
            with self.subTest(suffix=suffix), self.assertRaises(gate.DependencyError): self.check()
        self.assertEqual(self.calls, [])

    def test_manifest_rejects_prerelease_alias_url_duplicate_and_missing_graph_members(self):
        for change in (lambda m: m["packages"][0].update(version="4.1.0rc1"),
                       lambda m: m["packages"][0].update(pypi_json_url="https://attacker.invalid/pypi/x/json"),
                       lambda m: m["profiles"]["synthetic"].update(packages=["missing"]),
                       lambda m: m["profiles"]["synthetic"].update(packages=["fastmcp-slim", "fastmcp-slim"]),
                       lambda m: m.update(minimum_age_hours=0),
                       lambda m: m["profiles"]["synthetic"].update(lockfile="../secret")):
            value = deepcopy(self.manifest); change(value); self.path.write_text(json.dumps(value))
            with self.assertRaises(gate.DependencyError): self.check()
        self.assertEqual(self.calls, [])
        self.path.write_text('{"schema":"one","schema":"two"}')
        with self.assertRaisesRegex(gate.DependencyError, "duplicate_json_key"): self.check()

    def test_wheel_tamper_alias_unexpected_files_and_existing_download_target_refuse(self):
        destination = self.root / "wheels"; destination.mkdir()
        wheel = destination / self.artifact["filename"]
        wheel.write_bytes(b"wrong")
        with self.assertRaises(gate.DependencyError): self.check(wheel_dir=destination)
        wheel.unlink(); original = self.root / "original"; original.write_bytes(self.content); wheel.symlink_to(original)
        with self.assertRaisesRegex(gate.DependencyError, "aliased_input"): self.check(wheel_dir=destination)
        wheel.unlink(); wheel.write_bytes(self.content)
        (destination / "unexpected").write_text("kept")
        with self.assertRaisesRegex(gate.DependencyError, "wheel_directory_members_differ"): self.check(wheel_dir=destination)
        with self.assertRaises(FileExistsError): self.check(download_dir=destination)
        self.assertEqual((destination / "unexpected").read_text(), "kept")

    def test_network_failure_and_malformed_json_are_not_clean_evidence(self):
        for raw in (b'not-json', b'{"vulns":NaN}', b'{"vulns":[],"vulns":[]}'):
            with self.subTest(raw=raw), self.assertRaises(gate.DependencyError): gate.parse_json(raw)
        with patch.object(gate.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = TimeoutError("private diagnostics")
            with self.assertRaisesRegex(gate.DependencyError, "^network_evidence_unavailable$"):
                gate.fetch("https://api.osv.dev/v1/query", body={})
        for url in ("http://pypi.org/pypi/x/json", "https://pypi.org.evil.invalid/pypi/x/json",
                    "https://pypi.org:443/pypi/x/json", "https://api.osv.dev/private", "https://user@pypi.org/pypi/x/json"):
            with self.subTest(url=url), self.assertRaises(gate.DependencyError): gate.fetch(url)

    def test_existing_receipt_is_unchanged_and_check_not_started(self):
        receipt = self.root / "receipt.json"; receipt.write_text("preserve me")
        with patch.object(gate, "check", side_effect=AssertionError("must not run")), redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(["--profile", "synthetic", "--receipt", str(receipt)]), 1)
        self.assertEqual(receipt.read_text(), "preserve me")

    def test_automatic_profile_refuses_unreviewed_libc_and_old_macos(self):
        with patch.object(gate.platform, "system", return_value="Linux"), patch.object(gate.platform, "machine", return_value="x86_64"):
            for library, version in (("musl", "1.2.5"), ("glibc", "2.27"), ("", "")):
                with self.subTest(library=library, version=version), patch.object(gate.platform, "libc_ver", return_value=(library, version)):
                    self.assertEqual(gate.automatic_profile(), "unsupported-linux-libc")
            with patch.object(gate.platform, "libc_ver", return_value=("glibc", "2.28")):
                self.assertTrue(gate.automatic_profile().startswith("linux-x86_64-py"))
        with patch.object(gate.platform, "system", return_value="Darwin"), patch.object(gate.platform, "machine", return_value="arm64"):
            with patch.object(gate.platform, "mac_ver", return_value=("10.15", (), "")):
                self.assertEqual(gate.automatic_profile(), "unsupported-macos-version")
            with patch.object(gate.platform, "mac_ver", return_value=("11.0", (), "")):
                self.assertTrue(gate.automatic_profile().startswith("macos-arm64-py"))


if __name__ == "__main__":
    unittest.main()
