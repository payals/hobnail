#!/usr/bin/env python3
"""Run one explicit stdlib/Git POSIX test profile; never silently skip tests.

This profile does not qualify PostgreSQL, macOS isolation, Docker, OpenBao or an
adjacent project. Classification is deliberate: an unknown new test file or a
missing selected module is a refusal, not a reason to alter the selection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "hobnail-portable-posix-v1"
SELECTED = {
    "test_mcp_dependencies.py": "Exact dependency metadata, lock and network refusal checks using inert registry fixtures; no downloads or package execution.",
    "test_mcp_adapter.py": "Dependency-free worker adapter, configuration, package metadata and bounded stdio client fixtures; no MCP framework or database runtime.",
    "test_client_limits.py": "Actual owned local subprocess output, backpressure, timeout and retirement checks; no database or third-party execution.",
    "test_docker_sources.py": "Pinned source assembly and anonymous retrieval checks with inert fixtures; no acquired image execution.",
    "test_jev_advice.py": "Offline advisory recipes, bounded HTTP fixtures and private receipt handling; no model accuracy or runtime authority claim.",
    "test_contracts.py": "Closed contract shapes and non-authoritative discovery.",
    "test_client.py": "SDK/CLI transport and JSON checks with controlled subprocess results.",
    "test_audit.py": "Exact audit bytes, checkpoints and bounded export fixtures.",
    "test_adapter_contracts.py": "File/Git/research action argument validation.",
    "test_openbao_acl_checks.py": "Pure ACL-checker orchestration, not live server evidence.",
    "test_execution_backend.py": "Explicit backend selection and owned source snapshots; no native sandbox.",
    "test_release_inventory_facts.py": "Committed-object facts from temporary local Git repositories.",
    "test_release_safety.py": "Redacted release scanning with synthetic bytes and temporary Git repositories.",
    "test_maintenance_triage.py": "Offline advisory schema and controlled HTTP/worker fixtures; no model calls or credential inspection.",
    "test_maintenance_policy.py": "Prepared maintenance policy/workflow fixtures with mocked Git/HTTP; no live GitHub configuration.",
    "test_effects.py": "Actual temporary POSIX file publication/observation; no service isolation claim.",
    "test_qualified_openbao.py": "Controlled cleanup fixtures; no OpenBao/PostgreSQL runtime construction.",
    "test_docker_policy.py": "Static profile and inert archive preparation fixtures; no Docker or acquired-code execution.",
    "test_docker_entrypoints.py": "Owned entrypoint, framing and inert local-child fixtures; no Docker or PostgreSQL execution.",
    "test_docker_supervisor.py": "Supervisor faults with controlled Docker/child interfaces; no daemon or image execution.",
    "test_docker_qualification_unit.py": "Qualification, probe and cleanup fixtures with controlled runtime/SQL interfaces.",
    "test_verify_public_distribution.py": "Standard public archives and tamper checks built from first-party temporary source fixtures.",
    "test_check_portable.py": "Runner refusal/receipt and CI bootstrap validation fixtures.",
}
EXCLUDED_GROUPS = {
    "postgresql": (
        "Requires fresh owned PostgreSQL 18 and module-specific integration prerequisites.",
        ("test_administrator_retirement.py", "test_bootstrap_cleanup.py", "test_catalog_resolution.py",
         "test_credential_kernel.py", "test_credential_recovery.py", "test_credentials.py",
         "test_dev_cluster.py", "test_explicit_dev_cluster.py", "test_external_credentials.py",
         "test_git_effects.py", "test_kernel_acceptance.py", "test_password_authentication.py",
         "test_recovery.py", "test_research_integration.py", "test_typed_operations.py",
         "test_acceptance_proofs.py")),
    "optional_mcp_runtime": (
        "Requires the reviewed optional MCP dependency lock, actual stdio server, owned PostgreSQL and native macOS role services.",
        ("test_mcp_runtime.py", "test_mcp_protocol.py")),
    "native_macos": (
        "Requires actual macOS confinement and, where composed, owned PostgreSQL; not a portable substitute.",
        ("test_end_to_end.py", "test_isolation.py", "test_native_application.py", "test_native_effects.py",
         "test_native_recovery.py", "test_plugin_runtime.py", "test_qualified_local.py",
         "test_runtime_pipeline.py", "test_runtime_review.py", "test_service_isolation.py",
         "test_validators.py", "test_release_inventory_workload.py")),
    "approved_openbao": (
        "Requires the exact owner-approved reviewed OpenBao artifact and exclusive native runtime.",
        ("test_openbao_runtime.py",)),
    "distribution": (
        "Separate offline package verification against its complete declared source/archive profile.",
        ("test_verify_distribution.py",)),
    "docker_runtime": (
        "Requires reviewed images, explicit release authority and actual owned Docker integration.",
        ("test_docker_runtime.py",)),
    "private_release_preparation": (
        "Internal initial-publication exporter fixtures; tooling is deliberately absent from the public candidate.",
        ("test_public_export.py",)),
}


class PortableCheckError(RuntimeError):
    pass


def private_inventory(root):
    """A private checkout may add explicit classifications outside public source.

    Missing this optional file never hides an on-disk module: ordinary unknown-
    module detection still refuses. Private entries cannot override public ones.
    """
    path = root / "release/private-portable-tests.json"
    if not path.exists() and not path.is_symlink():
        return [], None
    if path.is_symlink() or path.resolve(strict=True) != path or not path.is_file():
        raise PortableCheckError("private_inventory_not_regular_canonical")
    if path.stat().st_size > 65536:
        raise PortableCheckError("private_inventory_too_large")
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise PortableCheckError("private_inventory_too_large")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise PortableCheckError("duplicate_private_inventory_key")
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise PortableCheckError("private_inventory_invalid_json") from None
    if (not isinstance(value, dict) or set(value) != {"schema", "tests"}
            or value["schema"] != "hobnail-private-test-inventory-v1"
            or not isinstance(value["tests"], list) or len(value["tests"]) > 128):
        raise PortableCheckError("private_inventory_invalid_schema")
    for entry in value["tests"]:
        if (not isinstance(entry, dict) or set(entry) != {"file", "category", "reason"}
                or not isinstance(entry["file"], str) or not re.fullmatch(r"test_[a-z0-9_]+\.py", entry["file"])
                or not isinstance(entry["category"], str) or entry["category"] not in {"portable", "adjacent_project"}
                or not isinstance(entry["reason"], str) or len(entry["reason"].strip()) < 12):
            raise PortableCheckError("private_inventory_invalid_entry")
    return value["tests"], hashlib.sha256(raw).hexdigest()


def describe(root: Path = ROOT) -> dict:
    root = Path(root).resolve()
    classified = {name: ("portable", reason) for name, reason in SELECTED.items()}
    for category, (reason, names) in EXCLUDED_GROUPS.items():
        for name in names:
            if name in classified:
                raise PortableCheckError("duplicate_test_classification:" + name)
            classified[name] = category, reason
    private, private_hash = private_inventory(root)
    selected_names = set(SELECTED)
    for entry in private:
        name = entry["file"]
        if name in classified:
            raise PortableCheckError("duplicate_test_classification:" + name)
        classified[name] = entry["category"], entry["reason"]
        if entry["category"] == "portable":
            selected_names.add(name)
    tests = root / "tests"
    # Match unittest's normal discovery name pattern, including names without
    # an underscore, so a new discoverable file cannot evade classification.
    present = {path.relative_to(tests).as_posix(): path for path in tests.rglob("test*.py")}
    unknown = sorted(present.keys() - classified.keys())
    if unknown:
        raise PortableCheckError("unclassified_test_files:" + ",".join(unknown))
    missing = sorted(selected_names - present.keys())
    if missing:
        raise PortableCheckError("required_portable_tests_missing:" + ",".join(missing))
    for name, path in present.items():
        if not path.is_file() or path.is_symlink() or path.resolve() != path:
            raise PortableCheckError("test_path_not_regular_canonical:" + name)
    rows = []
    for name in sorted(classified):
        category, reason = classified[name]
        rows.append({"file": "tests/" + name, "module": Path(name).stem, "category": category,
                     "selected": name in selected_names, "present": name in present, "reason": reason,
                     "sha256": hashlib.sha256(present[name].read_bytes()).hexdigest() if name in present else None})
    return {"schema": "hobnail-portable-checks-v1", "profile": PROFILE, "status": "listed",
            "scope": "explicit stdlib/Git POSIX source checks; no runtime or adjacent-project qualification",
            "discovery_pattern": "tests/**/test*.py",
            "private_inventory_sha256": private_hash,
            "selected": [row for row in rows if row["selected"]],
            "nonselected": [row for row in rows if not row["selected"]],
            "unclassified": [], "selection_changed_on_failure": False}


def run_profile(root: Path = ROOT) -> dict:
    report = describe(root)
    root = Path(root).resolve()
    original_path = sys.path[:]
    try:
        sys.path[:0] = [str(root / "tests"), str(root / "src"), str(root)]
        suite = unittest.TestSuite()
        for row in report["selected"]:
            selected = unittest.defaultTestLoader.loadTestsFromNames([row["module"]])
            if selected.countTestCases() == 0:
                raise PortableCheckError("selected_module_has_no_tests:" + row["module"])
            suite.addTests(selected)
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    finally:
        sys.path[:] = original_path
    try:
        unchanged = describe(root) == report
    except (PortableCheckError, OSError) as error:
        unchanged = False
        report["inventory_error"] = str(error) if isinstance(error, PortableCheckError) else type(error).__name__
    report.update({"status": "passed" if result.wasSuccessful() and not result.skipped
                   and not result.expectedFailures and unchanged else "failed",
                   "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
                   "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
                   "unexpected_successes": len(result.unexpectedSuccesses),
                   "test_inventory_unchanged": unchanged})
    return report


def reserve_receipt(path: Path) -> int:
    path = path.absolute()
    if path.parent.resolve(strict=True) != path.parent:
        raise PortableCheckError("receipt_parent_must_be_canonical")
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list explicit selected/nonselected modules without executing tests")
    parser.add_argument("--receipt", type=Path, help="write JSON to a new file in an existing canonical directory; never overwrite")
    args = parser.parse_args(argv)
    descriptor = None
    try:
        if args.receipt is not None:
            descriptor = reserve_receipt(args.receipt)
        report = describe() if args.list else run_profile()
    except (PortableCheckError, OSError) as error:
        report = {"schema": "hobnail-portable-checks-v1", "profile": PROFILE, "status": "refused",
                  "error": str(error) if isinstance(error, PortableCheckError) else type(error).__name__}
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if descriptor is not None:
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            report["status"] = "refused"
            report["error"] = "receipt_persistence_failed"
            encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(encoded, end="")
    return 0 if report["status"] in {"listed", "passed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
