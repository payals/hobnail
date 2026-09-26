#!/usr/bin/env python3
"""Deliver an independently checked inventory of one sanitized release export.

The producer reads only the supplied filesystem snapshot. Expected facts arrive
separately from the trusted Git-object registrar. This module never reads Git.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.native_application import NativeApplication
from hobnail.deployment import NativeConsumer

REQUIRED_DOCUMENTS = (
    "AGENTS.md", "CONTRIBUTING.md", "LICENSE", "README.md", "SECURITY.md",
    "docs/AGENT-GUIDE.md", "docs/CONTRACT.md", "docs/OPERATIONS.md", "docs/SUPPORT.md",
)
SCHEMA = "hobnail-release-inventory-v1"
TARGET = "release-inventory.json"
MAX_FILES = 2048
MAX_BLOB_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


class WorkloadError(RuntimeError):
    """A fixed diagnostic code, without source contents or machine paths."""


def require(condition, code):
    if not condition:
        raise WorkloadError(code)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha(content):
    return hashlib.sha256(content).hexdigest()


def _safe_path(value):
    path = PurePosixPath(value)
    return (isinstance(value, str) and value == path.as_posix() and not path.is_absolute()
            and value not in {"", "."} and all(part not in {"..", ".git"} for part in path.parts)
            and len(value) <= 1024 and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", value) is not None)


def _read_regular(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), "snapshot_nonregular_file")
        require(before.st_size <= MAX_BLOB_BYTES, "snapshot_blob_exceeds_limit")
        content = stream.read(MAX_BLOB_BYTES + 1)
        require(len(content) <= MAX_BLOB_BYTES, "snapshot_blob_exceeds_limit")
        after = os.fstat(stream.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode),
            "snapshot_changed_during_read")
    return content, "100755" if before.st_mode & 0o111 else "100644"


def producer_inventory(snapshot_root, source_commit, required_documents=REQUIRED_DOCUMENTS):
    """Enumerate the complete owned export without reading an expected answer."""
    require(isinstance(source_commit, str) and re.fullmatch(r"[0-9a-f]{40}", source_commit), "invalid_source_commit")
    require(tuple(required_documents) == REQUIRED_DOCUMENTS, "required_documents_changed")
    root = Path(snapshot_root).absolute()
    require(root.resolve() == root and root.is_dir(), "snapshot_root_not_canonical")
    entries = []
    total = 0
    package_bytes = None
    pending = [root]
    while pending:
        directory = pending.pop()
        require(directory.resolve() == directory and stat.S_ISDIR(directory.lstat().st_mode), "snapshot_directory_changed")
        with os.scandir(directory) as children:
            for child in children:
                path = Path(child.path)
                relative = path.relative_to(root).as_posix()
                require(_safe_path(relative), "unsafe_snapshot_path")
                metadata = child.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(path)
                    continue
                require(stat.S_ISREG(metadata.st_mode), "snapshot_nonregular_file")
                require(len(entries) < MAX_FILES, "snapshot_file_count_exceeds_limit")
                content, mode = _read_regular(path)
                total += len(content)
                require(total <= MAX_TOTAL_BYTES, "snapshot_total_bytes_exceed_limit")
                require(path.resolve() == path, "snapshot_file_aliased")
                entries.append({"path": relative, "sha256": sha(content), "mode": mode, "bytes": len(content)})
                if relative == "pyproject.toml":
                    package_bytes = content
    entries.sort(key=lambda entry: entry["path"])
    paths = {entry["path"] for entry in entries}
    require(set(required_documents) <= paths, "required_document_missing")
    require(package_bytes is not None, "package_metadata_missing")
    metadata = tomllib.loads(package_bytes.decode("utf-8"))["project"]
    package = {"name": metadata["name"], "version": metadata["version"],
               "requires_python": metadata["requires-python"], "license": metadata["license"],
               "entry_points": metadata.get("scripts", {})}
    require(all(isinstance(package[key], str) and package[key] for key in
                ("name", "version", "requires_python", "license")), "invalid_package_metadata")
    require(package["license"] in {"MIT", "Apache-2.0"}, "unsupported_declared_license")
    require(isinstance(package["entry_points"], dict) and package["entry_points"] and all(isinstance(key, str) and isinstance(value, str)
            for key, value in package["entry_points"].items()), "invalid_entry_points")
    migrations = []
    for entry in entries:
        path = PurePosixPath(entry["path"])
        if path.parts[0] == "migrations":
            match = re.fullmatch(r"migrations/([0-9]{3})_[A-Za-z0-9_]+\.sql", entry["path"])
            require(match is not None, "invalid_migration_name")
            migrations.append({"version": int(match[1]), "path": entry["path"], "sha256": entry["sha256"]})
    require(migrations and [item["version"] for item in migrations] == list(range(1, len(migrations) + 1)),
            "invalid_migration_versions")
    return {"schema": SCHEMA, "source_commit": source_commit, "package": package,
            "files": entries, "counts": {"files": len(entries), "bytes": sum(entry["bytes"] for entry in entries)},
            "migrations": migrations, "required_documents": list(required_documents)}


def contract(application):
    principals = application.principals
    pointers = ["/" + key for key in ("schema", "source_commit", "package", "files", "counts", "migrations", "required_documents")]
    pointers += ["/package/" + key for key in ("name", "version", "requires_python", "license", "entry_points")]
    return {"schema_version": 1, "description": "Exact fresh sanitized release inventory",
        "access": {"workers": [principals["worker"]], "verifiers": [principals["verifier"]],
                   "observers": [principals["observer"]], "adapters": {"publish": [principals["adapter"]]}},
        "subject": {"media_type": "application/json", "max_bytes": 1048576},
        "sources": [{"name": "gitfacts", "registrars": [principals["registrar"]], "require_current": True}],
        "checks": [
            {"id": "shape", "plugin": "json.required_fields", "plugin_digest": application.plugin_digests["json.required_fields"],
             "parameters": {"pointers": pointers}, "max_age_seconds": 300},
            {"id": "whole-document", "plugin": "json.equals", "plugin_digest": application.plugin_digests["json.equals"],
             "parameters": {"source": "gitfacts", "pairs": [{"artifact": "", "input": ""}]}, "max_age_seconds": 300}],
        "actions": [{"name": "publish", "plugin": "file.publish", "plugin_digest": application.plugin_digests["file.publish"],
                     "target": TARGET, "arguments": {}, "max_age_seconds": 300}],
        "budgets": {"verification": 2, "effects": 1},
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")}


def render_inventory(inventory, comparison=None):
    """Render the observed inventory, with no scripts or external resources."""
    def escaped(value):
        return html.escape(str(value), quote=True)
    package = inventory["package"]
    rows = "".join("<tr>" + "".join("<td>" + escaped(entry[key]) + "</td>"
                  for key in ("path", "mode", "bytes", "sha256")) + "</tr>" for entry in inventory["files"])
    migration_rows = "".join("<li>" + escaped(item["path"]) + " — version " + str(item["version"])
                             + "; SHA-256 " + escaped(item["sha256"]) + "</li>" for item in inventory["migrations"])
    required = "".join("<li>" + escaped(path) + "</li>" for path in inventory["required_documents"])
    metadata = "".join("<dt>" + escaped(key) + "</dt><dd>" + escaped(value) + "</dd>" for key, value in package.items()
                       if key != "entry_points")
    metadata += "<dt>entry_points</dt><dd>" + escaped(json.dumps(package["entry_points"], sort_keys=True)) + "</dd>"
    cost = ("<h2>Measured execution evidence</h2><pre>" + escaped(json.dumps(comparison, sort_keys=True, indent=2)) + "</pre>"
            if comparison is not None else "")
    return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">"
            "<title>Hobnail release inventory</title><style>body{font:16px system-ui;margin:2rem;line-height:1.5}"
            "table{border-collapse:collapse;width:100%;font-size:.8rem}td,th{text-align:left;border:1px solid #aaa;padding:.4rem}"
            "td{overflow-wrap:anywhere}pre{white-space:pre-wrap}dt{font-weight:bold}dd{margin-bottom:.5rem}</style>"
            "<h1>Hobnail release inventory</h1><p>Selected sanitized export commit: <code>" + escaped(inventory["source_commit"])
            + "</code>.</p><p>" + str(inventory["counts"]["files"]) + " files; " + str(inventory["counts"]["bytes"])
            + " bytes. This is a source inventory, not a publication or deployment certification.</p><dl>" + metadata
            + "</dl><h2>Migrations</h2><ul>" + migration_rows + "</ul><h2>Required documents</h2><ul>" + required
            + "</ul>" + cost + "<h2>Complete file inventory</h2><table><thead><tr><th>Path</th><th>Mode</th>"
            "<th>Bytes</th><th>SHA-256</th></tr></thead><tbody>" + rows + "</tbody></table></html>\n")


def _write_new(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def _native_case(name, artifact, expected, destination, receipt):
    destination.mkdir(mode=0o700)
    case = {"name": name, "attempts": 1, "injected_control": name != "accepted",
            "artifact_sha256": sha(artifact), "expected_input_sha256": sha(expected)}
    receipt["cases"].append(case)
    app = NativeApplication("release-" + name, NativeConsumer.file(destination), sources=("gitfacts",))
    started = time.perf_counter()
    try:
        with app:
            document = contract(app)
            case["contract"] = document
            case["approval"] = app.approve(document)
            require(case["approval"].get("ok") is True, "owner_activation_failed")
            app.run(document=document, inputs={"gitfacts": expected}, artifact=artifact, action="publish")
    finally:
        case["elapsed_seconds"] = round(time.perf_counter() - started, 6)
        # Full native receipts remain in their owned private runtimes. This
        # transferable receipt drops the two native absolute path references.
        case["native"] = {key: value for key, value in app.receipt.items() if key not in {"retained_root", "receipt"}}
        if app.receipt.get("receipt"):
            case["private_native_receipt_sha256"] = sha(Path(app.receipt["receipt"]).read_bytes())
        case["output_entries"] = sorted(path.relative_to(destination).as_posix() for path in destination.rglob("*"))
        case["output_files"] = sorted(path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file())
    native = case["native"]
    require(native.get("runtime_stopped") is True
            and native.get("checks", {}).get("all_runtime_credentials_revoked") is True
            and native.get("checks", {}).get("generated_credentials_absent_from_receipt_and_log") is True,
            "native_retirement_unconfirmed")
    if name == "accepted":
        require(native["status"] == "completed" and native.get("effect_state") == "complete", "native_delivery_unconfirmed")
        require(case["output_entries"] == [TARGET], "unexpected_published_files")
        observed, mode = _read_regular(destination / TARGET)
        case["observed_sha256"] = sha(observed)
        require(observed == artifact, "observed_artifact_changed")
        return observed
    stages = native["stages"]
    verification = next((item for item in stages if item["stage"] == "independent_verification"), {})
    require(native["status"] == "refused" and verification.get("result", {}).get("code") == "CHECK_FAILED",
            "injected_control_not_refused_by_acceptance")
    require(not any(item["stage"] in {"reserve_effect", "confined_dispatch", "independent_observation"} for item in stages)
            and not case["output_entries"], "refused_control_produced_output")
    return None


def run_workload(snapshot_root, source_commit, facts_file, output_root):
    """Write a new owned delivery and retain evidence on success or failure."""
    output = Path(output_root).absolute()
    require(output.parent.resolve() == output.parent and not output.exists() and not output.is_symlink(),
            "output_must_be_new_canonical_directory")
    require(not output.is_relative_to(Path(snapshot_root).resolve()), "output_cannot_modify_snapshot")
    output.mkdir(mode=0o700)
    receipt = {"schema": "hobnail-release-workload-receipt-v1", "status": "incomplete", "source_commit": source_commit,
               "scope": "operator-assisted fresh sanitized release inventory", "cases": [], "automatic_retries": 0,
               "workload_implementation_sha256": sha(Path(__file__).read_bytes()),
               "human_authoring_and_review_seconds": None, "human_time_note": "Unmeasured; no time-savings or effort-reduction claim."}
    stage = "read_trusted_facts"
    started = time.perf_counter()
    try:
        facts_path = Path(facts_file).absolute()
        require(facts_path.resolve() == facts_path, "facts_file_not_canonical")
        expected, _ = _read_regular(facts_path)
        facts = json.loads(expected)
        require(facts.get("schema") == SCHEMA and facts.get("source_commit") == source_commit
                and facts.get("required_documents") == list(REQUIRED_DOCUMENTS), "trusted_facts_identity_mismatch")
        receipt["trusted_input_sha256"] = sha(expected)
        _write_new(output / "independent-facts.json", expected)
        stage = "direct_baseline"
        baseline_started = time.perf_counter()
        baseline = producer_inventory(snapshot_root, source_commit)
        baseline_bytes = encode(baseline)
        _write_new(output / "baseline.json", baseline_bytes)
        _write_new(output / "baseline.html", render_inventory(baseline).encode())
        receipt["baseline"] = {"elapsed_seconds": round(time.perf_counter() - baseline_started, 6), "attempts": 1,
                               "artifact_sha256": sha(baseline_bytes), "matches_independent_facts": baseline == facts,
                               "protected_effect": False}
        stage = "produce_protected_candidate"
        producer_started = time.perf_counter()
        produced = producer_inventory(snapshot_root, source_commit)
        artifact = encode(produced)
        receipt["protected_production_seconds"] = round(time.perf_counter() - producer_started, 6)
        require(produced == baseline, "snapshot_changed_since_baseline")
        require(len(artifact) <= 1048576 and len(expected) <= 1048576, "inventory_exceeds_contract_bound")
        stage = "native_accepted_delivery"
        observed = _native_case("accepted", artifact, expected, output / "published", receipt)
        require(json.loads(observed) == facts, "observed_inventory_does_not_match_trusted_facts")
        controls = {}
        omitted = copy.deepcopy(produced)
        victim = omitted["migrations"].pop()["path"]
        omitted["files"] = [entry for entry in omitted["files"] if entry["path"] != victim]
        omitted["counts"] = {"files": len(omitted["files"]), "bytes": sum(entry["bytes"] for entry in omitted["files"])}
        controls["omitted-migration"] = omitted
        changed = copy.deepcopy(produced)
        changed["package"]["version"] += ".injected-wrong"
        controls["wrong-version"] = changed
        extra = copy.deepcopy(produced)
        extra["unexpected_field"] = "deliberately injected control"
        controls["extra-field"] = extra
        for name, control in controls.items():
            stage = "native_control:" + name
            _native_case(name, encode(control), expected, output / name, receipt)
        stage = "confirm_source_preservation"
        receipt["source_snapshot_unchanged"] = producer_inventory(snapshot_root, source_commit) == produced
        require(receipt["source_snapshot_unchanged"], "snapshot_changed_during_workload")
        receipt["workload_implementation_unchanged"] = sha(Path(__file__).read_bytes()) == receipt["workload_implementation_sha256"]
        require(receipt["workload_implementation_unchanged"], "workload_implementation_changed")
        stage = "render_observed_delivery"
        final_observed, _ = _read_regular(output / "published" / TARGET)
        require(final_observed == observed, "observed_artifact_changed_before_render")
        comparison = {"baseline_seconds": receipt["baseline"]["elapsed_seconds"],
                      "protected_production_seconds": receipt["protected_production_seconds"],
                      "protected_native_seconds": receipt["cases"][0]["elapsed_seconds"],
                      "injected_control_seconds": sum(case["elapsed_seconds"] for case in receipt["cases"][1:]),
                      "trusted_supervisor_contract_activations": len(receipt["cases"]),
                      "native_stage_counts": {case["name"]: len(case["native"]["stages"]) for case in receipt["cases"]},
                      "automatic_retries": 0, "human_authoring_and_review_seconds": None,
                      "scope": "Operator-assisted local delivery; injected controls are not discovered defects.",
                      "measurement_note": "Baseline includes production and direct JSON/HTML writes. Protected native time includes setup through cleanup; protected HTML rendering is excluded.",
                      "cost_limit": receipt["human_time_note"]}
        _write_new(output / "release-inventory.html", render_inventory(json.loads(observed), comparison).encode())
        receipt["comparison"] = comparison
        receipt["delivery"] = {"json": "published/" + TARGET, "html": "release-inventory.html",
                               "json_sha256": sha(observed), "html_sha256": sha((output / "release-inventory.html").read_bytes()),
                               "release_preflight_consumption": "pending_separate_release_operator_receipt"}
        receipt["status"] = "completed"
    except Exception as error:
        receipt["status"] = "failed"
        receipt["failure"] = {"stage": stage, "kind": type(error).__name__,
                              "code": str(error) if isinstance(error, WorkloadError) else "runtime_failure"}
    finally:
        receipt["elapsed_seconds"] = round(time.perf_counter() - started, 6)
        _write_new(output / "workload-receipt.json", json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--facts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    receipt = run_workload(options.snapshot, options.commit, options.facts, options.output)
    print(json.dumps({"status": receipt["status"], "source_commit": receipt["source_commit"],
                      "receipt": str(options.output / "workload-receipt.json")}))
    return 0 if receipt["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
