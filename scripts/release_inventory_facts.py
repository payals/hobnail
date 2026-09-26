"""Independent release facts collected from an explicit immutable Git tree.

No checkout code executes. No working-tree content supplies expected answers.
The caller selects the already reviewed public candidate; this collector does
not certify privacy, security, licensing compliance or release readiness.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tomllib

REQUIRED_DOCUMENTS = (
    "AGENTS.md", "CONTRIBUTING.md", "LICENSE", "README.md", "SECURITY.md",
    "docs/AGENT-GUIDE.md", "docs/CONTRACT.md", "docs/OPERATIONS.md", "docs/SUPPORT.md",
)
MAX_FILES = 2048
MAX_BLOB = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024


class ReleaseFactsError(RuntimeError):
    pass


def _git(repository, *arguments):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat", "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "", "GIT_PROTOCOL_FROM_USER": "0"}
    try:
        result = subprocess.run(["git", "--no-replace-objects", "--no-optional-locks", "-c", "core.fsmonitor=false",
            "-c", "credential.helper=", "-c", "protocol.allow=never", "-C", str(repository),
            *arguments], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    except (OSError, subprocess.SubprocessError):
        raise ReleaseFactsError("git_object_transport_unavailable") from None
    if result.returncode:
        raise ReleaseFactsError("git_object_read_failed")
    return result.stdout


def collect_release_facts(public_repo, commit):
    repository = Path(public_repo).absolute()
    try:
        canonical = repository.resolve(strict=True) == repository
    except OSError:
        canonical = False
    if not canonical or not (repository / ".git").is_dir() or (repository / ".git").is_symlink():
        raise ReleaseFactsError("canonical_standalone_candidate_required")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseFactsError("exact_sha1_commit_required")
    if _git(repository, "cat-file", "-t", commit).strip() != b"commit":
        raise ReleaseFactsError("commit_object_required")
    raw_tree = _git(repository, "ls-tree", "-rz", "--full-tree", commit)
    records = raw_tree.rstrip(b"\0").split(b"\0") if raw_tree else []
    if not records or len(records) > MAX_FILES:
        raise ReleaseFactsError("source_tree_size_refused")
    entries, special = [], {}
    total = 0
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
            path = raw_path.decode("ascii")
        except (ValueError, UnicodeError):
            raise ReleaseFactsError("unsupported_tree_record") from None
        parts = PurePosixPath(path).parts
        if (mode not in {"100644", "100755"} or kind != "blob"
                or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", path)
                or any(part in {".", "..", ".git"} for part in parts)
                or str(PurePosixPath(path)) != path or len(path) > 1024):
            raise ReleaseFactsError("unsupported_source_path_or_type")
        size = int(_git(repository, "cat-file", "-s", oid).strip())
        if size > MAX_BLOB or total + size > MAX_TOTAL:
            raise ReleaseFactsError("source_bytes_exceed_limit")
        content = _git(repository, "cat-file", "blob", oid)
        if len(content) != size:
            raise ReleaseFactsError("object_size_changed")
        total += size
        entries.append({"path": path, "sha256": hashlib.sha256(content).hexdigest(), "mode": mode, "bytes": size})
        if path in {"pyproject.toml", "LICENSE"}:
            special[path] = content
    entries.sort(key=lambda item: item["path"])
    paths = {item["path"] for item in entries}
    if not set(REQUIRED_DOCUMENTS).issubset(paths) or "pyproject.toml" not in special:
        raise ReleaseFactsError("required_source_document_missing")
    try:
        project = tomllib.loads(special["pyproject.toml"].decode("utf-8"))["project"]
        package = {"name": project["name"], "version": project["version"],
            "requires_python": project["requires-python"], "license": project["license"],
            "entry_points": dict(sorted(project["scripts"].items()))}
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        raise ReleaseFactsError("project_metadata_invalid") from None
    if (any(not isinstance(package[key], str) or not package[key] for key in ("name", "version", "requires_python", "license"))
            or package["license"] not in {"MIT", "Apache-2.0"}
            or not package["entry_points"]
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in package["entry_points"].items())):
        raise ReleaseFactsError("unsupported_project_metadata")
    migrations = []
    for item in entries:
        if item["path"].startswith("migrations/"):
            match = re.fullmatch(r"migrations/([0-9]{3})_[A-Za-z0-9_]+\.sql", item["path"])
            if not match:
                raise ReleaseFactsError("migration_path_invalid")
            migrations.append({"version": int(match[1]), "path": item["path"], "sha256": item["sha256"]})
    if not migrations or [item["version"] for item in migrations] != list(range(1, len(migrations) + 1)):
        raise ReleaseFactsError("migration_sequence_invalid")
    return {"schema": "hobnail-release-inventory-v1", "source_commit": commit, "package": package,
        "files": entries, "counts": {"files": len(entries), "bytes": total}, "migrations": migrations,
        "required_documents": list(REQUIRED_DOCUMENTS)}
