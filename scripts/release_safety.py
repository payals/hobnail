"""Offline, redacted signature/privacy scan of explicitly selected Git objects.

This is a bounded release check, not proof that code has no vulnerabilities or
that every possible secret is detectable. It never validates credentials with
an external service, reads credential stores, or rewrites repository history.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.release_inventory_facts import ReleaseFactsError, _git

RULES = {
    "private_key_header": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{1,65536}-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "github_token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "aws_access_key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "slack_token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "vault_token": re.compile(rb"\b(?:hvs|hvb)\.[A-Za-z0-9_-]{24,}\b"),
    "jwt": re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{20,}\b"),
    "scram_verifier": re.compile(rb"SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]{8,}\$[A-Za-z0-9+/=:]{16,}"),
    "credential_uri": re.compile(rb"\b(?:postgres(?:ql)?|mysql|redis|https?)://[^\s/@:'\"]+:[^\s/@'\"]+@[^\s/'\"]+"),
    "credential_query": re.compile(rb"(?i)[?&](?:access_token|token|api_key|password|secret)=[A-Za-z0-9%._~-]{8,}"),
    "credential_literal": re.compile(rb"(?im)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password|passwd|secret|token)[\"']?\s*[:=]\s*[\"'][^\"'\r\n]{8,}[\"']"),
    "home_path": re.compile(rb"/(?:Users|home)/[A-Za-z0-9_.-]+(?:/[^\s\"'<>)]*)?"),
    "machine_temp_path": re.compile(rb"/(?:private/)?var/folders/[^\s\"'<>)]{4,}"),
    "private_evidence_path": re.compile(rb"/(?:private/)?tmp/(?:hbn|hobnail|codex)-[A-Za-z0-9_.-]{4,}(?:/[^\s\"'<>)]*)?"),
}
FORBIDDEN_PATH_PARTS = {".state", ".venv", "__pycache__", ".env", ".ssh", ".aws", ".gnupg"}
MAX_BLOB = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_COMMITS = 1000


class ReleaseScanError(RuntimeError):
    pass


def sha(value):
    return hashlib.sha256(value).hexdigest()


def safe_location(path, private_terms=()):
    encoded = path.encode("utf-8")
    if any(pattern.search(encoded) for pattern in RULES.values()) or any(term.encode().lower() in encoded.lower() for term in private_terms):
        return {"path": "<redacted-path>", "path_sha256": sha(encoded)}
    return {"path": path}


def load_allowlist(path):
    if path is None:
        return {}
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"schema", "entries"} or value["schema"] != "hobnail-scan-allowlist-v1":
        raise ReleaseScanError("invalid_allowlist_schema")
    if not isinstance(value["entries"], list):
        raise ReleaseScanError("invalid_allowlist_entries")
    result = {}
    for entry in value["entries"]:
        if (not isinstance(entry, dict) or set(entry) != {"path", "rule", "match_sha256", "reason"}
                or entry["rule"] not in RULES or not isinstance(entry["match_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry["match_sha256"])
                or not isinstance(entry["path"], str) or any(char in entry["path"] for char in "*?[]\n\r")
                or not isinstance(entry["reason"], str) or len(entry["reason"].strip()) < 12):
            raise ReleaseScanError("invalid_exact_allowlist_entry")
        key = entry["path"], entry["rule"], entry["match_sha256"]
        if key in result:
            raise ReleaseScanError("duplicate_allowlist_entry")
        result[key] = entry["reason"]
    return result


def scan_bytes(path, content, *, allowlist=None, private_terms=()):
    allowlist = allowlist or {}
    findings = []
    patterns = dict(RULES)
    for index, term in enumerate(private_terms):
        if not isinstance(term, str) or not term:
            raise ReleaseScanError("invalid_private_term")
        patterns[f"private_term_{index + 1}"] = re.compile(re.escape(term.encode()), re.IGNORECASE)
    for rule, pattern in patterns.items():
        for match in pattern.finditer(content):
            digest = sha(match.group())
            key = path, rule, digest
            allowed = key in allowlist
            finding = {**safe_location(path, private_terms), "rule": rule, "line": content.count(b"\n", 0, match.start()) + 1,
                "match_sha256": digest, "allowed": allowed}
            if allowed:
                finding["allowlist_reason_sha256"] = sha(allowlist[key].encode())
            findings.append(finding)
    return findings


def scan_repository(repository, revision, *, history=False, allowlist=None, private_terms=(), github_owner="payals",
                    attribution_policy="owner-only"):
    root = Path(repository).absolute()
    if root.resolve(strict=True) != root or not (root / ".git").is_dir() or (root / ".git").is_symlink():
        raise ReleaseScanError("canonical_standalone_repository_required")
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", github_owner):
        raise ReleaseScanError("exact_revision_and_owner_required")
    if attribution_policy not in {"owner-only", "github-noreply"}:
        raise ReleaseScanError("unknown_attribution_policy")
    if _git(root, "cat-file", "-t", revision).strip() != b"commit":
        raise ReleaseScanError("commit_required")
    if history and any((root / ".git" / name).exists() or (root / ".git" / name).is_symlink()
                       for name in ("shallow", "info/grafts", "commondir")):
        raise ReleaseScanError("complete_ungrafted_standalone_history_required")
    commits = _git(root, "rev-list", revision).decode().splitlines() if history else [revision]
    if not commits or len(commits) > MAX_COMMITS:
        raise ReleaseScanError("history_size_limit")
    findings, checked = [], set()
    total = 0
    owner_email = re.compile(rb"(?:[0-9]+\+)?" + re.escape(github_owner.encode()) + rb"@users\.noreply\.github\.com\Z", re.IGNORECASE)
    # Public collaboration admits GitHub's privacy-preserving contributor/bot
    # attribution. This is a privacy rule, not proof of signer identity.
    public_email = re.compile(rb"(?:(?:[0-9]+\+)?[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?@users\.noreply\.github\.com|noreply@github\.com)\Z", re.IGNORECASE)
    email_pattern = owner_email if attribution_policy == "owner-only" else public_email
    for commit in commits:
        raw_commit = _git(root, "cat-file", "commit", commit)
        for finding in scan_bytes("git/commit", raw_commit, private_terms=private_terms):
            findings.append({**finding, "commit": commit})
        for line in raw_commit.split(b"\n\n", 1)[0].splitlines():
            if line.startswith((b"author ", b"committer ")):
                address = re.search(rb"<([^<>]+)>", line)
                if address is None or email_pattern.fullmatch(address[1]) is None:
                    findings.append({"path": "git/commit", "rule": "unapproved_commit_email", "commit": commit,
                        "line": 0, "match_sha256": sha(address[1] if address else line), "allowed": False})
        raw_tree = _git(root, "ls-tree", "-rz", "--full-tree", commit)
        for record in raw_tree.rstrip(b"\0").split(b"\0") if raw_tree else []:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
            location = safe_location(path, private_terms)
            for finding in scan_bytes(path, raw_path, private_terms=private_terms):
                findings.append({**finding, "rule": "filename_" + finding["rule"], "commit": commit})
            if mode not in {"100644", "100755"} or kind != "blob":
                findings.append({**location, "rule": "nonregular_tracked_entry", "commit": commit,
                    "line": 0, "match_sha256": sha(record), "allowed": False})
                continue
            if any(part in FORBIDDEN_PATH_PARTS for part in path.split("/")) or path.endswith((".pyc", ".p12", ".pfx", ".key")):
                findings.append({**location, "rule": "private_or_generated_path", "commit": commit,
                    "line": 0, "match_sha256": sha(raw_path), "allowed": False})
            key = path, oid
            if key in checked:
                continue
            checked.add(key)
            size = int(_git(root, "cat-file", "-s", oid).strip())
            if size > MAX_BLOB or total + size > MAX_TOTAL:
                raise ReleaseScanError("object_bytes_limit")
            content = _git(root, "cat-file", "blob", oid)
            if len(content) != size:
                raise ReleaseScanError("object_size_mismatch")
            total += size
            for finding in scan_bytes(path, content, allowlist=allowlist, private_terms=private_terms):
                findings.append({**finding, "commit": commit, "blob": oid})
    blocking = [entry for entry in findings if not entry["allowed"]]
    return {"schema": "hobnail-release-scan-v1", "status": "passed" if not blocking else "blocked",
        "revision": revision, "history_scanned": history, "commits_scanned": len(commits),
        "attribution_policy": attribution_policy,
        "path_blob_pairs_scanned": len(checked), "bytes_scanned": total,
        "rules": sorted(RULES), "findings": findings, "blocking_findings": len(blocking),
        "limitations": ["Heuristic signatures do not prove absence of all secrets or vulnerabilities",
                        "No external credential validity checks or credential-store inspection",
                        "Only objects reachable from the explicitly selected commit were scanned"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--allowlist", type=Path)
    parser.add_argument("--github-owner", default="payals")
    parser.add_argument("--attribution-policy", choices=("owner-only", "github-noreply"), default="owner-only")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    try:
        result = scan_repository(args.repository, args.revision, history=args.history,
            allowlist=load_allowlist(args.allowlist), github_owner=args.github_owner,
            attribution_policy=args.attribution_policy)
        if args.receipt:
            with args.receipt.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2, sort_keys=True); stream.write("\n")
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(0 if result["status"] == "passed" else 1)
    except (ReleaseFactsError, ReleaseScanError, OSError, ValueError) as error:
        print(json.dumps({"status": "error", "type": type(error).__name__, "detail": "scan refused; no match values emitted"}))
        raise SystemExit(2)
