#!/usr/bin/env python3
"""Recheck the reviewed MCP lock against PyPI and OSV without executing packages.

Optional downloads use only exact reviewed wheel URLs and hashes. Nothing is
installed. Network failure, changed metadata, an advisory or incomplete evidence
refuses the check. A successful receipt is a point-in-time check, not a guarantee
against unknown vulnerabilities or a substitute for the recorded source review.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "security/mcp-dependencies.json"
NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*(?:\.post[0-9]+)?")
SHA = re.compile(r"[0-9a-f]{64}")
FILENAME = re.compile(r"[A-Za-z0-9_.+-]+\.whl")


class DependencyError(RuntimeError):
    """A stable refusal code; never arbitrary remote or filesystem diagnostics."""


def require(condition, code):
    if not condition:
        raise DependencyError(code)


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def parse_json(raw):
    def invalid(_value):
        raise DependencyError("nonfinite_json")
    try:
        return json.loads(raw, object_pairs_hook=_object, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise DependencyError("invalid_json") from None


def timestamp(value):
    require(isinstance(value, str) and len(value) <= 40, "invalid_timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise DependencyError("invalid_timestamp") from None
    require(result.tzinfo is not None and result.utcoffset() == timedelta(0), "timestamp_not_utc")
    return result


def digest(content):
    return hashlib.sha256(content).hexdigest()


def _regular_bytes(path, maximum):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, "aliased_input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        record = os.fstat(source.fileno())
        require(stat.S_ISREG(record.st_mode) and record.st_nlink == 1 and record.st_uid == os.getuid()
                and record.st_size <= maximum, "input_not_bounded_regular_file")
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_mode)
        require(len(data) == record.st_size and identity(record) == identity(after)
                and identity(after) == identity(path.stat(follow_symlinks=False)), "input_changed_or_oversized")
    return data


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url, *, body=None, maximum=8 * 1024 * 1024):
    """Only fixed public metadata services or the reviewed PyPI wheel host."""
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and parsed.netloc in {"pypi.org", "files.pythonhosted.org", "api.osv.dev"}
            and not parsed.query and not parsed.fragment and not parsed.username, "network_destination_refused")
    require((parsed.netloc == "pypi.org" and body is None and parsed.path.startswith("/pypi/") and parsed.path.endswith("/json"))
            or (parsed.netloc == "files.pythonhosted.org" and body is None and parsed.path.startswith("/packages/"))
            or (parsed.netloc == "api.osv.dev" and parsed.path == "/v1/query" and body is not None), "network_path_refused")
    headers = {"User-Agent": "hobnail-mcp-dependency-check", "Accept": "application/json" if body is not None or parsed.netloc == "pypi.org" else "application/octet-stream"}
    encoded = None if body is None else json.dumps(body, separators=(",", ":"), allow_nan=False).encode()
    if encoded is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=encoded, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            require(response.status == 200, "network_status_refused")
            require(not any(response.headers.get(k) for k in ("Content-Range", "Link", "X-GitHub-Truncated")), "incomplete_network_evidence")
            chunks, remaining, deadline = [], maximum + 1, time.monotonic() + 60
            while remaining:
                require(time.monotonic() <= deadline, "network_deadline_exceeded")
                chunk = response.read1(min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            require(len(raw) <= maximum, "network_response_oversized")
            length = response.headers.get("Content-Length")
            require(length is None or (length.isdigit() and int(length) == len(raw)), "network_length_mismatch")
            return raw
    except (OSError, urllib.error.URLError, TimeoutError, http.client.HTTPException):
        raise DependencyError("network_evidence_unavailable") from None


def resolve_profile(manifest, name):
    require(isinstance(manifest, dict) and manifest.get("schema") == "hobnail-mcp-dependencies-v1"
            and type(manifest.get("minimum_age_hours")) is int and manifest["minimum_age_hours"] == 168,
            "dependency_manifest_policy_invalid")
    profiles = manifest.get("profiles")
    require(isinstance(profiles, dict) and isinstance(name, str) and name in profiles, "unsupported_profile")
    profile = profiles[name]
    require(isinstance(profile, dict) and isinstance(profile.get("packages"), list)
            and isinstance(profile.get("artifacts"), list), "profile_invalid")
    names, filenames = profile["packages"], profile["artifacts"]
    require(0 < len(names) <= 128 and all(isinstance(n, str) and NAME.fullmatch(n) for n in names)
            and len(names) == len(set(names)), "profile_packages_invalid")
    require(len(filenames) == len(names) and all(isinstance(f, str) and FILENAME.fullmatch(f) for f in filenames)
            and len(set(filenames)) == len(filenames), "profile_artifacts_invalid")
    packages = manifest.get("packages")
    require(isinstance(packages, list) and len(packages) <= 128, "packages_invalid")
    by_name = {}
    for package in packages:
        require(isinstance(package, dict) and isinstance(package.get("name"), str)
                and NAME.fullmatch(package["name"]) and package["name"] not in by_name, "package_identity_invalid")
        version = package.get("version")
        require(isinstance(version, str) and VERSION.fullmatch(version), "unstable_package_version")
        require(package.get("pypi_json_url") == "https://pypi.org/pypi/" + package["name"] + "/" + version + "/json",
                "package_source_invalid")
        require(isinstance(package.get("requires_dist"), list) and all(isinstance(x, str) for x in package["requires_dist"])
                and isinstance(package.get("project_urls"), dict), "package_metadata_invalid")
        by_name[package["name"]] = package
    require(set(names) <= by_name.keys(), "profile_package_missing")
    root_requirement = manifest.get("root_requirement")
    require("fastmcp-slim" in names and root_requirement == "fastmcp-slim[server]==" + by_name["fastmcp-slim"]["version"],
            "root_requirement_differs")
    selected = []
    for name in names:
        package = by_name[name]
        require(isinstance(package.get("artifacts"), list), "package_artifacts_invalid")
        matching = [a for a in package["artifacts"] if isinstance(a, dict) and a.get("filename") in filenames]
        require(len(matching) == 1, "profile_artifact_ambiguous")
        artifact = matching[0]
        require(isinstance(artifact.get("sha256"), str) and SHA.fullmatch(artifact["sha256"])
                and type(artifact.get("size")) is int and 0 < artifact["size"] <= 128 * 1024 * 1024, "artifact_integrity_invalid")
        u = urlsplit(artifact.get("url", ""))
        require(u.scheme == "https" and u.netloc == "files.pythonhosted.org" and not u.query and not u.fragment
                and u.path.startswith("/packages/") and u.path.endswith("/" + artifact["filename"]), "artifact_source_invalid")
        timestamp(artifact.get("uploaded_at"))
        selected.append((package, artifact))
    require({a["filename"] for _, a in selected} == set(filenames), "profile_artifact_set_differs")
    return profile, selected


def check_lock(root, profile, selected):
    lock_name = profile.get("lockfile", "")
    require(isinstance(lock_name, str) and re.fullmatch(r"integrations/mcp/requirements-[a-z0-9_-]+\.lock", lock_name), "lock_path_invalid")
    raw = _regular_bytes(Path(root) / lock_name, 256 * 1024)
    require(profile.get("lock_sha256") == digest(raw), "lock_hash_differs")
    lines = raw.decode("utf-8").replace("\\\n", " ").splitlines()
    found, options = {}, set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line in {"--only-binary=:all:", "--require-hashes", "--index-url https://pypi.org/simple"}:
            require(line not in options, "duplicate_lock_option")
            options.add(line)
            continue
        match = re.fullmatch(r"([a-z0-9-]+)(\[server\])?==([0-9.]+(?:post[0-9]+)?)\s+--hash=sha256:([0-9a-f]{64})", line)
        require(match is not None and match[1] not in found, "lock_requirement_invalid")
        require(bool(match[2]) == (match[1] == "fastmcp-slim"), "lock_extra_invalid")
        found[match[1]] = (match[3], match[4])
    require(options == {"--only-binary=:all:", "--require-hashes", "--index-url https://pypi.org/simple"}, "lock_options_invalid")
    require(found == {p["name"]: (p["version"], a["sha256"]) for p, a in selected}, "lock_graph_differs")
    return digest(raw)


def check_package(package, artifact, now, request=fetch):
    raw = request(package["pypi_json_url"])
    metadata = parse_json(raw)
    require(isinstance(metadata, dict) and isinstance(metadata.get("info"), dict)
            and isinstance(metadata.get("urls"), list), "pypi_metadata_invalid")
    require(isinstance(metadata.get("vulnerabilities"), list), "pypi_advisory_evidence_invalid")
    require(not metadata["vulnerabilities"], "pypi_known_vulnerability_record")
    info = metadata["info"]
    require((info.get("requires_dist") is None or (isinstance(info["requires_dist"], list)
                and all(isinstance(x, str) for x in info["requires_dist"])))
            and (info.get("project_urls") is None or (isinstance(info["project_urls"], dict)
                and all(isinstance(k, str) and isinstance(v, str) for k, v in info["project_urls"].items()))),
            "pypi_metadata_invalid")
    normalized = re.sub(r"[-_.]+", "-", str(info.get("name", ""))).lower()
    require(normalized == package["name"] and info.get("version") == package["version"], "pypi_identity_differs")
    require(info.get("requires_python") == package.get("requires_python")
            and (info.get("requires_dist") or []) == package["requires_dist"]
            and (info.get("project_urls") or {}) == package["project_urls"], "pypi_reviewed_metadata_changed")
    matches = [a for a in metadata["urls"] if isinstance(a, dict) and a.get("filename") == artifact["filename"]]
    require(len(matches) == 1, "pypi_artifact_missing_or_duplicated")
    actual = matches[0]
    require(actual.get("yanked") is False and actual.get("packagetype") == "bdist_wheel", "artifact_yanked_or_not_wheel")
    require(actual.get("url") == artifact["url"] and type(actual.get("size")) is int and actual["size"] == artifact["size"]
            and isinstance(actual.get("digests"), dict) and actual["digests"].get("sha256") == artifact["sha256"], "pypi_artifact_integrity_changed")
    uploaded = timestamp(actual.get("upload_time_iso_8601"))
    require(uploaded == timestamp(artifact["uploaded_at"]), "pypi_upload_time_changed")
    require(now - uploaded >= timedelta(hours=168), "artifact_too_young_or_future")
    osv_raw = request("https://api.osv.dev/v1/query", body={"package": {"name": package["name"], "ecosystem": "PyPI"}, "version": package["version"]})
    osv = parse_json(osv_raw)
    require(isinstance(osv, dict) and set(osv) <= {"vulns", "next_page_token"}, "osv_response_invalid")
    require("next_page_token" not in osv or isinstance(osv["next_page_token"], str), "osv_response_invalid")
    require(not osv.get("next_page_token"), "osv_incomplete_evidence")
    vulns = osv.get("vulns", [])
    require(isinstance(vulns, list) and all(isinstance(v, dict) and isinstance(v.get("id"), str) for v in vulns), "osv_response_invalid")
    # A listed advisory is a blocker even if another service or historical review
    # classified it differently. Disposition is an explicit new review, not a flag.
    require(not vulns, "known_vulnerability_record")
    return {"name": package["name"], "version": package["version"], "filename": artifact["filename"],
            "sha256": artifact["sha256"], "pypi_metadata_sha256": digest(raw), "osv_response_sha256": digest(osv_raw),
            "age_hours": round((now - uploaded).total_seconds() / 3600, 3), "known_vulnerability_records": 0}


def check(manifest_path, profile_name, *, root=ROOT, download_dir=None, wheel_dir=None, request=fetch, now=None):
    require(not (download_dir is not None and wheel_dir is not None), "conflicting_wheel_locations")
    raw = _regular_bytes(manifest_path, 8 * 1024 * 1024)
    manifest = parse_json(raw)
    profile, selected = resolve_profile(manifest, profile_name)
    lock_hash = check_lock(root, profile, selected)
    now = datetime.now(timezone.utc) if now is None else now
    require(now.tzinfo is not None and now.utcoffset() == timedelta(0), "current_time_not_utc")
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda pair: check_package(*pair, now, request), selected))
    destination = None
    if download_dir is not None:
        destination = Path(download_dir).absolute()
        require(destination.parent.resolve(strict=True) == destination.parent, "download_parent_aliased")
        destination.mkdir(mode=0o700)
    elif wheel_dir is not None:
        destination = Path(wheel_dir).absolute()
        require(destination.resolve(strict=True) == destination and destination.is_dir(), "wheel_directory_invalid")
    if destination is not None:
        for _package, artifact in selected:
            path = destination / artifact["filename"]
            content = request(artifact["url"], maximum=artifact["size"]) if download_dir is not None else _regular_bytes(path, artifact["size"])
            require(len(content) == artifact["size"] and digest(content) == artifact["sha256"], "wheel_bytes_differ")
            if download_dir is not None:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
                with os.fdopen(fd, "wb") as target:
                    target.write(content)
        require({p.name for p in destination.iterdir()} == {a["filename"] for _, a in selected}, "wheel_directory_members_differ")
    return {"schema": "hobnail-mcp-dependency-check-v1", "status": "passed", "checked_at": now.isoformat(),
            "profile": profile_name, "manifest_sha256": digest(raw), "lock_sha256": lock_hash, "packages": results,
            "wheel_bytes_verified": destination is not None, "installed": False,
            "scope": "Current exact PyPI metadata/advisories, artifact age and OSV evidence. The reviewed lock graph is bound, not independently re-resolved; signed provenance is not reverified."}


def automatic_profile():
    system = {"Darwin": "macos", "Linux": "linux"}.get(platform.system(), "unsupported")
    machine = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "x86_64"}.get(platform.machine(), "unsupported")
    if system == "linux":
        library, version = platform.libc_ver()
        if library != "glibc" or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version) or tuple(map(int, version.split("."))) < (2, 28):
            return "unsupported-linux-libc"
    if system == "macos":
        version = platform.mac_ver()[0]
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version) or tuple(map(int, version.split("."))) < (11, 0):
            return "unsupported-macos-version"
    return f"{system}-{machine}-py{sys.version_info.major}{sys.version_info.minor}"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default=automatic_profile())
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--download-dir", type=Path, help="new directory for exact verified wheels; never installs")
    group.add_argument("--wheel-dir", type=Path, help="existing exact wheel set to hash; never executes")
    parser.add_argument("--receipt", type=Path, help="new JSON receipt, exclusive creation")
    args = parser.parse_args(argv)
    output = None
    result = {"schema": "hobnail-mcp-dependency-check-v1", "status": "failed", "profile": args.profile,
              "code": "dependency_check_interrupted", "installed": False}
    try:
        if args.receipt:
            path = args.receipt.absolute()
            require(path.parent.resolve(strict=True) == path.parent, "receipt_parent_aliased")
            output = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w")
        result = check(args.manifest, args.profile, download_dir=args.download_dir, wheel_dir=args.wheel_dir)
    except (DependencyError, OSError, ValueError, TypeError, KeyError) as error:
        result = {"schema": "hobnail-mcp-dependency-check-v1", "status": "failed", "profile": args.profile,
                  "code": str(error) if isinstance(error, DependencyError) else "dependency_check_unavailable", "installed": False}
    except KeyboardInterrupt:
        pass
    finally:
        if output is not None:
            output.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
            output.close()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
