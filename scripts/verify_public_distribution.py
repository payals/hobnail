"""Verify the exact public Git tree, standard archives and an offline install.

Requires a prepared PUBLIC-SOURCE.json layout; no private operational files or
history are required. Builds execute reviewed first-party source in a fresh
snapshot. This script neither publishes artifacts nor activates services.
"""
from __future__ import annotations

import argparse
import base64
import configparser
import csv
from email.parser import BytesParser
import hashlib
import io
import json
import os
import re
from pathlib import Path, PurePosixPath
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.release_inventory_facts import _git, collect_release_facts
from scripts.release_safety import load_allowlist, scan_bytes, scan_repository


class PublicDistributionError(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise PublicDistributionError(reason)


def digest(content):
    return hashlib.sha256(content).hexdigest()


def environment():
    result = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ}
    result.update({"LC_ALL": "C", "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    return result


def check_metadata(content, files, project):
    content.decode("utf-8")
    value = BytesParser().parsebytes(content)
    require(not value.defects and not value.is_multipart(), "malformed_core_metadata")
    expected_fields = (("Metadata-Version", "2.4"), ("Name", project["name"]), ("Version", project["version"]),
        ("Summary", project["description"]),
        ("Requires-Python", project["requires-python"]), ("License-Expression", project["license"]),
        ("License-File", "LICENSE"), ("Description-Content-Type", "text/markdown"))
    require(set(value.keys()) == {key for key, _ in expected_fields}, "unexpected_core_metadata_field")
    for key, expected in expected_fields:
        require(value.get_all(key) == [expected], "core_metadata_mismatch:" + key)
    require(value.get_payload(decode=True) == files["README.md"], "metadata_description_mismatch")
    require(not value.get_all("Requires-Dist") and not value.get_all("Dynamic") and project.get("dependencies", []) == [],
        "unexpected_dependency_or_dynamic_metadata")


def check_archives(wheel, source_archive, files, modes, project):
    """Read all members without tar extraction and compare with Git-bound bytes."""
    info = project["name"] + "-" + project["version"] + ".dist-info"
    python_files = {path.removeprefix("src/"): content for path, content in files.items()
                    if path.startswith("src/hobnail/") and path.endswith(".py")}
    expected_wheel = set(python_files) | {info + "/" + name for name in
        ("METADATA", "WHEEL", "entry_points.txt", "licenses/LICENSE", "RECORD")}
    with zipfile.ZipFile(wheel) as archive:
        require(not archive.comment, "unbound_zip_archive_comment")
        entries = archive.infolist()
        require(len(entries) == len(expected_wheel) and {entry.filename for entry in entries} == expected_wheel,
            "wheel_members_mismatch")
        require(all(not entry.is_dir() and not stat.S_ISLNK(entry.external_attr >> 16) and not entry.flag_bits & 1 for entry in entries),
            "unsafe_wheel_member")
        require(all(not entry.comment and not entry.extra and entry.date_time == (2020, 1, 1, 0, 0, 0)
            and entry.external_attr == 0o644 << 16 for entry in entries), "unbound_zip_member_metadata")
        # Central-directory metadata does not cover local-header extra fields.
        # ZipFile accepts those fields without surfacing them in ZipInfo.extra.
        with Path(wheel).open("rb") as raw:
            for entry in entries:
                raw.seek(entry.header_offset)
                header = raw.read(30)
                require(len(header) == 30 and header[:4] == b"PK\x03\x04", "invalid_zip_local_header")
                name_length, extra_length = struct.unpack_from("<HH", header, 26)
                require(extra_length == 0, "unbound_zip_local_extra")
                require(raw.read(name_length) == entry.filename.encode("utf-8"), "zip_local_name_mismatch")
        wheel_files = {entry.filename: archive.read(entry) for entry in entries}
    require(all(wheel_files[name] == value for name, value in python_files.items()), "wheel_code_mismatch")
    require(wheel_files[info + "/licenses/LICENSE"] == files["LICENSE"], "wheel_license_mismatch")
    check_metadata(wheel_files[info + "/METADATA"], files, project)
    wheel_metadata = BytesParser().parsebytes(wheel_files[info + "/WHEEL"])
    require(not wheel_metadata.defects
        and all(wheel_metadata.get_all(key) == [value] for key, value in
            (("Wheel-Version", "1.0"), ("Root-Is-Purelib", "true"), ("Tag", "py3-none-any"), ("Generator", "hobnail-stdlib")))
        and set(wheel_metadata.keys()) == {"Wheel-Version", "Root-Is-Purelib", "Tag", "Generator"}
        and not wheel_metadata.get_payload(), "wheel_tags_mismatch")
    entrypoints = configparser.ConfigParser(interpolation=None); entrypoints.optionxform = str
    entrypoints.read_string(wheel_files[info + "/entry_points.txt"].decode())
    require(entrypoints.sections() == ["console_scripts"] and dict(entrypoints["console_scripts"]) == project["scripts"],
        "wheel_entrypoints_mismatch")
    expected_entrypoints = "[console_scripts]\n" + "".join(name + " = " + value + "\n" for name, value in project["scripts"].items())
    require(wheel_files[info + "/entry_points.txt"] == expected_entrypoints.encode(), "unbound_entrypoint_metadata")
    rows = list(csv.reader(io.StringIO(wheel_files[info + "/RECORD"].decode())))
    require(len(rows) == len(expected_wheel) and all(len(row) == 3 for row in rows)
        and {row[0] for row in rows} == expected_wheel, "wheel_record_members_mismatch")
    for name, recorded, size in rows:
        if name == info + "/RECORD":
            require(recorded == size == "", "wheel_record_self_mismatch")
        else:
            encoded = base64.urlsafe_b64encode(hashlib.sha256(wheel_files[name]).digest()).rstrip(b"=").decode()
            require(recorded == "sha256=" + encoded and size == str(len(wheel_files[name])), "wheel_record_hash_mismatch")
    prefix = project["name"] + "-" + project["version"] + "/"
    expected_source = {prefix + name for name in files} | {prefix + "PKG-INFO"}
    require(Path(source_archive).name == prefix[:-1] + ".tar.gz", "source_archive_name_mismatch")
    with tarfile.open(source_archive, "r:gz") as archive:
        members = archive.getmembers()
        require(len(members) == len(expected_source) and {member.name for member in members} == expected_source,
            "source_archive_members_mismatch")
        for member in members:
            require(member.isfile() and not member.issym() and not member.islnk(), "unsafe_source_archive_member")
            require(member.uid == member.gid == member.mtime == member.devmajor == member.devminor == 0
                and member.uname == member.gname == member.linkname == ""
                and member.pax_headers in ({}, {"path": member.name}), "unbound_tar_member_metadata")
            content = archive.extractfile(member).read()
            name = member.name.removeprefix(prefix)
            if name == "PKG-INFO":
                check_metadata(content, files, project)
                require(content == wheel_files[info + "/METADATA"] and member.mode == 0o644, "source_metadata_mismatch")
            else:
                require(content == files[name] and member.size == len(files[name]), "source_archive_bytes_mismatch")
                require(member.mode == modes[name], "source_archive_mode_mismatch")
        require(not archive.pax_headers, "unbound_tar_global_metadata")
    require(Path(source_archive).read_bytes()[:10] == b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff", "unbound_gzip_metadata")
    return {"wheel_sha256": digest(Path(wheel).read_bytes()), "source_archive_sha256": digest(Path(source_archive).read_bytes()),
        "source_members": len(expected_source), "wheel_members": len(expected_wheel), "metadata_version": "2.4"}


def consume_inventory(path, expected_facts):
    """Use an explicitly delivered inventory only after independent Git equality."""
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, "inventory_path_not_canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "inventory_not_regular")
        content = stream.read(1_048_577)
    require(len(content) <= 1_048_576, "inventory_too_large")
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_inventory_key")
            result[key] = value
        return result
    value = json.loads(content, object_pairs_hook=unique)
    require(json.dumps(value, sort_keys=True, allow_nan=False) ==
        json.dumps(expected_facts, sort_keys=True, allow_nan=False), "delivered_inventory_differs_from_git")
    return value, {"sha256": digest(content), "source_commit": value["source_commit"],
        "files": len(value["files"]), "independent_git_comparison": "equal",
        "used_for_source_member_verification": True}


def verify_public_distribution(source_root, *, base_dir="/tmp", inventory_path=None):
    source = Path(source_root).absolute()
    require(source.resolve(strict=True) == source, "source_not_canonical")
    require(not _git(source, "status", "--porcelain"), "source_not_clean")
    commit = _git(source, "rev-parse", "HEAD").decode().strip()
    facts = collect_release_facts(source, commit)
    inventory_receipt = None
    if inventory_path is not None:
        facts, inventory_receipt = consume_inventory(inventory_path, facts)
    files, modes = {}, {}
    for entry in facts["files"]:
        path = source / entry["path"]
        require(path.resolve(strict=True) == path and path.is_file() and not path.is_symlink(), "working_tree_alias")
        content = path.read_bytes()
        require(digest(content) == entry["sha256"], "working_tree_byte_drift")
        mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
        require(mode == (0o755 if entry["mode"] == "100755" else 0o644), "working_tree_mode_drift")
        files[entry["path"]], modes[entry["path"]] = content, mode
    require("PUBLIC-SOURCE.json" in files, "prepared_public_source_required")
    declaration = json.loads(files["PUBLIC-SOURCE.json"])
    require(declaration.get("schema") == "hobnail-public-source-v1" and declaration.get("profile") == "public"
        and declaration.get("files") == sorted(files), "public_source_manifest_mismatch")
    allowlist_path = source / "security/scan-allowlist.json"
    allowances = load_allowlist(allowlist_path if allowlist_path.exists() else None)
    scan = scan_repository(source, commit, history=True, allowlist=allowances,
        attribution_policy="github-noreply")
    require(scan["status"] == "passed", "public_source_scan_blocked")
    project = tomllib.loads(files["pyproject.toml"].decode())["project"]
    require(isinstance(project["name"], str) and re.fullmatch(r"[a-z0-9]+(?:_[a-z0-9]+)*", project["name"])
        and isinstance(project["version"], str) and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", project["version"]),
        "unsupported_package_identity")
    root = Path(tempfile.mkdtemp(prefix="hbn-public-dist-", dir=base_dir)).resolve(); root.chmod(0o700)
    snapshot = root / "source"; snapshot.mkdir(mode=0o700)
    for name, content in files.items():
        path = snapshot / name; path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream: stream.write(content)
        path.chmod(modes[name])
    receipt = {"schema": "hobnail-public-distribution-v1", "status": "incomplete", "revision": commit,
        "retained_root": str(root), "network_packages_requested": False, "scan": scan, "commands": [],
        "delivered_inventory": inventory_receipt}
    stage = "build"
    def run(label, command, cwd=root):
        result = subprocess.run(command, cwd=cwd, env=environment(), stdin=subprocess.DEVNULL,
            capture_output=True, timeout=120)
        (root / (label + ".stdout")).write_bytes(result.stdout)
        (root / (label + ".stderr")).write_bytes(result.stderr)
        receipt["commands"].append({"step": label, "exit_code": result.returncode,
            "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr)})
        require(result.returncode == 0, "command_failed:" + label)
        return result.stdout.decode().strip()
    try:
        builder = "import build_backend,sys;print(getattr(build_backend,sys.argv[1])(sys.argv[2]))"
        wheel1 = root / "wheel1" / run("wheel1", [sys.executable, "-B", "-c", builder, "build_wheel", str(root / "wheel1")], snapshot)
        wheel2 = root / "wheel2" / run("wheel2", [sys.executable, "-B", "-c", builder, "build_wheel", str(root / "wheel2")], snapshot)
        sdist = root / "sdist" / run("sdist", [sys.executable, "-B", "-c", builder, "build_sdist", str(root / "sdist")], snapshot)
        require(wheel1.read_bytes() == wheel2.read_bytes(), "wheel_build_not_reproducible")
        receipt["archives"] = check_archives(wheel1, sdist, files, modes, project)
        # Complete source-byte comparison above binds source archive privacy.
        # Scan generated metadata too, since it is additional archive content.
        with zipfile.ZipFile(wheel1) as archive:
            metadata = archive.read(project["name"] + "-" + project["version"] + ".dist-info/METADATA")
        require(not [f for f in scan_bytes("generated/METADATA", metadata) if not f["allowed"]], "generated_metadata_scan_blocked")
        stage = "offline_install"
        venv = root / ".venv"
        run("venv", [sys.executable, "-m", "venv", str(venv)])
        python = venv / "bin/python"
        run("install", [str(python), "-m", "pip", "install", "--no-index", "--no-deps", "--no-compile", str(wheel1)])
        run("module_help", [str(python), "-I", "-m", "hobnail", "--help"])
        run("console_help", [str(venv / "bin/hobnail"), "--help"])
        stage = "final_source_check"
        require(_git(source, "rev-parse", "HEAD").decode().strip() == commit and not _git(source, "status", "--porcelain"), "source_changed")
        require(all(digest((source / name).read_bytes()) == digest(content) for name, content in files.items()), "source_bytes_changed")
        receipt.update(status="passed", wheel=str(wheel1), source_archive=str(sdist), offline_install=True,
            source_unchanged=True, receipt=str(root / "verification.json"))
    except Exception as error:
        receipt.update(status="failed", failure={"stage": stage, "type": type(error).__name__})
        if isinstance(error, PublicDistributionError): receipt["failure"]["code"] = str(error)
    finally:
        with (root / "verification.json").open("x") as stream:
            json.dump(receipt, stream, indent=2, sort_keys=True); stream.write("\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--base-dir", type=Path, default=Path("/tmp"))
    parser.add_argument("--inventory", type=Path, help="Explicit protected release inventory to consume and independently bind to Git")
    args = parser.parse_args()
    try:
        result = verify_public_distribution(args.source_root, base_dir=args.base_dir, inventory_path=args.inventory)
        print(json.dumps(result, indent=2, sort_keys=True))
        raise SystemExit(0 if result["status"] == "passed" else 1)
    except (OSError, ValueError, PublicDistributionError) as error:
        print(json.dumps({"status": "failed", "type": type(error).__name__, "detail": "public source preflight refused"}))
        raise SystemExit(2)
