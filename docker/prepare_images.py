#!/usr/bin/env python3
"""Assemble reviewed file inventories without executing any image contents.

This prepares deterministic root filesystems for later, explicitly authorized
import. It does not call Docker, install packages, or release quarantined bytes.
Inputs are the supervisor's retained static-review records, not worker input.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile


IMAGES = {
    "python": "sha256:480abd719aa1bedf60a3ad2d9237e61fd17112ad0c39a484b351e34cddbe46fd",
    "postgres": "sha256:1d70b0960b2d1c39a0a82cda0d19d78b9b676d64b2120efe82631cd9768d1814",
}
LIMIT = 80_000_000


def safe_path(value):
    if (not isinstance(value, str) or not value or value.startswith("/")
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(part.startswith(".wh.") for part in value.split("/"))
            or "\x00" in value or "\\" in value):
        raise ValueError("invalid image path or OCI whiteout")
    return value


def excluded(path):
    parts = PurePosixPath(path).parts
    return (any(part in {"site-packages", "ensurepip"} for part in parts)
            or PurePosixPath(path).name in {"gosu", "pip", "pip3", "pip3.14"}
            or PurePosixPath(path).name.startswith("docker-entrypoint"))


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifests(review):
    """Bind source layers to the actual pinned OCI bytes, not asserted IDs."""
    manifests = {}
    for image, expected in IMAGES.items():
        path = review / f"{image}-arm64-manifest.json"
        if path.resolve(strict=True) != path or not path.is_file() or path.stat().st_size > 2_000_000:
            raise ValueError("manifest must be a bounded canonical regular file")
        raw = path.read_bytes()
        if "sha256:" + hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("source manifest bytes differ from reviewed pins")
        manifest = json.loads(raw)
        config = review / f"{image}-arm64-config.json"
        if config.resolve(strict=True) != config or not config.is_file() or config.stat().st_size > 2_000_000:
            raise ValueError("configuration must be a bounded canonical regular file")
        raw_config = config.read_bytes()
        if "sha256:" + hashlib.sha256(raw_config).hexdigest() != manifest["config"]["digest"]:
            raise ValueError("source configuration differs from its manifest")
        configuration = json.loads(raw_config)
        if configuration.get("architecture") != "arm64" or configuration.get("os") != "linux":
            raise ValueError("source platform differs from the reviewed platform")
        manifests[image] = manifest
    return manifests


def load_content(manifests, quarantine, selections):
    """Read bounded selected regular files, never extract an archive to disk."""
    descriptors = {}
    permitted = {}
    for image, manifest in manifests.items():
        permitted[image] = {row["digest"] for row in manifest["layers"]}
        for row in manifest["layers"]:
            if row["digest"] in descriptors and descriptors[row["digest"]] != row:
                raise ValueError("conflicting source layer descriptors")
            descriptors[row["digest"]] = row
    needed = {}
    for entry in selections:
        if entry["layer"] not in permitted.get(entry["image"], set()):
            raise ValueError("selected source layer is outside its pinned manifest")
        if entry["type"] == "0":
            needed.setdefault(entry["layer"], {})[entry["name"]] = entry
    content = {}
    for digest, entries in sorted(needed.items()):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("invalid layer digest")
        path = quarantine / (digest.replace(":", "-") + ".tar.gz")
        if path.resolve(strict=True) != path or not path.is_file():
            raise ValueError("layer must be a canonical regular file")
        before = path.stat()
        if (before.st_uid != os.getuid() or before.st_mode & 0o222
                or before.st_nlink != 1 or before.st_size != descriptors[digest]["size"]
                or digest_file(path) != digest.removeprefix("sha256:")):
            raise ValueError("quarantined layer integrity or ownership changed")
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                name = member.name.removeprefix("./").rstrip("/")
                if name not in entries:
                    continue
                expected = entries[name]
                if not member.isfile() or not 0 <= member.size <= LIMIT or member.size != expected["size"]:
                    raise ValueError("selected source is not a bounded regular file")
                with archive.extractfile(member) as stream:
                    value = stream.read(LIMIT + 1)
                if len(value) != member.size or hashlib.sha256(value).hexdigest() != expected["sha256"]:
                    raise ValueError("selected file integrity changed")
                content[(digest, name)] = value
        after = path.stat()
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(after):
            raise ValueError("layer changed during static reading")
    if len(content) != sum(len(entries) for entries in needed.values()):
        raise ValueError("selected file missing from source layers")
    return content


def generated_files():
    roles = {"registrar": 10001, "approver": 10002, "worker": 10003,
             "verifier": 10004, "credential_provider": 10005, "adapter": 10006,
             "observer": 10007, "auditor": 10008, "parser": 10009}
    passwd = ["root:*:0:0:root:/nonexistent:/bin/false", "postgres:*:70:70:PostgreSQL:/nonexistent:/bin/false"]
    groups = ["root:*:0:", "postgres:*:70:", "dbsocket:*:20000:", "observation:*:20001:"]
    for role, uid in roles.items():
        passwd.append(f"{role}:*:{uid}:{uid}:{role}:/nonexistent:/bin/false")
        groups.append(f"{role}:*:{uid}:")
    return {"etc/passwd": ("\n".join(passwd) + "\n").encode(),
            "etc/group": ("\n".join(groups) + "\n").encode(),
            "etc/nsswitch.conf": b"passwd: files\ngroup: files\nhosts: files\n",
            "etc/ld-musl-aarch64.path": b"/lib:/usr/local/lib:/usr/lib\n"}


def assemble(review, quarantine, output):
    manifests = source_manifests(review)
    inventories = {name: json.loads((review / f"{name}-closure-inventory.json").read_text())
                   for name in ("parser", "runtime")}
    selections = []
    for name, inventory in inventories.items():
        if inventory["flavor"] != name or inventory["missing"]:
            raise ValueError("dependency inventory is incomplete")
        seen = set()
        for entry in inventory["entries"]:
            path = safe_path(entry["name"])
            if path in seen or excluded(path) or entry["type"] not in {"0", "1", "2", "5"}:
                raise ValueError("invalid or excluded selected image member")
            if entry["mode"] & 0o6000 and entry["type"] != "5":
                raise ValueError("set-ID image file is forbidden")
            seen.add(path)
            selections.append(entry)
        if "usr/local/bin/initdb" in seen:
            # These modules are loaded by standard post-bootstrap SQL, rather
            # than ELF DT_NEEDED. A successful linker closure misses them.
            for module in ("dict_snowball", "plpgsql"):
                required = "usr/local/lib/postgresql/" + module + ".so"
                if required not in seen:
                    raise ValueError("standard PostgreSQL initialization module is missing: " + required)
    content = load_content(manifests, quarantine, selections)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    records = []
    for flavor, inventory in inventories.items():
        selected = {entry["name"]: entry for entry in inventory["entries"]}
        additional = generated_files()
        directories = {"dev", "proc", "sys", "tmp", "run", "scratch", "var", "var/lib",
                       "var/lib/postgresql", "run/postgresql", "destination"}
        for name in (*selected, *additional):
            directories.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != ".")
        directories.update(name for name, entry in selected.items() if entry["type"] == "5")
        link_targets = {}
        for name, entry in selected.items():
            if entry["type"] not in {"1", "2"}:
                continue
            target = PurePosixPath(entry["linkname"])
            if target.is_absolute():
                resolved = str(target).lstrip("/")
            elif entry["type"] == "1":
                resolved = str(target)
            else:
                import posixpath
                resolved = posixpath.normpath(str(PurePosixPath(name).parent / target))
            safe_path(resolved)
            if resolved not in selected and resolved not in directories:
                raise ValueError("selected link target is outside the image inventory")
            link_targets[name] = resolved
        for name, entry in selected.items():
            if any(str(parent) in link_targets for parent in PurePosixPath(name).parents):
                raise ValueError("selected member is beneath a link")
            if name not in link_targets:
                continue
            target, visited = name, set()
            while target in link_targets:
                if target in visited:
                    raise ValueError("cyclic selected link")
                visited.add(target)
                target = link_targets[target]
            if entry["type"] == "1" and (target not in selected or selected[target]["type"] != "0"):
                raise ValueError("hard link does not reach a selected regular file")
        def source_bytes(name, visited=None):
            visited = set() if visited is None else visited
            if name in visited:
                raise ValueError("cyclic source link")
            visited.add(name)
            entry = selected[name]
            if entry["type"] in {"1", "2"}:
                return source_bytes(link_targets[name], visited)
            return content[(entry["layer"], name)]
        path = output / f"hobnail-{flavor}-arm64.rootfs.tar"
        members = []
        with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
            for name in sorted(directories, key=lambda value: (value.count("/"), value)):
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                if name == "var/lib/postgresql":
                    member.uid = member.gid = 70
                    member.mode = 0o700
                elif name == "run/postgresql":
                    member.uid, member.gid, member.mode = 70, 20000, 0o770
                elif name == "destination":
                    member.uid, member.gid, member.mode = 10006, 20001, 0o750
                archive.addfile(member)
            for name in sorted(set(selected) | set(additional)):
                if name in directories:
                    continue
                member = tarfile.TarInfo(name)
                if name in additional:
                    value = additional[name]
                    member.mode = 0o644
                else:
                    entry = selected[name]
                    member.mode = entry["mode"] & 0o755
                    if entry["type"] == "2":
                        member.type = tarfile.SYMTYPE
                        member.linkname = entry["linkname"]
                        archive.addfile(member)
                        members.append({"path": name, "source": entry, "type": "symlink"})
                        continue
                    value = source_bytes(name)
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
                members.append({"path": name, "sha256": hashlib.sha256(value).hexdigest(),
                                "source": None if name in additional else selected[name], "first_party": name in additional})
        path.chmod(0o400)
        record = {"flavor": flavor, "filename": path.name, "sha256": digest_file(path),
                  "size": path.stat().st_size, "source_manifests": IMAGES, "members": members,
                  "execution_authorized": False}
        manifest = output / f"{flavor}-members.json"
        manifest.write_text(json.dumps(record, indent=2) + "\n")
        manifest.chmod(0o400)
        records.append({key: record[key] for key in ("flavor", "filename", "sha256", "size")})
    output.chmod(0o500)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--quarantine", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(assemble(arguments.review.resolve(strict=True), arguments.quarantine.resolve(strict=True),
                              arguments.output.absolute()), indent=2))


if __name__ == "__main__":
    main()
