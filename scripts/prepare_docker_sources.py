#!/usr/bin/env python3
"""Reconstruct the locked rootfs pair from pinned official Docker Library bytes.

Use --download for anonymous, bounded retrieval, or --source-cache for an
offline reconstruction from a prior sources directory. No Docker command,
image code, package installer, approval override or quarantine release runs.
This is deterministic assembly from existing image layers, not an upstream
PostgreSQL/Python source rebuild or a current vulnerability clearance.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "hobnail-docker-source-closure-v1"
JSON_LIMIT = 2_000_000
LAYER_LIMIT = 128_000_000
EXPANDED_LAYER_LIMIT = 512_000_000
TOTAL_COMPRESSED_LIMIT = 160_000_000
DOWNLOAD_SECONDS = 600
REQUEST_SECONDS = 30
REGISTRY = "registry-1.docker.io"
# Docker's published download allowlist; unknown CDN changes refuse review.
# https://docs.docker.com/desktop/setup/allow-list/
REDIRECT_HOSTS = frozenset({REGISTRY, "production.cloudfront.docker.com"})
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ENTRY_FIELDS = {"image", "name", "size", "mode", "uid", "gid", "type", "linkname", "layer"}


class PreparationError(RuntimeError):
    """Fixed diagnostics: never echo URLs, tokens, exception bodies or data."""


def require(condition, code):
    if not condition:
        raise PreparationError(code)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(PreparationError("nonfinite_json")))
    except (ValueError, UnicodeError, RecursionError):
        raise PreparationError("invalid_json") from None


def identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_mode)


def read_file(path, limit, *, readonly=False):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, "source_path_not_canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid(), "source_file_not_owned_regular")
        require(0 < before.st_size <= limit, "source_file_size_invalid")
        require(not readonly or not before.st_mode & 0o222, "source_cache_not_readonly")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) == before.st_size and identity(before) == identity(after)
            and identity(after) == identity(path.stat(follow_symlinks=False)), "source_changed_during_read")
    return raw


def write_file(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o400)


def checked_descriptor(value, limit):
    require(isinstance(value, dict) and set(value) == {"digest", "size"}, "descriptor_shape_invalid")
    require(isinstance(value["digest"], str) and DIGEST.fullmatch(value["digest"]) is not None, "descriptor_digest_invalid")
    require(type(value["size"]) is int and 0 < value["size"] <= limit, "descriptor_size_invalid")


def load_recipe():
    raw = read_file(ROOT / "docker/source-closure.json", JSON_LIMIT)
    recipe = decode(raw)
    lock = decode(read_file(ROOT / "docker/images.lock.json", JSON_LIMIT))
    require(isinstance(recipe, dict) and set(recipe) == {"schema", "platform", "assembler_sha256", "sources", "inventories", "outputs"}, "recipe_shape_invalid")
    require(recipe["schema"] == SCHEMA and recipe["platform"] == lock["platform"] == "linux/arm64/v8", "recipe_platform_invalid")
    assembler = ROOT / "docker/prepare_images.py"
    require(recipe["assembler_sha256"] == hashlib.sha256(read_file(assembler, JSON_LIMIT)).hexdigest(), "assembler_changed")
    require(recipe["outputs"] == lock["rootfs"], "recipe_outputs_differ_from_lock")
    require(set(recipe["sources"]) == {"python", "postgres"} and set(recipe["inventories"]) == {"parser", "runtime"}, "recipe_members_invalid")
    locked = {entry["repository"].removeprefix("docker.io/library/"): entry for entry in lock["source_images"]}
    for name, source in recipe["sources"].items():
        require(isinstance(source, dict) and set(source) == {"repository", "manifest", "configuration", "layers"}, "source_shape_invalid")
        require(source["repository"] == "library/" + name, "source_repository_invalid")
        checked_descriptor(source["manifest"], JSON_LIMIT)
        checked_descriptor(source["configuration"], JSON_LIMIT)
        require(source["manifest"]["digest"] == locked[name]["manifest_digest"]
                and source["configuration"]["digest"] == locked[name]["configuration_digest"]
                and source["layers"] == locked[name]["layers"], "source_differs_from_lock")
        require(isinstance(source["layers"], list) and 1 <= len(source["layers"]) <= 32, "layer_count_invalid")
        for layer in source["layers"]:
            require(set(layer) == {"digest", "size", "mediaType"}
                    and layer["mediaType"] == "application/vnd.oci.image.layer.v1.tar+gzip", "layer_shape_invalid")
            checked_descriptor({key: layer[key] for key in ("digest", "size")}, LAYER_LIMIT)
    for flavor, inventory in recipe["inventories"].items():
        require(isinstance(inventory, dict) and set(inventory) == {"flavor", "entries", "missing"}
                and inventory["flavor"] == flavor and inventory["missing"] == [], "inventory_incomplete")
        require(isinstance(inventory["entries"], list) and 1 <= len(inventory["entries"]) <= 4096, "inventory_size_invalid")
        seen = set()
        for entry in inventory["entries"]:
            require(isinstance(entry, dict) and entry.get("type") in {"0", "1", "2", "5"}, "entry_type_invalid")
            require(set(entry) == ENTRY_FIELDS | ({"sha256"} if entry["type"] == "0" else set()), "entry_shape_invalid")
            require(entry["image"] in recipe["sources"], "entry_image_invalid")
            require(entry["layer"] in {row["digest"] for row in recipe["sources"][entry["image"]]["layers"]}, "entry_layer_invalid")
            name = entry["name"]
            require(isinstance(name, str) and len(name) <= 1024 and re.fullmatch(r"[A-Za-z0-9_+.,@=-]+(?:/[A-Za-z0-9_+.,@=-]+)*", name)
                    and not any(part in {".", ".."} or part.startswith(".wh.") for part in name.split("/")), "entry_path_invalid")
            require(name not in seen, "entry_repeated")
            seen.add(name)
            require(all(type(entry[key]) is int and 0 <= entry[key] <= limit for key, limit in
                        (("size", 80_000_000), ("mode", 0o7777), ("uid", 65535), ("gid", 65535))), "entry_metadata_invalid")
            require(isinstance(entry["linkname"], str) and len(entry["linkname"]) <= 1024
                    and "\x00" not in entry["linkname"] and "\\" not in entry["linkname"], "entry_link_invalid")
            if entry["type"] == "0":
                require(isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), "entry_hash_invalid")
    return recipe, hashlib.sha256(raw).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, newurl):
        return None


def public_url(url, hosts):
    try:
        value = urllib.parse.urlsplit(url)
        valid = (value.scheme == "https" and value.hostname in hosts and value.port in {None, 443}
                 and value.username is None and value.password is None and not value.fragment
                 and bool(value.path) and len(url) <= 8192 and not any(ord(c) < 33 for c in url))
    except ValueError:
        valid = False
    require(valid, "network_destination_refused")
    return url


class Registry:
    def __init__(self):
        # No credential files, Docker config, cookie jar, proxy credentials or
        # caller-selected registry. Only anonymous repository:pull tokens.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.deadline = time.monotonic() + DOWNLOAD_SECONDS

    def chunks(self, response, maximum):
        """One buffered socket read per chunk, with elapsed checks on both sides.

        HTTPResponse.read(n) may repeatedly read a trickling peer to fill n.
        read1(n) returns after at most one underlying read. Socket operations
        have the configured I/O timeout; system DNS resolution is not claimed
        to have a hard overall deadline.
        """
        require(callable(getattr(response, "read1", None)), "response_read1_unavailable")
        size = 0
        while True:
            require(time.monotonic() <= self.deadline, "download_deadline_exceeded")
            block = response.read1(min(65536, maximum + 1 - size))
            require(time.monotonic() <= self.deadline, "download_deadline_exceeded")
            require(isinstance(block, bytes), "registry_response_invalid")
            if not block:
                break
            size += len(block)
            yield block
            require(size <= maximum, "registry_body_oversize")

    def open(self, url, *, token=None, manifest=False, auth=False):
        hosts = {"auth.docker.io"} if auth else REDIRECT_HOSTS
        for hop in range(4):
            public_url(url, hosts)
            remaining = self.deadline - time.monotonic()
            require(remaining > 0, "download_deadline_exceeded")
            headers = {"User-Agent": "hobnail-source-preparation/1", "Accept-Encoding": "identity"}
            if manifest:
                headers["Accept"] = "application/vnd.oci.image.manifest.v1+json"
            if token is not None:
                require(urllib.parse.urlsplit(url).hostname == REGISTRY, "token_destination_refused")
                headers["Authorization"] = "Bearer " + token
            request = urllib.request.Request(url, headers=headers)
            try:
                response = self.opener.open(request, timeout=min(REQUEST_SECONDS, remaining))
            except urllib.error.HTTPError as error:
                location = error.headers.get("Location")
                status = error.code
                error.close()
                require(not auth and status in {301, 302, 303, 307, 308} and location is not None and hop < 3,
                        "registry_http_refused")
                url = public_url(urllib.parse.urljoin(url, location), hosts)
                token = None  # Never forward registry authority on a redirect.
                continue
            except (OSError, urllib.error.URLError):
                raise PreparationError("registry_transport_failed") from None
            if response.status != 200:
                response.close()
                raise PreparationError("registry_status_invalid")
            return response
        raise PreparationError("registry_redirect_limit")

    def token(self, repository):
        require(repository in {"library/python", "library/postgres"}, "token_scope_invalid")
        query = urllib.parse.urlencode({"service": "registry.docker.io", "scope": "repository:" + repository + ":pull"})
        with self.open("https://auth.docker.io/token?" + query, auth=True) as response:
            raw = b"".join(self.chunks(response, 16384))
        require(len(raw) <= 16384 and time.monotonic() <= self.deadline, "anonymous_token_response_invalid")
        body = decode(raw)
        value = body.get("token", body.get("access_token")) if isinstance(body, dict) else None
        require(isinstance(value, str) and 1 <= len(value) <= 8192
                and re.fullmatch(r"[A-Za-z0-9._~-]+", value) is not None
                and body.get("access_token", value) == value, "anonymous_token_invalid")
        return value

    def fetch(self, repository, kind, descriptor, path):
        require(repository in {"library/python", "library/postgres"} and kind in {"manifests", "blobs"}, "registry_object_invalid")
        checked_descriptor(descriptor, LAYER_LIMIT)
        token = self.token(repository)
        url = f"https://{REGISTRY}/v2/{repository}/{kind}/{descriptor['digest']}"
        with self.open(url, token=token, manifest=kind == "manifests") as response:
            length = response.headers.get("Content-Length")
            require(length is None or length == str(descriptor["size"]), "registry_length_mismatch")
            digest = hashlib.sha256()
            size = 0
            descriptor_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor_fd, "wb") as stream:
                try:
                    for chunk in self.chunks(response, descriptor["size"]):
                        stream.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                        require(size <= descriptor["size"], "registry_body_oversize")
                    stream.flush()
                    os.fsync(stream.fileno())
                finally:
                    os.fchmod(stream.fileno(), 0o400)  # Failed downloaded bytes stay inert and retained.
        require(size == descriptor["size"] and "sha256:" + digest.hexdigest() == descriptor["digest"], "registry_integrity_mismatch")


def blob_name(digest):
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), "layer_digest_invalid")
    return digest.replace(":", "-") + ".tar.gz"


def object_plan(recipe):
    objects = []
    layers = {}
    for name, source in sorted(recipe["sources"].items()):
        objects += [(source["repository"], "manifests", source["manifest"], name + "-arm64-manifest.json"),
                    (source["repository"], "blobs", source["configuration"], name + "-arm64-config.json")]
        for layer in source["layers"]:
            descriptor = {key: layer[key] for key in ("digest", "size")}
            old = layers.get(layer["digest"])
            require(old is None or old[2] == descriptor, "shared_layer_descriptor_conflict")
            layers.setdefault(layer["digest"], (source["repository"], "blobs", descriptor, blob_name(layer["digest"])))
    require(sum(row[2]["size"] for row in layers.values()) <= TOTAL_COMPRESSED_LIMIT, "total_source_size_exceeded")
    return objects + [layers[key] for key in sorted(layers)]


def check_layer(path, expected, diff_id):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, "layer_path_not_canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                and not before.st_mode & 0o222 and before.st_size == expected["size"], "layer_authority_or_size_invalid")
        compressed = hashlib.sha256()
        while block := stream.read(1024 * 1024):
            compressed.update(block)
        require("sha256:" + compressed.hexdigest() == expected["digest"], "layer_hash_mismatch")
        stream.seek(0)
        digest, size = hashlib.sha256(), 0
        with gzip.GzipFile(fileobj=stream, mode="rb") as decoded:
            while block := decoded.read(1024 * 1024):
                size += len(block)
                require(size <= EXPANDED_LAYER_LIMIT, "expanded_layer_size_exceeded")
                digest.update(block)
        after = os.fstat(stream.fileno())
    require(identity(before) == identity(after) and identity(after) == identity(path.stat(follow_symlinks=False)), "layer_changed_during_read")
    require("sha256:" + digest.hexdigest() == diff_id, "layer_diff_id_mismatch")
    return {"digest": expected["digest"], "compressed_bytes": expected["size"], "diff_id": diff_id, "expanded_bytes": size}


def load_assembler(expected_digest):
    """Execute exactly verified first-party bytes, without reopening the path."""
    path = ROOT / "docker/prepare_images.py"
    source = read_file(path, JSON_LIMIT)
    require(hashlib.sha256(source).hexdigest() == expected_digest, "assembler_changed")
    module = types.ModuleType("hobnail_reviewed_image_assembler")
    module.__file__ = str(path)
    module.__package__ = ""
    exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def prepare(output, *, source_cache=None, download=False):
    require(type(download) is bool and download != (source_cache is not None), "select_one_source_mode")
    recipe, recipe_hash = load_recipe()
    plan = object_plan(recipe)  # The same total-input bounds apply offline.
    output = Path(output).absolute()
    require(output.parent.resolve(strict=True) == output.parent, "output_parent_not_canonical")
    output.mkdir(mode=0o700, exist_ok=False)
    receipt = {"schema": "hobnail-docker-preparation-v1", "status": "incomplete", "source_closure_sha256": recipe_hash,
               "assembler_sha256": recipe["assembler_sha256"], "source_mode": "anonymous-download" if download else "offline-cache",
               "scope": "static exact-byte assembly only; no image execution, release, or current vulnerability clearance"}
    try:
        if download:
            source_cache = output / "sources"
            source_cache.mkdir(mode=0o700)
            registry = Registry()
            for repository, kind, descriptor, filename in plan:
                registry.fetch(repository, kind, descriptor, source_cache / filename)
            source_cache.chmod(0o500)
        else:
            source_cache = Path(source_cache).absolute()
            info = source_cache.stat()
            require(source_cache.resolve(strict=True) == source_cache and stat.S_ISDIR(info.st_mode)
                    and info.st_uid == os.getuid() and not info.st_mode & 0o022, "source_cache_directory_invalid")
        review = output / "review"
        review.mkdir(mode=0o700)
        observed_layers = {}
        for name, source in sorted(recipe["sources"].items()):
            metadata = {}
            for kind, suffix in (("manifest", "manifest"), ("configuration", "config")):
                filename = name + "-arm64-" + suffix + ".json"
                raw = read_file(source_cache / filename, JSON_LIMIT, readonly=True)
                expected = source[kind]
                require(len(raw) == expected["size"] and "sha256:" + hashlib.sha256(raw).hexdigest() == expected["digest"], "metadata_integrity_mismatch")
                metadata[kind] = decode(raw)
                write_file(review / filename, raw)
            manifest, config = metadata["manifest"], metadata["configuration"]
            require(manifest.get("layers") == source["layers"] and manifest.get("config", {}).get("digest") == source["configuration"]["digest"], "manifest_descriptor_mismatch")
            require(config.get("architecture") == "arm64" and config.get("os") == "linux"
                    and config.get("rootfs", {}).get("type") == "layers", "configuration_platform_invalid")
            diff_ids = config["rootfs"].get("diff_ids")
            require(isinstance(diff_ids, list) and len(diff_ids) == len(source["layers"]), "configuration_diff_ids_invalid")
            for layer, diff_id in zip(source["layers"], diff_ids):
                require(isinstance(diff_id, str) and DIGEST.fullmatch(diff_id), "configuration_diff_id_invalid")
                if layer["digest"] in observed_layers:
                    require(observed_layers[layer["digest"]]["diff_id"] == diff_id, "shared_layer_diff_id_conflict")
                    continue
                observed_layers[layer["digest"]] = check_layer(source_cache / blob_name(layer["digest"]), layer, diff_id)
        receipt["layers"] = [observed_layers[key] for key in sorted(observed_layers)]
        for flavor, inventory in recipe["inventories"].items():
            write_file(review / (flavor + "-closure-inventory.json"), encode(inventory))
        review.chmod(0o500)
        assembler = load_assembler(recipe["assembler_sha256"])
        archives = assembler.assemble(review, source_cache, output / "rootfs")
        require(archives == recipe["outputs"], "reconstructed_archive_mismatch")
        receipt.update(status="prepared", archives=archives)
    except KeyboardInterrupt:
        receipt.update(status="interrupted", failure="KeyboardInterrupt")
        write_file(output / "preparation.json", encode(receipt))
        raise
    except Exception as error:
        receipt.update(status="failed", failure=str(error) if isinstance(error, PreparationError) else type(error).__name__)
        write_file(output / "preparation.json", encode(receipt))
        raise PreparationError(receipt["failure"]) from None
    write_file(output / "preparation.json", encode(receipt))
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New private directory; existing paths refuse")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--download", action="store_true", help="Retrieve only pinned official objects anonymously")
    mode.add_argument("--source-cache", type=Path, help="Existing read-only sources directory; no network")
    arguments = parser.parse_args(argv)
    try:
        result = prepare(arguments.output, source_cache=arguments.source_cache, download=arguments.download)
    except KeyboardInterrupt:
        print(json.dumps({"status": "interrupted", "failure": "KeyboardInterrupt"}))
        return 130
    except Exception as error:
        print(json.dumps({"status": "failed", "failure": str(error) if isinstance(error, PreparationError) else type(error).__name__}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
