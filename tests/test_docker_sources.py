"""Inert retrieval/integrity checks; no Docker or third-party code executes."""

from contextlib import contextmanager
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch

from scripts import prepare_docker_sources as preparation


class Response(io.BytesIO):
    status = 200

    def __init__(self, raw, headers=None):
        super().__init__(raw)
        self.headers = {} if headers is None else headers


class DockerSourcesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hobnail-source-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    @contextmanager
    def altered_recipe(self, mutation):
        root = self.root / "recipe"
        (root / "docker").mkdir(parents=True)
        for name in ("images.lock.json", "prepare_images.py"):
            (root / "docker" / name).write_bytes((preparation.ROOT / "docker" / name).read_bytes())
        value = json.loads((preparation.ROOT / "docker/source-closure.json").read_text())
        mutation(value)
        (root / "docker/source-closure.json").write_bytes(preparation.encode(value))
        with patch.object(preparation, "ROOT", root):
            yield

    def test_public_recipe_contains_exact_locked_inputs_and_no_private_receipts(self):
        recipe, digest = preparation.load_recipe()
        self.assertEqual(len(digest), 64)
        self.assertEqual({key: len(value["entries"]) for key, value in recipe["inventories"].items()},
                         {"parser": 1597, "runtime": 1944})
        self.assertEqual(len(preparation.object_plan(recipe)), 16)
        self.assertEqual(sum(row[2]["size"] for row in preparation.object_plan(recipe) if row[3].endswith(".tar.gz")), 131400224)
        text = json.dumps(recipe)
        for private in ("/Users/", "/home/", ".state/", ".codex/", "execution_authorized", "owner-approval"):
            self.assertNotIn(private, text)
        runtime = recipe["inventories"]["runtime"]["entries"]
        snowball = [entry for entry in runtime if entry["name"] == "usr/local/lib/postgresql/dict_snowball.so"]
        self.assertEqual(len(snowball), 1)
        self.assertEqual(snowball[0]["sha256"], "a8485fc896eadbae7070b005739b8098755d43e1c93f28ffacb201dfb2ec2bf1")

    def test_recipe_rejects_unknown_metadata_and_changed_source_before_output(self):
        mutations = {
            "extra": lambda value: value.update(private_receipt="hidden"),
            "repository": lambda value: value["sources"]["python"].update(repository="other/python"),
            "path": lambda value: value["inventories"]["parser"]["entries"][0].update(name="../outside"),
            "owner": lambda value: value["inventories"]["parser"]["entries"][0].update(uid=True),
            "source": lambda value: value["sources"]["python"]["manifest"].update(digest="sha256:" + "0" * 64),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                old_root = self.root
                self.root = Path(temporary)
                try:
                    with self.altered_recipe(mutation), self.assertRaises(preparation.PreparationError):
                        preparation.prepare(self.root / "output", source_cache=self.root)
                    self.assertFalse((self.root / "output").exists())
                finally:
                    self.root = old_root

    def test_duplicate_json_and_nonfinite_values_refuse(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(preparation.PreparationError):
                preparation.decode(raw)

    def test_cache_files_require_readonly_single_owned_regular_identity(self):
        path = self.root / "source"
        path.write_bytes(b"inert source")
        with self.assertRaisesRegex(preparation.PreparationError, "source_cache_not_readonly"):
            preparation.read_file(path, 100, readonly=True)
        path.chmod(0o400)
        self.assertEqual(preparation.read_file(path, 100, readonly=True), b"inert source")
        linked = self.root / "linked"
        os.link(path, linked)
        with self.assertRaisesRegex(preparation.PreparationError, "source_file_not_owned_regular"):
            preparation.read_file(path, 100, readonly=True)
        alias = self.root / "alias"
        alias.symlink_to(path)
        with self.assertRaisesRegex(preparation.PreparationError, "source_path_not_canonical"):
            preparation.read_file(alias, 100, readonly=True)

    def test_compressed_and_uncompressed_layer_hashes_are_independent(self):
        raw = b"inert tar-byte fixture; never executed" * 100
        compressed = gzip.compress(raw, mtime=0)
        path = self.root / "layer.tar.gz"
        preparation.write_file(path, compressed)
        expected = {"digest": "sha256:" + hashlib.sha256(compressed).hexdigest(), "size": len(compressed)}
        diff_id = "sha256:" + hashlib.sha256(raw).hexdigest()
        result = preparation.check_layer(path, expected, diff_id)
        self.assertEqual(result["expanded_bytes"], len(raw))
        with self.assertRaisesRegex(preparation.PreparationError, "layer_diff_id_mismatch"):
            preparation.check_layer(path, expected, "sha256:" + "0" * 64)
        with patch.object(preparation, "EXPANDED_LAYER_LIMIT", len(raw) - 1), self.assertRaisesRegex(preparation.PreparationError, "expanded_layer_size_exceeded"):
            preparation.check_layer(path, expected, diff_id)
        with self.assertRaisesRegex(preparation.PreparationError, "layer_hash_mismatch"):
            preparation.check_layer(path, {**expected, "digest": "sha256:" + "0" * 64}, diff_id)

    def registry(self):
        registry = preparation.Registry()
        registry.opener = Mock()
        return registry

    def test_redirect_strips_registry_token_and_refuses_unlisted_destinations(self):
        registry = self.registry()
        original = "https://registry-1.docker.io/v2/library/python/blobs/sha256:" + "a" * 64
        target = "https://production.cloudfront.docker.com/pinned-public-blob"
        redirect = urllib.error.HTTPError(original, 307, "body withheld", {"Location": target}, io.BytesIO())
        registry.opener.open.side_effect = [redirect, Response(b"bytes")]
        with registry.open(original, token="synthetic-anonymous-token") as response:
            self.assertEqual(response.read(), b"bytes")
        requests = [call.args[0] for call in registry.opener.open.call_args_list]
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer synthetic-anonymous-token")
        self.assertIsNone(requests[1].get_header("Authorization"))
        self.assertEqual(requests[1].full_url, target)
        for target in ("http://production.cloudfront.docker.com/blob", "https://unrelated.invalid/blob",
                       "https://registry-1.docker.io@unrelated.invalid/blob", "https://registry-1.docker.io:444/blob",
                       "https://registry-1.docker.io/blob#fragment"):
            with self.subTest(target=target), self.assertRaises(preparation.PreparationError):
                preparation.public_url(target, preparation.REDIRECT_HOSTS)

    def test_auth_is_anonymous_fixed_scope_without_refresh_or_personal_config(self):
        registry = self.registry()
        registry.opener.open.return_value = Response(b'{"token":"synthetic-token","access_token":"synthetic-token"}')
        self.assertEqual(registry.token("library/python"), "synthetic-token")
        request = registry.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fpython%3Apull")
        self.assertIsNone(request.get_header("Authorization"))
        self.assertNotIn("offline_token", request.full_url)
        with self.assertRaisesRegex(preparation.PreparationError, "token_scope_invalid"):
            registry.token("private/repository")
        registry.opener.open.return_value = Response(b'{"token":"first","access_token":"different"}')
        with self.assertRaisesRegex(preparation.PreparationError, "anonymous_token_invalid"):
            registry.token("library/python")

    def test_trickling_bodies_use_read1_and_cannot_run_past_checked_deadline(self):
        registry = self.registry()
        clock = [0]
        class Trickle(Response):
            def read(self, size=-1):
                raise AssertionError("unbounded buffered read must not be used")
            def read1(self, size=-1):
                clock[0] += 1
                return super().read(1)
        registry.deadline = 3
        with patch.object(preparation.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(preparation.PreparationError, "download_deadline_exceeded"):
                list(registry.chunks(Trickle(b"trickling"), 100))
        self.assertEqual(clock[0], 4)
        registry.deadline = 100
        registry.opener.open.return_value = Trickle(b'{"token":"synthetic-token"}')
        with patch.object(preparation.time, "monotonic", return_value=0):
            self.assertEqual(registry.token("library/python"), "synthetic-token")

    def test_assembler_executes_verified_bytes_even_if_path_changes_after_read(self):
        root = self.root / "assembler"
        (root / "docker").mkdir(parents=True)
        path = root / "docker/prepare_images.py"
        source = b"VALUE = 'verified bytes'\n"
        path.write_bytes(source)
        original_read = preparation.read_file
        def changed_after_read(target, maximum):
            raw = original_read(target, maximum)
            path.write_bytes(b"raise AssertionError('changed path must not execute')\n")
            return raw
        with patch.object(preparation, "ROOT", root), patch.object(preparation, "read_file", side_effect=changed_after_read):
            module = preparation.load_assembler(hashlib.sha256(source).hexdigest())
        self.assertEqual(module.VALUE, "verified bytes")
        self.assertEqual(module.__file__, str(path))
        with patch.object(preparation, "ROOT", root), self.assertRaisesRegex(preparation.PreparationError, "assembler_changed"):
            preparation.load_assembler(hashlib.sha256(source).hexdigest())

    def test_interrupt_retains_receipt_and_returns_130(self):
        output = self.root / "interrupted"
        registry = Mock()
        registry.fetch.side_effect = KeyboardInterrupt
        stdout = io.StringIO()
        with patch.object(preparation, "Registry", return_value=registry), patch.object(preparation.sys, "stdout", stdout):
            result = preparation.main(["--download", "--output", str(output)])
        self.assertEqual(result, 130)
        receipt = json.loads((output / "preparation.json").read_text())
        self.assertEqual(receipt["status"], "interrupted")
        self.assertEqual(receipt["failure"], "KeyboardInterrupt")
        self.assertEqual(json.loads(stdout.getvalue()), {"status": "interrupted", "failure": "KeyboardInterrupt"})
        self.assertEqual(stat.S_IMODE((output / "preparation.json").stat().st_mode), 0o400)

    def test_fetch_hash_mismatch_retains_readonly_bytes_without_credential_diagnostics(self):
        registry = self.registry()
        destination = self.root / "blob"
        with patch.object(registry, "token", return_value="synthetic-private-token"), patch.object(registry, "open", return_value=Response(b"wrong")):
            with self.assertRaisesRegex(preparation.PreparationError, "registry_integrity_mismatch") as caught:
                registry.fetch("library/python", "blobs", {"digest": "sha256:" + "0" * 64, "size": 5}, destination)
        self.assertEqual(destination.read_bytes(), b"wrong")
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
        self.assertNotIn("synthetic-private-token", str(caught.exception))

    def test_fetch_overflow_and_deadline_cannot_pass_or_overwrite_existing_file(self):
        registry = self.registry()
        expected = {"digest": "sha256:" + hashlib.sha256(b"abc").hexdigest(), "size": 3}
        destination = self.root / "overflow"
        with patch.object(registry, "token", return_value="synthetic-token"), patch.object(registry, "open", return_value=Response(b"abcdef")):
            with self.assertRaisesRegex(preparation.PreparationError, "registry_body_oversize"):
                registry.fetch("library/python", "blobs", expected, destination)
        self.assertEqual(destination.read_bytes(), b"abcd")
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
        with patch.object(registry, "token", return_value="synthetic-token"), patch.object(registry, "open", return_value=Response(b"abc")):
            with self.assertRaises(FileExistsError):
                registry.fetch("library/python", "blobs", expected, destination)
        self.assertEqual(destination.read_bytes(), b"abcd")
        registry.deadline = 0
        with self.assertRaisesRegex(preparation.PreparationError, "download_deadline_exceeded"):
            registry.open("https://registry-1.docker.io/v2/library/python/manifests/sha256:" + "a" * 64)

    def test_offline_failure_has_receipt_and_never_creates_registry_or_overwrites_output(self):
        output = self.root / "new-output"
        with patch.object(preparation, "Registry") as registry, self.assertRaises(preparation.PreparationError):
            preparation.prepare(output, source_cache=self.root)
        registry.assert_not_called()
        receipt = json.loads((output / "preparation.json").read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["source_mode"], "offline-cache")
        self.assertNotIn(str(self.root), json.dumps(receipt))
        before = (output / "preparation.json").read_bytes()
        with self.assertRaises(FileExistsError):
            preparation.prepare(output, source_cache=self.root)
        self.assertEqual((output / "preparation.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
