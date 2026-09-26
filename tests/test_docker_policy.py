"""Portable preparation checks; these do not establish kernel isolation."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hobnail_image_preparation", ROOT / "docker/prepare_images.py")
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


def action(profile, syscall, *arguments):
    """Interpret this profile's limited comparison vocabulary for static checks."""
    matches = []
    for rule in profile["syscalls"]:
        if syscall not in rule["names"]:
            continue
        allowed = True
        for condition in rule.get("args", []):
            value = arguments[condition["index"]]
            if condition["op"] == "SCMP_CMP_EQ":
                allowed &= value == condition["value"]
            elif condition["op"] == "SCMP_CMP_MASKED_EQ":
                allowed &= value & condition["value"] == condition["valueTwo"]
            else:
                raise AssertionError("profile comparison needs independent review")
        if allowed:
            matches.append(rule["action"])
    if len(set(matches)) > 1:
        raise AssertionError("overlapping actions need independent review")
    return matches[0] if matches else profile["defaultAction"]


class DockerProfileTests(unittest.TestCase):
    def setUp(self):
        self.profiles = {name: json.loads((ROOT / f"docker/seccomp-{name}-arm64.json").read_text())
                         for name in ("parser", "role", "database")}

    def test_socket_family_controls_and_parser_difference(self):
        for name, profile in self.profiles.items():
            for syscall in ("socket", "socketpair"):
                self.assertEqual(action(profile, syscall, 1),
                                 "SCMP_ACT_ERRNO" if name == "parser" else "SCMP_ACT_ALLOW")
                for family in (0, 2, 10, 16, 17, 38, 40, 44):
                    self.assertEqual(action(profile, syscall, family), "SCMP_ACT_ERRNO", (name, syscall, family))

    def test_no_alternate_kernel_or_namespace_entry(self):
        forbidden = ("socketcall", "io_uring_setup", "io_uring_enter", "io_uring_register",
                     "ptrace", "process_vm_readv", "process_vm_writev", "bpf", "userfaultfd",
                     "mount", "umount2", "unshare", "setns", "open_by_handle_at")
        for name, profile in self.profiles.items():
            self.assertEqual(profile["architectures"], ["SCMP_ARCH_AARCH64"])
            for syscall in forbidden:
                self.assertEqual(action(profile, syscall), "SCMP_ACT_ERRNO", (name, syscall))
            self.assertEqual(action(profile, "clone3"), "SCMP_ACT_ERRNO")
            for namespace in (0x00020000, 0x02000000, 0x04000000, 0x08000000,
                              0x10000000, 0x20000000, 0x40000000):
                self.assertEqual(action(profile, "clone", namespace | 17), "SCMP_ACT_ERRNO")
        self.assertEqual(action(self.profiles["role"], "clone", 17), "SCMP_ACT_ALLOW")
        self.assertEqual(action(self.profiles["parser"], "clone", 17), "SCMP_ACT_ERRNO")

    def test_database_signal_descriptor_is_only_fresh_process_local_creation(self):
        self.assertEqual(action(self.profiles["database"], "signalfd4", -1), "SCMP_ACT_ALLOW")
        self.assertEqual(action(self.profiles["database"], "signalfd4", 4), "SCMP_ACT_ERRNO")
        self.assertEqual(action(self.profiles["role"], "signalfd4", -1), "SCMP_ACT_ERRNO")
        self.assertEqual(action(self.profiles["parser"], "signalfd4", -1), "SCMP_ACT_ERRNO")

    def test_only_database_children_can_start_a_private_process_session(self):
        self.assertEqual(action(self.profiles["database"], "setsid"), "SCMP_ACT_ALLOW")
        for role in ("role", "parser"):
            self.assertEqual(action(self.profiles[role], "setsid"), "SCMP_ACT_ERRNO")
        for profile in self.profiles.values():
            self.assertEqual(action(profile, "setpgid"), "SCMP_ACT_ERRNO")
            self.assertEqual(action(profile, "setns"), "SCMP_ACT_ERRNO")

    def test_database_writeback_uses_only_existing_descriptor_write_flag(self):
        self.assertEqual(action(self.profiles["database"], "sync_file_range", 4, 0, 4096, 2), "SCMP_ACT_ALLOW")
        for flags in (0, 1, 3, 4, 5, 6, 7, 0x10002):
            self.assertEqual(action(self.profiles["database"], "sync_file_range", 4, 0, 4096, flags), "SCMP_ACT_ERRNO")
        for role in ("role", "parser"):
            self.assertEqual(action(self.profiles[role], "sync_file_range", 4, 0, 4096, 2), "SCMP_ACT_ERRNO")
        for profile in self.profiles.values():
            self.assertEqual(action(profile, "sync_file_range2", 4, 2, 0, 4096), "SCMP_ACT_ERRNO")

    def test_database_fd_io_does_not_enable_other_roles_or_allocation_modes(self):
        self.assertEqual(action(self.profiles["database"], "fallocate", 4, 0), "SCMP_ACT_ALLOW")
        for mode in (1, 2, 3, 8, 16, 32, 64):
            self.assertEqual(action(self.profiles["database"], "fallocate", 4, mode), "SCMP_ACT_ERRNO")
        for name in ("preadv", "pwritev"):
            self.assertEqual(action(self.profiles["database"], name), "SCMP_ACT_ALLOW")
        for role in ("role", "parser"):
            self.assertEqual(action(self.profiles[role], "fallocate", 4, 0), "SCMP_ACT_ERRNO")
            for name in ("preadv", "pwritev"):
                self.assertEqual(action(self.profiles[role], name), "SCMP_ACT_ERRNO")


class DockerPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hobnail-static-image-")
        self.root = Path(self.temporary.name).resolve()
        self.review = self.root / "review"
        self.quarantine = self.root / "quarantine"
        self.review.mkdir()
        self.quarantine.mkdir()
        source = self.quarantine / "source.tar.gz"
        value = b"controlled inert fixture bytes\n"
        with tarfile.open(source, "w:gz") as archive:
            member = tarfile.TarInfo("usr/local/bin/python3.14")
            member.size = len(value)
            member.mode = 0o755
            archive.addfile(member, io.BytesIO(value))
        digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
        layer = self.quarantine / (digest.replace(":", "-") + ".tar.gz")
        source.rename(layer)
        layer.chmod(0o400)
        self.layer = layer
        self.entry = {"name": "usr/local/bin/python3.14", "type": "0", "size": len(value),
                      "mode": 0o755, "uid": 0, "gid": 0, "linkname": "", "image": "python",
                      "layer": digest, "sha256": hashlib.sha256(value).hexdigest()}
        (self.review / "layer-integrity.json").write_text(json.dumps({"layers": [{"digest": digest, "size": layer.stat().st_size}]}))
        pins = {}
        for image in ("python", "postgres"):
            config = json.dumps({"architecture": "arm64", "os": "linux"}).encode()
            manifest = json.dumps({"config": {"digest": "sha256:" + hashlib.sha256(config).hexdigest()},
                                   "layers": [{"digest": digest, "size": layer.stat().st_size}]}).encode()
            (self.review / f"{image}-arm64-config.json").write_bytes(config)
            (self.review / f"{image}-arm64-manifest.json").write_bytes(manifest)
            pins[image] = "sha256:" + hashlib.sha256(manifest).hexdigest()
        self.pin_fixture = patch.object(PREPARE, "IMAGES", pins)
        self.pin_fixture.start()
        self.addCleanup(self.pin_fixture.stop)
        self.write_inventories([self.entry])

    def tearDown(self):
        for path in self.root.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
        self.temporary.cleanup()

    def write_inventories(self, entries):
        for flavor in ("parser", "runtime"):
            (self.review / f"{flavor}-closure-inventory.json").write_text(json.dumps({
                "flavor": flavor, "entries": entries, "missing": []}))

    def test_deterministic_assembly_and_no_source_execution(self):
        first = PREPARE.assemble(self.review, self.quarantine, self.root / "one")
        second = PREPARE.assemble(self.review, self.quarantine, self.root / "two")
        self.assertEqual(first, second)
        with tarfile.open(self.root / "one" / first[0]["filename"]) as archive:
            self.assertEqual(archive.extractfile("usr/local/bin/python3.14").read(), b"controlled inert fixture bytes\n")
            self.assertEqual(archive.getmember("destination").uid, 10006)
            self.assertFalse(any(member.mode & 0o6000 for member in archive))

    def test_corrupted_quarantine_layer_refuses_before_output(self):
        self.layer.chmod(0o600)
        with self.layer.open("ab") as stream:
            stream.write(b"tamper")
        self.layer.chmod(0o400)
        with self.assertRaisesRegex(ValueError, "integrity"):
            PREPARE.assemble(self.review, self.quarantine, self.root / "bad")
        self.assertFalse((self.root / "bad").exists())

    def test_path_alias_and_excluded_installers_refuse(self):
        for bad in ("../outside", "/absolute", "usr//bad", "usr/.wh.hidden", "usr/.wh..wh..opq",
                    "usr/local/bin/gosu",
                    "usr/local/lib/python3.14/site-packages/pip/example.py"):
            with self.subTest(path=bad):
                self.write_inventories([{**self.entry, "name": bad}])
                with self.assertRaises(ValueError):
                    PREPARE.assemble(self.review, self.quarantine, self.root / "bad")

    def test_symlink_cannot_reach_unselected_content(self):
        self.write_inventories([self.entry, {**self.entry, "name": "usr/local/bin/alias",
                                           "type": "2", "linkname": "../../../../outside", "size": 0}])
        with self.assertRaises(ValueError):
            PREPARE.assemble(self.review, self.quarantine, self.root / "bad")

    def test_asserted_source_identity_does_not_replace_pinned_bytes(self):
        (self.review / "python-arm64-manifest.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "manifest bytes"):
            PREPARE.assemble(self.review, self.quarantine, self.root / "bad")

    def test_selected_layers_must_belong_to_pinned_image(self):
        self.write_inventories([{**self.entry, "layer": "sha256:" + "a" * 64}])
        with self.assertRaisesRegex(ValueError, "outside its pinned manifest"):
            PREPARE.assemble(self.review, self.quarantine, self.root / "bad")

    def test_initdb_requires_modules_loaded_by_standard_bootstrap_sql(self):
        initdb = {**self.entry, "name": "usr/local/bin/initdb"}
        for missing, present in (("dict_snowball", "plpgsql"), ("plpgsql", "dict_snowball")):
            with self.subTest(missing=missing):
                self.write_inventories([self.entry, initdb,
                    {**self.entry, "name": "usr/local/lib/postgresql/" + present + ".so"}])
                with self.assertRaisesRegex(ValueError, "initialization module is missing: .*" + missing):
                    PREPARE.assemble(self.review, self.quarantine, self.root / "bad")
                self.assertFalse((self.root / "bad").exists())

    def test_selected_link_cycles_and_link_parents_refuse(self):
        link = {**self.entry, "type": "2", "size": 0}
        cases = [[self.entry, {**link, "name": "cycle-a", "linkname": "cycle-b"},
                  {**link, "name": "cycle-b", "linkname": "cycle-a"}],
                 [self.entry, {**link, "name": "usr/local", "linkname": "/usr/local/bin"}]]
        for number, entries in enumerate(cases):
            with self.subTest(case=number):
                self.write_inventories(entries)
                with self.assertRaises(ValueError):
                    PREPARE.assemble(self.review, self.quarantine, self.root / f"bad-{number}")


if __name__ == "__main__":
    unittest.main()
