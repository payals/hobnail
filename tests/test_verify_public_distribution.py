"""Published source layout and PyPA archive gates, with first-party fixtures."""
import importlib.util
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import struct
import tarfile
import tempfile
import tomllib
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_public_distribution import PublicDistributionError, check_archives, consume_inventory


class PublicDistributionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hbn-public-package-test-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"; self.source.mkdir()
        self.files = {"build_backend.py": (ROOT / "build_backend.py").read_bytes(),
            "LICENSE": (ROOT / "LICENSE").read_bytes(), "README.md": b"Public fixture description\n",
            "src/hobnail/__init__.py": b'__version__ = "0.2.0"\n',
            "src/hobnail/cli.py": b'def main():\n    return 0\n',
            "docker/Dockerfile": b"# Explicit source file without suffix\nFROM scratch\n",
            ".github/workflows/check.yml": b"name: fixture\non: workflow_dispatch\n",
            "pyproject.toml": b'''[build-system]
requires=[]
build-backend="build_backend"
backend-path=["."]
[project]
name="hobnail"
version="0.2.0"
description="Public package fixture"
requires-python=">=3.11"
license="MIT"
dependencies=[]
[project.scripts]
hobnail="hobnail.cli:main"
'''}
        self.manifest = {"schema": "hobnail-public-source-v1", "profile": "public",
            "files": sorted([*self.files, "PUBLIC-SOURCE.json"])}
        self.files["PUBLIC-SOURCE.json"] = (json.dumps(self.manifest, sort_keys=True) + "\n").encode()
        self.modes = {name: 0o644 for name in self.files}
        for name, content in self.files.items():
            path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
        self.project = tomllib.loads(self.files["pyproject.toml"].decode())["project"]
        self.backend = self.load_backend()
        self.wheel = self.root / "wheel" / self.backend.build_wheel(self.root / "wheel")
        self.sdist = self.root / "sdist" / self.backend.build_sdist(self.root / "sdist")

    def load_backend(self):
        spec = importlib.util.spec_from_file_location("public_fixture_build", self.source / "build_backend.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def altered_sdist(self, name, *, omitted=None, extra=False):
        directory = self.root / name; directory.mkdir()
        path = directory / self.sdist.name
        with tarfile.open(self.sdist, "r:gz") as original, tarfile.open(path, "w:gz") as changed:
            for member in original.getmembers():
                if omitted and member.name.endswith("/" + omitted):
                    continue
                changed.addfile(member, original.extractfile(member))
            if extra:
                content = b"unapproved output"
                entry = tarfile.TarInfo("hobnail-0.2.0/.state/private.json"); entry.size = len(content)
                changed.addfile(entry, io.BytesIO(content))
        return path

    def test_complete_public_layout_and_generated_metadata_match(self):
        result = check_archives(self.wheel, self.sdist, self.files, self.modes, self.project)
        self.assertEqual(result["metadata_version"], "2.4")
        self.assertEqual(result["source_members"], len(self.files) + 1)
        with tarfile.open(self.sdist, "r:gz") as archive:
            self.assertEqual(archive.extractfile("hobnail-0.2.0/docker/Dockerfile").read(), self.files["docker/Dockerfile"])
            self.assertEqual(archive.extractfile("hobnail-0.2.0/.github/workflows/check.yml").read(), self.files[".github/workflows/check.yml"])
            self.assertIn("hobnail-0.2.0/PKG-INFO", archive.getnames())

    def test_untracked_private_file_is_not_in_public_source_archive(self):
        (self.source / "WORKLOG.md").write_text("Unselected private operational history")
        other = self.root / "other" / self.backend.build_sdist(self.root / "other")
        self.assertEqual(other.read_bytes(), self.sdist.read_bytes())
        check_archives(self.wheel, other, self.files, self.modes, self.project)

    def test_missing_metadata_license_or_extra_private_member_refuses(self):
        for name in ("PKG-INFO", "LICENSE", "docker/Dockerfile"):
            with self.subTest(name=name), self.assertRaisesRegex(PublicDistributionError, "source_archive_members_mismatch"):
                check_archives(self.wheel, self.altered_sdist(name.replace("/", "-"), omitted=name), self.files, self.modes, self.project)
        with self.assertRaisesRegex(PublicDistributionError, "source_archive_members_mismatch"):
            check_archives(self.wheel, self.altered_sdist("extra", extra=True), self.files, self.modes, self.project)

    def test_source_content_and_executable_mode_are_not_replaceable(self):
        changed = dict(self.files); changed["src/hobnail/cli.py"] += b"\n# changed expected source\n"
        with self.assertRaisesRegex(PublicDistributionError, "wheel_code_mismatch"):
            check_archives(self.wheel, self.sdist, changed, self.modes, self.project)
        changed_modes = dict(self.modes); changed_modes["docker/Dockerfile"] = 0o755
        with self.assertRaisesRegex(PublicDistributionError, "source_archive_mode_mismatch"):
            check_archives(self.wheel, self.sdist, self.files, changed_modes, self.project)

    def test_public_manifest_cannot_read_outside_source_or_through_alias(self):
        outside = self.root / "outside.txt"; outside.write_text("outside owned fixture")
        for value in ("../outside.txt", str(outside)):
            manifest = dict(self.manifest); manifest["files"] = sorted([*manifest["files"], value])
            (self.source / "PUBLIC-SOURCE.json").write_text(json.dumps(manifest))
            with self.subTest(path=value), self.assertRaises(ValueError):
                self.backend.build_sdist(self.root / "refused")
        alias = self.source / "alias.txt"; alias.symlink_to(outside)
        manifest = dict(self.manifest); manifest["files"] = sorted([*manifest["files"], "alias.txt"])
        (self.source / "PUBLIC-SOURCE.json").write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            self.backend.build_sdist(self.root / "refused-alias")

    def test_self_consistent_extra_metadata_cannot_leak_unbound_information(self):
        prefix = "hobnail-0.2.0.dist-info/"
        with zipfile.ZipFile(self.wheel) as archive:
            original = {name: archive.read(name) for name in archive.namelist()}
            information = {entry.filename: entry for entry in archive.infolist()}
        alterations = {
            "METADATA": original[prefix + "METADATA"].replace(b"Metadata-Version: 2.4\n", b"Metadata-Version: 2.4\nAuthor-email: private@institution.example.invalid\n"),
            "WHEEL": original[prefix + "WHEEL"] + b"\nUnbound private build details\n",
            "duplicate-WHEEL": original[prefix + "WHEEL"] + b"Generator: unbound-private-field\n",
            "entry_points.txt": b"# Unbound private build details\n" + original[prefix + "entry_points.txt"],
        }
        for filename, content in alterations.items():
            actual_name = "WHEEL" if filename == "duplicate-WHEEL" else filename
            members = {**original, prefix + actual_name: content}
            rows = list(csv.reader(io.StringIO(members[prefix + "RECORD"].decode())))
            for row in rows:
                if row[0] == prefix + actual_name:
                    row[1] = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
                    row[2] = str(len(content))
            record = io.StringIO(newline=""); csv.writer(record, lineterminator="\n").writerows(rows)
            members[prefix + "RECORD"] = record.getvalue().encode()
            target = self.root / (filename.replace(".", "-") + ".whl")
            with zipfile.ZipFile(target, "w") as archive:
                for name, value in members.items(): archive.writestr(information[name], value)
            with self.subTest(filename=filename), self.assertRaises(PublicDistributionError):
                check_archives(target, self.sdist, self.files, self.modes, self.project)

    def test_container_comments_and_owner_metadata_cannot_carry_unbound_data(self):
        altered_wheel = self.root / "comment.whl"
        altered_wheel.write_bytes(self.wheel.read_bytes())
        with zipfile.ZipFile(altered_wheel, "a") as archive:
            archive.comment = b"/Users/" + b"synthetic-owner/private-evidence"
        with self.assertRaisesRegex(PublicDistributionError, "unbound_zip_archive_comment"):
            check_archives(altered_wheel, self.sdist, self.files, self.modes, self.project)
        for field in ("uname", "pax_headers"):
            directory = self.root / field; directory.mkdir(); path = directory / self.sdist.name
            with tarfile.open(self.sdist, "r:gz") as original, tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as modified:
                for member in original.getmembers():
                    if field == "uname": member.uname = "unbound-owner"
                    else: member.pax_headers = {"comment": "unbound-private-data"}
                    modified.addfile(member, original.extractfile(member))
            with self.subTest(field=field), self.assertRaisesRegex(PublicDistributionError, "unbound_tar_member_metadata"):
                check_archives(self.wheel, path, self.files, self.modes, self.project)

    def test_invalid_package_identity_refuses_before_writing_artifacts(self):
        original = (self.source / "pyproject.toml").read_text()
        for field, before, after in (("name", 'name="hobnail"', 'name="../../outside"'),
                                     ("version", 'version="0.2.0"', 'version="../../outside"')):
            (self.source / "pyproject.toml").write_text(original.replace(before, after))
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load_backend()
            self.assertFalse((self.root / "outside").exists())

    def test_local_zip_extra_refuses_even_when_central_metadata_and_contents_match(self):
        original = self.wheel.read_bytes()
        extra = struct.pack("<HH", 0xCAFE, 19) + b"synthetic-only-data!"
        name_length = struct.unpack_from("<H", original, 26)[0]
        insertion = 30 + name_length
        modified = bytearray(original[:insertion] + extra + original[insertion:])
        struct.pack_into("<H", modified, 28, len(extra))
        end = modified.rfind(b"PK\x05\x06")
        central = struct.unpack_from("<I", modified, end + 16)[0] + len(extra)
        struct.pack_into("<I", modified, end + 16, central)
        position = central
        while modified[position:position + 4] == b"PK\x01\x02":
            offset = struct.unpack_from("<I", modified, position + 42)[0]
            if offset:
                struct.pack_into("<I", modified, position + 42, offset + len(extra))
            lengths = struct.unpack_from("<HHH", modified, position + 28)
            position += 46 + sum(lengths)
        target = self.root / "local-extra.whl"; target.write_bytes(modified)
        with zipfile.ZipFile(self.wheel) as before, zipfile.ZipFile(target) as after:
            for entry in after.infolist():
                self.assertEqual(entry.extra, b"")
                self.assertEqual(after.read(entry), before.read(entry.filename))
        with self.assertRaisesRegex(PublicDistributionError, "unbound_zip_local_extra"):
            check_archives(target, self.sdist, self.files, self.modes, self.project)

    def test_delivered_inventory_is_consumed_only_when_exact_git_facts_match(self):
        expected = {"source_commit": "a" * 40, "files": [{"path": "README.md", "bytes": 1}]}
        path = self.root / "delivered-inventory.json"
        path.write_text(json.dumps(expected))
        actual, receipt = consume_inventory(path, expected)
        self.assertEqual(actual, expected)
        self.assertEqual(receipt["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertTrue(receipt["used_for_source_member_verification"])
        for altered in ({**expected, "source_commit": "b" * 40}, {**expected, "files": []},
                {**expected, "extra": True}, {**expected, "files": [{"path": "README.md", "bytes": True}]}):
            path.write_text(json.dumps(altered))
            with self.subTest(altered=altered), self.assertRaisesRegex(PublicDistributionError, "differs_from_git"):
                consume_inventory(path, expected)
        path.write_text('{"files":[],"files":[],"source_commit":"' + "a" * 40 + '"}')
        with self.assertRaisesRegex(PublicDistributionError, "duplicate_inventory_key"):
            consume_inventory(path, expected)


if __name__ == "__main__":
    unittest.main()
