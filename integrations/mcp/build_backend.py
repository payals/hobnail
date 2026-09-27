"""Deterministic stdlib backend for the separate optional MCP distribution."""
from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
NAME = "hobnail_mcp"
VERSION = PROJECT["version"]
INFO = f"{NAME}-{VERSION}.dist-info"


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def metadata():
    requirements = "".join("Requires-Dist: " + value + "\n" for value in PROJECT["dependencies"])
    return (f"Metadata-Version: 2.4\nName: {PROJECT['name']}\nVersion: {VERSION}\n"
            f"Summary: {PROJECT['description']}\nRequires-Python: {PROJECT['requires-python']}\n"
            "License-Expression: MIT\nLicense-File: LICENSE\n" + requirements +
            "Description-Content-Type: text/markdown\n\n" + (ROOT / "README.md").read_text()).encode()


def metadata_files():
    return {"METADATA": metadata(), "WHEEL": b"Wheel-Version: 1.0\nGenerator: hobnail-stdlib\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            "entry_points.txt": b"[console_scripts]\nhobnail-mcp = hobnail_mcp.server:main\n",
            "licenses/LICENSE": (ROOT / "LICENSE").read_bytes()}


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    destination = Path(metadata_directory) / INFO
    for name, data in metadata_files().items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return INFO


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    files = {path.relative_to(ROOT / "src").as_posix(): path.read_bytes()
             for path in sorted((ROOT / "src/hobnail_mcp").rglob("*.py"))}
    files.update({f"{INFO}/{name}": data for name, data in metadata_files().items()})
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, data in sorted(files.items()):
        writer.writerow([name, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode(), len(data)])
    writer.writerow([f"{INFO}/RECORD", "", ""])
    files[f"{INFO}/RECORD"] = record.getvalue().encode()
    destination = Path(wheel_directory)
    destination.mkdir(parents=True, exist_ok=True)
    filename = f"{NAME}-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(destination / filename, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            member = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            member.external_attr = 0o644 << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, data)
    return filename


def build_sdist(sdist_directory, config_settings=None):
    files = [*sorted((ROOT / "src/hobnail_mcp").rglob("*.py")),
             *(ROOT / name for name in ("pyproject.toml", "build_backend.py", "README.md", "LICENSE")),
             *sorted(ROOT.glob("requirements*.lock"))]
    members = {path.relative_to(ROOT).as_posix(): path.read_bytes() for path in files}
    members["PKG-INFO"] = metadata()
    destination = Path(sdist_directory)
    destination.mkdir(parents=True, exist_ok=True)
    filename = f"{NAME}-{VERSION}.tar.gz"
    with (destination / filename).open("wb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name, data in sorted(members.items()):
                    member = tarfile.TarInfo(f"{NAME}-{VERSION}/" + name)
                    member.size, member.mode = len(data), 0o644
                    archive.addfile(member, io.BytesIO(data))
    return filename
