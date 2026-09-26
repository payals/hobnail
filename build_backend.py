"""Small standard-library-only PEP 517 backend; no downloaded build tooling."""
from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
from pathlib import PurePosixPath
import re
import tarfile
import tomllib
import zipfile

_ROOT = Path(__file__).resolve().parent
_PROJECT = tomllib.loads((_ROOT / "pyproject.toml").read_text())["project"]
_NAME = _PROJECT["name"]
_VERSION = _PROJECT["version"]
if (not isinstance(_NAME, str) or not re.fullmatch(r"[a-z0-9]+(?:_[a-z0-9]+)*", _NAME)
        or not isinstance(_VERSION, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", _VERSION)):
    raise ValueError("this backend requires a normalized package name and stable numeric version")
_DIST_INFO = f"{_NAME}-{_VERSION}.dist-info"


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def _metadata() -> bytes:
    if not (_ROOT / "LICENSE").is_file():
        raise FileNotFoundError("required distribution license file is missing")
    return (f"Metadata-Version: 2.4\nName: {_NAME}\nVersion: {_VERSION}\n"
            f"Summary: {_PROJECT['description']}\nRequires-Python: {_PROJECT['requires-python']}\n"
            "License-Expression: MIT\nLicense-File: LICENSE\nDescription-Content-Type: text/markdown\n\n" +
            (_ROOT / "README.md").read_bytes().decode("utf-8")).encode("utf-8")


def _metadata_files() -> dict[str, bytes]:
    files = {"METADATA": _metadata(), "WHEEL": b"Wheel-Version: 1.0\nGenerator: hobnail-stdlib\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
             "entry_points.txt": b"[console_scripts]\nhobnail = hobnail.cli:main\n"}
    if (_ROOT / "LICENSE").is_file():
        files["licenses/LICENSE"] = (_ROOT / "LICENSE").read_bytes()
    return files


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    destination = Path(metadata_directory) / _DIST_INFO
    destination.mkdir(parents=True, exist_ok=True)
    for name, data in _metadata_files().items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return _DIST_INFO


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    files = {path.relative_to(_ROOT / "src").as_posix(): path.read_bytes()
             for path in sorted((_ROOT / "src" / "hobnail").rglob("*.py")) if "__pycache__" not in path.parts}
    files.update({f"{_DIST_INFO}/{name}": data for name, data in _metadata_files().items()})
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        writer.writerow([name, "sha256=" + digest, len(data)])
    writer.writerow([f"{_DIST_INFO}/RECORD", "", ""])
    files[f"{_DIST_INFO}/RECORD"] = record.getvalue().encode("utf-8")
    filename = f"{_NAME}-{_VERSION}-py3-none-any.whl"
    destination = Path(wheel_directory)
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination / filename, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            entry.external_attr = 0o644 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    return filename


def build_sdist(sdist_directory, config_settings=None):
    filename = f"{_NAME}-{_VERSION}.tar.gz"
    destination = Path(sdist_directory)
    destination.mkdir(parents=True, exist_ok=True)
    paths = [path for path in (_ROOT / "src" / "hobnail").rglob("*.py") if "__pycache__" not in path.parts]
    paths.extend(_ROOT / name for name in ("pyproject.toml", "build_backend.py", "README.md", "LICENSE", "SECURITY.md", "AGENTS.md", "CONTRIBUTING.md", "VISION.md", "PLAN.md", "WORKLOG.md", "install.sql", "pg_hba.example") if (_ROOT / name).is_file())
    # The wheel is the Python SDK. The source distribution additionally contains
    # the SQL/runtime setup and its documentation and verification suite.
    source_suffixes = {".py", ".sql", ".sh", ".md", ".html", ".txt", ".json", ".toml"}
    for folder in ("docs", "migrations", "schema", "scripts", "tests", "skills"):
        paths.extend(path for path in (_ROOT / folder).rglob("*")
                     if path.is_file() and not path.is_symlink() and path.suffix in source_suffixes
                     and not {"out", "__pycache__"}.intersection(path.relative_to(_ROOT).parts))
    public_manifest = _ROOT / "PUBLIC-SOURCE.json"
    if public_manifest.exists():
        # The reviewed public export explicitly lists its complete source tree,
        # including Docker/CI files without suffixes and excluding private work
        # history. Independent release verification compares this with Git.
        declaration = json.loads(public_manifest.read_text(encoding="utf-8"))
        names = declaration.get("files")
        if (declaration.get("schema") != "hobnail-public-source-v1" or declaration.get("profile") != "public"
                or not isinstance(names, list) or not all(isinstance(name, str) for name in names)
                or names != sorted(set(names)) or "PUBLIC-SOURCE.json" not in names or "PKG-INFO" in names):
            raise ValueError("invalid public source manifest")
        paths = []
        for name in names:
            relative = PurePosixPath(name)
            path = _ROOT / name
            if (relative.is_absolute() or str(relative) != name or any(part in {".", "..", ".git"} for part in relative.parts)
                    or path.resolve(strict=True) != path or not path.is_file() or path.is_symlink()):
                raise ValueError("public source member is unsafe")
            paths.append(path)
    # PyPA sdists require PKG-INFO (core metadata >=2.2) at the source root.
    # Generate the same static metadata used by wheels, with explicit licenses.
    members = [(path.relative_to(_ROOT).as_posix(), path.read_bytes(),
                0o755 if path.stat().st_mode & 0o111 else 0o644) for path in paths]
    members.append(("PKG-INFO", _metadata(), 0o644))
    with (destination / filename).open("wb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name, data, mode in sorted(members):
                    entry = tarfile.TarInfo(f"{_NAME}-{_VERSION}/" + name)
                    entry.size = len(data)
                    entry.mode = mode
                    archive.addfile(entry, io.BytesIO(data))
    return filename
