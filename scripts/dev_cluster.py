#!/usr/bin/env python3
"""Own a disposable, socket-only PostgreSQL development cluster.

    with DevCluster() as cluster:
        cluster.psql("SELECT session_user")
        cluster.psql_file("install.sql")

The private directory and every log are retained after stop, including failures.
Nothing is removed and no existing database or cluster is reused. Socket trust
authentication is for synthetic database-identity probes only: processes with
the same OS identity can impersonate any database role. This is NOT an OS
isolation or production-authentication recipe.

CLI: ``python scripts/dev_cluster.py create`` prints the owned root and socket;
``status ROOT`` and ``stop ROOT`` only inspect/stop that marked cluster.
``prune`` lists stopped, ownership-marked ``hbn-*`` roots under ``--base-dir``
(default /tmp) untouched for ``--older-than-hours`` (default 24) with their
sizes; only ``prune --delete`` removes them, and ``--data-only`` removes just
their database files, keeping receipts and logs.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any
import uuid


MARKER = ".hobnail-dev-cluster.json"
FORMAT = "hobnail-private-postgres-v1"
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")


class ClusterError(RuntimeError):
    """A lifecycle or ownership check failed; retained logs remain available."""


def _identifier(value: str) -> str:
    # libpq interprets database strings containing '=' as connection strings.
    # Restrict names before passing them to either SQL or connection options.
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("database and user names must be simple PostgreSQL identifiers")
    return value


def _bindir(value: str | Path | None = None) -> Path:
    executable = shutil.which("initdb") if value is None else None
    if value is None and executable is None:
        raise ClusterError("initdb is not installed; provide an existing reviewed PostgreSQL bin directory")
    directory = Path(value).resolve() if value is not None else Path(executable).resolve().parent
    for name in ("initdb", "pg_ctl", "postgres", "psql"):
        if not (directory / name).is_file() or not os.access(directory / name, os.X_OK):
            raise ClusterError(f"missing executable: {directory / name}")
    return directory


class DevCluster:
    """Fresh local PostgreSQL with explicit connection settings and owned teardown.

    Construction allocates a new mode-0700 directory. ``start`` initializes it,
    starts the server and creates ``database``. The context manager does both,
    then stops the server on every normal/exceptional exit. Stop never deletes
    data. Use ``from_path`` to inspect or stop a cluster created by the CLI.
    """

    def __init__(
        self,
        *,
        database: str = "hobnail_test",
        bin_dir: str | Path | None = None,
        base_dir: str | Path = "/tmp",
        root: str | Path | None = None,
        socket_name: str = "sock",
    ) -> None:
        if socket_name not in {"sock", "socket"}:
            raise ValueError("unsupported owned socket directory name")
        self.database = _identifier(database)
        self.bin_dir = _bindir(bin_dir)
        if root is None:
            self.root = Path(tempfile.mkdtemp(prefix="hbn-", dir=base_dir)).resolve()
        else:
            supplied = Path(root).absolute()
            if supplied.parent.resolve(strict=True) != supplied.parent:
                raise ClusterError("explicit cluster parent must be canonical")
            parent_info = supplied.parent.stat()
            if parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) & 0o022:
                raise ClusterError("explicit cluster parent must be owned and not writable by others")
            # Exclusive creation never adopts or replaces preexisting state.
            supplied.mkdir(mode=0o700, exist_ok=False)
            self.root = supplied.resolve(strict=True)
        os.chmod(self.root, 0o700)
        self.data_dir = self.root / "data"
        self.socket_dir = self.root / socket_name
        self.port = 5432  # Each cluster has a separate socket directory; TCP is off.
        if len(os.fsencode(self.socket_dir / f".s.PGSQL.{self.port}")) >= 100:
            raise ClusterError(f"socket path is too long; choose a shorter base directory: {self.root}")
        self.socket_dir.mkdir(mode=0o700)
        self._marker: dict[str, Any] = {
            "format": FORMAT,
            "token": uuid.uuid4().hex,
            "uid": os.getuid(),
            "root": str(self.root),
            "database": self.database,
            "pid": None,
            "started_at": None,
            "initialized": False,
            "database_created": False,
            "socket_name": socket_name,
        }
        with (self.root / MARKER).open("x", encoding="utf-8") as handle:
            os.chmod(handle.name, 0o600)
            json.dump(self._marker, handle, sort_keys=True)

    @classmethod
    def from_path(cls, root: str | Path, *, bin_dir: str | Path | None = None) -> DevCluster:
        """Open only an existing marked directory; never adopt an arbitrary PGDATA."""
        supplied = Path(root).absolute()
        if supplied.is_symlink():
            raise ClusterError("refusing a symlink as a cluster root")
        self = cls.__new__(cls)
        self.root = supplied.resolve()
        self.data_dir = self.root / "data"
        self.socket_dir = self.root / "sock"
        self.port = 5432
        self.bin_dir = _bindir(bin_dir)
        self._marker = self._read_marker()
        self.socket_dir = self.root / self._marker.get("socket_name", "sock")
        self.database = _identifier(self._marker["database"])
        return self

    def _read_marker(self) -> dict[str, Any]:
        try:
            root_info = self.root.lstat()
            marker_path = self.root / MARKER
            marker_info = marker_path.lstat()
            if (
                not stat.S_ISDIR(root_info.st_mode)
                or root_info.st_uid != os.getuid()
                or stat.S_IMODE(root_info.st_mode) != 0o700
                or not stat.S_ISREG(marker_info.st_mode)
                or marker_info.st_uid != os.getuid()
                or stat.S_IMODE(marker_info.st_mode) != 0o600
                or marker_info.st_size > 16384
            ):
                raise ValueError("ownership or permissions differ")
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            if not isinstance(marker, dict):
                raise ValueError("ownership marker must be an object")
            if (
                marker.get("format") != FORMAT
                or marker.get("uid") != os.getuid()
                or marker.get("root") != str(self.root)
                or not re.fullmatch(r"[0-9a-f]{32}", marker.get("token", ""))
            ):
                raise ValueError("invalid ownership marker")
            _identifier(marker["database"])
            socket_name = marker.get("socket_name", "sock")
            if socket_name not in {"sock", "socket"}:
                raise ValueError("invalid owned socket directory")
            for directory in (self.data_dir, self.root / socket_name):
                if directory.exists() or directory.is_symlink():
                    info = directory.lstat()
                    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                        raise ValueError("cluster subdirectory ownership differs")
            return marker
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise ClusterError(f"refusing unowned cluster {self.root}: {error}") from error

    def _check_owner(self) -> None:
        current = self._read_marker()
        if (current["token"] != self._marker["token"]
                or current.get("socket_name", "sock") != self.socket_dir.name):
            raise ClusterError(f"ownership marker changed: {self.root}")
        self._marker = current

    def _save_marker(self) -> None:
        # The temporary file and replacement both belong to this fresh cluster.
        descriptor, name = tempfile.mkstemp(prefix=".marker-", dir=self.root)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(self._marker, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, self.root / MARKER)

    def _environment(self) -> dict[str, str]:
        environment = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
        environment.update({
            "PGPASSFILE": os.devnull,
            "PGSERVICEFILE": os.devnull,
            "PGSYSCONFDIR": str(self.root / "no-system-pg-config"),
            "PGCONNECT_TIMEOUT": "5",
            "PSQL_PAGER": "",
            "LC_ALL": "C",
        })
        return environment

    def _run(
        self,
        executable: str,
        arguments: list[str],
        *,
        sql: str | None = None,
        check: bool = True,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [str(self.bin_dir / executable), *arguments],
            input=sql,
            capture_output=True,
            text=True,
            env=self._environment(),
            timeout=timeout,
            check=False,
        )
        if check and result.returncode:
            raise ClusterError(
                f"{executable} failed ({result.returncode}); cluster/logs retained at {self.root}\n"
                f"{result.stderr[-4000:]}"
            )
        return result

    def _runtime(self) -> tuple[int, str] | None:
        """Prove a PID belongs to this exact data directory before signaling it."""
        self._check_owner()
        pidfile = self.data_dir / "postmaster.pid"
        if not pidfile.exists():
            return None
        if pidfile.is_symlink() or not pidfile.is_file():
            raise ClusterError("refusing a non-regular postmaster.pid")
        try:
            lines = pidfile.read_text(encoding="utf-8").splitlines()
            pid, started = int(lines[0]), lines[2]
            if (
                pid <= 1
                or Path(lines[1]).resolve() != self.data_dir
                or int(lines[3]) != self.port
                or Path(lines[4]).resolve() != self.socket_dir
                or (self._marker.get("pid") is not None and self._marker["pid"] != pid)
                or (self._marker.get("started_at") is not None and self._marker["started_at"] != started)
            ):
                raise ValueError("postmaster identity differs from owned cluster")
        except (ValueError, IndexError) as error:
            raise ClusterError(f"refusing to signal cluster with unexpected pidfile: {self.root}") from error
        process = subprocess.run(
            ["ps", "-p", str(pid), "-o", "uid=", "-o", "command="],
            capture_output=True, text=True, check=False,
        )
        if process.returncode:
            raise ClusterError(f"stale pidfile retained for diagnosis: {self.root}")
        uid, separator, command = process.stdout.strip().partition(" ")
        if (
            not separator
            or uid != str(os.getuid())
            or not command.strip().startswith(str(self.bin_dir / "postgres") + " ")
            or f" -D {self.data_dir} " not in f" {command.strip()} "
        ):
            raise ClusterError(f"refusing to signal a process outside this owned cluster: {self.root}")
        return pid, started

    def start(self) -> DevCluster:
        self._check_owner()
        if self.is_running():
            self._ensure_database()
            return self
        self._marker["pid"] = None
        self._marker["started_at"] = None
        self._save_marker()
        if not self._marker["initialized"]:
            if self.data_dir.exists():
                raise ClusterError(f"initialization was incomplete; retained for diagnosis: {self.root}")
            result = self._run("initdb", [
                "-D", str(self.data_dir), "--username=postgres", "--encoding=UTF8",
                "--locale=C", "--auth-local=trust", "--auth-host=reject", "--no-instructions",
            ], check=False)
            (self.root / "initdb.log").write_text(result.stdout + result.stderr, encoding="utf-8")
            if result.returncode:
                raise ClusterError(f"initdb failed; retained logs: {self.root / 'initdb.log'}")
            self._marker["initialized"] = True
            self._save_marker()
        options = shlex.join([
            "-h", "", "-k", str(self.socket_dir), "-p", str(self.port),
            "-c", "unix_socket_permissions=0700", "-c", "max_connections=30",
            "-c", "shared_buffers=16MB",
        ])
        result = self._run("pg_ctl", [
            "-D", str(self.data_dir), "-l", str(self.root / "server.log"),
            "-o", options, "-w", "-t", "20", "start",
        ], check=False)
        (self.root / "pg_ctl-start.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        if result.returncode:
            raise ClusterError(f"PostgreSQL start failed; retained logs: {self.root}")
        runtime = self._runtime()
        if runtime is None:
            raise ClusterError(f"PostgreSQL returned success without an owned runtime: {self.root}")
        self._marker["pid"], self._marker["started_at"] = runtime
        self._save_marker()
        self._ensure_database()
        return self

    def _ensure_database(self) -> None:
        if not self._marker["database_created"]:
            exists = self.psql(
                f"SELECT EXISTS (SELECT FROM pg_database WHERE datname = '{self.database}')",
                database="postgres",
            ).stdout.strip()
            if exists != "t":
                self.create_database(self.database)
            self._marker["database_created"] = True
            self._save_marker()

    def is_running(self) -> bool:
        return self._runtime() is not None

    def status(self) -> dict[str, Any]:
        runtime = self._runtime()
        return {
            "root": str(self.root), "socket_dir": str(self.socket_dir),
            "port": self.port, "database": self.database, "user": "postgres",
            "running": runtime is not None, "pid": runtime[0] if runtime else None,
            "authentication": "private socket trust; database identity probes only, no OS isolation",
            "logs_retained": True,
        }

    def stop(self) -> bool:
        if self._runtime() is None:
            return False
        result = self._run("pg_ctl", [
            "-D", str(self.data_dir), "-m", "fast", "-w", "-t", "20", "stop",
        ], check=False)
        (self.root / "pg_ctl-stop.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        if result.returncode:
            raise ClusterError(f"PostgreSQL stop failed; retained logs: {self.root}")
        self._marker["pid"] = None
        self._marker["started_at"] = None
        self._save_marker()
        if (self.data_dir / "postmaster.pid").exists():
            raise ClusterError(f"pidfile remains after stop: {self.root}")
        return True

    def psql(
        self,
        sql: str,
        *,
        user: str = "postgres",
        database: str | None = None,
        check: bool = True,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        if not self.is_running():
            raise ClusterError(f"cluster is not running: {self.root}")
        return self._run("psql", self._psql_arguments(user, database), sql=sql, check=check, timeout=timeout)

    def _psql_arguments(self, user: str, database: str | None) -> list[str]:
        return [
            "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
            "-h", str(self.socket_dir), "-p", str(self.port),
            "-U", _identifier(user), "-d", _identifier(database or self.database),
        ]

    def psql_file(
        self,
        path: str | Path,
        *,
        user: str = "postgres",
        database: str | None = None,
        check: bool = True,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        if not self.is_running():
            raise ClusterError(f"cluster is not running: {self.root}")
        return self._run("psql", [
            *self._psql_arguments(user, database), "-f", str(Path(path).resolve()),
        ], check=check, timeout=timeout)

    def create_database(self, name: str) -> None:
        self.psql(f'CREATE DATABASE "{_identifier(name)}"', database="postgres")

    def __enter__(self) -> DevCluster:
        try:
            return self.start()
        except BaseException as error:
            self._cleanup_after_failure(error)
            raise

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc is None:
            self.stop()
        else:
            self._cleanup_after_failure(exc)

    def _cleanup_after_failure(self, original: BaseException) -> None:
        try:
            self.stop()
        except (ClusterError, OSError, subprocess.TimeoutExpired) as cleanup_error:
            original.add_note(f"Cluster cleanup also failed; logs retained at {self.root}: {cleanup_error}")


def _tree_bytes(root: Path) -> int:
    total = 0
    for directory, _subdirectories, files in os.walk(root, followlinks=False):
        for name in files:
            try:
                total += (Path(directory) / name).lstat().st_size
            except OSError:
                pass
    return total


PRUNE_DEFAULT_HOURS = 24.0
PRUNE_MINIMUM_HOURS = 1.0


def prune(base_dir: str | Path = "/tmp", *, older_than_hours: float = PRUNE_DEFAULT_HOURS, delete: bool = False,
          data_only: bool = False, force: bool = False, now: float | None = None) -> list[dict[str, Any]]:
    """List, and with ``delete`` remove, stopped roots this user's DevCluster created.

    Only direct ``hbn-*`` children of ``base_dir`` with a valid ownership marker
    for the current user are candidates. A root with a postmaster.pid, a recorded
    running pid, an unfinished initialization or a start within the last hour is
    never touched, and no PostgreSQL binary is needed. A root may still be in use
    shortly after its server stops (a demo writes evidence then), so an age floor
    below one hour requires ``force``.
    """
    if older_than_hours < PRUNE_MINIMUM_HOURS and not force:
        raise ClusterError(f"--older-than-hours below {PRUNE_MINIMUM_HOURS:g} can remove a root that is still in use; add --force")
    base = Path(base_dir).resolve(strict=True)
    if not shutil.rmtree.avoids_symlink_attacks:
        raise ClusterError("this platform's rmtree is not symlink-safe; refusing to prune")
    now = time.time() if now is None else now
    results: list[dict[str, Any]] = []
    for root in sorted(base.iterdir()):
        if not root.name.startswith("hbn-") or root.is_symlink() or not root.is_dir():
            continue
        entry: dict[str, Any] = {"root": str(root)}
        results.append(entry)
        probe = DevCluster.__new__(DevCluster)
        probe.root, probe.data_dir = root, root / "data"
        try:
            marker = probe._read_marker()
        except ClusterError:
            entry.update(action="skipped", reason="no valid ownership marker for this user")
            continue
        if marker.get("pid") is not None or (probe.data_dir / "postmaster.pid").exists() \
                or (probe.data_dir / "postmaster.pid").is_symlink():
            entry.update(action="skipped", reason="running or not cleanly stopped; use: dev_cluster.py stop ROOT")
            continue
        if marker.get("initialized") is not True:
            entry.update(action="skipped", reason="initialization not recorded as finished")
            continue
        started = marker.get("started_at")
        try:
            recently_started = started is not None and now - float(started) < 3600
        except (TypeError, ValueError):
            recently_started = True  # unreadable start time: treat as possibly in use
        if recently_started:
            entry.update(action="skipped", reason="started within the last hour")
            continue
        age_hours = (now - max(root.lstat().st_mtime, (root / MARKER).lstat().st_mtime)) / 3600
        target = probe.data_dir if data_only else root
        entry.update(bytes=_tree_bytes(root), age_hours=round(age_hours, 2),
                      reclaim_bytes=_tree_bytes(target) if target.exists() else 0)
        if age_hours < older_than_hours:
            entry.update(action="skipped", reason=f"newer than {older_than_hours:g} hours")
            continue
        if data_only and not target.exists():
            entry.update(action="skipped", reason="no database files left")
            continue
        if not delete:
            entry["action"] = "would_delete_data" if data_only else "would_delete"
            continue
        try:
            probe._read_marker()  # re-check ownership immediately before removal
            if (probe.data_dir / "postmaster.pid").exists():
                raise ClusterError("started while pruning")
            shutil.rmtree(target)
            entry["action"] = "deleted_data" if data_only else "deleted"
        except (ClusterError, OSError) as error:
            entry.update(action="failed", reason=type(error).__name__)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="create and leave running a fresh private cluster")
    create.add_argument("--database", default="hobnail_test")
    create.add_argument("--bin-dir")
    for command in ("status", "stop"):
        subcommand = commands.add_parser(command)
        subcommand.add_argument("root")
        subcommand.add_argument("--bin-dir")
    pruner = commands.add_parser("prune", help="list (default) or --delete stopped owned hbn-* roots")
    pruner.add_argument("--base-dir", default="/tmp")
    pruner.add_argument("--older-than-hours", type=float, default=PRUNE_DEFAULT_HOURS,
                        help=f"only roots untouched for this long (default {PRUNE_DEFAULT_HOURS:g}; below "
                             f"{PRUNE_MINIMUM_HOURS:g} needs --force)")
    pruner.add_argument("--force", action="store_true", help="allow an age floor below one hour")
    pruner.add_argument("--data-only", action="store_true",
                        help="remove only each root's data/ directory; keep evidence, logs and outputs")
    pruner.add_argument("--delete", action="store_true", help="actually remove; without it nothing changes")
    arguments = parser.parse_args(argv)
    if arguments.command == "prune":
        try:
            entries = prune(arguments.base_dir, older_than_hours=arguments.older_than_hours,
                            delete=arguments.delete, data_only=arguments.data_only, force=arguments.force)
        except (ClusterError, OSError) as error:
            print(json.dumps({"error": str(error)}))
            return 1
        selected = [e for e in entries if e["action"] not in {"skipped"}]
        print(json.dumps({"base_dir": str(Path(arguments.base_dir).resolve()), "dry_run": not arguments.delete,
                          "data_only": arguments.data_only, "roots": entries,
                          "older_than_hours": arguments.older_than_hours,
                          "selected_bytes": sum(e.get("reclaim_bytes", 0) for e in selected)}, indent=2, sort_keys=True))
        return 1 if any(e["action"] == "failed" for e in entries) else 0
    cluster: DevCluster | None = None
    try:
        if arguments.command == "create":
            cluster = DevCluster(database=arguments.database, bin_dir=arguments.bin_dir)
            cluster.start()
        else:
            cluster = DevCluster.from_path(arguments.root, bin_dir=arguments.bin_dir)
            if arguments.command == "stop":
                cluster.stop()
        print(json.dumps(cluster.status(), sort_keys=True))
        return 0
    except (ClusterError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        if arguments.command == "create" and cluster is not None:
            try:
                cluster.stop()
            except ClusterError as cleanup_error:
                print(json.dumps({"cleanup_error": str(cleanup_error), "root": str(cluster.root)}))
        print(json.dumps({"error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
