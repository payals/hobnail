"""Confinement for reviewed service controllers with separately supplied authority.

Each policy is trusted supervisor configuration, never candidate data. Services
may spawn only the listed reviewed executables, while retaining their sandbox.
The supervisor launches candidate parsers separately with isolation.py's stricter
policy; this module makes no nested-sandbox assumption or containment claim.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import platform
import re
import stat
import subprocess

from .isolation import ChildResult, IsolationUnavailable, _bounded_child, _runtime


@dataclass(frozen=True)
class ServicePolicy:
    role: str
    script: Path
    config: Path
    scratch: Path
    socket_path: Path
    read_paths: tuple[Path, ...] = ()
    write_roots: tuple[Path, ...] = ()
    executables: tuple[Path, ...] = ()
    metadata_paths: tuple[Path, ...] = ()


def _canonical(value, *, kind):
    path = Path(value).absolute()
    try:
        if path.resolve(strict=True) != path:
            raise IsolationUnavailable("service policy paths must be canonical without symlink aliases")
        info = path.lstat()
    except OSError:
        raise IsolationUnavailable("service policy path is unavailable") from None
    match = {"file": stat.S_ISREG, "directory": stat.S_ISDIR, "socket": stat.S_ISSOCK,
             "read": lambda mode: stat.S_ISDIR(mode) or stat.S_ISREG(mode)}[kind]
    if not match(info.st_mode):
        raise IsolationUnavailable("service policy path has the wrong type")
    if kind != "socket" and (info.st_uid not in {os.geteuid(), 0} or info.st_mode & 0o022):
        raise IsolationUnavailable("service policy path must be protected from other users' writes")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise IsolationUnavailable("service policy files cannot have hard-link aliases")
    return path


def _library_aliases(reference):
    """Retain every exact existing symlink spelling traversed by the loader."""
    current = Path(reference)
    aliases = set()
    for _ in range(64):
        if current in aliases:
            raise IsolationUnavailable("service library alias cycle")
        aliases.add(current)
        prefixes = list(reversed(current.parents)) + [current]
        for prefix in prefixes:
            if prefix.is_symlink():
                target = prefix.readlink()
                expanded = target if target.is_absolute() else prefix.parent / target
                current = Path(os.path.normpath(expanded / current.relative_to(prefix)))
                break
        else:
            return aliases
    raise IsolationUnavailable("service library alias chain exceeds the supported bound")


def _dependencies(executables):
    """Resolve existing binary dependencies in the trusted supervisor only."""
    pending = list(executables)
    visited = set()
    libraries = set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        try:
            result = subprocess.run(["/usr/bin/otool", "-L", str(path)], capture_output=True,
                                    text=True, check=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            raise IsolationUnavailable("reviewed service executable dependencies are unavailable") from None
        if len(result.stdout) > 65536 or len(visited) > 128:
            raise IsolationUnavailable("service dependency graph exceeds the supported bound")
        for line in result.stdout.splitlines()[1:]:
            dependency = line.strip().split(" (", 1)[0]
            if dependency.startswith(("/System/Library/", "/usr/lib/")):
                continue
            if not dependency.startswith("/"):
                raise IsolationUnavailable("service dependency uses an unresolved relative library path")
            try:
                resolved = Path(dependency).resolve(strict=True)
            except OSError:
                raise IsolationUnavailable("service dependency is unavailable") from None
            resolved = _canonical(resolved, kind="file")
            # dyld may check the original install-name alias before resolving
            # it. Both refer to this reviewed file; neither is a directory grant.
            libraries.update(_library_aliases(dependency))
            libraries.add(resolved)
            pending.append(resolved)
    return libraries


def _literal(path):
    # Policy paths are already canonical, except exact reviewed Mach-O install
    # names retained for dyld's required alias traversal.
    return json.dumps(str(path))


def service_profile(policy: ServicePolicy) -> str:
    """Generate a default-deny profile for exact reviewed role capabilities.

    Directory read grants are recursive. The supervisor must supply only code
    or approved destination directories there, never a shared credential root.
    Per-role credential/config files must be supplied solely as ``config``.
    """
    if not isinstance(policy, ServicePolicy) or not isinstance(policy.role, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", policy.role):
        raise IsolationUnavailable("invalid service role policy")
    if any(not isinstance(value, tuple) for value in (policy.read_paths, policy.write_roots, policy.executables, policy.metadata_paths)):
        raise IsolationUnavailable("service capability sets must be immutable tuples")
    script = _canonical(policy.script, kind="file")
    config = _canonical(policy.config, kind="file")
    scratch = _canonical(policy.scratch, kind="directory")
    endpoint = _canonical(policy.socket_path, kind="socket")
    if stat.S_IMODE(scratch.stat().st_mode) != 0o700 or scratch.stat().st_uid != os.geteuid():
        raise IsolationUnavailable("service scratch must be owned and mode 0700")
    if config.stat().st_mode & 0o077:
        raise IsolationUnavailable("service configuration must be private to its owner")
    reads = tuple(_canonical(path, kind="read") for path in policy.read_paths)
    writes = tuple(_canonical(path, kind="directory") for path in policy.write_roots)
    executable, runtime, python_libraries = _runtime()
    commands = {executable}
    for path in policy.executables:
        command = _canonical(path, kind="file")
        if not os.access(command, os.X_OK):
            raise IsolationUnavailable("service executable is not executable")
        commands.add(command)
    for root in (scratch, *writes):
        if config.is_relative_to(root) or script.is_relative_to(root) or endpoint.is_relative_to(root):
            raise IsolationUnavailable("service writable directories cannot contain configuration, code or database socket")
        if runtime.is_relative_to(root) or any(command.is_relative_to(root) for command in commands):
            raise IsolationUnavailable("service writable directories cannot contain runtime executables")
        if root in (Path("/"), Path("/tmp"), Path("/private/tmp"), Path("/var"), Path("/private/var")):
            raise IsolationUnavailable("shared write roots are unsupported")
    metadata = set()
    if len(policy.metadata_paths) > 32:
        raise IsolationUnavailable("too many exact metadata paths")
    for value in policy.metadata_paths:
        path = Path(value).absolute()
        # Existing and absent installed configuration names may be checked for
        # presence. This never grants data reads or directory traversal writes.
        metadata.update(_library_aliases(path))
    libraries = set(python_libraries) | _dependencies(commands - {executable})
    for root in (scratch, *writes):
        if any(path.is_relative_to(root) for path in (*reads, *libraries)):
            raise IsolationUnavailable("service writable directories cannot contain approved read-only code or libraries")
    ancestors = set()
    for path in (script, config, scratch, endpoint, runtime, *reads, *writes, *commands, *libraries, *metadata):
        ancestors.update(path.parents)
    rules = [
        "(version 1)", "(deny default)", "(deny process-info* mach-task*)",
        "(allow process-fork)",
        "(allow process-exec " + " ".join(f"(literal {_literal(path)})" for path in sorted(commands)) + ")",
        '(allow sysctl-read (sysctl-name "kern.ostype") (sysctl-name "kern.osrelease") '
        '(sysctl-name "kern.version") (sysctl-name "hw.machine") '
        '(sysctl-name "kern.hostname") (sysctl-name "kern.osversion") (sysctl-name "hw.model"))',
        '(allow file-read* (literal "/"))',
        '(allow file-read* (subpath "/System/Library") (subpath "/usr/lib"))',
        f"(allow file-read* (subpath {_literal(runtime)}))",
        *[f"(allow file-read* (literal {_literal(path)}))" for path in sorted({script, config, endpoint, *commands, *libraries})],
        *[f"(allow file-read* ({'subpath' if path.is_dir() else 'literal'} {_literal(path)}))" for path in reads],
        *[f"(allow file-read* file-write* (subpath {_literal(path)}))" for path in (scratch, *writes)],
        '(allow file-read* file-write* (literal "/dev/null"))',
        f"(allow network-outbound (remote unix-socket (path-literal {_literal(endpoint)})))",
        *[f"(allow file-read-metadata (literal {_literal(path)}))" for path in sorted(ancestors | metadata)],
    ]
    return "\n".join(rules)


def run_service(policy: ServicePolicy, payload: str, *, timeout: float = 30) -> ChildResult:
    """Run SCRIPT CONFIG with stdin data and bounded output, retaining failures.

    argv[1] inside the script is the exact own configuration path. No secret is
    placed in argv or inherited environment. Profiles apply to spawned psql and
    Python children as well; all socket-accessible database roles must require
    real authentication before the supervisor launches the first service.
    """
    if platform.system() != "Darwin" or not Path("/usr/bin/sandbox-exec").is_file():
        raise IsolationUnavailable("macOS service isolation is unavailable")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("service timeout must be within (0, 60]")
    if not isinstance(payload, str):
        raise ValueError("service payload must be UTF-8 text")
    encoded = payload.encode("utf-8")
    if len(encoded) > 36_000_000:
        raise ValueError("service payload exceeds the 36 MB input limit")
    profile = service_profile(policy)
    executable, _, _ = _runtime()
    args = ["/usr/bin/sandbox-exec", "-p", profile, str(executable), "-I", "-S", "-B",
            str(Path(policy.script).absolute()), str(Path(policy.config).absolute())]
    return _bounded_child(args, encoded, directory=str(Path(policy.scratch).absolute()), timeout=timeout,
                          stdout_limit=36_000_000, stderr_limit=32768)
