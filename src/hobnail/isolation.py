"""Explicit restricted child execution. Unsupported platforms fail closed.

This backend is for bounded data validators, not a general hostile-code sandbox.
Qualification probes establish only the tested file/network denial properties.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time


class IsolationUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class ChildResult:
    returncode: int
    stdout: str
    stderr: str


def _literal(path):
    return json.dumps(str(Path(path).resolve()))


@lru_cache(maxsize=1)
def _runtime():
    """Resolve the existing interpreter and its hash extension's actual dylibs.

    Homebrew's bin/python launcher re-execs Python.app. Invoking the actual
    executable avoids permitting a general process launcher. No package or
    home configuration is consulted; otool reads the already-installed binary.
    """
    base = Path(sys.base_prefix).resolve()
    framework = base / "Resources/Python.app/Contents/MacOS/Python"
    executable = framework if framework.is_file() else Path(sys.executable).resolve()
    if base in (Path("/"), Path("/usr"), Path("/usr/local"), Path("/opt/homebrew")):
        raise IsolationUnavailable("interpreter runtime does not have a narrow installation root")
    extension = importlib.util.find_spec("_hashlib")
    if extension is None or extension.origin is None:
        raise IsolationUnavailable("the installed hash extension cannot be identified")
    pending = [executable, Path(extension.origin).resolve()]
    inspected = set()
    libraries = set()
    while pending:
        binary = pending.pop()
        if binary in inspected:
            continue
        inspected.add(binary)
        try:
            result = subprocess.run(
                ["/usr/bin/otool", "-L", str(binary)], capture_output=True,
                text=True, check=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise IsolationUnavailable("installed interpreter dependencies cannot be inspected") from error
        for line in result.stdout.splitlines()[1:]:
            dependency = line.strip().split(" (", 1)[0]
            if dependency.startswith(("/usr/lib/", "/System/Library/")):
                continue
            if not dependency.startswith("/"):
                raise IsolationUnavailable("interpreter has an unresolved relative library dependency")
            try:
                path = Path(dependency).resolve(strict=True)
            except OSError as error:
                raise IsolationUnavailable("an installed interpreter dependency is unavailable") from error
            if not path.is_relative_to(base):
                libraries.add(path)
            pending.append(path)
    return executable, base, tuple(sorted(libraries))


def macos_profile(script, workspace):
    """Allow only interpreter/runtime reads and this child's scratch directory."""
    executable, runtime, libraries = _runtime()
    script, workspace = Path(script).resolve(), Path(workspace).resolve()
    ancestors = set()
    for path in (script, workspace, runtime, *libraries):
        ancestors.update(path.parents)
    return "\n".join([
        "(version 1)", "(deny default)",
        # Some informational operations are implicitly permitted by the
        # platform despite deny-default. Deny these families explicitly.
        "(deny process-info* mach-task*)",
        f"(allow process-exec (literal {_literal(executable)}))",
        # ctypes asks uname during initialization. Permit only these platform
        # values, never process arguments/environment via kern.procargs2.
        '(allow sysctl-read (sysctl-name "kern.ostype") (sysctl-name "kern.osrelease") '
        '(sysctl-name "kern.version") (sysctl-name "hw.machine") '
        '(sysctl-name "kern.hostname") (sysctl-name "kern.osversion") (sysctl-name "hw.model"))',
        # dyld/Python requires a read of the root directory itself. This does
        # not grant reads below it; a subpath '/' rule would expose credentials.
        '(allow file-read* (literal "/"))',
        "(allow file-read* (subpath \"/System/Library\") (subpath \"/usr/lib\"))",
        f"(allow file-read* (subpath {_literal(runtime)}))",
        *[f"(allow file-read* (literal {_literal(path)}))" for path in libraries],
        f"(allow file-read* (literal {_literal(script)}))",
        f"(allow file-read* file-write* (subpath {_literal(workspace)}))",
        "(allow file-read* file-write* (literal \"/dev/null\"))",
        *[f"(allow file-read-metadata (literal {_literal(path)}))" for path in sorted(ancestors)],
    ])


_OUTPUT_LIMIT = 32768
_INPUT_LIMIT = 36_000_000
_SCRIPT_LIMIT = 1_048_576


def _kill_owned_child(process):
    """Terminate only the session created for this child, then reap its leader."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _bounded_child(args, payload, *, directory, timeout, stdout_limit=_OUTPUT_LIMIT, stderr_limit=_OUTPUT_LIMIT):
    """Drain both output streams while stdin comes from an already-written file.

    communicate/capture_output can allocate unbounded memory before the caller
    sees a byte count. The selector loop retains at most the two configured
    limits and kills this child's process group as soon as either is exceeded.
    """
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    if any(type(limit) is not int or not 1 <= limit <= _INPUT_LIMIT for limit in limits.values()):
        raise ValueError("child output limits must be integers within the input bound")
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryFile(mode="w+b", dir=directory) as source:
        source.write(payload)
        source.seek(0)
        with subprocess.Popen(
            args, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=directory,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": directory},
            close_fds=True, start_new_session=True,
        ) as process:
            try:
                with selectors.DefaultSelector() as selector:
                    for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, name)
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired("restricted-validator", timeout)
                        for key, _ in selector.select(min(remaining, 0.25)):
                            available = limits[key.data] + 1 - len(outputs[key.data])
                            chunk = os.read(key.fileobj.fileno(), min(8192, available))
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            outputs[key.data].extend(chunk)
                            if len(outputs[key.data]) > limits[key.data]:
                                _kill_owned_child(process)
                                return ChildResult(process.returncode or 1, "", "output_limit")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired("restricted-validator", timeout)
                    process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                _kill_owned_child(process)
                raise subprocess.TimeoutExpired("restricted-validator", timeout) from None
            except BaseException:
                _kill_owned_child(process)
                raise
            try:
                return ChildResult(process.returncode, outputs["stdout"].decode("utf-8"),
                                   outputs["stderr"].decode("utf-8"))
            except UnicodeDecodeError:
                return ChildResult(1, "", "invalid_output_encoding")


def run_restricted(script, payload, *, timeout=10):
    """Execute a trusted script with bounded I/O and the existing sandbox policy.

    Configured developer plugins must use run_implementation, which additionally
    binds the approved digest to an immutable snapshot of the executed bytes.
    """
    if platform.system() != "Darwin" or not Path("/usr/bin/sandbox-exec").is_file():
        raise IsolationUnavailable("macOS sandbox-exec backend is unavailable")
    script = Path(script).resolve(strict=True)
    executable, _, _ = _runtime()
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
        raise ValueError("timeout must be within (0, 60]")
    if not isinstance(payload, str):
        raise ValueError("validator payload must be UTF-8 text")
    encoded = payload.encode("utf-8")
    if len(encoded) > _INPUT_LIMIT:
        raise ValueError("validator payload exceeds the 36 MB input limit")
    with tempfile.TemporaryDirectory(prefix="hobnail-validator-") as directory:
        os.chmod(directory, 0o700)
        args = ["/usr/bin/sandbox-exec", "-p", macos_profile(script, directory),
                str(executable), "-I", "-S", "-B", str(script)]
        return _bounded_child(args, encoded, directory=directory, timeout=timeout)


@contextmanager
def implementation_snapshot(script, expected_digest):
    """Yield precisely the approved immutable single-file implementation.

    The script comes from the protected controller registry, never a candidate
    path. No code is imported into the controller. This helper rejects aliases,
    nonregular/oversized files and sources writable by another user. Ownership
    checks are an additional guard, not proof of a qualified runtime boundary.
    """
    if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise IsolationUnavailable("implementation digest is invalid")
    source = Path(script).absolute()
    try:
        if source.resolve(strict=True) != source:
            raise IsolationUnavailable("implementation path must be canonical and not an alias")
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o022
                    or not 0 < before.st_size <= _SCRIPT_LIMIT):
                raise IsolationUnavailable("implementation source permissions or size are invalid")
            content = handle.read(_SCRIPT_LIMIT + 1)
            after = os.fstat(handle.fileno())
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if identity(before) != identity(after) or len(content) != before.st_size:
                raise IsolationUnavailable("implementation source changed while being read")
    except OSError:
        raise IsolationUnavailable("implementation source cannot be read safely") from None
    if hashlib.sha256(content).hexdigest() != expected_digest:
        raise IsolationUnavailable("implementation digest mismatch")
    with tempfile.TemporaryDirectory(prefix="hobnail-implementation-") as directory:
        os.chmod(directory, 0o700)
        snapshot = Path(directory) / "validator.py"
        descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        yield snapshot


def run_implementation(script, expected_digest, payload, *, timeout=10):
    """Use the default native backend with the shared source-custody checks."""
    with implementation_snapshot(script, expected_digest) as snapshot:
        return run_restricted(snapshot, payload, timeout=timeout)
