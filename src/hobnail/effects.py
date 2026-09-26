"""Exact-byte local publishing with distinct dispatch and observation controllers.

The configured root belongs to the protected adapter/observer deployment. A
worker with write access to it invalidates the exclusive-consumer guarantee.
"""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import uuid

from .verifier import checked_bytes


class EffectBoundaryError(RuntimeError):
    pass


def implementation_digest():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _parts(target):
    if not isinstance(target, str) or not target or "\\" in target or "\x00" in target:
        raise EffectBoundaryError("invalid target")
    path = PurePosixPath(target)
    if path.is_absolute() or any(part in {".", "..", ""} for part in target.split("/")):
        raise EffectBoundaryError("target must be a confined relative path")
    if len(target.encode()) > 1024:
        raise EffectBoundaryError("target too long")
    return path.parts


@contextmanager
def _parent(root, target, *, owner_uid=None):
    parts = _parts(target)
    root = Path(root).absolute()
    # Do not resolve a symlink and then silently declare the destination trusted.
    if root.is_symlink() or root.resolve() != root:
        raise EffectBoundaryError("adapter root must be a canonical directory")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    expected_owner = os.getuid() if owner_uid is None else owner_uid
    try:
        info = os.fstat(descriptor)
        if info.st_uid != expected_owner or info.st_mode & 0o022:
            raise EffectBoundaryError("adapter root must be owned and not writable by other users")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            info = os.fstat(child)
            if info.st_uid != expected_owner or info.st_mode & 0o022:
                os.close(child)
                raise EffectBoundaryError("target directory permissions violate adapter boundary")
            os.close(descriptor)
            descriptor = child
        yield descriptor, parts[-1]
    finally:
        os.close(descriptor)


class FilePublisher:
    plugin_id = "file.publish"

    def __init__(self, root, *, observer_group=None):
        self.root = Path(root).absolute()
        if observer_group is not None and (type(observer_group) is not int or observer_group < 0):
            raise ValueError("observer_group must be an explicit trusted group ID")
        self.observer_group = observer_group

    def publish(self, target, content, expected_digest):
        if not isinstance(content, bytes) or len(content) > 1_048_576:
            raise EffectBoundaryError("invalid artifact size")
        digest = hashlib.sha256(content).hexdigest()
        if digest != expected_digest:
            raise EffectBoundaryError("artifact digest mismatch")
        with _parent(self.root, target) as (directory, filename):
            try:
                existing = os.stat(filename, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
                    raise EffectBoundaryError("destination is not a private regular file")
            except FileNotFoundError:
                pass
            temporary = ".hobnail-" + uuid.uuid4().hex
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    if self.observer_group is not None:
                        os.fchown(stream.fileno(), -1, self.observer_group)
                        os.fchmod(stream.fileno(), 0o640)
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, filename, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                # This name was created exclusively by this invocation.
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
        return {"target": target, "artifact_digest": digest, "bytes": len(content)}


class FileObserver:
    def __init__(self, root, *, adapter_owner_uid=None):
        self.root = Path(root).absolute()
        if adapter_owner_uid is not None and (type(adapter_owner_uid) is not int or adapter_owner_uid < 0):
            raise ValueError("adapter_owner_uid must be an explicit trusted user ID")
        self.adapter_owner_uid = adapter_owner_uid

    def observe(self, target, expected_digest):
        try:
            with _parent(self.root, target, owner_uid=self.adapter_owner_uid) as (directory, filename):
                descriptor = os.open(filename, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                                     dir_fd=directory)
                with os.fdopen(descriptor, "rb") as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 1_048_576:
                        raise EffectBoundaryError("destination is not a bounded regular file")
                    content = stream.read(1_048_577)
                    after = os.fstat(stream.fileno())
                    current = os.stat(filename, dir_fd=directory, follow_symlinks=False)
                    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
                    if (identity(before) != identity(after) or identity(after) != identity(current)
                            or len(content) != before.st_size):
                        return {"outcome": "unknown", "artifact_digest": None,
                                "receipt": {"reason": "changed_during_observation"}}
        except FileNotFoundError:
            return {"outcome": "absent", "artifact_digest": None, "receipt": {"reason": "not_present"}}
        except (OSError, EffectBoundaryError):
            return {"outcome": "unknown", "artifact_digest": None, "receipt": {"reason": "boundary_refused"}}
        digest = hashlib.sha256(content).hexdigest()
        return {"outcome": "complete" if digest == expected_digest else "mismatch",
                "artifact_digest": digest, "receipt": {"target": target, "bytes": len(content)}}


def dispatch_file(client, effect_id, publisher, *, lease_seconds=60):
    response = client.call("effect.claim", {"effect_id": effect_id, "lease_seconds": lease_seconds})
    if not response["ok"]:
        return response
    claim = response["data"]
    content = checked_bytes(claim["artifact"])
    manifest = claim["action"].get("manifest", {})
    if (claim["action"]["plugin"] != publisher.plugin_id or claim["args"] != {}
            or manifest.get("implementation") != implementation_digest()
            or manifest.get("execution_backend") != "local-file"):
        raise EffectBoundaryError("unsupported approved action")
    _parts(claim["target"])
    fence = {"effect_id": effect_id, "token": claim["token"], "generation": claim["generation"]}
    dispatched = client.call("effect.dispatch", fence)
    if not dispatched["ok"]:
        return dispatched
    # A lost dispatch response raises from Client and never reaches this code.
    # A subsequent call must reconcile; the database forbids another dispatch.
    try:
        receipt = publisher.publish(claim["target"], content, claim["artifact"]["digest"])
    except (OSError, EffectBoundaryError):
        return client.call("effect.report", {**fence, "outcome": "uncertain",
                                             "receipt": {"reason": "consumer_failure"}})
    return client.call("effect.report", {**fence, "outcome": "attempted", "receipt": receipt})


def observe_file(client, effect_id, observer):
    response = client.call("effect.get", {"effect_id": effect_id})
    if not response["ok"]:
        return response
    effect = response["data"]
    if effect["action"]["plugin"] != "file.publish":
        raise EffectBoundaryError("unsupported observation adapter")
    observation = observer.observe(effect["action"]["target"], effect["artifact"]["digest"])
    return client.call("effect.observe", {"effect_id": effect_id, **observation})
