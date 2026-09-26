"""Clients for separately confined local role processes.

The supervisor and operator remain trusted. A role receives only its own
configuration capability; candidate parsers run separately under the stricter
data-validator profile. This module never creates OS accounts or discovers
existing credentials.
"""

from dataclasses import dataclass
import hashlib
import os
import re
from pathlib import Path
import subprocess

from .client import Client, ProtocolError, TransportError, canonical_json, parse_json, validate_envelope
from .service_isolation import ServicePolicy, run_service, service_profile
from .git_effects import GitBoundaryError, _Repository


@dataclass(frozen=True)
class NativeConsumer:
    """Exact supervisor-owned consumer capabilities; never request payload data."""
    plugin: str
    root: Path | None = None
    repositories: tuple[tuple[str, Path], ...] = ()
    executable: Path | None = None

    def __post_init__(self):
        if self.plugin not in {"file.publish", "research.promote", "git.commit"}:
            raise ValueError("unsupported native consumer")
        if self.plugin == "git.commit":
            if self.root is not None or not isinstance(self.repositories, tuple) or not 1 <= len(self.repositories) <= 16 or self.executable is None:
                raise ValueError("Git consumer requires immutable repository aliases and an explicit executable")
            names = []
            for entry in self.repositories:
                if not isinstance(entry, tuple) or len(entry) != 2:
                    raise ValueError("repository configuration must be alias/path pairs")
                alias, path = entry
                if (not isinstance(alias, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", alias)
                        or any(part in {"", ".", ".."} for part in alias.split("/"))):
                    raise ValueError("repository alias is invalid")
                names.append(alias)
                self._directory(path)
            if len(set(names)) != len(names):
                raise ValueError("duplicate repository aliases")
            command = Path(self.executable).absolute()
            if command.resolve(strict=True) != command or not command.is_file() or not os.access(command, os.X_OK):
                raise ValueError("Git executable must be an exact canonical existing executable")
        elif self.root is None or self.repositories or self.executable is not None:
            raise ValueError("file and research consumers require only an exact root")
        else:
            self._directory(self.root)

    @staticmethod
    def _directory(value):
        path = Path(value).absolute()
        if path.resolve(strict=True) != path or not path.is_dir():
            raise ValueError("consumer root must be an existing canonical directory")
        return path

    @classmethod
    def file(cls, root):
        return cls("file.publish", root=Path(root).absolute())

    @classmethod
    def research(cls, root):
        return cls("research.promote", root=Path(root).absolute())

    @classmethod
    def git(cls, repositories, *, executable):
        return cls("git.commit", repositories=tuple(sorted((name, Path(path).absolute()) for name, path in repositories.items())),
                   executable=Path(executable).absolute())

    @classmethod
    def from_document(cls, value):
        if not isinstance(value, dict):
            raise ValueError("consumer configuration must be an object")
        if value.get("plugin") == "git.commit":
            if set(value) != {"plugin", "repositories", "executable"} or not isinstance(value["repositories"], dict):
                raise ValueError("invalid Git consumer configuration fields")
            return cls.git(value["repositories"], executable=value["executable"])
        if set(value) != {"plugin", "root"}:
            raise ValueError("invalid native consumer configuration fields")
        return cls(value["plugin"], root=Path(value["root"]).absolute())

    def document(self):
        if self.plugin == "git.commit":
            return {"plugin": self.plugin, "repositories": {name: str(Path(path).absolute()) for name, path in self.repositories},
                    "executable": str(Path(self.executable).absolute())}
        return {"plugin": self.plugin, "root": str(Path(self.root).absolute())}

    @property
    def roots(self):
        return tuple(Path(path).absolute() for _, path in self.repositories) if self.plugin == "git.commit" else (Path(self.root).absolute(),)


_COMMAND_PREFIX = {"file.publish": "file", "git.commit": "git", "research.promote": "research"}


def _review_git_controls(consumer, *, extra_paths=()):
    """Inspect effective ambient controls in the trusted supervisor first.

    The service's intentionally clean environment must never conceal a global
    hook, filter, signing configuration or default attributes that affect the
    selected repositories. No global configuration is modified or granted to a
    role; unsupported effective controls refuse before its consumer can run.
    """
    if consumer is None or consumer.plugin != "git.commit":
        return ()
    metadata = set()
    for alias, directory in consumer.repositories:
        repository = _Repository(directory, executable=consumer.executable)
        repository.policy()
        paths = set(repository.tree("HEAD")) | set(extra_paths)
        if repository._run(["check-attr", "-z", "--all", "--stdin"],
                           source=b"".join(path.encode("utf-8") + b"\x00" for path in sorted(paths))):
            raise GitBoundaryError("effective attributes require another qualified native adapter")
        system_config = repository._run(["var", "GIT_CONFIG_SYSTEM"]).decode("utf-8").strip()
        if not system_config or "\n" in system_config or not Path(system_config).is_absolute():
            raise GitBoundaryError("Git system configuration path cannot be established")
        metadata.add(Path(system_config))
    # Apple's installed Git additionally probes its packaged system config.
    # endpoint() read-grants existing exact system files after this policy
    # inspection; absent filenames receive only metadata access.
    command = Path(consumer.executable)
    metadata.add(command.parent.parent / "share" / "git-core" / "gitconfig")
    return tuple(sorted(metadata))


class RoleEndpoint:
    def __init__(self, policy: ServicePolicy, *, consumer: NativeConsumer | None = None):
        self.policy = policy
        self.consumer = consumer

    def request(self, command, *, timeout=30):
        if isinstance(command, dict) and command.get("command") in {"git.dispatch", "git.observe"}:
            refused = self._review_effect_paths(command.get("effect_id"))
            if refused is not None:
                return refused
        try:
            child = run_service(self.policy, canonical_json(command), timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TransportError("role process timed out; reconcile its operation before retrying") from None
        if child.returncode:
            raise TransportError("role process failed; no authoritative response was received")
        try:
            result = parse_json(child.stdout)
        except (ValueError, TypeError, RecursionError):
            raise ProtocolError("role process returned an invalid response") from None
        if not isinstance(result, dict):
            raise ProtocolError("role process response must be an object")
        if "service_error" in result:
            raise TransportError("role process reported " + str(result["service_error"]))
        return result

    def call(self, operation, payload):
        return validate_envelope(self.request({"command": "api", "operation": operation, "payload": payload}))

    def client(self):
        return Client(self)

    def _review_effect_paths(self, effect_id):
        if self.consumer is None or self.consumer.plugin != "git.commit":
            return None
        response = self.call("effect.get", {"effect_id": effect_id})
        if not response["ok"]:
            return response
        action = response["data"]["action"]
        if action["plugin"] != "git.commit":
            raise GitBoundaryError("effect is not approved for the configured Git consumer")
        if action["target"] not in dict(self.consumer.repositories):
            raise GitBoundaryError("effect repository alias is not configured")
        _review_git_controls(self.consumer, extra_paths=action["arguments"]["paths"])
        return None

    def dispatch(self, effect_id):
        prefix = _COMMAND_PREFIX[self.consumer.plugin] if self.consumer is not None else "file"
        return validate_envelope(self.request({"command": prefix + ".dispatch", "effect_id": effect_id}))

    def observe(self, effect_id):
        prefix = _COMMAND_PREFIX[self.consumer.plugin] if self.consumer is not None else "file"
        return validate_envelope(self.request({"command": prefix + ".observe", "effect_id": effect_id}))

    def configuration_fingerprint(self):
        """Historical code/profile fingerprint, not a reusable deployment seal.

        No credential hash is exported. Nonsecret connection configuration,
        binary bytes, database state and validity are not all bound here; a
        matching value never substitutes for actual deployment qualification.
        """
        package = self.policy.script.parent
        files = sorted(package.rglob("*.py"))
        source = {path.relative_to(package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
        value = {"role": self.policy.role, "profile": service_profile(self.policy), "code": source}
        return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def endpoint(role, *, config, scratch, socket_path, destination=None, permission="none", psql,
             package_root=None, consumer: NativeConsumer | None = None):
    """Construct an exact consumer capability with independent role permissions.

    For new configurations, serialize ``consumer.document()`` as the private
    config's ``consumer`` field and supply the same object here. Existing file
    deployments using ``destination`` remain supported. Destination roots and
    Git executable paths never come from the operation request.
    """
    required = {"adapter": "write", "observer": "read", "worker": "none", "verifier": "none",
                "registrar": "none", "approver": "none", "auditor": "none", "credential_provider": "none"}
    if role not in required or permission not in {"none", "read", "write"}:
        raise ValueError("unsupported role or destination authority")
    if consumer is not None:
        if not isinstance(consumer, NativeConsumer) or destination is not None or required[role] == "none":
            raise ValueError("consumer capabilities belong only to adapter/observer roles")
        if permission == "none":
            permission = required[role]
    elif destination is not None:
        consumer = NativeConsumer.file(destination)
    if permission != required[role] or (consumer is None) != (permission == "none"):
        raise ValueError("destination authority must match the role")
    package = Path(__file__).resolve().parent if package_root is None else Path(package_root).resolve(strict=True)
    reads = (package,)
    writes = ()
    commands = (Path(psql).resolve(strict=True),)
    if consumer is not None:
        if permission == "read":
            reads += consumer.roots
        elif permission == "write":
            writes = consumer.roots
        if consumer.plugin == "git.commit":
            commands += (Path(consumer.executable),)
    metadata = _review_git_controls(consumer)
    # Git's installed system configuration remains active. The trusted policy
    # inspection above has checked effective controls; grant only existing exact
    # system files, never a user-global directory or credential store.
    reads += tuple(path.resolve(strict=True) for path in metadata if path.is_file())
    policy = ServicePolicy(role=role, script=package / "_role_service.py",
        config=Path(config).absolute(), scratch=Path(scratch).absolute(),
        socket_path=Path(socket_path).absolute(), read_paths=reads, write_roots=writes,
        executables=commands, metadata_paths=metadata)
    return RoleEndpoint(policy, consumer=consumer)
