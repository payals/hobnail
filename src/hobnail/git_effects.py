"""Exact local Git integration for explicitly hook-free protected repositories.

Only configured aliases are destinations. This module never pushes, fetches,
sets an author, overrides a hook path, disables a hook, or resets another writer.
Its locks fence cooperating Git writers, not arbitrary editors with write access.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import uuid

from .client import canonical_json, parse_json
from .effects import EffectBoundaryError
from .verifier import checked_bytes


class GitBoundaryError(EffectBoundaryError):
    pass


def implementation_digest():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _unlink_owned(path, identity):
    try:
        info = path.lstat()
        if (info.st_dev, info.st_ino) == identity:
            path.unlink()
    except FileNotFoundError:
        pass


def _fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _oid(value):
    return isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is not None


def _path(value):
    if (not isinstance(value, str) or not 0 < len(value.encode("utf-8")) <= 1024
            or not re.fullmatch(r"[A-Za-z0-9_./-]+", value)):
        raise GitBoundaryError("unsupported repository path")
    parts = value.split("/")
    forbidden = {".git", ".gitignore", ".gitattributes", ".gitmodules", ".gitconfig",
                 ".githooks", ".husky", ".pre-commit-config.yaml"}
    if any(part in {"", ".", ".."} or part.lower() in forbidden for part in parts):
        raise GitBoundaryError("protected or unconfined repository path")
    return parts


def _no_case_aliases(paths):
    aliases = {}
    for path in paths:
        parts = path.split("/")
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            prior = aliases.setdefault(prefix.casefold(), prefix)
            if prior != prefix:
                raise GitBoundaryError("case aliases are unsupported")


def validate_action(arguments, content):
    if not isinstance(arguments, dict) or set(arguments) != {"branch", "base_commit", "paths", "message"}:
        raise GitBoundaryError("unsupported git.commit arguments")
    branch, message, paths = arguments["branch"], arguments["message"], arguments["paths"]
    if (not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,127}", branch)
            or not _oid(arguments["base_commit"])):
        raise GitBoundaryError("invalid branch or exact base commit")
    if (not isinstance(message, str) or not message.strip() or len(message.encode("utf-8")) > 2048
            or "\x00" in message or "\r" in message or message.endswith("\n")):
        raise GitBoundaryError("invalid exact commit message")
    if (not isinstance(paths, list) or not 1 <= len(paths) <= 64
            or any(not isinstance(path, str) for path in paths) or len(set(paths)) != len(paths)):
        raise GitBoundaryError("paths must be a bounded unique set")
    for path in paths:
        _path(path)
    _no_case_aliases(paths)
    if any(a != b and b.startswith(a + "/") for a in paths for b in paths):
        raise GitBoundaryError("file and directory targets overlap")
    if not isinstance(content, bytes) or not 0 < len(content) <= 1_048_576:
        raise GitBoundaryError("invalid artifact size")
    try:
        bundle = parse_json(content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise GitBoundaryError("artifact is not a strict JSON bundle") from None
    if not isinstance(bundle, dict) or set(bundle) != set(paths):
        raise GitBoundaryError("artifact paths differ from approved paths")
    if any(not isinstance(value, str) or len(value) % 2 or re.fullmatch(r"[0-9a-f]*", value) is None
           for value in bundle.values()):
        raise GitBoundaryError("artifact must map paths to exact lowercase content_hex")
    return {path: bytes.fromhex(bundle[path]) for path in paths}


@dataclass(frozen=True)
class _State:
    head: str
    tree: dict
    index: bytes
    identity: tuple


class _Repository:
    def __init__(self, root, *, owner_uid=None, executable=None):
        self.root = Path(root).absolute()
        self.owner_uid = os.getuid() if owner_uid is None else owner_uid
        executable = shutil.which("git") if executable is None else str(executable)
        if executable is None:
            raise GitBoundaryError("existing Git executable unavailable")
        command = Path(executable).absolute()
        if not command.is_file() or not os.access(command, os.X_OK):
            raise GitBoundaryError("configured Git executable is unavailable")
        self.executable = str(command.resolve())
        self.git_dir = self.root / ".git"

    def _directory(self, path):
        if path.resolve() != path:
            raise GitBoundaryError("repository aliases and symlinks are unsupported")
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner_uid or info.st_mode & 0o022:
            raise GitBoundaryError("repository directory is not protected")
        return info.st_dev, info.st_ino

    def _run(self, args, *, source=b"", index=None, allowed=(0,)):
        # Refuse injected Git configuration instead of quietly disabling it.
        # A pager is a display preference; --no-pager prevents executing it.
        # Every repository/identity/configuration override still refuses.
        if any(key.startswith("GIT_") and key != "GIT_PAGER" for key in os.environ):
            raise GitBoundaryError("ambient Git overrides are unsupported")
        env = {key: os.environ[key] for key in ("PATH", "HOME", "XDG_CONFIG_HOME", "SYSTEMROOT") if key in os.environ}
        env.update(LC_ALL="C", LANG="C", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
        if index is not None:
            env["GIT_INDEX_FILE"] = str(index)
        try:
            result = subprocess.run([self.executable, "--no-pager", "-C", str(self.root), *args],
                                    input=source, capture_output=True, timeout=15, env=env, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise GitBoundaryError("local Git operation failed or timed out") from None
        if result.returncode not in allowed or len(result.stdout) > 4_194_304 or len(result.stderr) > 65_536:
            raise GitBoundaryError("local Git operation refused: " + args[0])
        return result.stdout

    def policy(self):
        identity = (*self._directory(self.root), *self._directory(self.git_dir))
        count = 0
        def walk_error(error):
            raise error
        for directory, directories, files in os.walk(self.git_dir, followlinks=False, onerror=walk_error):
            for name in [*directories, *files]:
                item = Path(directory) / name
                info = item.lstat()
                count += 1
                if (count > 50000 or info.st_uid != self.owner_uid or info.st_mode & 0o022
                        or stat.S_ISLNK(info.st_mode)
                        or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                        or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                    raise GitBoundaryError("aliased or unprotected Git storage is unsupported")
        config = (self.git_dir / "config").lstat()
        if (not stat.S_ISREG(config.st_mode) or config.st_nlink != 1
                or config.st_uid != self.owner_uid or config.st_mode & 0o022):
            raise GitBoundaryError("repository configuration is not protected")
        for name in ("commondir", "config.worktree", "shallow", "info/grafts", "info/attributes",
                     "info/sparse-checkout", "objects/info/alternates", "objects/info/http-alternates"):
            path = self.git_dir / name
            if path.exists() or path.is_symlink():
                raise GitBoundaryError("unsupported Git layout or attributes")
        hooks = self.git_dir / "hooks"
        if hooks.exists() or hooks.is_symlink():
            self._directory(hooks)
            if any(path.is_symlink() or (not path.name.endswith(".sample") and path.is_file()
                                        and os.access(path, os.X_OK)) for path in hooks.iterdir()):
                raise GitBoundaryError("active Git hooks require a different qualified adapter")
        replacements = self.git_dir / "refs/replace"
        if replacements.exists() and any(replacements.iterdir()):
            raise GitBoundaryError("replacement objects are unsupported")
        names = self._run(["config", "--no-includes", "--name-only", "--list"]).decode("utf-8").splitlines()
        remote_urls = any(key.lower().startswith("remote.") and key.lower().endswith(".url") for key in names)
        forbidden = ("include.", "includeif.", "filter.", "extensions.", "gpg.", "diff.", "merge.",
                     "author.", "committer.", "i18n.", "index.")
        forbidden_keys = {"core.hookspath", "core.fsmonitor", "core.attributesfile", "core.excludesfile",
                          "core.sparsecheckout", "core.sparsecheckoutcone", "core.splitindex",
                          "core.worktree", "core.bare", "core.autocrlf", "core.safecrlf", "core.symlinks",
                          "commit.gpgsign", "commit.template", "commit.cleanup"}
        for key in names:
            key = key.lower()
            # Git's URL-dependent include cannot activate without any remote
            # URL key. This avoids reading URL values or include destinations.
            if key.startswith("includeif.hasconfig:remote.*.url:") and key.endswith(".path") and not remote_urls:
                continue
            if key == "core.bare":
                if self._run(["config", "--no-includes", "--get", "core.bare"]).strip() == b"false":
                    continue
            if key.startswith(forbidden) or key in forbidden_keys:
                raise GitBoundaryError("unsupported active Git configuration")
        if self._run(["rev-parse", "--show-toplevel"]).strip().decode() != str(self.root):
            raise GitBoundaryError("configured target is not the repository root")
        if Path(self._run(["rev-parse", "--absolute-git-dir"]).strip().decode()) != self.git_dir:
            raise GitBoundaryError("unsupported Git directory indirection")
        if self._run(["for-each-ref", "--format=%(refname)", "refs/replace/"]):
            raise GitBoundaryError("packed replacement objects are unsupported")
        return identity

    def tree(self, revision):
        result = {}
        for entry in self._run(["ls-tree", "-r", "-z", "--full-tree", revision]).split(b"\x00"):
            if not entry:
                continue
            header, path = entry.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
            path = path.decode("utf-8")
            if mode not in {"100644", "100755"} or kind != "blob" or not _oid(oid):
                raise GitBoundaryError("symlinks, submodules and nonregular tree entries are unsupported")
            # Existing ignore files do not execute Git controls; never accept
            # them as mutation targets. Attribute files are refused anywhere.
            if any(part.lower() in {".git", ".gitattributes", ".gitmodules", ".gitconfig"} for part in path.split("/")):
                raise GitBoundaryError("repository attributes or submodules are unsupported")
            result[path] = (mode, oid)
        if len(result) > 10000:
            raise GitBoundaryError("repository exceeds supported tree size")
        return result

    def read(self, path, *, missing=False):
        parts = path.split("/")
        directory = self.root
        for part in parts[:-1]:
            directory /= part
            if not directory.exists() and missing:
                return None
            self._directory(directory)
        target = directory / parts[-1]
        try:
            descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if missing:
                return None
            raise
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.owner_uid
                    or info.st_mode & 0o022 or info.st_size > 8_388_608):
                raise GitBoundaryError("worktree file violates protected-file boundary")
            content = stream.read(8_388_609)
            after = os.fstat(stream.fileno())
            if (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                    after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise GitBoundaryError("worktree changed during inspection")
            return content, "100755" if info.st_mode & 0o111 else "100644"

    def state(self, branch):
        identity = self.policy()
        self._run(["check-ref-format", "refs/heads/" + branch])
        if self._run(["symbolic-ref", "-q", "HEAD"]).strip().decode() != "refs/heads/" + branch:
            raise GitBoundaryError("symbolic branch differs from approved branch")
        head = self._run(["rev-parse", "--verify", "HEAD^{commit}"]).strip().decode()
        if not _oid(head):
            raise GitBoundaryError("invalid current commit")
        tree = self.tree(head)
        if self._run(["check-attr", "-z", "--all", "--stdin"],
                     source=b"".join(path.encode("utf-8") + b"\x00" for path in tree)):
            raise GitBoundaryError("active attributes are unsupported")
        index_tree = {}
        for item in self._run(["ls-files", "--stage", "-z"]).split(b"\x00"):
            if item:
                header, path = item.split(b"\t", 1)
                mode, oid, stage = header.decode().split(" ")
                if stage != "0":
                    raise GitBoundaryError("unmerged index is unsupported")
                index_tree[path.decode("utf-8")] = (mode, oid)
        if index_tree != tree or any(item[:2] != b"H " for item in self._run(["ls-files", "-v", "-z"]).split(b"\x00") if item):
            raise GitBoundaryError("staged changes or hidden index flags are unsupported")
        if self._run(["status", "--porcelain=v1", "-z", "--untracked-files=all"]):
            raise GitBoundaryError("worktree must be clean")
        total = 0
        for path, (mode, oid) in tree.items():
            content, actual_mode = self.read(path)
            total += len(content)
            if total > 67_108_864 or actual_mode != mode or self._run(["hash-object", "--stdin"], source=content).strip().decode() != oid:
                raise GitBoundaryError("worktree does not match exact committed tree")
        index = self.read(".git/index")[0]
        return _State(head, tree, index, identity)

    def expected(self, base, bundle):
        tree = self.tree(base)
        for path, content in bundle.items():
            tree[path] = (tree.get(path, ("100644", ""))[0],
                          self._run(["hash-object", "--stdin"], source=content).strip().decode())
        return tree

    def commit_matches(self, commit, arguments, expected_tree):
        raw = self._run(["cat-file", "commit", commit])
        header, message = raw.split(b"\n\n", 1)
        parents = [line[7:].decode() for line in header.splitlines() if line.startswith(b"parent ")]
        return (parents == [arguments["base_commit"]]
                and message == (arguments["message"] + "\n").encode("utf-8")
                and self.tree(commit) == expected_tree)


def _key(effect_id, binding_digest):
    if type(effect_id) is not int or effect_id < 1 or not re.fullmatch(r"[0-9a-f]{64}", binding_digest or ""):
        raise GitBoundaryError("invalid protected effect identity")
    return f"{effect_id}-{binding_digest}"


class GitCommitter:
    plugin_id = "git.commit"

    def __init__(self, repositories, *, observer_group=None, executable=None):
        self.repositories = dict(repositories)
        if observer_group is not None and (type(observer_group) is not int or observer_group < 0):
            raise ValueError("observer_group must be an explicit trusted group ID")
        self.observer_group = observer_group
        self.executable = executable

    def _repo(self, target):
        if target not in self.repositories:
            raise GitBoundaryError("repository alias is not configured")
        return _Repository(self.repositories[target], executable=self.executable)

    def commit(self, target, content, digest, arguments, *, effect_id, binding_digest):
        bundle = validate_action(arguments, content)
        if hashlib.sha256(content).hexdigest() != digest:
            raise GitBoundaryError("artifact digest mismatch")
        repo = self._repo(target)
        key = _key(effect_id, binding_digest)
        ledger_dir = repo.git_dir / "hobnail-effects"
        repo.policy()
        if ledger_dir.exists():
            repo._directory(ledger_dir)
        else:
            ledger_dir.mkdir(mode=0o700)
            if self.observer_group is not None:
                os.chown(ledger_dir, -1, self.observer_group)
                os.chmod(ledger_dir, 0o750)
        journal = ledger_dir / (key + ".jsonl")
        if journal.exists() or journal.is_symlink():
            observation = GitObserver(self.repositories, executable=self.executable).observe(target, content, digest, arguments,
                                                                  effect_id=effect_id, binding_digest=binding_digest)
            if observation["outcome"] == "complete":
                return {**observation["receipt"], "reconciled": True}
            raise GitBoundaryError("existing effect requires reconciliation")
        initial = repo.state(arguments["branch"])
        if initial.head != arguments["base_commit"]:
            raise GitBoundaryError("current HEAD differs from approved base")
        for path in bundle:
            if path not in initial.tree and repo.read(path, missing=True) is not None:
                raise GitBoundaryError("new path already exists outside the admitted tree")
        if repo._run(["check-attr", "-z", "--all", "--stdin"],
                     source=b"".join(path.encode("utf-8") + b"\x00" for path in bundle)):
            raise GitBoundaryError("accepted paths have active attributes")
        expected = repo.expected(initial.head, bundle)
        _no_case_aliases(expected)
        if expected == initial.tree:
            raise GitBoundaryError("artifact makes no repository change")
        for field in ("user.name", "user.email"):
            value = repo._run(["config", "--local", "--get", field]).strip()
            if not value or b"\n" in value or b"\x00" in value:
                raise GitBoundaryError("target needs an explicitly configured local Git identity")
        lock = repo.git_dir / "hobnail-adapter.lock"
        lock_fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        index_lock = repo.git_dir / "index.lock"
        index_fd = None
        lock_info = os.fstat(lock_fd)
        lock_identity = lock_info.st_dev, lock_info.st_ino
        index_identity = None
        started = False
        settled = False
        workspace = None
        try:
            os.write(lock_fd, key.encode())
            os.fsync(lock_fd)
            index_fd = os.open(index_lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            original_index_info = (repo.git_dir / "index").lstat()
            os.fchmod(index_fd, stat.S_IMODE(original_index_info.st_mode))
            os.fchown(index_fd, -1, original_index_info.st_gid)
            index_info = os.fstat(index_fd)
            index_identity = index_info.st_dev, index_info.st_ino
            locked = repo.state(arguments["branch"])
            if locked != initial:
                raise GitBoundaryError("repository changed while acquiring its reservation")
            workspace = Path(tempfile.mkdtemp(prefix="hobnail-transaction-", dir=repo.git_dir))
            (workspace / "index.preimage").write_bytes(initial.index)
            private_index = workspace / "index"
            with journal.open("x", encoding="utf-8") as ledger:
                if self.observer_group is not None:
                    os.fchown(ledger.fileno(), -1, self.observer_group)
                    os.fchmod(ledger.fileno(), 0o640)
                else:
                    os.fchmod(ledger.fileno(), 0o600)
                def record(phase, **fields):
                    ledger.write(canonical_json({"phase": phase, "effect_id": effect_id,
                        "binding_digest": binding_digest, "artifact_digest": digest,
                        "arguments": arguments, **fields}) + "\n")
                    ledger.flush()
                    os.fsync(ledger.fileno())
                record("reserved", recovery_directory=workspace.name)
                started = True
                repo._run(["read-tree", initial.head], index=private_index)
                for path, content_bytes in bundle.items():
                    oid = repo._run(["hash-object", "-w", "--stdin"], source=content_bytes).strip().decode()
                    repo._run(["update-index", "--add", "--cacheinfo", f"{expected[path][0]},{oid},{path}"], index=private_index)
                tree = repo._run(["write-tree"], index=private_index).strip().decode()
                if repo.tree(tree) != expected:
                    raise GitBoundaryError("prepared tree differs from accepted artifact")
                commit = repo._run(["commit-tree", tree, "-p", initial.head],
                                   source=(arguments["message"] + "\n").encode()).strip().decode()
                if not repo.commit_matches(commit, arguments, expected):
                    raise GitBoundaryError("prepared commit differs from approved parent/tree/message")
                record("prepared", commit=commit)
                if repo.state(arguments["branch"]) != initial:
                    raise GitBoundaryError("repository changed before expected-base integration")
                repo._run(["update-ref", "-m", f"hobnail effect {effect_id}", "refs/heads/" + arguments["branch"], commit, initial.head])
                record("ref_advanced", commit=commit)
                for path, new_content in bundle.items():
                    current = repo.read(path, missing=True)
                    old = initial.tree.get(path)
                    if (old is None and current is not None) or (old is not None and
                            (current is None or current[1] != old[0]
                             or repo._run(["hash-object", "--stdin"], source=current[0]).strip().decode() != old[1])):
                        raise GitBoundaryError("concurrent worktree change preserved for reconciliation")
                    directory = repo.root
                    for part in _path(path)[:-1]:
                        directory /= part
                        if not directory.exists():
                            directory.mkdir(mode=0o755)
                        repo._directory(directory)
                    temporary = directory / (".hobnail-" + uuid.uuid4().hex)
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as output:
                        output.write(new_content)
                        if old is not None:
                            old_info = (repo.root / path).lstat()
                            os.fchmod(output.fileno(), stat.S_IMODE(old_info.st_mode))
                            os.fchown(output.fileno(), -1, old_info.st_gid)
                        else:
                            os.fchmod(output.fileno(), 0o644)
                        output.flush()
                        os.fsync(output.fileno())
                    os.replace(temporary, repo.root / path)
                    _fsync_directory(directory)
                data = memoryview(private_index.read_bytes())
                while data:
                    written = os.write(index_fd, data)
                    if not written:
                        raise OSError("index write made no progress")
                    data = data[written:]
                os.fsync(index_fd)
                os.close(index_fd)
                index_fd = None
                os.replace(index_lock, repo.git_dir / "index")
                _fsync_directory(repo.git_dir)
                final = repo.state(arguments["branch"])
                if final.head != commit or final.tree != expected:
                    raise GitBoundaryError("integrated worktree or index did not settle")
                record("settled", commit=commit)
                settled = True
                return {"commit": commit, "base_commit": initial.head, "artifact_digest": digest,
                        "target": target, "reconciled": False}
        finally:
            os.close(lock_fd)
            if index_fd is not None:
                os.close(index_fd)
            if settled or not started:
                _unlink_owned(lock, lock_identity)
                if index_identity is not None:
                    _unlink_owned(index_lock, index_identity)
                if workspace is not None:
                    for name in ("index", "index.preimage"):
                        file = workspace / name
                        if file.exists():
                            file.unlink()
                    workspace.rmdir()
            # On partial failure, owned locks, journal and original index remain.


class GitObserver:
    def __init__(self, repositories, *, adapter_owner_uid=None, executable=None):
        self.repositories = dict(repositories)
        self.owner_uid = adapter_owner_uid
        self.executable = executable

    def observe(self, target, content, digest, arguments, *, effect_id, binding_digest):
        try:
            bundle = validate_action(arguments, content)
            if target not in self.repositories or hashlib.sha256(content).hexdigest() != digest:
                raise GitBoundaryError("observation binding mismatch")
            repo = _Repository(self.repositories[target], owner_uid=self.owner_uid, executable=self.executable)
            repo.policy()
            state = repo.state(arguments["branch"])
            key = _key(effect_id, binding_digest)
            journal = repo.git_dir / "hobnail-effects" / (key + ".jsonl")
            if state.head == arguments["base_commit"]:
                if journal.exists() or journal.is_symlink():
                    raise GitBoundaryError("existing integration intent requires reconciliation")
                return {"outcome": "absent", "artifact_digest": None, "receipt": {"head": state.head}}
            expected = repo.expected(arguments["base_commit"], bundle)
            if not repo.commit_matches(state.head, arguments, expected):
                return {"outcome": "mismatch", "artifact_digest": None,
                        "receipt": {"head": state.head, "reason": "parent_tree_or_message_mismatch"}}
            data = repo.read(str(journal.relative_to(repo.root)), missing=True)
            if data is None or len(data[0]) > 524_288:
                raise GitBoundaryError("matching commit lacks protected effect provenance")
            rows = [parse_json(line) for line in data[0].decode("utf-8").splitlines()]
            if (not 1 <= len(rows) <= 4 or any(not isinstance(row, dict) for row in rows)
                    or any(row.get("effect_id") != effect_id or row.get("binding_digest") != binding_digest
                    or row.get("artifact_digest") != digest or row.get("arguments") != arguments for row in rows)):
                raise GitBoundaryError("protected intent differs from requested observation")
            if not any(row.get("phase") == "prepared" and row.get("commit") == state.head for row in rows):
                raise GitBoundaryError("current commit was not prepared for this effect")
            return {"outcome": "complete", "artifact_digest": digest,
                    "receipt": {"commit": state.head, "base_commit": arguments["base_commit"],
                                "target": target, "pending_lock": (repo.git_dir / "hobnail-adapter.lock").exists()}}
        except (OSError, GitBoundaryError, ValueError, KeyError, UnicodeError, TypeError, RecursionError):
            return {"outcome": "unknown", "artifact_digest": None,
                    "receipt": {"reason": "repository_unsettled_or_boundary_refused"}}


def dispatch_git(client, effect_id, committer, *, lease_seconds=60):
    response = client.call("effect.claim", {"effect_id": effect_id, "lease_seconds": lease_seconds})
    if not response["ok"]:
        return response
    claim = response["data"]
    content = checked_bytes(claim["artifact"])
    manifest = claim["action"].get("manifest", {})
    if (claim["action"]["plugin"] != "git.commit" or manifest.get("implementation") != implementation_digest()
            or manifest.get("execution_backend") != "local-git"):
        raise GitBoundaryError("unsupported approved Git implementation")
    validate_action(claim["args"], content)
    fence = {"effect_id": effect_id, "token": claim["token"], "generation": claim["generation"]}
    permitted = client.call("effect.dispatch", fence)
    if not permitted["ok"]:
        return permitted
    try:
        receipt = committer.commit(claim["target"], content, claim["artifact"]["digest"], claim["args"],
                                   effect_id=effect_id, binding_digest=claim["binding_digest"])
    except (OSError, GitBoundaryError):
        return client.call("effect.report", {**fence, "outcome": "uncertain",
                                             "receipt": {"reason": "git_integration_requires_reconciliation"}})
    return client.call("effect.report", {**fence, "outcome": "attempted", "receipt": receipt})


def observe_git(client, effect_id, observer):
    response = client.call("effect.get", {"effect_id": effect_id})
    if not response["ok"]:
        return response
    effect = response["data"]
    if effect["action"]["plugin"] != "git.commit":
        raise GitBoundaryError("unsupported Git observation")
    content = checked_bytes(effect["artifact"])
    observation = observer.observe(effect["action"]["target"], content, effect["artifact"]["digest"],
                                   effect["action"]["arguments"], effect_id=effect_id,
                                   binding_digest=effect["binding_digest"])
    return client.call("effect.observe", {"effect_id": effect_id, **observation})
