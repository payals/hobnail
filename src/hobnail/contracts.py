"""Strict manual contract validation and non-authoritative authoring suggestions.

This validates data; it does not approve policy or certify a deployment. The
protected database independently checks registered identities and manifests.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping

from .client import canonical_json, parse_json

IDENTIFIER = re.compile(r"[A-Za-z0-9_.:/-]{1,128}\Z", re.ASCII)
DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
BUILTIN_VALIDATORS = frozenset({"bytes.sha256", "json.required_fields", "json.equals"})
BUILTIN_EFFECTS = frozenset({"file.publish", "research.promote", "git.commit"})
_EFFECT_BACKENDS = {"file.publish": "local-file", "git.commit": "local-git", "research.promote": "research-registry"}
_GIT_PROTECTED_SEGMENTS = frozenset({".git", ".gitignore", ".gitattributes", ".gitmodules", ".gitconfig",
                                     ".githooks", ".husky", ".pre-commit-config.yaml"})


class ContractError(ValueError):
    def __init__(self, path: str, detail: str, *, code: str = "INVALID_REQUEST"):
        self.path = path
        self.detail = detail
        self.code = code
        super().__init__(f"{path}: {detail}")


def _fail(path: str, detail: str, *, unsupported: bool = False) -> None:
    raise ContractError(path, detail, code="UNSUPPORTED_CAPABILITY" if unsupported else "INVALID_REQUEST")


def _object(value: Any, path: str, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    if any(not isinstance(key, str) for key in value):
        _fail(path, "all object keys must be strings")
    missing = required - value.keys()
    unknown = value.keys() - required - (optional or set())
    if missing:
        _fail(path, "missing fields: " + ", ".join(sorted(missing)))
    if unknown:
        _fail(path, "unknown fields: " + ", ".join(sorted(unknown)))
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        _fail(path, "must be a protocol identifier (1-128 ASCII identifier characters)")
    return value


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(path, f"must be an integer between {minimum} and {maximum}")
    return value


def _array(value: Any, path: str, minimum: int, maximum: int) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        _fail(path, f"must be an array with {minimum}-{maximum} entries")
    return value


def _identifiers(value: Any, path: str, *, minimum: int = 0) -> list[str]:
    values = _array(value, path, minimum, 128)
    for index, item in enumerate(values):
        _identifier(item, f"{path}/{index}")
    if len(set(values)) != len(values):
        _fail(path, "duplicate identifiers")
    return values


def _digest(value: Any, path: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        _fail(path, "must be 64 lowercase hexadecimal characters")


def _pointer(value: Any, path: str) -> None:
    if not isinstance(value, str) or (value and not value.startswith("/")) or len(value.encode("utf-8")) > 2048:
        _fail(path, "must be an RFC 6901 pointer of at most 2048 UTF-8 bytes")
    if re.search(r"~(?:[^01]|$)", value):
        _fail(path, "contains an invalid RFC 6901 escape")


def _media_type(value: Any, path: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+", value) or len(value) > 128:
        _fail(path, "must be a media type without parameters")


def _unique_records(records: list[dict[str, Any]], key: str, path: str) -> None:
    values = [item[key] for item in records]
    if len(values) != len(set(values)):
        _fail(path, f"duplicate {key} values")


def _confined_target(target: str, path: str) -> None:
    if (target.startswith("/") or "\\" in target or re.search(r"[\x00-\x1f\x7f-\x9f]", target)
            or any(part in {"", ".", ".."} for part in target.split("/"))):
        _fail(path, "must be a confined relative target without aliases or control characters")


def _git_arguments(arguments: dict[str, Any], path: str) -> None:
    _object(arguments, path, {"branch", "base_commit", "paths", "message"})
    branch = arguments["branch"]
    if (not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,127}", branch)
            or re.search(r"(\.\.|//|(^|/)\.|\.lock(/|$)|[./]$)", branch)):
        _fail(path + "/branch", "must be a supported literal Git branch name")
    if not isinstance(arguments["base_commit"], str) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", arguments["base_commit"]):
        _fail(path + "/base_commit", "must be an exact lowercase 40- or 64-hex commit ID")
    message = arguments["message"]
    if (not isinstance(message, str) or not message.strip() or len(message.encode("utf-8")) > 2048
            or "\x00" in message or "\r" in message or message.endswith("\n")):
        _fail(path + "/message", "must be a nonblank exact message of at most 2048 UTF-8 bytes without NUL, CR or trailing LF")
    paths = _array(arguments["paths"], path + "/paths", 1, 64)
    for index, target in enumerate(paths):
        location = f"{path}/paths/{index}"
        if (not isinstance(target, str) or len(target.encode("utf-8")) > 1024
                or not re.fullmatch(r"[A-Za-z0-9_./-]+", target)):
            _fail(location, "must be a bounded ASCII repository path")
        _confined_target(target, location)
        if any(part.lower() in _GIT_PROTECTED_SEGMENTS for part in target.split("/")):
            _fail(location, "Git control and hook paths are protected")
    if len(set(paths)) != len(paths):
        _fail(path + "/paths", "duplicate repository paths")
    prefixes: dict[str, str] = {}
    for target in paths:
        parts = target.split("/")
        for count in range(1, len(parts) + 1):
            prefix = "/".join(parts[:count])
            folded = prefix.casefold()
            if folded in prefixes and prefixes[folded] != prefix:
                _fail(path + "/paths", "case aliases are unsupported at every repository path prefix")
            prefixes[folded] = prefix
    if any(a != b and b.startswith(a + "/") for a in paths for b in paths):
        _fail(path + "/paths", "file and directory targets overlap")


def validate_contract(document: Mapping[str, Any], *, for_activation: bool = False,
                      now: datetime | None = None, allow_unsupported: bool = False) -> dict[str, Any]:
    """Return an independent JSON copy or fail closed on a malformed contract.

    ``allow_unsupported`` is only for coverage reporting. Activation callers must
    not use it: an unknown mandatory plugin is never an advisory check.
    """
    if not isinstance(document, Mapping):
        _fail("/", "must be an object")
    try:
        # Round-trip removes object aliases and rejects values JSON cannot carry.
        encoded = canonical_json(dict(document))
        doc = parse_json(encoded)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ContractError("/", "must contain only finite JSON values") from exc
    _object(doc, "/", {"schema_version", "access", "subject", "sources", "checks", "actions", "budgets", "expires_at"}, {"description"})
    _integer(doc["schema_version"], "/schema_version", 1, 1)
    if "description" in doc and (not isinstance(doc["description"], str) or len(doc["description"].encode("utf-8")) > 2048):
        _fail("/description", "must be a string of at most 2 KiB")
    access = _object(doc["access"], "/access", {"workers", "verifiers", "observers", "adapters"})
    for name in ("workers", "verifiers", "observers"):
        _identifiers(access[name], f"/access/{name}", minimum=1 if name != "observers" else 0)
    if not isinstance(access["adapters"], dict):
        _fail("/access/adapters", "must be an object")
    for action, principals in access["adapters"].items():
        _identifier(action, "/access/adapters")
        _identifiers(principals, f"/access/adapters/{action}", minimum=1)
    subject = _object(doc["subject"], "/subject", {"media_type", "max_bytes"})
    _media_type(subject["media_type"], "/subject/media_type")
    _integer(subject["max_bytes"], "/subject/max_bytes", 1, 1048576)
    sources = _array(doc["sources"], "/sources", 1, 16)
    for index, value in enumerate(sources):
        path = f"/sources/{index}"
        source = _object(value, path, {"name", "registrars", "require_current"})
        _identifier(source["name"], path + "/name")
        _identifiers(source["registrars"], path + "/registrars", minimum=1)
        if type(source["require_current"]) is not bool:
            _fail(path + "/require_current", "must be a boolean")
    _unique_records(sources, "name", "/sources")
    source_names = {source["name"] for source in sources}
    checks = _array(doc["checks"], "/checks", 1, 64)
    for index, value in enumerate(checks):
        path = f"/checks/{index}"
        check = _object(value, path, {"id", "plugin", "plugin_digest", "parameters", "max_age_seconds"})
        _identifier(check["id"], path + "/id")
        _identifier(check["plugin"], path + "/plugin")
        _digest(check["plugin_digest"], path + "/plugin_digest")
        _integer(check["max_age_seconds"], path + "/max_age_seconds", 1, 86400)
        params = check["parameters"]
        plugin = check["plugin"]
        if plugin == "bytes.sha256":
            _object(params, path + "/parameters", {"expected"})
            _digest(params["expected"], path + "/parameters/expected")
        elif plugin == "json.required_fields":
            _object(params, path + "/parameters", {"pointers"})
            pointers = _array(params["pointers"], path + "/parameters/pointers", 1, 128)
            for pointer in pointers:
                _pointer(pointer, path + "/parameters/pointers")
            if len(set(pointers)) != len(pointers):
                _fail(path + "/parameters/pointers", "duplicate pointers")
        elif plugin == "json.equals":
            _object(params, path + "/parameters", {"source", "pairs"})
            _identifier(params["source"], path + "/parameters/source")
            if params["source"] not in source_names:
                _fail(path + "/parameters/source", "source is not declared")
            pairs = _array(params["pairs"], path + "/parameters/pairs", 1, 128)
            for pair in pairs:
                _object(pair, path + "/parameters/pairs", {"artifact", "input"})
                _pointer(pair["artifact"], path + "/parameters/pairs/artifact")
                _pointer(pair["input"], path + "/parameters/pairs/input")
            if len({(pair["artifact"], pair["input"]) for pair in pairs}) != len(pairs):
                _fail(path + "/parameters/pairs", "duplicate pointer pairs")
        elif plugin.startswith("custom:") and len(plugin) > len("custom:"):
            if not isinstance(params, dict) or len(canonical_json(params).encode("utf-8")) > 16384:
                _fail(path + "/parameters", "custom validator parameters must be an object of at most 16 KiB")
        elif not allow_unsupported:
            _fail(path + "/plugin", "mandatory validator is unsupported", unsupported=True)
        elif not isinstance(params, dict):
            _fail(path + "/parameters", "must be an object")
    _unique_records(checks, "id", "/checks")
    actions = _array(doc["actions"], "/actions", 0, 16)
    for index, value in enumerate(actions):
        path = f"/actions/{index}"
        action = _object(value, path, {"name", "plugin", "plugin_digest", "target", "arguments", "max_age_seconds"})
        _identifier(action["name"], path + "/name")
        _identifier(action["plugin"], path + "/plugin")
        _digest(action["plugin_digest"], path + "/plugin_digest")
        _integer(action["max_age_seconds"], path + "/max_age_seconds", 1, 86400)
        if not isinstance(action["target"], str) or not action["target"] or len(action["target"].encode("utf-8")) > 1024 or "\x00" in action["target"]:
            _fail(path + "/target", "must be a nonempty string of at most 1024 bytes without NUL")
        if not isinstance(action["arguments"], dict):
            _fail(path + "/arguments", "must be an object")
        # JSONB text includes separator spaces. Count them here as well so an
        # otherwise valid large argument object does not exceed the SQL cap.
        if len(json.dumps(action["arguments"], ensure_ascii=False, allow_nan=False).encode("utf-8")) > 16384:
            _fail(path + "/arguments", "action arguments exceed the 16 KiB metadata limit")
        if action["plugin"] in _EFFECT_BACKENDS:
            _confined_target(action["target"], path + "/target")
        if action["plugin"] in {"file.publish", "research.promote"}:
            if action["arguments"]:
                _fail(path + "/arguments", action["plugin"] + " supports no arguments", unsupported=True)
            if action["plugin"] == "research.promote" and not re.fullmatch(r"[0-9a-f]{64}\.json", action["target"].split("/")[-1]):
                _fail(path + "/target", "research.promote target must end in the exact lowercase research identity digest plus .json")
        elif action["plugin"] == "git.commit":
            _identifier(action["target"], path + "/target")
            _git_arguments(action["arguments"], path + "/arguments")
        elif not allow_unsupported:
            _fail(path + "/plugin", "mandatory effect adapter is unsupported", unsupported=True)
        if action["name"] not in access["adapters"]:
            _fail(path + "/name", "action has no adapter allowlist")
    _unique_records(actions, "name", "/actions")
    if set(access["adapters"]) != {action["name"] for action in actions}:
        _fail("/access/adapters", "adapter allowlists must exactly cover actions")
    if actions and not access["observers"]:
        _fail("/access/observers", "effects require an independent observer allowlist")
    budgets = doc["budgets"]
    if not isinstance(budgets, dict) or not {"verification", "effects"}.issubset(budgets):
        _fail("/budgets", "must be an object containing verification and effects")
    for name, cap in budgets.items():
        _identifier(name, "/budgets")
        _integer(cap, f"/budgets/{name}", 0, 1000000000)
    expiry = doc["expires_at"]
    if not isinstance(expiry, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", expiry):
        _fail("/expires_at", "must be a canonical UTC timestamp ending in Z")
    try:
        expires = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("/expires_at", "invalid calendar timestamp") from exc
    if for_activation:
        current = datetime.now(timezone.utc) if now is None else now
        if current.tzinfo is None:
            _fail("/expires_at", "activation clock must be timezone-aware")
        if expires <= current:
            _fail("/expires_at", "contract is expired")
    return doc


def coverage_report(document: Mapping[str, Any]) -> dict[str, Any]:
    """Describe implementation versus deployment evidence, without approving it."""
    doc = validate_contract(document, allow_unsupported=True)
    entries = []
    for check in doc["checks"]:
        supported = check["plugin"] in BUILTIN_VALIDATORS
        custom = check["plugin"].startswith("custom:") and len(check["plugin"]) > len("custom:")
        entries.append({"requirement": "check:" + check["id"],
                        "status": "implemented" if supported else "external" if custom else "unsupported",
                        "mechanism": check["plugin"], "qualification":
                        "registered digest and independent restricted verifier execution" if supported else
                        "reviewed exact script in protected controller registry and qualified isolated-json backend"
                        if custom else "no supported execution backend"})
    for action in doc["actions"]:
        supported = action["plugin"] in BUILTIN_EFFECTS
        entries.append({"requirement": "action:" + action["name"], "status": "implemented" if supported else "unsupported",
                        "mechanism": action["plugin"], "execution_backend": _EFFECT_BACKENDS.get(action["plugin"]),
                        "qualification": (
                            "protected repository alias, hook-free qualified Git configuration, exact base/tree/message and independent observation"
                            if action["plugin"] == "git.commit" else
                            "protected create-only registry, exact research identity and independent observation; no champion activation"
                            if action["plugin"] == "research.promote" else
                            "exclusive consumer authority, target confinement and independent observation"
                        ) if supported else "no supported adapter"})
    entries.extend([
        {"requirement": "runtime-authority", "status": "external", "mechanism": "restricted authenticated logins and protected registry", "qualification": "exercise actual role-denial paths"},
        {"requirement": "restricted-execution", "status": "external", "mechanism": "separate evaluator security boundary", "qualification": "probe credential, filesystem and network confinement"},
    ])
    return {"schema_version": 1, "supported": all(entry["status"] != "unsupported" for entry in entries),
            "qualified": False, "requirements": entries}


def discover(artifact: bytes, inputs: Mapping[str, bytes] | None = None) -> dict[str, Any]:
    """Suggest checks from supplied bytes only; never scan a repository or execute it.

    Suggestions intentionally omit policy/authority and manifest digests. They
    are authoring data, not a proposed, activated or independently judged policy.
    Matching sample data cannot establish that a check measures the real goal.
    """
    if not isinstance(artifact, bytes) or len(artifact) > 1048576:
        raise ValueError("artifact must be at most 1 MiB of bytes")
    suggestions: list[dict[str, Any]] = [{"id": "exact-bytes", "plugin": "bytes.sha256",
        "parameters": {"expected": hashlib.sha256(artifact).hexdigest()},
        "meaning": "Only these exact bytes pass; choose this only if the output is fixed in advance."}]
    try:
        value = parse_json(artifact.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        value = None
    if isinstance(value, dict):
        pointers = ["/" + key.replace("~", "~0").replace("/", "~1") for key in sorted(value)][:128]
        if pointers:
            suggestions.append({"id": "required-fields", "plugin": "json.required_fields", "parameters": {"pointers": pointers},
                                "meaning": "Presence only; this does not establish correctness."})
        for name, content in sorted((inputs or {}).items()):
            _identifier(name, "/inputs")
            if not isinstance(content, bytes) or len(content) > 1048576:
                raise ValueError("each input must be at most 1 MiB of bytes")
            try:
                source = parse_json(content.decode("utf-8"))
            except (ValueError, UnicodeDecodeError, RecursionError):
                continue
            if not isinstance(source, dict):
                continue
            common = sorted(set(value) & set(source))[:128]
            pairs = []
            for key in common:
                # This is discovery only: propose matching field names, even
                # when sample values disagree, rather than cherry-pick passes.
                pointer = "/" + key.replace("~", "~0").replace("/", "~1")
                pairs.append({"artifact": pointer, "input": pointer})
            if pairs:
                suggestions.append({"id": "compare-" + hashlib.sha256(name.encode()).hexdigest()[:12], "plugin": "json.equals",
                                    "parameters": {"source": name, "pairs": pairs},
                                    "meaning": "Compare fields to independently registered source bytes."})
    return {"schema_version": 1, "authoritative": False, "suggestions": suggestions,
            "required_review": ["Select checks against the real goal, not sample success.",
                                "Choose independent principals, trusted sources, budgets and exact actions.",
                                "Resolve approved plugin manifests, validate the complete contract, and obtain separate activation."]}
