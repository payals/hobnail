"""Protected built-in validator catalog with no candidate code execution."""

import hashlib
import json
from pathlib import Path
import subprocess

from .isolation import IsolationUnavailable, run_implementation
from .client import parse_json


BUILTINS = {
    "bytes.sha256": {"version": 1, "required_parameters": ["expected"]},
    "json.required_fields": {"version": 1, "required_parameters": ["pointers"]},
    "json.equals": {"version": 1, "required_parameters": ["source", "pairs"]},
}


def implementation_digest():
    return hashlib.sha256(Path(__file__).with_name("_validator_worker.py").read_bytes()).hexdigest()


def evaluate(content, plugin_id, parameters, *, inputs=None, timeout=10,
             expected_implementation=None, plugins=None, implementation_runner=None):
    """Evaluate using an explicitly configured trusted execution backend.

    The optional callable is controller configuration, never candidate JSON or
    a contract-selected fallback. A deployment must qualify that backend and
    bind its implementation bytes using isolation.implementation_snapshot.
    """
    runner = run_implementation if implementation_runner is None else implementation_runner
    if not callable(runner):
        return {"result": "inconclusive", "detail": {"reason": "execution_backend_unavailable"}}
    if not isinstance(content, bytes) or len(content) > 1_048_576:
        return {"result": "error", "detail": {"reason": "artifact_size"}}
    custom = isinstance(plugin_id, str) and plugin_id.startswith("custom:")
    if plugin_id not in BUILTINS and not custom:
        return {"result": "inconclusive", "detail": {"reason": "unsupported_plugin"}}
    plugins = plugins or {}
    if custom and expected_implementation not in plugins:
        return {"result": "inconclusive", "detail": {"reason": "unqualified_implementation"}}
    inputs = inputs or {}
    if len(inputs) > 16 or any(not isinstance(value, bytes) or len(value) > 1_048_576
                              for value in inputs.values()):
        return {"result": "error", "detail": {"reason": "input_size"}}
    payload = json.dumps({"content_hex": content.hex(), "plugin_id": plugin_id,
                          "parameters": parameters,
                          "inputs": {key: value.hex() for key, value in inputs.items()}}, allow_nan=False)
    try:
        if custom:
            child = runner(plugins[expected_implementation], expected_implementation, payload, timeout=timeout)
        else:
            child = runner(Path(__file__).with_name("_validator_worker.py"),
                           expected_implementation or implementation_digest(), payload, timeout=timeout)
    except IsolationUnavailable:
        return {"result": "inconclusive", "detail": {"reason": "isolation_unavailable"}}
    except subprocess.TimeoutExpired:
        return {"result": "error", "detail": {"reason": "timeout"}}
    if child.returncode:
        return {"result": "error", "detail": {"reason": "worker_exit"}}
    try:
        result = parse_json(child.stdout)
        if not isinstance(result, dict) or set(result) != {"result", "detail"}:
            raise ValueError("invalid envelope")
        if result["result"] not in {"pass", "fail", "error", "inconclusive"}:
            raise ValueError("invalid result")
        if (not isinstance(result["detail"], dict)
                or len(json.dumps(result["detail"], allow_nan=False).encode()) > 16_384):
            raise ValueError("invalid detail")
        return result
    except (KeyError, TypeError, ValueError):
        return {"result": "error", "detail": {"reason": "worker_protocol"}}
