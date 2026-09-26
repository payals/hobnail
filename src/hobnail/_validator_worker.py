"""Credential-free deterministic check worker; invoked by the isolation backend.

The input is data, never Python or a command. Keep imports in the standard library.
"""

import hashlib
from decimal import Decimal
import json
import math
import re
import sys


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _validate(value, depth=0):
    if depth > 64:
        raise ValueError("nesting limit")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite number")
    if isinstance(value, Decimal) and (not value.is_finite() or abs(value.adjusted()) > 308
                                       or len(value.as_tuple().digits) > 128):
        raise ValueError("numeric limit")
    if isinstance(value, dict):
        for child in value.values():
            _validate(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate(child, depth + 1)
    return value


def parse(content):
    return _validate(json.loads(content.decode("utf-8"), object_pairs_hook=_object, parse_float=Decimal))


def pointer(document, path):
    if path == "":
        return document
    if not isinstance(path, str) or not path.startswith("/") or re.search(r"~(?![01])", path):
        raise ValueError("invalid pointer")
    value = document
    for encoded in path[1:].split("/"):
        key = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            value = value[key]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", key):
            value = value[int(key)]
        else:
            raise KeyError("missing pointer")
    return value


def equal(left, right):
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float, Decimal)) and isinstance(right, (int, float, Decimal)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(equal(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(equal(a, b) for a, b in zip(left, right))
    return left == right


def evaluate(request):
    content = bytes.fromhex(request["content_hex"])
    plugin = request["plugin_id"]
    parameters = request["parameters"]
    if plugin == "bytes.sha256":
        actual = hashlib.sha256(content).hexdigest()
        return {"result": "pass" if actual == parameters["expected"] else "fail",
                "detail": {"actual_digest": actual}}
    document = parse(content)
    if plugin == "json.required_fields":
        fields = parameters["pointers"]
        try:
            for field in fields:
                pointer(document, field)
        except (KeyError, IndexError):
            return {"result": "fail", "detail": {"reason": "missing_pointer"}}
        return {"result": "pass", "detail": {"required_count": len(fields)}}
    if plugin == "json.equals":
        source = parse(bytes.fromhex(request["inputs"][parameters["source"]]))
        try:
            passed = all(equal(pointer(document, pair["artifact"]), pointer(source, pair["input"]))
                         for pair in parameters["pairs"])
        except (KeyError, IndexError):
            return {"result": "fail", "detail": {"reason": "missing_pointer"}}
        return {"result": "pass" if passed else "fail", "detail": {"reason": "comparison"}}
    return {"result": "inconclusive", "detail": {"reason": "unsupported_plugin"}}


def main():
    raw = sys.stdin.buffer.read(36_000_001)
    if len(raw) > 36_000_000:
        response = {"result": "error", "detail": {"reason": "input_limit"}}
    else:
        try:
            response = evaluate(json.loads(raw))
        except (KeyError, TypeError, ValueError, RecursionError):
            # Do not echo candidate content, exception messages, or filesystem data.
            response = {"result": "error", "detail": {"reason": "invalid_input"}}
    print(json.dumps(response, allow_nan=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
