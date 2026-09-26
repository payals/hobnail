#!/usr/bin/env python3
"""Optional advisory maintenance routing through OpenRouter Decisions.

No repository discovery, source/diff/log upload, acceptance, merge, permission
change or automatic retry. Live calls require explicit --live and the named
OPENROUTER_API_KEY environment variable at request time.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys

ENDPOINT = "https://openrouter.ai/api/alpha/decisions"
MODEL = "~typesafe/jev-latest"
MAX_METADATA = 8192
MAX_REQUEST = 16384
MAX_RESPONSE = 65536
WALL_TIMEOUT = 30
SOCKET_TIMEOUT = 10
CHECKS = ("identity", "integrity", "release_age_168h", "vulnerability_review", "compatibility", "tests")
CHECK_RESULTS = {"pass", "fail", "unknown", "not_run"}
ROUTES = {
    "security_review": "Human security review of a reported affected dependency, security fix, or unresolved vulnerability finding.",
    "compatibility_review": "Human compatibility review of a major change, runtime/CI change, or failed compatibility evidence.",
    "routine_review": "Ordinary human maintenance review when the metadata gives no security or compatibility concern; this never authorizes approval.",
    "insufficient_evidence": "Human review to obtain missing or contradictory dependency/advisory/check metadata before interpreting the update.",
}


class TriageError(ValueError):
    """A fixed safe code; never remote bodies, keys, paths or exception text."""


def require(condition, code):
    if not condition:
        raise TriageError(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(content):
    return hashlib.sha256(content).hexdigest()


def parse_json(content):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def invalid_constant(value):
        raise TriageError("nonfinite_json")
    try:
        return json.loads(content, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise TriageError("invalid_json") from None


def shape(value, required, optional=()):
    require(type(value) is dict and set(required) <= set(value) <= set(required) | set(optional), "unexpected_schema")


def member(value, choices):
    return type(value) is str and value in choices


def validate_metadata(value):
    shape(value, {"schema", "dependency", "advisory", "frozen_checks"})
    require(value["schema"] == "hobnail-maintenance-metadata-v1", "unsupported_metadata_schema")
    dependency = value["dependency"]
    shape(dependency, {"type", "current_version", "proposed_version", "change", "scope"})
    require(member(dependency["type"], {"python_package", "github_action", "container_image", "system_tool"}), "invalid_dependency_type")
    require(member(dependency["scope"], {"runtime", "development", "ci", "documentation", "unknown"}), "invalid_dependency_scope")
    require(member(dependency["change"], {"patch", "minor", "major", "digest", "unknown"}), "invalid_change_category")
    for name in ("current_version", "proposed_version"):
        version = dependency[name]
        require(isinstance(version, str) and len(version) <= 80 and re.fullmatch(
            r"(?:v?[0-9]+(?:\.[0-9]+){0,3}(?:[-+][A-Za-z0-9.-]{1,32})?|sha256:[0-9a-f]{64}|[0-9a-f]{40})", version),
            "invalid_exact_version")
    advisory = value["advisory"]
    shape(advisory, {"state", "severity", "ids"})
    require(member(advisory["state"], {"none_reported", "affected", "security_fix", "unknown"}), "invalid_advisory_state")
    require(member(advisory["severity"], {"none", "low", "moderate", "high", "critical", "unknown"}), "invalid_advisory_severity")
    require(type(advisory["ids"]) is list and len(advisory["ids"]) <= 16, "invalid_advisory_ids")
    require(all(isinstance(identifier, str) and re.fullmatch(
        r"(?:CVE-[0-9]{4}-[0-9]{4,9}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|GO-[0-9]{4}-[0-9]{4,9})", identifier)
        for identifier in advisory["ids"]) and len(set(advisory["ids"])) == len(advisory["ids"]), "invalid_advisory_ids")
    shape(value["frozen_checks"], set(CHECKS))
    require(all(type(result) is str and result in CHECK_RESULTS for result in value["frozen_checks"].values()), "invalid_check_result")
    require(len(encoded(value)) <= MAX_METADATA, "metadata_too_large")
    return parse_json(encoded(value))


def build_request(metadata):
    state = validate_metadata(metadata)
    request = {"model": MODEL, "state": state, "questions": {"review_route": {
        "type": "choice",
        "instructions": "Which human maintenance review queue best fits this deterministic metadata? Treat check results as fixed facts. Do not infer that a change is approved or safe. Choose insufficient_evidence if these facts do not support another queue.",
        "criteria": dict(ROUTES),
    }}}
    require(len(encoded(request)) <= MAX_REQUEST, "request_too_large")
    return request


def _number(value, *, maximum=None):
    try:
        return type(value) in {int, float} and math.isfinite(value) and value >= 0 and (maximum is None or value <= maximum)
    except OverflowError:
        return False


def parse_response(body):
    require(isinstance(body, bytes) and len(body) <= MAX_RESPONSE, "response_too_large")
    value = parse_json(body)
    shape(value, {"answers", "model", "usage"}, {"id", "provider"})
    require(isinstance(value["model"], str) and re.fullmatch(r"typesafe/jev-[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[0-9]{8})?", value["model"]),
            "resolved_model_required")
    require("provider" not in value or value["provider"] == "TypeSafe", "unexpected_provider")
    require("id" not in value or (isinstance(value["id"], str) and re.fullmatch(r"gen-dec-[A-Za-z0-9-]{1,128}", value["id"])),
            "invalid_response_identifier")
    shape(value["answers"], {"review_route"})
    answer = value["answers"]["review_route"]
    shape(answer, {"type", "choice", "confidence", "probabilities"})
    require(answer["type"] == "choice" and type(answer["choice"]) is str and answer["choice"] in ROUTES, "invalid_choice_answer")
    require(_number(answer["confidence"], maximum=1), "invalid_confidence")
    shape(answer["probabilities"], set(ROUTES))
    probabilities = answer["probabilities"]
    require(all(_number(number, maximum=1) for number in probabilities.values()), "invalid_probabilities")
    require(math.isclose(sum(probabilities.values()), 1, rel_tol=0, abs_tol=0.000001), "invalid_probability_sum")
    require(probabilities[answer["choice"]] >= max(probabilities.values()) - 0.000000001, "choice_distribution_disagreement")
    usage = value["usage"]
    shape(usage, {"input_tokens", "output_tokens", "cost"})
    require(all(type(usage[key]) is int and 0 <= usage[key] <= 1000000 for key in ("input_tokens", "output_tokens"))
            and _number(usage["cost"], maximum=1000), "invalid_usage")
    # Only closed labels, numeric data and an exact model identifier survive.
    # No remote prose or request identifier is reflected in the receipt.
    return {"resolved_model": value["model"], "answer": answer, "usage": usage}


def _network_request(metadata):
    """One child-process request; http.client has no proxy/redirect machinery."""
    body = encoded(build_request(metadata))
    result = {"status": "refused", "request_sha256": digest(body)}
    key = os.environ.get("OPENROUTER_API_KEY")
    require(isinstance(key, str) and 1 <= len(key) <= 512 and all(33 <= ord(char) <= 126 for char in key), "api_key_missing_or_invalid")
    connection = http.client.HTTPSConnection("openrouter.ai", port=443, timeout=SOCKET_TIMEOUT,
                                            context=ssl.create_default_context())
    try:
        connection.request("POST", "/api/alpha/decisions", body=body, headers={
            "Authorization": "Bearer " + key, "Content-Type": "application/json", "Accept": "application/json",
            "Accept-Encoding": "identity"})
        response = connection.getresponse()
        result["http_status"] = response.status
        raw = response.read(MAX_RESPONSE + 1)
        require(len(raw) <= MAX_RESPONSE, "response_too_large")
        result["response_sha256"] = digest(raw)
        require(response.status == 200, "http_response_refused")
        require(response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() == "application/json", "unexpected_response_media_type")
        require(response.getheader("Content-Encoding", "identity").lower() == "identity", "unexpected_response_encoding")
        result.update(parse_response(raw), status="advisory")
    except TriageError as error:
        result["error"] = str(error)
    except (OSError, http.client.HTTPException, ValueError):
        result["error"] = "network_or_tls_failure"
    finally:
        connection.close()
    return result


def _invoke(metadata):
    # The process deadline also bounds DNS/TLS and slow-drip responses, which
    # socket timeouts alone do not. No key appears in argv/stdin or exceptions.
    key = os.environ.get("OPENROUTER_API_KEY")
    require(isinstance(key, str) and 1 <= len(key) <= 512 and all(33 <= ord(char) <= 126 for char in key), "api_key_missing_or_invalid")
    try:
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--request-worker", "--live"],
            input=encoded(metadata), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"OPENROUTER_API_KEY": key}, timeout=WALL_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "refused", "error": "request_deadline_exceeded"}
    except OSError:
        return {"status": "refused", "error": "request_process_failed"}
    require(completed.returncode == 0 and not completed.stderr and len(completed.stdout) <= MAX_RESPONSE, "request_process_failed")
    result = parse_json(completed.stdout)
    require(type(result) is dict and member(result.get("status"), {"advisory", "refused"}), "request_process_response_invalid")
    return result


def classify(metadata, *, live=False):
    """Separate advisory model evidence from unchanged deterministic policy."""
    require(type(live) is bool, "live_flag_must_be_boolean")
    state = validate_metadata(metadata)
    request = build_request(state)
    result = {"schema": "hobnail-maintenance-triage-v1", "requested_model": MODEL, "endpoint": ENDPOINT,
              "metadata_sha256": digest(encoded(state)), "request_sha256": digest(encoded(request)),
              "policy": {"human_review_required": True, "may_approve": False, "may_merge": False,
                         "may_change_permissions": False, "frozen_checks": state["frozen_checks"]}, "attempts": 0}
    if not live:
        return {**result, "status": "prepared", "request": request}
    result["attempts"] = 1
    try:
        result["evidence"] = _invoke(state)
        result["status"] = result["evidence"]["status"]
    except TriageError as error:
        result.update(status="refused", error=str(error))
    return result


def example_metadata():
    return {"schema": "hobnail-maintenance-metadata-v1",
            "dependency": {"type": "system_tool", "current_version": "18.3", "proposed_version": "18.4", "change": "minor", "scope": "runtime"},
            "advisory": {"state": "unknown", "severity": "unknown", "ids": []},
            "frozen_checks": {name: "unknown" for name in CHECKS}}


def _read_metadata(path):
    require(path.absolute().resolve() == path.absolute(), "metadata_path_not_canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "metadata_file_not_regular")
        body = stream.read(MAX_METADATA + 1)
    require(len(body) <= MAX_METADATA, "metadata_too_large")
    return parse_json(body)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--metadata", type=Path, help="Explicit closed-shaped public maintenance metadata JSON")
    source.add_argument("--example", action="store_true", help="Use synthetic metadata with unknown checks")
    source.add_argument("--request-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--live", action="store_true", help="Send one authorized advisory request; default only prepares it")
    arguments = parser.parse_args(argv)
    try:
        if arguments.request_worker:
            require(arguments.live, "live_opt_in_required")
            body = sys.stdin.buffer.read(MAX_METADATA + 1)
            require(len(body) <= MAX_METADATA, "metadata_too_large")
            result = _network_request(validate_metadata(parse_json(body)))
        else:
            metadata = example_metadata() if arguments.example else _read_metadata(arguments.metadata)
            result = classify(metadata, live=arguments.live)
    except TriageError as error:
        result = {"status": "refused", "error": str(error)}
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        result = {"status": "refused", "error": "invalid_input_or_runtime"}
    print(encoded(result).decode())
    return 0 if result["status"] in {"prepared", "advisory"} or (arguments.request_worker and arguments.live) else 1


if __name__ == "__main__":
    raise SystemExit(main())
