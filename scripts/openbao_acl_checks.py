"""Live lease ACL assertions; never starts a runtime or edits its policy.

The caller supplies two real, positively authenticated, currently valid leases
and holds sessions for both. Synthetic tests of this orchestration are not
evidence that OpenBao enforces an ACL. Configuration mutations need their own
operator-side observer and are deliberately outside this checker.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import re
import sys
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hobnail.credentials import Secret


_MAIN_PREFIX = "database/creds/hobnail-worker/"
_FOREIGN_PREFIX = "database/creds/hobnail-negative-control/"
_SNAPSHOT_KEYS = {"oid", "expires_at", "login_enabled", "active_sessions", "valid"}


class ACLCheckFailure(RuntimeError):
    """Safe partial evidence is retained without response bodies or references."""

    def __init__(self, evidence: dict[str, Any]):
        self.evidence = evidence
        super().__init__("live ACL qualification failed; inspect safe evidence")


@dataclass(frozen=True)
class _Case:
    name: str
    method: str
    path: str = field(repr=False)
    payload: dict[str, Any] | None = field(default=None, repr=False)


def _reference(lease: Any, prefix: str) -> str:
    reference = getattr(lease, "lease_ref", None)
    if (not isinstance(reference, str) or not reference.startswith(prefix) or len(reference) <= len(prefix)
            or len(reference) > 128 or not re.fullmatch(r"[A-Za-z0-9_./-]+", reference)
            or any(part in {"", ".", ".."} for part in reference.split("/"))):
        raise ValueError("lease does not belong to the frozen reference fixture")
    return reference


def _snapshot(callback: Callable[[Any], Mapping[str, Any]], lease: Any) -> dict[str, Any]:
    value = callback(lease)
    if not isinstance(value, Mapping) or set(value) != _SNAPSHOT_KEYS:
        raise ValueError("snapshot shape differs from the qualification contract")
    result = dict(value)
    if (type(result["oid"]) is not int or result["oid"] <= 0
            or type(result["active_sessions"]) is not int or result["active_sessions"] < 0
            or type(result["login_enabled"]) is not bool or type(result["valid"]) is not bool
            or type(result["expires_at"]) is not str):
        raise ValueError("snapshot types differ from the qualification contract")
    expiry = datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00"))
    if expiry.tzinfo is None or expiry.utcoffset().total_seconds() != 0:
        raise ValueError("snapshot expiry must be an explicit UTC timestamp")
    return result


def _live(value: dict[str, Any]) -> bool:
    return value["valid"] and value["login_enabled"] and value["active_sessions"] >= 1


def _cases(main: str, foreign: str) -> tuple[_Case, ...]:
    return (
        _Case("renew_foreign_existing_wrong_prefix", "PUT", "/v1/sys/leases/renew", {"lease_id": foreign, "increment": 60}),
        _Case("revoke_foreign_existing_wrong_prefix", "PUT", "/v1/sys/leases/revoke", {"lease_id": foreign, "sync": True}),
        _Case("renew_missing_increment", "PUT", "/v1/sys/leases/renew", {"lease_id": main}),
        _Case("renew_missing_lease_id", "PUT", "/v1/sys/leases/renew", {"increment": 60}),
        _Case("renew_excess_increment", "PUT", "/v1/sys/leases/renew", {"lease_id": main, "increment": 121}),
        _Case("revoke_missing_sync", "PUT", "/v1/sys/leases/revoke", {"lease_id": main}),
        _Case("revoke_missing_lease_id", "PUT", "/v1/sys/leases/revoke", {"sync": True}),
        _Case("revoke_async_refused", "PUT", "/v1/sys/leases/revoke", {"lease_id": main, "sync": False}),
        _Case("renew_main_alternate_url", "PUT", "/v1/sys/leases/renew/" + main, {"increment": 60}),
        _Case("revoke_main_alternate_url", "PUT", "/v1/sys/leases/revoke/" + main, {"sync": True}),
        _Case("renew_foreign_alternate_url", "PUT", "/v1/sys/leases/renew/" + foreign, {"increment": 60}),
        _Case("revoke_foreign_alternate_url", "PUT", "/v1/sys/leases/revoke/" + foreign, {"sync": True}),
        _Case("revoke_foreign_url_main_body", "PUT", "/v1/sys/leases/revoke/" + foreign, {"lease_id": main, "sync": True}),
        _Case("revoke_prefix_refused", "POST", "/v1/sys/leases/revoke-prefix/" + _MAIN_PREFIX.rstrip("/"), {"sync": True}),
        _Case("revoke_force_refused", "POST", "/v1/sys/leases/revoke-force/" + _MAIN_PREFIX.rstrip("/"), {}),
        _Case("lease_lookup_refused", "POST", "/v1/sys/leases/lookup", {"lease_id": main}),
        _Case("lease_listing_refused", "LIST", "/v1/sys/leases/lookup/" + _MAIN_PREFIX.rstrip("/")),
        _Case("known_connection_read_refused", "GET", "/v1/database/config/hobnail-reference"),
        _Case("known_role_read_refused", "GET", "/v1/database/roles/hobnail-worker"),
        _Case("known_policy_read_refused", "GET", "/v1/sys/policies/acl/hobnail-reference-provider"),
        _Case("known_builtin_plugin_read_refused", "GET", "/v1/sys/plugins/catalog/database/postgresql-database-plugin"),
        # Match the real provider's duration-string wire type so these exercise
        # the prefix, exact increment and parameter allowlist independently.
        _Case("renew_foreign_existing_duration_wrong_prefix", "PUT", "/v1/sys/leases/renew", {"lease_id": foreign, "increment": "60s"}),
        _Case("renew_excess_duration_increment", "PUT", "/v1/sys/leases/renew", {"lease_id": main, "increment": "121s"}),
        _Case("renew_duration_extra_parameter", "PUT", "/v1/sys/leases/renew", {"lease_id": main, "increment": "60s", "unexpected": True}),
    )


def run_acl_checks(runtime: Any, main_token: Secret, main_lease: Any, foreign_lease: Any,
                   snapshot: Callable[[Any], Mapping[str, Any]]) -> dict[str, Any]:
    """Assert exact HTTP 403 and unchanged real snapshots for every case.

    ``snapshot(lease)`` must return exactly ``oid`` (positive int),
    ``expires_at`` (UTC string), ``login_enabled`` (bool), ``active_sessions``
    (int), and ``valid`` (bool from an actual downstream expiry predicate).
    Both leases must have a held session and remain valid before/after every
    call. The caller establishes positive password authentication and a
    successful allowed operation with the same main token before and after this
    matrix; otherwise an invalid token's blanket 403 responses prove no ACL.

    Only safe case names, HTTP statuses and comparison booleans are returned.
    On failure, ``ACLCheckFailure.evidence`` retains the completed and failing
    cases. No response body, raw exception text, credential or lease reference
    is copied into that evidence.
    """
    if not isinstance(main_token, Secret) or not callable(snapshot):
        raise ValueError("explicit Secret and snapshot callback required")
    main = _reference(main_lease, _MAIN_PREFIX)
    foreign = _reference(foreign_lease, _FOREIGN_PREFIX)
    report: dict[str, Any] = {"status": "incomplete", "cases": [],
        "scope": "lease ACL denials and forbidden reads of separately established existing configuration targets",
        "configuration_mutations_tested": False, "caller_positive_controls_checked_here": False,
        "required_caller_controls": ["positive password authentication for both existing leases",
                                     "successful allowed main-token operation before and after the matrix"]}
    leases = {"main": main_lease, "foreign": foreign_lease}
    baseline = None
    for case in _cases(main, foreign):
        row: dict[str, Any] = {"case": case.name, "http_status": None, "request_attempted": False,
                              "main_unchanged": False, "foreign_unchanged": False, "both_still_valid": False}
        report["cases"].append(row)
        try:
            before = {name: _snapshot(snapshot, lease) for name, lease in leases.items()}
        except Exception:
            row["failure"] = "before_snapshot_unavailable_or_invalid"
            report["status"] = "failed"
            raise ACLCheckFailure(report) from None
        if not all(_live(value) for value in before.values()):
            row["failure"] = "lease_or_held_session_not_live_before_request"
            report["status"] = "failed"
            raise ACLCheckFailure(report)
        if before["main"]["oid"] == before["foreign"]["oid"]:
            row["failure"] = "lease_fixtures_share_one_role_identity"
            report["status"] = "failed"
            raise ACLCheckFailure(report)
        if baseline is None:
            baseline = before
        elif before != baseline:
            row["failure"] = "fixture_state_changed_between_cases"
            report["status"] = "failed"
            raise ACLCheckFailure(report)
        request_failed = False
        row["request_attempted"] = True
        try:
            response = runtime.request(case.method, case.path, case.payload, token=main_token, expectedstatuses=(403,))
            status = getattr(response, "status", None)
            row["http_status"] = status if type(status) is int and 100 <= status <= 599 else None
        except Exception as error:
            request_failed = True
            status = getattr(error, "status", None)
            row["http_status"] = status if type(status) is int and 100 <= status <= 599 else None
        try:
            after = {name: _snapshot(snapshot, lease) for name, lease in leases.items()}
            row["main_unchanged"] = before["main"] == after["main"]
            row["foreign_unchanged"] = before["foreign"] == after["foreign"]
            row["both_still_valid"] = all(_live(value) for value in after.values())
        except Exception:
            row["failure"] = "after_snapshot_unavailable_or_invalid"
        if request_failed:
            row["failure"] = "request_or_response_failed"
        elif row["http_status"] != 403:
            row["failure"] = "expected_exact_http_403"
        elif not (row["main_unchanged"] and row["foreign_unchanged"] and row["both_still_valid"]):
            row.setdefault("failure", "downstream_state_changed_or_expired")
        if "failure" in row:
            report["status"] = "failed"
            raise ACLCheckFailure(report) from None
        row["passed"] = True
    report["status"] = "passed"
    return report
