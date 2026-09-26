"""Verify exported audit bytes against an independently held checkpoint.

The PostgreSQL ``event::text`` string is the hash input; re-serializing parsed
JSON is not equivalent. A chain from genesis establishes internal consistency,
not authenticity against a database administrator. A caller-held authentic
checkpoint detects rewrites at/before that point, but cannot establish the
truth of later recorded statements or detect every omitted real-world event.

Pagination targets the first export's head. Export calls append their own audit
events, so chasing the newest head on every page would never finish at limit=1.
Callers may retain the returned checkpoint in an independently controlled store;
this module does not silently write or trust a database-provided checkpoint.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import hashlib
import json
import re
from typing import Any, Mapping, Protocol

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class AuditError(ValueError):
    """The export cannot establish continuity to the requested checkpoint."""


@dataclass(frozen=True)
class Checkpoint:
    sequence: int
    hash: str

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise AuditError("checkpoint sequence must be a nonnegative integer")
        if not isinstance(self.hash, str) or not _DIGEST.fullmatch(self.hash):
            raise AuditError("checkpoint hash must be lowercase SHA-256")
        if self.sequence == 0 and self.hash != "0" * 64:
            raise AuditError("genesis checkpoint must use the zero hash")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Checkpoint:
        if not isinstance(value, Mapping) or set(value) != {"sequence", "hash"}:
            raise AuditError("checkpoint must contain sequence and hash")
        return cls(value["sequence"], value["hash"])

    def as_dict(self) -> dict[str, Any]:
        return {"sequence": self.sequence, "hash": self.hash}


GENESIS = Checkpoint(0, "0" * 64)


@dataclass(frozen=True)
class PageVerification:
    checkpoint: Checkpoint
    target: Checkpoint
    verified_events: int
    complete: bool


@dataclass(frozen=True)
class AuditVerification:
    start: Checkpoint
    checkpoint: Checkpoint
    verified_events: int
    pages: int

    @property
    def externally_anchored(self) -> bool:
        """True assumes the caller supplied an authentic non-genesis start."""
        return self.start.sequence > 0


class AuditClient(Protocol):
    def require(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]: ...


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("canonical event contains duplicate keys")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise AuditError("canonical event contains a non-finite number")


def _same_json(left: Any, right: Any) -> bool:
    """Compare display JSON without Python's True == 1 equivalence."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float, Decimal)) and isinstance(right, (int, float, Decimal)):
        try:
            return Decimal(str(left)) == Decimal(str(right))
        except Exception:
            return False
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same_json(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_json(a, b) for a, b in zip(left, right))
    return left == right


def verify_page(
    page: Mapping[str, Any], *, checkpoint: Checkpoint = GENESIS,
    target: Checkpoint | None = None,
) -> PageVerification:
    """Verify one export page; never trust its ``chain_valid`` boolean.

    ``checkpoint`` is the previously verified boundary. ``target`` is fixed
    from the first page, even if later exports report a newer head. Rows beyond
    that target are deliberately outside this receipt's verification scope.
    """
    if not isinstance(page, Mapping) or not isinstance(page.get("events"), list):
        raise AuditError("export must contain an events array")
    head = Checkpoint.from_mapping(page.get("head"))
    if head.sequence < checkpoint.sequence:
        raise AuditError("export head precedes the caller-held checkpoint")
    if head.sequence == checkpoint.sequence and head.hash != checkpoint.hash:
        raise AuditError("export head contradicts the caller-held checkpoint")
    target = head if target is None else target
    if target.sequence < checkpoint.sequence or head.sequence < target.sequence:
        raise AuditError("export cannot reach the fixed target")
    if head.sequence == target.sequence and head.hash != target.hash:
        raise AuditError("export changed the fixed target hash")
    if checkpoint.sequence == target.sequence:
        if checkpoint.hash != target.hash:
            raise AuditError("target contradicts the caller-held checkpoint")
        return PageVerification(checkpoint, target, 0, True)
    current = checkpoint
    count = 0
    for row in page["events"]:
        if not isinstance(row, Mapping):
            raise AuditError("audit row must be an object")
        sequence = row.get("seq")
        if type(sequence) is not int or sequence != current.sequence + 1:
            raise AuditError("audit sequence has a gap, duplicate or reordering")
        canonical = row.get("event_canonical")
        if not isinstance(canonical, str):
            raise AuditError("raw PostgreSQL event_canonical text is required")
        try:
            event = json.loads(canonical, object_pairs_hook=_unique_object,
                               parse_float=Decimal, parse_constant=_invalid_constant)
            encoded = canonical.encode("utf-8")
        except (ValueError, UnicodeError, RecursionError) as error:
            raise AuditError("canonical event is invalid JSON or UTF-8") from error
        if not isinstance(event, dict) or type(event.get("sequence")) is not int or event["sequence"] != sequence:
            raise AuditError("canonical event sequence differs from the row")
        if "event" not in row or not _same_json(event, row["event"]):
            raise AuditError("display event differs from the hashed canonical event")
        if row.get("previous_hash") != current.hash:
            raise AuditError("audit link differs from the caller-held checkpoint")
        digest = hashlib.sha256(bytes.fromhex(current.hash) + encoded).hexdigest()
        if row.get("hash") != digest:
            raise AuditError("audit event hash differs from its canonical bytes")
        current = Checkpoint(sequence, digest)
        count += 1
        if current.sequence == target.sequence:
            if current.hash != target.hash:
                raise AuditError("verified chain differs from the fixed target")
            return PageVerification(current, target, count, True)
    if count == 0:
        raise AuditError("export omitted events required to reach its head")
    return PageVerification(current, target, count, False)


def export_verified(
    client: AuditClient, *, checkpoint: Checkpoint = GENESIS,
    page_size: int = 1000, max_pages: int = 10000,
) -> AuditVerification:
    """Fetch and verify a finite prefix, raising on denial, corruption or gaps."""
    if type(page_size) is not int or not 1 <= page_size <= 1000:
        raise ValueError("page_size must be between 1 and 1000")
    if type(max_pages) is not int or max_pages < 1:
        raise ValueError("max_pages must be positive")
    current = checkpoint
    target: Checkpoint | None = None
    count = 0
    for number in range(1, max_pages + 1):
        envelope = client.require("audit.export", {"after": current.sequence, "limit": page_size})
        result = verify_page(envelope["data"], checkpoint=current, target=target)
        current, target = result.checkpoint, result.target
        count += result.verified_events
        if result.complete:
            return AuditVerification(checkpoint, current, count, number)
    raise AuditError("page budget exhausted before the fixed head was verified")
