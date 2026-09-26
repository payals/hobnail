"""Research budget admission and exact accepted-result registry effects.

This module never evaluates a research holdout or replaces domain safeguards.
The application supplies a reviewed, idempotent guard that reserves its existing
domain budget. Protected promotion still requires independently registered
evidence and current kernel acceptance of the exact promotion artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Callable, Mapping
import uuid

from ..client import Client, canonical_json, parse_json
from ..effects import EffectBoundaryError, FileObserver, _parent
from ..verifier import checked_bytes


class ResearchBoundaryError(EffectBoundaryError):
    """Research identity, admission, or accepted promotion binding is invalid."""


def _digest(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ResearchBoundaryError("expected a lowercase SHA-256 digest")
    return value


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", value):
        raise ResearchBoundaryError("invalid research identifier")
    return value


def _positive(value: int, maximum: int = 1_000_000_000) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ResearchBoundaryError("expected a positive bounded integer")
    return value


def _hash(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


@dataclass(frozen=True)
class ResearchIdentity:
    """Immutable declared fingerprints, not an attestation that inputs are true."""

    study: str
    protocol_digest: str
    evaluator_digest: str
    candidate_digest: str
    consumed_inputs: tuple[tuple[str, str], ...]
    domain_identity_digest: str

    def __post_init__(self):
        _identifier(self.study)
        for value in (self.protocol_digest, self.evaluator_digest,
                      self.candidate_digest, self.domain_identity_digest):
            _digest(value)
        if type(self.consumed_inputs) is not tuple or not 1 <= len(self.consumed_inputs) <= 16:
            raise ResearchBoundaryError("consumed inputs must be a nonempty immutable tuple")
        names = []
        for pair in self.consumed_inputs:
            if type(pair) is not tuple or len(pair) != 2:
                raise ResearchBoundaryError("invalid consumed input fingerprint")
            names.append(_identifier(pair[0]))
            _digest(pair[1])
        if len(set(names)) != len(names) or tuple(sorted(self.consumed_inputs)) != self.consumed_inputs:
            raise ResearchBoundaryError("consumed inputs must have unique sorted names")

    @classmethod
    def from_fingerprints(cls, *, study: str, protocol_digest: str,
                          evaluator_digest: str, candidate_digest: str,
                          consumed_inputs: Mapping[str, str], domain_identity_digest: str):
        return cls(study, protocol_digest, evaluator_digest, candidate_digest,
                   tuple(sorted(consumed_inputs.items())), domain_identity_digest)

    def document(self) -> dict:
        return {"schema_version": 1, "study": self.study,
                "protocol_digest": self.protocol_digest, "evaluator_digest": self.evaluator_digest,
                "candidate_digest": self.candidate_digest, "consumed_inputs": dict(self.consumed_inputs),
                "domain_identity_digest": self.domain_identity_digest}

    @property
    def digest(self) -> str:
        return _hash(self.document())


@dataclass(frozen=True)
class GuardDecision:
    """Safe receipt from a reviewed domain guard; never arbitrary exception text.

    reservation_digest must identify an immutable domain reservation, so exact
    retries retain it even if current usage and display status have changed.
    """

    allowed: bool
    identity_digest: str
    reservation_digest: str | None
    status: str

    def __post_init__(self):
        if type(self.allowed) is not bool:
            raise ResearchBoundaryError("guard allowed must be boolean")
        _digest(self.identity_digest)
        _identifier(self.status)
        if self.allowed:
            _digest(self.reservation_digest)
        elif self.reservation_digest is not None:
            _digest(self.reservation_digest)


@dataclass(frozen=True)
class BudgetReservation:
    contract_id: str
    budget: str
    units: int
    reservation_id: int

    def __post_init__(self):
        _identifier(self.contract_id)
        _identifier(self.budget)
        _positive(self.units)
        _positive(self.reservation_id, 9223372036854775807)
        if self.budget in {"verification", "effects"}:
            raise ResearchBoundaryError("research cannot use internal budget categories")

    def document(self) -> dict:
        return {"contract_id": self.contract_id, "budget": self.budget,
                "units": self.units, "reservation_id": self.reservation_id}


@dataclass(frozen=True)
class Admission:
    identity: ResearchIdentity
    status: str
    reservation: BudgetReservation | None
    guard: GuardDecision | None
    denial_code: str | None = None

    @property
    def allowed(self) -> bool:
        return (self.status == "admitted" and self.reservation is not None
                and self.guard is not None and self.guard.allowed
                and self.guard.identity_digest == self.identity.domain_identity_digest)


def reserve_research(client: Client, contract_id: str, identity: ResearchIdentity,
                     guard: Callable[[ResearchIdentity, BudgetReservation], GuardDecision], *,
                     budget: str = "research", units: int = 1) -> Admission:
    """Commit a named reservation before invoking the existing domain guard.

    Transport uncertainty propagates without invoking the guard or retrying.
    Guard refusal/error keeps the committed reservation spent. A caller may
    explicitly retry the same immutable identity: both reservation layers must
    be idempotent. This function reserves admission, never evaluates research.
    """
    _identifier(contract_id)
    _identifier(budget)
    _positive(units)
    if budget in {"verification", "effects"}:
        raise ResearchBoundaryError("research cannot use internal budget categories")
    key = _hash({"contract_id": contract_id, "budget": budget, "identity_digest": identity.digest})
    response = client.call("budget.consume", {"contract_id": contract_id, "budget": budget,
                           "units": units, "idempotency_key": "research:" + key})
    if not response["ok"]:
        return Admission(identity, "budget_refused", None, None, response["code"])
    reservation = BudgetReservation(contract_id, budget, units, response["data"]["reservation_id"])
    # An idempotent consume may replay a historical receipt after policy or
    # scope changed. It proves expenditure, never fresh permission to proceed.
    # This separately committed read is the wrapper's current authorization
    # point; it cannot atomically fence a later external domain operation.
    current = client.call("budget.get", {"contract_id": contract_id})
    if not current["ok"]:
        return Admission(identity, "authority_refused", reservation, None, current["code"])
    state = current["data"]["budgets"].get(budget)
    if state is None:
        return Admission(identity, "authority_refused", reservation, None, "BUDGET_UNAVAILABLE")
    if (type(state.get("cap")) is not int or type(state.get("used")) is not int
            or state["used"] < units or state["cap"] < 0):
        raise ResearchBoundaryError("current budget state does not support the reservation")
    if state["used"] > state["cap"]:
        return Admission(identity, "authority_refused", reservation, None, "BUDGET_EXHAUSTED")
    try:
        decision = guard(identity, reservation)
    except Exception:
        return Admission(identity, "domain_error", reservation, None, "DOMAIN_GUARD_ERROR")
    if not isinstance(decision, GuardDecision) or decision.identity_digest != identity.domain_identity_digest:
        return Admission(identity, "domain_identity_mismatch", reservation, None, "DOMAIN_IDENTITY_MISMATCH")
    return Admission(identity, "admitted" if decision.allowed else "domain_refused", reservation, decision)


def promotion_artifact(admission: Admission, *, evaluation_digest: str, outcome: str) -> bytes:
    """Bind a passing evaluation claim to both immutable admission receipts.

    Independent contract checks must compare this artifact against trusted
    admission/evaluation inputs. The caller's word 'pass' is not verification.
    Terminal NULL, failed and inconclusive research cannot form this artifact.
    """
    if not admission.allowed or outcome != "pass":
        raise ResearchBoundaryError("promotion requires admitted, passing research")
    _digest(evaluation_digest)
    value = {"kind": "hobnail.research-promotion.v1", "identity": admission.identity.document(),
             "identity_digest": admission.identity.digest,
             "reservation": admission.reservation.document(),
             "domain_reservation_digest": admission.guard.reservation_digest,
             "evaluation_digest": evaluation_digest, "outcome": "pass"}
    return canonical_json(value).encode()


def validate_promotion(content: bytes) -> dict:
    if not isinstance(content, bytes) or len(content) > 1_048_576:
        raise ResearchBoundaryError("invalid promotion artifact size")
    try:
        value = parse_json(content.decode("utf-8"))
        expected = {"kind", "identity", "identity_digest", "reservation", "domain_reservation_digest",
                    "evaluation_digest", "outcome"}
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("invalid promotion shape")
        identity_doc = value["identity"]
        if set(identity_doc) != {"schema_version", "study", "protocol_digest", "evaluator_digest",
                                 "candidate_digest", "consumed_inputs", "domain_identity_digest"}:
            raise ValueError("invalid identity shape")
        if type(identity_doc["schema_version"]) is not int or identity_doc["schema_version"] != 1:
            raise ValueError("invalid identity version")
        identity = ResearchIdentity.from_fingerprints(**{key: val for key, val in identity_doc.items()
                                                       if key != "schema_version"})
        if value["kind"] != "hobnail.research-promotion.v1" or value["outcome"] != "pass":
            raise ValueError("invalid promotion meaning")
        if _digest(value["identity_digest"]) != identity.digest:
            raise ValueError("identity binding differs")
        _digest(value["domain_reservation_digest"])
        _digest(value["evaluation_digest"])
        if set(value["reservation"]) != {"contract_id", "budget", "units", "reservation_id"}:
            raise ValueError("invalid reservation shape")
        BudgetReservation(**value["reservation"])
        if canonical_json(value).encode() != content:
            raise ValueError("promotion artifacts must have canonical bytes")
        return value
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError) as error:
        raise ResearchBoundaryError("invalid promotion artifact") from None


def request_promotion(client: Client, candidate_id: int, admission: Admission, *,
                      evaluation_digest: str, action: str = "promote") -> dict:
    """Read exact current acceptance before requesting its protected effect."""
    expected = promotion_artifact(admission, evaluation_digest=evaluation_digest, outcome="pass")
    response = client.call("candidate.get", {"candidate_id": candidate_id})
    if not response["ok"]:
        return response
    candidate = response["data"]
    content = checked_bytes(candidate["artifact"])
    if content != expected or candidate["binding"]["contract_id"] != admission.reservation.contract_id:
        raise ResearchBoundaryError("candidate is not the exact admitted promotion artifact")
    if not candidate.get("eligible") or not any(
            row.get("binding_digest") == candidate["binding_digest"]
            and row.get("generation") == candidate["generation"]
            for row in candidate.get("acceptances", [])):
        raise ResearchBoundaryError("candidate lacks current exact acceptance")
    return client.call("effect.request", {"candidate_id": candidate_id, "action": _identifier(action),
                       "args": {}, "idempotency_key": "promotion:" + hashlib.sha256(expected).hexdigest()})


def implementation_digest() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


class ResearchRegistry:
    """Create-only promotion-record consumer, separate from any trading registry.

    The deployment owns the root exclusively; workers must not have write access
    for a prevention claim. No active-strategy pointer or account is changed.
    """

    def __init__(self, root: str | Path, *, observer_group: int | None = None):
        self.root = Path(root).absolute()
        if observer_group is not None and (type(observer_group) is not int or observer_group < 0):
            raise ValueError("observer_group must be an explicit trusted group ID")
        self.observer_group = observer_group

    def publish(self, target: str, content: bytes, expected_digest: str) -> dict:
        value = validate_promotion(content)
        if hashlib.sha256(content).hexdigest() != expected_digest:
            raise ResearchBoundaryError("promotion bytes differ from accepted artifact")
        if Path(target).name != value["identity_digest"] + ".json":
            raise ResearchBoundaryError("target must name the exact research identity")
        with _parent(self.root, target) as (directory, filename):
            temporary = ".research-" + uuid.uuid4().hex
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
                try:
                    # A link creates the destination atomically without replacing
                    # an earlier independently accepted record.
                    os.link(temporary, filename, src_dir_fd=directory, dst_dir_fd=directory,
                            follow_symlinks=False)
                except FileExistsError:
                    current = os.open(filename, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
                    with os.fdopen(current, "rb") as stream:
                        info = os.fstat(stream.fileno())
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != len(content):
                            raise ResearchBoundaryError("existing registry record is unsafe or different")
                        if stream.read(len(content) + 1) != content:
                            raise ResearchBoundaryError("registry identity already has different content")
                os.fsync(directory)
            finally:
                os.unlink(temporary, dir_fd=directory)
                os.fsync(directory)
        return {"identity_digest": value["identity_digest"], "artifact_digest": expected_digest,
                "reservation_id": value["reservation"]["reservation_id"], "bytes": len(content)}


def dispatch_promotion(client: Client, effect_id: int, registry: ResearchRegistry, *, lease_seconds: int = 60) -> dict:
    response = client.call("effect.claim", {"effect_id": effect_id, "lease_seconds": lease_seconds})
    if not response["ok"]:
        return response
    claim = response["data"]
    content = checked_bytes(claim["artifact"])
    value = validate_promotion(content)
    manifest = claim["action"].get("manifest", {})
    if (claim["action"]["plugin"] != "research.promote" or claim["args"] != {}
            or manifest.get("implementation") != implementation_digest()
            or manifest.get("execution_backend") != "research-registry"
            or Path(claim["target"]).name != value["identity_digest"] + ".json"):
        raise ResearchBoundaryError("unsupported or mismatched research promotion action")
    fence = {"effect_id": effect_id, "token": claim["token"], "generation": claim["generation"]}
    dispatched = client.call("effect.dispatch", fence)
    if not dispatched["ok"]:
        return dispatched
    try:
        receipt = registry.publish(claim["target"], content, claim["artifact"]["digest"])
    except (OSError, EffectBoundaryError):
        return client.call("effect.report", {**fence, "outcome": "uncertain",
                                             "receipt": {"reason": "research_consumer_failure"}})
    return client.call("effect.report", {**fence, "outcome": "attempted", "receipt": receipt})


def observe_promotion(client: Client, effect_id: int, observer: FileObserver) -> dict:
    response = client.call("effect.get", {"effect_id": effect_id})
    if not response["ok"]:
        return response
    effect = response["data"]
    if effect["action"]["plugin"] != "research.promote":
        raise ResearchBoundaryError("unsupported research observation action")
    observation = observer.observe(effect["action"]["target"], effect["artifact"]["digest"])
    return client.call("effect.observe", {"effect_id": effect_id, **observation})
