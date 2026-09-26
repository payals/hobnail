"""Independent verifier controller. Candidate parsing runs in restricted children."""

import hashlib

from .validators import BUILTINS, evaluate, implementation_digest


def checked_bytes(record):
    content = bytes.fromhex(record["content_hex"])
    if hashlib.sha256(content).hexdigest() != record["digest"]:
        raise ValueError("authoritative artifact digest mismatch")
    return content


def verify_candidate(client, candidate_id, *, lease_seconds=60, plugins=None, implementation_runner=None):
    """Run one generation and ask the database to decide; never infer acceptance."""
    response = client.call("verification.claim", {
        "candidate_id": candidate_id, "lease_seconds": lease_seconds})
    if not response["ok"]:
        return response
    claim = response["data"]
    artifact = checked_bytes(claim["artifact"])
    inputs = {name: checked_bytes(value) for name, value in claim["inputs"].items()}
    implementation = implementation_digest()
    for check in claim["checks"]:
        manifest = check["manifest"]
        custom = check["plugin"].startswith("custom:")
        if (manifest["execution_backend"] != "isolated-json"
                or (not custom and (check["plugin"] not in BUILTINS
                                    or manifest["implementation"] != implementation))):
            result = {"result": "inconclusive", "detail": {"reason": "unqualified_implementation"}}
        else:
            result = evaluate(artifact, check["plugin"], check["parameters"], inputs=inputs,
                              expected_implementation=manifest["implementation"], plugins=plugins,
                              implementation_runner=implementation_runner)
        recorded = client.call("verification.record", {
            "candidate_id": candidate_id, "token": claim["token"], "generation": claim["generation"],
            "binding_digest": claim["binding_digest"], "check_id": check["id"],
            "plugin_digest": check["plugin_digest"], **result})
        if not recorded["ok"]:
            return recorded
    return client.call("candidate.accept", {"candidate_id": candidate_id})
