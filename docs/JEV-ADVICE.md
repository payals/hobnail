# Optional Jev advice

`scripts/jev_advice.py` provides two application-side review tools:

- `evidence`: classify a supplied claim as supported, contradicted, or having
  insufficient evidence in the supplied records.
- `contract`: suggest possible gaps in integration checks, preservation of
  existing behavior, observation of outcomes, and independent evidence in a
  proposed protocol-1 contract.

These tools help a reviewer decide what to investigate. They do not record
verification, activate a contract, accept work, grant permissions, dispatch an
effect, or merge a pull request. Every existing mandatory check remains binding.
Advice belongs outside the contract's required-check results.

This is a standard-library helper for a source checkout or source archive. It is
not installed by the SDK wheel and requires no new Python package. Use the
project's existing `.venv/bin/python` (Python 3.11 or newer).

## Prepare a request without network access

Create a small synthetic evidence packet in a new file:

```sh
.venv/bin/python - <<'PY'
import json
from pathlib import Path

packet = {
    "claim": "The marker creation completed successfully.",
    "records": [
        {"source": "dispatcher", "action_id": "synthetic-1", "status": "acknowledged"},
        {"source": "observer", "action_id": "synthetic-1", "status": "unavailable"},
        {"source": "reconciler", "action_id": "synthetic-1", "status": "unknown"}
    ]
}
with Path("evidence-example.json").open("x") as stream:
    json.dump(packet, stream, indent=2)
PY
.venv/bin/python scripts/jev_advice.py evidence \
  --input evidence-example.json --output evidence-request.json
```

The default operation writes a prepared request and its identities. It does not
contact a service or produce a model judgment. Inspect the exact request before
opting into live use. The example's outcome is unknown: an acknowledgment alone
does not prove that the marker was created, and an unavailable observer does not
prove that creation failed.

The evidence input has exactly two fields: a nonempty `claim` string and a
`records` array of objects. Records are supplied by the caller. Descriptions
such as `source: independent observer` are claims in input, not independently
authenticated provenance. The helper does not fetch or verify those sources.

## Review a proposed contract

Provide a JSON object containing `goal`, `contract`, and optionally `context`.
`goal` is the concrete intended outcome; `contract` is a complete protocol-1
contract document; `context` can describe the relevant existing behavior and
integration assumptions. For example, wrap an existing proposal:

```sh
.venv/bin/python - <<'PY'
import json
from pathlib import Path

proposal = json.loads(Path("proposed-contract.json").read_text())
packet = {
    "goal": "Deliver a current report that agrees with its trusted source and is usable by the existing consumer.",
    "contract": proposal,
    "context": "The consumer requires its existing JSON fields and must observe the delivered report."
}
with Path("contract-advice-input.json").open("x") as stream:
    json.dump(packet, stream, indent=2)
PY
.venv/bin/python scripts/jev_advice.py contract \
  --input contract-advice-input.json --output contract-request.json
```

Ordinary `validate_contract()` validation runs before preparing the model
request. It checks the supported document shape, not actual registry grants,
runtime qualification, or semantic completeness. Invalid input is refused
locally. Valid input remains unchanged and unapproved.

Four separate questions return covered, a possible gap, unclear, or not
applicable. A reported gap selects a fixed follow-up suggestion from local code.
Jev does not generate a replacement contract, check implementation, digest,
principal, or permission. A reviewer must decide whether any suggestion is
correct and use the normal independent proposal/approval process for changes.

## Make one explicit live request

Provide `OPENROUTER_API_KEY` in the process environment through your normal
secret-injection mechanism, then use a new output path:

```sh
.venv/bin/python scripts/jev_advice.py evidence --live \
  --input evidence-example.json --output evidence-advice.json
.venv/bin/python scripts/jev_advice.py contract --live \
  --input contract-advice-input.json --output contract-advice.json
```

`--live` sends the entire selected input and the fixed rubric to OpenRouter,
which routes it to TypeSafe. Use only input authorized for those providers.
There is no general secret detector or automatic anonymization: remove private
or sensitive data before invoking the helper. The helper never discovers keys
from shell profiles, credential stores, browsers, or repository configuration.

The fixed endpoint is `https://openrouter.ai/api/alpha/decisions`, using the
explicit model name `typesafe/jev-1.13`. The expected answering model is
`typesafe/jev-1.13-20260917`, as observed in the research diagnostic. A different
or missing returned model identity produces unavailable advice. Receipts record
the matching identity. A provider can change availability or behavior even
behind a versioned route. Changing the expected identity requires a reviewed
source change and fresh evaluation.
See the [OpenRouter interface](https://openrouter.ai/~typesafe/jev-latest) and
[TypeSafe model documentation](https://docs.typesafe.ai/models).

Each invocation makes at most one bounded HTTP request. Redirects, ambient
proxies and automatic retries are disabled. The output file is reserved before
the call, created with private permissions, and never overwrites an existing
file or follows an output symlink. Input and response sizes and the HTTP timeout
are bounded. An HTTP error, timeout, invalid response, or missing key produces
an explicit unavailable result instead of advice.

## Interpret the receipt

Receipts identify the input, request and versioned rubric with SHA-256 hashes;
include timestamps, status, model identity and available usage/latency; and mark
all output as advisory. The CLI additionally binds the exact input-file bytes.
Validated probabilities and classifications are retained. Unknown remote
metadata and remote error text are excluded rather than blindly logged.

`prepared` means no model was called. `advice` means a valid model response was
received. `unavailable` means no usable advice was obtained. None means the
artifact passed its contract. Exit zero for prepared/advice reports successful
tool operation regardless of the model's classification; it is not an
acceptance signal. Invalid input or unavailable advice exits nonzero. Programs
using the tool must inspect the receipt and preserve the normal Hobnail path.

Input, rubric and request hashes identify the bytes evaluated; they do not
prove that the records are true. Similarly, returned probabilities or confidence
are not calibrated error bounds for this application. No automatic confidence
threshold authorizes or rejects work. The helper never replaces an existing
unknown outcome with a model's opinion.

Keep local receipts private as appropriate for the selected input. For live
calls, the supplied API key is excluded from output. The helper does not discover
other secret values; arbitrary sensitive content inside an input packet is not
safe to publish merely because it is in a receipt.

## Verification and limits

Run the focused offline checks and the repository's explicit portable profile:

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_jev_advice.py' -v
.venv/bin/python scripts/check_portable.py
```

Offline tests exercise real file handling and synthetic service responses.
They establish tool behavior, not Jev accuracy or service availability. A live
smoke call demonstrates the requested route and receipt handling only. It does
not qualify autonomous acceptance, security enforcement, or automatic merging.

The separate initial research diagnostic used 12 synthetic evidence cases and
four repeats. Descriptive labels matched 10/12 cases and neutral labels matched
11/12; missing evidence was sometimes mislabeled as contradiction. Those cases
are not a held-out evaluation of this helper's rubrics. Do not tune these
questions on future held-out acceptance data or claim the earlier accuracy as
this helper's performance.

For adoption, compare current review with and without advice on independently
labelled cases. Count missed defects, unnecessary warnings, total reviewer
effort, latency and cost separately. Freeze the rubric and thresholds before
final evaluation, and retain adverse results. TypeSafe documents input
injection and other failure modes in its
[Jev limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13).
