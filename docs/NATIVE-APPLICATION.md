# Run an application-owned native workflow

`NativeApplication` is a reusable context manager for one short application
workflow on a fresh owned PostgreSQL runtime. It accepts the existing complete
protocol-1 contract, caller-supplied trusted input snapshots, exact artifact
bytes and an explicit `NativeConsumer`. It does not introduce another contract
format, generate validators, start a daemon or change a live project's controls.

The caller is the trusted owner/supervisor. An explicit `approve(document)`
step proposes the document through the worker identity and activates it through
a different approver identity. `run(...)` requires that exact approved document;
mutating the caller's nested dictionary after approval cannot alter the saved
policy. Untrusted worker requests cannot perform this owner step.

## Complete source-checkout example

Run from the Hobnail repository using its existing project `.venv`, PostgreSQL
18 and the supported macOS backend. Create `.venv` only if it is absent using
`python3 -m venv .venv`; no third-party package installation is needed. The
output directory below is newly created and retained. Historical native checks
used Python 3.14 and PostgreSQL 18.3; the public candidate needs its own checks.
The same example is built into the helper, so this runs it directly:

```sh
.venv/bin/python scripts/native_application.py
```

It prints the final `status`, the private `receipt` path and the published
`output` path, and exits 0 only for `completed`. The script is otherwise a
library: import `NativeApplication` as below to run your own contract and
artifact.

```sh
PYTHONPATH=src .venv/bin/python - <<'PY'
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile

from scripts.native_application import NativeApplication
from hobnail.deployment import NativeConsumer

output = Path(tempfile.mkdtemp(prefix="warehouse-publication-")).resolve()
trusted_warehouse = b'{"stock":7}'
report = b'{"available":7,"label":"Warehouse report"}'

with NativeApplication(
    "warehouse-workflow", NativeConsumer.file(output), sources=("warehouse",)
) as application:
    actors = application.principals
    plugins = application.plugin_digests
    contract = {
        "schema_version": 1,
        "description": "Match the report quantity to the owner-supplied warehouse snapshot",
        "access": {
            "workers": [actors["worker"]],
            "verifiers": [actors["verifier"]],
            "observers": [actors["observer"]],
            "adapters": {"release": [actors["adapter"]]},
        },
        "subject": {"media_type": "application/json", "max_bytes": 1048576},
        "sources": [{"name": "warehouse", "registrars": [actors["registrar"]], "require_current": True}],
        "checks": [{
            "id": "quantity", "plugin": "json.equals", "plugin_digest": plugins["json.equals"],
            "parameters": {"source": "warehouse", "pairs": [{"artifact": "/available", "input": "/stock"}]},
            "max_age_seconds": 300,
        }],
        "actions": [{
            "name": "release", "plugin": "file.publish", "plugin_digest": plugins["file.publish"],
            "target": "warehouse-report.json", "arguments": {}, "max_age_seconds": 300,
        }],
        "budgets": {"verification": 2, "effects": 1},
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    }
    approval = application.approve(contract)
    if approval.get("ok") is not True:
        raise RuntimeError("owner contract activation was refused")
    application.run(document=contract, inputs={"warehouse": trusted_warehouse},
                    artifact=report, action="release")

# Read the final receipt after context exit: cleanup can invalidate the result.
print(json.dumps({"status": application.receipt["status"],
                  "receipt": application.receipt["receipt"],
                  "output": str(output / "warehouse-report.json")}, indent=2))
PY
```

The input name is arbitrary; there is no special `orders` source. Declare the
complete unique source tuple at construction. Registrar registry grants and
contract source allowlists bind those names. `inputs` must cover them exactly,
with bytes of at most 1 MiB per source. The artifact is bounded by the approved
subject limit. The registrar's independent database identity does not prove
that an external warehouse was independently queried: the owner is responsible
for the supplied snapshot's provenance.

The server registers exact reviewed manifests before authoring, so
`plugin_digests` contains authoritative values. The helper never inserts fake
digests or silently rewrites a contract. Its registered checks are
`bytes.sha256`, `json.required_fields` and `json.equals`, plus the chosen native
consumer. Custom validators explicitly refuse with `UNSUPPORTED_CAPABILITY` in
this convenience lifecycle. Applications needing a reviewed custom registry can
use the lower-level verifier and deployment APIs; a requirement is never made
advisory to make this runner accept it.

## Other protected consumers

Pass `NativeConsumer.git({...}, executable=...)` or
`NativeConsumer.research(root)` instead. Author the corresponding complete
contract action and exact artifact described in
[the protocol](CONTRACT.md) and the consumer implementations
([Git](../src/hobnail/git_effects.py),
[research](../src/hobnail/integrations/research.py)). The helper registers only the selected
effect plugin and refuses actions for another consumer. Git aliases must be in
the explicit supervisor map. It does not perform a research evaluation or
construct an authoritative reservation/evaluation receipt on the caller's behalf.

`worker_client` exposes the assigned native worker API to the trusted application
integrator. Giving someone a Python object is not an isolation boundary: do not
run untrusted code inside this supervisor or expose its other configurations.
Use the enforced role processes for untrusted runtime authority. No generated
credential value is part of the public application receipt.

## Lifecycle and failure meaning

Every operation appends a `started` stage before it runs, followed by its actual
result or a safe error type. The receipt retains exact server policy, artifact,
input and candidate bindings and separate dispatch/observation results.
`completed` requires an independent matching observation; a worker claim or an
adapter's attempted report is insufficient.

- `refused` preserves the named kernel refusal and the completed stages. Bad
  content does not reserve or dispatch an effect.
- `failed` preserves the first failure and any separate cleanup failures.
  Exception text is omitted because it can contain runtime credentials.
- `control_failure` preserves a definitive independently observed violation,
  such as destination bytes differing from the admitted artifact. It is not
  relabeled uncertainty; the exact authoritative `effect_state` remains visible.
- `reconciliation_required` preserves an effect that did not receive matching
  completion. There is no automatic redispatch or compensation.
- `incomplete` means the context ended without completing a submitted workflow.

Context exit attempts actual revocation of every generated role before stopping
its owned cluster. It checks that generated credentials do not appear in the
receipt or statement log and persists `application.json` privately. A cleanup,
status or persistence failure invalidates success and retains safe evidence;
a newly owned fallback directory is used if the original root cannot safely
receive a receipt. If both writes fail, `receipt` is null and both errors stay in
the in-memory result; no saved receipt is claimed and the original caller failure
still propagates. Outputs and private database evidence remain available.

Each context admits one explicitly approved work item. It cannot be restarted,
reused to retry an uncertain operation, or used to reset a live mission's spent
budget. Generated bootstrap credentials have a 300-second TTL; do not leave the
context idle while planning. This is a fresh integration lifecycle, not a
persistent production budget namespace. Persistent applications should retain
their control plane and use the documented SDK, credential and recovery APIs.

The helper uses the tested native role machinery, but its receipt always says
`qualified: false`: successful execution of caller data is not a reusable
qualification seal for every deployment or domain. The host/supervisor remains
trusted; deployment activation and application outcome measurements are
separate requirements. Docker and other backends do not inherit native evidence.

## Verification

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_native_application.py' -v
```

The focused tests exercise a non-demo caller contract and source name through
actual SCRAM-authenticated native services. They check exact observed output,
worker approval refusal, mutable-contract refusal, unsupported-check refusal,
input mismatch, failed content, safe failure receipts and complete retirement.
