---
name: hobnail
description: Author, validate and exercise exact-work accountability contracts with the repository-local Hobnail protocol through your chosen developer or agent workflow.
compatibility: Plain Markdown guidance for tools that can read repository context and use the SDK, JSON CLI or optional MCP adapter. Uses the existing Python and PostgreSQL environment; optional MCP dependencies are separate.
---

# Hobnail contract authoring and use

Use this optional repository-local guide for a task that needs exact work,
independent checks and an explicitly protected action. It does not grant
permission, create a new acceptance authority or activate a runtime. Follow
the owner and directory instructions and the task's existing authorization.
When first applying this skill, name it and link this file in the progress
update. No global registration is needed to read and use this Markdown guide.
If your tool does not load it or the root `AGENTS.md` automatically, provide the
files as repository context through its normal interface.

Read [the protocol](../../docs/CONTRACT.md) and the task-relevant sections of
[operations](../../docs/OPERATIONS.md). Reconcile them with actual source and
runtime evidence. Use your chosen coding agent, runtime or orchestrator and the
smallest bounded workflow. When supported, subagents may own independent
implementation, review or verification tasks. Do not change shared instructions
or global configuration merely to use this guide.

Core Hobnail requires no model-provider account. Keep your tool's existing
subscription, API or local-model authentication and billing arrangement; client
features and provider terms determine what is available. Use an interface the
client supports, as described in [the agent guide](../../docs/AGENT-GUIDE.md),
without assuming universal client compatibility. Named advisor integrations
have separate explicit requirements and remain optional. Keep provider secrets
out of prompts, contracts and evidence.

## Establish the actual goal

State what useful outcome the user needs, which deterministic observations can
support it, and which safety/authority boundaries must hold. Distinguish the
goal from proxy checks. A matching JSON field establishes that match; it does
not establish prose truth, source correctness or project success on its own.

Identify the exact artifact, independently supplied inputs, stable submitting
principal, independent verifier, approver, destination adapter and observer.
Choose an action only when its real destination has an approved consumer
boundary. If direct worker access bypasses the adapter, report that limitation
instead of describing a protocol refusal as universal prevention.

## Author a complete proposal

Manual authoring and LLM assistance use the same contract document and API.
An LLM may suggest required fields or comparisons from authorized, nonsecret
examples. It cannot invent the owner-approved registry, trusted inputs,
implementation digests, budgets, authority scopes or destination permissions.
Do not send personal records, credentials or private artifacts to an external
model merely to draft a contract.

This complete source-only example produces suggestions from synthetic bytes:

```sh
python3 - <<'PY' | PYTHONPATH=src .venv/bin/python -m hobnail discover
import json
content = b'{"orders":2,"period":"synthetic-period"}'
print(json.dumps({"artifact_hex": content.hex(), "inputs_hex": {"orders": content.hex()}}))
PY
```

Suggestions remain proposals. Fill the actual complete closed-shape document
from the protocol, including registered digests, source freshness, every
mandatory check, exact action arguments, expiry and lineage-wide budget caps.
Use `validate` with the authorized document on stdin and inspect `coverage`.
Neither successful local validation nor coverage inspection activates a policy
or qualifies a backend.

Workers use `contract.propose`. A separately bound approver uses
`contract.activate` after the existing owner-approved review path. Never
activate as a worker, acquire an approver credential to finish the workflow,
reset a budget, relax profile ACLs or change required checks to admit the work.
Proceed with already authorized proposal/implementation work while reporting
any genuinely missing independent authority.

## Exercise the actual path

The maintained wired example requires no global installation:

```sh
.venv/bin/python scripts/local_demo.py
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_end_to_end.py' -v
```

Use [the demo source](../../scripts/local_demo.py) for the actual SDK sequence:
explicit connection, owner provisioning, native credential broker, plugin
registration, contract proposal/activation, input registration, artifact
submission, restricted validator execution, protected dispatch and independent
observation. Do not substitute manually written passing verdicts or mock
consumers when claiming this path works.

For project integration, configure the approved adapter and implementation
registry outside worker control. The candidate supplies data, not executable
paths, shell commands or service credentials. Unsupported mandatory plugins or
execution backends must remain unsupported/inconclusive. A custom manifest is
not isolation evidence; run the relevant actual boundary probes.

## Preserve evidence and uncertainty

Report acceptance, action authorization, attempted dispatch and independently
observed consequence separately. Include actual refused cases and retained
failed checks. A historical acceptance does not establish current eligibility
after an input/policy/expiry change. An idempotency key is scoped to stable
principal and operation; do not reuse it for a different intent across contracts.

On an uncertain mutating response, reconcile the existing intent. Do not create
a new key or redispatch an effect after its dispatch point. Use the native
broker's `reconcile_request` for uncertain credential issuance; record requested
revocation separately from confirmed downstream denial and session termination.
Keep credentials out of prompts, process arguments, contracts and evidence.

Verify only owned task changes. Preserve failures and all acceptance criteria.
Use independent review plus deterministic checks or actual consequences; a
subagent's success report is not acceptance. Cite the concrete evidence and
scope of qualification. In particular, the local demo does not qualify
production OS authority separation, another live provider configuration or useful application outcomes.
See [dependency status](../../docs/DEPENDENCIES.md) before any external-provider
installation; this skill does not waive dependency or quarantine gates.
