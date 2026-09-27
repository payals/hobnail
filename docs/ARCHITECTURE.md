# How Hobnail gates agent work

Hobnail combines a PostgreSQL control plane, a Python SDK/CLI, protected
verification processes, and adapters that perform and observe approved actions.
Your application still owns planning, the meaning of a correct result, and its
trusted input sources. Hobnail is not an agent runtime or a retrieval system.

The integration boundary is an interface and a database identity, not a coding
agent brand or billing method. A developer can use a subscription-backed agent,
an API-backed application or a local model through supported MCP, SDK or CLI
calls. Provider authentication stays outside Hobnail's core. Your client's tool
support and provider terms determine which connection route is available;
changing agent software never grants a different database role or approval power.

For example, an application can require a warehouse report's quantity to match
an independently registered stock snapshot. A worker submits the report bytes;
a verifier checks them; PostgreSQL decides whether the exact work is accepted;
an adapter publishes the permitted file; an observer checks what was written.
Changing the bytes or invalidating the input prevents reuse of old acceptance.

## The maintained database entry point

The maintained wire entry point is
`hobnail.api(op text, payload jsonb) RETURNS jsonb`, implemented in PL/pgSQL as a
`SECURITY DEFINER` function. Operation-specific validation checks the JSON
fields and values. A small set of [typed SQL functions](TYPED-SQL.md) delegates
to this same dispatcher. They provide explicit signatures without duplicating
authorization, evidence checks, idempotency or audit logic.

Runtime principals have no direct table/sequence access or permission to call
internal kernel functions. `PUBLIC` has schema usage and permission to
execute the API; the API then authenticates `session_user` against the registered
principal and checks capabilities and contract scope. Typed wrappers run with
the caller's privileges and retain that same API boundary. An unbound login cannot
obtain authority just because it can invoke the entry point. All kernel
functions use the fixed trusted search path `pg_catalog,hobnail,pg_temp`.

The database owner and superusers remain trusted. A worker must not hold those
credentials or alternate write access to a target whose protection it claims.
The boundary is the actual grants, identities and permitted API behavior, not
merely a Python method name or a JSON tool schema.

Implementation: [maintained migration](../migrations/001_hobnail.sql),
[trusted catalog resolution](../migrations/004_trusted_catalog_resolution.sql),
and [wire contract](CONTRACT.md).

## What is inside each transaction

Each API operation places its state changes and audit append in the caller's
PostgreSQL transaction; keyed operations include their replay record there.
The shipped SDK commits each call independently. A direct SQL caller can group
calls in an explicit transaction or roll it back. Budget updates and admission use
locks; verifier leases include time, generation and stable-principal fencing.
An accepted API response is durable only after its transaction commits.
A caller rollback, SQL error or lost transport can require reconciliation;
there is no promise that every attempted refusal survives a rollback.

A complete workflow spans several transactions. Claiming verification,
recording each check, accepting a candidate, dispatching an effect and observing
it are distinct API calls. Hobnail does not hold a database transaction open
while a model runs, and it does not put every check and the final answer in one
transaction.

File writes, Git commits and external research records are outside PostgreSQL's
transaction. The database authorizes and records dispatch; a separate observer
confirms the consequence. A lost reply may leave an uncertain effect that must
be reconciled against the existing effect and dispatch identity. This is not universal exactly-once
execution, and cancellation after dispatch cannot undo an external action.

## Which checks run where

Protected Python verifiers execute the approved builtin or custom validators.
They record results bound to the artifact, input snapshots, policy, plugin
identity, lease and verifier identity. PostgreSQL rechecks those bindings,
required-check completeness, current authority and freshness before accepting.
It does not rerun arbitrary Python content validators inside PL/pgSQL.

An immediate insertion trigger also binds each acceptance receipt to an
immutable proof of its complete passing check set. The proof binds the recorded
candidate, generation, bytes, inputs, policy and plugin identities. This is a
structural backstop against an incorrect kernel write. It does not recreate
historical credential authorization or re-run freshness checks against an old
receipt. Later input, policy or time changes can invalidate current eligibility
while the historical receipt remains intact. There is no blanket deferred
commit-time freshness trigger.

For example, the Python validator can compare a JSON quantity with a registered
input value. The database ensures the required comparison result belongs to
this exact work, an authorized verifier and the current approved contract.
A worker's own claim is not an independent verdict. A poorly chosen contract
can still measure the wrong thing; applications must define meaningful checks.

Implementation: [verifier controller](../src/hobnail/verifier.py),
[validator execution](../src/hobnail/validators.py), and
[acceptance tests](../tests/test_kernel_acceptance.py).

## MCP, typed functions and extension points

| Capability | What ships today |
| --- | --- |
| PostgreSQL enforcement | Maintained protocol-1 schema, PL/pgSQL API, role/scope checks, exact-work admission, budgets, leases, audit and effect lifecycle. |
| Typed operation interfaces | Explicit SECURITY INVOKER SQL wrappers and Python SDK methods share the validated API. Existing JSON callers remain compatible; there is no SQL generator or separate typed-only privilege profile. |
| FastMCP / MCP server | Optional `hobnail-mcp` distribution with seven worker tools over stdio, strict inputs, database-verified configured identity and explicit errors. Its reviewed dependencies are separate from the dependency-free core. |
| Contract authoring | Manual or assisted authoring with local validation and non-authoritative discovery suggestions. Activation is separate. |
| Custom validators | Reviewed single-file implementations, immutable manifests and digests, protected implementation registration and supported isolated execution. Docker currently accepts only the reviewed builtin validators. |
| Transport and credentials | Python transport and credential-provider interfaces for deliberate integrations. Implementing an interface does not qualify its security boundary. |
| Effect consumers | Builtin file publication, local Git commit and create-only research records. New effect kinds require kernel and consumer support plus verification; this is not an open-ended action loader. |
| PostgreSQL extension packaging | Not a `CREATE EXTENSION` package. The source installer applies additive SQL migrations; the Python package installs the SDK/CLI. |
| Workflow orchestration / retrieval | Supplied by your existing agent or application. No generic DAG scheduler, retrieval index or agent planner is shipped as part of the maintained protocol. |

The [MCP adapter](MCP.md) calls the SDK as one configured worker. It exposes no
raw SQL, arbitrary operation, credential selection or privileged-role tools.
PostgreSQL still enforces authority and acceptance. The adapter does not approve
contracts, acquire trusted inputs, run verification or publish effects itself;
those services retain separate identities. Stdio is a transport, not process
isolation. The [integration guide](INTEGRATION-TESTING.md) explains the actual
end-to-end checks and application integration boundary.

To build an application today, start with the
[native application example](NATIVE-APPLICATION.md) and
[contract authoring guide](AGENT-GUIDE.md#propose-a-complete-contract).
Custom validators are described in [the contract reference](CONTRACT.md).

## The legacy SQL example is a different surface

The separate `schema/` directory and root `install.sql` contain the earlier
`work`/`eval` example. It has typed per-operation functions, per-role execute
grants, a `SKIP LOCKED` queue and a deferred verification trigger that refuses
an unsupported state change at commit. These illustrate the database-gate
pattern; they are not the maintained `hobnail` protocol-1 implementation.

Use `migrations/` and `scripts/install.py` for the maintained framework. Do not
run the root legacy installer as a shortcut for installing protocol 1 or count
the legacy example as evidence that the maintained API includes its exact
function signatures, queue or deferred-trigger design.

The legacy verifier login remains `grader_role` for installed-role and
authentication-map compatibility. Current documentation and protocol roles use
**verifier**. Naming consistency does not change the authorization model.

[Installation](INSTALLATION.md) · [Operations](OPERATIONS.md) ·
[Support boundaries](SUPPORT.md) · [Security](../SECURITY.md)
