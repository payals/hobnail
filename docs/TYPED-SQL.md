# Typed SQL operations and acceptance proofs

The typed functions give SQL clients named arguments and PostgreSQL types for
common protocol-1 operations. Every function returns the same JSON receipt as
`hobnail.api(op, payload)`. The API still decides who may act, what checks are
required, and whether the exact work is eligible.

This reference covers the interfaces added in Hobnail 0.3.0. Start with
[installation](INSTALLATION.md) for the SDK and PostgreSQL prerequisites, or
[MCP](MCP.md) to connect an agent through the optional worker adapter.

[Functions](#function-reference) ·
[Runnable example](#see-the-interfaces-agree-in-an-owned-database) ·
[Authority and errors](#authority-and-error-behavior) ·
[Historical proof](#what-an-acceptance-proof-establishes) ·
[Upgrades](#installation-upgrades-and-compatibility)

## Function reference

All names below are in the `hobnail` schema and return `jsonb`. Argument order
is significant for positional calls. PostgreSQL named notation is also valid.

| Function and arguments | Delegated API operation |
| --- | --- |
| `session_get()` | `session.get` |
| `contract_propose(contract_id text, version integer, document jsonb)` | `contract.propose` |
| `artifact_put(content bytea, media_type text)` | `artifact.put` |
| `candidate_submit(contract_id text, artifact_id bigint, inputs jsonb, idempotency_key text)` | `candidate.submit` |
| `candidate_get(candidate_id bigint)` | `candidate.get` |
| `verification_claim(candidate_id bigint, lease_seconds integer DEFAULT 60)` | `verification.claim` |
| `verification_record(candidate_id bigint, token uuid, generation integer, binding_digest text, check_id text, plugin_digest text, result text, detail jsonb)` | `verification.record` |
| `candidate_accept(candidate_id bigint)` | `candidate.accept` |
| `budget_get(contract_id text)` | `budget.get` |
| `budget_consume(contract_id text, budget text, units bigint, idempotency_key text)` | `budget.consume` |
| `effect_request(candidate_id bigint, action text, args jsonb, idempotency_key text)` | `effect.request` |
| `effect_get(effect_id bigint)` | `effect.get` |
| `effect_cancel(effect_id bigint)` | `effect.cancel` |

`artifact_put` converts `bytea` to the API's hexadecimal representation without
parsing or rewriting the bytes. The JSON arguments still follow the
[wire contract](CONTRACT.md): `inputs` maps each required source name to its
snapshot ID, `document` is a complete contract, and `args` must match the approved
action. SQL types do not replace those validations. Operations without a typed
wrapper remain available through the existing API.

`session_get()` returns an authenticated identity in the receipt's `data`:
`principal_id`, `role`, `contracts`, and nullable `valid_until`. PostgreSQL obtains
it from the actual `session_user` and registered principal. Callers cannot submit
an identity in its arguments. A connection pool using one database login presents
that login's identity, regardless of which agent made a request upstream.

## See the interfaces agree in an owned database

Run this from the checkout root with the existing `.venv` and PostgreSQL 18
binaries on `PATH`. It creates a fresh socket-only cluster, installs the schema,
binds one synthetic worker, compares the identity responses and stores exact
artifact bytes. It stops that cluster on exit and retains its directory.

```sh
.venv/bin/python - <<'PY'
import json
from scripts.dev_cluster import DevCluster
from scripts.install import install

with DevCluster(database="typed_sql_example") as cluster:
    dsn = (f"host={cluster.socket_dir} port={cluster.port} "
           f"dbname={cluster.database} user=postgres sslmode=disable")
    first = install(dsn, str(cluster.bin_dir / "psql"))
    assert install(dsn, str(cluster.bin_dir / "psql")) == first
    cluster.psql("CREATE ROLE typed_sql_worker LOGIN NOSUPERUSER NOCREATEDB "
                 "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS")
    binding = cluster.psql("""
        SELECT hobnail.api('principal.bind', '{
          "login":"typed_sql_worker", "principal":"typed-sql-worker",
          "role":"worker", "contracts":[], "sources":[], "profiles":[]
        }'::jsonb)
    """)
    assert json.loads(binding.stdout)["ok"] is True

    def worker(sql):
        return json.loads(cluster.psql(sql, user="typed_sql_worker").stdout)

    typed = worker("SELECT hobnail.session_get()")
    generic = worker("SELECT hobnail.api('session.get', '{}'::jsonb)")
    assert typed["ok"] is True and generic["ok"] is True
    assert typed["data"] == generic["data"]
    stored = worker("""
        SELECT hobnail.artifact_put(
            content => convert_to('{"total":7}', 'UTF8'),
            media_type => 'application/json')
    """)
    assert stored["ok"] is True
    print("Authenticated role:", typed["data"]["role"])
    print("Typed and generic identity agree:", typed["data"] == generic["data"])
    print("Artifact stored:", stored["ok"])

print("Owned cluster stopped; retained directory:", cluster.root)
PY
```

The first three printed lines are `Authenticated role: worker`,
`Typed and generic identity agree: True`, and `Artifact stored: True`.
Each API call has its own audit event, so compare the returned identity rather
than expecting identical event IDs. This example uses local socket trust for
synthetic SQL identities. Processes sharing its OS identity can impersonate those
logins. It demonstrates the SQL interface, not protected service isolation or
accepted work. Use the [MCP workflow](MCP.md) for the separate protected services.

## Authority and error behavior

The wrappers are `SECURITY INVOKER` functions with a fixed trusted search path.
They call the existing `SECURITY DEFINER` API with fixed operation names.
`PUBLIC` may execute both the wrappers and the API; principal registration,
role, contract scope and current authorization still decide which calls succeed.
This migration does not introduce a typed-only access policy. Runtime principals
still cannot write protected tables or call the internal dispatcher. Owners and
superusers remain trusted.

The wrappers use `CALLED ON NULL INPUT`, rather than silently returning SQL
`NULL`. Required null arguments reach the common validation path. A type error
such as a string that cannot be converted to `bigint` happens before the function
body and produces a SQL error instead of an API receipt. Clients must handle both
SQL errors and JSON refusal envelopes. Do not invent an audit event for a call
that never reached the API.

An API refusal normally has `ok: false`, `status: "denied"`, a `code`, and an
`event_id`. Its audit event is durable only when the enclosing transaction
commits. Rolling back an explicit transaction also rolls back its audit records.
An accepted API response likewise needs a committed transaction. Keep model
calls, content validation and external effects outside database transactions.

Typed calls preserve idempotency and effect semantics. After a lost response,
retain the original request and idempotency key and reconcile it before retrying.
A previously dispatched effect may already exist outside PostgreSQL. A new key
is not a recovery mechanism; cancellation cannot undo an external action that
already happened. See [operations](OPERATIONS.md) and
[integration recovery checks](INTEGRATION-TESTING.md).

## What an acceptance proof establishes

An acceptance now references an immutable proof keyed by candidate ID,
verification generation and binding digest. A `BEFORE INSERT` trigger builds or
checks that proof before the acceptance row is inserted. A composite foreign
key binds the acceptance to the proof immediately; it is not a deferred trigger
that waits until commit to recheck the current clock.

The proof checks the artifact and input bytes against their digests, the
candidate's exact policy and binding, and a complete set of passing results for
the recorded generation. Check IDs, plugin identities and verifier identities
must match the contract. The verifier and registrars must be independent of the
worker as required by that recorded contract. The stored document includes the
binding and ordered result identities, plugins, verifier and observation times;
its digest is computed in PostgreSQL.

This is a structural backstop for historical evidence. It does not rerun Python
validators or reconstruct historical credential authorization. It does not
prove the contract measured the right outcome, nor does it prevent a trusted
administrator from disabling enforcement.

Current eligibility remains separate. The normal API checks current policy,
source/evidence freshness and authorized identities before accepting work or
dispatching an effect. Verification and adapter mutations also enforce their
applicable lease fences. A later policy change, source update or expiry can
prevent a new action
without deleting an earlier acceptance. The proof backfill deliberately uses
immutable recorded facts; it does not invalidate history because time passed or
a principal was subsequently revoked.

## Installation, upgrades and compatibility

[Migration 005](../migrations/005_typed_operations.sql) adds the typed interfaces
and authenticated session description. [Migration 006](../migrations/006_acceptance_proofs.sql)
adds proofs and inserts one for each distinct existing acceptance identity. It
preserves existing acceptance rows. If existing evidence cannot support a proof,
the transactional migration fails and rolls back; do not rewrite old evidence
or migration checksums to make it pass.

Use the maintained [installer](../scripts/install.py) through the explicit
administrative path in [operations](OPERATIONS.md).
The example above exercises the same fresh-install and repeated-install path.
On an existing deployment, retain an approved backup and use the matching
PostgreSQL tools before applying the update. The installer verifies previous
migration hashes, applies pending migrations transactionally and checks the
proof table's immutable trigger and acceptance trigger/foreign-key shape.

The JSON API remains protocol 1; existing clients can continue to use it.
The optional MCP adapter requires `session.get` and refuses startup against an
older database that lacks it. Repeating the current installer is supported;
running an older installer against a newer database refuses. There is no
automatic downgrade or history rewrite. Recovery uses the reviewed backup and
matching source version, with uncertain external effects reconciled separately.

[Architecture](ARCHITECTURE.md) · [Wire contract](CONTRACT.md) ·
[Support boundaries](SUPPORT.md) · [Security](../SECURITY.md)
