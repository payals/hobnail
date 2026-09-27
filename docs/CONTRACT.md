# Hobnail protocol 1

This is the implementation contract for the maintained framework. The original
`work` / `eval` reference schema is a separate compatibility surface. It is not a
substitute for this protocol's artifact, policy, identity, and effect bindings.

The goal is independently justified acceptance of exact work and authorized,
observable protected effects. Passing tests is a check of named mechanisms, not
proof of useful project outcomes or containment of an arbitrary deployment.
Runtime actors must not change the policy, required checks, identity registry,
credential profiles, or evidence used to judge their work.

## Transport and common types

The language-neutral database entry point is:

```sql
SELECT hobnail.api(operation text, payload jsonb) RETURNS jsonb;
```

The Python transport invokes an existing `psql` without a shell and without new
Python dependencies. Each call commits independently. It must use an actual
restricted login, never a superuser session followed by `SET ROLE`. Connection
passwords, vault tokens, and downstream credentials are not API payload fields.

Success:

```json
{"ok":true,"status":"submitted","data":{"candidate_id":1,"binding_digest":"64 lowercase hexadecimal characters"},"event_id":1}
```

Business refusal:

```json
{"ok":false,"status":"denied","code":"MISSING_CHECKS","detail":{"checks":["metrics"]},"event_id":2}
```

Denials return normally so the caller can commit their audit record. An explicit
caller rollback, transport failure, database outage, or SQL permission error may
prevent a durable denial record. Such a failure is never an authorization. The
SDK does not retry an uncertain mutating call with a different idempotency key.

Protocol values are strict: unknown operation/fields, null where not explicitly
allowed, malformed types, and out-of-range values are refused. The SDK's raw JSON
parser rejects duplicate object keys. PostgreSQL receives an already normalized
JSONB value and cannot recover duplicate keys discarded by a caller's earlier
JSON-to-JSONB conversion. A direct SQL integration must enforce that raw JSON
boundary itself. Declared check/source/principal arrays still reject duplicates.
Identifiers are nonempty ASCII `[A-Za-z0-9_.:/-]`, at most 128 characters.
Digests are 64 lowercase hex characters. Database IDs are positive integers;
versions are positive integers. Timestamps are UTC RFC 3339 strings. General
metadata is an object, at most 16 KiB serialized; it must contain no secrets.
Idempotency keys are identifiers, scoped to stable principal and operation.
Reusing a key for different arguments returns `IDEMPOTENCY_CONFLICT`.

The standard-library Python/CLI JSON transport refuses a numerical token whose
value would change after float parsing and JSON serialization; for example,
`0.10000000000000001` is refused rather than becoming `0.1`. Non-finite numbers
are refused. This transport limitation does not alter artifact or input bytes
submitted through `content_hex`; the isolated JSON validators compare numbers
using exact decimal values.

Limits: at most 64 checks, 16 sources, 16 actions, 128 JSON-pointer fields per
check, 2048 UTF-8 bytes per pointer, 1024 UTF-8 bytes per action target, and 1 MiB
per artifact or input. Binary content is even-length lowercase
`content_hex`; the database decodes it and computes its SHA-256. JSON protocol
and manifests are hashed by the server over UTF-8 `jsonb::text`. This is a
Postgres representation, not a cross-language canonical-JSON claim. Clients use
server-returned digests. JSON numbers used as integer budgets must be integers.

## Stable authority

The owner-only `principal.bind` operation has this payload:

```json
{"login":"worker_login","principal":"report-worker","role":"worker","contracts":["client-report"],"sources":[],"profiles":[]}
```

Roles are `worker`, `registrar`, `verifier`, `adapter`, `observer`, `approver`,
`credential_provider`, and `auditor`. The owner maps the authenticated
`session_user` to one stable principal, role and explicit scope. Wildcards are
unsupported. Multiple rotating logins may map to one principal; rotation never
creates a new independent authority. A runtime login cannot bind itself or
another login. Unknown logins are denied. Runtime roles have no table writes,
ownership, role administration, or access to privileged credential profiles.

`principal.bind` inserts one binding; it does not replace an existing login's
identity or grants. Rebinding returns `ALREADY_RECORDED`. Issue a fresh scoped
login and retire the old one through the supported credential lifecycle when a
new binding is needed. Expiry is managed through that lifecycle, not an extra
`principal.bind` payload field.

`session.get {}` returns the authenticated caller's `principal_id`, `role`,
`contracts` and `valid_until`. It accepts no identity fields and returns no
secret material. The optional MCP launcher uses this operation to confirm its
configured worker identity. This read is audited like other API operations.
The [typed SQL reference](TYPED-SQL.md) lists convenience wrappers that call the
same API with the caller's privileges.

Contract access requires both a registry contract grant and the contract's role
allowlist. Source registration requires both a registry source grant and the
active contract's registrar allowlist. Approval authority comes from the
protected registry, never from an unapproved proposal. A submitter cannot judge
its candidate, register its trusted inputs, or independently observe its effect.
The observer must also differ from the dispatching adapter principal. Owner and
database superuser compromise are outside these runtime authority guarantees.

## Contract document

`contract.propose` takes `{contract_id,version,document}`. The same operation is
used by manual authoring and assisted authoring. A complete document is:

```json
{
  "schema_version": 1,
  "description": "Independently check exact report bytes before local release",
  "access": {
    "workers": ["report-worker"],
    "verifiers": ["report-verifier"],
    "observers": ["report-observer"],
    "adapters": {"publish": ["report-publisher"]}
  },
  "subject": {"media_type":"application/json","max_bytes":1048576},
  "sources": [
    {"name":"orders","registrars":["source-registrar"],"require_current":true}
  ],
  "checks": [
    {
      "id":"metrics",
      "plugin":"json.equals",
      "plugin_digest":"<registered manifest digest>",
      "parameters":{"source":"orders","pairs":[{"artifact":"/orders","input":"/orders"}]},
      "max_age_seconds":3600
    }
  ],
  "actions": [
    {
      "name":"publish",
      "plugin":"file.publish",
      "plugin_digest":"<registered manifest digest>",
      "target":"reports/current.json",
      "arguments":{},
      "max_age_seconds":300
    }
  ],
  "budgets":{"verification":100,"effects":20,"research":20},
  "expires_at":"2027-01-01T00:00:00Z"
}
```

Contract `expires_at` uses canonical UTC with a trailing `Z` and at most six
fractional-second digits. Offset forms such as `+00:00` are refused locally,
matching the existing database wire rule; the SDK does not silently rewrite
the approved document's bytes.

This is an exact, closed shape. `description` is optional and limited to 2 KiB;
all other shown top-level fields are required. Arrays contain unique IDs or
principals. Checks and sources are nonempty. Actions may be empty. Every check
is mandatory and must pass; advisory material belongs in application metadata
and cannot silently satisfy a check. Source names in check parameters must exist
in the source list. Age limits range from 1 to 86400 seconds. Contract expiry
must be in the future at activation. Budgets are nonnegative integer caps no
greater than 1,000,000,000. `verification` and `effects` are required budget keys;
other keys authorize explicit `budget.consume` calls.

An action's `target` and `arguments` are exact approved values, not regexes,
shell fragments, prefixes, path traversal allowances, or worker-selected
destinations. Its protected adapter interprets the approved target relative to
an administrator-configured root or destination. Symlinks and mutable external
state require adapter-specific checks. Unsupported action plugins fail closed.

`contract.activate` takes
`{contract_id,version,expected_active_version:null|positive_integer}`. An
approver activates by compare-and-swap, after validating all registry grants,
plugin identities, supported parameters and capability coverage. Only one
version per contract is active. Approval and proposal are separate append-only
facts. Runtime workers may propose; they cannot activate. Activating a new
version immediately makes old candidates ineligible for new acceptance or
dispatch. Historical decisions, failures, reservations and spent budgets remain.
There is no automatic evidence carry-forward or budget-reset operation.

`contract.get {contract_id,version?}` returns the immutable document, policy
digest, proposal principal and approval/active state.

## Plugins and supported coverage

`plugin.register {plugin_id,version,kind,manifest}` is approver-only. `kind` is
`validator` or `effect`; a registration returns `plugin_digest`. The immutable
manifest declares `implementation`, `input_media_types`, `parameters`,
`capabilities`, `result_semantics`, and `execution_backend`. Manifest size is
limited to 16 KiB. Registration is not execution qualification.

The first deterministic validator vocabulary is:

| Plugin | Parameters | Passing meaning |
|---|---|---|
| `bytes.sha256` | `{"expected":"<digest>"}` | The independently retrieved exact artifact bytes hash to the fixed approved digest. |
| `json.required_fields` | `{"pointers":["/field"]}` | Each RFC 6901 pointer resolves in the artifact JSON. A present null value is present. |
| `json.equals` | `{"source":"source-name","pairs":[{"artifact":"/field","input":"/field"}]}` | Each pair resolves and its JSON values have the same type and value. Booleans are not numbers; `1` and `1.0` are numerically equal. |

JSON validators reject duplicate object keys, non-finite numbers, invalid UTF-8,
invalid pointers, excessive nesting and missing values. They do not establish
free-form prose truth or application integration. The empty pointer refers to
the whole JSON value; array indices are unsigned decimal integers without
leading zeroes. `-` does not resolve an existing array member.

A developer validator uses an ID beginning `custom:`, manifest kind `validator`,
backend `isolated-json`, and the exact SHA-256 of a reviewed single-file Python
script. Its capability list is limited to `read_artifact` and `read_inputs`.
Check parameters are a bounded metadata object; the contract contains no script
path, import path, shell command or executable content. An administrator's
protected controller configuration maps implementation digests to reviewed
scripts. The controller checks and snapshots the exact bytes before restricted
execution; no custom code is imported into the credentialed controller.

The child reads one JSON object from stdin:

```json
{"content_hex":"7b7d","plugin_id":"custom:report-metrics","parameters":{},"inputs":{"orders":"7b7d"}}
```

It writes exactly `{"result":"pass|fail|error|inconclusive","detail":{...}}`
as JSON to stdout. Output, input, execution time and detail sizes are bounded;
invalid output or timeout is an error. A missing configured implementation,
changed implementation digest or unavailable isolation cannot pass and records
an inconclusive result. Scripts use the Python standard library available in
the qualified runtime. This is reviewed developer code running against
untrusted candidates, not a guarantee of containment for arbitrary hostile code.

The selected execution backend must be separately qualified. A manifest that
merely asserts isolation cannot establish it. Unsupported mandatory plugins
produce `UNSUPPORTED_CAPABILITY`; they are not treated as advisory. Built-in
code also parses candidate data outside the credentialed controller in the
supported deployment. Same-user subprocesses alone do not qualify isolation.

`coverage.inspect {contract_id,version}` returns one entry per requirement with
`implemented`, `external`, or `unsupported`, plus the concrete mechanism and
qualification requirement. No contract field can assert a deployment is safe.

## Artifacts, inputs and acceptance

| Operation | Payload | Caller / outcome |
|---|---|---|
| `artifact.put` | `{content_hex,media_type}` | Worker; immutable `{artifact_id,digest,size}`. |
| `input.put` | `{contract_id,source,version,content_hex,media_type,expected_current}` | Authorized registrar; `expected_current` is null or snapshot ID; CAS installs immutable snapshot and updates the source's current pointer. Returns `{snapshot_id,digest}`. |
| `candidate.submit` | `{contract_id,artifact_id,inputs,idempotency_key}` | Worker; `inputs` maps every declared source to one snapshot ID. Returns `{candidate_id,binding_digest}`. |
| `candidate.get` | `{candidate_id}` | Scoped runtime reader; exact binding, current decision, required-check results and refusal reasons. |
| `verification.claim` | `{candidate_id,lease_seconds}` | Independent verifier; returns `{token,generation,lease_until,binding_digest,artifact,inputs,contract,checks}`. |
| `verification.record` | `{candidate_id,token,generation,binding_digest,check_id,plugin_digest,result,detail}` | Claimed verifier; `result` is `pass`, `fail`, `error` or `inconclusive`. Immutable, one result per required check per generation. |
| `candidate.accept` | `{candidate_id}` | Scoped worker or verifier; computes and records the authoritative current decision. |

The binding digest commits to protocol version, stable submitting principal,
contract ID/version/digest, artifact digest, and the sorted complete source
name/snapshot ID/digest set. Check results additionally bind check ID, approved
plugin digest, evaluation generation, authenticated verifier and observation
time. A result for different bytes, inputs, policy, plugin or generation cannot
be transferred. The registry hashes the actual bytes; supplied digests do not
establish byte identity. Submission must own or be authorized to use its artifact.

Verification leases range from 1 to 300 seconds, use `clock_timestamp()`, and
require token, generation and principal on every mutation. At most one live
generation exists per candidate. Reclaiming an expired lease fences old writers
and consumes another verification unit; every prior result remains visible.
Results from different generations cannot be assembled into a complete set.
After a complete generation with any non-pass result, that candidate is refused;
new verification requires a new candidate, not replacement of the failing row.

Acceptance requires exactly the declared complete check set, all `pass`, current
generation, authorized independent identity, approved plugin identities,
unexpired evidence, active policy, current required inputs, and unexpired
contract. There must be at least one check. Missing evidence is not a pass.
An acceptance receipt records what was true then; a current eligibility query
and every protected dispatch recheck time-sensitive preconditions. A current
input change or policy activation invalidates eligibility without rewriting the
historical receipt. Database locks serialize competing policy/input/cancellation
changes and admissions at the documented authorization point.

Migration 006 adds an immediate insertion check and a foreign-key relationship
from every acceptance receipt to its immutable proof. The proof records the
exact candidate/generation/binding and complete declared passing check set,
including plugin and independent verifier identities. It does not recreate
historical login authorization or consult current input heads, policy heads or
the clock when validating an old receipt. Upgrade backfill preserves existing
receipts and refuses inconsistent immutable evidence rather than inventing proof.
The use-time eligibility and dispatch checks above remain authoritative.

## Budgets

`budget.get {contract_id}` returns each active cap and lineage-wide consumption.
`budget.consume {contract_id,budget,units,idempotency_key}` atomically reserves
positive units for an allowed named purpose and returns `{reservation_id,used,
remaining}`. Consumption precedes the operation it permits. No refund, reset or
delete operation exists in protocol 1. A failed or uncertain operation still
consumed its reservation. Successful idempotent replay consumes nothing extra.

Counters are scoped to stable `contract_id`, never to version or temporary
login. Activation cannot erase prior consumption. A reduced cap below existing
consumption permits no new consumption. Every new verification generation
consumes one `verification` unit; every new effect reservation consumes one
`effects` unit. Explicit `budget.consume` cannot consume those two reserved
internal categories. Research plugins must bind their immutable experiment
identity to the returned reservation before beginning an evaluation.

## Protected effects and recovery

| Operation | Payload | Meaning |
|---|---|---|
| `effect.request` | `{candidate_id,action,args,idempotency_key}` | Worker; binds exact accepted work, approved action/target/arguments, active policy, expiry and budget reservation. Returns `{effect_id,state}`. |
| `effect.claim` | `{effect_id,lease_seconds}` | Approved adapter; returns lease token/generation and exact immutable artifact, action, target and arguments. |
| `effect.dispatch` | `{effect_id,token,generation}` | Adapter; atomically rechecks authority and records the durable dispatch point before external I/O. |
| `effect.report` | `{effect_id,token,generation,outcome,receipt}` | Adapter; `outcome` is `attempted`, `uncertain` or `failed`. Never observed completion. |
| `effect.observe` | `{effect_id,outcome,artifact_digest,receipt}` | Independent observer; outcome is `complete`, `absent`, `mismatch` or `unknown`. Digest is required for `complete`, otherwise null is allowed. |
| `effect.cancel` | `{effect_id}` | Requesting worker or scoped approver; blocks undispatched work and requests supported revocation. |
| `effect.get` | `{effect_id}` | Scoped reader; authorization, dispatch, cancellation and observations remain distinct facts. |

`args` must equal the contract action's `arguments` as JSONB. The target comes
from the approved action, never the request. The adapter consumes the bytes
returned by the authoritative claim, verifies the digest immediately before
use, and enforces target confinement at the consumer. An adapter claim is not
dispatch permission. The `effect.dispatch` call must commit before acting.

State progression is `reserved -> dispatched -> attempted|uncertain|failed`,
with independent observation producing `complete`, `failed` or `reconcile`.
`reserved -> cancelled` is allowed. Cancellation after dispatch sets a separate
cancel-requested fact; it cannot claim the action was prevented or undone.
Expired adapter leases before dispatch may be reclaimed and old tokens are
fenced. After dispatch, a lost response or expired lease requires reconciliation;
there is no automatic redispatch. Supported adapter-specific idempotency may
allow a reconciler to recover an existing dispatch, never create a different
intent under the same key. Compensation requires another authorized effect.

Only an independent matching observation can establish `complete`. An absent
observation does not prove the effect never happened unless the adapter's
observation contract establishes that fact. A mismatch or an observed effect
without valid authorization records `control_failure` and preserves both the
refusal and observation. Neither a denial log nor an adapter success return can
override observed reality. External systems are not part of a Postgres atomic
transaction, and protocol 1 does not promise universal exactly-once effects.

## Credential provider contract

Providers are replaceable. The supported provider authenticates a stable
workload independently and maps a profile to narrowly scoped credentials. A
worker cannot request verifier, adapter, approver or provider authority merely
by naming that profile. Provider authentication, framework operation authority,
and downstream credentials are separate capabilities.

Profile configuration is owner-managed outside worker contracts through
`credential.profile`, using an actual installer/superuser connection:

```json
{"profile":"worker-basic","provider":"credential-issuer","principals":["report-worker"],"role":"worker","max_ttl_seconds":300,"max_lifetime_seconds":3600,"renewable":true,"capabilities":["dynamic_postgres","renewal","revocation","active_session_termination"]}
```

The profile name is immutable; a changed profile uses a new name. Provider and
allowed principals must already be registered with that profile in their
registry `profiles` allowlists. The role must match the requester's current
role. TTL is 1–86400 seconds; maximum lifetime is between the TTL and 86400
seconds. `renewable:true` requires the `renewal` capability. These declared
capabilities do not themselves qualify actual provider behavior. Protocol 1
supports dynamic Postgres logins; other credential kinds fail closed.

A contract may require a profile but cannot widen it. Provider secrets and
issued secrets never enter database payloads,
receipts, audit exports, process arguments or candidate processes.

| Operation | Payload | Caller / result |
|---|---|---|
| `credential.request` | `{profile,ttl_seconds,idempotency_key}` | Profile-authorized principal; returns request ID, requested TTL and `requested`. |
| `credential.request.get` | `{request_id}` | The profile's provider; returns approved principal, profile, role, requested TTL and scope, without secret material. |
| `credential.issued` | `{request_id,lease_ref,login,expires_at,renewable}` | The profile's provider; registers a fresh login under the requesting stable principal and records `active`. Delivery of sensitive credential material is out of band to the authorized workload. |
| `credential.renew_requested` | `{credential_id,ttl_seconds}` | Credential's principal; records request, not effective extension. |
| `credential.renewed` | `{credential_id,expires_at}` | Provider; records actual renewal within configured maximum lifetime. |
| `credential.revoke_requested` | `{credential_id}` | Credential's principal or scoped approver; records requested revocation. |
| `credential.revoked` | `{credential_id,result,receipt}` | Provider; result is `confirmed`, `pending` or `failed`, preserving requested versus effective revocation. |
| `credential.get` | `{credential_id}` | Credential's principal, provider or auditor; safe metadata only. |

The provider interface implements `issue`, `renew`, `revoke` and `observe`.
Capability discovery explicitly distinguishes dynamic credentials, static
secrets, renewal, active-session termination and confirmed revocation. Requested
TTL cannot exceed profile limits. Database server time defines framework
expiry; provider-confirmed time cannot silently extend approved authority.
Time expiry or a successful revoke HTTP response alone does not prove existing
sessions terminated. Qualification must exercise the actual downstream denial
and active-session behavior. An unsupported requested capability is refused.

Issued logins receive the requester's captured role and scope, never a
provider-supplied role or principal. An existing or previously leased registry
login cannot be rebound or reused. The source principal must still be enabled
with identical scope. A native provider creates a fresh unprivileged login,
grants only schema usage and API execution, and records a protected role comment
`hobnail-credential-v1:` followed by JSON containing `provider`, `request_id`,
`profile`, `principal`, `role`, `ttl_seconds`, `lease_ref`, actual role `oid`,
and `created_at`. Registration verifies that metadata against the approved
request, actual role and expiry. The issuance request expires after five
minutes. Credentials do not become API authority until this binding succeeds.
An OpenBao configuration without equivalent registered provenance is unsupported
for framework-login issuance; availability of its HTTP adapter is insufficient.

The mapped principal expires using database wall-clock time, including existing
sessions. Renewal requires a prior pending request, its TTL and the original
maximum lifetime, and an actual matching Postgres role expiry. Requested
revocation immediately disables framework API authority while downstream
revocation remains pending. A confirmed native revocation also requires no
login-enabled role and no remaining active sessions. Safe credential metadata
includes role, login, lease reference, original issuance, actual expiry and any
pending renewal's approved `renewal_ttl` so a
provider can reconcile a restart without recovering or exposing a password.

## Evidence, qualification and operational limits

`audit.export {after,limit}` is auditor-only, with `after >= 0` and
`1 <= limit <= 1000`. It exports ordered, redacted append-only facts and chain
verification state. Seal all security-relevant fields, including detail,
principal, target, result and metadata. The sealer uses a lock and sequence
discipline that remains valid under supported concurrent transactions. A local
hash chain does not prove an administrator did not rewrite or truncate all
history; an external trusted checkpoint is required for that stronger claim.

`qualification.record {configuration_digest,checks,expires_at}` is restricted
to the separately bound approver. Each check is
`{id,result,evidence}` with result `pass`, `fail`, `error` or `unsupported`.
`qualification.get {configuration_digest}` returns the most recent 100 records
with explicit expiry and `grants_authority:false`. Records contain 1–64 unique
check IDs, and expire within seven days. Registration or a supplied `passed:true` is not a deployment
qualification. The qualification runner must exercise actual restricted
identities and real controlled consumers; the record only preserves results.
Configuration changes and expired records remove current qualification claims.

Qualification separates `acceptance_integrity` from `restricted_execution`.
The latter additionally requires real evaluator isolation, credential
confinement, network boundaries and exclusive adapter authority. Absence of an
applicable actual probe refuses that claim. Neither Docker nor two different
temporary usernames is sufficient evidence by itself.

## Stable refusal codes

`INVALID_REQUEST`, `UNKNOWN_OPERATION`, `UNAUTHENTICATED`, `FORBIDDEN`,
`NOT_FOUND`, `SCOPE_MISMATCH`, `SELF_JUDGING`, `UNSUPPORTED_CAPABILITY`,
`POLICY_INACTIVE`, `POLICY_EXPIRED`, `VERSION_CONFLICT`,
`IDEMPOTENCY_CONFLICT`, `ARTIFACT_MISMATCH`, `INPUT_MISMATCH`, `INPUT_STALE`,
`BINDING_MISMATCH`, `PLUGIN_MISMATCH`, `MISSING_CHECKS`, `CHECK_FAILED`,
`EVIDENCE_STALE`, `LEASE_EXPIRED`, `LEASE_MISMATCH`, `ALREADY_RECORDED`,
`BUDGET_EXHAUSTED`, `ACTION_MISMATCH`, `CANCELLED`, `RECONCILIATION_REQUIRED`,
`OBSERVATION_MISMATCH`, `CREDENTIAL_SCOPE`, `CREDENTIAL_EXPIRED`,
`REVOCATION_PENDING`, `QUALIFICATION_REQUIRED`, and `CONTROL_FAILURE`.

Transport errors and unexpected implementation exceptions are reported
separately from these business refusals. They must never be translated into a
passing check or a completed effect. Details may add machine-readable check
IDs and safe mismatched digests, but must not leak credentials or private data.

## Frozen acceptance cases for protocol 1

1. A real worker login cannot write protected tables, bind principals, activate
   policy, register plugins, forge a verdict, assume verifier identity, or obtain
   a privileged credential profile. Rotated logins do not evade self-judging.
2. Independently supplied exact artifact/input bytes with all mandatory checks
   passing can be accepted. Missing, failed, error and inconclusive checks each
   refuse. Unknown or duplicate checks and wrong validator manifests refuse.
3. Changed bytes, source snapshots, policy versions and expired evidence cannot
   reuse a previous acceptance. A concurrent policy/input update has a defined
   ordering with admission/dispatch and leaves no mixed binding.
4. An expired or replaced verifier/adapter token refuses even inside a
   transaction that began before the deadline. Old-generation results cannot
   complete a new generation's check set. Concurrent budget consumption never
   exceeds the cap; policy amendment and retry never reset consumption.
5. Effect target/arguments cannot widen approved scope. The controlled consumer
   receives exactly the accepted bytes. Duplicate intent requests preserve one
   reservation. Reusing an idempotency key for changed work refuses.
6. Crash before dispatch permits safe claim recovery; crash after dispatch
   preserves uncertainty and requires observation before any recovery action.
   Cancellation prevents later dispatch but does not erase an already observed
   effect. Attempted dispatch never counts as observed completion.
7. An independent mismatching or unauthorized observed effect records a control
   failure. Both denial and reality remain visible. No aggregate score hides it.
8. Credential requests enforce real profile ACLs, TTL and renewal bounds;
   revocation pending/failure remains distinct from effective downstream denial,
   including existing sessions. Secret values never appear in evidence exports.
9. Runtime evidence mutation refuses. Concurrent seals verify. Tampered fields,
   broken links and disabled enforcement are detected, with administrator and
   truncation limits stated. Malformed/untrusted JSON never runs with verifier
   credentials. Missing isolation refuses the restricted-execution claim.
10. Fresh install, upgrade from the reference schema, and backup/restore retain
    actual grants, policy versions, evidence, reservations and reconciliation
    requirements. The existing refusal suite stays intact. Independent review
    and real application outcomes are reported separately from fixture results.

The cases above are fixed before implementation tuning. A measurement defect
requires separate authorization and independent evidence to change; a failing
case is not made to pass by weakening its check or narrowing its label.
