# Security and support boundaries

Hobnail protocol 1 protects acceptance and named effects in an explicitly
configured deployment. It does not establish the semantic completeness of a
contract, protect against a compromised administrator, or make arbitrary agent
code safe. The tested local configuration is described in [OPERATIONS](docs/OPERATIONS.md).

## Trusted components

The database administrator and `hobnail_owner`, approved control-plane code,
credential issuer, protected verifier controllers, approved validator code and
effect/observation controllers are trusted. Runtime workers are not policy
approvers or verifiers. A rotating login retains its stable workload identity;
new usernames do not create independent authorities.

The application must remove alternate authority for an effect it claims to
protect. A worker with filesystem access to the publisher root or write access
to a protected Git repository can bypass an SDK. Protect controller code,
configuration, target directories and credentials from the worker's execution
environment. The original local demo reports mechanism evidence. The separately
tested [native role deployment](docs/NATIVE-DEPLOYMENT.md) confines each role's
configuration, execution, network and destination access while trusting the
operator/supervisor and other unsandboxed processes of the same OS user. Its
file-workflow qualification is specific to the tested configuration.

## Evidence and action semantics

Acceptance binds exact bytes, trusted input snapshots, policy version, complete
checks, validator identities, generation and freshness. A passing check proves
only its declared meaning. A human-approved but incomplete contract remains
incomplete. Discovery suggestions and LLM recommendations never activate policy.

An API `ok` means the operation was recorded successfully. It does not by itself
mean a candidate passed or an action completed: inspect `status`, `data.state`,
the authoritative acceptance result and the independent observation. In
particular, recording an observed `control_failure` is a successful recording
of failure. Historical idempotent receipts are not renewed authority.

External actions have a durable dispatch point and a separate observed result.
A timeout can leave an unknown outcome. Inspect the existing effect and use its
observer/reconciliation procedure; do not issue a new intent to hide or repeat
an unresolved action. Cancellation does not undo an already dispatched effect.
Git and filesystem locks require the documented exclusive/cooperating-writer
assumptions and do not fence an administrator editing files behind the adapter.

## Credentials and audit

Supply runtime secrets explicitly and keep them out of contracts, artifacts,
metadata, receipts, command arguments and source control. The provider's secret
value has a redacted representation; applications must not log `.reveal()`.
The SDK and installer do not discover personal libpq credentials or services.

PostgreSQL password expiry blocks new authentication, not all existing
sessions. Hobnail checks current expiry for API calls; confirmed native provider
revocation additionally requires login denial and no surviving role sessions.
Lost issuance/renewal replies need reconciliation of both provider state and
kernel metadata. OpenBao protocol tests are not a live OpenBao qualification.
The exact native OpenBao reference has a separate
[real qualification record](docs/OPENBAO-QUALIFICATION.md); its artifact,
configuration and trusted-supervisor limits do not extend to other deployments.

Audit exports hash the server's exact canonical event bytes. Verification from
genesis establishes internal consistency. An authentic checkpoint retained by a
separate authority establishes continuity from that point; a database-supplied
checkpoint alone is not independent. Administrators can rewrite the database,
and a chain cannot prove the truth of statements or the absence of unrecorded
real-world effects. Redaction covers named sensitive fields, not arbitrary
secrets concealed in application data.

## Supported operation and changes

Use only qualified runtime combinations and reviewed, exact plugin
implementations. The local macOS backends confine bounded single-file data
validators and explicitly configured service processes; they are not a general
sandbox-escape guarantee. Qualification probes use separate fixed code under
the same resource profile; production controllers expose no diagnostic write
command. Code/profile fingerprints are historical evidence, not complete
deployment seals. Research budgets count
approved work units; they are not a database connection or denial-of-service
rate limiter. Configure operational resource limits separately.

No migration may silently weaken an invariant, change applied migration bytes,
reset consumed budgets or reinterpret old failures. This repository is currently
unpublished; migration files are under active development. Once deployed as a
released revision, preserve its hashes and add a new migration for changes.
Recovery verifies effective privileges as well as persisted data. Requalify
affected boundaries after code, policy, credential or deployment changes.

## Reporting a problem

The current supported matrix and maintenance limits are in
[SUPPORT.md](docs/SUPPORT.md). Package 0.2.0 is being prepared for publication;
no public release or calendar support/response-time commitment is implied.

Use a private report to the deployment operator or maintainer with the exact
revision, supported configuration, expected invariant and a minimal synthetic
reproduction. Include observed refusal/effect records with secrets and personal
data removed. The planned GitHub target is `payals/hobnail`; this local
preparation does not claim a public issue tracker or disclosure endpoint is
active. Public release and disclosure are separate owner-authorized actions.

Before publishing code, the owner must establish a monitored private reporting
route. GitHub's private vulnerability reporting is available for public
repositories; a `SECURITY.md` file does not enable it. Use an established private
contact, or configure and verify reporting on an expressly approved empty public
repository before uploading code. Once that feature is actually enabled, use
the repository's **Security → Report a vulnerability** form.
Until then, use an already established private maintainer/operator channel;
do not publish the exploit or attach credentials while seeking a contact.
[GitHub's private reporting instructions](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

A useful report identifies the affected revision and configuration, the
authority boundary crossed, expected versus observed behavior, a minimal
synthetic reproduction and any known mitigation. Keep unrelated private data,
production secrets and raw sensitive logs out of the report. Acknowledge what
has actually been reproduced and preserve uncertainty about other versions or
deployments. Coordinate public disclosure and remediation through the
authorized maintainer process; no bounty or response deadline is promised here.

Release preparation and the settings that remain to verify are documented in
[RELEASE-GUIDANCE.md](docs/RELEASE-GUIDANCE.md). An unavailable reporting route
must remain an explicit public-launch blocker, not a fictitious email address,
account or enabled-service claim.
