# Compatibility, maintenance and deprecation

This policy describes the 0.2.0 source candidate and its maintained protocol-1
interfaces. Release checks must identify the exact candidate. Native and Docker
reference results are evidence for their recorded configuration, not a
transferable deployment certificate. The source repository is public; packaged release/deployment authority is separate. No support SLA or calendar response
commitment is promised.

## Installation by operating system

The SDK/CLI and portable source checks have a macOS/Linux path; the native
role/parser workflow is macOS-specific. Native Windows onboarding/runtime is
not supported in this release, and WSL2 is not separately tested. Docker is a
qualified reference with undistributed runtime/build inputs, not a published
image that users can install with one command.
[INSTALLATION.md](INSTALLATION.md) gives the exact available paths and prerequisites.

## Scope

| Surface | Checked reference scope | Limit |
| --- | --- | --- |
| Package/API | Package 0.2.0, protocol 1, `hobnail` schema | Legacy `work`/`eval` records have separate semantics. |
| Database | PostgreSQL 18.3 native and 18.6 in the Docker reference; installer requires major 18 | Other majors refuse. New minor versions need relevant checks. |
| Python | Python 3.14 native and 3.14.7 in the Docker reference | Python 3.11+ is the metadata compatibility target; not every version is tested. Use a project `.venv`. |
| Native execution | macOS role processes and restricted parser profile | The host and supervisor remain trusted. Unsupported mandatory backends refuse. |
| Credentials | Native PostgreSQL lifecycle and the exact reviewed OpenBao 2.6.2 Darwin arm64 reference | Other artifacts/configurations and production storage do not inherit qualification. |
| Consumers | Explicit native file publication, local Git commit, create-only research records | Each application's contract, destination and independent facts require review. |
| Recovery | Same-cluster restore with existing role identities and external effects preserved | Cross-cluster identity/issuer recovery and reconstruction of lost external effects are not established. |
| Docker/Linux | All eight frozen criteria passed on the exact Linux ARM64 archives, Docker Desktop 4.91.0 / Engine 29.8.0 / kernel 7.0.12-linuxkit; native PostgreSQL credentials and file publication | Trusted supervisor/daemon; builtin byte/JSON validators only. Docker OpenBao, custom plugins, Git/research consumers, other hosts/images and production operation remain unqualified. See [Docker deployment](DOCKER-DEPLOYMENT.md). |

The [native boundary](NATIVE-DEPLOYMENT.md), [OpenBao record](OPENBAO-QUALIFICATION.md)
and [security policy](../SECURITY.md) define the assumptions. A fingerprint,
successful API response or old receipt cannot qualify a changed deployment.
Portable CI deliberately reports a subset and does not certify native services.

## Version namespaces

Package versions identify distributed code. Protocol versions identify wire
meaning. Migration numbers identify schema changes. Contract and plugin
versions identify approved validation and action meaning. These namespaces
must not substitute for each other.

Preserve protocol-1 operation names, required fields, authority checks and
acceptance/effect meaning. Additive data cannot turn a previous refusal or
unknown outcome into success. A change requiring reinterpretation of stored
records or client behavior needs an explicit version/migration boundary,
compatibility explanation and relevant checks.

Changed plugin bytes require a new registered identity and separate approval.
Historical results cannot validate another implementation. Contract amendments
preserve earlier policy, failures, consumed lineage budgets and invalidation
rules. A fresh `NativeApplication` is not a reset mechanism for an existing
mission's budget or authority.

Once a revision is deployed, preserve its applied migration bytes and hashes.
Use additive migrations for later changes. An incompatible checkout must refuse
installation; never rewrite the deployment's checksum ledger to force it through.

## Deprecation and removal

A deprecation notice must identify the affected API/plugin/configuration, why
it changes, the supported replacement, affected versions, migration procedure
and checks required before switching. Ship the notice with the release notes
and operating guide. Deprecation alone does not disable a deployed control or
expand worker authority.

Do not remove or incompatibly redefine a supported operation in a routine
patch. Removal needs an explicit version boundary and a reviewed, tested
transition preserving identities, evidence, spent budgets and unresolved
effects. Operators choose and authorize upgrades. Agents cannot silently
replace their own acceptance path or turn unknown effects into fresh retries.

No calendar maintenance window is promised for this candidate. Any later
public schedule must be stated explicitly, not inferred from package metadata.

## Upgrade, recovery and security fixes

Retain the prior source, configuration, approved manifests, database backup,
external-effect records and independently held audit checkpoint. Run the
installation, authority/refusal, consequence and recovery checks relevant to
the proposed configuration. Requalify affected boundaries after changes to
code, policy, credentials, artifacts or deployment.

A database backup does not preserve every secret, destination or real-world
effect. Keep those boundaries separately and never publish live role/password
dumps. Follow [OPERATIONS.md](OPERATIONS.md) for the maintained installer and
owned runtime checks.

Report security problems through [SECURITY.md](../SECURITY.md). Private
vulnerability reporting is enabled on the public repository. Preserve the original failure,
use a minimal synthetic reproduction and obtain independent assessment. Urgency
does not authorize weaker checks, erased evidence or unreviewed dependencies.

Custom platforms and plugins remain unqualified until their actual boundaries
are established. Unsupported mandatory requirements must fail closed rather
than becoming advisory.
