# Docker deployment and qualification

Status: the bounded Linux ARM64 reference passed actual qualification on
2026-09-26 UTC. All eight frozen criteria below were independently checked
against the real observations and resource readback. This qualifies the exact
reviewed archives, profiles and host configuration, with the supervisor and
Docker daemon trusted. Native OpenBao evidence remains a separate scope.

The useful result is a caller-supplied contract, exact inputs and candidate
passing the maintained PostgreSQL protocol, independent verification, protected
publication and separate observation inside explicit container boundaries.
Building an image, starting PostgreSQL or passing SQL tests alone cannot meet
that result. Approval independence, exact-byte bindings, role separation,
failure retention and uncertain-effect reconciliation remain mandatory.

## Availability for new users

The qualified implementation is in this repository, but there is no published
Hobnail image, Compose quick start or public-only build recipe for the exact
reviewed archives. The assembler needs reviewed closure inventories and pinned
source metadata/layers that are not included in this source export. The rootfs
archives are not distributed here either. The command below is for operators
who already have those separately reviewed artifacts; it is not an installation
shortcut from a fresh clone. See [INSTALLATION.md](INSTALLATION.md#linux-and-docker)
for the available SDK path and the remaining Docker packaging gap.

## Scope and trusted components

The first configuration uses the existing native PostgreSQL credential provider.
It requires actual SCRAM logins for every runtime identity, including bootstrap
administration, and exercises issuance, use and retirement of an expiring login.
OpenBao's reviewed native macOS artifact and qualification do not cover Linux
containers. No OpenBao image is part of this configuration.

The operator, host supervisor, Docker daemon, Linux VM/kernel, reviewed image
bytes, PostgreSQL administrator and approved verifier/effect implementations
remain trusted. A workload never receives the Docker socket, host PID/network
namespace, host home directory, repository checkout, or supervisor credentials.
The supervisor alone creates resources and chooses immutable container policy;
worker requests cannot supply Docker arguments, host paths, commands or images.
Docker's [daemon security documentation](https://docs.docker.com/engine/security/)
explains why access to the daemon is an administrative capability.

The observed local daemon is already serving unrelated work. Qualification must
use fresh named resources and leave that workload untouched. It must not restart
Docker, prune images/volumes, change shared settings, install a global runtime,
or claim the shared VM is secure against other tenants.

## Artifact decision

The initial exact platform is `linux/arm64/v8`; other architectures require their
own artifact review and actual run. The candidate versions are PostgreSQL 18.6
and Python 3.14.7 on Alpine 3.23. They meet the maintained PostgreSQL-major and
Python-runtime targets. PostgreSQL's [18.6 release notes](https://www.postgresql.org/docs/release/18.6/)
and Python's [3.14.7 release page](https://www.python.org/downloads/release/python-3147/)
are the upstream version references.

| Candidate | Exact ARM64 manifest | Authoritative platform publication |
| --- | --- | --- |
| `docker.io/library/postgres:18.6-alpine3.23` | `sha256:1d70b0960b2d1c39a0a82cda0d19d78b9b676d64b2120efe82631cd9768d1814` | 2026-09-18 01:12:47 UTC |
| `docker.io/library/python:3.14.7-alpine3.23` | `sha256:480abd719aa1bedf60a3ad2d9237e61fd17112ad0c39a484b351e34cddbe46fd` | 2026-09-17 23:06:23 UTC |

The owner approved bounded local use of the exact reviewed archives below;
that approval does not cover arbitrary images or public redistribution.
The registry's per-platform
publication timestamps exceed 168 hours at the review time. Mutable tag/index
updates and image configuration `created` timestamps are not the age proof.
The observed [PostgreSQL tag metadata](https://hub.docker.com/v2/repositories/library/postgres/tags/18.6-alpine3.23)
and [Python tag metadata](https://hub.docker.com/v2/repositories/library/python/tags/3.14.7-alpine3.23)
must be retained with the selected manifests; future tag contents can change.

The retained private review contains hash-checked index,
platform manifest, configuration, layer descriptors, SPDX package inventories,
BuildKit provenance statements, exact Dockerfile sources, PostgreSQL entrypoint,
OSV responses and Alpine security databases. It contains no registry credential.
The source commits are `docker-library/postgres` at
`e00e1bd34ec5c8a8e7ad89b273b3d42efaf6d5bc` and `docker-library/python` at
`688a0b86bb44289df16a363e9f41d90514c1a5f9`. The provenance identifies the official
Docker Library builder and these commits; it declares the builds nonreproducible.
A registry-served provenance statement is not an independently verified signature.

Both manifests share the same Alpine base layer. Their reported common Alpine
packages have matching versions. All 12 unique compressed source layers were
downloaded into a new read-only quarantine and matched their manifest hashes
and sizes: 131,400,224 bytes. Static inspection read archive members without
extracting them to the host filesystem or executing their contents.

`docker/prepare_images.py` assembles two deterministic root filesystems from
explicit reviewed file inventories. The parser contains Python and its standard
library/runtime dependencies; the service image additionally contains
`postgres`, `initdb`, `psql`, PL/pgSQL and their runtime dependencies. Both include
timezone/terminal data; the service image also includes ICU's external data.
Static ELF accounting resolves 93 parser and 118 corrected-service ELF dependency records.
This covers direct shared-library links and the named data dependencies, not a
claim that every possible dynamic feature has run.

The prepared archives are recorded in `docker/images.lock.json`:

| Root filesystem | Size | SHA-256 |
| --- | --- | --- |
| Parser | 40,028,160 bytes | `a9ef107a021aa6efc3b46a55792d515a5d6ff644b43c8e2fd3315a1c968293bc` |
| PostgreSQL/Python service | 101,283,840 bytes | `01231c53cba4a64b38638fea32a8a5fcb1c4c29b667fdd3ad6213102b20de580` |

Every copied file retains its source layer, file hash and package provenance in
the private member inventory. The original archives remain preserved; approved
copies were imported for local qualification. Earlier drafts and failed runs
remain retained. The corrected service archive adds only the standard
`dict_snowball.so` from the same reviewed PostgreSQL layer. Independent static
review verified all 1,971 common members, metadata and order unchanged;
removing the added raw tar member reproduces the original archive exactly.
Two assemblies matched, the parser is byte-identical, and the added module's
only linked library was already included. The owner separately approved this
exact changed service archive for isolated local qualification.

The assembly has no image startup hooks or network-enabled build step. It omits
`site-packages`, `ensurepip`, package-manager commands, `gosu`, and the official
image entrypoints. No `apk add`, package resolver or downloaded source build is
needed. It preserves source bytes and creates only explicit first-party account
and loader configuration. Third-party license/source materials still need to
accompany any future public image redistribution; local preparation is not an
authorization to publish these archives.

Current scan findings are retained rather than described as a clean scan:

- Python's bundled installer inventory includes affected MessagePack 1.1.2 and
  setuptools 70.3.0. Their source inventory evidence points to the bundled pip
  dependency inventory. The entire installer/site-package tree and bundled
  `ensurepip` archives are physically absent from the prepared filesystems.
- PostgreSQL's `gosu` helper carries Go 1.24.6 package findings. The official
  SPDX evidence maps those Go packages to `usr/local/bin/gosu`, which is
  physically absent from both prepared filesystems. The lifecycle still must
  start `initdb`, `postgres` and `psql` directly with fixed numeric users.
- `GO-2026-5024` concerns `golang.org/x/sys/windows.NewNTUnicodeString`; the
  selected Linux ARM64 artifact is outside its stated Windows platform range.
- The Alpine package findings require the official distribution security data,
  source-package mapping and installed versions, in addition to OSV package
  queries. An empty package-query response alone is not complete screening.

Direct CPython release-commit and current PSF advisory review found additional
issues that a generic package query did not identify. The selected release
contains the affected standard-library files. The initial workflow therefore
requires the following exact feature exclusions; it is not a general clearance
for arbitrary Python applications or newly approved custom plugins.

| CPython advisory | Required feature absent from the initial workflow |
| --- | --- |
| [CVE-2026-15806](https://github.com/psf/advisory-database/blob/8667e46510b7bbd20619ddfda12c245b2f59f9bf/advisories/python/PSF-2026-36.json) | No HTTP password manager or HTTP connection; database connections use explicit UNIX paths and native PostgreSQL credentials. |
| [CVE-2026-17084](https://github.com/psf/advisory-database/blob/8667e46510b7bbd20619ddfda12c245b2f59f9bf/advisories/python/PSF-2026-37.json) | No IDNA domain-name processing or Python stringprep authentication path. |
| [CVE-2026-19672](https://github.com/psf/advisory-database/blob/8667e46510b7bbd20619ddfda12c245b2f59f9bf/advisories/python/PSF-2026-38.json) | No tar extraction filters. Static preparation reads bounded regular-file bytes with `extractfile`; it never calls `extract` or `extractall`. |
| [CVE-2026-15310](https://github.com/psf/advisory-database/blob/8667e46510b7bbd20619ddfda12c245b2f59f9bf/advisories/python/PSF-2026-39.json) | No ZIP decompression; the accepted validator input formats are exact bytes and JSON. |
| [CVE-2026-87910](https://github.com/psf/advisory-database/blob/8667e46510b7bbd20619ddfda12c245b2f59f9bf/advisories/python/PSF-2026-40.json) | No archive extraction or fallback link extraction. |

CVE-2026-82049 is limited by the PSF CNA record to releases before 3.14.0b1 and
does not match 3.14.7. The final runtime must bind these feature exclusions to
the executed source and closed entrypoints. Resource limits remain necessary
but are not used to dismiss an applicable decompression vulnerability.

Primary advisory records include
[MessagePack](https://github.com/msgpack/msgpack-python/security/advisories/GHSA-6v7p-g79w-8964),
[setuptools download traversal](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf),
[setuptools distribution exclusions](https://github.com/pypa/setuptools/security/advisories/GHSA-h35f-9h28-mq5c),
and [the Go Windows advisory](https://pkg.go.dev/vuln/GO-2026-5024).

Before execution, complete independent static review, advisory dispositions
and the exact permitted startup behavior. Preserve any
quarantined artifact until its release is authorized. Hashes of metadata alone
do not prove integrity of unexamined layer bytes.

## Installed runtime constraint

Current readback observed Docker Desktop 4.91.0, Engine 29.8.0,
containerd 2.3.4, runc 1.4.3 and Linux `7.0.12-linuxkit` on ARM64.
The separately approved upgrade preserved rollback copies and restored the
pre-existing workload. This is not evidence of an enabled AppArmor/SELinux
mitigation or Enhanced Container Isolation, nor blanket advisory clearance.

The original host used Desktop 4.65.0 and kernel `6.12.76-linuxkit`, earlier
than the 6.12.85 fix for CVE-2026-31431; Desktop 4.72.0 later backported that fix.
See the [Linux CNA record](https://www.cve.org/CVERecord?id=CVE-2026-31431)
and [Docker Desktop 4.72.0 notes](https://docs.docker.com/desktop/release-notes/#4720).
The daemon's default profile alone is insufficient evidence for
the parser boundary. A task-local default-deny seccomp profile must
exclude `AF_ALG`, the complete `socketcall` multiplexer, all `io_uring` entrypoints
and alternate ABIs. Role/database profiles permit only necessary UNIX socket
creation; the parser profile permits no socket creation. All task containers
receive the reviewed profile, including temporary bootstrap helpers.

Independent profile review and benign syscall-refusal probes are prerequisites.
They mitigate the specified entrypoints only for these containers. They do not
patch or qualify the shared VM or another container. Qualification does not
change shared runtime settings. [Docker's seccomp documentation](https://docs.docker.com/engine/security/seccomp/)
describes the default-deny mechanism, and its [Engine 29 notes](https://docs.docker.com/engine/release-notes/29/)
record the subsequent mitigations.

## Resource and authority layout

The supervisor creates a random run identifier, private evidence directory,
immutable source snapshot and resource journal before creating any container.
Every named volume/container has that identifier and an exact recorded ID.
Labels support discovery; labels alone do not authorize deletion or attachment.
The launcher verifies expected image, ownership journal and complete configuration.

| Process | Database access | Writable resources | Other readable task resources |
| --- | --- | --- | --- |
| PostgreSQL | Server's own data | Fresh data volume, socket directory, bounded scratch | Exact server/HBA configuration |
| Bootstrap/admin | Exact socket and admin credential | Private scratch | Reviewed migrations and bootstrap code |
| Credential provider | Exact socket and issuer credential | Private scratch | Own credential profile |
| Registrar | Exact socket and own credential | Private scratch | Owner-supplied trusted input snapshots |
| Approver | Exact socket and own credential | Private scratch | Exact owner-approved contract |
| Worker | Exact socket and own credential | Private scratch | Candidate input supplied through bounded stdin |
| Verifier controller | Exact socket and own credential | Private scratch | Reviewed controller and exact admitted work |
| Data parser | None | Private bounded scratch | Exact reviewed implementation snapshot only |
| Adapter | Exact socket and own credential | Only configured destination volume and scratch | Reviewed adapter and immutable configuration |
| Observer | Exact socket and own credential | Private scratch | Destination mounted read-only |
| Auditor | Exact socket and own credential | Private scratch | Reviewed auditor code |

PostgreSQL data and sockets live in Linux named volumes, not a macOS host socket
bind mount. A task-only shared socket group permits connection, while SCRAM
authenticates the login. Every role uses a distinct nonroot UID and its own
single credential/configuration file; no peer directory is mounted. Socket
directory permissions and read-only client mounts must be tested for actual
cross-container connections. PostgreSQL listens only on that UNIX socket, with
no host port publication or IP listener. `initdb` starts with SCRAM for local and
host authentication; no temporary runtime `trust` interval is allowed.

All runtime containers use read-only root filesystems, `cap-drop=ALL`,
`no-new-privileges`, private PID/IPC namespaces, fixed nonroot UIDs, no devices,
bounded PIDs/memory/CPU and private size-limited `tmpfs` scratch. No workload gets
host namespaces, privileged mode, extra capabilities or a Docker socket.
All use `network=none`; [Docker documents](https://docs.docker.com/engine/network/drivers/none/)
that this leaves only loopback. Seccomp separately restricts socket families;
network namespace isolation alone does not address `AF_ALG` or `AF_VSOCK`.

Credentials never enter image layers, container-launch environment variables, argv, output,
public receipts or container labels. The supervisor keeps returned issuance
material in memory before fallible evidence writes, then provisions only the
owning role's private file. Docker CLI invocations use an explicit local daemon,
task-owned empty configuration directory, clean environment and closed FDs.
No ambient Docker registry, libpq, cloud, proxy or personal authentication
configuration is loaded.

The existing SDK passes an explicitly supplied password to its private `psql`
child environment. That process is inside the same role's private PID namespace;
this is distinct from putting a secret in Docker's inspectable launch metadata.
Actual peer-process denial remains part of qualification.

## Narrow implementation interfaces

The new Docker backend is selected explicitly. Existing macOS isolation stays
unchanged and continues failing closed on unsupported platforms.

- `docker/`: exact image lock/review metadata, offline role-image assembly,
  reviewed seccomp profiles, first-party role/parser entrypoints and bounded
  qualification-only probe code. Production role commands remain a closed set;
  diagnostics never introduce a generic command, SQL or file-write route.
- `scripts/docker_runtime.py`: trusted supervisor lifecycle, ownership journal,
  immutable container policies, bounded stdin/stdout/stderr, role endpoints,
  parser execution and cleanup. `DockerRuntime` owns one fresh cluster;
  `endpoint(role, connection)` returns a fixed-role endpoint exposing the existing
  `call`, `dispatch` and `observe` operations. Only the adapter and observer
  endpoints receive their role-specific destination access. The caller never supplies launch
  flags or destination paths through an operation payload.
- `scripts/qualified_docker.py`: actual bootstrap and qualification driver using
  the maintained migrations and protocol. It records every stage before an
  assertion, then retires owned credentials and reconciles uncertain effects.
- `tests/test_docker_runtime.py`: focused lifecycle, injection, policy and real
  consequence tests. Missing reviewed artifacts/runtime are explicit failures
  for the integration command, not silent qualification skips.

The parser starts as a separate container under the trusted supervisor. A
verifier container receives no daemon access and cannot launch sibling
containers. The supervisor passes only the exact artifact/input/check binding
to the parser, then the verifier's scoped identity records the result against
the original work. A worker cannot substitute a child result or mint acceptance.
Custom implementations retain exact digest checking, no-follow bounded source
reads, immutable snapshots, reviewed registry ownership and JSON-only results.
The core now has an explicit trusted `implementation_runner` keyword on
`verify_candidate` and `evaluate`, and the common `implementation_snapshot`
context manager preserves the original source custody checks. The Docker
runner must use that snapshot and return the existing `ChildResult`; the core
continues to validate child output and record the original claim/token/binding.
Omitting the keyword continues selecting the unchanged native backend. The
Docker runner accepts only the reviewed byte/JSON built-ins and refuses custom
plugin scripts. Supporting a custom script requires a separately reviewed
implementation change, renewed artifact/feature review and actual qualification.

The initial consequence is `file.publish`, with a separately mounted observer.
The same layout can cover create-only `research.promote` when its exact registry
consumer is exercised. Git requires its own explicit reviewed executable and
effective-control preflight; neither Git nor a live application deployment is
covered merely because the file path succeeds.

## Observed reference result

Six actual integration tests passed in 439.607 seconds, with zero failures,
errors or skips. The retained qualification contains 289 observations and
543 true assertions; these counts are not additional unit tests or a claim
about arbitrary workloads. Independent review checked every named requirement
in the unchanged eight-part acceptance matrix.

The run authenticated eight distinct roles and observed 24 exact SQL permission
denials, live peer/process/file restrictions, forbidden socket and `io_uring`
operations, and actual parser confinement, mismatch, timeout and overflow
controls. It exercised accepted, failed, stale, changed and non-admitted work,
then reconciled a deliberately lost dispatch reply without a new effect,
duplicate file write or budget reset. Held SQL backends were actually terminated;
15-second expiry and the unchanged 180-second lifetime ceiling were observed.

A separate real contract delivered an inventory of 35 runtime source files and
two approved image archives. An independent consumer compared the observed
inventory with Git, the runtime snapshot and the actual archive bytes and used
it for the release source/image view. The 96-event audit chain through that
completed observation was recomputed from genesis; it was not externally
anchored and does not establish administrator-proof history.

Normal cleanup confirmed retirement of 12 generated credentials and the
administrator. The separate fault runtime confirmed three more credentials and
its administrator retired while preserving its intentionally failed receipts.
All 395 main and 40 fault-runtime container identities were absent afterward.
The 16 pre-existing container states and all pre-existing volumes, networks and
images were preserved. Owned volumes and failures remain retained; no pruning
was performed.

Earlier startup failures exposed the missing standard PostgreSQL module and
necessary database-only process-session/writeback syscalls. A later full attempt
failed on the missing writeback syscall and retained unconfirmed retirement.
Its later correction allows only `sync_file_range` with `SYNC_FILE_RANGE_WRITE`
(flag 2) in the database profile. Database-only `setsid` is also required;
role and parser profiles remain restrictive. Successful later cleanup does not
rewrite those earlier failed receipts or their unresolved retirement evidence.

The final private qualification receipt has SHA-256
`d1a9a32552ce2b530e334e5e9f8623aadda0a4e538d26008da9a85ead253c9d7`.
Its private storage location is deliberately not part of the public source.
The hash identifies retained evidence, not a transferable deployment seal.
Seeded failure controls and the parts fixture remain distinct from the actual
source-inventory delivery; neither measures autonomous project benefit.

## Run the bounded qualification

Use already approved, canonical, read-only archive copies outside quarantine.
The command checks their exact locked hashes and the declared host versions;
matching values do not grant artifact approval. It creates fresh owned resources
and retains its receipt, logs and volumes. Do not run it while another owned
qualification remains unresolved.

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/qualified_docker.py \
  --parser-archive /canonical/approved/hobnail-parser-arm64.rootfs.tar \
  --runtime-archive /canonical/approved/hobnail-runtime-arm64.rootfs.tar \
  --engine-version 29.8.0 \
  --kernel-version 7.0.12-linuxkit
```

Read the final receipt after cleanup. A startup pass or completed publication
cannot hide a failed control, uncertain outcome or unconfirmed retirement.
This command does not download artifacts, upgrade Docker or publish images.

## Acceptance evidence

Each negative control has a positive control proving the intended resource was
present and usable by the authorized identity. An absent file, down database,
malformed request or generic transport exception does not prove denial.

1. Inspect actual running policy: immutable image ID, exact mounts, no published
   ports, namespace modes, zero effective capabilities, `NoNewPrivs=1`, active
   seccomp, numeric UID and resource limits. Probe forbidden `AF_ALG`,
   `AF_VSOCK`, non-UNIX sockets, `socketcall` and `io_uring` benignly where the ABI
   supports them; no exploit payload is needed or permitted.
2. Authenticate each actual SQL identity over the private socket. Correct
   passwords succeed and wrong passwords produce typed password rejection.
   Unknown principals, direct table writes, unauthorized API operations and
   worker-to-approver/verifier/adapter transitions fail under the kernel ACLs.
3. From each role's exact policy, deny peer credential reads/writes, parent
   directory traversal, supervisor files, peer process inspection/signalling,
   IP egress, daemon access and writes outside assigned scratch/destination.
   Verify worker cannot mutate the destination and observer cannot write it.
4. Run the actual parser over valid data successfully, then prove verifier
   credentials, socket, destination, host paths and controller process state
   are unavailable. Exact script mismatch, timeout and output overflow fail
   with owned processes reaped and no fabricated verification evidence.
5. Run a fresh non-demo contract through registered inputs, immutable approval,
   worker submission, independent check, admission, protected publication and
   independent observation. Verify exact destination bytes and completed effect
   state through the observer and audit chain.
6. Demonstrate rejection of failed, stale, changed and non-admitted work. A
   changed consumer consequence must become `control_failure`, while uncertain
   dispatch remains pending until independent reconciliation. Reconciliation
   must not duplicate the consequence or reset budgets.
7. Issue and use a fresh short-lived SQL login, rotate/revoke it, establish that
   the retired credential fails authentication and record all owned roles as
   retired before server shutdown. Preserve custody and cleanup failures if
   an issuance response or evidence write is lost.
8. Inject launch/readiness/output/receipt failures. Stop and reap only recorded
   owned containers; retain evidence and volumes until effect/resource state is
   known. Verify the pre-existing unrelated workload remains running unchanged.

Record the full source/image/profile/policy identities and observed results,
including failures. A profile/source fingerprint is historical evidence, not a
reusable deployment seal. Any future artifact, host runtime, policy, consumer or
credential topology change needs the relevant review and actual checks again.

## Current next step

Use the command above to qualify a newly approved deployment and retain its
actual receipt. Changes to source, images, profiles, host configuration, plugins
or consumers require the corresponding review and real checks again. Public
source packaging, native release-inventory delivery and GitHub configuration
have their own evidence; this Docker result does not authorize publication or
protected live-project activation.
