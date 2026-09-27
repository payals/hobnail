# Runtime dependencies and artifact review

Hobnail's core Python implementation uses the standard library and has no third-party
Python package dependencies. Use the project `.venv`; source execution does not
need `pip install`. PostgreSQL/client tools and platform isolation are external
runtime prerequisites. The historical native environment used Python 3.14 and
PostgreSQL 18.3 on macOS. This is not a statement that every installed host tool
or supported Python version has current vulnerability clearance.

## Optional MCP package

The separate `hobnail-mcp` distribution depends on
`fastmcp-slim[server]==4.0.5`. Its complete reviewed platform locks are under
[`integrations/mcp`](../integrations/mcp/README.md), with artifact hashes,
publication times, dependency metadata and provenance limits in the
[dependency manifest](../security/mcp-dependencies.json). The
[MCP installation guide](MCP.md) rechecks current PyPI and OSV evidence before
installing hash-verified wheels offline. Missing, changed, too-young, yanked,
prerelease or known-vulnerable inputs refuse installation through that recipe.
Do not bypass a failed check with an unlocked install.

The checker binds the reviewed dependency graph; it does not independently
resolve a new graph or cryptographically verify publisher attestations. The
initial review inspected selected wheel metadata, members and RECORD hashes,
and recorded missing attestations. A clean known-advisory result cannot exclude
unknown vulnerabilities. Updating the dependency set requires a new review and
lock/manifest update, not just a changed version in package metadata.

The framework's server dependency set includes optional authentication, storage
and keyring libraries. The Hobnail worker entry point disables environment-file
discovery, inherited framework settings and telemetry before imports; it does
not enable remote authentication, credential caches or keyring features.
Dependency availability does not grant those features authority.

## Credential-provider boundary

`PostgresCredentialProvider` receives an explicit trusted administrator
transport and owner-configured profiles. Profiles fix the principal, role,
TTL, maximum lifetime and connection limit. Workers do not receive administrator
authority. `CredentialBroker` binds issuance to a kernel-authorized request and
registers nonsecret lease metadata. Passwords travel through protected channels,
not SQL text, command arguments, receipts or source control.

Revocation is confirmed only after login is disabled and active SQL sessions
are absent. Password expiry alone does not terminate existing sessions.
Restart reconciliation recovers nonsecret request/role identity; it does not
recover passwords or issue replacement credentials for an unresolved request.

The standard-library OpenBao adapter requires explicit token/CA/role
configuration, verified HTTPS, no redirects and no inherited proxy. Synthetic
HTTP tests check protocol handling; they are not real-provider qualification.
The PostgreSQL bridge supplies actual creation witnesses, authentication and
downstream retirement evidence. An HTTP revocation response alone remains
insufficient for confirmed SQL retirement.

## Historical reviewed OpenBao artifact

The September 23, 2026 review selected stable OpenBao **2.6.2, Darwin arm64**,
published August 18, 2026. The runner remains pinned to these exact bytes:

| Object | SHA-256 |
| --- | --- |
| `openbao_2.6.2_darwin_arm64.tar.gz` | `4e495376174accc0e014d31e9901f518a974f966850c839f626347eaac05fd52` |
| Extracted `bao`, 193,769,394 bytes | `d476d17e81a35e6d70dd7e86a8ab2a3664313525118f1f1cfe0130e7a2b95f3a` |

The review matched signed checksum/SBOM metadata to the artifact and examined
its embedded module identities. It compared 315 nonlocal embedded module
checksums with authoritative HTTPS checksum-database records; it did not
independently verify checksum-log Merkle proofs or establish a reproducible
build. Four local module replacements remained tied to the release source.
These are historical bounded observations, not a fresh scanner result or
permission to execute any downloaded binary.

[Upstream release](https://github.com/openbao/openbao/releases/tag/v2.6.2),
[installation and signature guidance](https://openbao.org/docs/install/),
[tagged module manifest](https://github.com/openbao/openbao/blob/v2.6.2/go.mod).

The historical review retained findings for six dependency groups: AWS SDK,
CEL, go-archive, OpenTelemetry SDK, x/crypto and gRPC. Configuration-specific
source review narrowed applicability to the fixed local reference: file storage,
no cloud seal, no clustering/external plugin transport, no untrusted archive or
download workflow, no SSH/PGP workflow, no stored CEL workflow and no telemetry
exporter/diagnostics command. These exclusions depend on those paths remaining
inactive and the actual role/operation allowlists binding execution. They are
not publisher VEX, a claim of absent vulnerable code or universal CVE clearance.

The [reference parameters](OPENBAO-REFERENCE.md) and
[historical real-server qualification](OPENBAO-QUALIFICATION.md) describe the
tested conditions. Changed artifacts, plugins, configuration, environment or
allowed operations require a renewed review and the corresponding actual
checks. The new public source candidate still needs its own evidence.

## Acquisition and Docker limits

No OpenBao binary or container image is bundled in this repository. Obtain and
review third-party artifacts separately: exact version/digest, authoritative
provenance and publication age, signatures/integrity, dependency inventory,
scripts/network behavior and current vulnerability disposition. This project's
owner policy requires artifacts to be at least 168 hours old and keeps
unreviewed code quarantined; a digest alone does not waive review or authorize
release from quarantine. Do not use floating tags or unreviewed installers.

Docker has a separately qualified, exact Linux ARM64 reference using native
PostgreSQL credentials. Native Darwin OpenBao review does not qualify a Linux
OpenBao image. The [Docker record](DOCKER-DEPLOYMENT.md) and
[artifact review](../docker/ARTIFACT-REVIEW.md) retain the corrected archive,
actual controls, prior failures and configuration-specific vulnerability limits.
Its reviewed syscall profiles and actual denials do not patch the host or clear
other workloads. No general clean-scan or production-readiness claim follows.
