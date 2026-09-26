# Docker artifact review and bounded qualification

Review date: 2026-09-26 UTC. The corrected, explicitly approved archive pair
passed the bounded local Docker qualification below. Earlier failed artifacts
and runs remain preserved. This record grants no deployment or publication
authority. The exact source manifests,
source layers, derived root filesystems and profile hashes are in
[`images.lock.json`](images.lock.json). The implementation and acceptance plan
is [DOCKER-DEPLOYMENT.md](../docs/DOCKER-DEPLOYMENT.md).

## Artifacts and source chain

The source is Docker Library's official Linux ARM64/v8 images:

| Source | Platform manifest | Platform publication |
| --- | --- | --- |
| PostgreSQL 18.6, Alpine 3.23 | `sha256:1d70b0960b2d1c39a0a82cda0d19d78b9b676d64b2120efe82631cd9768d1814` | 2026-09-18 01:12:47 UTC |
| Python 3.14.7, Alpine 3.23 | `sha256:480abd719aa1bedf60a3ad2d9237e61fd17112ad0c39a484b351e34cddbe46fd` | 2026-09-17 23:06:23 UTC |

The authoritative age evidence is the retained per-platform
[PostgreSQL registry response](https://hub.docker.com/v2/repositories/library/postgres/tags/18.6-alpine3.23)
and [Python registry response](https://hub.docker.com/v2/repositories/library/python/tags/3.14.7-alpine3.23),
each exceeding 168 hours. The source bytes are pinned by platform manifest,
configuration and layer digest; discovery tags are never execution inputs.

Reviewed Dockerfile sources are
[PostgreSQL at e00e1bd](https://github.com/docker-library/postgres/blob/e00e1bd34ec5c8a8e7ad89b273b3d42efaf6d5bc/18/alpine3.23/Dockerfile)
and [Python at 688a0b8](https://github.com/docker-library/python/blob/688a0b86bb44289df16a363e9f41d90514c1a5f9/3.14/alpine3.23/Dockerfile).
The registry-attached SPDX and BuildKit provenance statements bind to those
platform manifests and source commits. Their claimed builder is Docker Library;
they declare the builds nonreproducible. No independent signature verification
or reproducible rebuild is claimed.

All 12 unique compressed layers matched their hashes and declared sizes:
131,400,224 bytes. Independent review additionally checked their uncompressed
configuration `diff_ids` and the final overlay selections. No source entrypoint,
package installer, downloaded executable or library was executed during review.

The first-party assembler reads selected regular-file bytes directly from the
archives. It does not extract source paths onto the host filesystem. It binds
the actual raw manifest to the exact pin, the configuration to that manifest,
and selected layer/file bytes to those records. It rejects unsupported file
types, OCI whiteouts, excluded installer paths, unsafe paths, unselected link targets, cycles
and members beneath links. Selection of the appropriate final-overlay files
and dynamic data dependencies remains an explicit trusted review input; the
assembler does not discover an arbitrary application's dependencies for it.

Originally approved artifacts (retained as historical evidence):

| Archive | Bytes | SHA-256 |
| --- | --- | --- |
| `hobnail-parser-arm64.rootfs.tar` | 40,028,160 | `a9ef107a021aa6efc3b46a55792d515a5d6ff644b43c8e2fd3315a1c968293bc` |
| `hobnail-runtime-arm64.rootfs.tar` | 100,014,080 | `a1c9b0f1080c853746d1a18ea9eabdd959af8862163054ca2c159980fd80527f` |

Independent byte review established 1,621 parser members and 1,971 runtime
members, with 3,259 non-directory output/source mappings. It found no duplicate
or escaping names, dangling/cyclic links, link-parent traversal, device entries,
set-ID files, world-writable members or unexpected ownership. The server socket
directory's declared `70:20000` ownership and `0770` mode are intentional. Both
archives were rebuilt identically after the preparation checks were hardened.

Neither archive contains pip, site-packages, ensurepip, gosu or an upstream image
entrypoint. The parser also has no PostgreSQL client/server or shell. This is a
physical file-set result, not an assumption based on `python -I -S`.

## Required replacement after actual initialization failure

The fifth isolated run loaded the exact approved runtime archive above, then
failed standard `initdb` post-bootstrap initialization because
`usr/local/lib/postgresql/dict_snowball.so` was absent. Its linked-library closure
was insufficient: PostgreSQL's standard `snowball_create.sql` loads this module
dynamically. The standard initialization and frozen qualification checks remain
unchanged. The assembler now refuses an inventory containing `initdb` without
the required Snowball and PL/pgSQL modules.

A replacement prepared without execution adds only that one regular file:

| Property | Value |
| --- | --- |
| Module size and mode | 1,269,112 bytes; `0755` |
| Module SHA-256 | `a8485fc896eadbae7070b005739b8098755d43e1c93f28ffacb201dfb2ec2bf1` |
| Existing pinned source layer | `sha256:8aaacd1b534b4c3a0969e9c0fbc5e01f629e311c277ea0021828b5f6b5b314fb` |
| Replacement runtime archive | 101,283,840 bytes |
| Replacement runtime SHA-256 | `01231c53cba4a64b38638fea32a8a5fcb1c4c29b667fdd3ad6213102b20de580` |

The module comes from the same reviewed PostgreSQL 18.6 platform manifest,
publication, package and source-layer bytes. Its only ELF `DT_NEEDED` entry is
the already selected musl libc; it has no RPATH/RUNPATH. No upstream artifact or
package was added. Two static reassemblies matched; the parser archive remains
byte-identical. The owner approved this exact corrected runtime archive for
isolated local qualification, and verified read-only copies were released into
fresh private state. The quarantine originals, old approved archive and all
failed evidence remain retained. Static correction
does not establish successful initialization or qualification.

The [PostgreSQL 18.6 initializer](https://github.com/postgres/postgres/blob/REL_18_6/src/bin/initdb/initdb.c)
loads the Snowball SQL and later creates PL/pgSQL, whose module was already
included. Other encoding-conversion modules named in the bootstrap catalog are
not selected by this limited UTF-8 workload; arbitrary extension or encoding
use is not qualified by this file inventory.

## Vulnerability findings and scope

The retained scan queried all 136 source-SBOM package identifiers and accounted
for every response. It also retained Alpine 3.23 main/community security data,
actual APK package ownership metadata, upstream PostgreSQL security information,
the exact CPython release commit, and current PSF advisory records. Generic
package queries alone missed CPython advisories; this limitation is preserved.

| Finding | Disposition for these exact derived files and proposed initial flow |
| --- | --- |
| Bundled MessagePack 1.1.2; setuptools 70.3.0 | Source-image evidence is inside pip's dependency inventory. All site-package and ensurepip contents are physically excluded. |
| Go 1.24.6 standard-library findings in PostgreSQL source image | SPDX maps them to `usr/local/bin/gosu`. That executable is physically excluded; no other Go executable is selected. |
| `GO-2026-5024`, x/sys Windows string conversion | Windows-only affected package and function; selected artifacts are Linux ARM64. Gosu is also omitted. |
| CPython `CVE-2026-15806`, HTTP password-manager scheme matching | Affected code remains present. The initial native-PostgreSQL workflow has no HTTP credential manager or HTTP connection. |
| CPython `CVE-2026-17084`, stringprep/IDNA | Affected code remains present. Explicit UNIX socket paths and ASCII generated credential material do not use this domain-processing path. |
| CPython `CVE-2026-19672` and `CVE-2026-87910`, tar extraction/filter behavior | Affected code remains present. Neither the proposed byte/JSON validator flow nor preparation calls `extract`/`extractall` or fallback link extraction. Preparation checks regular members before `extractfile`. |
| CPython `CVE-2026-15310`, ZIP decompression allocation | Affected code remains present. No ZIP input or decompression is part of the qualified-flow proposal. Resource limits are additional bounds, not the advisory disposition. |
| CPython `CVE-2026-82049` | PSF's affected range ends before 3.14.0b1; it does not include 3.14.7. |

The five remaining CPython issues prohibit a blanket safe-Python or arbitrary
custom-plugin claim. The actual controller, role entrypoints and byte/JSON
validator path must enforce the stated input/configuration boundaries before
controlled qualification can pass. A new custom script using these features
needs its own review or an appropriately reviewed fixed runtime.

Primary sources: [PostgreSQL 18 security table](https://www.postgresql.org/support/security/18/),
[PSF advisory database](https://github.com/psf/advisory-database/tree/8667e46510b7bbd20619ddfda12c245b2f59f9bf/advisories/python),
[Alpine main security data](https://secdb.alpinelinux.org/v3.23/main.json),
[Alpine community security data](https://secdb.alpinelinux.org/v3.23/community.json),
[MessagePack advisory](https://github.com/msgpack/msgpack-python/security/advisories/GHSA-6v7p-g79w-8964),
[setuptools download advisory](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf),
[setuptools distribution advisory](https://github.com/pypa/setuptools/security/advisories/GHSA-h35f-9h28-mq5c),
and [Go Windows advisory](https://pkg.go.dev/vuln/GO-2026-5024).

## Runtime and permission boundary

The owner explicitly approved the original archive pair and the bounded local
Docker Desktop 4.91.0 upgrade. That upgrade and five qualification attempts
occurred. The corrected runtime archive received separate exact approval.
The operator supplies explicit archive paths; no personal path is embedded in
tracked source. Approval does not authorize registry publication, unrelated
container changes or resource pruning.

The three ARM64 seccomp profiles received independent static review and were
bound to actual inspected containers. Only role/database profiles permit
AF_UNIX sockets; the parser permits no sockets or process creation. Actual
AF_INET, AF_INET6, AF_ALG, AF_VSOCK and all three io_uring entrypoint probes
refused. Native AArch64 has no socketcall entrypoint; that case is explicitly
inapplicable, not a measured denial. Namespace creation remains excluded.

Preserved startup/writeback failures identified two additional database-only
requirements: PostgreSQL creates a separate session for each postmaster child
with `setsid`, and schedules writeback on an existing descriptor with
`sync_file_range(..., SYNC_FILE_RANGE_WRITE)`. Independent PostgreSQL, kernel,
musl-source and pinned-binary review bound the latter to native AArch64 syscall
84 with flag argument 3 equal to 2. The profile permits only that flag value.
Parser/role profiles were not widened; filesystem durability and error handling
were not disabled or reclassified.
The corresponding upstream paths are
[postmaster child initialization](https://github.com/postgres/postgres/blob/REL_18_6/src/backend/utils/init/miscinit.c)
and [PostgreSQL file writeback](https://github.com/postgres/postgres/blob/REL_18_6/src/backend/storage/file/fd.c).

The current reviewed host is Docker Desktop 4.91.0, Engine 29.8.0 and Linux
`7.0.12-linuxkit` on ARM64, replacing the earlier affected 6.12.76 VM. Its
containerd 2.3.4 has the Linux CRI `ExecSync` issue
[CVE-2026-53495 / GHSA-7jxh-36q5-gcqv](https://github.com/containerd/containerd/security/advisories/GHSA-7jxh-36q5-gcqv).
The publisher excludes users not using CRI. This bounded supervisor uses the
ordinary Docker API and no CRI `ExecSync` probes. That scoped exclusion is not
blanket host vulnerability clearance; it does not qualify other workloads.

The host preparation and tests use the repository's `.venv/bin/python`.
Container processes use the independently reviewed interpreter contained in
these archives; they do not use or change the host's global Python environment.

The complete actual run passed six integration tests in 439.607 seconds, with
543 observed assertions and no test failures, errors or skips. It delivered a
35-file source inventory plus both archive identities using independent reads
of Git objects and the retained snapshot, followed by protected publication and
observation. Its 96-event
audit proof verifies consistency from genesis; it is not externally anchored.
Seeded fixture refusals remain distinct from that real inventory delivery.

The unchanged 60/120/180-second runtime credential limits, natural 15-second expiry,
held SQL termination, exact parser mismatch, timeout/overflow and authority
controls ran against actual services. The run also retained seeded lost
issuance/dispatch replies and evidence-persistence failures, with independent
reconciliation; blind credential/effect retry attempts were refused. Twelve main credentials
and the administrator retired; the separate fault runtime retired its three
credentials and administrator while retaining its expected failed receipts.
The 395 main and 40 fault-container identities were recorded removed. Source
bytes stayed unchanged throughout the run, and the preexisting unrelated
container states were preserved.

Earlier failed initialization and writeback receipts retain their original
unconfirmed retirements, even though their owned containers are now absent.
Stopped volumes and original evidence were retained rather than pruned. This
qualification covers only the locked Linux ARM64 artifacts, reviewed local
host, builtin JSON validators, native PostgreSQL credential provider and fixed
file consumer under the trusted-supervisor boundary. It does not qualify
arbitrary plugins, other hosts, Docker OpenBao, live-project activation or
resilience against a compromised daemon/kernel. Third-party copyright/source
obligations must be handled before any public image redistribution; no image
publication is authorized here.
