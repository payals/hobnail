# Connect an agent through the worker MCP adapter

The optional `hobnail-mcp` package lets an existing agent submit exact work and
inspect its progress through seven named MCP tools over stdio. A trusted
supervisor supplies a worker credential and independently runs the verifier,
action adapter and observer. The MCP server does not create a database, approve
contracts, verify work or perform a protected action on the worker's behalf.

Use this guide after [installing the core SDK](INSTALLATION.md). The core
`hobnail` package remains dependency-free; installing it does not install MCP.
The optional package is a separate distribution, which can share this project's
`.venv`. You do not need to replace the environment to add it.

[Install](#install-the-optional-package-from-reviewed-locks) ·
[Run the demo](#run-the-complete-protected-workflow-on-macos) ·
[Worker configuration](#prepare-the-worker-identity-and-configuration) ·
[Client launch](#launch-from-your-mcp-client) ·
[Workflow](#submit-and-follow-work) ·
[Recovery](#handle-refusal-and-uncertainty)

## Install the optional package from reviewed locks

The optional package requires Hobnail 0.3.0 and
`fastmcp-slim[server]==4.0.5`. The Python import remains `fastmcp`. Each lock pins
the full third-party dependency closure and exact wheel hashes, rather than
letting pip select new versions during installation.

| Interpreter and platform | Lock |
| --- | --- |
| CPython 3.14, macOS ARM64 | [macOS lock](../integrations/mcp/requirements-macos-arm64-py314.lock) |
| CPython 3.14, Linux ARM64 | [Linux ARM64 lock](../integrations/mcp/requirements-linux-arm64-py314.lock) |
| CPython 3.14, Linux x86_64 | [Linux x86_64 lock](../integrations/mcp/requirements-linux-x86_64-py314.lock) |
| CPython 3.12, Linux x86_64 | [Linux Python 3.12 lock](../integrations/mcp/requirements-linux-x86_64-py312.lock) |

These are dependency profiles, not proof that every platform can run the
protected native workflow. The Linux wheels require glibc 2.28 or newer; the
macOS wheel tags require macOS 11 or newer. Wheel compatibility does not qualify
those operating-system versions for protected execution. There is no reviewed
optional-package lock here for
Python 3.11, Intel macOS, native Windows or musl Linux. The core's broader Python
compatibility target does not make another MCP dependency resolution reviewed.
The native protected-service examples require macOS; see
[support boundaries](SUPPORT.md).

Run the following from the checkout root with its existing `.venv` and pip.
The subshell stops if a check or install fails. It retains a newly created
directory containing the dependency receipt and downloaded wheels.

```sh
(
set -eu
MCP_SETUP_ROOT="$(.venv/bin/python - <<'PY'
from pathlib import Path
import tempfile
print(Path(tempfile.mkdtemp(prefix="hobnail-mcp-setup-")).resolve())
PY
)"
.venv/bin/python scripts/check_mcp_dependencies.py \
  --download-dir "$MCP_SETUP_ROOT/wheels" \
  --receipt "$MCP_SETUP_ROOT/dependencies.json"
MCP_LOCK="$(.venv/bin/python - "$MCP_SETUP_ROOT/dependencies.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
receipt = json.loads(Path(sys.argv[1]).read_text())
assert receipt["status"] == "passed" and receipt["wheel_bytes_verified"] is True
manifest_bytes = Path("security/mcp-dependencies.json").read_bytes()
assert hashlib.sha256(manifest_bytes).hexdigest() == receipt["manifest_sha256"]
manifest = json.loads(manifest_bytes)
lock = Path(manifest["profiles"][receipt["profile"]]["lockfile"])
assert hashlib.sha256(lock.read_bytes()).hexdigest() == receipt["lock_sha256"]
print(lock)
PY
)"
PIP_CONFIG_FILE=/dev/null .venv/bin/python -m pip --isolated install --no-index \
  --find-links "$MCP_SETUP_ROOT/wheels" --require-hashes --only-binary=:all: \
  -r "$MCP_LOCK"
PIP_CONFIG_FILE=/dev/null .venv/bin/python -m pip --isolated install --no-index --no-deps \
  --no-build-isolation . ./integrations/mcp
.venv/bin/python -I -m hobnail_mcp --help
printf 'Retained dependency receipt: %s/dependencies.json\n' "$MCP_SETUP_ROOT"
)
```

The checker selects the current interpreter/platform profile, checks the
reviewed manifest against PyPI metadata and OSV advisories, enforces the minimum
artifact age, and verifies downloaded bytes. It installs nothing. Missing
profiles, unavailable evidence, changed metadata or vulnerability findings stop
the check. The subsequent dependency installation reads only those local wheels;
the final command installs the two first-party packages without resolving other
dependencies. The snippet binds the selected manifest and lock bytes to the
receipt and disables pip configuration files for both installs. A successful
check is current known-advisory and integrity evidence,
not a guarantee against unknown vulnerabilities or a new signed-provenance review.

Do not resolve an unlisted platform by removing hashes, changing versions or
replacing the lock with a bare `pip install fastmcp`. A new dependency profile
needs its own review. Core-only users can continue using the offline SDK install
in [the installation guide](INSTALLATION.md#1-install-the-sdk-and-command).

## Run the complete protected workflow on macOS

After the optional package installation, run this from the checkout root on
macOS with PostgreSQL 18 binaries on `PATH` and `/usr/bin/sandbox-exec` available:

```sh
.venv/bin/python scripts/mcp_demo.py
```

The demo starts a fresh owned PostgreSQL cluster and provisions synthetic roles.
It uses the installed MCP server through an actual stdio client. The supervisor
separately configures protected registrar, approver, verifier, action-adapter and
observer processes; those credentials are not passed to the MCP worker. The
approver activates the contract, the registrar supplies a stock snapshot, and
the verifier compares the report quantity with that snapshot. The protected
adapter publishes the accepted bytes, and the observer reads the resulting file.

Four scenarios cover a matching report, incorrect content, an input advanced
after acceptance, and cancellation before dispatch. The latter three must leave
their destination files absent. The demo also checks the seven-tool interface,
scope refusal, malformed/privileged-tool refusal, same-key replay and conflicting
key reuse. The correct report's final effect must be `complete` after independent
observation.

Success exits with code 0 and prints a receipt with `status: "passed"`,
`runtime_stopped: true`, and `qualified: false`. Check
`checks.all_runtime_credentials_revoked` and `checks.mcp_process.closed` too.
The receipt reports its own retained pathname and runtime directory. Those files
are private runtime evidence: the directory includes synthetic configuration and
database state, and is not a public report bundle.

The script revokes its generated credentials, retires its administrator and stops
its owned cluster. Failures retain a named stage and any cleanup failure; a
cleanup failure invalidates success. Do not reuse its retained worker
configuration to attach another client: that credential has been retired.

This is an executable synthetic integration example, not a persistent production
service or a qualification of every host. The native services require the macOS
backend; running the SDK or installing Linux dependency wheels does not supply
that backend. Continue with [integration testing](INTEGRATION-TESTING.md) for
focused SQL, adapter, wire-protocol and native-runtime checks.

## Prepare the worker identity and configuration

The deployment supervisor must first install the maintained schema, create and
bind a scoped worker login, approve the contract, register trusted input
snapshots, and arrange the protected service processes. The schema needs the
authenticated `session.get` operation described in [typed SQL](TYPED-SQL.md).
Use the [native deployment guide](NATIVE-DEPLOYMENT.md) for authority and process
boundaries. The MCP adapter is the worker's transport into that deployment.

The supervisor creates the private configuration below. It is not an MCP tool
argument, and an agent cannot change its role, credentials, executable or expected
principal through a tool call. Keep the file outside source control and model
context; it contains the worker password.

| Field | Required meaning |
| --- | --- |
| `schema_version` | Integer `1`. |
| `role` | Exactly `"worker"`. |
| `expected_principal` | Stable worker principal registered in PostgreSQL. |
| `connection` | Object with explicit `host`, `port`, `database`, `user`, `password`, `sslmode`, and `connect_timeout`; optional `sslrootcert`. |
| `psql` | Absolute canonical path to the reviewed executable, not a shell command or executable discovered from the agent's `PATH`. |
| `timeout_seconds` | Integer from 1 to 120 for each database transport call. |
| `owned_development` | Boolean; permits the narrow local-development connection mode described below. |

Normal connections require `sslmode: "verify-full"` and an explicit trusted root
certificate. When `owned_development` is `true`, only an explicit Unix socket or
literal loopback address (`127.0.0.1` or `::1`) with `sslmode: "disable"` is accepted.
This option does not make a shared database an owned development runtime.

The configuration must be a canonical regular file with one hard link, owned
by the server's current UID, between 1 byte and 16 KiB, and with no group or other
permission bits. A mode-0600 file under a mode-0700 directory is the usual
choice. Its immediate parent must have the same owner and must not be writable
by group or others. Symlink or parent-path aliases refuse. The root certificate,
when used, and `psql` also need canonical paths. Unknown configuration fields
refuse rather than becoming options passed through to libpq.

At startup the server calls `session.get` through the configured connection.
It requires the database-authenticated role to be `worker` and the returned
principal to equal `expected_principal`. Writing `"role": "worker"` into a file
cannot turn an approver or administrator connection into a valid worker server.
Every later API operation rechecks the current database authority; the startup
check does not extend an expired or revoked credential.

## Launch from your MCP client

Configure your client to launch this environment's Python with arguments
`-I`, `-m`, `hobnail_mcp`, `--config`, and the supervisor-provided canonical
configuration pathname. Use an absolute Python executable path if the client
has another working directory. This is stdio transport: the client owns the
server subprocess and communicates through its stdin and stdout.

To inspect the command itself:

```sh
.venv/bin/python -I -m hobnail_mcp --help
```

The equivalent installed console entry point is `.venv/bin/hobnail-mcp`.
Starting either with `--config` validates the identity and then waits for MCP
messages; it does not print an interactive prompt. Keep stdout reserved for
protocol messages. Safe startup failures are emitted on stderr as a small JSON
object with `status: "startup_refused"` and exit with code 2. A serving/frame
failure uses `status: "server_refused"`. There is no remote HTTP listener to
configure.

The source package also contains `hobnail_mcp.client.WorkerMCPClient`, the bounded
stdio helper used by Hobnail's owned demos and qualification workflows. It covers
their initialize/discover, list/call and subprocess-shutdown needs; it is not a
general MCP SDK for arbitrary servers. It bounds retained stderr to 64 KiB and
retires its owned process after uncertainty or protocol desynchronization.

Stdio is not an operating-system sandbox. The host, supervisor, server code and
other unconfined processes of the same OS identity remain trusted. The adapter
clears ambient settings before importing FastMCP, disables dotenv discovery,
telemetry and update checks, and uses private temporary framework state. It does
not load personal credential files, OAuth stores or arbitrary tool plugins.

## Submit and follow work

Ask the client for `tools/list`; the server exposes exactly these names:

| Tool | Arguments | What a successful call means |
| --- | --- | --- |
| `get_contract` | `contract_id`, optional `version` | Returns the scoped contract and approval state. |
| `put_artifact` | `content_hex`, `media_type` | Registers exact bytes; does not accept them. |
| `submit_candidate` | `contract_id`, `artifact_id`, `inputs`, `idempotency_key` | Binds the registered artifact to specified input snapshot IDs. |
| `get_candidate` | `candidate_id` | Returns current eligibility and recorded independent evidence. |
| `request_effect` | `candidate_id`, `action`, `args`, `idempotency_key` | Reserves the approved action if its current requirements pass. |
| `get_effect` | `effect_id` | Returns the effect's dispatch and observation state. |
| `cancel_effect` | `effect_id` | Requests cancellation; cannot undo an already dispatched action. |

Read the contract first. Encode the artifact's original bytes as lowercase hex;
the adapter accepts at most 1 MiB and does not parse and reserialize your JSON.
`inputs` maps each required source name to a registrar-supplied snapshot ID.
Submitting a file path or URL does not upload its contents. IDs must be positive
integers, not strings or booleans; schemas reject unknown fields. The optional
contract version can be omitted or null to request the current version.

Before FastMCP parses a message, the server's frame reader requires valid UTF-8
and unambiguous JSON: duplicate keys, non-finite numbers and lossy JSON values
refuse. A complete newline-terminated input frame must fit within 2,400,000
bytes, including its newline. Validated frames retain their original bytes.
These input bounds do not establish a general denial-of-service qualification.

After submission, the separately authorized verifier claims and checks the
candidate. Poll `get_candidate` to inspect that evidence. Request only an action
and arguments declared in the approved contract. The protected action adapter
then performs the authorized effect, and the observer checks its actual
consequence. Follow `get_effect` until the authoritative state establishes the
outcome. A successful reservation or dispatch is not observed completion.

There is no tool for arbitrary SQL, choosing an API operation, approving policy,
forging a verdict, acquiring a privileged credential or overriding a failed
check. [The wire contract](CONTRACT.md) defines the returned data and lifecycle;
[integration testing](INTEGRATION-TESTING.md) exercises the separate services and
failure paths.

## Handle refusal and uncertainty

Results carry the database envelope in MCP `structuredContent`. A database
refusal preserves `ok: false`, its `code` and actual `event_id`; the MCP result
also marks it as an error. Read the complete result: `ok: true` can still carry
an observed `control_failure`, so a successful tool invocation is not a success
metric for the work.

Malformed MCP requests can fail framework validation before the adapter runs.
Adapter validation failures identify `origin: "adapter"` and do not invent an
event ID. Reads are audited too. Neither an MCP error nor the absence of a reply
by itself establishes whether a database mutation committed.

At most four database calls can run concurrently through one adapter. An excess
call returns `status: "busy"`, `code: "CONCURRENCY_LIMIT"`, and
`outcome: "not_attempted"`, with no event ID. That local capacity refusal differs
from a timeout after entering the transport, whose outcome may be unknown.

The MCP database transport captures at most 8 MiB of stdout and 64 KiB of stderr
within its configured deadline. The adapter also limits its JSON response to
8 MiB. `TransportOutputLimit` or `RESPONSE_TOO_LARGE` reports an unknown outcome;
it does not return a truncated receipt as if it were complete. Reconcile the
original operation just as for a lost response.

A client timeout can leave server-side work running. A stopped client process
does not prove that a database session ended or its transaction rolled back.
The separately authorized supervisor must reconcile any surviving owned work;
the worker must not acquire administrator authority to perform that cleanup.

Keep the same persistent caller key and exact arguments for candidate submission
and effect requests. Same-key replay and conflicting reuse have different
meaning. Artifact registration and cancellation are not advertised as idempotent.
After a timeout, cancelled client call, broken pipe or lost response, preserve
the original request. Adapter transport errors report `outcome: "unknown"` and
the available candidate/effect/key references; they do not retry automatically.
Read the existing state and use the separately authorized recovery path before
any further dispatch. Never change a key merely to retry an uncertain effect.

| Startup or runtime result | Next step |
| --- | --- |
| `INVALID_WORKER_CONFIGURATION` | Have the supervisor check the exact fields, canonical paths, ownership, permissions and connection mode. Do not paste the password-bearing file into a prompt or log. |
| `PROTOCOL_UPGRADE_REQUIRED` | Apply the additive schema update through the administrative installer; the server does not install it. |
| `WORKER_IDENTITY_MISMATCH` | Reconcile the configured expected principal with the actual bound worker login; do not substitute a privileged login. |
| `IDENTITY_REFUSED` or `IDENTITY_UNAVAILABLE` | Check credential validity and database reachability through the trusted supervisor. |
| `OPTIONAL_DEPENDENCY_UNAVAILABLE` | Use the reviewed lock and first-party package installation above in the interpreter the client launches. |
| `CONCURRENCY_LIMIT` with `outcome: "not_attempted"` | Reduce client concurrency and retain the original arguments/key; this call did not reach PostgreSQL. |
| A database denial such as `INPUT_STALE` or `CHECK_FAILED` | Inspect the existing candidate and evidence; correct the proposed work or obtain a separately authorized policy/input change. |
| `outcome: "unknown"` | Reconcile the original operation and effect; do not interpret a transport error as permission to repeat it. |

[Architecture](ARCHITECTURE.md) · [Package source](../integrations/mcp/README.md) ·
[Typed SQL](TYPED-SQL.md) · [Security](../SECURITY.md)
