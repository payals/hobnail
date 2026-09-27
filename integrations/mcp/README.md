# Hobnail worker MCP adapter

This optional package exposes seven named worker operations over stdio. The core
`hobnail` package remains independent of MCP and has no third-party dependencies.
The adapter requires Hobnail 0.3.0 and the separately reviewed, pinned FastMCP
dependency closure. Follow the repository's [MCP guide](../../docs/MCP.md) and
the applicable dependency lock before installing the optional dependencies.

Once the reviewed dependencies and core package are installed in the project
environment, install this first-party package without resolving anything:

```sh
.venv/bin/python -m pip --isolated install --no-index --no-deps --no-build-isolation ./integrations/mcp
.venv/bin/python -I -m hobnail_mcp --help
```

The installed `hobnail-mcp` entry point accepts only `--config PATH` and runs
stdio. Prefer the isolated module command for explicit interpreter selection:

```sh
.venv/bin/python -I -m hobnail_mcp --config /canonical/private/worker.json
```

The path must identify an owner-controlled, canonical, private regular file.
An independently trusted supervisor provisions that file and the short-lived
worker credential. This command does not install SQL, start a database, activate
policy, acquire trusted inputs, run a verifier, dispatch an effect or observe
its consequence. Those independently authorized roles remain separate.

The closed configuration fields are `schema_version` (1), `role` (`worker`),
`expected_principal`, `connection`, `psql`, `timeout_seconds` (1–120), and
`owned_development` (boolean). `connection` requires explicit `host`, `port`,
`database`, `user`, `password`, `sslmode`, and `connect_timeout`; `sslrootcert`
is the only optional field. The configured `psql` is an absolute canonical
reviewed executable. Normal connections require `verify-full` and an explicit
trusted root. Only explicit owned-development configurations permit disabled
TLS, over a Unix socket or literal loopback address. Neither environment nor
libpq credential files are searched.

Startup calls `session.get` and requires the actual authenticated role to be
`worker` and its stable principal to match `expected_principal`. Older schemas,
unbound/expired credentials and mismatched identities refuse startup. The file
must have no group/other permissions, one link, the current owner's UID, and
at most 16 KiB. Its immediate parent must be owner-controlled and not writable
by group or others. Keep it and retained runtime evidence out of source control.

| Tool | Arguments |
| --- | --- |
| `get_contract` | `contract_id`, optional `version` |
| `put_artifact` | `content_hex`, `media_type` |
| `submit_candidate` | `contract_id`, `artifact_id`, `inputs`, `idempotency_key` |
| `get_candidate` | `candidate_id` |
| `request_effect` | `candidate_id`, `action`, `args`, `idempotency_key` |
| `get_effect` | `effect_id` |
| `cancel_effect` | `effect_id` |

Inputs have closed schemas and exact types. Artifact bytes use lowercase hex,
bounded to 1 MiB; the adapter does not reserialize artifact JSON, read supplied
host paths or fetch URLs. A request can select only actions and arguments already
bound by the approved contract. No generic SQL/API operation, approval,
verification, observation, credential-provider or administrator tool is exposed.
The stdio bridge accepts complete newline-delimited frames of at most 2,400,000
bytes. Before FastMCP parses them, the bridge rejects duplicate keys, non-finite
or lossy JSON numbers, invalid UTF-8 and oversized frames. Accepted bytes are
forwarded unchanged. The worker runs at most four database calls concurrently;
excess calls return `CONCURRENCY_LIMIT` with `outcome: not_attempted`. These
bounds do not establish a general denial-of-service qualification of the MCP
framework or host.
The actual PostgreSQL subprocess capture is bounded to 8 MiB of stdout and
64 KiB of stderr, with a deadline covering input writes and both output pipes.
The adapter also caps the serialized result at 8 MiB. A large otherwise-valid
candidate history or input set may exceed this limit; the response then remains
explicitly unknown (`TransportOutputLimit` or `RESPONSE_TOO_LARGE`), never a
truncated successful receipt. Text output uses compact serialization alongside
the same structured receipt.

Results preserve the original database envelope, including business refusals and
event IDs. Adapter-side errors have an explicit `origin: adapter` and never mint
an event ID. MCP's error marker accompanies `ok: false`; an `ok: true` receipt
still requires inspection of the actual acceptance/effect state. Reads append
audit records. Artifact registration and cancellation are not advertised as
idempotent. Keep the same caller key for the same submission/effect request.
Timeouts or cancelled transport calls can leave a committed operation: reconcile
the original identity and key, and never blindly redispatch. Cancelling an
effect does not undo a dispatch.

FastMCP imports occur only after clearing ambient configuration, disabling dotenv
loading and telemetry, and selecting private temporary framework state. No
remote listener, OAuth provider, cached token store, dynamic tool loader or
background task queue is enabled. Stdio itself is not a sandbox; the operator,
server implementation and host remain trusted, while protected role processes
retain the repository's existing confinement and authority requirements.

`hobnail_mcp.client.WorkerMCPClient` is a bounded stdlib qualification helper for
this worker workflow, not a general MCP SDK. It uses real subprocess stdio
messages and explicit version negotiation. The synthetic source demo is
`scripts/mcp_demo.py`; its completed runtime credentials are retired, so its
retained configuration is evidence rather than a reusable client attachment.
