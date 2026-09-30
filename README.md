# Hobnail

**A PostgreSQL gate between what an AI agent says it did and what actually happens.**

Coding agents report "done" all the time. A claim is not evidence. When agent
output feeds something real, such as a published report or a commit to a
repository, you need a decision made outside the agent about what is allowed to
take effect. Hobnail is that decision point. It is a PostgreSQL control plane
plus a small, dependency-free Python SDK. An agent's work must pass through four
steps: a snapshot of the exact bytes, the checks you declared in advance, a
verdict from a separate verifier, and a recorded effect confirmed by a separate
observer. Every step is written to an append-only, hash-chained audit ledger.

**For coding agents:** start with [AGENTS.md](AGENTS.md), then the
[agent guide](docs/AGENT-GUIDE.md).

## What it does in one picture

```text
 worker            verifier            adapter              observer
 (the agent)       (separate role)     (separate role)      (separate role)
    |                  |                   |                    |
    | submit exact     |                   |                    |
    | bytes + input    |                   |                    |
    | snapshots        |                   |                    |
    |---> candidate -->| run every         |                    |
    |                  | declared check    |                    |
    |                  |---> accepted? ----|                    |
    | request the      |                   |                    |
    | approved action -------------------->| record dispatch,   |
    |                  |                   | then write the     |
    |                  |                   | file or commit --->| look at the real
    |                  |                   |                    | result; record
    |                  |                   |                    | complete or not
```

PostgreSQL makes each decision in one function, `hobnail.api(op, payload)`. It
maps the database login to a registered role and refuses anything that role may
not do. An action produces three separate records:

- **Authorization.** The worker asks for an action the contract already approved, on accepted work.
- **Dispatch.** The adapter commits a durable "about to act" record before touching anything outside the database.
- **Observation.** A different observer checks the real file or commit. Only a matching observation marks the effect `complete`.

An adapter reporting success is not completion. A timeout leaves the outcome
unknown until someone observes it. There is no automatic retry.

## What it refuses

Each refusal is a stable code from the database API or a named adapter error:

- **`SELF_JUDGING`**: the principal that submitted work tries to verify it, or observe its own effect.
- **`MISSING_CHECKS`**: acceptance or an action is requested before every declared check has a result.
- **`CHECK_FAILED`**: any check came back `fail`, `error` or `inconclusive`. Only `pass` counts.
- **`INPUT_STALE`**: the trusted input changed after the check ran, so the old verdict no longer applies.
- **`EVIDENCE_STALE`**: a check result, or an approved action's time window, is older than the contract allows.
- **`ACTION_MISMATCH`**: the requested action or its arguments differ from what the contract approved.
- **`FORBIDDEN`** or **`SCOPE_MISMATCH`**: a worker tries to activate a contract, register inputs, or act outside its scope.
- **`POLICY_INACTIVE`**: the contract version was replaced. Older candidates are no longer eligible.
- **`BUDGET_EXHAUSTED`**: the contract's cap on verification runs or effects is used up.
- **Path outside the contract**: the Git adapter refuses with "artifact paths differ from approved paths". It also refuses deletions, renames, symlinks, hooks and a dirty worktree.

The full list is in the [protocol reference](docs/CONTRACT.md#stable-refusal-codes).

## Try it in five minutes

You need Git and Python 3.11 or newer. The workflow demos also need macOS and
PostgreSQL 18 binaries (`initdb`, `postgres`, `psql`, `pg_ctl`) on `PATH`.

```sh
git clone https://github.com/payals/hobnail.git
cd hobnail
python3 -m venv .venv
.venv/bin/python -m pip --isolated install --no-index --no-deps --no-build-isolation .
.venv/bin/hobnail --help
```

This installs from the checkout and downloads nothing. Keep the checkout: the
scripts and database migrations are not part of the installed package.

**1. Portable checks (macOS or Linux, no database).**

```sh
.venv/bin/python scripts/check_portable.py
```

It prints a JSON receipt with `"status": "passed"` and the number of tests
run. This proves the SDK and adapters behave on your machine. It does not test
PostgreSQL or the macOS sandbox.

**2. Local demo (macOS, PostgreSQL 18).**

```sh
.venv/bin/python scripts/local_demo.py
```

It creates its own database, runs three scenarios, and stops the database. It
prints:

```text
Hobnail local demo: completed (runtime stopped)
Scenarios:
  happy        expected_outcome_observed=true   destination written: yes
  bad_content  expected_outcome_observed=true   destination written: no
  stale_input  expected_outcome_observed=true   destination written: no
```

A correct report is published. A wrong report is refused with `CHECK_FAILED`.
A report whose input changed after checking is refused with `INPUT_STALE`. The
full receipt stays in a temporary directory the command prints. This proves the
database gate works. It does not prove process isolation, because one trusted
demo controller holds every synthetic role's credentials.

**3. Qualified local run (macOS, PostgreSQL 18).**

```sh
.venv/bin/python scripts/qualified_local.py
```

It runs each role as its own sandboxed process with password (SCRAM) logins. It
prints a JSON receipt with `"status": "passed"` and `"runtime_stopped": true`.
Each role shows that it could not read peers' configuration, reach the
administrator, or open other network connections. This proves role separation
in this tested configuration only. The script takes no options.

**4. MCP prerequisite check (network access to PyPI and OSV).**

```sh
.venv/bin/python scripts/check_mcp_dependencies.py
```

The optional MCP server has a pinned, reviewed dependency lock. This command
checks that lock for your interpreter and platform against current PyPI metadata
and known advisories. It installs nothing and prints `"status": "passed"` and
`"installed": false`. It refuses when there is no reviewed lock for your setup.
Installing the package and running `scripts/mcp_demo.py` are covered in the
[MCP guide](docs/MCP.md).

Each demo keeps its stopped database and logs for inspection. To list them, run
`.venv/bin/python scripts/dev_cluster.py prune`. Add `--delete` to remove them.

## Run your own work

**The contract.** You write a JSON document per workflow. It names who may act
in each role, the media type and size of the output, the trusted input sources,
the checks that must all pass, and the exact actions allowed. An action has a
fixed target and fixed arguments, such as one file name or an exact list of Git
paths on an exact base commit. The contract also sets budgets and an expiry. A
worker may propose a contract. Only a separate approver can activate it.

**The roles.**

- **Worker**: the agent. It submits output and requests approved actions. It cannot judge or publish.
- **Registrar**: supplies the trusted input snapshots that checks compare against.
- **Verifier**: runs the declared checks in a restricted process and records one result per check.
- **Adapter**: performs the approved action, a file publication or a local Git commit, after recording dispatch.
- **Observer**: independently inspects the real result and records whether it matches.
- **Approver**: activates contract versions. The worker never holds this role.

**Entry points.**

- **Python SDK**: `hobnail.Client` calls any operation your role allows. `hobnail.discover` suggests checks from sample output, but suggestions never activate anything.
- **CLI**: `hobnail call`, `validate`, `coverage` and `discover`.
- **MCP**: seven worker-only tools over stdio for agents that speak MCP. There is no raw SQL and no approval tool.
- **Native application**: `.venv/bin/python scripts/native_application.py` runs one complete supervised workflow on macOS and prints its status and receipt.

Read next:

- [Protocol and contract format](docs/CONTRACT.md)
- [Complete application example](docs/NATIVE-APPLICATION.md)
- [MCP worker adapter](docs/MCP.md)
- [Local Git commit adapter](docs/GIT-ADAPTER.md)
- [Operations and recovery](docs/OPERATIONS.md)
- [Installation and troubleshooting](docs/INSTALLATION.md)
- [Architecture](docs/ARCHITECTURE.md)

## What it is not

- **Not an agent sandbox.** Hobnail confines its own role processes and validators. It does not confine the agent's shell, files or network. If the agent can write the destination directly, it can bypass Hobnail. Remove that access.
- **Not protection from a compromised administrator.** The database administrator, the schema owner, the supervisor process and the approved checker and adapter code are trusted.
- **Not proof that a check is complete.** A passing check proves only what it declares. An approved but incomplete contract is still incomplete.
- **Not a claim of qualification for your deployment.** Results cover the tested combinations in the [support matrix](docs/SUPPORT.md): PostgreSQL 18 (18.3 native, 18.6 in Docker) and Python 3.14. Python 3.11 or newer is the compatibility target, but not every version is tested.
- **Native workflows are macOS only.** Linux runs the SDK, CLI and portable checks. Native Windows is not supported, and WSL2 is not tested.
- **Docker is a reference, not a product.** You can assemble the exact Linux ARM64 reference from pinned inputs and run its qualification. No image is published, and a plain `docker run postgres` is not a Hobnail deployment. See [installation](docs/INSTALLATION.md#linux-and-docker).
- **Not exactly-once.** External actions are outside a PostgreSQL transaction. Unknown outcomes need reconciliation, not a blind retry.

## Security, support and license

Report security issues through the
[private vulnerability reporting form](https://github.com/payals/hobnail/security/advisories/new).
Do not put exploit details or credentials in a public issue. [SECURITY.md](SECURITY.md)
describes the trust boundaries and what a useful report contains.
[SUPPORT.md](docs/SUPPORT.md) lists tested configurations and the compatibility
policy. There is no support SLA. See [CONTRIBUTING.md](CONTRIBUTING.md) to
contribute.

Hobnail is [MIT licensed](LICENSE). No third-party executable or container image
is bundled.
