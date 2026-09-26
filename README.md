# Hobnail

**Approve exact agent work, control its side effects, and verify what happened.**

**For coding agents:** start with [AGENTS.md](AGENTS.md), then the
[agent guide](docs/AGENT-GUIDE.md). The optional [authoring skill](skills/hobnail/SKILL.md)
helps prepare contracts; it does not grant execution authority.

Hobnail lets an application require evidence before accepting or publishing an
agent's output. You define a **contract**: the required checks, trusted inputs
and permitted actions. A worker submits the output, an authorized verifier
checks it, and PostgreSQL decides whether that exact work can proceed. A
separate observer then confirms the action actually happened.

Existing agent tools retain planning and coordination. Hobnail supplies a
PostgreSQL control plane, standard-library Python SDK, bounded validators and
protected file, local Git and research-record consumers. Applications own their
contracts, trusted source acquisition and validation meaning.

Hobnail is public at [payals/hobnail](https://github.com/payals/hobnail).
Report security issues through the enabled
[private vulnerability reporting form](https://github.com/payals/hobnail/security/advisories/new);
see [SECURITY.md](SECURITY.md) for the reporting and support policy.

## Install the SDK and CLI

On **macOS or Linux**, start with Git and Python **3.11+**. From a directory
where you want a new checkout:

```sh
git clone https://github.com/payals/hobnail.git
cd hobnail
python3 -m venv .venv
.venv/bin/python -m pip --isolated install --no-index --no-deps --no-build-isolation .
.venv/bin/hobnail --help
```

This installs from the cloned source without downloading build or runtime
packages. Reuse an existing `.venv` if you already have one. Keep the checkout:
workflow scripts and database migrations are source tools, not part of the
installed SDK wheel. [Full installation and troubleshooting](docs/INSTALLATION.md)
explains prerequisites, platform differences and expected output.

Try the installed SDK without PostgreSQL:

```sh
.venv/bin/python -I - <<'PYCODE'
from hobnail import discover

suggestions = discover(b'{"total":7}')
print("Authoritative:", suggestions["authoritative"])
print("Suggested checks:", ", ".join(item["plugin"] for item in suggestions["suggestions"]))
PYCODE
```

It prints `Authoritative: False` and suggests `bytes.sha256` and
`json.required_fields`. Suggestions help you author a contract; they do not
approve work or prove the example's value is correct.

## Run a complete workflow on macOS

With PostgreSQL **18** binaries (`initdb`, `postgres`, `psql`, `pg_ctl`) on `PATH`:

```sh
.venv/bin/python scripts/local_demo.py
```

The demo runs an accepted report and two rejection cases, creates and stops its
own database, and prints `"run_status": "completed"` and `"runtime_stopped": true`
when its checks pass. It uses synthetic inputs and a trusted demo controller.
See the [step-by-step native example](docs/INSTALLATION.md#3-run-an-accepted-workflow-and-two-refusals-on-macos)
for binary checks and help interpreting the receipt.

| Platform | Available path |
| --- | --- |
| macOS | SDK/CLI, portable tests, and the PostgreSQL 18 native demo/role workflow. |
| Linux | SDK/CLI and portable source tests. The macOS native helpers do not run here. |
| Docker | A qualified, exact Linux ARM64 reference exists, but there is no public image or public-only build/install recipe yet. [What is available](docs/INSTALLATION.md#linux-and-docker). |
| Native Windows | Not supported by the current onboarding/runtime matrix. WSL2 is not separately tested. |

The Docker archive/build-input distribution gap is explicit; an ordinary
`docker run postgres` command would not create a Hobnail deployment.
The [support matrix](docs/SUPPORT.md) names the tested configurations and limits.

## How the database gate works

The maintained entry point is `hobnail.api(op text, payload jsonb)`, with
operation-specific validation and PostgreSQL role/scope enforcement. State
changes and their audit record share a transaction; the SDK commits each call
independently. Protected Python
verifiers perform content checks; the database rechecks exact evidence and
current authority before acceptance. External actions require separate
observation and are not part of a PostgreSQL transaction.

A FastMCP server and per-operation typed-SQL generator are **not shipped**.
The earlier `work`/`eval` schema is a separate legacy example.
[Architecture and extension points](docs/ARCHITECTURE.md) explains what is
implemented, what can be extended, and the distinction from that example.

## Run your own work

The [complete application example](docs/NATIVE-APPLICATION.md) accepts an
owner-authored protocol-1 contract, trusted input bytes and an exact candidate.
The trusted supervisor explicitly approves the contract. A separate verifier
checks it, an adapter performs the authorized effect, and a separate observer
records the result. Read the final receipt after context exit: cleanup failures
can invalidate success. Unknown effects require reconciliation, not a new key
and blind redispatch.

The [protocol](docs/CONTRACT.md) defines the API and refusal semantics.
[Operations](docs/OPERATIONS.md) covers installation, checks and recovery.
[Native deployment](docs/NATIVE-DEPLOYMENT.md) describes the trusted host and
supervisor boundary. [Dependency review](docs/DEPENDENCIES.md) and the
[OpenBao reference](docs/OPENBAO-REFERENCE.md) distinguish reviewed artifacts,
historical qualification and unresolved applicability limits.

## Working with coding agents

Use [AGENTS.md](AGENTS.md) as the repository instruction entry point and
[the agent guide](docs/AGENT-GUIDE.md) for workflow and evidence requirements.
Give an untrusted worker only its scoped interface; a Python object handed to
unrestricted code is not an isolation boundary. Suggestions and generated
contracts remain proposals until an authorized independent approver activates
them. The [optional skill](skills/hobnail/SKILL.md) assists authoring; it does not
grant credentials or policy authority.

## CI and delivery

[GitHub Actions](https://github.com/payals/hobnail/actions) runs portable checks
and the source/history security scan on pushes and pull requests. The security
scan also has a weekly Monday 06:37 UTC schedule. Dependabot is configured for
weekly Python-package and GitHub Actions version-update proposals.

There is **no automatic deployment, PyPI publication, Docker image push or
GitHub release workflow**. CodeQL, dependency-review enforcement and the
proposed branch rules are separate configurations, not implied by a green CI
run. [Current CI/CD and maintenance details](docs/MAINTENANCE.md) distinguishes
active checks from proposals and runtime qualifications.

## Contributing and licensing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the current contribution phase and
verification instructions, and use the [PR template](.github/PULL_REQUEST_TEMPLATE.md)
for concrete problem/result, scoped changes, exact checks and compatibility or
security implications. Human and agent contributors follow the same review
requirements; omit secrets, private logs/transcripts, system paths and unrelated
generated state. No public test total is inferred from the private
development suite; the selected export omits private application integrations.
See [maintenance controls](docs/MAINTENANCE.md) for the prepared branch rules,
Dependabot and scheduled checks, and [optional maintenance triage](docs/MAINTENANCE-TRIAGE.md)
for Jev's advisory-only role. Committed configuration is not evidence that a
GitHub setting or scheduled job is active.
Legacy SQL and expected-output fixtures are retained for reference and recovery
checks. They are not maintained protocol-1 installation instructions. Use
`scripts/install.py`, not the legacy root `install.sql`.

Hobnail is [MIT licensed](LICENSE). Preserve its existing attribution and notice.
No third-party executable or container image is bundled or relicensed here.
