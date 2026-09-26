# Hobnail

**Exact-work acceptance and protected actions for agent applications.**

Hobnail binds a candidate's acceptance to its exact bytes, registered input
snapshots, approved policy, complete required checks and independent identities.
It records authorization, dispatch and observation separately. A worker's
"done" or an adapter's successful response is not an observed outcome.

Existing agent tools retain planning and coordination. Hobnail supplies a
PostgreSQL control plane, standard-library Python SDK, bounded validators and
protected file, local Git and research-record consumers. Applications own their
contracts, trusted source acquisition and validation meaning.

This source is being prepared for **`payals/hobnail`**. Public repository
creation, publication and private vulnerability reporting setup are separate
release steps; this document does not claim they
have happened. Read [SECURITY.md](SECURITY.md) before deploying or reporting a
security issue. A monitored reporting route must be established before launch.
The [planned private reporting form](https://github.com/payals/hobnail/security/advisories/new)
is **not enabled yet**; until it is verified, use an established private
maintainer/operator channel as described in the security policy.

## Try it locally

Use an existing reviewed Python installation. Create a project environment only
if `.venv` is absent; reuse an existing one rather than replacing it:

```sh
test -d .venv || python3 -m venv .venv
.venv/bin/python --version
PYTHONPATH=src .venv/bin/python -m hobnail --help
.venv/bin/python scripts/check_portable.py
```

The package has no third-party Python dependencies, so these source-checkout
commands need no package installation. The portable runner reports the exact
selected and nonselected modules and refuses unclassified tests. Its pass is
not a database, sandbox or provider qualification.

For the native workflow, use PostgreSQL 18 binaries on `PATH` and the supported
macOS role/parser backend:

```sh
psql --version
.venv/bin/python scripts/local_demo.py
.venv/bin/python scripts/qualified_local.py
```

Each command creates and stops its own PostgreSQL cluster and retains private
evidence. The demo performs real authenticated submission, independent checks,
publication and observation using synthetic data. The separate qualification
command also tests role isolation, actual forbidden reads/writes/connections,
credential retirement and the protected file consequence. Do not point these
commands at a shared database or publish their private runtime directories.

The historical native combination is Python 3.14, PostgreSQL 18.3 and macOS.
Python 3.11+ is the declared compatibility target, not a claim that every version
was tested. Source and release checks must identify the exact candidate commit.
Unsupported mandatory execution backends fail closed. The separately reviewed
Linux ARM64 Docker reference passed actual role, parser, credential, effect and
cleanup controls; it trusts the supervisor and daemon and supports only the
locked configuration and builtin validators. See the [Docker record](docs/DOCKER-DEPLOYMENT.md)
and [support matrix](docs/SUPPORT.md).

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
