# Test an agent integration before connecting live work

Use these checks to exercise the optional MCP worker, the typed SQL interfaces
and the independent verification/action/observation path. A tool responding
successfully is only one step. The useful result is that exact accepted bytes
reach the intended destination, an independent observer confirms them, named
failure cases refuse, and the owned runtime is retired.

Run from the Hobnail checkout with its existing `.venv`. Install the optional
package using the reviewed locks in [MCP.md](MCP.md) before running MCP checks.
PostgreSQL tests require the existing major-18 binaries on `PATH`. The protected
native workflows additionally require macOS and `/usr/bin/sandbox-exec`.
The [support guide](SUPPORT.md) separates source compatibility, dependency
profiles and actual runtime support; Linux dependency installation does not
supply the macOS isolation backend.

[Choose checks](#choose-the-check-that-matches-the-change) ·
[MCP workflow](#exercise-the-installed-worker-and-protected-services) ·
[Failure handling](#read-failure-and-cleanup-evidence)

## Choose the check that matches the change

For changes to tool validation or worker configuration, start with the
framework-independent adapter tests:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_mcp_adapter.py' -v
```

These tests use controlled transports and configuration fixtures. They check
closed arguments, exact bytes, startup identity requirements, redaction and
uncertain-result handling without establishing live MCP/database isolation.

For actual MCP framing and framework behavior without PostgreSQL, use:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_mcp_protocol.py' -v
```

This POSIX suite uses real FastMCP/stdin/stdout with an explicitly synthetic
database transport. It checks wire behavior, bounds and errors, not protected
role authority. The production server has no switch to select that fixture
transport or bypass its identity check.

For typed SQL or acceptance-proof changes, use the actual PostgreSQL suites:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_typed_operations.py' -v
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_acceptance_proofs.py' -v
```

These create fresh owned databases. They exercise wrapper/API compatibility,
authentication and grants, upgrade/reinstall behavior, and structural proof
requirements against PostgreSQL. The historical-proof cases distinguish an
immutable acceptance from current eligibility. Some malformed-proof probes use
a deliberately privileged fixture writer to check the backstop; they do not
establish resistance to an administrator who disables it. The SQL fixtures use
local socket trust and do not qualify operating-system separation.

The portable source profile is useful for compatible source changes:

```sh
.venv/bin/python scripts/check_portable.py
```

Its explicit module inventory defines its scope. It does not start PostgreSQL
or establish that the MCP, native or Docker runtimes work. A passing portable
result cannot replace the runtime checks below.

## Exercise the installed worker and protected services

On the supported macOS native path, run the complete demo:

```sh
.venv/bin/python scripts/mcp_demo.py
```

This launches the installed MCP package over actual stdio and separately uses
the protected registrar, approver, verifier, action adapter and observer. It
provisions and retires its own synthetic credentials and PostgreSQL cluster.
The [MCP guide](MCP.md#run-the-complete-protected-workflow-on-macos) describes the
four scenarios and receipt fields. The accepted report must be independently
observed as complete; incorrect content, stale inputs and cancellation must
leave the corresponding outputs absent.

When modifying the server implementation, also run its actual protocol tests:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_mcp_runtime.py' -v
```

The runtime tests select the source server with installed reviewed dependencies;
the demo command selects the installed server. This distinction matters after
editing source: reinstall the first-party package through the offline command
in [MCP.md](MCP.md#install-the-optional-package-from-reviewed-locks) before
checking what a client will import from the environment. Do not confuse a source
test with verification of an older installed wheel.

The runtime suite runs actual requests for both protocol versions exposed by
its test cases, checks the fixed tool surface and refusals, and requires observed
file bytes and cleanup. Missing prerequisites are failures rather than evidence
that a runtime test passed. These bounded cases do not qualify every MCP client,
untrusted extension, operating system or future service configuration.

## Read failure and cleanup evidence

Keep expected rejection controls distinct from unexpected failures. A seeded
bad artifact is a successful control only when the required refusal and absence
of its effect are observed. An unrelated transport error cannot substitute for
that refusal. Conversely, an observed wrong destination is a control failure,
not an inconclusive result that can be retried away.

On a failed run, inspect its recorded first failing stage and exact operation
identity. Preserve the receipt, prior events and cleanup observations. Determine
whether an effect is pending before attempting another run. A missing response
does not prove that the database transaction or file write did not happen.
Reconcile the original effect and idempotency key; do not use a fresh key to hide
the uncertain attempt or reset its budget.

Read the final receipt after teardown. Require the owned cluster to be stopped,
generated credentials to be retired and MCP subprocesses to be reaped. Record
the exact source revision and installed package used for the check. Incomplete cleanup invalidates success even
when the main workflow completed. Stop only identified owned resources; do not
prune shared Docker resources, stop another service or remove retained failures
to make the environment appear clean.

Treat retained directories as private. They can contain synthetic credentials,
database files, source snapshots and contextual repository metadata even when
the public-facing output has a closed aggregate schema. For review, report the
actual commands, exact source revision and scenario outcomes with their limits;
do not publish the runtime directory as a release artifact.

[MCP setup](MCP.md) · [Typed SQL](TYPED-SQL.md) ·
[Native deployment](NATIVE-DEPLOYMENT.md) · [Operations](OPERATIONS.md) ·
[Security](../SECURITY.md)
