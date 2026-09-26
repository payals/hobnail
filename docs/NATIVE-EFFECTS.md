# Native protected consumers

The native service driver supports three explicit consumer configurations:
`file.publish`, `git.commit`, and `research.promote`. An adapter process can
write only its configured consumer roots. Its observer uses an independent
PostgreSQL identity and a profile with read access to those roots. Worker
processes receive neither capability. All socket-accessible logins, including
the administrator, must already require SCRAM authentication.

This extends the local process boundary described in
[NATIVE-DEPLOYMENT.md](NATIVE-DEPLOYMENT.md). The supervisor, operator, installed
binaries and other unsandboxed processes of the OS user remain trusted. It does
not activate a live maintenance harness or research/promotion path.

## Exact protected configuration

The trusted supervisor creates a frozen `NativeConsumer` and includes its
closed document in each relevant role's private configuration:

```python
from hobnail.deployment import NativeConsumer, endpoint

# Paths and aliases are trusted deployment choices, never worker arguments.
consumer = NativeConsumer.git(
    {"maintenance-repository": "/absolute/canonical/protected/repository"},
    executable="/absolute/canonical/reviewed/git",
)
# Alternatives:
# consumer = NativeConsumer.research("/absolute/canonical/research-records")
# consumer = NativeConsumer.file("/absolute/canonical/published-files")

adapter_config = {
    "role": "adapter",
    "connection": explicit_adapter_connection,
    "psql": explicit_psql_executable,
    "consumer": consumer.document(),
}
observer_config = {
    "role": "observer",
    "connection": explicit_observer_connection,
    "psql": explicit_psql_executable,
    "consumer": consumer.document(),
}
```

The connection dictionaries contain caller-supplied runtime credentials. Create
these configuration files exclusively with mode `0600` inside a private
supervisor-owned directory. Never commit, print or include them in a receipt.
Configuration and code must be outside every consumer write root and scratch
directory. Copy the reviewed Python package without bytecode to a protected
read-only snapshot before constructing endpoints, as the qualification runner
demonstrates.

```python
adapter = endpoint(
    "adapter", config=adapter_config_path, scratch=adapter_scratch,
    socket_path=postgres_socket, psql=explicit_psql_executable,
    package_root=reviewed_package_snapshot, consumer=consumer,
)
observer = endpoint(
    "observer", config=observer_config_path, scratch=observer_scratch,
    socket_path=postgres_socket, psql=explicit_psql_executable,
    package_root=reviewed_package_snapshot, consumer=consumer,
)

# The effect ID already belongs to an accepted candidate and approved action.
dispatched = adapter.dispatch(effect_id)
observed = observer.observe(effect_id)
```

Each call starts a bounded role process under its existing default-deny profile.
The typed consumer determines the command; the request contains only an effect
ID. It cannot supply a repository path, consumer implementation, executable,
command, new destination or replacement arguments. The service checks the
configured consumer and role before invoking its corresponding protected
adapter. SQL authorization and exact manifest checks still precede external
writes. Dispatch is an attempted effect; only the separate observer can report
completion. Old file deployments using `destination` remain supported.

## Git requirements

Use the actual reviewed Git executable, not a launcher that discovers and
executes another binary. For the installed Apple toolchain, the trusted
supervisor can resolve it with `xcrun --find git`; `xcrun` is not granted to the
role process. The service permits only the exact configured Git executable and
its inspected installed dynamic libraries. The adapter retains its existing
ambient-override and active-control refusals; it does not change `PATH`, author
identity, hooks, filters, signing settings or repository configuration to make
a command pass.

Before creating a Git endpoint, the trusted supervisor inspects effective Git
configuration and active attributes in its original environment. Before each
typed Git dispatch or observation, it retrieves the approved action through the
restricted role's read API and repeats that inspection for the complete current
tree and approved paths, including newly created paths. Unsupported global
hooks, filters, signing, includes and attributes therefore refuse before the
service's clean environment could conceal them. Generic database reads remain
available for reconciliation after such a refusal.

The profile grants read access to the exact installed system Git configuration
files needed by the reviewed executable after that inspection. Absent system
configuration names receive only metadata access. User-global configuration
directories and credential stores are not granted to the service. These checks
assume the trusted supervisor and other unsandboxed users of its OS identity do
not change controls between inspection and execution; they are not a persistent
configuration seal.

The alias map is immutable configuration. Every mapped directory must already
exist and be canonical. The adapter receives writes to those repositories,
including the Git metadata needed for prepared objects, intent journals, locks,
index updates and a compare-and-swap branch update. The observer receives reads
only. Choose narrow dedicated repositories; do not grant a whole project parent
or an unrelated workspace root. Repository contents and declared paths still
pass all checks in [GIT-ADAPTER.md](GIT-ADAPTER.md).

The native service has a clean environment. A live repository that relies on
unsupported user-global controls is refused by the supervisor inspection and
requires a different qualified integration. A synthetic repository result does
not establish that existing live controls remain binding.

## Research requirements

`NativeConsumer.research(root)` grants only the configured record root. The
approved action requires empty arguments and an exact
`<research-identity-digest>.json` basename. The service invokes the existing
create-only `ResearchRegistry`; an earlier different record cannot be
replaced. The observer checks the actual published bytes independently.

These are admitted research records, not active-strategy pointers. The
framework does not run a study, bypass a domain guard, change a trading account
or reopen a terminal study. The authoritative reservation, independent input
receipt, evaluation evidence and acceptance remain application integration
responsibilities described in the application's own independent research protocol.

## Focused qualification

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_native_effects.py' -v
```

The test suite creates an owned all-SCRAM PostgreSQL cluster, restricted role
configurations, a reviewed code snapshot and fresh synthetic repositories or
research records. It runs the real independent verifier and the native consumer
processes. It checks observed exact output, independent observer completion,
worker/observer write denials, changed and stale-work refusal, preservation of
concurrent content and existing research records, and the existing file route.
Generated roles are revoked and the cluster is stopped. Its private directory
and evidence remain available after the run.

This is qualification of those named local mechanisms with the stated trusted
supervisor boundary. Full deployment drift binding, live project activation,
external-provider qualification and fresh autonomy/research outcomes remain
separate requirements. No remote Git operation, package installation or shared
runtime modification is part of these commands.
