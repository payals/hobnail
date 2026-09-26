# Native local role deployment

The maintained native configuration runs database-facing roles in separate
macOS sandboxed processes and requires SCRAM for every socket-accessible SQL
login, including the administrator. The historical checked environment used
Python 3.14 and PostgreSQL 18.3. The new public candidate needs its own actual
qualification; no result transfers automatically to a changed host or source.

From a reviewed source checkout with its project `.venv`:

```sh
.venv/bin/python scripts/qualified_local.py
```

The runner creates a fresh owned PostgreSQL 18 cluster, executes real positive
and negative controls, publishes accepted bytes through the adapter, records
an independent observation, retires credentials and stops its server. Outputs
and private evidence remain available. It changes no existing application
controls, OS accounts or shared runtime configuration.

## Trust and authority

The operator, bootstrap supervisor, installed PostgreSQL/Python/OS runtime and
other unsandboxed processes of the operator's OS user are trusted. Every
untrusted workload must stay inside its assigned profile. Calling an SDK from
an unrestricted process does not establish isolation, and an approved check
can prove only its declared validation meaning.

The eight roles are worker, registrar, approver, verifier, adapter, observer,
auditor and credential provider. Each controller can read its own configuration,
reviewed code and private scratch, execute only reviewed binaries, and connect
only to the configured database Unix socket. Adapter destination writes are
explicit; observers read that destination without write authority. Workers and
verifiers do not receive destination writes or peer credentials.

The supervisor copies controller code into a read-only source snapshot without
bytecode caches. Interpreter startup disables site initialization and bytecode
writes. Library aliases are resolved before exact read grants are generated.
The trusted supervisor starts the stricter parser profile separately; it does
not give candidate parsers verifier credentials or relax profiles to make
nested sandbox initialization work.

## Actual qualification controls

The runner checks real authenticated session identity and rejects wrong or
absent administrator credentials. Each role can read its own configuration
while actual peer reads fail and peer bytes remain unchanged. Allowed SQL
socket traffic succeeds; forbidden sibling Unix/loopback connections deliver
no message. Worker/observer destination writes fail and protected bytes remain
unchanged. The parser cannot read the verifier's real credential file or use
the real SQL socket.

Separate fixed probe code runs under the same resource profile for diagnostic
tests. Production controllers expose no arbitrary shell, SQL or diagnostic
mutation verb. A valid verifier credential request succeeds while a worker's
request for that profile refuses. Correct content is accepted, actually
published and independently observed; failed/stale work refuses effects.
Generated authority is retired before shutdown, and cleanup failures invalidate
the receipt rather than being hidden behind an earlier success.

This qualification command covers the file workflow. Git and research-record
consumers have their own exact arguments, preconditions and consequence tests.
Neither file success nor a registered plugin silently qualifies every consumer.

## Integrating an application

`hobnail.deployment.endpoint(...)` builds a supervisor-owned endpoint from an
explicit private configuration, scratch directory, SQL socket and consumer.
`endpoint.client()` exposes the existing SDK transport. Give an untrusted
application only its assigned interface, not the privileged endpoint factory,
other profiles or supervisor interpreter.

The production interface has typed API operations and configured file/Git/
research dispatch and observation. Destination roots, Git aliases and executable
selection are supervisor configuration, not worker arguments. See
[NativeApplication](NATIVE-APPLICATION.md) for a complete one-item integration
and [the deployment source](../src/hobnail/deployment.py) for consumer builders.

`configuration_fingerprint()` identifies historical profile/source material;
it does not bind all binary bytes, database state or a perpetual validity period.
Rerun applicable actual controls after meaningful changes. A completed runner
retires its runtime; it leaves no permanent deployment grant.

## Other configurations

Unsupported mandatory execution backends fail closed. The exact Linux ARM64
[Docker reference](DOCKER-DEPLOYMENT.md) has its own actual qualification.
Native macOS evidence does not establish Docker syscall, daemon, mount, network
or parser boundaries. Custom deployments must remove alternate
worker authority to their protected targets and prove their own consequences.

Same-cluster recovery requires preserved role identities and external effects;
unknown dispatches must be observed and reconciled without blind redispatch.
The host/supervisor and privileged database owner remain trusted throughout.
This is not a claim of immunity to unknown OS vulnerabilities or compromised
administrators. See [SECURITY.md](../SECURITY.md) and [SUPPORT.md](SUPPORT.md).
