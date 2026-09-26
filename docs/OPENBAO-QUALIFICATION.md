# Native OpenBao qualification

The maintained runner exercises the real OpenBao server and PostgreSQL bridge
in new owned local state. Historical execution on September 23, 2026 completed
23 required control groups, 24 ACL refusals and 40 cleanup/persistence checks
for the exact native reference below. Those results describe that run; the new
public source candidate has not yet acquired its own qualification receipt.
Private runtime paths and development-history identifiers are not distributed.

## Exact historical scope

| Component | Selected identity |
| --- | --- |
| Platform | macOS arm64, Python 3.14, PostgreSQL 18 |
| OpenBao | Stable 2.6.2 Darwin arm64 |
| Archive SHA-256 | `4e495376174accc0e014d31e9901f518a974f966850c839f626347eaac05fd52` |
| Executable SHA-256 | `d476d17e81a35e6d70dd7e86a8ab2a3664313525118f1f1cfe0130e7a2b95f3a` |
| Executable bytes | 193,769,394 |
| Server HCL SHA-256 | `2823145927895c366a3061c012de0df452e66ff07841ba6617f89364e9cb6848` |
| Listener | Explicit TLS 1.3 at `127.0.0.1:18200` |
| Database | Fresh private Unix socket; every login requires SCRAM |
| Provider | Builtin PostgreSQL database plugin; bounded role/token profiles |

The [reference](OPENBAO-REFERENCE.md) defines the storage, TLS, ACL and lifetime
parameters. The [dependency review](DEPENDENCIES.md) retains applicability
limits. This is not Docker, production file-storage, other-platform or general
OpenBao qualification. The host, bootstrap supervisor and approved provider
remain trusted. Shamir material is held in separate redacted objects in the
supervisor's memory; independent human custodians and durable key recovery are
not established.

## Run the real checks

Use the project `.venv` and existing reviewed PostgreSQL/OpenSSL tools. The
runner does not fetch or install OpenBao. Supply a canonical path to the exact
reviewed artifact whose execution the operator has authorized:

```sh
HOBNAIL_REVIEWED_BAO='/canonical/operator-approved/read-only/bao'
PYTHONPATH=src .venv/bin/python scripts/qualified_openbao.py \
  --source-binary "$HOBNAIL_REVIEWED_BAO"
```

The example path is a placeholder, not a bundled executable. The source must
be an operator-owned regular file with one hard link, mode `0400`, the exact
size and SHA-256 above, and no symlink substitution. The runner copies verified
bytes into a new private runtime and leaves the original unchanged. An occupied
port `18200` refuses; do not stop another process or silently change endpoints.

Allow several minutes: the checks observe natural expiry and the real lifetime
boundary. They do not move clocks or lower thresholds to speed up a pass. The
safe summary identifies a retained private receipt. Inspect its required-check
inventory, failures, cleanup, source/configuration hashes and observed states.
A failed cleanup or missing check cannot be reported as qualification.

Related mechanism checks, with distinct evidence scopes:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_openbao_acl_checks.py' -v
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_external_credentials.py' -v
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_qualified_openbao.py' -v
```

The ACL and cleanup unit tests use explicit fakes. External-credential tests
combine real PostgreSQL with a synthetic HTTP issuer. None substitutes for the
real qualification command. The actual runtime test module also requires an
explicit reviewed binary path through `HOBNAIL_REVIEWED_OPENBAO_BINARY`; that
environment value is a path, never a credential. No old private suite total is
claimed for the public export.

## What the real controls establish

The runner checks exact server/plugin inventory, verified TLS, token/ACL
denials with positive controls, scoped issuance and actual authentication,
60/120-second renewal, original-age ceilings, inactive creation witnesses,
profile separation, login/session revocation and natural expiry. It exercises
lost replies, delayed creation, bridge drift, restart reconciliation and
pending external outcomes without issuing replacement authority blindly.

Cleanup attempts every generated lease and token, then retires root authority
and stops only owned services. Required checks include actual nonempty server,
audit and PostgreSQL logs, HMAC-protected credential responses, synthetic-secret
exclusion and unchanged executed source. Process exit alone is not credential
retirement. Unknown external requests remain pending absent independent proof.

Earlier qualification failures led to narrow corrections: a complete strict
TLS certificate chain, explicit numeric catalog identity collection, exact
renewal-duration strings, and distinguishing SQL client sessions from internal
server processes. Those failed attempts were preserved; negative ACL counts
alone did not establish a usable positive renewal path. The acceptance limits,
TLS verification and independent retirement requirements remained intact.

## Limits and reruns

Recorded source/profile hashes are historical evidence, not reusable seals.
Changed code, binary, configuration, plugin selection or authority requires
relevant checks again. Socket inventory was point-in-time evidence, not
continuous egress monitoring. Conditional dependency exclusions are not a clean
CVE scan or publisher VEX. No claim extends to untrusted hosts, production HA,
cloud seals, container images or a new application's outcomes.

Keep TLS keys, initialization material, raw audit state and private receipts
out of source archives and public reports. Release evidence must be separately
reviewed and sanitized. On interruption, inspect cleanup/reconciliation state
before any continuation; do not replace an unknown action with a fresh retry.
