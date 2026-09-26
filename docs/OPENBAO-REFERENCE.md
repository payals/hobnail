# Exact native OpenBao reference

This is the nonsecret configuration for the bounded native qualification.
It is a local reference, not a production vault deployment recipe. Use only
the artifact identified in [OPENBAO-QUALIFICATION.md](OPENBAO-QUALIFICATION.md)
after its required review and authorization. No executable, token, private key,
unseal share or existing vault state is bundled.

The trusted launcher creates a fresh canonical `0700` workspace, copies the
reviewed binary, generates reference-only TLS material and owns every process
it starts. All paths below are relative to that new workspace. A source path
must not silently adopt an existing vault, database or personal configuration.

## Server HCL

`scripts/openbao_runtime.py` contains the exact `REFERENCE_HCL`. Its SHA-256 is
`2823145927895c366a3061c012de0df452e66ff07841ba6617f89364e9cb6848`:

```hcl
storage "file" {
  path = "./state"
}

listener "tcp" {
  address = "127.0.0.1:18200"
  tls_cert_file = "./tls/server-chain.pem"
  tls_key_file = "./tls/server-key.pem"
  tls_min_version = "tls13"
  tls_max_version = "tls13"
  disable_unauthed_rekey_endpoints = true
  disable_unauthed_generate_root_endpoints = true
}

api_addr = "https://127.0.0.1:18200"
disable_clustering = true
ui = false
plugin_auto_download = false
plugin_auto_register = false
raw_storage_endpoint = false
introspection_endpoint = false
allow_unauthenticated_workflows = false
unsafe_allow_api_audit_creation = false
allow_audit_log_prefixing = false
default_lease_ttl = "15m"
max_lease_ttl = "15m"
log_level = "info"
log_format = "json"

telemetry {
  prometheus_retention_time = "0s"
  disable_hostname = true
}

audit "file" "hobnail-reference" {
  options {
    file_path = "./audit/openbao.json"
    mode = "0600"
    log_raw = "false"
    hmac_accessor = "true"
  }
}
```

The server runs with `server -config=./config/bao.hcl` from the owned workspace,
never `-dev`, an extra configuration directory or a login helper. The launcher
supplies a closed environment rather than inheriting proxy, cloud, OpenBao,
Vault, xDS or OpenTelemetry settings. It does not repoint `HOME`. The HTTP
client uses an explicit CA, verifies the IP/hostname, and refuses redirects and
inherited proxies. TLS client certificates are not required: this is verified
TLS plus explicitly supplied bearer-token authorization, not an mTLS claim.

Clustering, HA storage, cloud seals, external plugin directories and automatic
plugin downloads are absent. The single-node file backend is not recommended
as production storage. OpenBao 2.6.2 does not provide the earlier `mlock`
behavior; this reference makes no memory-locking or host-swap protection claim.
See the pinned [server configuration](https://github.com/openbao/openbao/blob/v2.6.2/website/content/docs/configuration/index.mdx)
and [file backend](https://github.com/openbao/openbao/blob/v2.6.2/website/content/docs/configuration/storage/filesystem.mdx).

## Database bridge and lifetime limits

The owned PostgreSQL 18 cluster is named `hobnail_reference` and listens only
on its private Unix socket with SCRAM required for every login. The dedicated
issuer `hbn_bao_reference` has only the reviewed external-hook grants, not
administrator, role-membership or direct protected-table authority. The bridge's
trusted administrator connection is separate from that issuer.

The selected nonsecret profile is:

```json
{"profile":"reference-worker","provider":"reference-provider","principals":["reference-worker"],"role":"worker","max_ttl_seconds":120,"max_lifetime_seconds":240,"renewable":true,"capabilities":["dynamic_postgres","renewal","revocation","active_session_termination"]}
```

Owner setup uses `configure_openbao_postgres` with profile `reference-worker`,
issuer `hbn_bao_reference`, backend role `hobnail-worker`, mount `database` and
issuance TTL 60 seconds. Use its returned SQL/template strings exactly; do not
assemble a password-bearing SQL creation statement. Creation first produces
a witnessed inactive SQL role; the bridge installs SCRAM material through the
protected COPY channel and proves authentication before delivery.

The database engine has default TTL `60s` and maximum TTL `240s`. Its connection
selects the builtin `postgresql-database-plugin`, allows only `hobnail-worker`,
verifies the connection, limits open/idle connections to one and sets connection
lifetime `60s`. The username template is `hbx_{{ random 32 | lowercase }}`.
The DSN uses only the owned Unix socket and explicit issuer credentials;
`sslmode=disable` here is a Unix-socket setting, not permission to use plaintext
TCP. No extra plugin, rotation policy or cloud connection is selected.

## Provider token ACL

The main provider's complete selected operations are:

```hcl
path "database/creds/hobnail-worker" {
  capabilities = ["read"]
}
path "sys/leases/renew" {
  capabilities = ["update"]
  required_parameters = ["lease_id", "increment"]
  allowed_parameters = {
    "lease_id" = ["database/creds/hobnail-worker/*"]
    "increment" = ["60s", "120s"]
  }
}
path "sys/leases/revoke" {
  capabilities = ["update"]
  required_parameters = ["lease_id", "sync"]
  allowed_parameters = {
    "lease_id" = ["database/creds/hobnail-worker/*"]
    "sync" = [true]
  }
}
path "auth/token/revoke-self" {
  capabilities = ["update"]
}
```

The renewal wire values are exact strings, while the Hobnail API uses integer
TTL seconds. Numeric HCL alternatives previously failed a genuine positive
control; do not broaden the allowlist to arbitrary durations. Unlisted
parameters/endpoints have no grant. The token has no default policy, is a
nonrenewable service token with 15-minute TTL/explicit maximum, and is orphaned
from the bootstrap root. Therefore root retirement alone does not retire the
provider token: its leases and the token itself need explicit confirmation.

Separate finite negative-control profiles test a real foreign existing lease
without expanding the main profile. Valid requester positive controls establish
the privileged-profile refusal's cause. These are qualification fixtures, not
additional application authority.

Initialization uses Shamir three-share/two-share-threshold parameters. Secrets
stay in separate redacted objects in trusted supervisor memory. That separation
does not establish independent human custodians or durable unseal-key recovery.
The [qualification runner](../scripts/qualified_openbao.py) verifies actual
inventory, allowed/denied requests, logs, lifetimes, reconciliation and complete
retirement. Static HCL review alone is insufficient.
