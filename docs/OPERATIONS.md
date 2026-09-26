# Operating Hobnail

The goal is independently justified acceptance of exact work and an authorized,
observed consequence. Keep approved policy, trusted inputs, validators,
credentials and destination authority outside worker control. These procedures
exercise a named local configuration, not arbitrary application success.

## Environment and first checks

Use `.venv` for project Python execution and dependency work. If it is absent,
create it with an existing reviewed interpreter; do not replace an environment
belonging to other work. The implementation uses only the standard library.

```sh
test -d .venv || python3 -m venv .venv
.venv/bin/python --version
psql --version
PYTHONPATH=src .venv/bin/python -m hobnail --help
.venv/bin/python scripts/check_portable.py --list
.venv/bin/python scripts/check_portable.py
```

The portable runner reports its explicit scope. PostgreSQL and native checks
need the prerequisites in [SUPPORT.md](SUPPORT.md): PostgreSQL major 18,
matching `psql`, `initdb` and `pg_ctl`, and the supported macOS backend where
role/parser isolation is required. Backup checks also need matching `pg_dump`
and `pg_restore`. No fallback to unrestricted parser execution is permitted.

## Complete local workflows

```sh
.venv/bin/python scripts/local_demo.py
.venv/bin/python scripts/local_demo.py --scenario bad_content
.venv/bin/python scripts/qualified_local.py
```

The demo uses synthetic data, actual SQL identities and protected file delivery.
The qualification adds separate native role processes and actual denial probes.
Both allocate fresh owned runtimes and retain receipts after retiring their
credentials and stopping their own servers. An expected refusal is evidence
only when its positive control and cause are established. Read the receipt's
effect and cleanup states rather than only the shell exit status.

To supply your own contract and bytes, use
[NativeApplication](NATIVE-APPLICATION.md). The owner remains responsible for
independent acquisition of trusted facts and for sufficient validation meaning.

## Install the maintained schema

`scripts/install.py` is the protocol-1 installer. It checks PostgreSQL major 18,
owner/schema state and applied migration hashes under an installation lock, and
applies contiguous migrations transactionally. A repeated call validates prior
hashes and installs only new migrations. Drift must remain a refusal.

This example starts a fresh disposable cluster and checks repeat installation:

```sh
.venv/bin/python - <<'PY'
import json
from scripts.dev_cluster import DevCluster
from scripts.install import install

with DevCluster(database="hobnail_install_check") as cluster:
    dsn = (f"host={cluster.socket_dir} port={cluster.port} "
           f"dbname={cluster.database} user=postgres sslmode=disable")
    first = install(dsn, str(cluster.bin_dir / "psql"))
    second = install(dsn, str(cluster.bin_dir / "psql"))
    assert first == second
    print(json.dumps({"installation": second, "retained_root": str(cluster.root)}))
PY
```

This lower-level cluster is an installation test, not a role-isolation or
password-authentication qualification. For a separately approved deployment,
`install.py --dsn` accepts an explicit administrative connection. It does not
discover personal libpq services/password files or accept inline DSN passwords.
Secure the administrator independently; installation alone does not provision
an isolated application.

The root `install.sql`, `schema/`, `tests/scenario.sql` and `tests/expected.txt`
are a separate legacy reference retained for recovery regression. Their records
do not become protocol-1 acceptance. The legacy launcher is not shipped in the
public source export; never reconstruct its shared-database shortcuts.

## Relevant verification

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_kernel_acceptance.py' -v
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_end_to_end.py' -v
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_native_application.py' -v
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_recovery.py' -v
```

These commands have different runtime prerequisites. The exported tests are
not the private development suite, so do not reuse an older aggregate count.
Missing prerequisites are not skipped qualification. Real OpenBao tests and
the exact external artifact are documented in
[OPENBAO-QUALIFICATION.md](OPENBAO-QUALIFICATION.md). Do not download or execute
an unreviewed binary to make those checks run.

The release's public distribution verifier separately checks the selected
export and offline package installation. Packaging proves the checked artifact
properties; it does not activate a deployment or enable security reporting.

From the prepared public repository, whose `PUBLIC-SOURCE.json` declares its
complete file set:

```sh
.venv/bin/python scripts/verify_public_distribution.py --source-root .
```

The verifier retains a fresh source snapshot, repeated wheels, a complete source
archive and an offline installation in its own `.venv`. It refuses a dirty tree,
missing source members, unapproved metadata or a blocked public-source scan.

## Failure, upgrades and recovery

An API `ok` reports that an operation was recorded; inspect the actual acceptance
or effect state. Failed/inconclusive checks cannot admit work. A dispatch with
a lost response may already have changed the destination. Preserve that effect
and reconcile it through its independent observer; do not create a new intent
to retry an unknown consequence. Cancellation does not undo dispatch.

For lost credential issuance/registration replies, use
`CredentialBroker.reconcile_request(request_id)` against the existing provider
state. A downstream HTTP response is not proof that SQL login and active
sessions are retired. Preserve pending outcomes until independent confirmation.

Before upgrades, retain the exact revision/configuration, applied migration
hashes, approved manifests, database backup, external-effect records and an
independently held audit checkpoint. Do not edit old migration bytes or checksum
ledgers. Same-cluster restoration preserves existing role identities; a database
dump is not a backup of credentials, target files or external effects. Cross-
cluster issuer recovery needs separate qualification. See
[SUPPORT.md](SUPPORT.md) and [SECURITY.md](../SECURITY.md).

Keep runtime receipts/logs private until reviewed for release. Generated
credentials, personal records, private paths and arbitrary application data
must not enter public bug reports or source archives.
