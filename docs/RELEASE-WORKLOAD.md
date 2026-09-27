# Fresh release inventory workload

## Frozen acceptance: version 1

This workload delivers a current inventory of the new sanitized public-export
repository for the release package preflight and a self-contained HTML view. It
does not inventory the private development history, certify publication, or
activate live applications. The owner supplies the selected export commit and an
owned, exact filesystem snapshot of that commit. The candidate is selected only
after the release source lanes are complete.

Two implementations acquire the source facts separately. The trusted registrar
receives the result of `scripts/release_inventory_facts.py`, which reads the
selected commit's Git objects. The producer in
`scripts/release_inventory_workload.py` reads the exported filesystem snapshot;
it must not import the fact collector, read Git objects, or obtain expected
values from the accepted artifact. The selected commit and the following
required-document list are trusted owner configuration, not facts invented by
the producer:

```text
AGENTS.md
CONTRIBUTING.md
LICENSE
README.md
SECURITY.md
docs/AGENT-GUIDE.md
docs/CONTRACT.md
docs/OPERATIONS.md
docs/SUPPORT.md
```

The immutable artifact schema is exactly:

```json
{
  "schema": "hobnail-release-inventory-v1",
  "source_commit": "<40 lowercase hexadecimal characters>",
  "package": {
    "name": "<project.name>",
    "version": "<project.version>",
    "requires_python": "<project.requires-python>",
    "license": "<project.license>",
    "entry_points": {"<script name>": "<script reference>"}
  },
  "files": [
    {"path": "<relative POSIX path>", "sha256": "<64 lowercase hex>",
     "mode": "100644", "bytes": 0}
  ],
  "counts": {"files": 0, "bytes": 0},
  "migrations": [
    {"version": 1, "path": "migrations/001_example.sql", "sha256": "<64 lowercase hex>"}
  ],
  "required_documents": ["<required relative path>"]
}
```

Every regular file in the supplied exported tree appears exactly once. Files,
migrations, and required documents are sorted by path. File hashes are SHA-256
of exact bytes; byte counts are exact; modes are normalized Git modes `100644`
or `100755`. The two totals cover the complete file list. Migration versions
come from contiguous prefixes `001` through the final version of SQL files
directly under `migrations/`, without a hard-coded latest version. The declared
migration filename grammar is `[0-9]{3}_[A-Za-z0-9_]+.sql`; every file under that
directory must match. Package values come from `pyproject.toml`; the
license is its declared string, and entry points are `[project.scripts]`.
Required documents must exist. Snapshots with symbolic links, nonregular
entries, `.git`, or unsafe relative paths are refused. There are no timestamps,
absolute paths, identities, secrets, or readiness claims in the inventory.

Before the real-candidate baseline, the source collector owner specified these
bounded input preconditions: at most 2,048 files, at most 16 MiB per file, and
at most 64 MiB total; relative paths at most 1,024 characters matching
`[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*`; a declared MIT or Apache-2.0 license and
nonempty script entry points. Both implementations refuse unsupported source
trees. These preconditions do not omit files, change the inventory schema,
waive independent equality, or imply that the declared license was legally
audited. The artifact and registered input must each fit the contract's 1 MiB
limit.

The activated contract requires the exact top-level and package fields and
mandatory whole-document JSON equality against the independently registered
Git facts. Equality binds nested keys, complete file membership, byte hashes,
counts, modes, package values, migrations, required documents, and the selected
commit. Extra fields cannot pass. A single exact local `file.publish` action
can publish the accepted JSON. A separately confined observer must confirm the
exact effect, and the HTML renderer must read that observed JSON. Failed or
unconfirmed acceptance, dispatch, observation, or credential retirement cannot
be reported as completed delivery.

## Evidence and comparison

The baseline is a direct filesystem inventory of the same candidate, written
to a separate owned output. The protected path must produce the same legitimate
content and then deliver it through the real native registrar, approver,
verifier, adapter, and observer processes. The trusted supervisor explicitly
activates this one-work-item contract; it is operator-assisted execution.

Seeded controls remove one actual migration, change the declared package
version, and add an unexpected field. They demonstrate refusal before protected
publication and absence of an alternate output. They are deliberately injected
faults, not naturally discovered release defects. Each control has its own
fresh, explicitly approved one-work-item runtime; none resets a live mission
budget or authority. Any unexpected result is retained in the receipt.

The retained receipt records the candidate identity, independently supplied
input digest, produced and observed artifact digests, native response envelopes,
measured baseline and protected elapsed time, stage counts, attempts, refusals,
and cleanup results. Human authoring and review time is unmeasured. The report
makes no claim of lower operator effort, time saved, fresh trading performance,
or autonomous live project improvement. The useful consequence is delivery of
the fresh inventory actually consumed by the release package preflight and its
HTML view; that consumption is recorded separately from workload execution.

## Scope and execution

The workload uses first-party Python and the existing native application
lifecycle. It writes only a new owned output directory and its owned temporary
runtime. It does not change the source snapshot, private repository history,
live project files, harness controls, credentials belonging to other work, or
external services. Public publication remains a separate owner-authorized
release action.

The release operator supplies the new sanitized repository's exact snapshot,
commit, and independent facts file. Paths must be canonical, and the new output
directory must be outside the source snapshot. The collector runs separately;
the producer never imports it. With facts already retained by the registrar:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/release_inventory_workload.py \
  --snapshot /canonical/owned/export-snapshot \
  --commit <selected-40-character-export-commit> \
  --facts /canonical/owned/independent-facts.json \
  --output /canonical/owned/new-delivery
```

The output contains `baseline.json`, `baseline.html`, the independent facts,
the protected `published/release-inventory.json`, `release-inventory.html`,
and `workload-receipt.json`. The three injected-control directories must remain
empty. Native runtimes retain their private full receipts and logs; the workload
receipt includes response envelopes and native-receipt hashes but omits their
absolute path references. The final source candidate and consumer receipt are
release evidence recorded outside this source document to avoid changing the
inventoried commit after acceptance.

This document freezes acceptance before the producer's real workload; changing
a failed result by relaxing these requirements is not permitted. Unit tests
use owned synthetic source fixtures and are mechanism evidence, not the fresh
release workload itself.
