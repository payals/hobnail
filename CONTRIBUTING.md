# Contributing to Hobnail

Hobnail binds approved acceptance to exact work and records protected actions
separately from their observed consequences. Contributions should improve that
usable path while preserving existing behavior, authority and evidence. Start
with [README.md](README.md), the [protocol](docs/CONTRACT.md) and the
[support matrix](docs/SUPPORT.md). Coding agents also read [AGENTS.md](AGENTS.md).

The public repository and issue tracker are at
[payals/hobnail](https://github.com/payals/hobnail). Private vulnerability
reporting is enabled; follow [SECURITY.md](SECURITY.md) for security issues.
Start with [installation](docs/INSTALLATION.md) for an installed SDK/CLI, or use
the source-only test commands below. Publication and deployment still follow
the repository owner's authorization.

## Development environment

Use `.venv/bin/python` from the project's existing reviewed environment. All new
reviewed Python requirements belong in this `.venv`; do not use global pip.
If the project environment is absent, create it with an existing reviewed
Python 3.11+ interpreter: `python3 -m venv .venv`. This does not
download packages. The package uses Python's
standard library and has no third-party Python dependencies; source-checkout
commands do not require `pip install`, a global CLI or a plugin manager.
Metadata targets Python 3.11+, while the retained native evidence uses Python
3.14, PostgreSQL 18.3 and macOS. The maintained installer accepts PostgreSQL 18.

Read the current worktree before editing and preserve concurrent changes.
Propose a narrow change with a concrete before/after outcome. Keep unrelated
cleanup separate. Use small local commits and a branch when that helps review;
do not include another contributor's uncommitted files in your commit.

## Choose verification by the boundary changed

The explicit portable POSIX profile checks contract/transport/audit behavior,
adapter arguments, backend selection, temporary Git/file consequences and
controlled lifecycle/CI orchestration. It requires installed Git. It does not
start PostgreSQL, invoke the macOS sandbox, or run OpenBao:

```sh
.venv/bin/python scripts/check_portable.py --list
.venv/bin/python scripts/check_portable.py
```

`--list` names selected and nonselected modules, reasons and presence without
running tests. Unknown new test files or missing required selected modules
refuse; selection never changes because a test failed. Skips and expected
failures also prevent a pass. JSON results go to stdout. Optional `--receipt PATH`
creates a new file only, in an existing canonical directory; it refuses to
overwrite an existing file or follow a symlink. The full suite stays unchanged.

Run the relevant actual integration tests for database or credential changes,
using an existing PostgreSQL 18 installation whose binaries are on `PATH`:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_kernel_acceptance.py' -v
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_external_credentials.py' -v
```

Those tests create fresh owned PostgreSQL clusters. The external-credential
suite uses a synthetic HTTP issuer with actual database roles/authentication;
it is not a real OpenBao qualification. Some database mechanism fixtures use
private socket trust; only explicitly all-SCRAM cases prove password controls.

For the supported macOS role/effect path, run the relevant native cases and
wired examples:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_end_to_end.py' -v
.venv/bin/python scripts/qualified_local.py
```

The full suite available in the checkout is intentionally stricter about
prerequisites. It includes private PostgreSQL, macOS isolation, real OpenBao and
actual Docker runtime checks. Establish the approved artifact/runtime conditions
in [OPENBAO-QUALIFICATION.md](docs/OPENBAO-QUALIFICATION.md) and
[DOCKER-DEPLOYMENT.md](docs/DOCKER-DEPLOYMENT.md) before running it. Supply the
canonical reviewed OpenBao executable and the private Docker release-config
path; these variables are paths, never tokens or passwords:

```sh
export HOBNAIL_REVIEWED_OPENBAO_BINARY='/absolute/path/to/approved/read-only/bao'
export HOBNAIL_DOCKER_RELEASE_CONFIG='/absolute/path/to/approved/private/docker-release.json'
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Do not download another executable, weaken TLS/isolation, skip unavailable tests
or replace a real service with a fixture to claim a complete pass. Report the
specific prerequisite and the checks that actually ran. The native qualification
uses port `18200` exclusively; coordinate with other runs and refuse an occupied
port instead of stopping unrelated work.

After a coordinated source checkpoint, verify distributions offline using the
checker for the actual source layout. A prepared public source tree contains
`PUBLIC-SOURCE.json`; from that tree's root run:

```sh
.venv/bin/python scripts/verify_public_distribution.py --source-root .
```

This checks the public Git-bound manifest, archive metadata/content, repeated
builds, offline installation and redacted release evidence. Do not manufacture
a public-source marker in a private checkout to bypass the layout check.
When adding or removing a public source file, keep the manifest's sorted
`files` list complete; the verifier compares it with Git and refuses omissions.
New test modules also need an explicit reviewed portable-profile classification.

The internal developer checkout has a different checker. Only where
`scripts/verify_distribution.py` is present and `PUBLIC-SOURCE.json` is absent,
run `.venv/bin/python scripts/verify_distribution.py`. That internal checker
and the legacy `tests/run.sh` launcher are not shipped in the public export.
If an internal checkout contains the legacy launcher, its destructive scenario
is for a disposable owned database only; never use a shared connection or
reconstruct the absent launcher in the public tree.

Both distribution paths retain receipts and publish nothing. Coordinate checks
with concurrent writers so the evidence describes one source identity.

## Code, protocol and migration expectations

Follow the surrounding Python/SQL style and keep public values explicit and
closed-shaped. Prefer the existing standard-library helpers over a new runtime
dependency. New dependencies or workflow actions need exact reviewed identities
and the owner's provenance, integrity, age and vulnerability checks; an update
bot is a proposal, not approval to install.

Preserve the protocol's distinction between proposals, approvals, acceptance,
authorization, attempted dispatch and independent observation. Keep database
session identity separate from stable principal identity. Reconcile lost replies
against existing durable state, and never reset spent budgets or erase a refusal.
See [compatibility and deprecation](docs/SUPPORT.md) before changing an API.

Never edit applied migration files or their recorded checksums to make an
upgrade pass. Add a migration and verify both data and effective privileges.
Existing external OpenBao hooks are not automatically upgraded by migration 004;
their inventory refusal must remain visible until a reviewed upgrade exists.

For a defect, retain a minimal synthetic reproduction and test the actual
consequence. Include a positive control when a refusal could also be explained
by broken setup, unavailable transport or an invalid token. Preserve failure
records. Do not tailor a validator, fixture, assertion or held-out input to admit
the proposed result. If an authorized measuring surface is independently shown
wrong, document the evidence and before/after results and obtain separate
verification of the repaired behavior.

## Review and contribution record

Use the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) for both human-
and agent-authored changes. Lead with the concrete problem and final result,
then provide enough evidence for a reviewer who has not seen the conversation.
A reviewable change explains:

- The concrete trigger/problem and resulting behavior.
- Which files, protocol boundaries and support claims changed.
- The exact checks run, actual results and retained failures or untested limits.
- Any migration/recovery implication and new artifact's review evidence.

Keep secrets, private logs/transcripts, personal records and identifying system
paths out of the diff, description and attachments. Use approved redacted
evidence and repository-relative paths. Do not include unrelated edits,
generated runtime state or unsupported completion claims. Synthetic data is
the default reproduction input. A CI pass or reviewer opinion does not prove
an untested deployment or project outcome. Security-sensitive changes need
independent review and the relevant actual boundary checks. Drafting the review
record does not authorize a GitHub upload or disclosure.

Hobnail is licensed under [MIT](LICENSE). Preserve the existing notice. Submit
only material you are entitled to contribute under that license and retain
required notices for any separately licensed material. No additional contributor
agreement or publication permission is created by this document.
