# Advisory maintenance triage with Jev

`scripts/maintenance_triage.py` optionally classifies bounded maintenance
metadata into a human review queue. It cannot approve or merge a change, alter
permissions, satisfy an acceptance check, or modify the repository. Every
answer requires human review. Model output and deterministic policy remain
separate in the receipt; a routine classification cannot override a failed,
missing or unknown check.

## Verified API contract

The selected model is exactly `~typesafe/jev-latest`, a moving alias chosen by
the operator. It uses `POST https://openrouter.ai/api/alpha/decisions`, not chat
completions. The request contains `model`, `state` and one `choice` question;
the answer contains a selected label, confidence and per-label probabilities.
The response's model identifier is recorded separately from the requested alias.
See the official [alias page](https://openrouter.ai/~typesafe/jev-latest) and
[Decisions reference](https://openrouter.ai/docs/api/api-reference/alphadecisions/submit-a-decisions-request),
reviewed September 26, 2026 UTC.

The parser requires a versioned `typesafe/jev-…` response model, the exact
question/label set, finite probabilities totaling one, a consistent winning
label, and numeric usage. Unresolved aliases, missing fields, extra fields,
unexpected providers and malformed responses refuse. This strict application
profile may refuse future API changes; it never fills missing evidence with a
plausible default. Confidence is model evidence, not measured accuracy on this
maintenance task. No calibrated threshold or effectiveness claim is implied.

## Input and disclosure boundary

Input is explicit JSON with exactly `schema`, `dependency`, `advisory` and
`frozen_checks`. The schema is `hobnail-maintenance-metadata-v1`.

- `dependency` contains only `type`, exact `current_version` and
  `proposed_version`, `change`, and `scope`. Types are Python package, GitHub
  action, container image or system tool. Versions accept bounded numeric
  versions, exact Git hashes or SHA-256 image digests; floating tags refuse.
- `advisory` contains an enumerated state/severity and at most 16 unique public
  CVE, GHSA or Go advisory identifiers. It contains no free-text report.
- `frozen_checks` contains exactly `identity`, `integrity`, `release_age_168h`,
  `vulnerability_review`, `compatibility` and `tests`. Each result is `pass`,
  `fail`, `unknown` or `not_run`. These values come from independent deterministic
  checks and are not established by this classifier.

The script discovers no repository, source, raw diff, log, pull-request prose,
identity or private configuration. It refuses unknown input fields. The caller
must still establish that supplied metadata is public, truthful and authorized
for disclosure: a schema is not a universal secret detector or a provenance
proof. Arithmetic, version classification, advisory lookup and actual checks
belong in deterministic tooling upstream, not in model judgment.

## Prepare and run

Use the existing project `.venv`; there are no new dependencies. First inspect
the prepared synthetic request without loading a key or making a network call:

```sh
.venv/bin/python scripts/maintenance_triage.py --example
```

For real metadata, use `--metadata` with an explicitly selected canonical
regular JSON file. Only after the disclosure and API call are authorized, use:

```sh
.venv/bin/python scripts/maintenance_triage.py --metadata maintenance.json --live
```

The calling process must already have `OPENROUTER_API_KEY` set through an
approved secret channel. The script reads only that named environment variable
at request time. Do not put a key in the JSON, command arguments, shell history,
source or receipt. No credentials file is discovered. `--example --live` makes
one real model call over synthetic metadata; its output is a connectivity/schema
observation, not a maintenance-quality benchmark.

A fresh isolated Python child performs one verified HTTPS request to the fixed
host/path. It inherits only the named key, has no proxy/redirect handling, and
uses no optional referral, trace, session or user identity headers/fields.
Metadata, request and response limits are 8, 16 and 64 KiB respectively. A
30-second parent process deadline bounds DNS, TLS and response handling; socket
operations also use a 10-second timeout. No automatic retry occurs, including
after timeouts or rate limits. The endpoint is a billable external service; the
byte and time bounds are not an account spending cap.

Output is a safe JSON receipt. It retains requested/resolved model, closed
answer data, usage, input/request/response hashes and failures without raw remote
prose or authentication headers. HTTP, schema, timeout and process errors are
refusals with no manufactured classification. The moving alias can change
behavior; record the returned identity and review any changed model before
depending on its judgments. No schedule, workflow, auto-merge or token-permission
integration is installed by this command.

## Verification

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_maintenance_triage.py' -v
```

These are offline mechanism tests with synthetic responses and keys. They check
wire shape, strict parsing, closed metadata, secret-safe failures, request bounds
and unchanged human-only policy. They do not read a real key, call the model or
measure its accuracy. Live connectivity evidence and independent maintenance
evaluation must be recorded separately; policy never treats either as approval.

A single owner-authorized synthetic `--example --live` check on September 26,
2026 UTC returned HTTP 200 and resolved the requested alias to
`typesafe/jev-1.13-20260917`. The unchanged client parsed the answer as
`insufficient_evidence`; all supplied check results were `unknown`. There was
one request, no retry, and no permission or merge action. This establishes that
one API exchange worked, not classifier accuracy or readiness for unattended
merging. The private receipt records source/request/response hashes and usage.
