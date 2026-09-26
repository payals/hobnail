# Prepared GitHub maintenance controls

These files prepare `payals/hobnail`; they have not created a repository, pushed
code, activated settings, opened a pull request, or granted a bot authority.
The goal is reviewed, reproducible maintenance with preserved failures. Named
checks provide bounded evidence; neither a green badge nor an LLM review may
change the acceptance policy or declare a release ready.

## Files and live activation

| Prepared file | Meaning | Live step still required |
|---|---|---|
| `.github/rulesets/main.json` | Importable branch ruleset for `main` and the default branch; no bypass actors | Import after the reviewed initial public commit and successful CI, then verify actual enforcement |
| `.github/repository-settings.json` | Desired-state document, **not an API request or an applied receipt** | Owner applies and verifies each supported repository setting |
| `.github/dependabot.yml` | Weekly `pip` and `github-actions` proposals; seven-day version cooldown | Enable dependency graph, Dependabot alerts and security-update PRs |
| `.github/workflows/security.yml` | Read-only, dependency-free source/history scan plus optional public dependency review | Observe actual PR and scheduled executions after publication |
| `security/scan-allowlist.json` | Exact file/rule/match-hash exceptions for reviewed synthetic fixtures | Code-owner review for every change; no wildcard or directory-wide exclusions |

The ruleset requires a pull request, one approving code-owner review, dismissal
of stale approvals, approval of the latest reviewable push by someone other than
its pusher, resolved discussions, and fresh-base success for `portable` and
`security`. It blocks force pushes and deletion and permits squash merging only.
The import JSON deliberately omits `integration_id` because no live App ID has
been verified. Before calling activation complete, select the actual **GitHub
Actions** source for both required contexts. Record the live ruleset and perform
an independently observed refused-merge check. Required checks must have run
successfully in the repository recently before they can be selected reliably.
[Ruleset creation and parameters](https://docs.github.com/en/rest/repos/rules),
[required-check troubleshooting](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks).

GitHub may accept `skipped` or `neutral` as satisfying a required check. The
required `security` job therefore runs unconditionally on `pull_request` without
path filters, `continue-on-error`, or a conditional job skip. Scheduled or manual
success is not a substitute for the exact pull request's eligible check result.
An eventual merge controller must require actual `success`, the exact latest
SHA, the expected App, a current base, and the independently approved change.
Review workflow and scanner changes: a check name alone cannot prove that an
untrusted pull request preserved the measuring code.

For a sole maintainer, these review requirements are intentional: an author
cannot approve their own pull request. With the current `* @payals` code-owner
rule, owner-authored changes need a second genuinely independent authorized
code owner configured before activation; an arbitrary second review alone
cannot satisfy the code-owner requirement. A Dependabot-authored change can be
reviewed by the owner, provided the owner did not supply its latest reviewable
push. An LLM, a
second identity controlled by the worker, or an administrator bypass does not
silently substitute for independent acceptance. Do not lower the review count
to get a maintenance pull request through.

## What the security job establishes

The workflow fetches the exact GitHub event SHA anonymously from the intended
public repository, with complete selected ancestry and no submodules, hooks,
credential helper, replacement refs or lazy fetching. It refuses a shallow
history or an absent/wrong `PUBLIC-SOURCE.json` identity marker. It does not use
the owner's original development checkout or private history. The marker's
initial file list is not treated as the current file list: new committed files
remain included in the scan.

The native scanner examines current and historical tracked objects and emits
redacted signature/privacy findings. Exact reviewed synthetic exceptions remain
visible. Commit attribution in ordinary public CI accepts documented GitHub
no-reply identities, including platform/bot attribution; contributors must use
their GitHub no-reply email. Initial export retains its stricter owner-only
policy. This is not proof that all possible secrets or vulnerabilities are
absent. Never print a detected secret or test whether it works against a service.

Set repository variable `HOBNAIL_DEPENDENCY_REVIEW=enabled` to request the
additional PR dependency-graph comparison. It uses the public REST endpoint
without a token. Added vulnerable dependencies block; HTTP errors, rate limits,
unsupported access and malformed evidence are explicit failures, not a clean
result. Pagination, a partial-content range, truncation evidence or a mismatched
response length also refuse; the client never treats a clean first page as a
complete comparison or follows a server-supplied next-page URL. GitHub documents
pagination through the response's `Link` header.
[Pagination semantics](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api).
Without the variable it reports `not_configured`; non-PR events report
`not_applicable_to_event`. The mandatory source/history scan still executes.
This optional comparison does not decide package age, provenance, licensing or
runtime applicability. [Dependency-review API](https://docs.github.com/en/rest/dependency-graph/dependency-review).

## Dependabot and artifact review

The project currently has no third-party Python requirements, build requirements,
or workflow `uses:` actions. Dependabot configuration establishes a future
proposal path; it cannot produce meaningful updates to dependencies that do not
exist. `docker/images.lock.json`, native Python/PostgreSQL/OpenBao executables,
Docker Desktop and operating-system packages are outside these two ecosystems.
Their pinned artifacts keep the separate authoritative registry, publication-age,
integrity, provenance, vulnerability and runtime review requirements.

Seven-day cooldown applies to **version updates only**. GitHub security-update
PRs ignore it, and are not limited by the version-update PR limit. A proposed
security fix is not permission to install or merge it. The owner must approve
any qualifying under-168-hour advisory exception; prereleases remain excluded.
Do not enable `insecure-external-code-execution`, add registry credentials, group
unrelated changes, or disable a finding simply to make an updater succeed.
[Dependabot configuration](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference).

## Scheduled checks, CodeQL and advisory review

The source scan runs weekly at Monday 06:37 UTC, as well as on pushes, PRs and
manual dispatch. GitHub schedules can be delayed or dropped, and public scheduled
workflows may be disabled after 60 days without repository activity. Monitor the
last real execution; do not manufacture keepalive commits or claim a perpetual
watchdog. [Schedule semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

CodeQL default setup is a proposed live setting for Python and Actions. Inspect
its actual language coverage and successful runs after enablement. It does not
analyze PostgreSQL SQL/PLpgSQL authority, replace runtime refusal/effect tests,
or establish the dependency-age gate. Default setup is GitHub-managed; its
scanner versions update independently. Its fork/Dependabot and merge-group
limitations must be checked before making it a merge requirement. If exact
scanner artifact pins are required, prepare and review an advanced setup instead.
[CodeQL setup types](https://docs.github.com/en/code-security/concepts/code-scanning/setup-types).

The separate [maintenance triage command](MAINTENANCE-TRIAGE.md) supplies Jev
with explicitly selected, closed public metadata: dependency/version category,
advisory identifiers and independent check states. It discovers or uploads no
repository, raw source, diff, log, PR prose or private context. Its model evidence
does not establish the truth of those input facts. The optional
[Jev advice boundary](JEV-ADVICE.md) is a separate contract/evidence channel.
Neither path can approve its own proposal, modify rules or required checks,
merge, publish, create releases or deploy. The model identity and authenticated
external call follow their explicit configuration; this workflow neither loads
an API key nor calls the model. Failure or unavailable output remains visible
and cannot become fabricated approval.

## Fork security and automatic merging

Run untrusted fork code only in ephemeral GitHub-hosted jobs with no secrets or
write token. Keep Actions' ability to create/approve PRs disabled. Require owner
approval for outside-contributor workflow runs. Do not execute fork code through
`pull_request_target` or a privileged `workflow_run`, use a persistent workstation
runner, interpolate PR text into shell commands, or consume a fork's artifact as
trusted executable/configuration. The current security job declares
`permissions: {}` and uses no third-party actions.
[GitHub's untrusted-PR guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).

Automatic merging is disabled. A later proposal may queue an exact reviewed
Dependabot PR for GitHub's ordinary auto-merge after **human owner approval**,
all exact-SHA checks and the artifact gates. It must verify bot identity, changed
paths and manifests, disallow changes to policy, evaluators, workflows, tests,
credentials, isolation and migrations, and stop when the head changes. Labels,
semver-patch claims, LLM approval and an absence of scanner alerts are not merge
authority. No approve/merge workflow is supplied here.

## Public-repository availability

GitHub Free supports public branch rulesets/protection, Dependabot, CodeQL,
secret scanning and ordinary PR auto-merge. Standard hosted runners are free for
public repositories; larger runners and storage have separate limits or charges.
User-owned `payals/hobnail` has no organization teams or personal-repository merge
queue. Do not assume organization-only controls or paid Copilot review
entitlements. GitHub CodeQL's public-repository terms are separate from Hobnail's
MIT license, and model-provider usage can incur costs. None of these features
is activated merely by committing the prepared files.
[Ruleset availability](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets),
[CodeQL availability and terms](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli),
[Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).
