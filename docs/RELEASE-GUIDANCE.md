# Public release preparation and primary-source guidance

The source repository is public at [payals/hobnail](https://github.com/payals/hobnail),
and private vulnerability reporting is enabled. The current automation and
verified settings are described in [MAINTENANCE.md](MAINTENANCE.md). This guide
covers future release decisions and optional hardening; a committed desired-state
file does not mean a remote setting is active. Package publication, container
image distribution and deployment remain separate operations.

## License and project entry points

Retain [MIT](../LICENSE), including the existing 2026 copyright notice. There is
no identified compatibility reason in this documentation task to replace it
with Apache-2.0 or add a second license. New third-party material still needs
its own license/provenance review and preserved notices; MIT does not make
separately licensed artifacts part of Hobnail's license.

Use one root [AGENTS.md](../AGENTS.md) for scoped coding instructions, one
[CONTRIBUTING.md](../CONTRIBUTING.md) for setup/checks/review, and the
[agent guide](AGENT-GUIDE.md) for workflow and evidence details. Avoid a redundant
`agent.md`, conflicting instructions or global tool setup. The canonical format
is ordinary Markdown; it supplies no permission or enforcement mechanism.
[AGENTS.md format](https://agents.md/). GitHub recognizes contributor guidelines
and surfaces them when users open issues or pull requests.
[GitHub contributor guidance](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/setting-guidelines-for-repository-contributors).

The README and release notes should state what is usable, how to reproduce it,
the supported matrix and the measured limits. Keep the maintained framework
separate from the legacy schema, local replay separate from live adoption, and
portable CI separate from host/provider qualification. Do not use a badge or a
test total as a substitute for those distinctions.

## GitHub settings to verify before code publication

These are proposed settings and evidence requirements. A Markdown checkbox or
workflow file does not establish that a remote setting is enabled.

| Gate | Required observable result |
|---|---|
| Destination and authority | Owner names the exact account/repository, intended visibility, upload contents and action. Existing Git history/content is reviewed for authorized public disclosure. |
| Private vulnerability reporting | A real monitored private contact is established, or GitHub's reporting feature is enabled and verified on the approved empty public repository before code upload/announcement. SECURITY.md describes the actual route. |
| Secret protection | Verify repository secret scanning and push protection settings for the actual account/plan, alert recipients and bypass handling. Do not rely on the contributor's account default. Review the outgoing tracked tree/history and release archives locally as well. |
| Protected changes | An active branch/ruleset requires the intended PR review and named successful checks, blocks unintended force pushes/deletion and has a documented minimal bypass set. Required checks correspond to actual jobs and their expected source. |
| Release authority | Tag/release creation is restricted to the intended maintainer path. Build provenance, artifact hashes and source revision correspond to the exact published bytes. |

GitHub private vulnerability reporting is available for public repositories and
is distinct from `SECURITY.md`. Do not impose an impossible requirement to enable
it while a repository is private. The owner can first establish a usable private
contact, or authorize creation of an empty public repository, enable its reporting
feature, verify the route and maintainer notification configuration, and only
then authorize the reviewed code push/announcement. Each outward operation keeps
its exact authorization requirement. An absent or unmonitored route remains an
unresolved code-publication gate, not a reason to invite public exploit reports.
[Private reporting configuration](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository),
[reporting workflow](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

GitHub distinguishes repository push protection from account-level protection,
including different configuration and alert behavior. Detection covers supported
patterns and is not proof that all personal data or secrets are absent.
[Push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection),
[secret scanning enablement](https://docs.github.com/en/code-security/how-tos/secure-your-secrets/detect-secret-leaks/enable-secret-scanning).
Branch/tag rules support review, checks and restricted history changes; verify
the effective rules on the actual target instead of assuming defaults.
[Available rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).

Do not inspect personal credential stores to perform these checks. Use only an
explicitly authorized account/tool context when the target and operation are
approved. Do not create a public repository, push, send a security report or
change account permissions as a side effect of preparing these files.

## CI and release build recommendations

Use a small test workflow with explicit minimal token permissions, normally
`contents: read`. Grant any additional permission only to the job that needs it.
Pin reviewed third-party actions to their full commit SHA from the authoritative
repository; retain a human-readable release/version note and review updates.
Avoid interpolating untrusted PR titles, branch names or issue bodies directly
into shell source; pass necessary data through a safe structured boundary.
[GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use).

Use an ordinary unprivileged pull-request workflow to test proposed code. Do
not check out and execute an untrusted PR in a `pull_request_target` job, whose
trust and credentials belong to the base repository. Keep any privileged
triage/release job separate from candidate-code execution and artifacts.
[GitHub's pull_request_target guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).
Do not expose personal/self-hosted runtime state, approved binary paths or live
provider credentials to fork-controlled code.

The prepared workflow uses ephemeral `ubuntu-24.04` GitHub-hosted runners and
an anonymous HTTPS fetch of the validated event repository and exact commit.
It has no third-party action dependency or private-repository authentication
support. It creates the project `.venv` with the runner's existing Python and
`venv --without-pip`, then runs the explicit portable profile and syntax checks
with a clean environment. Local bootstrap/static tests are not evidence that
GitHub has executed the workflow; that observation remains after publication.

Label each job by what it actually checks. Portable contract/SDK tests can run
without native services. PostgreSQL, macOS isolation and the reviewed OpenBao
artifact require separate prerequisites and actual runs. A selected subset is
useful, but it cannot be labeled the entire 320-test historical qualification.
CI action pins and build images remain subject to the owner's artifact review;
a full SHA is not provenance, vulnerability or publication-age evidence by
itself. A dependency bot may propose a reviewed update, not merge/install it
automatically under a weaker policy.

Use the existing offline distribution verifier to bind source contents,
reproducible wheel bytes, archive membership, hashes and installed behavior.
Keep private `.state`, temporary runtimes and raw logs out of public archives.
Review actual archive contents, not only `.gitignore`. Add a reviewed signing
or attestation path to a publication workflow only when its authority and
dependencies are established. GitHub attestations connect artifact identity to
source/build provenance; they do not prove secure code or a qualified runtime.
[Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations).

## Applying OpenSSF and NIST without claiming certification

OpenSSF's concise developer guide supports practices relevant here: justified
dependencies, vulnerability monitoring, negative tests, review before merging,
a usable security reporting process and release integrity. Use those practices
to address concrete risks. No Best Practices badge, Scorecard result, SLSA level
or external audit is claimed. Its general cooldown advice does not replace the
owner's stricter minimum **168-hour** artifact age and quarantine rules.
[OpenSSF concise guide](https://best.openssf.org/Concise-Guide-for-Developing-More-Secure-Software.html).

NIST SSDF 1.1 is the final published baseline consulted here; the NIST publication
list currently labels version 1.2 as draft. Use SSDF to structure the project's
development/review, release-integrity and vulnerability-response responsibilities,
not to declare conformance from a few documents. The repository's authority
model, focused refusal tests, retained failure evidence, source-bound packages
and private reporting preparation are concrete practices to maintain; they are
not an independent SSDF assessment.
[SSDF 1.1 publication](https://csrc.nist.gov/pubs/sp/800/218/final),
[NIST publication status](https://csrc.nist.gov/projects/ssdf/publications).

## Container guidance is a separate qualification

If Docker becomes a supported target, specify the exact reviewed image digests,
component inventory, runtime configuration and real acceptance probes. Prefer
an unprivileged process, read-only filesystem except explicit writable state,
minimal mounts/capabilities, `no-new-privileges`, applicable resource limits and
the normal seccomp restrictions. Keep the worker away from the Docker socket,
host credentials and privileged controllers. Default seccomp is useful but
does not establish Hobnail's authority boundary by itself.
[Docker run controls](https://docs.docker.com/reference/cli/docker/container/run/),
[seccomp](https://docs.docker.com/engine/security/seccomp/).

Rootless Docker changes daemon/container privilege and has prerequisites; it
is distinct from merely setting a container user. Access to the daemon remains
a powerful authority and must be restricted. Do not silently reconfigure the
host daemon or grant a worker its socket to make a test pass.
[Rootless mode](https://docs.docker.com/engine/security/rootless/),
[daemon security](https://docs.docker.com/engine/security/).
Image packaging, a successful container start and native macOS receipts do not
qualify Linux/Docker. Actual denial, credential, verifier, effect and independent
observer paths must be exercised on that target before extending support.

## Release decision record

Before publication, retain the exact source revision, outgoing files/history,
artifact identities, executed checks and limits, actual GitHub setting evidence,
private reporting route/monitor, license review and owner authorization. Keep
private evidence private; publish only the approved redacted record. If any
required item is missing, report that specific item and leave publication
pending. Completing source preparation does not waive the remaining gate.
