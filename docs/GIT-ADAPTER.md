# Local Git commit adapter

`git.commit` integrates an accepted bundle into one configured local repository.
It creates a real commit with the approved parent, complete tree and message,
then requires an independent observer to inspect the current repository before
Hobnail reports completion. It never fetches, pushes, contacts a remote, or
changes the repository's configured author identity.

The supported surface is deliberately narrow: an ordinary repository with a
clean complete index/worktree, no active hooks, and no unsupported Git storage
or content transformations. Existing applications can use the adapter through
the same effect API as `file.publish`. This does not activate a live project, replace
its verifier, reset its budgets, or establish autonomous project completion.

## Declaration and exact artifact

Register an effect plugin with ID `git.commit`, backend `local-git`, and
`implementation` equal to
`hobnail.git_effects.implementation_digest()`. Registration remains an approver
operation. The manifest's input media type is `application/json`.

An approved action has this shape:

```json
{
  "name":"maintenance_commit",
  "plugin":"git.commit",
  "plugin_digest":"<registered manifest digest>",
  "target":"maintenance-repository",
  "arguments":{
    "branch":"main",
    "base_commit":"<complete 40- or 64-character lowercase Git object ID>",
    "paths":["src/report.py","tests/test_report.py"],
    "message":"Fix report field validation"
  },
  "max_age_seconds":300
}
```

The protected adapter configuration maps `maintenance-repository` to one
canonical local directory. The worker cannot submit a destination path or URL.
The submitted artifact is strict UTF-8 JSON mapping exactly the approved paths
to even-length lowercase hexadecimal file contents:

```json
{"src/report.py":"706173730a","tests/test_report.py":"706173730a"}
```

Those example bytes are illustrative; applications supply their actual accepted
content. The total JSON artifact is at most 1 MiB. There are 1–64 unique paths,
each at most 1,024 UTF-8 bytes using ASCII letters, digits, `_`, `.`, `/` and `-`.
Absolute paths, empty/dot/dot-dot components, path-prefix conflicts and case
aliases at any directory component are refused. The resulting complete tree is
also checked for case aliases.

Targets cannot include `.git`, `.gitignore`, `.gitattributes`, `.gitmodules`,
`.gitconfig`, `.githooks`, `.husky`, or `.pre-commit-config.yaml` as a component
(case-insensitive). This version adds or replaces regular files. It supports no
deletion, rename, symlink, submodule, or executable-mode change. Existing file
permissions are preserved; new files use regular mode `0644`.

The branch must be a valid explicit `refs/heads/<branch>` name. The message must
be nonblank, at most 2,048 UTF-8 bytes, contain no NUL or carriage return, and
have no terminal newline. Git stores that message followed by one newline.
The API matches the request's arguments to the approved action exactly.

## Runtime use

```python
from hobnail.git_effects import GitCommitter, GitObserver, dispatch_git, observe_git

# Trusted service configuration, not worker-supplied arguments.
committer = GitCommitter({"maintenance-repository": "/srv/protected/project"})
observer = GitObserver({"maintenance-repository": "/srv/protected/project"})

# adapter_client and observer_client authenticate as independent principals.
dispatch_receipt = dispatch_git(adapter_client, effect_id, committer)
observation_receipt = observe_git(observer_client, effect_id, observer)
```

For separate operating-system identities, configure a read-only observer group
with `GitCommitter(..., observer_group=gid)` and set
`GitObserver(..., adapter_owner_uid=uid)` to the adapter's actual owner.
The repository, index and object storage must already grant that observer the
required read access. This configuration does not grant the worker repository
write access. Test the actual identities and filesystem permissions before
claiming an exclusive protected path; different database usernames alone do
not establish that boundary.

Dispatch claims a fenced reservation, verifies the approved implementation and
artifact bytes, and commits `effect.dispatch` before running the Git consumer.
A lost dispatch response causes no consumer invocation. A successful Git call
records `attempted`; only `effect.observe` from the independent observer can
establish `complete`.

## Supported repository boundary

The adapter refuses these conditions before changing the branch:

- A destination outside its trusted alias map, a noncanonical path, a bare
  repository, linked worktree, `.git` locator file, alternate/shared object
  storage, shallow/grafted history, or loose/packed replacement refs.
- Symlinked, hardlinked or unprotected Git administrative storage; a repository
  or relevant file writable by other users; unmerged, sparse, split, hidden or
  changed index entries; dirty tracked or untracked work.
- Active executable hooks, hook-directory overrides, fsmonitor, filters,
  attributes, signing/GPG settings, external diff/merge commands, unsupported
  index/extensions configuration, or configuration includes whose inactivity
  has not been established. Sample hook files are inactive and permitted.
- Missing local `user.name` or `user.email`. The adapter never invents those
  values or injects author/committer environment variables.

One narrow conditional-include case is supported: a
`hasconfig:remote.*.url` include is known inactive when no remote URL keys exist.
The probe inspects configuration key names without reading credential values,
remote URLs or include destinations. All other includes refuse. Ambient Git
repository, identity and configuration overrides refuse; `GIT_PAGER` is a
display preference and is never executed because commands use `--no-pager`.

The adapter checks actual active attributes, including defaults outside the
repository. It does not turn them off. It likewise does not pass `--no-verify`,
change `core.hooksPath`, suppress signing, or otherwise disable existing controls.
A repository needing those features requires a separately implemented and
qualified adapter.

Current inspection bounds are 10,000 tracked files, 8 MiB per existing file,
64 MiB of tracked working content, and 50,000 administrative storage entries.
Each Git command has a 15-second timeout; responses above 4 MiB stdout or 64 KiB
stderr are refused after capture. This is not a process-memory limit. These are
support limits, not measured workload throughput claims.

## Expected-base integration and recovery

The adapter creates a private index from the approved base, hashes the accepted
bytes, builds the full intended tree and creates a commit using `commit-tree`.
This plumbing path is permitted only after proving the supported repository
has no active hooks or unsupported configuration. The target's actual local
identity remains authoritative.

Before changing the branch, it records durable intent and a prepared commit,
preserves the original index, and rechecks repository identity, policy, source
bytes, branch and original index. The actual branch update is a compare-and-swap:

```text
git update-ref refs/heads/<branch> <prepared-commit> <approved-base>
```

A competing commit causes that operation to fail. It is not overwritten.
After the compare-and-swap, the adapter installs only accepted paths and the
prepared index, then rechecks the complete current worktree/index. The ordinary
`.git/index.lock` and a separate adapter lock reserve cooperating writers;
they do not prevent an arbitrary editor with repository write access. Exclusive
adapter ownership remains a required deployment assumption.

The per-effect append journal lives under `.git/hobnail-effects/`. Its key binds
the effect ID and candidate binding digest. It records the artifact digest,
approved arguments, prepared commit and settlement phases. An unresolved
failure preserves the journal, locks, original index and private prepared
index. No reset, ref rewind, unrelated edit removal or automatic retry occurs.
The SQL effect becomes uncertain and requires reconciliation.

The observer independently reads the current symbolic branch, HEAD, complete
tree, single parent, exact message, working bytes and index. A journal alone is
insufficient; a matching commit without this effect's protected provenance is
also insufficient. A replay after a completed consumer operation discovers the
existing commit and does not create another commit. The SQL dispatcher refuses
redispatch after a committed dispatch point.

After partial installation, observation returns `unknown` until the actual
state can be resolved. An unrelated competing commit is preserved and can
produce a mismatch. Returning to the original base with an existing intent
also requires reconciliation. `absent` does not mean the action never happened.
Never remove a retained lock simply to make the next attempt proceed: inspect
the exact ref, journal, preimage and affected files first, then obtain authority
for the specific repair. A needed subsequent change is a new authorized effect.

## Verification and limits

Run the focused tests with:

```sh
python3 -m unittest discover -s tests -p 'test_git_effects.py' -v
```

The tests use freshly owned repositories and synthetic local Git identities.
They commit actual accepted bytes and exercise independently observed completion,
dirty/staged preservation, active hooks and filters, packed replacement refs,
administrative aliases, foreign index locks, a real competing ref update,
partial filesystem failure, malformed journals, duplicate-free reconciliation
and the real PostgreSQL effect lifecycle including a lost report response.

These tests qualify those named local mechanisms. They do not establish a live
orchestration deployment, worker isolation, network containment of arbitrary code,
semantic maintenance quality, or owner-free project autonomy. The Git executable,
adapter/observer configuration, protected filesystem and control plane remain
trusted components. No public repository or remote publication is created.
