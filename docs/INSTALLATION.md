# Install Hobnail and run your first example

This guide installs the Python SDK and `hobnail` command from the public source
repository. Start with the SDK on macOS or Linux; PostgreSQL is only needed
when you reach the database-backed workflow.

## Choose a supported path

| Your environment | Start here | Full workflow support |
| --- | --- | --- |
| macOS | SDK installation below | Native demo and role workflows require PostgreSQL 18 and the built-in `sandbox-exec` backend. The checked native reference uses Python 3.14 and PostgreSQL 18.3. |
| Linux | The same SDK/CLI installation and portable source checks | Native macOS helpers cannot run here. The Docker implementation has a separately qualified Linux ARM64 reference, but its runtime artifacts are not yet distributed as an installable public image. |
| Native Windows | Not a supported onboarding target in this release | No native Windows runtime or tested Windows installation recipe. |
| WSL2 | Treat as a Linux environment, not native Windows support | WSL2 has not been separately tested or qualified. |

Python 3.11+ is the package's compatibility target, not a claim that every
Python/OS combination has been tested. See [SUPPORT.md](SUPPORT.md) for the
exact reference configurations.

## 1. Install the SDK and command

Prerequisites: Git, Python 3.11 or newer, and Python's `venv` support with bundled
pip. On Debian/Ubuntu, `venv` support may be provided by the distribution's
`python3-venv` package. Obtain prerequisites through your normal reviewed
installation process; Hobnail does not download or install them for you.

From a directory where you want a new checkout:

```sh
git clone https://github.com/payals/hobnail.git
cd hobnail
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip --isolated install --no-index --no-deps --no-build-isolation .
.venv/bin/hobnail --help
```

If you already have this checkout and its `.venv`, reuse them and start at the
local install command. Do not replace another project's environment.

The install builds this checkout with Hobnail's standard-library build backend.
It installs no third-party runtime or build dependencies and contacts no package
index. `--no-build-isolation` uses the existing environment; this project's
build requirements are empty. These are [local-project pip installation options](https://pip.pypa.io/en/stable/cli/pip_install/).

The help output lists `call`, `validate`, `coverage`, and `discover`. Activating the virtual environment in your shell
is optional: the commands above use the installed executable directly. The
module entry point also works:

```sh
.venv/bin/python -I -m hobnail --help
```

Installing the Python package does **not** start PostgreSQL, provision a database
or start an MCP server. Keep this source checkout: database migrations, workflow
scripts, Docker tooling and guides ship with the source, not inside the SDK wheel.
There is no `CREATE EXTENSION hobnail` installation command.

## 2. Try the installed SDK without a database

This inspects a small JSON artifact and suggests checks you could put in a
contract. `-I` ensures the example imports the installed package rather than a
module injected through the current directory or `PYTHONPATH`.

```sh
.venv/bin/python -I - <<'PYCODE'
from hobnail import discover

suggestions = discover(b'{"total":7}')
print("Authoritative:", suggestions["authoritative"])
print("Suggested checks:", ", ".join(item["plugin"] for item in suggestions["suggestions"]))
PYCODE
```

Expected output:

```text
Authoritative: False
Suggested checks: bytes.sha256, json.required_fields
```

Discovery is authoring assistance. It does not approve a contract, verify that
`total` is correct, or authorize an action. [The architecture](ARCHITECTURE.md)
explains where those decisions happen.

## 3. Run an accepted workflow and two refusals on macOS

Prerequisites: macOS, `/usr/bin/sandbox-exec`, and PostgreSQL **major 18** binaries
on `PATH`. `initdb`, `postgres`, `psql`, and `pg_ctl` must come from the same
installation. You do not need to start a database service. PostgreSQL's
[download page](https://www.postgresql.org/download/) lists platform installers.

Check the binaries before running the demo:

```sh
initdb --version
postgres --version
psql --version
pg_ctl --version
```

If PostgreSQL 18 is already installed through Homebrew but its binaries are not
on `PATH`, use this optional macOS-only adjustment, then repeat the checks above:

```sh
export PATH="$(brew --prefix postgresql@18)/bin:$PATH"
```

From the checkout root with the SDK environment created in step 1:

```sh
.venv/bin/python scripts/local_demo.py
```

The default `all` scenario runs an accepted report, a report with an incorrect
order count, and a stale-input refusal. Successful execution exits with code 0
and prints a JSON receipt containing `"run_status": "completed"` and
`"runtime_stopped": true`. Expected refusals are successful demo controls;
a runtime error still makes the command fail.

The demo creates and stops its own private PostgreSQL cluster and retains its
receipt and output paths for inspection. It does not use a shared/default
database or discover personal credentials. Keep its generated receipts and
runtime directories private. The input is synthetic and one trusted controller
holds the demo credentials; this is not a production deployment qualification.

For your own contract, follow the complete [native application example](NATIVE-APPLICATION.md).
For the separate native role-boundary qualification, use
[NATIVE-DEPLOYMENT.md](NATIVE-DEPLOYMENT.md). Do not run these macOS helpers on
Linux and assume they will select an unrestricted fallback; they refuse there.

## Linux and Docker

The SDK, CLI and portable source checks have a Linux path. These do not provide
a Linux replacement for macOS's native service/parser isolation:

```sh
.venv/bin/python scripts/check_portable.py
```

There is currently **no published Hobnail Docker image, Docker Compose quick
start, or public-only build recipe for the qualified images**. The public tree
contains the supervisor, assembler, image pins and profiles, but omits the
reviewed closure inventories, downloaded source layers and derived rootfs
archives. The assembler cannot recreate the reviewed artifacts from this
checkout alone. An ordinary upstream PostgreSQL/Python image is not that
qualified runtime.

Maintainers who already have the exact approved artifacts can follow the
[Docker reference command](DOCKER-DEPLOYMENT.md#run-the-bounded-qualification).
That is a conditional qualification recipe, not a public Docker installation
shortcut. The qualified reference is Linux ARM64 on the recorded Docker
Desktop/Engine/kernel combination; x86 images and other hosts are not qualified
by that run. A distributable Docker build/install path remains separate work.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Python version is below 3.11 | Select an installed Python 3.11+ interpreter before creating `.venv`. |
| Creating `.venv` says `ensurepip` or `venv` is unavailable | Install the matching virtual-environment support for your Python using your normal platform process. Do not switch to global pip. |
| Existing `.venv` has no pip | It may have been created with `--without-pip`. If your Python includes it, `.venv/bin/python -m ensurepip` bootstraps the bundled pip without a download. Then rerun the local install command. |
| `hobnail` is not found | Use `.venv/bin/hobnail`, or activate this checkout's environment. The SDK install does not install a global command. |
| The installed command works but a workflow script is missing | Run from the cloned source tree; workflow scripts and migrations are not installed into the wheel. |
| `initdb` is missing or reports another major version | Put one complete PostgreSQL 18 binary directory on `PATH`; check all four commands above. |
| Native isolation is unavailable | Confirm you are on the supported macOS path. Linux/Windows do not inherit that backend. Do not disable isolation to make the example pass. |
| A demo fails | Read its reported `evidence_file` and failure stage. Keep the failed receipt; do not point it at another project's database or erase its evidence. |

[Python virtual environments](https://docs.python.org/3/library/venv.html) ·
[Operations](OPERATIONS.md) · [Agent guide](AGENT-GUIDE.md) ·
[Security reporting](../SECURITY.md)
