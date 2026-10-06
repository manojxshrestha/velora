# Installation & Setup

[← Back to README](../README.md)

## Installation

Requires **Python 3.10+** with `pip`. Everything installs into a virtual environment, so nothing outside it is touched.

**Standard install** — clone, virtualenv, install, verify:

```bash
git clone https://github.com/manojxshrestha/velora.git
cd velora
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[scan]"
velora --version          # -> velora 0.0.1
```

What each step does:

| Step | Purpose |
|------|---------|
| `git clone … && cd velora` | Fetch the source; run everything from the repo root |
| `python3 -m venv .venv` | Create an isolated Python environment under `.venv/` |
| `. .venv/bin/activate` | Put it on your shell's `PATH` (re-run in every new terminal) |
| `pip install -e ".[scan]"` | Install Velora in editable mode **plus the `[scan]` extra** — the tree-sitter frontends that `velora scan` needs |
| `velora --version` | Confirm the `velora` console command is available |

Already inside a virtualenv or CI runner (skip the venv step):

```bash
git clone https://github.com/manojxshrestha/velora.git && cd velora && pip install -e ".[scan]" && velora --help
```

Prefer not to clone? Install straight from GitHub — same one-liner, console command included:

```bash
pip install "velora[scan] @ git+https://github.com/manojxshrestha/velora.git"
```

**Install variants:**

| Command | What you get |
|---------|--------------|
| `pip install -e .` | Minimal: separation-logic solver (`solve`, `check`, `parse`, `repl`) — and the interactive-view dependencies (`prompt-toolkit`, `rich`) are core requirements, so the TTY view never breaks. `velora scan` will refuse with a tree-sitter install hint |
| `pip install -e ".[scan]"` | **Recommended.** Everything: all 5 symbolic language frontends for `velora scan` |
| `pip install -e ".[dev]"` | Test-suite tooling (pytest, coverage, PyYAML, zstandard); combine with `[scan]` — or just use `[all]` — so scanner tests can run too |
| `pip install -e ".[all]"` | `scan` + `dev` combined — the CI `pyproject-install` job runs the full suite from exactly this install |

A clean `pip install .` is a first-class supported path: the packaging CI job
(`pyproject-install`) installs only from `pyproject.toml` and runs `pytest tests/`,
so a dependency that lives only in `requirements.txt` can never silently break
the CLI or the test collection again.

**Verify** (all three must work):

```bash
velora --help    # lists: scan, exploit, fix, solve, check, parse, repl, models, doctor, setup, serve-bridge
velora solve "ls(x, y) * ls(y, z) * x != z |- ls(x, z)"    # -> ✓ VALID
velora scan examples/app.py                                # -> 2 CRITICAL findings; exit code 1 (high+ findings, the default --fail-on high)
```

## Setup

The symbolic engine needs **no setup** — `velora scan` (without `--ai`), `velora solve`, `check`, `parse`, and `repl` work the moment installation finishes. Only the LLM-dependent commands (`velora scan --ai`, `velora exploit`, `velora fix`) need a model endpoint. The zero-key path below gives you one without ever storing an API key.

### Zero-key quickstart (recommended)

```bash
velora setup          # one-time bootstrap (below); safe to re-run, --yes skips the prompt
velora doctor         # diagnose the setup; exit 0 when ready
velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt   # activate a free model
velora doctor --probe # end-to-end check: one real keyless chat through the bridge
```

**`velora setup`** installs whatever is missing, user-local (no sudo): Node ≥ 18 into `~/.local/opt` (symlinked into `~/.local/bin`), the `opencode` CLI, and the bridge's dependencies — then seeds and starts the bridge daemon. It is idempotent (re-running changes nothing that's already present), and `--yes` makes it non-interactive for scripts.

**`velora doctor`** checks the whole chain and exits 1 while anything is missing:

```text
velora doctor
  ✅ platform         Linux … (x86_64) WSL
  ✅ python           Python 3.14.7, velora 0.0.1, z3 5.1.0
  ✅ node             …/node (v22.23.3)
  ✅ opencode         …/opencode (1.18.34)
  ✅ bridge-sources   …/velora/_bridge
  ✅ bridge-runtime   …/share/velora/bridge (deps installed)
  ✅ bridge           healthy on :8399 (pid …)
  ✅ model            opencode-bridge/opencode/mimo-v2.6-flash-free -> http://127.0.0.1:8399/v1 [config]
  ✅ bridge-required  active model is bridge-backed and the bridge is healthy
  ✅ endpoints        bridge: 10; local down: 5/5

ready for zero-key `velora scan --ai`
```

Add `--probe` to go further and send one real keyless chat end-to-end (exit code reflects the result); `--format json` for scripts.

### The bridge

The bridge (`velora serve-bridge`) is a local OpenAI-compatible server on `http://127.0.0.1:8399/v1` that proxies opencode's own client — opencode owns every credential, so Velora stores none. Manage it directly when you don't want `velora setup`/`models tui` to do it for you:

```bash
velora serve-bridge --start     # start the daemon in the background
velora serve-bridge --status    # -> [bridge] healthy on http://127.0.0.1:8399 (pid …)   (exit 0 when healthy)
velora serve-bridge --stop      # stop it (models tui / setup restart it on demand)
velora serve-bridge             # run it in the foreground (Ctrl+C to stop)
```

The daemon logs to `$XDG_STATE_HOME/velora/bridge.log` (typically `~/.local/state/velora/bridge.log`). `velora models tui` auto-starts the bridge whenever you pick a model through it.

### Choosing a model

```bash
velora models list                # Zen catalog: free first, ✓ = usable by Velora
velora models list --free         # free models only
velora models current             # what's active and where it came from
velora models tui                 # full-screen picker (bridge + any local servers), auto-starts the bridge
velora models use zen/glm-5.2     # switch model (example ref; free bridge ref: opencode-bridge/opencode/<id>)
velora models providers           # velora config, env keys, opencode providers
```

`velora models use … --no-prompt` is the non-interactive form. Full provider walkthroughs (Zen key, models.dev registry, local servers, import-opencode) are in [Model Providers](ai-models.md#model-providers).

### Configuration precedence & environment variables

Model settings resolve per field in this order: **`--model` flag → `VELORA_LLM_*` environment variables → `~/.config/velora/config.json` → existing opencode config** (auto-fallback, announced once on stderr; disable with `VELORA_SKIP_PROVIDER_FALLBACK=1`). Every model-printing command tells you which source won, e.g. `using model '…' from velora config (…)`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `VELORA_LLM_BASE_URL` | — | OpenAI-compatible endpoint |
| `VELORA_LLM_MODEL` | — | Model id |
| `VELORA_LLM_API_KEY` | — | API key (leave empty for local servers) |
| `VELORA_LLM_REPO_ROOT` | — | Repo root for the agentic cross-file `read_file`/`grep` tools |
| `VELORA_LLM_TIMEOUT` | `120` | Max gap (seconds) between network bytes on a model call |
| `VELORA_LLM_AGENT_TIMEOUT` | `300` | Socket-gap budget (seconds) between bytes for one agent round-trip; the wall-clock deadline is `max(gap × 2, 600)` s per attempt (pin it absolutely with `VELORA_LLM_TOTAL_TIMEOUT`). Free-tier turns of 30–90 s fit with headroom |
| `VELORA_LLM_AGENT_RETRIES` | `2` | Extra HTTP attempts inside a round-trip before it counts as a failure |
| `VELORA_SKIP_PROVIDER_FALLBACK` | — | `=1` disables the opencode config auto-fallback |

All of them accept the legacy `FRAME_LLM_*` spelling too. Defaults cover the free tier; only reach for the timeouts on unusually slow endpoints.

### Platform support

**Linux (incl. WSL) and macOS.** On native Windows, run `wsl --install` and do everything inside WSL — the bridge will not start from a Windows shell.
