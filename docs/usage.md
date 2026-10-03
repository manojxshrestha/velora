# Usage & Commands

[← Back to README](../README.md)

One CLI, two jobs: a security loop (**scan → exploit → fix → scan again**) and a separation-logic solver. Everything below is copy-pasteable; `velora <command> --help` lists every flag.

**Contents** — [Quick Start](#quick-start) · [Command pack](#command-pack-black-box-white-box--enterprise) · [Scan](#scan) · [Exploit](#exploit) · [Fix](#fix) · [AI & Model Setup](#ai--model-setup) · [Separation Logic](#separation-logic) · [Commands Reference](#commands-reference) · [Troubleshooting](#troubleshooting)

## Quick Start

```bash
velora scan examples/app.py            # bundled demo: two critical findings, no model needed
velora scan .                          # scan the current directory (**/*.py by default)
velora setup && velora doctor --probe   # one-time AI setup: bootstrap + verify (exit 0 = ready)
```

The full loop — one `findings.json` drives every stage:

```bash
velora scan . --ai -f json -o findings.json                       # 1. detect
velora exploit --target https://target.com --guidance findings.json \
  --goal 'read the admin secret'                                             # 2. exploit (live, authorized)
velora fix . --guidance findings.json --diff               # 3. preview patches
velora fix . --guidance findings.json --in-place           # 4. apply + re-scan to verify
velora scan . --ai                                                # 5. confirm it's gone
```

Pipes work too (`-` = stdin): `velora scan . -f json | velora exploit --guidance - --target https://target.com --goal '…'`.

Exit codes everywhere: **`0`** = success/proven/clean · **`1`** = findings / invalid / not solved · **`2`** = usage error or LLM unreachable.

## Command pack: black-box, white-box & enterprise

The three testing modes as ready-to-copy-paste commands. Every command runs as-is: paths are `.`, the remote target is `https://target.com` (one find-and-replace to your own authorized target), plus the local practice target `http://127.0.0.1:8080` (`python examples/practice_target.py`) and `scope.txt` placeholders. `# PROPOSED:` = mission-needed command/flag that is not implemented yet.

### Black-box: live URL only, no source

```bash
# bootstrap Node + opencode + the bridge, and start the daemon (one-time, any mode)
velora setup

# activate a free Zen model through the bridge (no API key needed)
velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt

# verify model + bridge with one live round-trip (exit 0 = healthy)
velora doctor --probe

# map the surface and probe for one high-confidence flaw (recon run)
velora exploit --target https://target.com --goal 'map the application surface (pages, forms, parameters) and probe them for one high-confidence flaw' --max-steps 20

# solve an HTS mission against the live consent-based target
velora exploit --target https://target.com --goal 'solve a beginner-level mission and document the vulnerability' --max-steps 40

# local practice target with an external success oracle (never faked by the model)
velora exploit --target http://127.0.0.1:8080 --goal 'steal the flag from /admin and POST it to /report' --success-check 'curl -sf http://127.0.0.1:8080/pwned' --max-steps 30

# pin success with your own oracle: re-run after every step, exit 0 = solved
velora exploit --target https://target.com --goal 'access a protected page without logging in' --success-check 'curl -sk https://target.com/private | grep -qi secret'

# keep machine-readable output + the full command/response transcript as evidence
velora exploit --target https://target.com --goal 'enumerate the login form and test for SQL injection' --format json --trace-out evidence.json

# AI detection over artifacts in the current dir (curl the target's JS bundles/pages in first)
velora scan . --ai -f json -o findings.json

# PROPOSED: retest previously-fixed findings after a patch lands (command not implemented yet)
velora retest --guidance findings.json --target https://target.com

# PROPOSED: route through Burp and send a program-identifying header (flags not implemented yet)
velora exploit --target https://target.com --goal 'test the upload feature for webshell delivery' --proxy http://127.0.0.1:8080 --header 'X-Bounty: program-slug'
```

### White-box: source in hand, proofs + patching

```bash
# scan the target's source (repo or artifacts you have) -> findings.json
velora scan . -f json -o findings.json --fail-on high

# same scan with AI detection + triage on top of the symbolic engine
velora scan . --ai -f json -o findings.json

# pipe the scan straight into the agent and attack the live target with those leads
velora scan . -f json | velora exploit --guidance - --target https://target.com --goal 'exploit the proven findings on the live target'

# preview model-generated patches as a unified diff
velora fix . --guidance findings.json --diff

# apply patches, then re-scan each file to verify the fix landed
velora fix . --guidance findings.json --in-place
```

### Enterprise: CI gates, fleets, authenticated scale

```bash
# CI gate: exit 1 on criticals, SARIF decorates PRs in GitHub's Security tab
velora scan . --fail-on critical -f sarif -o report.sarif

# fleet setup: daemonize the bridge once per machine, then run doctor --probe
velora serve-bridge --start

# PROPOSED: authenticated enterprise run - scope file + login flow (flags not implemented yet)
velora exploit --target https://target.com --scope scope.txt --login-url https://target.com/login --login-user svc --login-pass-env CORP_PASS --goal 'reach the admin dashboard'
```

- **`--success-check`** is the authoritative oracle: re-run after every step, exit 0 = solved — a model claim can never fake it.
- **`--format json --trace-out`** keeps the machine-readable summary plus the full transcript for the report.
- **Exit codes:** `0` = proven/solved/clean · `1` = invalid findings/not solved · `2` = usage/LLM unreachable.

## Scan

**`velora scan` checks local source** (a file or directory — never a URL) with the symbolic engine; `--ai` adds the LLM layer. No model needed for symbolic scans.

```bash
velora scan examples/app.py                      # one file (~10 ms, demo finds 2 criticals)
velora scan .                                    # current directory, **/*.py by default
velora scan . --pattern "**/*.js"                # explicit file filter (** = every subfolder)
velora scan . -f json -o findings.json           # JSON findings -> feeds exploit / fix
velora scan . --format sarif -o results.sarif --fail-on high   # CI gate: exit 1 on high+
velora scan . --ai                               # symbolic + AI layer (needs a model)
velora scan ./misc -l go --ai                    # force a language for odd extensions
```

- `--fail-on <critical|high|medium|low|any|none>` — severity threshold that makes the command **exit 1** (default `high`); `none` = always exit 0.
- `-f/--format`: `text` (default), `json` (input for `exploit`/`fix`), `sarif` (GitHub code scanning). `-o` writes to a file.
- `--min-severity` hides small findings; `--no-verify` skips verification (faster, more false positives); `--timeout <ms>` per-check solver budget (default 5000); `-v` verbose.
- Directory scans skip `.git`, `node_modules`, `.venv`, `__pycache__`, etc. — `--no-default-excludes` overrides.

Symbolic scans finish in milliseconds; each `--ai` file costs one or more LLM calls (seconds to tens of seconds).

## Exploit

**`velora exploit` drives an LLM agent against a live target** — `--target` is a **URL**, and it must be authorized: a target you own, or one a program lists as in-scope. Practice locally with `python examples/practice_target.py` (serves `http://127.0.0.1:8080`; win by stealing the admin flag to `/report`, then `GET /pwned` returns 200 → `--success-check 'curl -sf http://127.0.0.1:8080/pwned'`).

```bash
velora exploit --target https://target.com --goal 'read the admin secret'
```

One run = one goal. The agent executes real commands (curl, python, nc, sqlmap, …) in a recon → hypothesis → payload → verify loop. Exit **0** = verified success, **1** = not solved.

Key flags: `--goal '<words>'` (specific wording gets specific results) · `--success-check '<cmd>'` (external oracle, overrides agent claims) · `--guidance <findings.json|->` (attack what a scan already proved) · `--max-steps <n>` (default 40) · `--exec-timeout <sec>` (default 120) · `--trace-out <file>` (full transcript for evidence) · `--format json` · `--model <id>` (override for this run).

**Termination:** success is only claimed from observed state — either your `--success-check` oracle exits 0 (authoritative), or the agent's guarded final `VERIFIED: <evidence>` claim (a first-turn echo of the goal never terminates a run).

**Timing:** each step is one model round-trip (30–90 s on the free tier); the banner shows the budget (`deadline 600s/attempt, 3 attempts`) and a heartbeat ticks every 30 s while waiting. A 40-step run typically takes 15–60 min — a stronger model (`velora models use zen/glm-5.2`) or smaller `--max-steps` cuts that.

**Grey-box:** if you have any source (public repo, client drop, deploy artifact), prime the agent — runs converge far faster:

```bash
velora scan . --ai -f json -o findings.json
velora exploit --target https://target.com --guidance findings.json \
  --goal 'exploit the proven SQL injection to dump the users table'
```

### Command patterns

```bash
# 1. baseline unguided run: recon the surface, then attack the stated goal.
#    Exit code: 0 = exploited (verified), 1 = not solved -> iterate.
velora exploit --target https://target.com \
  --goal 'gain access to a protected resource (admin panel or private data)' \
  --max-steps 40

# 2. pin down "success" with an external oracle: your command is re-run after
#    every step, exit 0 => solved (a passing check prints [success-check] <evidence>).
#    Omit it and the agent self-terminates on its guarded VERIFIED: claim instead.
velora exploit --target https://target.com \
  --goal 'execute id on the application server' \
  --success-check 'curl -sf https://target.com/pwned | grep -q "uid="'

# 3. keep the evidence: full trace (system prompt, every command + response)
#    and machine-readable output for the report
velora exploit --target https://target.com --goal '...' \
  --trace-out trace.json --format json > report.json

# 4. iterate as a campaign: run focused goals one at a time (injection on
#    discovered parameters, auth/session bypass, IDOR, SSRF, file upload ...),
#    feeding each success back into the next goal's wording
velora exploit --target https://target.com --goal 'bypass authentication on /admin' --max-steps 60
velora exploit --target https://target.com --goal 'read /etc/passwd via the file download feature'
```

### Bug hunting guide (worked example: `target.com`)

A compact black-box campaign, one hypothesis at a time. **Authorization first:** only test targets you own or are explicitly in scope for — `target.com` is a stand-in for *your* in-scope target (swap it out), your app via `python examples/practice_target.py`, or a program's listed scope.

**Step 0 — Setup (one-time):**

```bash
velora setup && velora doctor --probe   # bootstrap + one real keyless chat (exit 0 = ready)
velora models tui                       # full-screen picker: opencode bridge + local servers
```

**Step 1 — Recon run (unguided):** exit 0 = verified win; exit 1 = iterate on the goal wording.

```bash
velora exploit --target https://target.com \
  --goal 'map the application surface (pages, forms, parameters) and probe them for one high-confidence flaw' \
  --max-steps 20
```

**Step 2 — Focused goals, one at a time.** Goal recipes by class — swap straight into `--goal`:

| Goal class | Example `--goal` wording |
|---|---|
| SQL / NoSQL injection | `test every search/query parameter for SQL injection; try error-based, boolean, and time-based techniques` |
| XSS | `find a reflected or stored cross-site scripting sink on any user-controlled parameter` |
| Command injection | `check whether any form or API parameter reaches a shell command on the server` |
| SSRF | `look for a URL/webhook parameter and point it at 169.254.169.254 to read cloud metadata` |
| Auth / session | `attempt login bypass: default credentials, password-reset flaws, JWT or session tampering` |
| IDOR / authorization | `change numeric ids on resource endpoints; check for horizontal and vertical privilege gaps` |
| File upload | `test the upload feature for unrestricted file types leading to code execution` |
| Secrets / info leak | `search responses, JS bundles, and common backup paths for hardcoded keys or tokens` |

```bash
velora exploit --target https://target.com \
  --goal 'test every search/query parameter for SQL injection' --max-steps 40

velora exploit --target https://target.com \
  --goal 'check whether login reveals which usernames are valid (user enumeration)' --max-steps 30
```

**Step 3 — Pin success with an oracle** and **step 4 — keep the evidence:**

```bash
velora exploit --target https://target.com \
  --goal 'access a protected page without logging in' \
  --success-check 'curl -sk https://target.com/private | grep -qi "secret"'

velora exploit --target https://target.com --goal '…' \
  --trace-out trace.json --format json > report.json
```

**Loop:** feed each success back into the next goal's wording; stop when the step budget stops paying off. Results: `✓ EXPLOITED (…)` = exit 0, verified win — save the trace as evidence; `✗ NOT EXPLOITED (… step budget exhausted)` = exit 1 — raise `--max-steps` or narrow the goal; `✗ NOT EXPLOITED (… model unreachable…)` = exit 1 — run `velora serve-bridge --start` + `velora doctor --probe`. Flags: [Command patterns](#command-patterns).

## Fix

**`velora fix` turns a scan's findings into patches — and proves them.** It reads findings from `--guidance` (required; `-` = stdin) and re-scans each patched file. Needs a model ([AI & Model Setup](#ai--model-setup)).

```bash
velora fix examples/app.py --guidance findings.json --diff         # preview: unified diff, writes nothing
velora fix examples/app.py --guidance findings.json --in-place     # apply: write, then re-scan to verify
```

```text
CWE-89 app.py:20 -> patched (verified✓)
2/2 findings patched (written in place); 2 verified fixed by re-scan.
```

- Per finding: `patched (verified✓)` (fixed, proof) · `patched (STILL DETECTED)` (incomplete) · `verify-skipped` (`--no-verify`) · `could not apply`.
- Flags: `--guidance` (required), `--diff` / `--in-place`, `--no-verify`, `--format json`, `--model <id>`.
- **Exit:** 0 when at least one patch was applied, 1 otherwise.

After `--in-place`, `velora scan` again — fixed findings disappear.

## AI & Model Setup

The symbolic engine never needs a model; the AI layer (`scan --ai`, `exploit`, `fix`) runs on an OpenAI-compatible endpoint — Velora's **zero-key** bridge to opencode's free tier stores no API key.

```bash
velora setup                                  # 1. bootstrap what's missing (user-local, no sudo) + start the bridge
velora models tui                             # 2. pick a model interactively (bridge + local servers, probed live)
velora doctor --probe                         # 3. verify with one real keyless chat (exit 0 = ready)
velora scan . --ai                            # 4. go
```

```bash
velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt   # non-interactive pick (scripts)
velora models list                            # browse (--free, --registry, --query <s>)
velora models current                         # active model
velora models use zen/glm-5.2                 # stronger hosted model (needs its key)
velora serve-bridge --start                   # restart the bridge daemon (port 8399)
velora serve-bridge --status                  # daemon health (exit 0 when healthy)
velora serve-bridge --stop                    # stop it
```

**Model not responding** (`no response from the model`, `model unreachable`, `doctor` exits 1) → the bridge daemon is down:

```bash
velora serve-bridge --start     # restart the daemon
velora doctor --probe           # verify: one real test chat (exit 0 = working)
```

- `--model <id>` on `scan`/`exploit`/`fix` overrides the active model for one run.
- Keys (if you use your own endpoint) live in `~/.config/velora/credentials.json` (0600); env vars `VELORA_LLM_BASE_URL` / `VELORA_LLM_MODEL` / `VELORA_LLM_API_KEY` also work.
- `velora models --help`: `list`, `use`, `current`, `providers`, `import-opencode`, `tui` with `--free`, `--registry`, `--refresh`, `--base-url`, `--api-key`, `--no-prompt`, `--local-url`.

## Separation Logic

Velora's soundness core, exposed directly — pure Z3, **no model, no setup**: you give it heap descriptions, it tells you whether one entails another.

### `velora solve` — check one entailment

```bash
velora solve "ls(x, y) * ls(y, z) * x != z |- ls(x, z)"    # -> ✓ VALID (exit 0) / ✗ INVALID (exit 1)
```

Flags: `--model` prints a countermodel when invalid, `-v` shows solving steps, `--timeout <ms>` (default 5000), `--unfold-depth <n>` (default 3), `--format json`.

### `velora check` — batch-check a file

```bash
velora check formulas.txt                                  # one entailment per line; totals + invalid list
velora check formulas.txt --format json --stop-on-failure  # scriptable, halt at first failure
```

Exit 1 if any line is invalid. Also `--format csv`, `-o <file>`, plus the `solve` flags.

### `velora parse` — inspect a formula

```bash
velora parse "x |-> y * y |-> z"                           # print the AST (grammar/precedence debugging)
```

`--format tree` (default), `json`, or `sexp`; `-f <file>` reads the formula from a file.

### `velora repl` — interactive checking

```bash
velora repl                                                # type entailments, then :parse <formula>, :help, :quit
```

`--timeout <ms>` sets the per-query solver timeout.

## Commands Reference

One CLI for the whole workflow plus the solver. `velora <command> --help` prints every flag; the sections above explain when and why to use each one.

### Core security

| Command | What it does |
|---------|--------------|
| `velora scan <path>` | Scan local source (`<path>` = file or directory) for vulnerabilities. Symbolic by default; `--ai` adds the LLM layer. `-f json\|sarif`, `-o`, `--fail-on <sev>` (default `high`), `--pattern`, `-l`. |
| `velora exploit --target <url>` | Agent against a live, authorized target. `--goal`, `--success-check`, `--guidance <findings.json\|->`, `--max-steps`, `--exec-timeout`, `--trace-out`, `--format json`. Exit 0 = verified success. |
| `velora fix <path>` | Patch each finding, then re-scan to prove it's gone. `--guidance` (required), `--diff` / `--in-place`, `--no-verify`, `--format json`. Exit 0 when ≥1 patch applied. |

### AI / setup

| Command | What it does |
|---------|--------------|
| `velora setup` | One-time bootstrap: install missing prerequisites user-local (no sudo), seed and start the bridge. `--yes`, `--no-start`, `--no-probe`. |
| `velora models` | Browse & switch AI models for `--ai`. `list` (`--free`, `--registry`, `--query`), `tui` (full-screen picker: opencode bridge + local servers, probes and auto-starts the bridge), `use <ref>`, `current`, `providers`, `import-opencode`. |
| `velora doctor` | Diagnose the zero-key AI setup; exit 1 when not ready. `--probe` sends a live keyless chat, `--format json`. |
| `velora serve-bridge` | Local OpenAI-compatible bridge to opencode (zero-key `--ai`). `--start` / `--stop` / `--status` manage the daemon on port 8399. |

### Separation logic

| Command | What it does |
|---------|--------------|
| `velora solve "<P> \|- <Q>"` | Check one entailment → `✓ VALID` / `✗ INVALID`; `--model` countermodel, `-v` steps, `--format json`. |
| `velora check <file>` | Batch-check entailments (one per line); totals + invalid list; `--format json\|csv`, `-o`, `--stop-on-failure`. |
| `velora parse "<formula>"` | Parse and display a formula's AST; `--format tree\|json\|sexp`. |
| `velora repl` | Interactive separation-logic REPL (`:parse`, `:help`, `:quit`). |

## Troubleshooting

| Problem | What it means | What to run / how to fix |
|---------|---------------|--------------------------|
| `Error: Target not found: ./repo` | The `scan` target path doesn't exist on your machine | Check with `ls`; run from inside the project, or use `velora scan examples/app.py` (always present) |
| `velora scan` prints findings but exits 1 | Not a crash — the severity gate: default `--fail-on high` exits 1 when high+ findings exist | Expected for a vulnerable file; `--fail-on none` to always exit 0 |
| `--ai` says no endpoint/model configured | No model set up yet | `velora setup`, then `velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt` |
| `bridge ... not running` / `velora doctor` exits 1 | Bridge daemon is down | `velora serve-bridge --start` (or run `velora models tui`, which starts it for you) |
| Exploit sits on `thinking...` for a while | Normal free-tier latency (30–90 s per step; deadline 600 s per attempt, ≤3 attempts + one step retry) | Watch the heartbeat (`[llm] · still waiting… 120s/600s`) — if it keeps ticking the turn is alive; verify the chain with `velora doctor --probe`, or switch to a faster model |
| `no response from the model -- retrying` in an exploit run | One round-trip came back empty (slow/overloaded endpoint); it retries automatically | Wait — if the run ends `✗ NOT EXPLOITED (reason=model unreachable after 2 failed attempts)` the endpoint is really down: `velora doctor --probe`, `velora serve-bridge --start`, check `~/.local/state/velora/bridge.log` |
| Exploit ends `✗ NOT EXPLOITED` | Step budget ran out or the goal wasn't achieved | Rephrase `--goal`, raise `--max-steps`, use a stronger model, or add `--guidance` from a scan |
| `velora scan --ai` is slow on first files | Model cold start / bridge warm-up | Normal; later files are faster |
