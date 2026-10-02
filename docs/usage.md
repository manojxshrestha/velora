# Usage & Commands

[← Back to README](../README.md)

Velora is one CLI covering a security workflow and a separation-logic solver. The security workflow is a loop:

```text
scan → exploit → fix → scan again
```

You scan local source for vulnerabilities, take the findings to a live authorized target, patch the code, and re-scan to prove each fix. Everything below is copy-pasteable, and every command explains what it produces and where that output goes next. Run `velora <command> --help` for the complete flag list of any command.

**Contents** — [Quick Start](#quick-start) · [Scan](#scan) · [Exploit](#exploit) · [Fix](#fix) · [AI & Model Setup](#ai--model-setup) · [Separation Logic](#separation-logic) · [CI/CD](#cicd) · [Commands Reference](#commands-reference) · [Troubleshooting](#troubleshooting)

## Quick Start

Two commands are enough to see Velora work. Both run as-is in a fresh clone.

**The simplest scan** — from inside any project directory:

```bash
velora scan .
```

This scans the folder you are standing in (`.` = current directory) for vulnerabilities, using the symbolic engine. No model, no setup — results print to your terminal in milliseconds.

**The bundled demo** — a tiny intentionally-vulnerable file that ships with the repo, so you always have something to scan:

```bash
velora scan examples/app.py
```

It scans that single file and reports what it finds (see [Example output](#example-output) below).

**The full loop.** One findings file drives every stage — scan produces it, exploit and fix consume it, and the final scan proves the fixes landed:

```bash
velora scan ./target-app --ai -f json -o findings.json        # 1. detect
velora exploit --target http://localhost:8080 \                # 2. exploit
  --guidance findings.json --goal 'read the admin secret'
velora fix ./target-app/app.py --guidance findings.json --diff     # 3. preview fix
velora fix ./target-app/app.py --guidance findings.json --in-place # 3. apply fix
velora scan ./target-app --ai                                 # 4. confirm it's gone
```

Stage by stage:

| Stage | Command | What it does | Output / next step |
|---|---|---|---|
| Detect | `velora scan ./target-app --ai -f json -o findings.json` | Scans the source (symbolic engine + AI layer) and writes findings to `findings.json` | `findings.json` is the hand-off file: `exploit` and `fix` both read it via `--guidance` |
| Exploit | `velora exploit --target http://localhost:8080 --guidance findings.json --goal '…'` | Drives an agent against a **live, authorized** target to turn a proven finding into a working exploit | Exit code 0 = verified success; the transcript is your evidence |
| Fix (preview) | `velora fix ./target-app/app.py --guidance findings.json --diff` | Generates a minimal patch per finding and prints it as a unified diff — nothing is written yet | Review the diff on screen |
| Fix (apply) | `velora fix ./target-app/app.py --guidance findings.json --in-place` | Writes the patches to the files, then re-scans each patched file to confirm the vulnerability is gone | Per-finding `patched (verified✓)` lines |
| Confirm | `velora scan ./target-app --ai` | Re-scans the whole project: the findings that were fixed no longer appear | Green run = the loop closed |

Paths are placeholders — swap in your own project (`examples/app.py` works out of the box). The stages also compose as a shell pipe, using `-` for stdin:

```bash
velora scan ./target-app --ai -f json | \
  velora exploit --target http://localhost:8080 --guidance - --goal 'read the admin secret'
```

Exit codes are scriptable throughout: `scan` gates on severity (`--fail-on`, default `high`), `exploit` returns 0 only when success was *verified*, and `fix` returns 0 when at least one patch was applied.

## Scan

**`velora scan` checks local source files for vulnerabilities** with Velora's sound symbolic engine (taint analysis + Z3 verification). Use it as the first stage of the loop — and any time you change code.

**The target is a path on your machine** — a file or a directory, *not* a URL (URLs are targets for [`velora exploit --target`](#exploit)). A path that does not exist gives:

```text
Error: Target not found: ./repo
```

Either run the scan from inside your project directory, or pass an absolute path.

### Basic usage

```bash
velora scan examples/app.py
```

Scans one file. ~10 ms, no model needed. The demo file is intentionally vulnerable, so you get two critical findings.

### Example output

```text
============================================================
Velora Security Scan: examples/app.py
============================================================

Lines scanned: 33
Procedures analyzed: 3
Scan time: 28.20ms

Vulnerabilities Found: 2
----------------------------------------

1. [CRITICAL] 🔴 sql_injection
   Location: examples/app.py:20:4
   Function: login
   Description: Tainted data from 'user' flows to sql sink
   CWE: CWE-89
   Source: user
   Confidence: 70%

2. [CRITICAL] 🔴 command_injection
   Location: examples/app.py:27:4
   Function: run
   Description: Tainted data from 'name' flows to command sink
   CWE: CWE-78
   Source: name
   Confidence: 70%

============================================================
```

Each finding names a severity, a vulnerability class, the file and line, and the CWE id. Because two findings are `critical` and the default severity gate is `--fail-on high`, this command **exits 1** — expected for a vulnerable file, not a crash ([Troubleshooting](#troubleshooting)).

### Common examples

```bash
velora scan .                                    # current directory (**/*.py by default)
velora scan /path/to/your/project                # any directory on your machine
velora scan . --pattern "**/*.py"                # explicit file filter (** = every subfolder)
velora scan . -f json -o findings.json           # JSON findings -> feeds exploit / fix
velora scan . --format sarif -o results.sarif --fail-on high   # CI gate (see CI/CD)
velora scan . --ai                               # symbolic + AI layer (needs a model, see AI & Model Setup)
```

One line each:

- `.` means **the current directory**; any relative or absolute path works as the target.
- `--pattern` controls **which files** inside a directory are scanned. Default is `**/*.py`. Use `**/*.java`, `**/*.js`, etc. for other languages.
- `-f/--format` chooses the **output format**: `text` (default, human-readable), `json` (machine-readable — the input for `exploit` and `fix`), or `sarif` (the GitHub code-scanning standard).
- `-o/--output` **writes the result to a file** instead of the terminal.
- `--fail-on` sets the **severity threshold that makes the command exit 1** (`critical|high|medium|low|any|none`, default `high`) — this is what turns a scan into a CI gate.
- `--ai` enables the **AI layer** (LLM detection + triage) on top of the symbolic engine. Symbolic scans never need a model; `--ai` does — see [AI & Model Setup](#ai--model-setup).
- `-l/--language` forces a language for unusual files; the symbolic frontends are Python, JavaScript, TypeScript, Java, C, C++, C#. Any other language (Go, PHP, Ruby, …) runs LLM-detect only, under `--ai`.
- `--min-severity` hides findings below a level; `--no-verify` skips Velora's verification pass (faster, may have false positives); `--timeout` sets the per-check verification timeout in ms (default 5000); `-v` gives verbose output.

Useful one-offs:

| Goal | Command |
|------|---------|
| Scan a single file | `velora scan examples/app.py` |
| Scan a directory (defaults to `**/*.py`) | `velora scan .` |
| Pick the files explicitly | `velora scan . --pattern "**/*.js"` |
| Force a language for odd extensions | `velora scan ./misc -l go --ai` |
| JSON findings for the loop | `velora scan . -f json -o findings.json` |
| SARIF + severity gate | `velora scan . --format sarif -o results.sarif --fail-on high` |

<sub>Directory scans skip agent/tool and dependency directories by default (`.git`, `.claude/worktrees`, `.cursor/worktrees`, `.worktrees`, `.idea`, `.vscode`, `node_modules`, `.venv`, `venv` only if it looks like a virtualenv, `.tox`, `__pycache__`, `.mypy_cache`, `.pytest_cache`); pass `--no-default-excludes` to scan them anyway.</sub>

Symbolic scans (no `--ai`) finish in milliseconds to seconds. Each `--ai` file costs one or more LLM calls — seconds on a fast endpoint, tens of seconds on the free tier.

## Exploit

**`velora exploit` drives an LLM agent against a live target** to turn findings into a working proof-of-concept. Unlike `scan`, its `--target` is a **URL** — the address of a running application.

> **Only test targets you are authorized to attack.** `--target` must be in-scope for you — a target you own, or one a program explicitly lists as in-scope. Practice locally with the throwaway app this repo ships: `python examples/practice_target.py` serves an application on `http://127.0.0.1:8080` whose goal is to steal the admin flag from `/admin` and POST it to `/report` — once that happens, `GET /pwned` returns 200, so `--success-check 'curl -sf http://127.0.0.1:8080/pwned'` turns the state change into an oracle.

### Basic usage

```bash
velora exploit --target http://localhost:8080 --goal 'read the admin secret'
```

One run = one goal. The agent executes real commands (curl, python, nc, sqlmap, … — installing tools if missing) in a recon → hypothesis → payload → verify loop, printing every step, and only reports success when it observes an actual state change on the target — never on its own say-so.

Exit code **0** = verified success, **1** = not solved (iterate).

### The flags, one at a time

Introduce them progressively — the simplest runs need only `--target`:

| Flag | What it does | Why use it |
|---|---|---|
| `--target <url>` | The live application under test | Required; the URL the agent attacks |
| `--goal '<words>'` | The objective in plain language (default: read a secret, run a command, or modify server state) | Specific wording gets specific results — "test the login form for SQL injection" beats "find something" |
| `--success-check '<shell command>'` | Your command is re-run after every step; **exit 0 = solved** (a passing check prints `[success-check] <evidence>`) | The strongest way to pin "success" to an objective fact; it also overrides a stale agent claim |
| `--guidance <findings.json>` | Prime the agent with Velora findings (file path, or `-` for stdin) | Skips generic recon — the agent attacks the exact endpoint/parameter a scan already proved vulnerable |
| `--max-steps <n>` | Maximum agent steps (default **40**) | Larger attack surfaces need more steps; smaller budgets finish faster |
| `--exec-timeout <sec>` | Per-command execution timeout (default **120**) | Raise it for slow targets |
| `--trace-out <file>` | Write the full agent trace (system prompt, guidance, every tool call and result) as JSON | Evidence for a report; comparing model behavior |
| `--format json` | Machine-readable result on stdout | Scripting the exit/result into other tools |
| `--model <id>` | Override the configured model for this run | Pick a stronger model for a hard target without changing config |

### How a run terminates

Success is only ever claimed from *observed* state, never on the model's say-so alone. Two mechanisms, in priority order:

- **External oracle (`--success-check '…'`, authoritative):** your command is re-run after every step; exit 0 → `✓ EXPLOITED` with a `[success-check] <evidence>` line. Use this whenever you can express the win condition as a command — it also overrides a stale agent claim.
- **Guarded self-termination (no oracle):** the agent stops when its **final** message carries a single `VERIFIED: <evidence>` line. Two guards keep this honest: the claim only counts after the agent has already been working (a first-turn echo of the goal never terminates a run), and the evidence must describe a concrete observation. Example: `✓ EXPLOITED (steps=2, reason=objective observed)`.

### What a run looks like

The agent prints every step as it happens, so you are never staring at a blank screen:

```text
$ velora exploit --target https://target.com --goal 'gain admin access' --max-steps 40
[velora] using model 'opencode/mimo-v2.6-flash-free' from velora config (...)
[exploit] step 1/40: thinking...        <- one model round-trip: 30-90 s on the free tier
[exploit] · found login form at /login; probing default creds...
[exploit] step 2/40: thinking...
[exploit] · session cookie for admin captured (role=admin)
...
✓ EXPLOITED  (steps=17, reason=objective observed)                # exit code 0
# or: ✗ NOT EXPLOITED  (steps=40, reason=step budget exhausted)   # exit code 1
```

With a function-calling endpoint you also see each shell command the agent runs (`[exploit] $ curl -sI https://target.com`); through the zero-key bridge the model runs tools itself and narrates instead — those are the `·` progress lines, one per step.

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

### Timing, budgets, and grey-box

**Timing:** each step is one LLM round-trip — 30–90 s on the free tier, with a per-step ceiling of 5 minutes (`VELORA_LLM_AGENT_TIMEOUT`); a dropped connection retries once before the run gives up with `reason=model unreachable after N failed attempts`. A full 40-step run therefore takes roughly 15–60 minutes. A faster/stronger model (`velora models use zen/glm-5.2`) cuts this dramatically; so does a smaller `--max-steps`. `Ctrl+C` stops cleanly at any point. When pasting multi-line commands, keep each line-ending `\` as the very last character (no trailing spaces) or join them into one line.

**Grey-box upgrade (if you can get the source):** any source you legitimately have — the app's public repo, a client-provided drop, the deploy artifact — makes the run dramatically more efficient. The symbolic scan proves reachable flaws, and `--guidance` hands the agent the exact endpoint, parameter, and sink as leads:

```bash
velora scan ./target-src --ai -f json -o findings.json
velora exploit --target https://target.com --guidance findings.json \
  --goal 'exploit the proven SQL injection to dump the users table'
```

Practical notes:

- **Reachability:** the agent runs commands on the machine where you invoke `velora`, so the target URL must be reachable from there (VPN, tunnel, or localhost port-forwards all work).
- **Budget:** default is 40 steps × 120 s per command (`--max-steps`, `--exec-timeout`). Large attack surfaces need more steps; slow targets need a higher `--exec-timeout`.
- **Model quality matters most here:** detection tolerates small models, exploitation does not — free-tier Zen works for triage, but use the strongest model you have (`velora models use zen/glm-5.2`, or a capable local model) for the exploit loop.
- **No model?** The symbolic pipeline (`scan` without `--ai`, `solve`) never needs one — only `exploit` and `--ai` do.

### Bug hunting guide (worked example: `example.com`)

A compact black-box campaign you can copy, one hypothesis at a time.

**Authorization first.** Only test targets you own or are explicitly in scope for. `example.com` is IANA's reserved *documentation* domain — treat it purely as a placeholder below and swap in your authorized target (your own app, `python examples/practice_target.py` for a local one, or a bug-bounty program's listed scope).

**Step 0 — One-time setup.** Confirm the zero-key chain works and pick your model (the strongest you have — exploitation is where model quality matters most):

```bash
velora setup && velora doctor --probe   # bootstrap + one real keyless chat (exit 0 = ready)
velora models tui                       # full-screen picker: opencode bridge + local servers
```

**Step 1 — Recon run (unguided).** Let the agent map the surface and attack a stated goal. Exit 0 = verified win; exit 1 = iterate on the goal wording:

```bash
velora exploit --target https://example.com \
  --goal 'map the application surface (pages, forms, parameters) and probe them for one high-confidence flaw' \
  --max-steps 20
```

**Step 2 — Focused goals, one at a time.** Each run is exactly one hypothesis; specific wording gets specific results. The agent executes real commands (curl, python, sqlmap, … — installing tools if missing) and narrates every step:

```bash
velora exploit --target https://example.com \
  --goal 'test every search/query parameter for SQL injection' --max-steps 40

velora exploit --target https://example.com \
  --goal 'check whether login reveals which usernames are valid (user enumeration)' --max-steps 30

velora exploit --target https://example.com \
  --goal 'look for IDOR: change numeric ids on resource endpoints and see if other records are returned' --max-steps 40
```

Goal recipes by vulnerability class — swap any of these straight into `--goal`:

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

**Step 3 — Pin "success" with an oracle.** Your command is re-run after every step; exit 0 means solved, and it overrides any stale agent claim:

```bash
velora exploit --target https://example.com \
  --goal 'access a protected page without logging in' \
  --success-check 'curl -sk https://example.com/private | grep -qi "secret"'
```

**Step 4 — Keep the evidence.** The full trace (system prompt, every command + response) plus machine-readable output goes into your report:

```bash
velora exploit --target https://example.com --goal '…' \
  --trace-out trace.json --format json > report.json
```

**Reading the results.** Every run ends with one of these:

| Ending | Exit | What it means | Next move |
|---|:---:|---|---|
| `✓ EXPLOITED (steps=N, reason=objective observed)` | 0 | A state change was *observed* on the target — a real, verified win | Save `--trace-out`, keep the output as evidence, feed the detail into the next goal |
| `✓ EXPLOITED` + `[success-check] <evidence>` | 0 | Your oracle command exited 0 — authoritative, overrides any agent claim | Same as above; prefer this ending whenever you can write an oracle |
| `✗ NOT EXPLOITED (… step budget exhausted)` | 1 | Out of steps before the goal was achieved | Raise `--max-steps`, narrow the goal, or split it into smaller hypotheses |
| `✗ NOT EXPLOITED (… model unreachable after N failed attempts)` | 1 | The endpoint is down after automatic retries | `velora doctor --probe`, `velora serve-bridge --start`, check `~/.local/state/velora/bridge.log` |

**Loop:** feed each success back into the next goal's wording, and stop when the step budget stops paying off. If you ever get the source, add `--guidance findings.json` from a `velora scan` (grey-box) and the same runs converge far faster. Flags and budgets: [Command patterns](#command-patterns) above.

## Fix

**`velora fix` turns a scan's findings into patches — and proves them.** For each finding it generates a minimal patch, then **re-scans the patched code** to confirm the vulnerability is actually gone (one re-scan per file; on by default).

It reads findings from a scan, so `--guidance` is required. `<source>` is the file or directory the findings refer to. `--guidance` accepts `-` for stdin, so it pipes from a scan. `fix` needs a model — see [AI & Model Setup](#ai--model-setup).

### Basic usage — preview

```bash
velora fix examples/app.py --guidance findings.json --diff
```

Prints a unified diff of every proposed patch and **writes nothing to disk** (`--diff` is the default when `--in-place` is off) — review first, apply second.

### Apply the patches

```bash
velora fix examples/app.py --guidance findings.json --in-place
```

Writes the patches to the files, then re-scans each patched file to confirm the fix.

### Example output

```text
CWE-89 app.py:20 -> patched (verified✓)
CWE-78 app.py:27 -> patched (verified✓)
2/2 findings patched (shown as diff); 2 verified fixed by re-scan.    # --diff,  exit 0
2/2 findings patched (written in place); 2 verified fixed by re-scan.  # --in-place, exit 0
```

Per finding you get one of:

| Status | Meaning |
|---|---|
| `patched (verified✓)` | Patch applied **and** the re-scan no longer finds the vulnerability |
| `patched (STILL DETECTED)` | Patch applied but the re-scan still finds it — the fix is incomplete |
| `verify-skipped` | Verification was turned off (`--no-verify`) |
| `could not apply` | The patch did not apply cleanly to the current file |

### Flags and exit behavior

- `--guidance <findings.json>` — **required**; the findings to fix (file path, or `-` for stdin). Produced by `velora scan -f json`.
- `--diff` — preview as a unified diff, the default when not writing.
- `--in-place` — write the changes to the files.
- `--no-verify` — skip the confirming re-scan. Verification is **on by default**; keep it on for proof.
- `--format json`, `--model <id>` — machine-readable output / model override for this run.
- **Exit code:** 0 when at least one patch was applied, 1 otherwise (no model, no findings, or nothing applied).

After `--in-place`, run `velora scan` again on the project — fixed findings disappear from the report (the last stage of the [Quick Start](#quick-start) loop).

## AI & Model Setup

The symbolic engine (`velora scan` **without** `--ai`, plus `velora solve`) never needs a model. Everything in the AI layer — `scan --ai`, `exploit`, `fix` — runs on an OpenAI-compatible endpoint, and Velora ships a **zero-key** path to one: a local bridge to opencode's free tier that stores no API key.

### Commands a new user needs

Run these once, in order:

```bash
velora setup                                  # 1. one-time bootstrap: install what's missing
                                              #    user-local (Node, opencode CLI, bridge deps)
                                              #    and start the bridge daemon
velora models tui                             # 2. pick a model interactively
velora doctor --probe                         # 3. verify: one real keyless chat (exit 0 = ready)
velora scan . --ai                            # 4. go
```

- **`velora setup`** — installs missing prerequisites without sudo, seeds the bridge, starts it, and verifies keyless access. Flags: `--yes` (no prompt), `--no-start`, `--no-probe`.
- **`velora models tui`** — the easy route: a full-screen picker that lists every model Velora can reach — the zero-key opencode bridge (free Zen tier) **plus** any local server (Ollama, LM Studio, llama.cpp, vLLM) — probes each source live, auto-starts the bridge if it isn't running, and saves your pick without ever storing an API key.
- **`velora models use <ref>`** — the same, non-interactively, for scripts: `velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt`.
- **`velora doctor --probe`** — health check: platform, node/opencode binaries, bridge deps, daemon health, active model. `--probe` adds one live keyless chat. Exit 1 when not ready — each failure prints the exact fix command.

### Advanced & troubleshooting

```bash
velora serve-bridge --start     # start the bridge daemon explicitly (port 8399)
velora serve-bridge --status    # health of the daemon (exit 0 when healthy)
velora serve-bridge --stop      # stop it
velora models list              # browse models (add --free for free-only, --query <s> to filter)
velora models current           # which model is active
velora models use zen/glm-5.2   # switch to a stronger hosted model (needs its key)
```

Use these when `--ai` complains that no endpoint/model is configured, or when `velora doctor` exits 1 — the troubleshooting table has the exact fix for each symptom. The symbolic-only workflow never touches any of this.

Other model facts worth knowing:

- Each `--ai` file costs one or more LLM calls — the first files are slower (cold start), then it speeds up.
- `--model <id>` on `scan`/`exploit`/`fix` overrides the active model for a single run, same as setting `VELORA_LLM_MODEL` for that invocation.
- `velora models --help` lists everything: `list`, `use`, `current`, `providers`, `import-opencode`, `tui`, with `--free`, `--registry`, `--refresh`, `--base-url`, `--api-key`, `--no-prompt`, `--local-url`.

## Separation Logic

Velora's soundness core, exposed directly — pure Z3, **no model, no setup**. This is a standalone verifier, unrelated to the scan → exploit → fix security workflow: you give it heap descriptions, it tells you whether one entails another.

### `velora solve` — check one entailment

Ask whether a separation-logic formula `P` implies `Q` (written `P |- Q`).

```bash
velora solve "ls(x, y) * ls(y, z) * x != z |- ls(x, z)"
```

Returns `✓ VALID` (exit 0) or `✗ INVALID` (exit 1), with a reason:

```text
✓ VALID
```

```text
✗ INVALID
  Reason: Sanity check
```

Useful flags: `--model` prints a countermodel when invalid, `-v` shows the solving steps, `--timeout <ms>` (default 5000) and `--unfold-depth <n>` (default 3) tune the solver, `--format json` for scripts.

### `velora check` — batch-check a file

Checks a text file with **one entailment per line** and prints totals:

```bash
velora check formulas.txt
```

```text
============================================================
Velora Entailment Check: formulas.txt
============================================================

Total: 2
Valid: 1 (50.0%)
Invalid: 1
Errors: 0
Time: 58.06ms

Invalid entailments:
  ✗ x |-> y |- y |-> x
============================================================
```

Exit 1 if any line is invalid. `--format json|csv`, `-o <file>`, `--stop-on-failure`, plus the same `--timeout`/`--unfold-depth`/`-v` as `solve`.

### `velora parse` — inspect a formula

Lexes and parses a formula, then prints its AST — for debugging grammar or understanding precedence:

```bash
velora parse "x |-> y * y |-> z"
```

```text
└── *
    ├── points-to
    │   ├── x
    │   └── y
    └── points-to
        ├── y
        └── z
```

`--format tree` (default), `json`, or `sexp`; `-f <file>` reads the formula from a file.

### `velora repl` — interactive checking

An interactive session for trying entailments without re-typing the whole command:

```bash
velora repl
```

Type entailments directly, then `:parse <formula>`, `:help`, `:quit`. `--timeout <ms>` sets the per-query solver timeout.

## CI/CD

In plain language: make your build **fail when the scan finds something serious**, and publish the results where reviewers can see them. `velora scan` writes [SARIF](https://sarifweb.azurewebsites.net/) — the standard format GitHub's code scanning UI understands — and `--fail-on high` makes the process exit non-zero when any `high` (or worse) finding exists, which is what actually fails the build step.

```yaml
# GitHub Actions
- name: Install Velora
  run: pip install -e ".[scan]"

- name: Security Scan
  run: velora scan . --format sarif -o results.sarif --fail-on high
  env:                          # only needed for --ai; the symbolic engine needs no model
    VELORA_LLM_BASE_URL: ${{ vars.VELORA_LLM_BASE_URL }}
    VELORA_LLM_MODEL: ${{ vars.VELORA_LLM_MODEL }}
    VELORA_LLM_API_KEY: ${{ secrets.VELORA_LLM_API_KEY }}

- name: Upload Results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

Why these two pieces:

- **`--format sarif -o results.sarif`** — SARIF is the interchange format for static-analysis results; uploading it decorates pull requests with annotations in GitHub's Security tab.
- **`--fail-on high`** — the gate: exit 1 (build failure) when findings of `high` severity or above exist. Lower it (`--fail-on critical`) to fail only on the worst, raise it (`--fail-on any`) to fail on everything, or `--fail-on none` to always exit 0 and just report.

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
| Exploit sits on `thinking...` for a while | Normal free-tier latency (30–90 s per step, ceiling 5 min per step) | Wait it out; verify the chain with `velora doctor --probe`; or switch to a faster model |
| `no response from the model -- retrying` in an exploit run | One round-trip came back empty (slow/overloaded endpoint); it retries automatically | Wait — if the run ends `✗ NOT EXPLOITED (reason=model unreachable after 2 failed attempts)` the endpoint is really down: `velora doctor --probe`, `velora serve-bridge --start`, check `~/.local/state/velora/bridge.log` |
| Exploit ends `✗ NOT EXPLOITED` | Step budget ran out or the goal wasn't achieved | Rephrase `--goal`, raise `--max-steps`, use a stronger model, or add `--guidance` from a scan |
| `velora scan --ai` is slow on first files | Model cold start / bridge warm-up | Normal; later files are faster |
