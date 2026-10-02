# Usage & Commands

[← Back to README](../README.md)

## Usage

### Scan source code

**The target for `velora scan` is a path on your machine** — a source file or a project directory you have locally. It is *not* a URL (URLs are targets for `velora exploit --target`, see below). Passing a path that doesn't exist gives:

```text
Error: Target not found: ./repo
```

Either run `velora scan` from inside your project directory, or pass an absolute path.

A guided first run — these exact commands work in a fresh clone:

```bash
# 1. Scan the bundled intentionally-vulnerable demo (ships with the repo)
velora scan examples/app.py
#    -> [CRITICAL] sql_injection    (CWE-89) examples/app.py:20
#       [CRITICAL] command_injection (CWE-78) examples/app.py:27
#       ~10 ms, no model needed

# 2. Scan your own project. "." = current directory, --pattern picks the files.
#    (Replace the path with wherever YOUR code lives.)
velora scan . --pattern "**/*.py"
velora scan . --pattern "**/*.java"        # only .java files (a project that has them; the repo has none -> "No files found")

# 3. Machine-readable findings (input for the exploit/fix stages)
velora scan . --pattern "**/*.py" -f json -o findings.json

# 4. Add the AI layer (LLM detection + triage) -- one-time model setup first:
velora setup                               # install + start the zero-key model bridge
velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt   # activate the free model
velora models tui                          # full-screen picker: opencode bridge + local servers
velora scan . --ai

# 5. CI gate: fail the build on high+ findings (SARIF for code-scanning UIs)
velora scan . --format sarif -o results.sarif --fail-on high
```

New to model setup? **`velora models tui`** is the easy route: a full-screen picker that lists every model Velora can reach — the zero-key opencode bridge (free Zen tier) **plus** any local server (Ollama, LM Studio, llama.cpp, vLLM) — probes each source live, auto-starts the bridge if it isn't running, and saves your pick without ever storing an API key. `velora models use <ref>` does the same thing non-interactively (for scripts).

Symbolic scans (no `--ai`) finish in milliseconds to seconds and never need a model. Each `--ai` file costs one or more LLM calls — seconds on a fast endpoint, tens of seconds on the free tier.

| Goal | Command |
|------|---------|
| Scan a single file | `velora scan examples/app.py` |
| Scan a directory (defaults to `**/*.py`) | `velora scan .` |
| Pick the files explicitly | `velora scan . --pattern "**/*.js"` |
| Force a language for odd extensions | `velora scan ./misc -l go --ai` |
| JSON findings for the loop | `velora scan . -f json -o findings.json` |
| SARIF + severity gate | `velora scan . --format sarif -o results.sarif --fail-on high` |

<sub>Directory scans skip agent/tool and dependency directories by default (`.git`, `.claude/worktrees`, `.cursor/worktrees`, `.worktrees`, `.idea`, `.vscode`, `node_modules`, `.venv`, `venv` only if it looks like a virtualenv, `.tox`, `__pycache__`, `.mypy_cache`, `.pytest_cache`); pass `--no-default-excludes` to scan them anyway.</sub>

### The full loop: detect → exploit → fix

With source available, one findings file drives every stage — and the shell is the pipeline. (Paths below are placeholders: swap in your own project; `examples/app.py` works out of the box.)

```bash
# 1. detect: symbolic + LLM findings
velora scan ./target-app --ai -f json -o findings.json

# 2. exploit: the agent attacks the localized flaw on a live, authorized target
velora exploit --target http://localhost:8080 --guidance findings.json \
  --goal 'read the admin secret' \
  --success-check 'curl -sf http://localhost:8080/pwned'   # exit 0 => solved

# 3. fix: patch each finding, auto re-scan to verify it's gone, then confirm
velora fix ./target-app/app.py --guidance findings.json --diff        # preview
velora fix ./target-app/app.py --guidance findings.json --in-place    # apply
velora scan ./target-app --ai                                         # finding gone

# stages also compose as a pipe (stdin guidance with -)
velora scan ./target-app --ai -f json | \
  velora exploit --target http://localhost:8080 --guidance - --goal 'read the admin secret'
```

Exit codes are scriptable throughout: `exploit` returns 0 only when success was *verified*, `scan --fail-on` gates on severity, `fix` returns 0 when at least one patch was applied.

### Fix findings

`velora fix <source> --guidance <findings.json>` turns a scan's findings into patches and **proves them** by re-scanning the patched code (one re-scan per file; on by default, `--no-verify` skips it). It needs a model — see [Setup](installation.md#setup). `<source>` is the file or directory the findings refer to; `--guidance` is required and accepts `-` for stdin.

```bash
# Preview (default): unified diff only, nothing written to disk
velora fix examples/app.py --guidance findings.json --diff
#   CWE-89 app.py:20 -> patched (verified✓)
#   CWE-78 app.py:27 -> patched (verified✓)
#   2/2 findings patched (shown as diff); 2 verified fixed by re-scan.   # exit 0

# Apply: write the patches to the files, then re-scan to confirm each fix
velora fix examples/app.py --guidance findings.json --in-place
#   2/2 findings patched (written in place); 2 verified fixed by re-scan. # exit 0
```

Per finding you get `patched (verified✓)`, `patched (STILL DETECTED)` if the re-scan still finds it, `verify-skipped`, or `could not apply`. Exit code: **0** when at least one patch was applied, **1** otherwise (no model, no findings, or nothing applied). Other flags: `--format json` for machine output, `--model` to override the model for this run.

### Black-box testing a live target (no source)

When all you have is a URL — `https://target.com` — the source-based `scan` doesn't apply; the black-box path is `velora exploit`. It drives an agent from *your* machine that executes real commands (curl, python, nc, sqlmap, ... installing tools if missing) in a recon → hypothesis → payload → verify loop, and only reports success when it observes an actual state change on the target — never on its own say-so.

**Only test targets you are authorized to attack.** `--target` must be in-scope for you — practice on a local app you own. The repo ships a throwaway one built for this: `python examples/practice_target.py` serves an app on `http://127.0.0.1:8080` whose goal is to steal the admin flag from `/admin` and POST it to `/report` (the `--success-check` above then turns 200).

**What a run looks like.** The agent prints every step as it happens, so you are never staring at a blank screen:

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

**How a run terminates.** Success is only ever claimed from *observed* state, never on the model's say-so alone:

- **External oracle (`--success-check '…'`, authoritative):** your command is re-run after every step; exit 0 → `✓ EXPLOITED` with a `[success-check] <evidence>` line. Use this whenever you can express the win condition as a command — it also overrides a stale agent claim.
- **Guarded self-termination (no oracle):** the agent stops when its **final** message carries a single `VERIFIED: <evidence>` line. Two guards keep this honest: the claim only counts after the agent has already been working (a first-turn echo of the goal never terminates a run), and the evidence must describe a concrete observation. Example: `✓ EXPLOITED (steps=2, reason=objective observed)`.

**Timing:** each step is one LLM round-trip — 30–90 s on the free tier, with a per-step ceiling of 5 minutes (`VELORA_LLM_AGENT_TIMEOUT`); a dropped connection retries once before the run gives up with `reason=model unreachable after N failed attempts`. A full 40-step run therefore takes roughly 15–60 minutes. A faster/stronger model (`velora models use zen/glm-5.2`) cuts this dramatically; so does a smaller `--max-steps`. `Ctrl+C` stops cleanly at any point. When pasting multi-line commands, keep each line-ending `\` as the very last character (no trailing spaces) or join them into one line.

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

**Loop:** feed each success back into the next goal's wording, and stop when the step budget stops paying off. If you ever get the source, add `--guidance findings.json` from a `velora scan` (grey-box) and the same runs converge far faster. Flags and budgets: [Black-box testing a live target](#black-box-testing-a-live-target-no-source) above.

### Separation-logic solver

Velora's soundness core, exposed directly — pure Z3, no model, no setup:

```bash
velora solve "ls(x, y) * ls(y, z) * x != z |- ls(x, z)"   # -> ✓ VALID
velora check formulas.txt        # batch-check a text file with one entailment per line
velora parse "x |-> y * y |-> z" # pretty-printed AST (grammar debugging)
velora repl                      # interactive: type entailments, :parse / :help / :quit
```

| Command | What it does |
|---------|--------------|
| `velora solve "<P> \|- <Q>"` | Check one entailment → `✓ VALID` / `✗ INVALID`; `--model` prints a countermodel when invalid, `-v` shows solving steps, `--format json` for scripts |
| `velora check <file>` | Check every line of a file (one entailment per line); prints totals, timing, and each invalid one |
| `velora parse "<formula>"` | Lex and parse a formula, then print its AST |
| `velora repl` | Interactive REPL — enter entailments directly, `:parse <formula>`, `:help`, `:quit` |

### CI/CD Integration

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

### Troubleshooting

| Symptom | What it means | Fix |
|---------|---------------|-----|
| `Error: Target not found: ./repo` | The `scan` target path doesn't exist on your machine | Check with `ls`; run from inside the project, or use `velora scan examples/app.py` (always present) |
| `velora scan` prints findings but exits 1 | Not a crash — the severity gate: default `--fail-on high` exits 1 when high+ findings exist | Expected for a vulnerable file; `--fail-on none` to always exit 0 |
| `--ai` says no endpoint/model configured | No model set up yet | `velora setup`, then `velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt` |
| `bridge ... not running` / `velora doctor` exits 1 | Bridge daemon is down | `velora serve-bridge --start` (or run `velora models tui`, which starts it for you) |
| Exploit sits on `thinking...` for a while | Normal free-tier latency (30–90 s per step, ceiling 5 min per step) | Wait it out; verify the chain with `velora doctor --probe`; or switch to a faster model |
| `no response from the model -- retrying` in an exploit run | One round-trip came back empty (slow/overloaded endpoint); it retries automatically | Wait — if the run ends `✗ NOT EXPLOITED (reason=model unreachable after 2 failed attempts)` the endpoint is really down: `velora doctor --probe`, `velora serve-bridge --start`, check `~/.local/state/velora/bridge.log` |
| Exploit ends `✗ NOT EXPLOITED` | Step budget ran out or the goal wasn't achieved | Rephrase `--goal`, raise `--max-steps`, use a stronger model, or add `--guidance` from a scan |
| `velora scan --ai` is slow on first files | Model cold start / bridge warm-up | Normal; later files are faster |

## Commands

Velora is one CLI covering the whole workflow (detect, triage, exploit, fix) plus the separation-logic solver. Run `velora <command> --help` for all flags.

| Command | What it does |
|---------|--------------|
| `velora scan <path>` | Scan local source (`<path>` = a file or directory on your machine) for vulnerabilities (sound symbolic engine; add `--ai` for LLM detection + triage). `-f json\|sarif`, `-o <file>`, `--fail-on <sev>` (default `high` → exit 1 when high+ findings exist). |
| `velora exploit --target <url>` | Drive an LLM agent against a live, authorized target (`--target` = a URL). Prime it with `--guidance <findings.json\|->`. `--goal`, `--success-check`, `--max-steps`, `--trace-out`, `--format json`. Prints every step; stops on a passing success-check or a guarded `VERIFIED:` claim; exit 0 = verified success. |
| `velora fix <path>` | Generate a minimal patch per finding, then re-scan the patched code to confirm each vulnerability is gone. `--guidance <findings.json\|->` (required), `--in-place` to write / default unified diff, `--no-verify`, `--format json`. Exit 0 when ≥1 patch applied. |
| `velora solve "<P> \|- <Q>"` | Check a single separation-logic entailment (`-v` steps, `--model` countermodel, `--format json`). |
| `velora check <file>` | Batch-check entailments (one per line). |
| `velora parse "<formula>"` | Parse and display a formula's AST. |
| `velora repl` | Interactive separation-logic REPL. |
| `velora models` | Browse & switch AI models for `--ai`. `list` (`--free`, `--registry`, `--query`), `tui` (full-screen picker: opencode bridge + local servers, probes and auto-starts the bridge), `use <ref>`, `current`, `providers`, `import-opencode`. |
| `velora doctor` | Diagnose the zero-key AI setup; exit 1 when not ready. `--probe` sends a live keyless chat, `--format json`. |
| `velora setup` | One-time bootstrap: install missing prerequisites user-local (no sudo), seed and start the bridge. `--yes` for non-interactive. |
| `velora serve-bridge` | Local OpenAI-compatible bridge to opencode (zero-key `--ai`). `--start` / `--stop` / `--status` manage the daemon on port 8399. |
