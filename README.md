<h1 align="center">
  <br>
  <img src="assets/logo-icon.png" alt="Velora" width="600">
  <br>
  Velora
  <br>
</h1>

<h4 align="center">Sound static analysis + LLM agent in one loop — detect → exploit → fix · 5 languages · zero-key AI · separation logic + Z3</h4>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/SL--COMP-79.9%25-brightgreen" alt="SL-COMP 79.9%">
  <img src="https://img.shields.io/badge/languages-5%20frontends-purple" alt="5 symbolic frontends">
  <img src="https://img.shields.io/badge/zero--key%20AI-free%20tier-orange" alt="Zero-key AI free tier">
  <img src="https://img.shields.io/badge/proved%20with-Z3-red" alt="Proved with Z3">
</p>

<p align="center">
  Velora is a neuro-symbolic security agent. A sound static-analysis core — taint analysis plus separation-logic verification with Z3 — is fused with an LLM layer in one loop: <b>the model proposes, the sound core disposes.</b>
</p>

<p align="center">
  It runs the whole loop end to end: detect vulnerabilities across 5 languages, exploit them with a working proof-of-concept against a live target, fix the code, then re-scan to confirm the bug is gone. Symbolic findings are proven, not guessed; LLM findings are tiered separately so the two are never confused. On independent real-world benchmarks Velora is competitive with commercial AI-SAST vendors, and it scores 80%+ on the synthetic OWASP suites. The LLM layer runs on any OpenAI-compatible endpoint — local or hosted, including a <b>zero-key free tier</b> (<code>velora setup</code>).
</p>

<details>
<summary><strong>What "neuro-symbolic security agent" means</strong></summary>

Velora is a *neuro-symbolic* system: a proof-producing **symbolic** core and a language-model **neuro** runtime operate as a single agent across the `scan → exploit → fix` loop.

| | Symbolic core | LLM agent |
|---|---|---|
| Discipline | Formal methods — separation logic encoded in the Z3 SMT solver | Machine learning — a language model that reads code and drives tools |
| Contribution | **Proves** reachability: a finding is reported only when it is mathematically verified — *sound* means zero false positives | Supplies the context formal methods cannot express — business intent, framework semantics, cross-file data flows |
| Limitation | Confined to what it can encode | Cannot prove; its claims stay provisional until independently checked |
| Role in the loop | Adjudicates: proven and LLM-tier findings are never conflated, and an exploit concludes only on an observed state change or a passing shell oracle | Proposes: candidate findings, triage decisions, exploit steps |

**The model proposes, the sound core disposes** — the coverage of an LLM with the assurance of a proof.

</details>

**Contents** — [Highlights](#highlights) · [Documentation](#documentation) · [Quick Start](#quick-start) · [Commands](#commands) · [What next](#what-next)

## Highlights

- **Sound by construction.** The symbolic core proves reachability with Z3 — its findings carry no false positives — and never conflates them with LLM-tier results.
- **One CLI, the whole loop.** `scan` → `exploit` → `fix`, composed over a shared findings file.
- **Five symbolic frontends** (Python, Java, JS/TS, C/C++, C#) plus an LLM tier for any other language.
- **Zero-key AI.** `velora setup` bootstraps a local bridge to opencode's free Zen tier — no API key is ever stored.
- **Separation-logic solver built in** (`velora solve`), validated on SL-COMP and SMT-LIB.

**Real-world security benchmarks**, validated on five independent datasets with published ground truth. Every Velora number uses open models (local Qwen via mlx-optiq, or hosted GLM-5.2):

| Benchmark | What it measures | Velora | Comparison |
|-----------|------------------|------|-----------|
| [XBOW / ZeroPath](benchmarks/xbow_zeropath/REPORT.md) | AI-SAST on 39 web-vuln apps | detect **78.8%**, FP **26.3%** (technical) | ties ZeroPath (80% / 25%); beats Semgrep, Snyk, Bearer |
| [CVE-Bench](benchmarks/cve_bench/README.md) | Full loop, 10 live web CVEs | detect **5/10**, exploit **4/10**, fix **4/10** | each stage verified on a live target |
| [Endor Labs corpus](benchmarks/endor_corpus/README.md) | 193 vulns, 5 production apps | recall **0.67**, precision **0.51** | Semgrep recall 0.52, precision 0.40 |
| [RealVuln IDOR/BOLA](benchmarks/realvuln_authz/REPORT.md) | Broken authorization, 4 real apps | **6/8** detected, precision **1.00** | 0 false positives on safe controls |
| [SusVibes](benchmarks/susvibes/README.md) | 181 real-CVE Python pairs | recall **0.14**, precision **0.56** | Semgrep recall 0.06, precision 0.55 |

<sub>Each cell names its own metric. SusVibes is hard for every tool (independent, execution-verified ground truth). See each benchmark's report for methods and caveats.</sub>

**OWASP score, synthetic suites** (True Positive Rate minus False Positive Rate):

| Benchmark | Velora | Semgrep | Difference |
|-----------|:---:|:---:|:---:|
| **Python** (OWASP) | 80.9% | 4.5% | +76.4 pts |
| **Java** (OWASP) | 81.5% | 15.7% | +65.8 pts |
| **JavaScript** (SecBench.js) | 43.0% | 10.0% | +33 pts |
| **C/C++** (NIST Juliet) | 54.4% | -14.9% | +69.3 pts |
| **C#** (IssueBlot.NET) | 80.3% | 14.2% | +66.1 pts |

<sub>Higher is better. See [benchmarks/](benchmarks/) for detailed methods and results.</sub>

## Documentation

Everything beyond the quick start lives in [`docs/`](docs/):

| Guide | What's inside |
|-------|---------------|
| [Installation & Setup](docs/installation.md) | Requirements, install variants, zero-key AI setup, the bridge, environment variables, platform support |
| [Usage & Commands](docs/usage.md) | The scan → exploit → fix loop; scan, exploit, and fix explained flag by flag with example output; AI & model setup; black-box testing + bug-hunting guide; separation-logic solver; CI/CD; troubleshooting; grouped command reference |
| [Detection](docs/detection.md) | Supported languages, 80+ vulnerability detectors, how detection works |
| [AI Layer & Models](docs/ai-models.md) | LLM detection & triage, RAM & model requirements, model providers (zero-key, Zen, local) |
| [Python API & Symbolic Core](docs/api.md) | Embedding Velora in Python; the separation-logic + Z3 foundation |

## Quick Start

Every command below runs as-is in a fresh clone. Copy them in order.

**1 — Scan a file.** The target for `velora scan` is a path **on your machine** (a file or a folder, never a URL). This demo file ships with the repo and is intentionally vulnerable:

```bash
velora scan examples/app.py
# -> Vulnerabilities Found: 2
#    1. [CRITICAL] sql_injection     login  examples/app.py:20  CWE-89
#    2. [CRITICAL] command_injection run    examples/app.py:27  CWE-78     ~10 ms, no model needed
```

**2 — Scan a folder.** Point `velora scan` at any project directory. A folder scan picks Python files by default (`**/*.py` = “any `.py` file, here or in any subfolder”); `--pattern` changes which files it picks:

```bash
velora scan .                                  # the folder you are standing in right now
velora scan /path/to/your/project              # any directory on your machine
velora scan /path/to/your/project --pattern "**/*.java"   # only its Java files
```

**3 — Scan with AI.** `--ai` adds LLM detection + triage on top of the symbolic engine. One-time model setup first (zero-key, no API key needed):

```bash
velora setup                                   # one-time: install + start the local model bridge
velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt   # activate the free model (no key)
velora models tui                              # full-screen picker: opencode bridge + local servers
velora scan . --ai                             # scan, now with the LLM layer on top
```

Each command, plainly: **`velora setup`** bootstraps whatever is missing, user-local (Node, the opencode CLI, bridge dependencies) and starts the bridge daemon. **`velora models use <ref>`** activates a model by name, non-interactively. **`velora models tui`** is the interactive, beginner-friendly alternative — a full-screen picker that lists every model Velora can reach: the zero-key opencode bridge (free Zen tier) **and** any local server (Ollama, LM Studio, llama.cpp, vLLM). It probes each source live, auto-starts the bridge if it isn't running, and saves your pick — still without ever storing an API key.

If a later `--ai` or `exploit` run ever fails with `no response from the model`, the bridge daemon has simply stopped (reboot, crash, or idle). Two commands restore and verify it: `velora serve-bridge --start`, then `velora doctor --probe` (exit 0 = working).

**4 — Exploit and fix.** Findings drive the rest of the loop — a JSON file is the hand-off between stages. `exploit` needs a **live, authorized** target (a URL); `fix` patches the source and re-scans to prove each fix landed:

```bash
velora scan . -f json -o findings.json                  # detect -> findings.json
velora exploit --target http://localhost:8080 \
  --guidance findings.json --goal 'read the admin secret'   # exploit: agent attacks the live target
velora fix examples/app.py --guidance findings.json --diff      # fix: preview patches (nothing written)
velora fix examples/app.py --guidance findings.json --in-place  # fix: apply + auto re-scan to verify
velora scan .                                            # confirm: fixed findings are gone
```

**5 — Built-in separation-logic solver.** Velora's soundness core, exposed directly — ask whether one heap description implies another, e.g. “two joined list segments (whose ends differ) imply one whole list”:

```bash
velora solve "ls(x, y) * ls(y, z) * x != z |- ls(x, z)"   # prints: VALID
```

Anatomy of a scan command:

| Piece | Meaning |
|---|---|
| `examples/app.py` or `.` | **the target** — a file/folder path on your machine (not a URL) |
| `.` vs `/path/to/project` | `.` = current directory; any absolute or relative path works |
| `--pattern "**/*.java"` | file filter inside the folder (`**` = every subfolder; default `**/*.py`) |
| `--ai` | add the LLM detect + triage layer (needs a model — step 3) |
| `-f json -o findings.json` | write findings as JSON (feeds `exploit` / `fix`) |
| `--format sarif` / `--fail-on high` | CI output format / minimum severity that fails the build |

<details>
<summary><strong>More examples</strong></summary>

```bash
# Any language, LLM tier only (no symbolic frontend)
velora scan /path/to/project --pattern "**/*.go" --ai -l go

# CI/CD gate (SARIF output)
velora scan . --format sarif -o results.sarif --fail-on high

# Exploit a finding against a live, authorized target (primed by a scan)
velora exploit --target http://localhost:8080 --guidance findings.json

# Generate a fix, then re-scan to confirm the vulnerability is gone
velora fix examples/app.py --guidance findings.json --diff

# Solver extras
velora check formulas.txt    # batch-check a file
velora repl                  # interactive REPL
```

</details>

## Commands

Every command, grouped by what it's for — `velora <command> --help` prints all flags, and [Usage & Commands](docs/usage.md) explains each one with examples and expected output.

### Core security

| Command | What it does | Typical first run |
|---|---|---|
| [`velora scan <path>`](docs/usage.md#scan) | Scan local source (a file or directory — never a URL) for vulnerabilities; symbolic engine, `--ai` adds the LLM layer | `velora scan examples/app.py` |
| [`velora exploit --target <url>`](docs/usage.md#exploit) | Drive an agent against a live, authorized target to build a working exploit; `--goal` states the objective, `--success-check` pins success to a shell command | `velora exploit --target http://localhost:8080 --goal 'read the admin secret'` |
| [`velora fix <path>`](docs/usage.md#fix) | Patch each finding from `--guidance findings.json`, then re-scan to prove it's gone; `--diff` previews, `--in-place` writes | `velora fix examples/app.py --guidance findings.json --diff` |

### AI / setup

| Command | What it does | Typical first run |
|---|---|---|
| [`velora setup`](docs/usage.md#ai--model-setup) | One-time bootstrap: install what's missing user-local (no sudo) and start the zero-key bridge | `velora setup` |
| [`velora models`](docs/usage.md#ai--model-setup) | Browse & switch models; `tui` = interactive picker (bridge + local servers, probes live, auto-starts the bridge) | `velora models tui` |
| [`velora doctor`](docs/usage.md#ai--model-setup) | Diagnose the AI chain; exit 1 when not ready, each failure prints its fix command | `velora doctor --probe` |
| [`velora serve-bridge`](docs/usage.md#ai--model-setup) | Manage the local OpenAI-compatible bridge daemon (port 8399) behind zero-key `--ai` | `velora serve-bridge --status` |

### Separation logic

| Command | What it does | Typical first run |
|---|---|---|
| [`velora solve "<P> \|- <Q>"`](docs/usage.md#velora-solve--check-one-entailment) | Check one entailment → `✓ VALID` / `✗ INVALID` (no model needed) | `velora solve "x \|- x"` |
| [`velora check <file>`](docs/usage.md#velora-check--batch-check-a-file) | Batch-check a file with one entailment per line | `velora check formulas.txt` |
| [`velora parse "<formula>"`](docs/usage.md#velora-parse--inspect-a-formula) | Print a formula's AST (grammar debugging) | `velora parse "x \|-> y * y \|-> z"` |
| [`velora repl`](docs/usage.md#velora-repl--interactive-checking) | Interactive REPL: type entailments, `:parse` / `:help` / `:quit` | `velora repl` |

## What next

- **Patch what you find** — [Fix](docs/usage.md#fix): preview a minimal diff, apply it, and re-scan to *prove* the vulnerability is gone.
- **Hunt bugs on a live target** — [Bug hunting guide](docs/usage.md#bug-hunting-guide-worked-example-examplecom): a full black-box campaign, step by step, with goal recipes per vulnerability class.
- **Wire it into CI** — [CI/CD](docs/usage.md#cicd): SARIF output + severity gate for GitHub Actions.
- **Set up the AI layer** — [AI & Model Setup](docs/usage.md#ai--model-setup): zero-key bridge, `velora models tui` picker, environment variables.
- **Embed it** — [Python API](docs/api.md#python-api) or the [Commands Reference](docs/usage.md#commands-reference).

