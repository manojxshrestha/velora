Velora is a neuro-symbolic security agent. A sound static-analysis core (taint analysis plus separation-logic verification with Z3) is fused with an LLM layer in one loop: the model proposes, the sound core disposes.

It runs the whole loop end to end. Detect vulnerabilities across 5 languages. Exploit them with a working proof-of-concept against a live target. Fix the code, then re-scan to confirm the bug is gone. Symbolic findings are proven, not guessed; LLM findings are tiered separately so the two are never confused. On independent real-world benchmarks Velora is competitive with commercial AI-SAST vendors, and it scores 80%+ on the synthetic OWASP suites. The LLM layer runs on any OpenAI-compatible endpoint — local or hosted, including a free tier (`velora models list --free`).

## Highlights

**Real-world security benchmarks.** Velora is competitive with commercial AI-SAST vendors, validated on five independent datasets with published ground truth, spanning detection, exploitation, and remediation on real applications. Every Velora number uses open models (local Qwen via mlx-optiq, or hosted GLM-5.2):

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

## Installation

Requires Python 3.10+. One line clones, installs everything (solver + all 5 language frontends), and leaves the `velora` command ready to use:

```bash
git clone https://github.com/manojxshrestha/velora.git && cd velora && python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[scan]" && velora --help
```

Already in a virtualenv or CI runner (no venv step needed):

```bash
git clone https://github.com/manojxshrestha/velora.git && cd velora && pip install -e ".[scan]" && velora --help
```

Prefer not to clone? Install straight from GitHub — same one-liner, console command included:

```bash
pip install "velora[scan] @ git+https://github.com/manojxshrestha/velora.git"
```

Verify: `velora --help` lists the full interface (scan, exploit, fix, solve, check, parse, repl, models). The legacy `frame` command still works as a deprecated alias.

## RAM & Model Requirements

**The tool itself is light — any laptop runs it.** Measured peaks for the symbolic engine (no model involved): **55 MB** to solve an entailment, **77 MB** to scan a 136-file package. Budget ~100 MB for Velora, nothing more.

**What actually costs RAM is running an LLM locally** (`--ai`). The model dominates:

| Setup | RAM needed | Notes |
|---|:---:|---|
| Symbolic scans & solver (no `--ai`) | **< 100 MB** | No model required — Z3 only |
| `--ai` with a hosted endpoint | **< 1 GB** | Inference happens remotely; RAM is irrelevant |
| `--ai` with a local **3–4B** model (4-bit) | **8 GB laptop ✅** | ~2–2.5 GB weights, fits alongside the OS |
| `--ai` with a local **7B** model (4-bit) | 8 GB, tight | ~4.5 GB weights — close other apps first |
| `--ai` with the **benchmark model** (Qwen3.6-35B, 4-bit, **24.7 GB** weights) | **32 GB machine** | What every number in this README uses |

Rule of thumb: ~**0.5–0.6 GB per 1B parameters** at 4-bit quantization (all weights load, even for MoE models).

**On an 8 GB laptop**, you have two good paths — hosted (full benchmark quality, zero extra RAM; free hosted models via `velora models list --free`, see [Model Providers](#model-providers)) or a small local model:

```bash
# small local model via Ollama (serves an OpenAI-compatible API)
ollama pull qwen3:4b
export VELORA_LLM_BASE_URL=http://localhost:11434/v1
export VELORA_LLM_MODEL=qwen3:4b
velora scan src/ --ai
```

Expectation setting: the benchmark results below were produced with the 35B local model and hosted GLM-5.2 — a 4B model on CPU will be noticeably weaker and slower at triage/exploitation. The symbolic engine (`velora scan` without `--ai`) is unaffected and runs identically on any machine above.

## Quick Start

```bash
# Scan for vulnerabilities
velora scan app.py

# Scan a directory
velora scan src/ --pattern "**/*.py"

# Another language: languages auto-detect per file, -p picks the files
velora scan src/ --pattern "**/*.java"
velora scan src/ --pattern "**/*.go" --ai -l go   # no symbolic frontend: LLM tier only

# AI-assisted scan: LLM detection + triage (pick a model first)
velora setup && velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt  # zero-key
# or: velora models use zen/glm-5.2, or export VELORA_LLM_BASE_URL / _MODEL / _API_KEY
velora scan src/ --ai

# CI/CD integration (SARIF output)
velora scan src/ --format sarif -o results.sarif --fail-on high
```

<details>
<summary><strong>More examples</strong></summary>

```bash
# Exploit a finding against a live, authorized target (primed by a scan)
velora exploit --target http://localhost:8080 --guidance findings.json

# Generate a fix, then re-scan to confirm the vulnerability is gone
velora fix app.py --guidance findings.json --diff

# Separation-logic solver
velora solve "x |-> 5 * y |-> 3 |- x |-> 5"   # check an entailment
velora check formulas.txt                       # batch-check a file
velora repl                                      # interactive REPL
```

</details>

## Commands

Velora is one CLI covering the whole workflow (detect, triage, exploit, fix) plus the separation-logic solver. Run `velora <command> --help` for all flags.

| Command | What it does |
|---------|--------------|
| `velora scan <path>` | Scan source for vulnerabilities (sound symbolic engine; add `--ai` for LLM detection + triage). `-f json\|sarif`, `-o <file>`, `--fail-on <sev>`. Directory scans skip agent/tool and dependency directories by default (`.git`, `.claude/worktrees`, `.cursor/worktrees`, `.worktrees`, `.idea`, `.vscode`, `node_modules`, `.venv`, `venv` only if it looks like a virtualenv, `.tox`, `__pycache__`, `.mypy_cache`, `.pytest_cache`); `--no-default-excludes` to scan them anyway. |
| `velora exploit --target <url>` | Drive an LLM agent to exploit a live, authorized target. Prime it with `--guidance <findings.json\|->` from a scan so it attacks the localized flaw. `--goal`, `--success-check`, `--max-steps`. |
| `velora fix <path>` | Generate a fix for each scan finding, then re-scan the patched code to confirm the vulnerability is gone. `--guidance <findings.json\|->`, `--in-place` or `--diff`. |
| `velora solve "<P> \|- <Q>"` | Check a single separation-logic entailment. |
| `velora check <file>` | Batch-check entailments (one per line). |
| `velora parse "<formula>"` | Parse and display a formula's AST. |
| `velora repl` | Interactive separation-logic REPL. |
| `velora models` | Browse & switch AI models for `--ai`. `list` (OpenCode Zen catalog, `--free`, `--registry` for the full models.dev registry, `--query`), `use <ref>`, `current`, `providers`, `import-opencode`. |

The analysis stages compose over a shared findings JSON, so the shell is the pipeline:

```bash
# scan (symbolic + LLM) produces findings; the exploit agent attacks the localized bug
velora scan ./repo --ai -f json | \
  velora exploit --target http://app:8080 --guidance - --goal 'read the admin secret'
```

## Supported Languages

The symbolic engine has sound frontends for five languages:

| Language | Frameworks & Libraries |
|----------|----------------------|
| **Python** | Flask, Django, FastAPI, SQLAlchemy, subprocess |
| **Java** | Spring, JDBC, Hibernate, JNDI |
| **JavaScript/TypeScript** | Express, Node.js, DOM APIs |
| **C/C++** | POSIX, Windows API, memory operations |
| **C#** | ASP.NET, Entity Framework, ADO.NET |

The LLM layer (`--ai`) runs on any language, including ones with no symbolic frontend (PHP, Ruby, Go, and more). Those findings stay in the LLM tier, never mixed with the sound symbolic results. Directory scans pick files with `--pattern`; each file's language is auto-detected from its extension, and `-l <language>` sets the fallback for unknown extensions (e.g. `-l go`).

## What Velora Detects

Velora recognizes 80+ vulnerability classes across the families below. The symbolic core proves the ones reachable by taint or memory reasoning; the LLM layer adds context-dependent, authorization, and business-logic flaws.

<table>
<tr>
<td width="50%">

**Injection**
- SQL / NoSQL / ORM Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Command & Code Injection (CWE-78/94)
- Template Injection (SSTI)
- LDAP / XPath / XML Injection
- Header & Log Injection

</td>
<td width="50%">

**Access Control & Auth**
- IDOR / BOLA (CWE-639)
- Authorization Bypass (CWE-285)
- Mass Assignment (CWE-915)
- Broken Authentication
- Session Fixation
- CSRF (CWE-352)

</td>
</tr>
<tr>
<td>

**Data Exposure & Crypto**
- Path Traversal (CWE-22)
- SSRF (CWE-918)
- Open Redirect (CWE-601)
- XXE (CWE-611)
- Hardcoded Secrets, Insecure Deserialization
- Weak Crypto / Hashing / Random

</td>
<td>

**Memory Safety**
- Buffer Overflow / Underflow (CWE-121/122)
- Use-After-Free (CWE-416)
- Double / Invalid Free (CWE-415)
- Null Pointer Dereference
- Integer Overflow, Format String

</td>
</tr>
</table>

## How It Works

Velora runs one investigation at rising commitment (detect, triage, exploit, fix), with a sound symbolic core grounding every stage so the LLM can't hallucinate:

<p align="center">
  <img src="assets/how-it-works.svg" alt="Velora pipeline: source code flows through DETECT, TRIAGE, EXPLOIT, and FIX" width="620">
</p>

- **Detect:** the sound core proves reachable bugs with zero false positives; the LLM layer adds recall, tracing flows across files. Symbolic and LLM findings are never conflated.
- **Triage:** the LLM drops confident false positives, keeping a finding unless it *finds* the mitigating control.
- **Exploit:** an LLM agent develops and executes a working proof-of-concept against a live, authorized target.
- **Fix:** Velora generates a patch, re-scans, and confirms the vulnerability is gone with no regressions.

**Inside detect:** a per-language frontend lowers source into SIL (a separation intermediate language); taint tracking follows untrusted data from sources to sinks, symbolic execution explores paths, and Z3 discharges the reachability proof. A bug is reported only when it is provably reachable.

## AI-Assisted Detection & Triage

Velora's symbolic core is sound and precise. But structural analysis can't reach everything: context-dependent flows, unknown frameworks, business logic. Velora adds a layer driven by an LLM.

- **Detect** (recall): find vulnerabilities the symbolic engine misses. It can explore across files, calling `read_file`/`grep` tools over your repo to trace a flow from one file into another.
- **Triage** (precision): drop confident false positives from the findings.
- **Verify**: each LLM finding is checked against Velora's own sink model. A finding grounded in a recognized sink, cross-file included, moves up to a higher-confidence tier (`llm_verified`). Symbolic results and LLM results are never conflated.

On the [Endor Labs public AI-SAST corpus](benchmarks/endor_corpus/README.md) (5 real-world apps), Velora's full mode (detection + triage) reaches 0.67 recall at 0.51 precision, or 0.71 recall with detection alone. Semgrep gets 0.52 recall at 0.40 precision. The LLM layer recovers around 65 real vulnerabilities across Java, JS/TS, and C# that both Velora's symbolic engine and Semgrep miss. See the [benchmark README](benchmarks/endor_corpus/README.md) for the full scoreboard and the honest caveats.

The layer works with any OpenAI-compatible endpoint, local or hosted, so Velora stays open and ungated end to end. Pick a model with `velora models` ([Model Providers](#model-providers) below) or export `VELORA_LLM_*` env vars — for a fully on-device setup, [mlx-optiq](https://mlx-optiq.com) serves [`mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit`](https://huggingface.co/mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit) on Apple Silicon; our benchmarks use both this local setup and a hosted open-source model, GLM-5.2 (`z-ai/glm-5.2`).

```bash
# our local setup (Apple Silicon): serve the model, then point Velora at it
pip install mlx-optiq
optiq kv-cache mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit --target-bits 5.0 -o ./kv
optiq serve --model mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit \
  --kv-config ./kv/kv_config.json --port 47317 --mtp    # --mtp: ~1.4x faster decode

export VELORA_LLM_BASE_URL=http://localhost:47317/v1
export VELORA_LLM_API_KEY=                                  # empty for local servers
export VELORA_LLM_MODEL=mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit
export VELORA_LLM_REPO_ROOT=/path/to/repo                   # enables agentic cross-file tools
```

The symbolic core runs on its own; add the LLM layer with one flag:

```bash
velora scan src/ --ai          # symbolic + LLM detection + triage
```

Or from the Python API:

```python
from velora.sil import VeloraScanner
# symbolic + LLM detection + triage (reads the VELORA_LLM_* env above)
scanner = VeloraScanner(language="java", llm_detect=True, llm_triage=True)
result = scanner.scan_file("Controller.java")
```

## Model Providers

### Zero-key quickstart (no API key)

```bash
velora doctor                              # 1. diagnose; exit 1 while something is missing
velora setup                               # 2. install what's missing user-local (no sudo), start the bridge
velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt   # 3. pick a free Zen model (keyless)
velora scan src/ --ai                      # 4. scan through the local bridge — free tier, zero keys
```

The bridge (`velora serve-bridge`) is a local OpenAI-compatible server on `:8399` that proxies opencode's own client — opencode owns every credential, so Velora stores none. `velora setup` installs missing prerequisites (Node ≥ 18 into `~/.local/opt`, the `opencode` CLI, bridge dependencies) after a single consent prompt; it is idempotent, and `--yes` makes it non-interactive. `velora doctor --probe` sends one real keyless chat to verify the whole chain end to end, and `velora models tui` auto-starts the bridge when you pick a model.

Supported platforms: **Linux (incl. WSL) and macOS**. On native Windows, use `wsl --install` and run everything inside WSL — the bridge will not start from a Windows shell.

#### Full usage on a target

Everything below runs with zero keys once the 4 commands above have run once. The full loop — detect, exploit, fix, re-confirm — on a target repo plus a live (authorized) target:

```bash
# --- one-time per machine ---
velora doctor                    # what's missing (exit 1 until ready)
velora setup                     # install prereqs user-local, seed the bridge, start it, verify with a live probe
velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt

# --- 1. detect: scan the target's source (symbolic + LLM) ---
velora scan ./target-app --ai -f json -o findings.json
velora scan ./target-app --ai                    # human-readable report instead
velora scan ./target-app --ai --fail-on high     # CI gate (exit 1 on high+)

# --- 2. exploit: drive the PoC against a live, authorized target ---
#     --guidance localizes the attack to the proven/likely-flawed parameter
velora exploit --target http://localhost:8080 --guidance findings.json \
  --goal 'read the admin secret' \
  --success-check 'curl -sf http://localhost:8080/pwned'

# --- 3. fix: patch, then re-scan to prove the finding is gone ---
velora fix ./target-app/app.py --guidance findings.json --diff
velora fix ./target-app/app.py --guidance findings.json --in-place
velora scan ./target-app --ai                    # re-run: the finding should disappear

# --- bridge & model management ---
velora doctor --probe           # end-to-end: one real keyless chat through the bridge
velora serve-bridge --status    # daemon state (also: --start / --stop, --format json)
velora serve-bridge --stop      # stop the daemon (models tui auto-restarts it on demand)
velora models current           # what model is active and where it came from
```

The daemon runs on `http://127.0.0.1:8399` with a log at `$XDG_STATE_HOME/velora/bridge.log`; the symbolically-proven findings (`Source: symbolic`) need no model at all, so the loop still works even if you only run `velora scan ./target-app` with no `--ai`.

`velora models` browses and switches the AI model behind `--ai`. Two sources are built in:

- **OpenCode Zen** — curated gateway (`https://opencode.ai/zen/v1`) with a **free tier** (e.g. `mimo-v2.6-flash-free`, `nemotron-3-ultra-free`, `ling-3.0-flash-fin-free`) and cheap pay-as-you-go models like `glm-5.2` ($1.40/$4.40 per 1M). Free hosted = no local RAM at all.
- **models.dev** — the registry opencode itself uses: 225 providers, 8,300+ models, 637 free (cached 24h; `--refresh` re-fetches).

Free-tier quickstart (a Zen key is free from [opencode.ai](https://opencode.ai)):

```bash
export OPENCODE_API_KEY=sk-...        # free key; `use` prompts for it on a tty otherwise
velora models list --free             # browse free models
velora models use mimo-v2.6-flash-free
velora scan src/ --ai                 # zero local RAM: inference is hosted
```

All actions:

```bash
velora models list                 # Zen catalog: free first, ✓ = usable by Velora
velora models list --free          # only free models
velora models list --registry      # full models.dev registry (filter: --query glm)
velora models tui                  # full-screen picker: opencode bridge + local servers
velora models use zen/glm-5.2      # activate a model (prompts for the API key once)
velora models current              # what's active and where it came from
velora models providers            # velora config, env keys, and opencode providers
velora models import-opencode      # reuse your existing opencode setup + keys
```

`velora models tui` probes every source at once and saves your pick keyless: the local opencode bridge (`velora serve-bridge --start` runs it as a daemon; `models tui` auto-starts it, free Zen tier) plus any running local server — mlx-optiq on `:47317` (the setup above), Ollama on `:11434`, LM Studio, llama.cpp, vLLM — with extras via `--local-url NAME=URL` or `VELORA_LOCAL_URLS=NAME=URL,...`. Local servers need no key, so none is stored.

`use` also accepts `opencode/<provider>/<model>` (reuse an opencode provider) or `<provider>/<model> --base-url <endpoint>` for any OpenAI-compatible server (Ollama, vLLM, ...). Keys are stored `0600` in `~/.config/velora/credentials.json` (override the directory with `VELORA_CONFIG_HOME`).

**Precedence** for `velora scan --ai` (per field): `--model` flag → `VELORA_LLM_*` env → `~/.config/velora/config.json` → existing opencode config (auto-fallback, announced once on stderr; disable with `VELORA_SKIP_PROVIDER_FALLBACK=1`). With no configuration at all, behavior is unchanged from before: `--ai` reports the missing endpoint.

**Compatibility.** Velora's client speaks OpenAI-style `/chat/completions` only. Zen's GPT/Claude/Gemini models use other transports and are listed as `✗ phase 2` until transport adapters land. models.dev rows that don't expose an OpenAI-style endpoint are marked `endpoint unverified` — pass `--base-url` if you know better.

## Exploitation

Detection tells you a bug *might* be there; exploitation proves it. `velora exploit` closes that gap. It drives an LLM through a tool loop against a live target and stops only when success is observably verified, never on the model's unchecked say-so.

- **Velora-guided.** Pipe a scan's findings in with `--guidance`. Velora's symbolic taint path hands the agent the exact endpoint, parameter, and sink, so it attacks the right surface instead of probing blind. The guidance header is honest about provenance: a symbolic finding is presented as a sound, verified-reachable lead; an LLM-detected finding as a heuristic lead to verify while exploiting.
- **Verified success.** Pass `--success-check '<cmd>'` (exit 0 ⇒ solved) to use an external oracle, or let the agent self-terminate once it verifies a real state change (a returned secret, a written file, an executed command). Unverified "done" is treated as failure.
- **Runs anywhere.** Commands execute from wherever you invoke `velora`, so point it at any reachable target; use any OpenAI-compatible model (an open, ungated model is the right base for offensive tasks).

```bash
# guided end-to-end: scan localizes the bug, the agent exploits it
velora scan ./repo --ai -f json | \
  velora exploit --target http://app:8080 --guidance - \
    --goal 'read /etc/secret' --success-check 'curl -sf http://app:8080/pwned'

# unguided attempt (no scan findings)
velora exploit --target http://app:8080 --goal 'achieve RCE' --max-steps 40
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Install Velora
  run: pip install -e ".[scan]"

- name: Security Scan
  run: velora scan src/ --format sarif -o results.sarif --fail-on high
  env:                          # only needed for --ai; the symbolic engine needs no model
    VELORA_LLM_BASE_URL: ${{ vars.VELORA_LLM_BASE_URL }}
    VELORA_LLM_MODEL: ${{ vars.VELORA_LLM_MODEL }}
    VELORA_LLM_API_KEY: ${{ secrets.VELORA_LLM_API_KEY }}

- name: Upload Results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

## Python API

```python
from velora import EntailmentChecker
from velora.sil import VeloraScanner

# Security scanning
scanner = VeloraScanner()
result = scanner.scan_file("app.py")
for vuln in result.vulnerabilities:
    print(f"{vuln.cwe_id}: {vuln.description}")

# Separation logic verification
checker = EntailmentChecker()
result = checker.check_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
print(result.valid)  # True
```

## The Symbolic Core: Separation Logic + Z3

Velora's soundness rests on a mathematical foundation. It models heaps in separation
logic and discharges the resulting proof obligations with the Z3 SMT solver, so the
symbolic engine can prove a vulnerability is reachable (reporting it with no false
positives) or prove it cannot happen. That same engine is exposed directly for
verifying heap properties:

| Syntax | Meaning |
|--------|---------|
| `x \|-> v` | x points to value v |
| `emp` | Empty heap |
| `P * Q` | P and Q in separate memory |
| `P -* Q` | Magic wand |
| `P \|- Q` | P entails Q |

**Built-in predicates:** `ls(x,y)`, `list(x)`, `tree(x)`, `dll(x,p,y,n)`

```bash
velora solve "ls(x, y) * ls(y, z) |- ls(x, z)"  # list-segment transitivity
```

The core is validated on the standard logic suites: SL-COMP (separation logic) at
79.9% and SMT-LIB QF_S (string theory) at 99.3%. Run the full suite with
`python -m benchmarks run --curated`; [benchmarks/README.md](benchmarks/README.md) has
every division, the real-world corpora, per-tool comparisons, and methods.
