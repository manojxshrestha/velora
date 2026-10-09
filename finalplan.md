# Velora Three-Mode Redesign — Final Plan

Design for `velora whitebox`, `velora blackbox`, `velora bughunt` as three
operating modes of **one general AI pentest platform**. The modes differ in
*how the system discovers and reasons*, not in which asset type it can
test: web, API, cloud, infrastructure, network, hosts, and mobile are
adapters over one universal asset abstraction.

---

## 1. Core idea

| Mode | View | Reasoning style | Delivers |
|---|---|---|---|
| **WHITEBOX** | source, binaries, IaC, configs, architecture available | code-assisted: prove it in the code, then exploit with precise aim | verified findings + patches |
| **BLACKBOX** | environment as an external target, no source assumptions | attacker-style: discover, enumerate, probe, exploit at runtime | reproducible exploit evidence |
| **BUGHUNT** | everything available, hunting what checklists miss | hypothesis-driven, iterative research loop | report-grade PoCs |

**One terminology rule:** `ASSET MODEL` / `SURFACE` is the universal
abstraction. Workers never care whether they hold a website, API, Kubernetes
cluster, host, cloud account, network service, or mobile backend — the
orchestrator hands each worker the relevant *slice* of the same
attack-surface graph.

---

## 2. Design principles

1. **Universal stage vocabulary, mode-specific stage graphs.** Modes compose
   shared stages; they never fork engines.
2. **One substrate.** Agent loop, LLM transport, findings contract, solver,
   oracle mechanics, capture/validate — built once (`§6`).
3. **Asset-agnostic dispatch.** `ASSET MODEL` unifies code-derived and
   recon-derived assets; `SURFACE` is the live, reachable view of it;
   per-asset-type logic lives in small adapters behind one interface.
4. **Provenance stays honest.** Every finding says how it was produced
   (`static` / `dynamic` / `llm` / `hybrid`) and carries captured evidence.
5. **Authorization is code-enforced.** Active stages run only against an
   explicit target (positional or `--target`) + declared scope; rate limits
   and budgets are
   enforced, not promised.
6. **Additive only.** Existing commands and flags (`scan exploit report fix
   solve check parse repl models serve-bridge doctor setup`) keep working;
   modes are new surfaces over them.
7. **Minimal commands first.** Every mode runs on obvious named inputs —
   `--source` for code, a URL (or `--target`) for a live target, `--goal`
   to aim it — never a stage flag. Everyday invocations carry at most two
   flags; no `./` or bare-`.` magic: paths are given plainly to `--source`
   (absolute or relative). The stage grammar (§8.2) is a power feature:
   real for scripts and resumption, but absent from every common example.
   AI stages stay opt-in via `--ai` (bughunt implies AI; its `--budget`
   defaults to 100 steps — cap only when you care), so plain runs remain
   deterministic and free.

---

## 3. Universal stage vocabulary

| Stage | Definition | Velora engine (now / planned) |
|---|---|---|
| **SCOPE** | declare targets, rules, out-of-scope; the enforceable allowlist | new `modes/common.py` scope object + `target_hosts`-style checks |
| **AUTH** | acquire a session (cookie/header/token, later scripted login) | new `active/session.py` |
| **INTEL** | external context about targets (fingerprint, tech stack, exposure) | new `active/intel.py` (minimal first: header/DNS fingerprint) |
| **OSINT** | public-source discovery (domains, certs, identifiers) | planned adapter, bughunt-first |
| **INGEST** | consume source / IaC / configs / dependencies | existing `sil/frontends/`, `_scan_literals`; IaC/dependency adapters planned |
| **ASSET MODEL** | universal graph: everything that *could* be attacked | new `assets/graph.py` (code symbols, URLs, hosts, ports, services…) |
| **CODE MODEL** | parsed program model (procedures, calls, dataflow) | existing SIL Program |
| **STATIC SCAN** | pattern + verification pipeline over the code model | existing `sil/scanner.py` |
| **DATAFLOW / CONTROLFLOW** | taint paths, guards, interprocedural state | existing analyzers + translator branch conditions |
| **RECON** | active discovery without source (crawl, specs, robots/JS) | new `active/recon.py` |
| **SURFACE** | the *reachable* view of the asset model — what testing can touch | new: stored slice/view of `assets/graph.py` |
| **ENUMERATION** | deepen each surface node (params, methods, routes, users) | new `active/probe.py` enumeration mode |
| **SERVICE MAPPING** | ports/services/banners for infra targets | planned network adapter (later phase) |
| **HUNT** | run detectors / hypotheses against the surface | static detectors (now) + dynamic probes (new) |
| **HYPOTHESIZE** | generate *falsifiable* novel-bug hypotheses | new `modes/bughunt.py` + agent loop |
| **TRIAGE** | confirm, dedupe, scope-check, rank (novelty rubric in bughunt) | existing `llm_triage.py` parameterized |
| **DEEPTHINK** | multi-step reasoning over evidence chains before spending on verify | agent loop with reasoning budget (bughunt-emphasized) |
| **PLAN** | turn evidence into an attack plan (code slices or surface map) | new source-slice enrichment of guidance |
| **VERIFY** | prove the claim: solver witness, or oracle-graded execution | `EntailmentChecker` / `--success-check` |
| **EXPLOIT** | run the PoC against the live target | existing `exploit_agentic` |
| **FIX** | patch the source | existing `llm_fix.py` + path containment |
| **RESCAN** | re-run the static pipeline to prove the fix | existing `verify_fixes` |
| **CAPTURE** | persist evidence: req/resp pairs, transcripts, witnesses | findings `evidence{}` + `trace.json` |
| **VALIDATE** | *independently re-check* captured evidence (re-run repro) | new validate pass before report |
| **SEARCH** | coverage-gap analysis → new intel/angles → feed the loop | bughunt loop stage (research + gap report) |
| **REPORT** | final artifacts (markdown / SARIF / bounty-grade) | `tui/report.py` extended |

---

## 4. The three mode graphs

### WHITEBOX — source/code-assisted pentesting

```
SCOPE → INGEST → ASSET MODEL → CODE MODEL → STATIC SCAN
      → DATAFLOW / CONTROLFLOW → HYPOTHESIZE → TRIAGE → PLAN
      → VERIFY → EXPLOIT → FIX → RESCAN → VALIDATE → REPORT
```

Purpose: Source, binaries, IaC, configs, architecture and runtime
information are available. Coverage (adapters, phased): Web applications,
APIs, Backend services, Mobile source, Cloud/IaC, Containers, Kubernetes,
Network configurations, Authentication/authorization, Business logic,
Dependencies, Secrets.

### BLACKBOX — external pentesting

```
SCOPE → AUTH → RECON → ASSET DISCOVERY → SURFACE → ENUMERATION
      → SERVICE MAPPING → HUNT → TRIAGE → VERIFY → EXPLOIT
      → CAPTURE → VALIDATE → REPORT
```

Purpose: Treat the environment as an external pentest target. No
source-code assumptions. The same pipeline dispatches across web, API,
network, hosts, services, cloud, VPN, DNS, TLS, email, directory services,
containers, mobile, wireless\* — \*where the engagement explicitly includes
it. `SURFACE` is the universal asset model:

```
Internet
   ├── Domains
   ├── IPs
   ├── Web apps
   ├── APIs
   ├── Hosts
   ├── Ports
   ├── Services
   ├── Cloud assets
   ├── VPN
   ├── Identity systems
   └── Other exposed infrastructure
```

### BUGHUNT — autonomous vulnerability research

```
SCOPE → AUTH → INTEL → OSINT → RECON → ASSET MODEL → SURFACE
      → HUNT → TRIAGE → DEEPTHINK → VERIFY → EXPLOIT
      → CAPTURE → VALIDATE → SEARCH ↺
      → REPORT
```

Key loop — hypothesis-driven and iterative, never a fixed checklist:

```
        ┌──────────────┐
        │     HUNT     │
        └──────┬───────┘
               ↓
        ┌──────────────┐
        │    TRIAGE    │
        └──────┬───────┘
               ↓
        ┌──────────────┐
        │  DEEPTHINK   │
        └──────┬───────┘
               ↓
            VERIFY
               ↓
           VALIDATE
               │
         coverage gap?
               ↓
             SEARCH ──→ HUNT
```

A hypothesis that neither proves nor reproduces is recorded as
**eliminated** (the loop never re-derives it); `SEARCH` refreshes angles
from gap analysis and returned intel, then feeds the next `HUNT`.

Loop termination — every ending proceeds to `REPORT`:
**converged** (SEARCH finds no actionable gap) · `--budget` (LLM steps,
default 100) · `--time-budget` · `--max-loop` · interrupt. Budget, time, loop-cap,
and convergence are normal endings (exit 0 once the gate runs), never
errors; interrupt is 130 with the session resume hint.

---

## 5. The three modes in one view

Stage presence per mode (`✓✓` = defining emphasis):

| Phase | WHITEBOX | BLACKBOX | BUGHUNT | Velora today |
|---|:-:|:-:|:-:|---|
| SCOPE | ✓ | ✓ | ✓ | partial (`--target`/scope checks) |
| AUTH | — | ✓ | ✓ | planned (`active/session.py`) |
| INTEL | — | optional | ✓ | planned (minimal fingerprint) |
| OSINT | — | optional | ✓ | planned |
| INGEST | ✓ | — | optional | **exists** (frontends, literals) |
| ASSET MODEL | ✓ | ✓ | ✓ | planned (`assets/graph.py`) |
| CODE MODEL | ✓ | — | optional | **exists** (SIL) |
| STATIC SCAN | ✓ | — | optional | **exists** |
| DATAFLOW / CONTROLFLOW | ✓ | — | optional | **exists** (analyzers) |
| RECON | ✓ | ✓ | ✓ | planned (`active/recon.py`) |
| SURFACE | ✓ | ✓ | ✓ | planned (view over asset graph) |
| ENUMERATION | ✓ | ✓ | ✓ | planned |
| HUNT | ✓ | ✓ | ✓ | partial (static detectors; dynamic planned) |
| HYPOTHESIZE | ✓ | ✓ | ✓ | partial (planned engine) |
| TRIAGE | ✓ | ✓ | ✓ | **exists** (`llm_triage`) |
| DEEPTHINK | ✓ | ✓ | **✓✓** | new stage (agent reasoning budget) |
| PLAN | ✓ | ✓ | ✓ | new stage (guidance enrichment) |
| VERIFY | ✓ | ✓ | ✓ | **exists** (Z3 + success-check) |
| EXPLOIT | ✓ | ✓ | ✓ | **exists** (`exploit_agentic`) |
| FIX | **✓** | optional | optional | **exists** (`llm_fix`) |
| RESCAN | **✓** | optional | optional | **exists** (`verify_fixes`) |
| CAPTURE | ✓ | ✓ | ✓ | partial (`evidence{}`, `trace.json`) |
| VALIDATE | ✓ | ✓ | **✓✓** | new stage (independent re-check) |
| SEARCH | optional | optional | **✓✓** | new stage (gap → loop) |
| REPORT | ✓ | ✓ | ✓ | **exists** (markdown/SARIF; bounty format planned) |

The matrix is also the **capability contract**: a mode may only run a stage
it has an engine for; anything not yet implemented is refused loudly (exit
2 with a clear "stage not available for this asset class" message), never
silently skipped.

---

## 6. Shared substrate (build once)

| Engine | Stages served | Location |
|---|---|---|
| Agent loop (steps, stall/transport budgets, compaction) | HUNT, HYPOTHESIZE, DEEPTHINK, PLAN, EXPLOIT | `sil/llm_agent.py::run_agent` |
| LLM transport + structured output + exit-2 discipline | every AI stage | `sil/llm_client.py` |
| Model precedence (flag → env → config → bridge) | every mode | `model_config.py` + bridge |
| Findings contract + formatters | all reportable stages | `sil/scanner.py` models |
| Solver / Z3 verification | STATIC SCAN, VERIFY, RESCAN | `checking/`, `encoding/` |
| Oracle mechanics + host allow-list | VERIFY, EXPLOIT | `llm_exploit.py` |
| Evidence capture + human-readable action timeline (report appendix) | CAPTURE | `evidence{}` + `trace.json` → derived timeline |
| Path containment + untrusted-fencing (target/tool output = data, never instructions) | FIX, PLAN, HUNT, EXPLOIT, tools | `cli.py::_resolve_finding_file`, guidance fences |
| Report builder | REPORT | `tui/report.py` |
| **Asset graph** (universal model) | ASSET MODEL, SURFACE | new `assets/graph.py` |
| **Active client** (rate-limited HTTP, session, redirects) | RECON, ENUMERATION, HUNT (dynamic) | new `active/client.py` |

**Knowledge substrate (deferred past Phases 1–2).** Testing knowledge
today: whitebox methodology already lives in the symbolic layer (taint →
sink → CWE via `guidance_from_finding`); every mode's prompts carry the
recon → hypothesize → payload → verify discipline; actual payloads come
from the LLM. Per-class knowledge packs for blackbox/bughunt — each pack
= guide (when to suspect / how to confirm / FP traps) + seed probe
payloads, under a WSTG/CWE-shaped class taxonomy — are a **future
addition**, decided after Phases 1–2. Contract when they land: packs
**feed the hypothesis loop as seed material, never as a fixed
checklist** (§4); pack availability enters the capability contract per
class (`full` = guide+payloads, `partial` = guide-only, `unavailable` =
LLM-only); REPORT discloses provenance per finding (pack-tested vs
LLM-guided). No phase depends on them.

---

## 7. Contract evolution (additive)

### 7.1 Finding additions

```json
{
  "type": "...", "severity": "...", "confidence": 0.85,
  "score": { "value": 7.5, "vector": "CVSS:3.1/...", "from": "rule|rubric|llm" },
  "mode": "whitebox" | "blackbox" | "bughunt",
  "provenance": "static" | "dynamic" | "llm" | "hybrid",
  "asset": { "kind": "web|api|host|service|cloud|...", "id": "..." },
  "evidence": {
    "kind": "reqresp" | "solver" | "transcript",
    "request": "...", "response": "...", "reproduced": 2
  },
  "hypothesis": "falsifiable statement (bughunt)"
}
```

Old fields untouched; SARIF gains `properties.provenance` and
`properties.asset`. Scoring rule: static findings keep rule severity as
`score.from=rule`; dynamic/agent findings must still produce a number —
CVSS vector when the class maps cleanly, else a compact rubric
(impact · exploitability · scope) with `score.from=rubric|llm`. One
severity number feeds `--fail-on`, SARIF consumers, and bounty reports.

### 7.2 Asset graph / surface store

- `assets.json` — ASSET MODEL: nodes (domain, host, port, service, url,
  endpoint, api_operation, workload, bucket, identity, code_symbol…) +
  edges (resolves_to, hosts, exposes, routes_to, calls).
- `surface.json` — SURFACE: the reachable subset + enumeration data
  (methods, params, auth seen, tech fingerprint), rebuilt each run,
  archivable for re-runs.
- Workers receive **slices** of these graphs keyed by asset kind — the
  dispatch rule that makes modes asset-agnostic.

### 7.3 Guidance envelope extension

Existing lead fields plus `source_slices[]` (whitebox: ±N lines around
source/sink + guards) and `surface[]` (blackbox: candidate endpoints).
Fencing unchanged — slices are quoted untrusted data, never instructions.

---

## 8. Command surface (CLI)

### 8.1 Command map after the redesign

| Command | Status | Role |
|---|---|---|
| `velora whitebox --source SRC` | **new** | whitebox stage graph (§4 · WHITEBOX); SRC = directory or source file |
| `velora blackbox [TARGET]` | **new** | blackbox stage graph (§4 · BLACKBOX); TARGET = URL or file of URLs (`--target` accepted as alias) |
| `velora bughunt [--source SRC] [TARGET]` | **new** | bughunt loop (§4 · BUGHUNT); source and/or target (at least one) |
| `velora bughunt ledger \| gaps \| resume` | **new** | read-only loop inspection / continuation |
| `velora modes` | **new** | overview: every mode, its stages, engine status |
| `scan exploit report fix solve check parse repl models serve-bridge doctor setup` | unchanged | single-job tools; stages *delegate* to them (§8.4) |

Everyday input rules (explicit, no magic):

```text
--source PATH        code input: directory or source file — whitebox
                     requires it, bughunt accepts it. Any absolute or
                     relative path; no ./ or bare-. notation needed.
[TARGET] positional  live input: URL → target; plain file → target list
                     (one URL per line). Required for blackbox, optional
                     for bughunt; --target URL is an accepted alias.
```

Positionals are only ever targets — source never rides positional, so a
file argument can never be misread (the classification ambiguity and the
bughunt first-line sniff are gone).

No existing command or flag is renamed, repurposed, or removed. Modes are
new surfaces that orchestrate the existing ones. Mental mapping for
today's users: `velora scan` ≈ whitebox `--scan --triage`; `velora
exploit` ≈ one EXPLOIT run; `velora fix` ≈ FIX + RESCAN — modes add
orchestration, session, and scope, not new power.

### 8.2 Three-level stage grammar

Users select work at three granularities; one grammar per mode:

```text
LEVEL 1 — full graph, inputs only, no stage flags (the 90% case)
  velora whitebox --source src
  velora blackbox https://x.tld
  velora blackbox targets.txt                      # one URL per line
  velora bughunt --source src --target https://x.tld   # wallet defaults to 100 steps
  velora bughunt https://x.tld                     # target-only hunt
  velora bughunt --source src                      # source-only hunt

LEVEL 2 — ranges (continuity via --session)
  --until STAGE      run up to and including STAGE
                     (recon-only: velora blackbox https://x.tld --until surface)
  --from STAGE       resume from STAGE; earlier artifacts loaded from session
  --only STAGE[,…]   exactly these stages, executed in canonical graph order

LEVEL 3 — exact stage lists (positive flags) and skips (negative flags)
  velora whitebox --source src --scan --triage # static-only pipeline
  velora whitebox --source src --fix --rescan  # re-run the fix tail
  velora blackbox https://x.tld --recon --surface --enumerate
  velora bughunt  https://x.tld --hunt --deepthink --verify --validate
  --no-fix / --no-exploit / --no-osint …       # auto-generated per stage
  --skip STAGE[,…]                             # multi-stage skip = several --no-*
                                               # (default graph minus these)

LEVEL 3+ — additive flags for stages outside the default graph
  --with-STAGE                                 # default graph PLUS that stage
                                               # (e.g. blackbox/bughunt:
                                               #  --with-fix --with-rescan,
                                               #  whitebox/blackbox: --with-search)
```

Two grammar classes, decided by the registry (§8.3):

- **Guard stages are not flag-selectable.** `SCOPE` runs first on every
  invocation — it enforces bounds, it is not work. Its inputs are
  ordinary value flags/positionals (`--source`, target positional or
  `--target`, `--scope/--scope-file`); there is no `--scope` stage flag
  (that name belongs to the input).
- **Default membership = §4 pipeline.** A stage marked `✓`/`optional` in
  the matrix (§5) but absent from a mode's §4 pipeline is selectable
  (positive flag, `--with-*`) yet off by default.

Rules (all violations are clean argparse/usage exits — code 2):

1. If **any** positive stage flag is present → graph = exactly those stages
   (canonical order, user order irrelevant). Positive flags are mutually
   exclusive with `--only/--until/--from/--skip/--with-*` (all of those
   shape the *default* graph; an exact list needs no shaping — add or drop
   stages in the list itself). `--with-*` does combine with ranges and
   `--skip`.
2. `--from` without prior session artifacts → exit 1 with a hint
   (`run --dry-run to see the plan / run without --from first`).
3. Stage flag that is neither in this mode's §4 default pipeline nor
   `✓`/`optional` in its §5 matrix row → exit 2 + this mode's valid stage
   list (membership = union of both, §8.3).
4. A stage the user **explicitly selected** (positive flag, `--only`)
   whose engine/adapter is `unavailable` → exit 2 naming the stage and
   asset kind (capability contract, §5) — never a silent skip.
5. A stage the user **explicitly selected** lacks a required input
   (e.g. `--exploit` with no target, `--hypothesize` with no `--source`
   or target, after CLI → session resolution) → exit 1 with the missing
   input named.
6. **Input-driven n/a (auto-compose).** Default-graph stages whose
   *mode-optional* inputs are absent are marked `n/a`: announced on
   stderr, listed by `--dry-run`, recorded in `session.json` — never an
   error, never silent. Covers: EXPLOIT/VERIFY(live) with no target
   (positional or `--target`)
   (--source-only whitebox runs truncate there); FIX/RESCAN/VALIDATE with
   zero findings. This is
   *not* rule-4 refusal — capability `unavailable` never degrades to
   n/a (§8.3), and single-command exit semantics (e.g. `fix` exiting 1
   on "no patch applied") do not apply inside a mode's default flow.
   Explicitly selected stages never truncate (rules 4–5 apply).

### 8.3 Stage registry — one source of truth

All three levels, help text, `--dry-run`, `velora modes`, and the docs
table are **generated from a single stage registry** (`modes/common.py`):

```text
StageSpec = (name, mode membership, graph order, default membership
             (from §4 pipeline) | guard | off-default, engine binding,
             flag name, inherited flag namespace, required inputs)
```

Generated per mode — `default` = §4 pipeline, `off-default` = §5 matrix
`✓`/`optional` but not in that pipeline, `unavailable` = matrix `—`
(everything else → rule 3):

```text
whitebox   guard: scope
  default:         ingest asset-model code-model scan dataflow hypothesize
                   triage plan verify exploit fix rescan validate report
  off-default:     recon surface enumerate hunt deepthink search
  unavailable:     auth intel osint
  inputs:          --source (required; guard-stage inputs are separate
                   flags, never stage flags)

blackbox   guard: scope
  default:         auth recon asset-discovery surface enumerate
                   service-mapping hunt triage verify exploit capture
                   validate report
  off-default:     asset-model hypothesize deepthink plan intel osint
                   fix rescan search            (add via --with-*)
  unavailable:     ingest code-model scan dataflow
  inputs:          target positional (--target alias) + --scope/--scope-file
                   (NOT stage flags)

bughunt    guard: scope
  default:         auth intel osint recon asset-model surface hunt triage
                   deepthink verify exploit capture validate search report
  off-default:     ingest code-model scan dataflow hypothesize plan
                   fix rescan enumerate           (add via --with-*)
  unavailable:     asset-discovery service-mapping
  inputs:          target positional (--target alias) + --scope/--scope-file
                   (NOT stage flags)

(+ `--with-*` offered for every off-default stage; `dataflow` covers
 DATAFLOW/CONTROLFLOW as one flag)
```

- A stage cannot exist without a flag and a flag cannot exist without a
  stage; `--help`, `--dry-run`, `--list-stages`, `velora modes`, and the
  docs table are all rendered from this registry — no drift is possible.

**Capability levels** (per stage, per asset kind — reported by
`--dry-run` and `velora modes`):

```text
full       engine complete for this asset kind
partial    runs with reduced-but-honest behavior (name the reduction)
unavailable no engine yet → exit 2 if selected (rule 4)
```

**Shippability gate:** a mode's *default* graph must be runnable end-to
end when the mode ships — every default stage at least `partial`
(`velora whitebox --source src`, `velora blackbox https://x.tld`,
 `velora bughunt`
must reach REPORT, n/a truncation aside). Enforced per roadmap phase:
Phase 1 whitebox needs a minimal HYPOTHESIZE (candidate generation from
static leads) wired day one; Phase 2 blackbox needs SERVICE MAPPING at
`partial` (recon-derived ports/services only, full adapter Phase 4 —
replacing the earlier "stub refused" idea, which would have broken every
default run). `unavailable` can only occur on off-default stages.

### 8.4 Flag inventory

**Shared by all three modes:**

```text
  Input:          --source PATH        code input (whitebox required,
                                       bughunt optional); dir or file,
                                       absolute or relative — no ./ needed
                  [TARGET] positional  live input (blackbox required,
                                       bughunt optional): URL, or a file
                                       of one URL per line
                  --target URL         alias for the target positional
                  --guidance FILE      seed findings; `-` = stdin; session
                                       findings.json wins when both exist
                  (missing required input resolves CLI → session → exit 1)
  Aim:            --goal TEXT            objective threaded into PLAN / HUNT /
                                         HYPOTHESIZE / EXPLOIT prompts; in
                                         bughunt it also drives convergence
                  --success-check CMD    oracle: exit 0 = goal achieved —
                                         used by VERIFY/EXPLOIT and loop exit
  Stage grammar:  --only | --until | --from | --skip STAGE[,…]
                  | --with-STAGE (off-default add) | --list-stages
  Session:        --session DIR        (default .velora/<mode>-<hash>; env VELORA_SESSION)
  Budgets:        --budget N           whole-run wallet (all optional;
                                        defaults shown in --dry-run/banner):
                                        bughunt = LLM steps (default 100),
                                        blackbox = HTTP requests (default
                                        cap), whitebox = total LLM steps
                                        for AI stages (static work is free)
  AI:             --ai                 opt-in for LLM stages (bughunt implies
                                        it); honest stderr hint, unchanged
  Output:         --format json|text|sarif · -o FILE · --trace-out FILE
  Gate:           --severity LEVEL   (sugar: sets both below)
                  --fail-on LEVEL · --min-severity LEVEL (fine-grain)
  Filter:         --asset KIND[,…]     operate only on these asset kinds (default: all
                                       the mode supports)
  Model:          --model ID · --base-url URL      (flag > VELORA_LLM_* > config > bridge)
  UX:             --dry-run · --no-tui · --quiet · -v/--verbose
  (global)        --version · -h/--help · exit codes 0/1/2/3/130
```

`--goal`/`--success-check` are the same names `velora exploit` already
uses (delegation) — now accepted at mode level to aim the whole run, not
just one EXPLOIT invocation.

**Cost & gate flags — one line each (they answer different questions):**

```text
--budget N         "How much may this WHOLE run spend?" — the wallet.
                   Optional everywhere; unit per mode: LLM steps
                   (bughunt, default 100) · HTTP requests (blackbox,
                   default cap) · LLM steps across AI stages (whitebox).
                   Exhaustion ends the run normally (exit 0 after the
                   gate), never an error.
--max-steps N      "How many model turns may ONE agent run take?" — the
                   per-run leash (default 40; one step = one round-trip,
                   30–90 s). Bounds EXPLOIT/agent invocations only.
--time-budget M    "How many wall-clock minutes may a bughunt loop run?"
--max-loop N       "How many SEARCH→HUNT iterations before stopping?"
--rate R           "How fast may blackbox send requests?" (req/s)
--severity SEV     "I care about SEV and above" — the ONE-flag answer.
                   Sugar: expands to --min-severity SEV + --fail-on SEV
                   (hide everything below SEV, go red on SEV+). Example:
                   --severity high = show only high+critical, CI fails on
                   either. An explicit --min-severity/--fail-on overrides
                   its half.
--fail-on SEV      "When should the process exit 1?" — the CI gate
                   (critical|high|medium|low|any|none; default high;
                   a THRESHOLD: high = high+critical trigger exit 1).
--min-severity SEV "Which findings appear in the output?" — a display
                   floor; never changes the exit code.

Detection is never filtered: all severities (low/medium/high/critical)
are always found and recorded; the gate flags only shape the report and
the exit code. `--fail-on low` = "fail on anything I could find";
`--fail-on none` = "never fail".

Pick by who you are: everyday run → no flag (see all, red on high) ·
"I only want serious bugs" → `--severity high` · CI needing
"report everything, fail on X" → the fine-grain pair.
```

Note: the REPORT stage's selector is `--report` (positive stage flag);
report *path* is `-o FILE` — no separate report-path flag exists.

**`velora whitebox` extra flags:**

```text
  INPUT      --source PATH (required; directory or source file)
             --target URL (optional: enables VERIFY(live)+EXPLOIT)
  BUDGET     --budget N (optional: total LLM steps across AI stages —
             static scan/detect/solver work is free)
  SCAN       --llm-detect · --llm-triage · --language · --pattern
             --no-default-excludes · --no-verify · --repo-scale
  PLAN       --context-lines N         (source-slice size, default 20)
  EXPLOIT    --max-steps N · --exec-timeout S   (+ shared --goal/--success-check)
             # one loop per step: think → run a command → observe →
             # think again, repeated up to --max-steps (§6 agent loop)
  FIX        --in-place · --diff
```

**`velora blackbox` extra flags:**

```text
  INPUT      [TARGET] positional — URL or target-list file
             --target URL (alias) · --scope HOST (repeatable) · --scope-file FILE
  AUTH       --auth-file FILE · --header "K: V" (repeatable)
  CONNECTION --proxy URL · -k/--insecure · --user-agent STR
  ACTIVITY   --rate R (req/s) · --budget N (requests, default cap)
             --depth N · --pages N · --seed URL (repeatable)
             --active (allow state-changing verbs; default inert)
  EXPLOIT    --max-steps N · --exec-timeout S   (+ shared --goal/--success-check)
             # one loop per step: think → run a command → observe →
             # think again, repeated up to --max-steps (§6 agent loop)
  # recon-only run: --until surface
```

**`velora bughunt` extra flags:**

```text
  INPUT      --source PATH (optional) · [TARGET] positional (optional:
             URL or target-list file) — at least one of the two required
  AUTH       --auth-file FILE · --header "K: V" (repeatable)
  SCOPE      --scope HOST · --scope-file FILE   (guard inputs, not stage flags)
  LOOP       --budget N (default 100: total LLM steps) · --time-budget M
             --max-loop N
             --classes logic,authz,race,… · --hypotheses FILE (seed ledger)
  STAGES     --no-intel · --no-osint (+ all auto-generated --no-<stage>)
  FIX        --with-fix (opt-in when source present; FIX is off-default
             here — positive `--fix` selects FIX as an exact list)
  SUBCOMMAND ledger | gaps | resume    (read-only; resume == --from hunt)
```

**Delegation rule (prevents flag duplication):** a stage flag inherits the
flag namespace of the command it delegates to — `--scan` accepts exactly
`velora scan`'s flags, `--exploit` exactly `velora exploit`'s, `--fix`
exactly `velora fix`'s. Declaring a parallel name for an inherited flag is
a review error.

**Reserved for adapters (not in the mode shell):** `--wordlist`,
`--jobs`, TLS-pinning bypass, wireless flags, login-script DSL — they land
with their adapter and capability entry, never prematurely.

### 8.5 Session & artifacts

```text
.velora/<mode>-<hash>/            # auto-created; --session overrides
├── session.json                  # completed stages, budgets spent, inputs resolved
├── assets.json                   # ASSET MODEL (§7.2)
├── surface.json                  # SURFACE view + enumeration data
├── findings.json                 # contract: every stage appends/updates
├── hypotheses.json               # bughunt ledger: open / eliminated / proven
├── trace.json                    # agent transcripts (CAPTURE)
└── report.md                     # REPORT output (also -o FILE)
```

- **Crash-safe:** a stage's outputs are committed to the session *before*
  the next stage starts — `--from` and `resume` are always safe.
- **Interrupt (130):** completed stages stay committed; the in-flight
  stage's partial output is discarded; stderr prints the `--from STAGE`
  hint to continue.
- **Session identity:** the default dir hash covers (mode + normalized
  target + path + resolved scope) so re-running the same command
  resumes-or-refreshes the same session; `--session DIR` overrides
  entirely. `session.json` carries `schema_version` (additive evolution,
  §7). A session in use is locked (`session.lock`) — concurrent second
  writers refuse with exit 1.
- **Secrets:** auth material (cookies, tokens, `--header` values) is
  stored as *references* (file path / env name) in `session.json`, never
  as values; secrets never enter `findings.json`, evidence, reports, or
  `--dry-run` output (which redacts resolved inputs).
- **Subcommand session resolution:** `bughunt ledger|gaps|resume`
  require `--session` (or `VELORA_SESSION`) — inspection never guesses a
  session from a hash.
- Sessions are archivable/re-runnable; `assets.json` is derived per run
  (no hidden state outside the session dir).

### 8.6 Discoverability

- `velora <mode> --help` prints the mode's stage graph with each stage's
  engine status.
- `--dry-run` → full plan: stages, capability report, inputs, session
  path, estimated budget consumption; runs nothing.
- `--list-stages --format json` → machine-readable stage registry
  (for scripts/CI).
- `velora modes` → all three graphs side by side with engine status
  (the §5 matrix, live from the registry).
- Progress: stage banners on stderr; stdout stays artifact-only so JSON
  pipes never break (existing discipline). A machine-readable
  `--progress json` (NDJSON stage events) is reserved for Phase 4 tooling.

### 8.7 Conventions

- **Precedence everywhere:** flag > `VELORA_*` env > config file > bridge
  fallback (identical to today's `--model` rule).
- **`-` = stdin** for `--guidance`, `--scope-file`, `--hypotheses`.
- **Streams:** stdout = artifacts only; stderr = progress, notes, the
  `--ai` honesty hint, scan errors.
- **TTY:** interactive views only on TTY; non-TTY (CI) is batch by
  default; `--no-tui` forces batch anywhere.
- **Exit codes unchanged:** `0` success/gate-passed · `1` findings gate,
  invalid input, missing required input, no patch applied · `2` LLM
  unreachable *or* usage *or* unavailable stage · `3` scan I/O · `130`
  interrupt. Budget exhaustion alone is never an error.

### 8.8 Examples

```bash
# ── everyday: inputs in, artifacts out (≤ 2 flags, usually 0) ──────────────
velora whitebox --source src                        # see all, red on high+
velora whitebox --source src --severity high        # only serious: high+ shown, red on high
velora blackbox https://x.tld
velora blackbox targets.txt                      # one URL per line
velora bughunt --source src --target https://x.tld     # 100-step wallet by default

# ── goal-driven: aim the whole run, not just one stage ─────────────────────
velora whitebox --source src --target https://x.tld \
  --goal 'exploit the auth weakness PLAN found in /api/login'

velora blackbox https://target.com \
  --goal 'access a protected page without logging in' \
  --success-check 'curl -sk https://target.com/private | grep -qi secret'

velora blackbox https://target.com \
  --goal 'enumerate the login form and test for SQL injection' \
  --format json --trace-out evidence.json

# ── aimed hunt: wallet, time, loop-cap, classes all visible ────────────────
velora bughunt --source src --target https://x.tld \
  --budget 120 --time-budget 45 --max-loop 6 --classes authz,race \
  --goal 'anything that leaks other users data'

# ── CI gate: output + gate flags only — never stage flags ──────────────────
#    the fine-grain pair, for "report everything, gate on high" (what
#    --severity high would collapse into one flag: here kept separate so
#    the report still contains low/medium while exit 1 = high+ only;
#    --fail-on high is already the default, spelled out for CI readers)
velora whitebox --source src --format sarif -o results.sarif --fail-on high

# ── lab target behind an intercepting proxy, self-signed cert ──────────────
velora blackbox https://10.0.0.5 -k --proxy http://127.0.0.1:8080 \
  --auth-file cookies.txt --rate 5

# ── power: plan, ranges, sessions, stage grammar (for scripts) ─────────────
velora blackbox https://x.tld --dry-run                     # see the plan first
velora blackbox https://x.tld --until surface --session .velora/bb1
velora blackbox --session .velora/bb1 --from hunt           # resume into full attack
velora whitebox --only validate --session .velora/wb…       # re-verify fixes only
velora bughunt ledger --session .velora/bh-…                # hypotheses + verdicts
velora bughunt gaps --session .velora/bh-…                  # what did the loop cover?
velora bughunt resume --session .velora/bh-…                # == --from hunt
velora whitebox --dry-run                                   # the 15-stage plan first

# ── inventory ──────────────────────────────────────────────────────────────
velora modes
```

---

## 9. Module layout

```
velora/
├── assets/                    # NEW — universal model
│   ├── graph.py               # asset nodes/edges, slices by kind
│   └── surface.py             # reachable view + enumeration store
├── active/                    # NEW — runtime surface engine
│   ├── client.py              # rate-limited HTTP (reuse opener rules)
│   ├── session.py             # auth: cookie/header/token (login flows later)
│   ├── intel.py               # fingerprint/DNS minimal intel
│   ├── recon.py               # crawl, robots/sitemap/JS/spec → assets
│   └── probe.py               # enumeration + differential detection
├── modes/                     # NEW — orchestrators only (stage graphs)
│   ├── __init__.py            # registry {whitebox, blackbox, bughunt}
│   ├── common.py              # ModeContext, Stage protocol, STAGE REGISTRY
│   │                          #   (StageSpec → flags/help/--dry-run generated)
│   ├── session.py             # session dir, crash-safe stage commits, resume
│   ├── whitebox.py            # …STATIC SCAN → …FIX → RESCAN → VALIDATE → REPORT
│   ├── blackbox.py            # …RECON → SURFACE → ENUM → HUNT → …VALIDATE → REPORT
│   └── bughunt.py             # …HUNT → TRIAGE → DEEPTHINK → VERIFY →
│                              #   VALIDATE → SEARCH ↺ → REPORT
├── sil/…                      # reused: scan internals, LLM tiers, fix, agent
├── cli.py                     # + 3 mode parsers, grammar (§8.2), `velora modes`
└── tui/report.py              # report extensions (bounty format, evidence §)
```

Adapters for further asset classes (network/service mapping, IaC, cloud,
mobile backend) plug into `assets/` + `active/` behind the same slice
interface — no mode graph changes.

---

## 10. Implementation roadmap

**Phase 1 — Stage framework + whitebox (wiring-heavy, lowest risk)**
- `modes/common.py`: ModeContext, SCOPE enforcement, stage protocol,
  capability contract, shared gate/exit-code helpers.
- **Stage registry (§8.3)** + generated argparse: three-level grammar
  (§8.2), conflict rules, `--dry-run`, `--list-stages`, `velora modes`.
- `modes/session.py`: session dir layout (§8.5), crash-safe stage commits,
  `--from`/resume plumbing.
- `assets/graph.py` skeleton (code-derived nodes first: files, symbols,
  endpoints from code) + slice API.
- `velora whitebox`: **full §4 default graph** wired — INGEST → ASSET
  MODEL → CODE MODEL → STATIC SCAN → DATAFLOW → HYPOTHESIZE (minimal:
  candidate generation from static leads) → TRIAGE → PLAN → VERIFY →
  EXPLOIT → FIX → RESCAN → VALIDATE → REPORT, with rule-6 n/a
  truncation (no target → EXPLOIT/VERIFY(live) n/a; zero findings →
  FIX/RESCAN/VALIDATE n/a). Shippability gate: `velora whitebox --source src`
  reaches REPORT on a fixture repo.
- **PLAN**: source-slice extraction → extended guidance; exploit when a
  target is given.
- **VALIDATE**: re-check stage (re-run repro/verify) before report.
- Tests: orchestrator e2e on fixture repo (monkeypatched LLM), gate
  parity with `scan`, slice extraction units, **grammar tests**
  (conflict/exit-code table for every §8.2 rule).

**Phase 2 — Active engine + blackbox**
- `active/client.py` (rate limit, timeouts, redirect/auth policy),
  `session.py`, `recon.py` (bounded crawl + robots/sitemap/JS/OpenAPI →
  asset graph), `surface.py` view, `probe.py` (enumeration +
  differential detection with ≥2 reproductions).
- `velora blackbox`: SCOPE → AUTH → RECON → ASSET DISCOVERY → SURFACE →
  ENUMERATION → HUNT → TRIAGE → VERIFY → EXPLOIT → CAPTURE → VALIDATE →
  REPORT.
- SERVICE MAPPING: **`partial`** in Phase 2 (recon-derived ports/services
  only — no active port scanning yet; capability report states the
  reduction), full network adapter in Phase 4. Default graph stays
  runnable per the shippability gate (§8.3).
- Tests: local vulnerable fixture app; dynamic findings carry evidence;
  safety rails (scope refusal, rate cap, non-destructive default).

**Phase 3 — Bughunt loop**
- HYPOTHESIZE engine (falsifiable-only claims), DEEPTHINK stage (reasoning
  budget over evidence chains), elimination memory, SEARCH gap analysis,
  novelty+impact triage rubric, budget enforcement (steps + wall-clock).
- Minimal INTEL (header/DNS fingerprint); OSINT adapter stubbed behind
  capability contract.
- Bounty-grade report template (title/class/impact/PoC/evidence).
- Tests: validator rejects vague hypotheses; loop terminates on budget,
  time, `--max-loop`, **and convergence** (no actionable gaps → REPORT);
  eliminated hypotheses not re-derived; report contains PoC steps.

**Phase 4 — Asset breadth + polish**
- API-operations adapter, SERVICE MAPPING (ports/services), INGEST
  extensions (IaC/deps), scripted AUTH login flows, OSINT minimal
  (cert/DNS), capture/validate hardening, TUI/ptui entries, docs updates,
  `doctor` readiness checks per mode.
- Capability matrix published per release — each adapter lands green with
  its own tests, never a big-bang.
- **Knowledge packs (design-gated, §6):** seed packs for the top web
  classes (guide + seed payloads) feeding HUNT/HYPOTHESIZE/EXPLOIT,
  provenance line in REPORT — starts only after the deferred §14 review;
  whitebox's symbolic methodology needs no packs.

---

## 11. Testing strategy

- **Fixture target app**: small vulnerable service (injection, IDOR, weak
  authz, race window) on a free port in-test — ground truth for
  blackbox/bughunt assertions and `--success-check`.
- **Effectiveness scoring (benchmark)**: fixtures ship gold expectations
  (known findings / flag); each run scores found / missed / false-alarm
  plus per-stage milestones (partial credit) — a success-rate number for
  comparing models and agent architectures, not just tool regressions.
- **Stage contract tests**: every stage either runs or refuses loudly;
  contract guards (`*_stays_*`) for behavior that must not drift.
- **Mode regression suites**: `tests/test_modes_*.py` in the style of the
  existing regression file (pinned behavior, pre/post proofs where a stage
  replaces an old path).
- **Grammar tests**: every §8.2 rule pinned to its exit code (table
  driven: input → code + message class).
- **Session tests**: kill mid-run → resume continues from the last
  committed stage; concurrent writer refused; secrets-at-rest audit
  (grep the session dir for auth values → zero hits).
- **Truncation tests**: `--source`-only whitebox reaches REPORT with
  EXPLOIT/RESCAN/VALIDATE `n/a` (exit 0); explicitly `--exploit` without
  a target exits 1; capability `unavailable` selection exits 2; missing
  `--source` (no session) exits 1 naming it.
- **Delegation tests**: stage flags accept exactly the underlying
  command's flag set (inheritance drift = test failure).
- **No-network-by-default**: LLM stages monkeypatched in unit tests; live
  model smokes opt-in (env-gated), as today.
- **Adversarial safety tests**: out-of-scope refusal, destructive-verb
  blocking, budget exhaustion, rate caps; **indirect-prompt-injection
  fixture** — a poisoned target page (injected instructions in HTML/JS/
  headers) must not alter agent goals, escalate privileges in-context, or
  widen egress beyond the SCOPE host allow-list.

---

## 12. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Breadth creep (too many asset classes at once) | adapter-per-phase + published capability matrix; unavailable stage = loud refusal |
| Three mode graphs fork the codebase | orchestrators contain *only* stage order; review rule: logic lives in engines/assets/active |
| Asset graph becomes a second source of truth | findings reference asset ids; graph is derived/rebuilt per run, archivable |
| Blackbox probing misused | explicit target (positional/`--target`), scope default same-origin, rate caps, non-destructive default |
| Dynamic false positives | differential delta reproducible ≥2× before a finding exists; fingerprint dedup |
| Bughunt burns budget on noise | falsifiable-hypothesis validator; elimination memory; per-stage sub-budgets |
| Contract drift breaks old commands | additive-only JSON; full suite green every phase |
| Secrets leak into session/findings/reports | references-not-values at rest; secrets-at-rest test (grep session dir); dry-run redaction |
| Default graphs rot during phased rollout | shippability gate (§8.3): every shipped mode's default graph reaches REPORT; capability levels reported in `--dry-run` |
| Payloads are LLM-only: unauditable, model-dependent quality | deferred knowledge packs (§6) are the structural fix; until they land, REPORT provenance stays honest (LLM-guided vs symbolic), and `--hypotheses FILE` already allows user-supplied seeds |
| Target-controlled bytes reach the LLM (indirect prompt injection → agent goal-hijack, exfiltration, forged "verifications") | untrusted-fencing treats page/tool output as data, never instructions (delimiters + lowest privilege, never system-role); egress pinned to the SCOPE host allow-list; secrets never enter prompts; adversarial IPI fixture in §11 |

---

## 13. Non-goals

- Removing or renaming any existing command or flag.
- Replacing the static pipeline or solver with dynamic testing.
- Autonomous action outside operator-declared target/scope.
- Day-one support for every asset class (wireless, full OSINT, cloud
  control-plane, etc.) — adapters land incrementally; the capability
  matrix is honest per release.
- Day-one protocol depth beyond plain HTTP enumeration (GraphQL,
  WebSocket, HTTP/2) — named as `partial` until an adapter covers them,
  never silently untested.
- A hosted/SaaS controller — local CLI first.

---

## 14. Open questions (decide Phases 1–2)

Decided already: command shape and stage grammar (§8.2, separate mode
subcommands, existing nine untouched); dual bughunt budgets (`--budget` +
`--time-budget`, either terminates); assets/findings/ledger live in the
session dir (§8.5).

Deferred past Phases 1–2 (decide before Phase 2 HUNT / Phase 3 loop):
knowledge packs for blackbox/bughunt — scope, sources (local packs vs
adapter tooling vs WSTG/CWE references), class-taxonomy shape, and
coverage scoring (§6 knowledge substrate). Whitebox already ships its
symbolic methodology; nothing waits on this.

Deferred past Phases 1–2 (decide before Phase 4 polish): finding
lifecycle across runs — states (open / fixed / false-positive /
suppressed), a suppressions file, and a baseline mode so CI gates on
*new* findings only; cross-run dedup exists only within one run today.

1. AUTH depth: paste-only MVP vs scripted logins — proposal: paste MVP
   accepting multiple cookie jars (≥2 roles — authz/IDOR checks need two
   sessions to compare), scripted flows in Phase 4.
2. PLAN slice size — proposal: ±20 lines + guards, token-capped,
   `--context-lines` tunable.
3. Session retention policy: keep-all vs N-most-recent vs explicit
   `velora sessions prune` — proposal: keep-all + prune in Phase 4.
4. `velora modes` capability display: static registry only, or live
   `doctor`-style probes — proposal: registry first, probe badge later.
5. `--progress json` event schema: field names frozen when first consumed
   by a real consumer (TUI/CI), not before.
6. Homonym hazard: `velora modes` vs existing `velora models` (LLM model
   management) — proposal: keep `modes`, cross-reference both in `--help`,
   revisit if support load shows confusion.
7. Cross-mode handoff (e.g. blackbox session surface fed into a bughunt
   loop) — proposal: not in scope until sessions prove stable; sessions
   are archivable so nothing blocks it later.
