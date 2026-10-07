# Velora Architecture

How Velora is put together: what each layer does, what it may be trusted to
do, and where the seams between layers are. This document is derived from
the code itself rather than from intent — every deviation the audit
uncovered is either corrected here or reclassified as a deliberate design
trade-off with the reason recorded. Each such item is pinned by a
regression test in `tests/test_bugfix_regressions.py`, so the behaviour
described below cannot silently drift.

## 1. Two cores, one loop

Velora is a *neuro-symbolic* system: a **symbolic core** (parser + SMT encoding
+ Z3) and a **language-model layer** (detect → triage → exploit → fix)
connected by a single CLI over a shared findings file.

```
                    ┌───────────────────────────────────────────────┐
   source files ───▶│  velora scan                                 │
                    │  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │
                    │  │ frontends │→ │   SIL    │→ │ translator  │  │
                    │  │ py/java/js│  │ (proced.)│  │ (checks)    │  │
                    │  │ c / c#    │  └──────────┘  └──────┬──────┘  │
                    │  └──────────┘        literal scan ───┤         │
                    │                       C memory  ─────┤         │
                    │                       C# interproc ───┤         │
                    │  ┌──────────────────────────────────▼───────┐  │
                    │  │ _process_check → (optional) _verify_check│ │
                    │  │ confidence tiering: symbolic | llm        │ │
                    │  └──────────────────┬───────────────────────┘  │
                    └─────────────────────┼──────────────────────────┘
                                          ▼
                                 findings.json  ──▶ velora report
                                          │
              ┌───────────────────────────┼──────────────────────────┐
              ▼                           ▼                          ▼
      velora exploit               velora fix                 velora tui/ptui
   (agent loop + tools)     (LLM patch + re-scan)          (curses/line views)
              │                           │
              └──────────▶ trace / patched sources ──▶ re-scan ──▶ report
```

The **solver** (`velora solve / check / repl`) is independent of the scan loop
and never touches the LLM layer.

## 2. Why Velora — what sets it apart

Security tooling in this space falls into four shapes, each leaving a
different gap:

| Category | Strength | Gap it leaves |
|---|---|---|
| Pattern / dataflow linters | fast, cheap, CI-friendly | shallow reasoning: no heap-shape analysis, no interprocedural state, no proof that a sink is reachable — alerts arrive unranked and unproven |
| Classic rule-pack SAST | broad rule coverage | opaque confidence, weak on polyglot repos, closed engines, and it usually stops at "here is a CSV" |
| Pure-LLM "AI hunter" agents | flexible, fluent prose | non-deterministic: findings cannot be reproduced, confidence is a guess, tool use is often unconstrained, and the report reads well even when wrong |
| Exploit / report generators | nice artifacts | single stage: nothing verified feeds them, success is self-graded, and no re-scan proves a fix worked |

Velora is deliberately built on the seam between the deterministic and the
generative. What that buys you, concretely:

1. **A symbolic core that decides; an LLM that only proposes.** The scan
   pipeline (frontends → SIL → analyzers → optional Z3 verification) is
   sampling-free: the same input yields the same findings, run after run.
   LLM tiers (`detect` / `triage`) are *additive* — every finding carries
   provenance (`symbolic` vs `llm`), so model output can never masquerade as
   a deterministically derived result. Pure-LLM agents cannot offer this;
   rule packs cannot offer the generative half.

2. **A separation-logic prover inside the scanner.** Memory-safety questions
   for C/C++ are answered as entailment checks against the heap-as-array Z3
   encoding, backed by inductive predicates, goal-directed folding, and
   lemmas (*see The entailment checker / Predicates*). Pattern matchers
   cannot express "does this free invalidate the shape"; language models
   cannot *prove* it — they can only assert it. The same solver ships as
   `velora solve / check / repl`, usable offline with no model at all.

3. **Honest, evidence-weighted confidence.** Confidence is derived from
   evidence, never stamped `1.0` without a solver witness; the verification
   gate actually runs. The exploit agent's guidance header re-states tiers as
   *"sound"* vs *"heuristic"* leads, and reports carry the provenance of
   every row — so triage can prioritize instead of guessing which alerts are
   real. Most scanners publish a single unlabeled score; most LLM agents
   publish none at all.

4. **One findings file, the whole lifecycle.** `scan → report → exploit →
   fix → re-scan` all communicate through one findings JSON — the exploit
   stage consumes exactly what the scan stage proved, `velora report` turns
   it into markdown, and SARIF export drops into an existing pipeline. The
   audit-hardened exit codes (`0/1/2/3`) are machine-readable for CI gates.
   Competing tools are typically strong at one arrow of that chain.

5. **Exploitation graded by an oracle, not by the model.** The exploit agent
   loop terminates on the operator's `--success-check` (a shell oracle) or a
   guarded final `VERIFIED:` claim — not on the model's own opinion that it
   "probably worked" — under a step budget, stall nudges, and a transport
   failure budget. You get reproducible evidence, or an honest failure.

6. **Fixes must re-earn their status.** `velora fix` applies an LLM patch
   only under realpath containment against `--source`, then re-scans; a fix
   is reported as verified only if the re-scan agrees. The loop closes with
   the same evidence discipline as detection.

7. **Agent plumbing hardened against hostile input — by construction.**
   Findings fields are fenced as untrusted data before reaching prompts;
   `read_file`/`grep` are repo-confined; the shell tool is operator-launched
   and target-host allow-listed; the local bridge speaks bearer-token auth
   with Host/Origin checks; `--stop` verifies process identity before any
   kill (*see Trust boundaries*). Scanned code and model output are treated
   as attacker-influenced — the usual failure mode of "AI pentester" tools
   is prompt injection through the very files being scanned.

8. **Your models, your infrastructure, no lock-in.** Any OpenAI-compatible
   endpoint (`--base-url` / `VELORA_LLM_*` / `--model` / config file), a
   zero-key fallback through the local opencode bridge (`velora
   serve-bridge`), and `velora doctor` / `setup` to diagnose it. The
   symbolic side needs no network, no API key, and collects no telemetry.

9. **Operational honesty as a feature.** Documented exit codes, clean stderr
   instead of tracebacks, an unconditional notice when `--ai` is requested
   but unconfigured, docs kept in sync with the code, and a suite of **2647 pytest
   cases + 18 Node bridge tests** with CI installing from `pyproject.toml`
   only. Claims in the docs are pinned by regression tests rather than
   asserted.

**When *not* to reach for Velora:** style linting, a quick syntax check, or
brainstorming prose — a linter or a bare chat model does that faster. Reach
for Velora when you need ranked findings with provenance you can audit,
reproducible symbolic results, agent-driven exploitation backed by
evidence, and patches that are verified rather than promised.

## 3. Repository map

```
velora/
├── core/           # AST (ast.py) + string parser (parser.py): "P |- Q" grammar
├── encoding/       # Z3 encoder (encoder.py) + spatial helpers (_spatial.py,
│                   #   _spatial_core.py): heap-as-array, domain, disjointness, rank
├── checking/       # EntailmentChecker (checker.py), heuristics (_ls_heuristics),
│                   #   _checker_core.py: fast paths → lemmas → folding → Z3
├── analysis/       # footprint / unification / predicate matching
├── heap/           # heap graph + fold proposal generation
├── folding/        # goal-directed & blind predicate synthesis, fold verification
├── lemmas/         # proven predicate transformations (matcher + substitution)
├── predicates/     # inductive predicate registry (ls, list, tree, dll, …)
├── arithmetic/     # arithmetic constraint check + synthesis
├── preprocessing/  # equality preprocessing
├── utils/          # proof state, satisfiability (satisfiability.py), frame rule
├── sil/            # scanner half:
│   ├── frontends/    # python, java, javascript, c, csharp → SIL Program
│   ├── specs/        # per-language sink/source specifications
│   ├── analyzers/    # memory safety, interprocedural taint, semantic patterns
│   ├── translator.py # SIL Program → VulnerabilityCheck list (VulnType enum)
│   ├── scanner.py    # VeloraScanner: pipeline, tiers, verification, output models
│   ├── llm_client.py # OpenAI-style transport, retries, structured output
│   ├── llm_agent.py  # shared agent loop (run_agent), investigation tools
│   ├── llm_detect.py / llm_triage.py / llm_exploit.py / llm_fix.py
│   ├── model_config.py, opencode_bridge.py   # model precedence + zero-key fallback
│   └── cli.py        # `velora scan` implementation (delegated from velora/cli.py)
├── tui/            # curses TUI (--curses, classic view)
├── ptui/           # prompt-toolkit + rich line REPL view (default TTY view)
├── _bridge/        # Node bridge (server.js): opencode → OpenAI-compatible API
├── cli.py          # root dispatcher: scan exploit report fix solve check parse
│                   #   repl models serve-bridge doctor setup
├── bridge_cli.py / doctor_cli.py / models_cli.py / setup_cli.py
└── __main__.py     # python -m velora
```

Test suite: `tests/` — 2647 tests, ~69% line coverage (gaps: see the audit
report; SL-COMP collection files currently collect 0 tests).

## 4. The entailment checker (solve path)

```
"P |- Q" string
   │
   ▼
core/parser.py ──▶ AST (core/ast.py)
   │
   ▼
checking/checker.py :: check_entailment()
   ├─ 1. syntactic reflexivity fast path            (<1 ms)
   ├─ 2. heuristics (checking/heuristics.py,
   │      _ls_heuristics.py): frame-shaped, list-shaped…
   │      • unsat-antecedent short-circuit (ex falso)  ← BUG-002 (fixed)
   ├─ 3. lemma application (lemmas/): ls_transitivity, ls_cons, ls_empty …
   ├─ 4. goal-directed folding (folding/goal_directed.py): synthesise
   │      predicates in the antecedent to match the consequent
   ├─ 5. bounded predicate unfolding (max_unfold_depth, adaptive)
   ├─ 6. encoding/encoder.py: AST → Z3
   │      heap : Loc → Val array + explicit domain set
   │      SepConj: pairwise domain disjointness
   │      rank/acyclicity constraints (single-field)   ← BUG-001 (fixed)
   │      wand: eliminate_wand on BOTH sides           ← wand-cons soundness
   └─ 7. Z3 check: valid ⇔ (P ∧ ¬Q) unsat
```

**Semantics switch.** `EntailmentChecker.affine_semantics` (default `True`)
only toggles two `check_cyclic_proof_soundness` pre-checks; the core pipeline
implements **exact (SL-COMP-style) footprint discipline in both modes** —
`P * Q |- P` and `P |- emp` are INVALID for non-empty P (pinned by the
Nov 2025 tests in `tests/test_lists.py`, `tests/test_trees.py` and the
SL-COMP suites; the audit's affine-expectation report was reclassified as a
design trade-off — BUG-003).

**Trust today:** individual entailments reaching the Z3 stage — antecedent
satisfiability is now decided uniformly regardless of consequent shape
(BUG-001 fixed) and `&` arms share one heap instead of demanding disjoint
domains (BUG-002 fixed), so cyclic and `&`-aliased antecedents behave
consistently. **Do not trust:** wand-consequent elimination on internal
(string-parser-unreachable) paths — a separate soundness item that remains
open (`docs/api.md` DOC-004 notes the CLI does not parse `-*`).

## 5. Heap-as-array encoding

Per Piskac–Wies–Zufferey (2013), as documented in `docs/api.md`:

- `heap : Loc → Val` Z3 array; allocation tracked by a companion domain set,
  so `x |-> v` asserts `x ∈ domain ∧ heap[x] = v`.
- `P * Q` encodes both sides and asserts the domains are disjoint.
- `emp` asserts the domain is empty.
- Values are Z3 ints/bools; `nil` is a distinguished constant.
- Optional `rank : Loc → Int` constraints prune cyclic models for
  single-field structures (`use_acyclicity_constraints`).

## 6. Predicates, folding, lemmas

Three deliberately separate mechanisms:

| Mechanism | Direction | Code |
|---|---|---|
| **Unfolding** | predicate → heap clauses | `predicates/registry`, bounded depth |
| **Folding** | heap clauses → predicate (synthesis toward the goal) | `folding/goal_directed.py` |
| **Lemmas** | proven predicate ⇒ predicate facts | `lemmas/` (matching + substitution) |

Lemmas never synthesise; folding never pattern-matches proven facts. New
"proven transformations" go in `lemmas/`, new "shape synthesis" in `folding/`.

## 7. The scanner (scan path)

```
velora scan PATH
   │  velora/cli.py::cmd_scan → sil/cli.py::cmd_scan
   ▼
VeloraScanner.scan_directory / scan_file          (sil/scanner.py)
   │ per file: read (utf-8/utf-8-sig, errors=replace)  ← BUG-006 (fixed)
   ▼
frontend.translate(src) → SIL Program             (sil/frontends/)
   │ procedures, taint sources/sinks from sil/specs/*
   ▼
SILTranslator.translate_program() → [VulnerabilityCheck]   (sil/translator.py)
   ▼
_process_check(check)
   ├─ path-sensitive / interprocedural analyzers   (sil/analyzers/)
   ├─ _verify_check(check) → BugReport            ← BUG-004 (fixed: enum names)
   │     taint branch: evidence-weighted confidence ← BUG-005 (fixed: no 1.0 by fiat)
   └─ severity + confidence tiering
   ▼
extra detectors: _scan_literals (hardcoded secrets),
   _analyze_memory_safety (C/C++, SL-based),
   _analyze_csharp_interprocedural
   ▼
optional LLM tiers (only with --ai):
   _apply_llm_detect  (llm_detect.py, provenance "llm")
   _apply_llm_triage  (llm_triage.py, demote/confirm)
   ▼
dedup → filter → ScanResult (json / sarif / text / -o)
```

**Finding tiers.** Every finding carries provenance: `symbolic` (front-end
taint + verification attempt) vs. `llm` (model detection). The exploit layer's
guidance header re-states this as "sound" vs "heuristic" leads
(`llm_exploit.py::_format_guidance`). The tier labels are honest: the
verification step runs (BUG-004 fixed — its crash silently disabled it) and
confidence is evidence-weighted rather than stamped `1.0` by fiat (BUG-005
fixed), so `symbolic` means "symbolically derived and solver-adjudicated".

## 8. LLM layer

- **Transport** (`llm_client.py`): OpenAI-style `POST /chat/completions`;
  retries with backoff, timeouts (`VELORA_LLM_TIMEOUT`=120 s plain,
  `VELORA_LLM_AGENT_TIMEOUT`=300 s agentic), structured-output modes
  (`json_object` / `json_schema`), fail-loud `LLMUnavailableError`.
- **Shared agent loop** (`llm_agent.py::run_agent`): message buffer → model →
  tool calls → results, with two termination hooks:
  - *self-terminating* (detect/triage): `finalize(content)` when the model
    stops calling tools;
  - *oracle-terminating* (exploit): `check_done()` — the shell oracle
    (`--success-check`) is authoritative, or a guarded final
    `VERIFIED: <evidence>` claim (`_self_verified`) when no oracle exists.
  - transport-failure budget (`MAX_TRANSPORT_FAILURES=2`), stall nudges,
    progress-note compaction (`_compact_messages`).
- **Tools**: investigation `read_file` / `grep` (repo-confined via
  `_safe_path`) for detect/triage; `run` (shell, `shell=True`, timeout +
  target-host allow-list derived from `--target`) for exploit — trust analysis
  in `docs/agent.md`.
- **Model precedence** (`model_config.py`): `--model` → `VELORA_LLM_*` →
  `~/.config/velora/config.json` → opencode fallback, which walks
  `opencode.json` up from the **cwd** — skipped entirely when
  `OPENCODE_CONFIG` is set, and loudly announced otherwise (BUG-012 fixed).
- **Bridge** (`_bridge/server.js`, port 8399): OpenAI-compatible façade over
  opencode; bearer-token authenticated with Host/Origin checks (BUG-013
  fixed; tokenless only when run raw without a configured token).

See [`docs/agent.md`](agent.md) for prompts, termination rules, and failure
handling.

## 9. CLI surface

| Command | Entry | Notes |
|---|---|---|
| `scan` | `cli.py::cmd_scan` → `sil/cli.py` | delegating wrapper; TUI branch first |
| `exploit` | `cli.py::cmd_exploit` | findings → guidance → agent loop |
| `fix` | `cli.py::cmd_fix` | LLM patch → apply → re-scan verify (realpath containment vs `--source`, BUG-007 fixed) |
| `report` | `cli.py::cmd_report` | findings JSON → markdown |
| `solve/check/parse/repl` | `cli.py` | solver front-ends, no LLM |
| `models` | `models_cli.py` / `models_tui.py` | picker + `use` |
| `serve-bridge` | `bridge_cli.py` | Node bridge lifecycle (PID file + cmdline identity check, BUG-015 fixed; per-session bearer token, BUG-013) |
| `doctor` / `setup` | `doctor_cli.py` / `setup_cli.py` | zero-key diagnosis/bootstrap |

Exit codes *as implemented*: `0` success · `1` findings/invalid/tool error ·
`2` LLM unreachable (clean `error: ...`, no traceback — `main()` maps
`LLMUnavailableError`) *or* argparse usage errors · `3` scan I/O errors
(unreadable files, after the findings gate).

The audit's dead/inert flags (`--unfold-depth`, `--diff`, `--repo-scale`) are
now wired (BUG-016): `--unfold-depth` reaches `predicate_registry.max_unfold_depth`,
`--in-place --diff` writes and prints the patch, and `--repo-scale` is registered
on the installed `velora scan` parser.

## 10. Interactive views

- **Line view (default on TTY)**: prompt-toolkit + rich (`velora/ptui/`),
  both declared as core dependencies (BUG-021 fixed).
- **Curses view**: `velora/tui/` (`--curses`).
- **REPL**: `velora repl` — parser-level, prints verdicts, no LLM.

## 11. Trust boundaries

```
                    ┌─ untrusted ─────────────────────────────┐
                    │ scanned source code (any language)      │
                    │ findings JSON (attacker-influenceable)  │
                    │ target HTTP responses (exploit)         │
                    │ repo-local opencode.json (cwd walk-up)  │
                    └───────────────┬─────────────────────────┘
                                    │  #1 findings fields fenced as untrusted (BUG-008)
                                    ▼
   ┌─ semi-trusted ─┐    ┌─ trusted ───────────────────────────────┐
   │ LLM responses  │───▶│ velora code, bridge endpoint, Z3,       │
   │ (model output  │    │ filesystem paths it chooses to write    │
   │  untrusted)    │    │ (containment-checked, BUG-007 fixed)   │
   └────────────────┘    └─────────────────────────────────────────┘
```

Rules the code must enforce (enforced as noted):

1. Model output is data: parsed defensively (non-dict tool args → `{}`,
   malformed findings → clean errors, malformed response shapes → retried
   `LLMUnavailableError` / `None`; BUG-009/010/011/020 fixed).
2. Paths from findings/config are validated against a root before I/O
   (realpath containment for `fix --in-place`, authoritative
   `OPENCODE_CONFIG` for the provider fallback; BUG-007/012 fixed).
3. The bridge authenticates: per-session bearer token, loopback Host check,
   Origin check (BUG-013 fixed); `--stop` verifies cmdline identity before
   any `os.kill` (BUG-015 fixed).
4. Nothing scanned or model-generated reaches a shell without an explicit
   operator action (`exploit --target`, `fix --in-place`); the model's own
   `run` tool is the deliberate exception — operator-launched, and
   target-host allow-listed with findings fenced as untrusted data
   (BUG-008 mitigated).

## 12. Timeouts & budgets

| Layer | Knob | Default |
|---|---|---|
| Z3 query | `EntailmentChecker(timeout=…)` | 5000 ms (benchmarks 10000) |
| Predicate unfolding | `max_unfold_depth` | 3 (adaptive) |
| Plain LLM call | `VELORA_LLM_TIMEOUT` | 120 s |
| Agent round-trip | `VELORA_LLM_AGENT_TIMEOUT` | 300 s (wall ≥ 600 s/attempt) |
| Tool execution | `--exec-timeout` | 120 s |
| Exploit budget | `--max-steps` | 40 |

## 13. Testing architecture

- Unit tests per module (`tests/test_*.py`, 2647 tests, ~69% line coverage).
- SL-COMP collection files exist for divisions but currently collect **0**
  tests (audit gap — wire or delete).
- CI (`.github/workflows/tests.yml`): pytest on push/PR plus a
  `pyproject-install` job (Python 3.10, installs `.[all,dev]` from
  `pyproject.toml` only — BUG-021 fixed); `permissions:` /
  `timeout-minutes:` still absent (open gap).
- Node bridge tests: `cd velora/_bridge && node --test server.test.js` (18/18).

## 14. Extension points

| Want to… | Touch |
|---|---|
| new language | `sil/frontends/<lang>_frontend.py` + `sil/specs/<lang>_specs.py` |
| new sink taxonomy | `sil/translator.py` (`VulnType`, CWE map) + specs |
| new detection pass | `sil/analyzers/` + hook in `VeloraScanner.scan` |
| new entailment heuristic | `checking/heuristics.py` (must be semantics-aware — exact footprint discipline is the contract, BUG-003) |
| new lemma | `lemmas/` (proven transformation only — never synthesis) |
| new fold pattern | `heap/_fold_proposals.py` + `folding/` |
| new model endpoint | OpenAI-compatible only; `--base-url` / `VELORA_LLM_BASE_URL` |

## 15. Known soundness caveats (pointer)

This document's §4 and §7 flag each trust caveat inline. Current status
(regression tests in
`tests/test_bugfix_regressions.py`):

- BUG-001/002 — **fixed**: antecedent satisfiability decided uniformly
  (acyclicity constraints no longer depend on the consequent; `&` arms share
  one heap, disjointness only for `*`).
- BUG-003 — **reclassified** as a design trade-off: exact footprint
  discipline is the contract in both modes; the docstring now says so.
- BUG-004/005 — **fixed**: the verification step runs, confidence is
  evidence-weighted (no `1.0` stamps without a solver witness).
- BUG-012/013/015 — **fixed**: authoritative `OPENCODE_CONFIG`, bridge
  bearer + Host/Origin checks, PID-identity stop.
- **Still open:** wand-consequent elimination on internal
  (string-parser-unreachable) paths can produce false VALIDs — tracked as a
  separate item; the CLI does not parse `-*` (`docs/api.md` DOC-004).

## 16. Design references

- Reynolds, O'Hearn — separation logic (spatial entailment).
- Piskac, Wies, Zufferey — *Guiding Dynamic Symbolic Execution toward layout
  errors* / heap-as-array SMT encoding (the encoding used here; see
  `docs/api.md` "Symbolic Core" section for the in-repo comparison).
- Cyclist — cyclic proof techniques (adapted as goal-directed folding, not
  literal cyclic proofs).
- SL-COMP / SMT-LIB benchmark suites — evaluation harness (`benchmarks/`).

## 17. Glossary

| Term | Meaning |
|---|---|
| **SIL** | Velora's scan-side intermediate language (procedures, checks) |
| **Finding / check** | One candidate vulnerability (`VulnerabilityCheck` → `Vulnerability`) |
| **Provenance** | `symbolic` vs `llm` tier tag on a finding |
| **Affine semantics** | Intuitionistic reading where garbage may be dropped (`P * Q |- P` holds). Velora's `affine_semantics` flag does **not** grant this: the pipeline is exact in both modes; the flag only skips two footprint pre-checks (see BUG-003) |
| **Fold / unfold** | Synthesise / expand inductive predicates |
| **Bridge** | Local Node service exposing opencode as an OpenAI-compatible API |
| **Guidance** | Findings rendered into the exploit agent's system prompt |

