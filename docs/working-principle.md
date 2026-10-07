# Velora Working Principle

How Velora actually works, end to end: every phase, every artifact, and how
data flows between them. This is the *operational* companion to
[`architecture.md`](architecture.md) (module layout, trust boundaries) — read
that one for "where things live", this one for "what happens when you run a
command".

---

## 1. The one-paragraph principle

Velora is a **neuro-symbolic offensive-security pipeline**. A deterministic
**symbolic core** — language frontends, a separation-logic intermediate
language, an SMT/Z3 verification gate, and a full entailment prover — decides
what is *proven*. A **language-model layer** — detect → triage → exploit →
fix — supplies *hypotheses and actions*, never ground truth. The two halves
talk through exactly one contract: a **findings JSON** file. Every stage
either feeds that contract, consumes it, or verifies against it, and every
claim in a report is tagged with how it was produced.

```
   ┌─────────────────────────────── DETERMINISTIC ───────────────────────────────┐
   │                                                                             │
   │  source ──▶ scan (frontends → SIL → checks → Z3 verify) ──▶ findings.json   │
   │                 │                                    │                     │
   │                 │  solver: solve/check/parse/repl     │                     │
   │                 └──▶ entailment prover (offline)      │                     │
   │                                                       ▼                     │
   │                    report (findings → markdown/SARIF) │                     │
   └───────────────────────────────────────────────────────┼─────────────────────┘
                                                           │ contract
   ┌──────────────────────── GENERATIVE (opt-in, --ai) ────┼─────────────────────┐
   │                                                       ▼                     │
   │   detect/triage (provenance "llm" findings) ◀── findings.json ──▶ exploit   │
   │                                                                     │       │
   │                              fix (LLM patch ──▶ apply ──▶ re-scan ──┘)      │
   │                                        │                                    │
   └────────────────────────────────────────┴──▶ verified findings / patched src ┘
```

---

## 2. The pipeline at a glance

| # | Phase | Command | Reads | Writes | Exit contract |
|---|---|---|---|---|---|
| 0 | Dispatch | `velora <cmd>` | argv, env, config | — | maps errors to `0/1/2/3` |
| 1 | Detect | `velora scan` | source tree | findings (json/sarif/text) | `0` clean · `1` gated findings · `2` LLM unreachable · `3` I/O errors |
| 2 | Report | `velora report` | findings JSON (+ trace) | markdown (stdout / file / preview) | `0/1` |
| 3 | Exploit | `velora exploit` | findings (`--guidance`), target URL | summary (+ trace JSON) | `0` solved · `1` not |
| 4 | Fix | `velora fix` | findings (`--guidance`), source | patched sources / diff (+ verify verdicts) | `0` applied · `1` none |
| 5 | Prove | `velora solve/check/parse/repl` | entailment formula | verdict (text/json) | `0` valid · `1` invalid/error |
| — | Support | `models` · `doctor` · `setup` · `serve-bridge` · TUIs | env/config/bridge state | model pick, diagnostics | `0/1` |

The **solver** (phase 5) is deliberately independent: it never imports or
calls the LLM layer, and works with no network and no API key.

---

## 3. Phase 0 — Invocation & dispatch (`velora/cli.py::main`)

1. **Argparse subcommand routing.** `main(argv)` builds the root parser
   (`scan, exploit, report, fix, solve, check, parse, repl, models,
   serve-bridge, doctor, setup`) and dispatches to `cmd_*`. Argparse usage
   errors exit **2**.
2. **Model override (uniform knob).** `--model` beats `VELORA_LLM_MODEL` for
   every layer — scan's AI tiers, exploit, and fix all read the same
   precedence chain (see §8).
3. **TUI branch.** On a TTY, `scan`/`exploit` can enter the interactive view
   (`ptui/` line view by default, `--curses` for the curses view) before the
   batch pipeline runs; `--no-tui`/redirect bypasses it.
4. **Error mapping (the exit-code contract).**
   - `LLMUnavailableError` anywhere → clean `error: …` on stderr → **exit 2**
     (never a traceback, never a misleading "0 findings").
   - Findings gate (`--fail-on`) → **exit 1**; evaluated *before* I/O errors.
   - Scan I/O errors (unreadable files, decode failures) → stderr
     `Scan error: …` → **exit 3**.
   - KeyboardInterrupt → **130**. Anything else unexpected → traceback + 1.
5. **The `--ai` honesty note.** If `--ai` / `--llm-detect` / `--llm-triage`
   is requested but no endpoint/model is configured, `cmd_scan` prints an
   unconditional stderr note (`AI layer requested … running without the LLM
   tier`) *before* scanning — stdout (e.g., JSON) stays clean.

---

## 4. Phase 1 — Scan: from source to findings (`velora scan`)

Entry: `velora/cli.py::cmd_scan` → `velora/sil/cli.py::cmd_scan` →
`VeloraScanner` (`velora/sil/scanner.py`). The scanner is the heart of the
symbolic side.

### 4.1 Stage-by-stage data flow

```
target path
   │ ① discovery: --pattern glob, default excludes (overridable --no-default-excludes)
   ▼
per file ──▶ ② read: utf-8 / utf-8-sig, errors=replace; failure recorded in
   │            ScanResult.errors, scan continues (no crash)
   ▼
③ frontend.translate(src) ──▶ SIL Program          (sil/frontends/: python, java,
   │      procedures + calls + returns                javascript, c, csharp)
   │      taint sources/sinks from sil/specs/*.py     (per-language sink tables)
   ▼
④ SILTranslator.translate_program() ──▶ [VulnerabilityCheck]   (sil/translator.py)
   │      each check = a *formula* (the vulnerability condition in Velora's
   │      logic language) + metadata: vuln_type, sink location, tainted var,
   │      source location, data-flow path, per-edge branch conditions
   ▼
⑤ _process_check(check) for each check
   │      ├─ path-sensitive / interprocedural analyzers   (sil/analyzers/)
   │      ├─ _verify_check(check) ──▶ BugReport           ← the Z3 gate:
   │      │      formula evaluated against source facts; only a solver-backed
   │      │      witness licenses top confidence (never 1.0 by fiat)
   │      └─ severity + confidence tiering → Vulnerability (provenance: symbolic)
   ▼
⑥ extra detectors (independent of the check pipeline)
   │      _scan_literals            hardcoded secrets / credentials
   │      _analyze_memory_safety    C/C++ frees/UAF/double-free via the SL solver
   │      _analyze_csharp_interproc C# interprocedural pass
   ▼
⑦ optional LLM tiers (only when configured + --ai)
   │      _apply_llm_detect   model proposes new findings → provenance "llm"
   │      _apply_llm_triage   model confirms/demotes existing findings
   │      (never re-tags a finding as symbolic; the tier label is sticky)
   ▼
⑧ dedup — three passes (_deduplicate_vulnerabilities):
   │      same-flow repeats → 5-line window collisions → best-per-file/CWE;
   │      IDOR findings kept one per (endpoint, selector)
   ▼
⑨ severity floor: filter_min_severity(results, --min-severity) applied ONCE,
   │      before any formatter → text / json / sarif all expose the same set,
   │      and the exit gate matches the artifact
   ▼
⑩ emit: stdout or -o (single open('w') per run — a rerun replaces, never appends)
   ▼
⑪ gate: should_fail(--fail-on) → 1 · scan_errors → 3 · else 0
        (LLM unreachable with --ai aborted earlier with 2)
```

### 4.2 The data structures at each step

| Stage | Type | Key fields |
|---|---|---|
| ③ | `SIL Program` | procedures, calls, source/sink annotations |
| ④ | `VulnerabilityCheck` | `formula`, `vuln_type`, `location`, `description`, `tainted_var`, `source_var`, `data_flow_path`, branch conditions, `procedure_name` |
| ⑤ | `BugReport` | solver verdict for one check (the *witness*) |
| ⑤ | `Vulnerability` | `type`, `severity`, `location`, `line`, `column`, `description`, `procedure`, `source_var`, `sink_type`, `data_flow[]`, `witness`, `confidence`, `cwe_id` |
| ⑩ | `ScanResult` | `filename`, `vulnerabilities[]`, `errors[]`, `warnings[]`, `scan_time_ms`, `lines_scanned`, `procedures_analyzed`, `summary{total,critical,high}` |

**findings.json shape** (what every downstream phase consumes):

```json
{
  "filename": "app.py",
  "vulnerabilities": [
    { "type": "sqli", "severity": "high", "location": "app.py", "line": 42,
      "column": 8, "description": "…", "procedure": "handler",
      "source_var": "uid", "data_flow": ["uid", "query"],
      "witness": "…", "confidence": 0.85, "cwe_id": "CWE-89" }
  ],
  "errors": [], "warnings": [],
  "scan_time_ms": 123.4, "lines_scanned": 812, "procedures_analyzed": 37,
  "summary": { "total": 1, "critical": 0, "high": 1 }
}
```

`format_json_result` concatenates per-file `ScanResult`s;
`format_sarif_result` maps severities to SARIF levels; `format_text_result`
renders the human report. All three see the **same post-floor finding set**.

### 4.3 Provenance and confidence — the honesty rules

- `symbolic` findings: derived from frontends + analyzers and passed through
  the verification gate. Confidence is **evidence-weighted** — a solver
  witness, a confirmed taint path, an unproven heuristic each license
  different ceilings. Confidence `1.0` is reserved for a solver witness.
- `llm` findings: proposed by the model tier; `source_var`/`procedure` hold
  tier *labels*, not real endpoint/param values (downstream guidance code
  detects this and keeps provenance honest).
- The exploit guidance header re-states the split as **sound** vs
  **heuristic** leads, so the agent — and the human — know what is proven.

---

## 5. Phase 2 — Report (`velora report`)

`velora/cli.py::cmd_report` → `velora/tui/report.py`:

1. **Read** one or more findings JSON files (`--findings`, repeatable; each
   may contain one file's list) → flat list of finding dicts.
2. **Optionally read** an exploit trace (`--trace-out` written by phase 3) —
   its `model` and `summary` become report metadata.
3. **Build** markdown via `build_report(findings, trace, meta{subject, model})`:
   summary counts by severity, per-finding sections (CWE, location, data
   flow, confidence, provenance), exploit evidence section if a trace is
   attached.
4. **Emit**: `--output file.md`, or — on a TTY — an interactive preview
   (`preview_markdown`) offering to save; otherwise plain stdout for piping.

Reading/writing failures are stderr + exit 1; the report itself never
alters findings — it is a pure projection of the contract.

---

## 6. Phase 3 — Exploit (`velora exploit`)

The agentic phase: a bounded, tool-using LLM loop against a live target,
**graded by an oracle**.

### 6.1 Setup

1. **Config gate**: `VELORA_LLM_BASE_URL` + `VELORA_LLM_MODEL` (or
   `--model`) required — otherwise stderr + exit 1.
2. **Guidance ingestion** (`--guidance findings.json | -` for stdin):
   - `_load_findings` parses defensively (malformed JSON → clean error,
     entries that aren't dicts are skipped — findings are *data*, not code).
   - `_select_findings` picks the actionable subset.
   - `guidance_from_finding(f)` maps each finding to a lead:

   | Lead field | From | Notes |
   |---|---|---|
   | `cwe`, `type`, `sink`, `location`, `approach` | finding as-is | |
   | `endpoint`, `param` | `procedure`, `source_var` | **only for symbolic leads** — empty for LLM leads |
   | `taint_path` | `data_flow[]` joined with `->` | the formal path |
   | `provenance` | `symbolic` / `llm` | computed, never trusted from input |

   The envelope carries `provenance: symbolic` iff any lead is symbolic.
   Guidance is rendered into the system prompt via `_format_guidance` with
   delimiter fences — untrusted content, quoted, never instruction.
3. **Goal**: `--goal`, or the default compromise objective (read a protected
   secret / execute a command / modify state — *with observed output*).
4. **Success oracle** (`--success-check "cmd"`): a shell command whose exit
   0 means *solved*; its stdout/stderr is captured and surfaced as evidence
   (`[success-check] …`) when it passes.
5. **Execution tool**: `local_exec_tool(timeout, allow_hosts=target_hosts(--target))`
   — remote commands are restricted to the target's origin host, so a
   crafted findings file cannot steer the agent's shell elsewhere.

### 6.2 The loop (`exploit_agentic` → `run_agent`)

```
messages = [system(+guidance) + task prompt]
repeat up to --max-steps (default 40):
   ▶ LLM call (agent timeout 300 s; structured streaming via llm_client)
        │
        ├─ tool_calls? ─▶ execute (run / read_file / grep, outputs truncated
        │                  to max_tool_output) ─▶ append results ─▶ continue
        │
        └─ no tool calls ─▶ finalize
   ▶ after every action: is_solved()?
        ├─ --success-check → shell oracle decides (authoritative)
        └─ no oracle → guarded _self_verified: a final
             "VERIFIED: <observed evidence>" claim is accepted only if it
             quotes real observed output — self-assessment alone fails
   protections along the way:
        • transport failure budget (MAX_TRANSPORT_FAILURES = 2) → give up cleanly
        • stall nudge after repeated no-tool rounds; final nudge before last step
        • progress-note compaction (_compact_messages) so long runs fit context
```

### 6.3 Output

- Summary: `target, solved, steps, reason, guided, provenance`.
- `--format json` prints it; text prints `✓ EXPLOITED` / `✗ NOT EXPLOITED`.
- `--trace-out file.json` writes `{model, summary, transcript[]}` — the
  transcript feeds `velora report` as exploit evidence.
- Exit **0** iff `solved`, else **1**.

---

## 7. Phase 4 — Fix (`velora fix`)

A closed verification loop, not a patch suggestions generator.

```
findings.json (--guidance)
   │  _load_findings → non-empty (else exit 1)
   ▼
group by file: _resolve_finding_file(location, --source)
   │  SECURITY: realpath containment — candidates tried in order:
   │    (1) location joined onto --source root (relative → root, not CWD)
   │    (2) basename under the root
   │    (3) location as given — accepted only if inside the root;
   │        outside → stderr warning, finding skipped (never written to)
   ▼
per file: original = read_text()
   │  for each finding: generate_fix(f, patched, config)   ← LLM patch
   │       → {original, replacement, rationale}
   │       apply_fix(patched, patch) → new text if the original anchor matches
   │       (patches chain: each applies to the previous result)
   ▼
verify (unless --no-verify), ONE re-scan per file:
   │  verify_fixes(patched, lang, basename, applied_findings, config)
   │       → verdicts: still detected / fixed   (reuses the scan pipeline)
   ▼
emit:
   │  --in-place → write patched file (containment-checked path);
   │               --diff additionally prints the unified diff
   │  default    → print unified diff only (nothing written)
   ▼
summary: "N/M findings patched (…); K verified fixed by re-scan."
exit 0 if ≥1 patch applied, else 1
```

The `verified` column is the point: a fix is only claimed fixed when the
**same symbolic pipeline** that found the bug fails to find it again.

---

## 8. Phase 5 — The solver (`solve` / `check` / `parse` / `repl`)

Independent of everything above; no LLM, no network.

1. **Input**: `"P |- Q"` string (`solve "…"`), a file (`-f`), or interactive
   lines (`repl`); `parse` dumps the AST for grammar debugging.
2. **Parse** (`core/parser.py`) → AST (`core/ast.py`).
3. **Check** (`checking/checker.py::check_entailment`), in order:
   1. syntactic reflexivity fast path (<1 ms);
   2. heuristics (frame-shaped / list-shaped), including the unsat-antecedent
      short-circuit;
   3. lemma application (`lemmas/`: ls_transitivity, ls_cons, …);
   4. goal-directed folding — synthesise predicates in the antecedent toward
      the consequent;
   5. bounded predicate unfolding (`max_unfold_depth`, `--unfold-depth`
      overrides it);
   6. Z3 encoding (`encoding/encoder.py`): heap-as-array + domain set,
      `*` → domain disjointness, exact (SL-COMP-style) footprint discipline —
      `P * Q |- P` and `P |- emp` are INVALID for non-empty P;
   7. Z3 query: valid ⇔ `(P ∧ ¬Q)` is unsat (5 s default timeout).
4. **Verdict**: `{entailment, valid, reason, time}` in text or JSON;
   exit 0 = valid, 1 = invalid/error.

The same checker powers the scanner's memory-safety verification — one
prover, two entry points.

---

## 9. End-to-end data flow (one operator session)

```bash
velora scan ./src -f json -o findings.json        # exit 0/1 (+2/3 on faults)
   │   writes: findings.json  (symbolic ± llm provenance, tiers, confidences)
   ▼
velora report --findings findings.json -o report.md
   │   writes: report.md (pure projection; optional --trace-out adds exploit §)
   ▼
velora exploit --target http://127.0.0.1:3000 \
   --guidance findings.json --success-check 'curl -sf localhost:3000/flag' \
   --trace-out trace.json
   │   reads:  findings.json (leads fenced as untrusted)
   │   writes: trace.json {model, summary{solved,steps,…}, transcript}
   │   exit:   0 solved / 1 not
   ▼
velora fix ./src --guidance findings.json --in-place --diff
   │   reads:  findings.json (paths containment-checked against ./src)
   │   writes: patched sources + diff; per-file re-scan verdicts
   ▼
velora scan ./src -f json -o findings-2.json       # re-scan: fixes must hold
   │   exit gate now reflects the *verified* state
   ▼
velora report --findings findings-2.json --trace trace.json -o final.md
```

Control-flow signals ride on **exit codes**, data rides on **files**:

```
0  success / gate not tripped          findings.json ──▶ report | exploit | fix
1  findings ≥ threshold · invalid ·    trace.json    ──▶ report (evidence §)
     no patch applied · tool misuse    patched src   ──▶ re-scan → findings-2
2  LLM unreachable (clean stderr)      verdict json  ──▶ scripts/CI
3  scan I/O errors (after gate 1)
130 user interrupt
```

---

## 10. The LLM layer underneath (shared by phases 1, 3, 4)

- **Transport** (`sil/llm_client.py`): OpenAI-style `POST /chat/completions`.
  Retries with backoff; plain calls `VELORA_LLM_TIMEOUT` (120 s), agentic
  rounds `VELORA_LLM_AGENT_TIMEOUT` (300 s); structured-output modes
  (`json_object`/`json_schema`); exhausted retries raise
  `LLMUnavailableError` → exit **2**, never a fake success.
- **Malformed-output discipline**: non-dict tool arguments → `{}`;
  unexpected response shapes → retried, then `None`; findings that fail
  parsing are skipped with a warning. Model output is *never* executed
  except through declared tools.
- **Model resolution** (per field, env wins where set):
  `--model` flag → `VELORA_LLM_BASE_URL/MODEL/API_KEY` (legacy `FRAME_*`
  accepted) → `~/.config/velora/config.json` → opencode auto-fallback that
  walks `opencode.json` up from cwd — **skipped entirely** when
  `OPENCODE_CONFIG` is set (authoritative), otherwise announced on stderr.
  `VELORA_SKIP_PROVIDER_FALLBACK=1` disables the fallback (used in tests).
- **Tools**: `read_file` / `grep` for detect/triage are repo-confined via
  `_safe_path`; `run` for exploit is shell, operator-launched, timeout-bounded,
  target-host allow-listed.
- **Bridge** (`velora serve-bridge`, `_bridge/server.js`): a local Node
  service (default port 8399) exposing opencode as an OpenAI-compatible API —
  the zero-key path. Per-session bearer token (env > state file, state 0600,
  `secrets.token_hex(32)`), loopback Host check (DNS-rebinding guard), Origin
  check, timing-safe comparison. `--stop` verifies the PID's cmdline identity
  before any kill. Diagnose with `velora doctor`, bootstrap with
  `velora setup`, pick models with `velora models`.

### Configuration quick reference

| Variable | Phase | Meaning |
|---|---|---|
| `VELORA_LLM_BASE_URL` | 1,3,4 | OpenAI-compatible endpoint |
| `VELORA_LLM_MODEL` | 1,3,4 | model id (`--model` overrides) |
| `VELORA_LLM_API_KEY` | 1,3,4 | key if the endpoint needs one |
| `VELORA_LLM_TIMEOUT` | 1 | plain-call timeout (default 120 s) |
| `VELORA_LLM_AGENT_TIMEOUT` | 3 | agent round timeout (default 300 s) |
| `OPENCODE_CONFIG` | 3,4 | authoritative config path for fallback |
| `VELORA_SKIP_PROVIDER_FALLBACK` | any | disable opencode auto-fallback |
| `VELORA_BRIDGE_TOKEN` | bridge | bearer token (beats state file) |

---

## 11. Safety properties that hold across every phase

1. **Findings are data.** Parsed defensively, quoted/fenced before entering
   any prompt, validated before becoming paths — a hostile findings file
   cannot execute, escape `--source`, or redirect the agent's shell.
2. **Containment.** `fix --in-place` realpath-checks every write against the
   source root; bridge file tools are repo-confined.
3. **No silent degradation.** Unconfigured `--ai` → notice; unreachable LLM →
   exit 2 + aborted scan (never "clean" output); scan I/O faults → exit 3;
   usage errors → exit 2 with usage text.
4. **Honest labels.** Provenance (`symbolic`/`llm`) is computed, not read
   from input; confidence needs evidence; exploit success needs an oracle.
5. **Bounded autonomy.** Every agent run is capped (steps, timeouts,
   transport-failure budget); nothing scanned or model-generated reaches a
   shell without an operator-launched tool and host allow-list.

---

## 12. Where to read next

- [`architecture.md`](architecture.md) — module map, checker internals,
  trust-boundary diagram, extension points, known caveats.
- [`usage.md`](usage.md) — every flag, exit codes, examples.
- [`agent.md`](agent.md) — prompts, termination rules, failure handling.
- [`ai-models.md`](ai-models.md) — model precedence and endpoint setup.
- [`api.md`](api.md) — programmatic use of the solver and scanner.
- [`installation.md`](installation.md) — install modes and CI recipe.
