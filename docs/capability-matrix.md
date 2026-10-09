# Capability matrix

Published per release — this document is generated from the live registry
(`velora/modes/common.py`). Regenerate it for each release:

```bash
velora modes                     # the table below, live from the registry
velora modes whitebox            # one mode in detail (flag + engine per stage)
velora modes --format json       # machine-readable (for CI/docs tooling)
```

**Legend** — **●** default pipeline · **○** off-default (select with
`--with-<stage>`) · **–** unavailable for this mode · **·** not part of this
mode.

## Release 0.2.0

```text
velora mode graphs (● default, ○ off-default, – unavailable, · not in this mode)
stage                     whitebox  blackbox   bughunt  engine
SCOPE                            ●         ●         ●  exists (scope object, target allowlist)
AUTH                             –         ●         ●  exists (active/session.py: refs-only jars + scripted flows)
INTEL                            –         ○         ●  partial (header/DNS fingerprint)
OSINT                            –         ○         ●  partial (TLS certificate + DNS; no CT/search feeds)
INGEST                           ●         –         ○  exists (frontends, literals, deps + IaC manifests)
RECON                            ○         ●         ●  exists (active/recon.py: bounded crawl)
ASSET MODEL                      ●         ○         ●  exists (assets/graph.py)
ASSET DISCOVERY                  ·         ●         –  exists (recon-derived assets)
CODE MODEL                       ●         –         ○  exists (SIL program)
STATIC SCAN                      ●         –         ○  exists (sil/scanner.py)
DATAFLOW / CONTROLFLOW           ●         –         ○  exists (analyzers + branch conditions)
SURFACE                          ○         ●         ●  exists (assets/surface.py view)
ENUMERATION                      ○         ●         ○  exists (active/probe.py: OPTIONS/GET)
SERVICE MAPPING                  ·         ●         –  full (connect scan + banner + TLS + HEAD probe)
HUNT                             ○         ●         ●  partial (static detectors + active/probe.py ≥2 repro)
HYPOTHESIZE                      ●         ○         ○  partial (candidate engine from static leads)
TRIAGE                           ●         ●         ●  exists (severity/confidence ranking)
DEEPTHINK                        ○         ○         ●  exists (falsifiable hypotheses + elimination memory)
PLAN                             ●         ○         ○  new (source-slice guidance enrichment)
VERIFY                           ●         ●         ●  exists (Z3 + probe recheck + --success-check)
EXPLOIT                          ●         ●         ●  exists (exploit_agentic)
FIX                              ●         ○         ○  exists (llm_fix)
RESCAN                           ●         ○         ○  exists (verify_fixes)
CAPTURE                          ○         ●         ●  full (evidence{}, trace.json -> report timeline)
VALIDATE                         ●         ●         ●  exists (independent re-check)
SEARCH                           ○         ○         ●  exists (gap analysis + convergence)
REPORT                           ●         ●         ●  exists (markdown/SARIF/bounty + action timeline)
```

## How to read the matrix

- **The matrix is the capability contract.** A mode may only run a stage it
  has an engine for. Selecting an unavailable stage exits `2` with a clear
  refusal — never a silent skip.
- **`partial`** means the stage runs but not at full depth (e.g. OSINT has
  TLS/DNS but no CT/search feeds); the honest status shows in `--dry-run`,
  `velora modes`, and the mode `--help` epilog.
- **Findings-gated stages** (`FIX`, `RESCAN`, `VALIDATE`) run `n/a` with
  zero findings unless selected explicitly.
- **Guard stage** `SCOPE` always runs first and is not stage-selectable.
- Each adapter lands with its own tests and its entry here — no big-bang.

## Protocol depth honesty

Named `partial` until an adapter covers them, never silently untested:
GraphQL, WebSocket, HTTP/2, and full OSINT (CT/search feeds) are outside
0.2.0's adapters.
