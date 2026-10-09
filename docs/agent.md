# The Velora Agent

How Velora's language-model layer works: model configuration, the shared agent
loop, every prompt, every tool, termination rules, and how failures are
handled. Grounded in the code on `main`; the audit's deviations are fixed in
place and pinned by `tests/test_bugfix_regressions.py`.

## 1. Layers

| Layer | Module | Self- or oracle-terminating | Tools |
|---|---|---|---|
| **detect** | `velora/sil/llm_detect.py` | self (JSON answer when tools stop) | `read_file`, `grep` |
| **triage** | `velora/sil/llm_triage.py` | self | `read_file`, `grep` |
| **exploit** | `velora/sil/llm_exploit.py` | oracle (`--success-check`) or guarded `VERIFIED:` claim | `run` (shell) |
| **fix** | `velora/sil/llm_fix.py` | single structured completion (no loop) | — |

All loop layers share `velora/sil/llm_agent.py::run_agent` — one loop, two
hooks (`finalize` vs `check_done`). Transport is always
`velora/sil/llm_client.py` (OpenAI-style `POST /chat/completions`).

## 2. Model configuration & precedence

Per field, first source wins:

```
--model / --base-url CLI flag          (cli.py::_apply_model_override)
  → VELORA_LLM_BASE_URL / _MODEL / _API_KEY / VELORA_LLM_TIMEOUT / _AGENT_TIMEOUT
      → ~/.config/velora/config.json   (VELORA_CONFIG_HOME overrides the dir)
          → opencode fallback          (velora/sil/model_config.py, announced once
                                        on stderr; disable with
                                        VELORA_SKIP_PROVIDER_FALLBACK=1)
```

The opencode fallback order (`velora/sil/opencode_bridge.py::config_candidates`):

1. `OPENCODE_CONFIG` if set (global slot only — **does not stop step 3**),
2. `~/.config/opencode/opencode.json[c]`,
3. nearest `opencode.json[c]` walking **up from the current directory**.

Values support opencode-style substitution: `{env:VAR}` and `{file:path}`
(relative to the config file's directory).

**Security (BUG-012, fixed):** step 3 means a repository could supply its own
`baseURL` and read host secrets via `{env:…}`/`{file:…}` into the
`Authorization` header of the next request — reproduced end-to-end during the
audit (`base_url = https://attacker.example/v1`, `api_key = <host USER>`).
The fix makes `OPENCODE_CONFIG` fully authoritative: when it is set (Velora's
own tests and hardened runs set it to a controlled path), the cwd walk-up is
skipped entirely. Without it, a cwd-derived config is still loaded but
announced loudly on stderr (`_warn_repo_config`). Treat any `opencode.json`
found below your home directory as code, not config; pin explicit
`VELORA_LLM_*` or set `VELORA_SKIP_PROVIDER_FALLBACK=1` inside untrusted trees.

Keys chosen interactively are stored `0600` in
`~/.config/velora/credentials.json`.

## 3. The agent loop (`llm_agent.py::run_agent`)

```
messages[0] = system prompt (+ layer suffix)
loop until max_steps / terminate / budget exhausted:
    response = client.chat(messages, tools=…)      # retries inside chat_raw
    if tool_calls:
        for each call:
            args = json.loads(arguments)           # non-dict -> {} (BUG-009 fixed)
            print progress line ("$ cmd" or narration "·")
            out = exec_tool(name, args)            # injected by the caller
            messages += tool result (truncated to max_tool_output)
        continue
    # no tool call:
    if check_done hook:        # exploit
        r = check_done(); if r: return r
        else: stall nudge ("take the next concrete step")
    if finalize hook:          # detect / triage
        return finalize(content)                   # content IS the answer
    # bridge-style model narrated instead of calling a tool → keep going,
    # show the narration (llm_agent.py:282)
transport failures ≥ MAX_TRANSPORT_FAILURES (2) for the step → retry once at
step level, then AgentResult.fail("model unreachable after N failed attempts")
```

Transcript management: `_compact_messages` replaces the middle of a long
transcript with a single `PROGRESS-NOTES` summary (system prompt and last 6
turns preserved; summary produced by `client.complete`, on failure the
transcript is left untouched).

## 4. Prompts

| Prompt | Location | Injected content |
|---|---|---|
| `EXPLOIT_SYSTEM` | `llm_exploit.py:49` | **+ `_format_guidance(guidance)`** — findings fields fenced in an `untrusted` delimiter block (BUG-008 mitigated) |
| `DETECT_SYSTEM` / `DETECT_REPO_SYSTEM` | `llm_detect.py:36/350` | repo context |
| `SYSTEM_PROMPT` / `TRIAGE_AGENTIC_SYSTEM` | `llm_triage.py:44/71` | candidate findings |
| `FIX_SYSTEM` | `llm_fix.py:23` | finding + source; strict `FIX_SCHEMA` structured output |
| `_COMPACT_SYSTEM` | `llm_agent.py:139` | transcript summary request |
| stall / final nudges | `llm_agent.py:24-26`, `llm_exploit.py:99` | step-level steering |

### Prompt-injection surface (BUG-008, mitigated)

`_format_guidance` renders finding fields (`type`, `location`, `description`,
`taint_path`, …) into the exploit **system** prompt. A crafted findings file
(or a scanner finding that echoes attacker-controlled source text — e.g. a
literal) used to speak to the model with system-level authority while the
model held a `run` tool executing `subprocess.run(cmd, shell=True, ...)`.

Mitigations now in code: every rendered value is escaped and fenced inside
`<velora_findings role="data" trust="untrusted">` (values can never forge or
close the delimiters), the block carries an untrusted-content preamble, and
`run` is target-scoped — `allow_hosts` derives from `--target` and
non-permitted hosts are rejected before the shell runs. Residual risk: a model
that *chooses* to comply with injected data can still be steered within those
bounds (`shell=True` remains for local, target-allowed commands) — keep
`--success-check` as the oracle.

## 5. Tools

### Detect / triage: `INVESTIGATION_TOOLS` (`llm_agent.py:68`)

| Tool | Behaviour | Boundary |
|---|---|---|
| `read_file {path}` | reads repo-relative file, first 8000 chars | `_safe_path` realpaths and rejects escapes (`p == root or startswith(root + os.sep)`) — confined to the repo |
| `grep {pattern}` | regex search over source extensions, ≤40 matches | same confinement |

### Exploit: `_TOOLS` (`llm_exploit.py:81`)

| Tool | Behaviour | Boundary |
|---|---|---|
| `run {cmd}` | `subprocess.run(cmd, shell=True, capture_output=True, timeout=exec_timeout)` | **timeout only**; stdout+stderr returned to the model |

The exploit tool is intentionally an attacker's shell: `velora exploit` is an
explicitly operator-launched, authorized-use-only action (CLI help says so).
The bridge mode variant (below) does not surface `run` through velora at all.

## 6. Termination rules

**Exploit with `--success-check` (preferred):** the shell oracle is
authoritative — it prints `[success-check] <evidence>` and overrides any model
claim. Exit `0` solved / `1` not solved.

**Exploit without `--success-check`:** a final

```
VERIFIED: <evidence>
```

claim in the **latest assistant message** terminates the run — only if
`_self_verified` guards hold: prior tool/assistant turn exists (a first-turn
echo of the goal can never terminate), and the evidence is non-placeholder.
Model claims are never treated as proof beyond this guarded final message;
the run's success still reflects the claim, not an oracle.

**Detect/triage:** last assistant content without tool calls is the answer
(`finalize`).

**Budget:** `--max-steps` (default 40); exhaustion →
`✗ NOT EXPLOITED (... step budget exhausted)`, exit 1.

## 7. Failure handling

| Failure | Behaviour | Contract |
|---|---|---|
| Endpoint down / DNS fail | `chat_raw` retries (`agent_retries + 1` HTTP attempts, backoff) | per-call gap must exceed turn length (`VELORA_LLM_AGENT_TIMEOUT` = 300 s for agentic) |
| Empty round-trip | step-level retry once (`no response from the model -- retrying`) | then `AgentResult.fail`, run prints `model unreachable after N failed attempts` |
| Heartbeat | `[llm] · still waiting… Ns/Ds` every 30 s | long turns stay visible |
| Malformed tool arguments (`"5"`, lists) | non-dict coerced to `{}`; `error:` string fed to the model | handled (BUG-009 fixed) |
| Malformed findings file shapes | clean `malformed findings file: ...` error + skip-warnings | handled (BUG-010 fixed) |
| Malformed response body shapes (missing/empty/scalar `choices`/`message`/`content`, non-JSON) | retried, then `LLMUnavailableError` (`... unreachable after N attempts: malformed response`) | handled (BUG-020 fixed); `chat_raw` returns `None` |
| Unreachable endpoint at `fix`/`exploit` start | clean `error: ...` on stderr, **exit 2** (no traceback) | BUG-011 fixed |
| Timeout on `run` tool | `error: command timed out after Ns` fed to model | handled |
| Zigzag JSON in completions | `_extract_json_object` tolerant extraction | handled |

### Model-specific notes (Mimo v2.6 Flash and friends)

The client is model-agnostic OpenAI-style JSON; nothing in the codebase
branches on model identity. What matters for a given model is behavioural, and
the loop defends against the four classic failure modes:

1. **Hallucinated tool arguments** → non-dict JSON (`"5"`, lists) is coerced
   to `{}`; `exec_tool` returns an `error:` string the model can recover from
   (BUG-009 fixed).
2. **Malformed JSON answers** → detect/triage `finalize` receives raw content;
   `_extract_json_object` rescues fenced/loose JSON; garbage after all rescues
   fails closed (no finding emitted) rather than crashing; `complete()` /
   `chat_raw()` validate response shape and degrade to `LLMUnavailableError` /
   `None` after retries (BUG-020 fixed).
3. **Timeouts / stalls** → stall nudges, `MAX_TRANSPORT_FAILURES`, heartbeat,
   step-level retry — a slow or wedged endpoint ends in a clean
   `model unreachable` line instead of a hung process (this behaviour was
   observed working during the audit).
4. **Prompt-injection compliance** → the loop cannot make model output safe by
   itself: guidance is fenced as untrusted data and `run` is target-scoped
   (BUG-008 mitigated), and the bridge requires its bearer token plus
   Host/Origin checks (BUG-013 fixed) — but a model that *follows* injected
   instructions within those bounds is still a residual risk; keep
   `--success-check` as the oracle.

**Operating guidance:** for agentic runs, pin the endpoint with explicit
`VELORA_LLM_*` env inside untrusted trees (BUG-012), always prefer
`--success-check`, and treat `VERIFIED:` lines without an oracle as claims.

## 8. The bridge (`velora serve-bridge`)

- **What it is:** Node service (default port **8399**) exposing opencode as
  `POST /v1/chat/completions` + `GET /v1/models` + `GET /health`
  (`velora/_bridge/server.js:296-346`), so `velora scan --ai` works with no
  API key (zero-key mode; `velora setup` bootstraps it).
- **Tool mode:** when `enabled`, the bridge passes `tools` through to
  opencode, which runs the **model's own tools** in its session (bash etc.) —
  velora's `exec_tool` never runs; the loop prints narration (`·`) lines
  instead of `$ cmd` lines.
- **Trust:** binds loopback and is authenticated — `serve-bridge --start` mints
  a per-session bearer token (kept in the daemon env and a `0600` state file);
  every route requires `Authorization: Bearer <token>` (401 otherwise) and
  non-loopback `Host` / foreign `Origin` headers are rejected (403), which
  covers DNS-rebinding and browser cross-origin abuse (BUG-013 fixed; a raw
  `node server.js` with no token configured stays open for local dev). The PID
  file records the bridge cmdline and `--stop` refuses to kill a recycled PID
  (BUG-015 fixed). With `OPENCODE_CONFIG` set, the repo `opencode.json`
  walk-up is skipped entirely (BUG-012 fixed); the HTTP client never forwards
  `Authorization` across an off-origin redirect (BUG-014 fixed). opencode still
  reads the repository content of the session cwd — treat the bridge as
  repo-trusting.
- **Tests:** `cd velora/_bridge && npm install && node --test server.test.js`
  (18/18 passing after the BUG-013 auth/Origin/Host guards).

Operational commands: `velora serve-bridge --start|--stop|--status`,
`velora doctor` (exit 1 when not ready), `velora models tui`.

## 9. Operator checklist

1. Run inside untrusted repos with `VELORA_LLM_*` pinned or
   `VELORA_SKIP_PROVIDER_FALLBACK=1` (BUG-012: repo walk-up is skipped when
   `OPENCODE_CONFIG` is set; otherwise a loud warning is printed).
2. Always pass `--success-check` on `exploit` (oracle beats claim).
3. `fix --in-place` refuses to write outside `--source` (realpath containment,
   BUG-007 fixed) — still review patches before committing them; findings
   fields are fenced as untrusted in prompts (BUG-008 mitigated).
4. Start the bridge only for the duration of a session: it now requires its
   per-session bearer token and rejects foreign Host/Origin (BUG-013 fixed),
   but it still drives an agent that reads the session's repo — stop it when
   idle.
5. `Verification error` in scan output means a check failed to run (not a
   verdict): those findings are tier-*labelled*, not solver-*verified*. The
   crash that caused it on every call is fixed (BUG-004) and confidence is
   evidence-weighted rather than stamped 1.0 by fiat (BUG-005).
