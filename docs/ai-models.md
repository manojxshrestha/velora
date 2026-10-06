# AI Layer & Models

[← Back to README](../README.md)

## AI-Assisted Detection & Triage

Velora's symbolic core is sound and precise. But structural analysis can't reach everything: context-dependent flows, unknown frameworks, business logic. Velora adds a layer driven by an LLM.

- **Detect** (recall): find vulnerabilities the symbolic engine misses. It can explore across files, calling `read_file`/`grep` tools over your repo to trace a flow from one file into another.
- **Triage** (precision): drop confident false positives from the findings.
- **Verify**: each LLM finding is checked against Velora's own sink model. A finding grounded in a recognized sink, cross-file included, moves up to a higher-confidence tier (`llm_verified`). Symbolic results and LLM results are never conflated.

On the [Endor Labs public AI-SAST corpus](../benchmarks/endor_corpus/README.md) (5 real-world apps), Velora's full mode (detection + triage) reaches 0.67 recall at 0.51 precision, or 0.71 recall with detection alone. Semgrep gets 0.52 recall at 0.40 precision. The LLM layer recovers around 65 real vulnerabilities across Java, JS/TS, and C# that both Velora's symbolic engine and Semgrep miss. See the [benchmark README](../benchmarks/endor_corpus/README.md) for the full scoreboard and the honest caveats.

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

Or from the Python API:

```python
from velora.sil import VeloraScanner
# symbolic + LLM detection + triage (reads the VELORA_LLM_* env above)
scanner = VeloraScanner(language="java", llm_detect=True, llm_triage=True)
result = scanner.scan_file("Controller.java")
```

## RAM & Model Requirements

**The tool itself is light — any laptop runs it.** Measured peaks for the symbolic engine (no model involved): **55 MB** to solve an entailment, **77 MB** to scan a 136-file package. Budget ~100 MB for Velora, nothing more.

**What actually costs RAM is running an LLM locally** (`--ai`). The model dominates:

| Setup | RAM needed | Notes |
|---|:---:|---|
| Symbolic scans & solver (no `--ai`) | **< 100 MB** | No model required — Z3 only |
| `--ai` with a hosted endpoint | **< 1 GB** | Inference happens remotely; RAM is irrelevant |
| `--ai` with a local **3–4B** model (4-bit) | **8 GB laptop ✅** | ~2–2.5 GB weights, fits alongside the OS |
| `--ai` with a local **7B** model (4-bit) | 8 GB, tight | ~4.5 GB weights — close other apps first |
| `--ai` with the **benchmark model** (Qwen3.6-35B, 4-bit, **24.7 GB** weights) | **32 GB machine** | What every benchmark number uses |

Rule of thumb: ~**0.5–0.6 GB per 1B parameters** at 4-bit quantization (all weights load, even for MoE models).

**On an 8 GB laptop**, you have two good paths — hosted (full benchmark quality, zero extra RAM; free hosted models via `velora models list --free`, see [Model Providers](#model-providers)) or a small local model:

```bash
# small local model via Ollama (serves an OpenAI-compatible API)
ollama pull qwen3:4b
export VELORA_LLM_BASE_URL=http://localhost:11434/v1
export VELORA_LLM_MODEL=qwen3:4b
velora scan . --ai
```

Expectation setting: the benchmark results were produced with the 35B local model and hosted GLM-5.2 — a 4B model on CPU will be noticeably weaker and slower at triage/exploitation. The symbolic engine (`velora scan` without `--ai`) is unaffected and runs identically on any machine above.

## Model Providers

### Zero-key quickstart (no API key)

```bash
velora doctor                              # 1. diagnose; exit 1 while something is missing
velora setup                               # 2. install what's missing user-local (no sudo), start the bridge
velora models use opencode-bridge/opencode/mimo-v2.6-flash-free --no-prompt   # 3. pick a free Zen model (keyless)
velora scan . --ai                         # 4. scan through the local bridge — free tier, zero keys
```

The bridge (`velora serve-bridge`) is a local OpenAI-compatible server on `:8399` that proxies opencode's own client — opencode owns every credential, so Velora stores none. `velora setup` installs missing prerequisites (Node ≥ 18 into `~/.local/opt`, the `opencode` CLI, bridge dependencies) after a single consent prompt; it is idempotent, and `--yes` makes it non-interactive. The daemon logs to `$XDG_STATE_HOME/velora/bridge.log`.

```bash
velora doctor --probe           # end-to-end: one real keyless chat through the bridge
velora serve-bridge --status    # daemon state (also: --start / --stop, --format json)
velora serve-bridge --stop      # stop it (models tui auto-restarts on demand)
velora models current           # what model is active and where it came from
```

`velora models tui` auto-starts the bridge when you pick a model. Supported platforms: **Linux (incl. WSL) and macOS**. On native Windows, use `wsl --install` and run everything inside WSL — the bridge will not start from a Windows shell.

### Hosted free tier (Zen key)

`velora models` browses and switches the AI model behind `--ai`. Two sources are built in:

- **OpenCode Zen** — curated gateway (`https://opencode.ai/zen/v1`) with a **free tier** (e.g. `mimo-v2.6-flash-free`, `nemotron-3-ultra-free`, `ling-3.0-flash-fin-free`) and cheap pay-as-you-go models like `glm-5.2` ($1.40/$4.40 per 1M). Free hosted = no local RAM at all.
- **models.dev** — the registry opencode itself uses: 225 providers, 8,300+ models, 637 free (cached 24h; `--refresh` re-fetches).

A Zen key is free from [opencode.ai](https://opencode.ai):

```bash
export OPENCODE_API_KEY=sk-...        # free key; `use` prompts for it on a tty otherwise
velora models list --free             # browse free models
velora models use mimo-v2.6-flash-free
velora scan . --ai                    # zero local RAM: inference is hosted
```

### All model actions

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

`velora models tui` probes every source at once and saves your pick keyless: the local opencode bridge (free Zen tier) plus any running local server — mlx-optiq on `:47317` (the setup above), Ollama on `:11434`, LM Studio, llama.cpp, vLLM — with extras via `--local-url NAME=URL` or `VELORA_LOCAL_URLS=NAME=URL,...`. Local servers need no key, so none is stored.

`use` also accepts `opencode/<provider>/<model>` (reuse an opencode provider) or `<provider>/<model> --base-url <endpoint>` for any OpenAI-compatible server (Ollama, vLLM, ...). Keys are stored `0600` in `~/.config/velora/credentials.json` (override the directory with `VELORA_CONFIG_HOME`).

**Precedence** for `velora scan --ai` (per field): `--model` flag → `VELORA_LLM_*` env → `~/.config/velora/config.json` → existing opencode config (auto-fallback, announced once on stderr; disable with `VELORA_SKIP_PROVIDER_FALLBACK=1`). With no configuration at all the scan proceeds **without** the LLM tier and says so on stderr unconditionally (`Note: AI layer requested (--ai) but no endpoint/model is configured...`, even without `-v`; the JSON/SARIF payload on stdout stays clean).

**Compatibility.** Velora's client speaks OpenAI-style `/chat/completions` only. Zen's GPT/Claude/Gemini models use other transports and are listed as `✗ phase 2` until transport adapters land. models.dev rows that don't expose an OpenAI-style endpoint are marked `endpoint unverified` — pass `--base-url` if you know better.
