"""OpenCode Zen catalog snapshot.

Static table transcribed from https://opencode.ai/docs/zen/ (Sep 2026): every
model Zen serves, its transport, and its price per 1M tokens (None = free).

Velora's client only speaks OpenAI ``/chat/completions``. Zen serves four
transports; ``chat`` entries work with Velora today, the rest are listed but
marked phase-2 until transport adapters land:

    chat       https://opencode.ai/zen/v1/chat/completions   (ready)
    responses  https://opencode.ai/zen/v1/responses          (phase 2)
    anthropic  https://opencode.ai/zen/v1/messages           (phase 2)
    google     https://opencode.ai/zen/v1/models/<id>        (phase 2)
    systemone  https://opencode.ai/zen/v1/systemone          (phase 2, not text)

The live list at ``https://opencode.ai/zen/v1/models`` (public, no key) is
validated against this table on ``velora models list --refresh``.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

ZEN_BASE_URL = "https://opencode.ai/zen/v1"

# (id, display name, transport, price_in, price_out) -- prices per 1M tokens,
# None/None = free. Only "chat" transports are usable by Velora today.
ZenEntry = Tuple[str, str, str, Optional[float], Optional[float]]

ZEN_MODELS: List[ZenEntry] = [
    # --- free, all served over /chat/completions (ready) -------------------
    ("big-pickle", "Big Pickle", "chat", None, None),
    ("space-bunny-free", "Space Bunny Free", "chat", None, None),
    ("longcat-2.5-preview-free", "LongCat 2.5 Preview Free", "chat", None, None),
    ("mimo-v2.6-flash-free", "MiMo-V2.6-Flash Free", "chat", None, None),
    ("mimo-v2.5-free", "MiMo-V2.5 Free", "chat", None, None),
    ("ling-3.0-flash-fin-free", "Ling 3.0 Flash Fin Free", "chat", None, None),
    ("nemotron-3-ultra-free", "Nemotron 3 Ultra Free", "chat", None, None),
    ("nemotron-3.5-lightning-free", "Nemotron 3.5 Lightning Free", "chat", None, None),
    # --- paid, /chat/completions (ready) -----------------------------------
    ("qwen3.8-max", "Qwen3.8 Max", "chat", 2.00, 6.00),
    ("deepseek-v4.1-flash", "DeepSeek V4.1 Flash", "chat", 0.30, 1.20),
    ("deepseek-v4-pro", "DeepSeek V4 Pro", "chat", 1.74, 3.48),
    ("deepseek-v4-flash", "DeepSeek V4 Flash", "chat", 0.14, 0.28),
    ("deepseek-v4-flash-vision-exp", "DeepSeek V4 Flash Vision Exp", "chat", 0.14, 0.28),
    ("minimax-m3", "MiniMax M3", "chat", 0.30, 1.20),
    ("minimax-m2.7", "MiniMax M2.7", "chat", 0.30, 1.20),
    ("minimax-m2.5", "MiniMax M2.5", "chat", 0.30, 1.20),
    ("glm-5.3-flash", "GLM 5.3 Flash", "chat", 0.15, 0.50),
    ("glm-5.3", "GLM 5.3", "chat", 1.40, 4.40),
    ("glm-5.2", "GLM 5.2", "chat", 1.40, 4.40),
    ("glm-5.1", "GLM 5.1", "chat", 1.40, 4.40),
    ("glm-5", "GLM 5", "chat", 1.00, 3.20),
    ("kimi-k2.5", "Kimi K2.5", "chat", 0.60, 3.00),
    ("kimi-k2.6", "Kimi K2.6", "chat", 0.95, 4.00),
    ("kimi-k2.7-code", "Kimi K2.7 Code", "chat", 0.95, 4.00),
    ("kimi-k3", "Kimi K3", "chat", 3.00, 15.00),
    # --- phase 2: OpenAI Responses transport -------------------------------
    ("gpt-6-astra", "GPT 6 Astra", "responses", 10.00, 50.00),
    ("gpt-6-sol", "GPT 6 Sol", "responses", 2.00, 10.00),
    ("gpt-6.1-sol", "GPT 6.1 Sol", "responses", 2.00, 10.00),
    ("gpt-6-luna", "GPT 6 Luna", "responses", 0.10, 0.50),
    ("gpt-5.6-sol", "GPT 5.6 Sol", "responses", 4.00, 20.00),
    ("gpt-5.6-terra", "GPT 5.6 Terra", "responses", 2.00, 12.00),
    ("gpt-5.6-luna", "GPT 5.6 Luna", "responses", 0.20, 1.20),
    ("gpt-5.5", "GPT 5.5", "responses", 5.00, 30.00),
    ("gpt-5.5-pro", "GPT 5.5 Pro", "responses", 30.00, 180.00),
    ("gpt-5.4", "GPT 5.4", "responses", 2.50, 15.00),
    ("gpt-5.4-pro", "GPT 5.4 Pro", "responses", 30.00, 180.00),
    ("gpt-5.4-mini", "GPT 5.4 Mini", "responses", 0.75, 4.50),
    ("gpt-5.4-nano", "GPT 5.4 Nano", "responses", 0.20, 1.25),
    ("gpt-5.3-codex", "GPT 5.3 Codex", "responses", 1.75, 14.00),
    ("gpt-5.3-codex-spark", "GPT 5.3 Codex Spark", "responses", 1.75, 14.00),
    ("gpt-5.2", "GPT 5.2", "responses", 1.75, 14.00),
    ("gpt-5.2-codex", "GPT 5.2 Codex", "responses", 1.75, 14.00),
    ("gpt-5.1", "GPT 5.1", "responses", 1.07, 8.50),
    ("gpt-5.1-codex", "GPT 5.1 Codex", "responses", 1.07, 8.50),
    ("gpt-5.1-codex-max", "GPT 5.1 Codex Max", "responses", 1.25, 10.00),
    ("gpt-5.1-codex-mini", "GPT 5.1 Codex Mini", "responses", 0.25, 2.00),
    ("gpt-5", "GPT 5", "responses", 1.07, 8.50),
    ("gpt-5-codex", "GPT 5 Codex", "responses", 1.07, 8.50),
    ("gpt-5-nano", "GPT 5 Nano", "responses", 0.05, 0.40),
    ("grok-4.7", "Grok 4.7", "responses", 2.00, 6.00),
    ("grok-4.6", "Grok 4.6", "responses", 2.00, 6.00),
    ("grok-4.5", "Grok 4.5", "responses", 2.00, 6.00),
    ("grok-build-0.1", "Grok Build 0.1", "responses", 1.00, 2.00),
    ("muse-spark-1.3", "Muse Spark 1.3", "responses", 1.25, 4.25),
    ("muse-spark-1.2", "Muse Spark 1.2", "responses", 1.25, 4.25),
    ("muse-spark-1.3-contributor-free", "Muse Spark 1.3 Contributor Free", "responses", None, None),
    # --- phase 2: Anthropic Messages transport ------------------------------
    ("claude-fable-5-1", "Claude Fable 5.1", "anthropic", 10.00, 50.00),
    ("claude-fable-5", "Claude Fable 5", "anthropic", 10.00, 50.00),
    ("claude-opus-5-5", "Claude Opus 5.5", "anthropic", 4.00, 20.00),
    ("claude-opus-5", "Claude Opus 5", "anthropic", 5.00, 25.00),
    ("claude-opus-4-8", "Claude Opus 4.8", "anthropic", 5.00, 25.00),
    ("claude-opus-4-7", "Claude Opus 4.7", "anthropic", 5.00, 25.00),
    ("claude-opus-4-6", "Claude Opus 4.6", "anthropic", 5.00, 25.00),
    ("claude-opus-4-5", "Claude Opus 4.5", "anthropic", 5.00, 25.00),
    ("claude-sonnet-5", "Claude Sonnet 5", "anthropic", 2.00, 10.00),
    ("claude-sonnet-4-6", "Claude Sonnet 4.6", "anthropic", 3.00, 15.00),
    ("claude-sonnet-4-5", "Claude Sonnet 4.5", "anthropic", 3.00, 15.00),
    ("claude-haiku-4-5", "Claude Haiku 4.5", "anthropic", 1.00, 5.00),
    ("qwen3.8-flash", "Qwen3.8 Flash", "anthropic", 0.15, 0.47),
    ("qwen3.7-max", "Qwen3.7 Max", "anthropic", 2.50, 7.50),
    ("qwen3.7-plus", "Qwen3.7 Plus", "anthropic", 0.40, 1.60),
    ("qwen3.6-plus", "Qwen3.6 Plus", "anthropic", 0.50, 3.00),
    ("qwen3.5-plus", "Qwen3.5 Plus", "anthropic", 0.20, 1.20),
    # --- phase 2: Google-native transport ----------------------------------
    ("gemini-3.8-flash", "Gemini 3.8 Flash", "google", 1.50, 7.50),
    ("gemini-3.7-flash", "Gemini 3.7 Flash", "google", 1.50, 7.50),
    ("gemini-3.6-flash", "Gemini 3.6 Flash", "google", 1.50, 7.50),
    ("gemini-3.5-flash", "Gemini 3.5 Flash", "google", 1.50, 9.00),
    ("gemini-3.5-flash-lite", "Gemini 3.5 Flash Lite", "google", 0.30, 2.50),
    ("gemini-3.1-pro", "Gemini 3.1 Pro", "google", 2.00, 12.00),
    ("gemini-3-flash", "Gemini 3 Flash", "google", 0.50, 3.00),
    # --- phase 2: SystemOne (not a text-generation model) ------------------
    ("jev-1.13", "Jev 1.13", "systemone", 0.042, 0.0),
    ("jev-1.13-free", "Jev 1.13 Free", "systemone", None, None),
]
