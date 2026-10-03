"""Transport resilience + exploit self-termination.

The free tier and any slow/hosted endpoint produce two failure modes these
tests lock down:
  * a turn takes longer than the socket budget -> chat_raw returns None; the
    loop must retry once with a clear message, then give up with a distinct
    reason instead of silently eating the whole step budget;
  * without `--success-check` the run must still be able to succeed, but only
    on the agent's guarded `VERIFIED: <evidence>` claim -- never on narration.
"""

import json

from velora.sil.llm_agent import run_agent
from velora.sil.llm_client import LLMConfig
from velora.sil.llm_exploit import exploit_agentic, _self_verified
from velora.sil.llm_triage import TriageConfig


SYS = {"role": "system", "content": "S"}


def _tool_call(cmd="curl target"):
    return {"content": "", "tool_calls": [{"id": "1", "function": {
        "name": "run", "arguments": json.dumps({"cmd": cmd})}}]}


class _FlakyClient:
    """chat_raw fails (returns None) `fails` times, then replays `script`."""

    def __init__(self, fails, script=None):
        self.fails = fails
        self.script = script or []
        self.calls = 0
        self.config = LLMConfig(base_url="http://dead:1", model="m")

    def chat_raw(self, messages, tools=None):
        self.calls += 1
        if self.calls <= self.fails:
            return None
        msg = self.script[min(self.calls - self.fails - 1, len(self.script) - 1)]
        return msg

    def complete(self, messages, **kw):
        return "SUMMARY"


def _oracle(done):
    return lambda: True if done["ok"] else None


# --- config defaults ------------------------------------------------------------

def test_timeout_defaults_raised_for_slow_models():
    cfg = LLMConfig()
    assert cfg.timeout == 120          # single-shot calls (was 60: too small)
    assert cfg.agent_timeout == 300    # agentic turns (was 60: cut off free tier)


def test_from_env_agent_timeout(monkeypatch):
    for v in ("VELORA_LLM_TIMEOUT", "VELORA_LLM_AGENT_TIMEOUT",
              "VELORA_LLM_AGENT_RETRIES"):
        monkeypatch.delenv(v, raising=False)
    assert LLMConfig.from_env().timeout == 120
    assert LLMConfig.from_env().agent_timeout == 300
    monkeypatch.setenv("VELORA_LLM_AGENT_TIMEOUT", "450")
    assert LLMConfig.from_env().agent_timeout == 450


# --- transport retry / give-up --------------------------------------------------

def test_transport_blip_retries_and_recovers(capsys):
    c = _FlakyClient(fails=1, script=[_tool_call("curl t")])
    done = {"ok": False}

    def ex(name, args):
        done["ok"] = True
        return "ran"

    r = run_agent([SYS], c, tools=[], exec_tool=ex, max_steps=5,
                  check_done=_oracle(done), progress=True, progress_label="exploit")
    assert r.done and r.fail is None
    assert c.calls == 2                      # one failed attempt + one real one
    assert r.steps == 2                      # the blip cost exactly one step
    out = capsys.readouterr().out
    assert "no response from the model -- retrying (attempt 2/2)" in out


def test_transport_failure_gives_up_with_reason():
    c = _FlakyClient(fails=99)
    r = run_agent([SYS], c, tools=[], exec_tool=lambda n, a: "x", max_steps=5,
                  check_done=lambda: None)
    assert not r.done
    assert c.calls == 2                      # 2 attempts, then stop -- not 5
    assert r.steps == 2
    assert r.fail and "unreachable" in r.fail


def test_transport_failure_finalize_returns_empty():
    c = _FlakyClient(fails=99)
    r = run_agent([SYS], c, tools=[], exec_tool=lambda n, a: "x", max_steps=5,
                  finalize=lambda content: ("parsed", content))
    assert r.done is False
    assert r.result == ("parsed", "")
    assert c.calls == 2 and r.fail


# --- exploit self-termination (no --success-check) ------------------------------

def _exploit_client(script):
    c = _FlakyClient(fails=0, script=script)
    return c


def test_exploit_self_terminates_on_verified_claim():
    c = _exploit_client([_tool_call("curl t"),
                         {"content": 'VERIFIED: {"flag": "pwn{admin_cookie=abc123}"}',
                          "tool_calls": []}])
    r = exploit_agentic("pwn target", TriageConfig(), c,
                        exec_tool=lambda n, a: "secret output observed here",
                        is_solved=None, max_steps=5)
    assert r.solved and r.reason == "objective observed"
    assert r.steps == 2


def test_exploit_narration_without_verified_exhausts_budget():
    c = _exploit_client([{"content": "I believe I am done.", "tool_calls": []}])
    r = exploit_agentic("pwn target", TriageConfig(), c,
                        exec_tool=lambda n, a: "x",
                        is_solved=None, max_steps=3)
    assert not r.solved
    assert r.steps == 3 and r.reason == "step budget exhausted"


def test_external_oracle_wins_over_verified_claim():
    c = _exploit_client([{"content": "VERIFIED: evidence line that is long enough",
                          "tool_calls": []}])
    r = exploit_agentic("pwn target", TriageConfig(), c,
                        exec_tool=lambda n, a: "x",
                        is_solved=lambda: False, max_steps=2)
    assert not r.solved and r.steps == 2


def test_self_verified_guards():
    verified = {"role": "assistant", "content": "VERIFIED: uid=0(root) gid=0(root)"}
    prior_turn = {"role": "assistant", "content": "recon: nginx on :443"}
    user = {"role": "user", "content": "task"}
    # valid: prior activity, real evidence
    assert _self_verified([SYS, user, prior_turn, verified])
    # first-turn echo of the instruction can never fire (no prior activity)
    assert not _self_verified([SYS, user, verified])
    # placeholder / short evidence rejected
    short = {"role": "assistant", "content": "VERIFIED: <the evidence>"}
    assert not _self_verified([SYS, user, prior_turn, short])
    # latest narrative without the marker blocks even an older VERIFIED line
    narrate = {"role": "assistant", "content": "still probing the endpoint"}
    assert not _self_verified([SYS, user, prior_turn, verified, narrate])


def test_progress_prints_narration_for_bridge_style_endpoints(capsys):
    c = _exploit_client([{"content": "Recon: nginx/1.24, /admin returns 403",
                          "tool_calls": []}])
    run_agent([SYS], c, tools=[], exec_tool=lambda n, a: "x", max_steps=1,
              check_done=lambda: None, progress=True, progress_label="exploit")
    out = capsys.readouterr().out
    assert "[exploit] · Recon: nginx/1.24, /admin returns 403" in out


# --- live output: budget banner + narration alongside tool calls ----------------

def test_budget_suffix_reports_real_deadline_and_attempts():
    from velora.sil.llm_agent import _budget_suffix
    from velora.sil.llm_client import LLMClient

    c = LLMClient(LLMConfig(base_url="http://127.0.0.1:9/v1", model="m",
                             agent_timeout=300, agent_retries=2))
    assert _budget_suffix(c) == " (deadline 600s/attempt, 3 attempts)"
    # fake/custom clients without the transport surface get no suffix
    assert _budget_suffix(_FlakyClient(fails=0)) == ""


def test_step_banner_carries_transport_budget(capsys):
    """The step banner must tell the operator the real per-step budget."""
    from velora.sil.llm_client import LLMClient

    c = _FlakyClient(fails=0, script=[_tool_call("curl t")])
    real = LLMClient(LLMConfig(base_url="http://127.0.0.1:9/v1", model="m",
                                agent_timeout=300, agent_retries=2))
    real.chat_raw = c.chat_raw          # budget from the real transport, calls scripted
    run_agent([SYS], real, tools=[], exec_tool=lambda n, a: "x", max_steps=1,
              check_done=lambda: None, progress=True, progress_label="exploit")
    out = capsys.readouterr().out
    assert "step 1/1: thinking... (deadline 600s/attempt, 3 attempts)" in out


def test_narration_prints_alongside_tool_calls(capsys):
    """Bridge-style turns that narrate AND call tools must show both live —
    narration was previously held back until the turn ended."""
    c = _exploit_client([{"content": "Recon: /admin is 403, probing login",
                          "tool_calls": [{"id": "1", "function": {
                              "name": "run",
                              "arguments": json.dumps({"cmd": "curl -s target/login"})}}]}])
    run_agent([SYS], c, tools=[], exec_tool=lambda n, a: "ran", max_steps=1,
              check_done=lambda: None, progress=True, progress_label="exploit")
    out = capsys.readouterr().out
    assert "[exploit] · Recon: /admin is 403, probing login" in out
    assert "[exploit] $ curl -s target/login" in out
