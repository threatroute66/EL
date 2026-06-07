"""Shared Claude Code deferral detection.

EL has LLM-augmented steps (the executive brief, the red-review
adversarial challenger) that normally call the Anthropic SDK in-process
when ``ANTHROPIC_API_KEY`` is set. When the key is *absent* but EL is
running inside a Claude Code session, there is still a model available —
the orchestrating session itself. Rather than silently skipping the LLM
work, EL writes a self-describing request file and lets a Claude Code
skill fulfil it out-of-band (the same model, a different transport).

This module is the single source of truth for *"should we take the
Claude Code deferral path?"* so every LLM call site answers it the same
way. Both ``el/reporting/executive_ai.py`` (the executive brief) and
``el/agents/red_reviewer.py`` (the adversarial challenger) consume it.

It also provides the **headless fulfilment backend** (``run_headless_claude``):
a detached/background run has no live assistant to fulfil a deferred
request, so the request file would sit forever. When the ``claude`` binary
is installed, that run can instead shell out to ``claude -p`` (one-shot,
uses the operator's Claude Code auth — no API key) and generate the LLM
output in-process. ``should_use_headless_cli`` is the shared gate; every
call site uses it so detached runs behave identically across the executive
brief, the combined brief, and any future LLM step.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

# Claude Code sets CLAUDECODE=1 in the subprocess environment of any tool
# it launches. Older builds only set AI_AGENT=claude-code_… — we honour
# both so a run launched from any Claude Code version is detected.
CLAUDE_CODE_ENV = "CLAUDECODE"

_TRUTHY = {"1", "true", "yes", "on"}


def running_inside_claude_code() -> bool:
    """True when EL is being executed from within a Claude Code session.

    Detection priority: CLAUDECODE=1 (the canonical marker), falling
    back to the AI_AGENT=claude-code_… prefix for older CLI versions.
    Both vars sit in the environment we inherited, so the check is free.
    """
    val = (os.environ.get(CLAUDE_CODE_ENV) or "").strip().lower()
    if val in _TRUTHY:
        return True
    agent = (os.environ.get("AI_AGENT") or "").strip().lower()
    return agent.startswith("claude-code")


def defer_enabled(env_var: str) -> bool:
    """True when the operator explicitly opted into the deferred path
    for a given call site via its env var (e.g. EL_AI_BRIEF_DEFER=1 or
    EL_RED_REVIEW_DEFER=1)."""
    return (os.environ.get(env_var) or "").strip().lower() in _TRUTHY


def claude_code_path_enabled(defer_env_var: str | None = None) -> bool:
    """The deferral path should fire when EITHER the operator explicitly
    opted in for this call site, OR EL was launched from inside a Claude
    Code session. Either way a request file should be written and a
    Claude model fulfils it out-of-band."""
    if defer_env_var and defer_enabled(defer_env_var):
        return True
    return running_inside_claude_code()


def deferral_trigger(defer_env_var: str | None = None) -> str:
    """Label for *why* the deferral fired — recorded in the request file
    so the skill (and any human reading it) can distinguish a Claude Code
    orchestrated run from an explicit operator opt-in."""
    if running_inside_claude_code():
        return "claude_code_session"
    if defer_env_var and defer_enabled(defer_env_var):
        return "explicit_defer_flag"
    return "unknown"


# ---------------------------------------------------------------------------
# Headless fulfilment backend — `claude -p`
# ---------------------------------------------------------------------------

# Env that marks a detached/background run (set by the `el … --detach` /
# auto-detach wrapper in cli.py). Such a run has CLAUDECODE riding along in
# its unit env but NO live assistant attached, so it must self-fulfil.
DETACHED_ENV = "EL_DETACHED"
# Generic opt-in for other headless contexts (cron, CI) that aren't detached
# EL runs but still have no interactive assistant.
HEADLESS_OPT_IN_ENV = "EL_AI_HEADLESS"
_HEADLESS_CLI = "claude"
_DEFAULT_HEADLESS_TIMEOUT = int(
    os.environ.get("EL_AI_HEADLESS_TIMEOUT", "240"))


def headless_cli_path() -> str | None:
    """Absolute path to the ``claude`` binary, or None if not installed.

    Checks ``$PATH`` plus the operator-local install dir Claude Code uses
    (``~/.local/bin/claude``) — a detached ``systemd --user`` unit may run
    with a trimmed PATH that omits it."""
    found = shutil.which(_HEADLESS_CLI)
    if found:
        return found
    local = Path.home() / ".local" / "bin" / _HEADLESS_CLI
    return str(local) if local.exists() else None


def should_use_headless_cli(opt_in_env: str | None = None) -> bool:
    """True when EL should self-fulfil an LLM step via headless
    ``claude -p`` rather than write a request file for an out-of-band
    responder.

    Fires only for runs with NO live assistant watching:
      * a detached/background run (``EL_DETACHED=1``), or
      * an explicit opt-in (``EL_AI_HEADLESS=1`` globally, or a
        call-site-specific ``opt_in_env``) for cron / CI contexts.
    An attached Claude Code session deliberately does NOT trigger this —
    there the el-ai-brief skill fulfils the request in the same session
    without spawning a nested headless process."""
    if headless_cli_path() is None:
        return False
    if defer_enabled(DETACHED_ENV):
        return True
    if defer_enabled(HEADLESS_OPT_IN_ENV):
        return True
    return bool(opt_in_env) and defer_enabled(opt_in_env)


def run_headless_claude(
    prompt: str, model: str,
    timeout: int | None = None,
) -> tuple[str | None, dict]:
    """Generate one-shot output via ``claude -p`` (headless, no API key —
    uses the operator's Claude Code auth).

    Returns ``(result_text, usage_dict)`` on success, or ``(None, {})`` on
    any failure (binary missing, non-zero exit, timeout, error envelope).
    The prompt is passed via stdin (not argv) to stay clear of ARG_MAX on
    large contexts. ``--output-format json`` is requested so token usage is
    available for the audit log; if the envelope can't be parsed the raw
    stdout is returned as the result text."""
    cli = headless_cli_path()
    if cli is None:
        return None, {}
    try:
        proc = subprocess.run(
            [cli, "-p", "--model", model, "--output-format", "json"],
            input=prompt, capture_output=True, text=True,
            timeout=timeout or _DEFAULT_HEADLESS_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None, {}
    # AUP blocks arrive as non-zero exit with the policy message in stderr
    # or inside the JSON envelope's "result" field.  Callers check for the
    # "aup_blocked" key in the returned usage dict to log the event distinctly
    # rather than treating it as a generic tool failure.
    _AUP_MARKERS = ("usage policy", "aup", "acceptable use", "violates our")
    if proc.returncode != 0:
        stderr_lower = (proc.stderr or "").lower()
        if any(m in stderr_lower for m in _AUP_MARKERS):
            return None, {"aup_blocked": True}
        return None, {}
    text, usage = proc.stdout, {}
    try:
        env = json.loads(proc.stdout)
        if isinstance(env, dict):
            if env.get("is_error"):
                result_lower = (env.get("result") or "").lower()
                if any(m in result_lower for m in _AUP_MARKERS):
                    return None, {"aup_blocked": True}
                return None, {}
            text = env.get("result", proc.stdout)
            usage = env.get("usage") or {}
    except json.JSONDecodeError:
        pass
    if not (text or "").strip():
        return None, {}
    return text, usage


__all__ = [
    "CLAUDE_CODE_ENV",
    "DETACHED_ENV",
    "HEADLESS_OPT_IN_ENV",
    "running_inside_claude_code",
    "defer_enabled",
    "claude_code_path_enabled",
    "deferral_trigger",
    "headless_cli_path",
    "should_use_headless_cli",
    "run_headless_claude",
]
