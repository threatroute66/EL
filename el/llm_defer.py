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
"""
from __future__ import annotations

import os

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


__all__ = [
    "CLAUDE_CODE_ENV",
    "running_inside_claude_code",
    "defer_enabled",
    "claude_code_path_enabled",
    "deferral_trigger",
]
