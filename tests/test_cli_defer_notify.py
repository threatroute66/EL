"""End-of-investigate notification for the deferred AI-brief workflow.

Covers the bridge between EL's defer mode and Claude Code's
`el-ai-brief` skill: when `el investigate --defer-ai-brief` runs in
an environment without `ANTHROPIC_API_KEY`, the CLI must print a
discoverable message naming the request file + the slash command
to invoke. Without `--defer-ai-brief` (or with an API key), the
notification must stay silent — it's not a marketing line, it's a
do-this-next pointer that only appears when work is actually pending.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from el.cli import app
from el.evidence import intake as intake_mod
from el.reporting.executive_ai import _REQUEST_FILENAME


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("EL_AI_BRIEF_DEFER", raising=False)
    yield tmp_path


def test_notification_fires_when_defer_flag_set(isolated):
    """End-to-end: invoke `el investigate --defer-ai-brief` on a
    trivial input with no API key. The notification must mention
    /el-ai-brief and the request file path."""
    runner = CliRunner()
    src = isolated / "fake.bin"
    src.write_bytes(b"x")

    result = runner.invoke(
        app,
        ["investigate", str(src), "--case-id", "defer-notify-test",
         "--defer-ai-brief"],
    )
    assert result.exit_code == 0, result.output

    # Notification surface
    assert "/el-ai-brief" in result.output
    assert "Pending AI executive brief" in result.output

    # Request file must actually exist where the notification claims
    case_dir = isolated / "cases" / "defer-notify-test"
    req = case_dir / "reports" / _REQUEST_FILENAME
    assert req.is_file(), "defer flag must produce a request file"
    payload = json.loads(req.read_text())
    assert payload["request_version"] == 1
    assert payload["cache_key"]


def test_notification_silent_without_defer_flag(isolated):
    """No --defer-ai-brief flag, no API key: no request file, and
    the notification must not appear (silence is the contract when
    there is no pending work)."""
    runner = CliRunner()
    src = isolated / "fake.bin"
    src.write_bytes(b"x")

    result = runner.invoke(
        app,
        ["investigate", str(src), "--case-id", "no-defer-test"],
    )
    assert result.exit_code == 0, result.output
    assert "Pending AI executive brief" not in result.output
    assert "/el-ai-brief" not in result.output

    case_dir = isolated / "cases" / "no-defer-test"
    req = case_dir / "reports" / _REQUEST_FILENAME
    assert not req.exists()


def test_notification_silent_when_api_key_present(isolated, monkeypatch):
    """With an API key (and the SDK stubbed so we don't actually hit
    the network), the direct API path is used — no request file
    written, no notification.

    Stubs the SDK so the AI brief produces an empty (rejected)
    response and the renderer falls back to the deterministic
    digest — that's fine; the contract here is that the *defer
    request file* must not appear when an API key was set."""
    import anthropic

    class _NopMessages:
        def create(self, **kwargs):
            class _B:
                text = "not json"
                type = "text"
            class _M:
                content = [_B()]
            return _M()

    class _NopClient:
        def __init__(self, **kwargs):
            self.messages = _NopMessages()

    monkeypatch.setattr(anthropic, "Anthropic", _NopClient)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-stub-key")

    runner = CliRunner()
    src = isolated / "fake.bin"
    src.write_bytes(b"x")
    result = runner.invoke(
        app,
        ["investigate", str(src), "--case-id", "with-api-key-test",
         "--defer-ai-brief"],
    )
    assert result.exit_code == 0, result.output
    # defer + API key → API key wins; no request file, no notification
    assert "Pending AI executive brief" not in result.output
    case_dir = isolated / "cases" / "with-api-key-test"
    req = case_dir / "reports" / _REQUEST_FILENAME
    assert not req.exists()
