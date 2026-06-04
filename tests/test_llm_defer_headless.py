"""Contract for the shared headless fulfilment backend in el.llm_defer.

A detached/background EL run has CLAUDECODE riding along in its unit env
(so it *looks* like a Claude Code session and would defer) but has NO live
assistant attached to fulfil the request file. The headless backend lets
such a run self-fulfil via `claude -p`. These tests lock the gate
(should_use_headless_cli) and the subprocess envelope handling
(run_headless_claude) without spawning a real CLI.
"""
from __future__ import annotations

import json

import pytest

from el import llm_defer as ld


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    for var in ("EL_DETACHED", "EL_AI_HEADLESS", "EL_AI_BRIEF_HEADLESS",
                "CLAUDECODE", "AI_AGENT"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def cli_present(monkeypatch):
    monkeypatch.setattr(ld, "headless_cli_path", lambda: "/fake/bin/claude")


# ----- should_use_headless_cli gate ----------------------------------------

def test_gate_off_when_cli_absent(monkeypatch):
    monkeypatch.setattr(ld, "headless_cli_path", lambda: None)
    monkeypatch.setenv("EL_DETACHED", "1")
    assert ld.should_use_headless_cli() is False


def test_gate_on_when_detached(cli_present, monkeypatch):
    monkeypatch.setenv("EL_DETACHED", "1")
    assert ld.should_use_headless_cli() is True


def test_gate_off_for_attached_session(cli_present, monkeypatch):
    """An attached Claude Code session (CLAUDECODE only, not detached)
    must NOT self-fulfil — the el-ai-brief skill handles it in-session."""
    monkeypatch.setenv("CLAUDECODE", "1")
    assert ld.should_use_headless_cli() is False


def test_gate_on_with_global_opt_in(cli_present, monkeypatch):
    monkeypatch.setenv("EL_AI_HEADLESS", "1")
    assert ld.should_use_headless_cli() is True


def test_gate_on_with_call_site_opt_in(cli_present, monkeypatch):
    monkeypatch.setenv("EL_AI_BRIEF_HEADLESS", "1")
    assert ld.should_use_headless_cli("EL_AI_BRIEF_HEADLESS") is True
    # a different call-site env is NOT honoured by this gate call
    assert ld.should_use_headless_cli("EL_OTHER_HEADLESS") is False


# ----- run_headless_claude envelope handling -------------------------------

def _stub_run(monkeypatch, returncode=0, stdout=""):
    calls = []

    class _Proc:
        def __init__(self):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = ""

    def _fake(argv, input=None, **kw):
        calls.append({"argv": argv, "input": input, "timeout": kw.get("timeout")})
        return _Proc()

    monkeypatch.setattr(ld, "headless_cli_path", lambda: "/fake/bin/claude")
    monkeypatch.setattr(ld.subprocess, "run", _fake)
    return calls


def test_run_returns_text_and_usage(monkeypatch):
    out = json.dumps({"is_error": False, "result": "HELLO",
                      "usage": {"input_tokens": 10, "output_tokens": 3}})
    calls = _stub_run(monkeypatch, 0, out)
    text, usage = ld.run_headless_claude("prompt-body", "claude-sonnet-4-6")
    assert text == "HELLO"
    assert usage == {"input_tokens": 10, "output_tokens": 3}
    # prompt rides on stdin, model + json output-format on argv
    assert calls[0]["input"] == "prompt-body"
    assert "--output-format" in calls[0]["argv"] and "json" in calls[0]["argv"]
    assert "claude-sonnet-4-6" in calls[0]["argv"]


def test_run_nonzero_exit_returns_none(monkeypatch):
    _stub_run(monkeypatch, 1, "")
    assert ld.run_headless_claude("p", "m") == (None, {})


def test_run_error_envelope_returns_none(monkeypatch):
    _stub_run(monkeypatch, 0, json.dumps({"is_error": True, "result": ""}))
    assert ld.run_headless_claude("p", "m") == (None, {})


def test_run_empty_result_returns_none(monkeypatch):
    _stub_run(monkeypatch, 0, json.dumps({"is_error": False, "result": "  "}))
    assert ld.run_headless_claude("p", "m") == (None, {})


def test_run_raw_stdout_when_not_json(monkeypatch):
    """If the CLI ever drops the json envelope, treat stdout as the text."""
    _stub_run(monkeypatch, 0, "PLAINTEXT-REPLY")
    text, usage = ld.run_headless_claude("p", "m")
    assert text == "PLAINTEXT-REPLY"
    assert usage == {}


def test_run_no_cli_returns_none(monkeypatch):
    monkeypatch.setattr(ld, "headless_cli_path", lambda: None)
    assert ld.run_headless_claude("p", "m") == (None, {})
