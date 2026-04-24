"""Coordinator signal guard — SIGTERM/SIGINT must be visible in the
forensic audit log before the process dies.

Background: two SRL-2018 memory runs OOM-killed silently under
concurrent load. The audit log stopped at `parallel_investigate` with
no `agent_failed` entry, leaving the analyst blind to why the case
never reached DONE. SIGKILL (OOM) is untraceable from Python, but
SIGTERM and SIGINT are trappable, and any graceful kill must leave
a breadcrumb in the log.
"""
import signal
from pathlib import Path

import pytest

from el.audit import AuditLog
from el.orchestrator.coordinator import Coordinator
from el.orchestrator.states import State


def _make_audit(tmp_path: Path) -> AuditLog:
    case_dir = tmp_path / "case"
    (case_dir / "analysis").mkdir(parents=True, exist_ok=True)
    return AuditLog(case_dir, "test-case")


def test_sigterm_logs_coordinator_signalled_and_raises_systemexit(tmp_path):
    c = Coordinator()
    c.audit = _make_audit(tmp_path)
    c.state = State.PARALLEL_INVESTIGATE
    c._current_agent = "MemoryForensicatorAgent"

    with pytest.raises(SystemExit) as exc:
        c._on_signal(signal.SIGTERM, None)
    assert exc.value.code == 128 + signal.SIGTERM

    log = (tmp_path / "case" / "analysis" / "forensic_audit.log").read_text()
    assert "coordinator_signalled" in log
    assert "SIGTERM" in log
    assert "parallel_investigate" in log
    assert "MemoryForensicatorAgent" in log


def test_sigint_logs_and_raises_keyboardinterrupt(tmp_path):
    c = Coordinator()
    c.audit = _make_audit(tmp_path)
    c.state = State.CORRELATE
    c._current_agent = None  # between agents

    with pytest.raises(KeyboardInterrupt):
        c._on_signal(signal.SIGINT, None)

    log = (tmp_path / "case" / "analysis" / "forensic_audit.log").read_text()
    assert "coordinator_signalled" in log
    assert "SIGINT" in log
    assert "correlate" in log
    assert "(between agents)" in log


def test_install_uninstall_restores_handlers():
    default_term = signal.getsignal(signal.SIGTERM)
    default_int = signal.getsignal(signal.SIGINT)

    c = Coordinator()
    c._install_signal_handlers()
    assert signal.getsignal(signal.SIGTERM) == c._on_signal
    assert signal.getsignal(signal.SIGINT) == c._on_signal

    c._uninstall_signal_handlers()
    assert signal.getsignal(signal.SIGTERM) == default_term
    assert signal.getsignal(signal.SIGINT) == default_int


def test_run_agent_tracks_current_agent(tmp_path):
    """_current_agent must be set while an agent is running and cleared
    after (including on exception). This is what the signal handler
    reports as the last-known agent."""
    class _OK:
        name = "OKAgent"
        def run(self, ctx):
            return []

    class _Boom:
        name = "BoomAgent"
        def run(self, ctx):
            raise RuntimeError("boom")

    c = Coordinator()
    c.audit = _make_audit(tmp_path)

    # Capture during run via a side-channel: inject a fake agent whose
    # .run() reads c._current_agent mid-flight.
    seen = {}
    class _Spy:
        name = "SpyAgent"
        def run(self, ctx):
            seen["mid"] = c._current_agent
            return []

    c._run_agent(_Spy(), ctx=None)
    assert seen["mid"] == "SpyAgent", "current_agent must be set during run()"
    assert c._current_agent is None, "current_agent must clear after success"

    with pytest.raises(RuntimeError):
        c._run_agent(_Boom(), ctx=None)
    assert c._current_agent is None, "current_agent must clear after exception"
