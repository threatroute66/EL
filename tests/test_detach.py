"""Contract tests for the --detach transient-service launcher.

Background: a 15-device SRL-2018 bundle launched with `nohup … &`
was killed mid-run when the operator's GUI session crashed and
restarted. nohup blocks SIGHUP but NOT the SIGKILL systemd sends to
every PID in a login-session cgroup at session teardown. el-serve
(a systemd --user service) survived because it lives in its own
unit outside the session scope.

`_maybe_detach` re-launches the el invocation as a systemd --user
transient service so long runs get that same durability. These
tests verify the control flow without actually spawning systemd
units (subprocess.run is stubbed).
"""
from __future__ import annotations

import subprocess

import pytest
import typer

from el import cli


def test_noop_when_detach_false(monkeypatch):
    """detach=False → return immediately, never touch subprocess."""
    called = {"run": False}
    monkeypatch.setattr(subprocess, "run",
                         lambda *a, **k: called.__setitem__("run", True))
    # Should not raise, should not spawn
    cli._maybe_detach(False, "investigate-x")
    assert called["run"] is False


def test_noop_when_already_detached(monkeypatch):
    """EL_DETACHED=1 guard → run in-process (the re-exec'd unit must
    NOT recurse into another systemd-run)."""
    monkeypatch.setenv("EL_DETACHED", "1")
    called = {"run": False}
    monkeypatch.setattr(subprocess, "run",
                         lambda *a, **k: called.__setitem__("run", True))
    cli._maybe_detach(True, "investigate-x")
    assert called["run"] is False


def test_foreground_fallback_when_systemd_run_missing(monkeypatch):
    """systemd-run absent → warn + return (degrade to foreground),
    do NOT raise Exit. Better to run attached than not at all."""
    monkeypatch.delenv("EL_DETACHED", raising=False)
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    # Should return normally (no Exit raised) — foreground fallback
    cli._maybe_detach(True, "investigate-x")


def test_spawns_transient_unit_and_exits(monkeypatch):
    """Happy path: detach=True + systemd-run present + not already
    detached → build the systemd-run command, spawn it, raise
    typer.Exit(0)."""
    monkeypatch.delenv("EL_DETACHED", raising=False)
    import shutil
    monkeypatch.setattr(shutil, "which",
                         lambda name: "/usr/bin/systemd-run"
                         if name == "systemd-run" else None)

    captured = {}

    def fake_run(cmd, *a, **k):
        captured["cmd"] = cmd
        class _R:
            returncode = 0
        return _R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    # Control argv so the reconstruction is deterministic
    monkeypatch.setattr(
        "sys.argv",
        ["/opt/EL/.venv/bin/el", "investigate-bundle", "srl", "-d", "x:y"])

    with pytest.raises(typer.Exit) as ei:
        cli._maybe_detach(True, "bundle-srl")
    assert ei.value.exit_code == 0

    cmd = captured["cmd"]
    # Built the right shape
    assert cmd[0] == "/usr/bin/systemd-run"
    assert "--user" in cmd
    assert "--collect" in cmd
    assert any(c.startswith("--unit=el-bundle-srl-") for c in cmd)
    assert "--setenv=EL_DETACHED=1" in cmd
    # The original argv is appended after the `--` separator
    sep = cmd.index("--")
    assert cmd[sep + 1] == "/opt/EL/.venv/bin/el"
    assert cmd[sep + 2:] == ["investigate-bundle", "srl", "-d", "x:y"]


def test_forwards_allowlisted_env(monkeypatch):
    """Env vars the detached unit needs (API key, malware-triage
    caps, …) are forwarded as --setenv since systemd --user services
    don't inherit the caller's shell env."""
    monkeypatch.delenv("EL_DETACHED", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-123")
    monkeypatch.setenv("EL_MALWARE_TRIAGE_MAX_DUMP_SIZE_MB", "128")
    import shutil
    monkeypatch.setattr(shutil, "which",
                         lambda name: "/usr/bin/systemd-run"
                         if name == "systemd-run" else None)
    captured = {}
    monkeypatch.setattr(subprocess, "run",
                         lambda cmd, *a, **k: captured.__setitem__("cmd", cmd)
                         or type("R", (), {"returncode": 0})())
    monkeypatch.setattr("sys.argv",
                         ["/opt/EL/.venv/bin/el", "investigate", "/ev"])

    with pytest.raises(typer.Exit):
        cli._maybe_detach(True, "investigate-case")

    cmd = captured["cmd"]
    assert "--setenv=ANTHROPIC_API_KEY=sk-test-123" in cmd
    assert "--setenv=EL_MALWARE_TRIAGE_MAX_DUMP_SIZE_MB=128" in cmd
    # Forwarded env vars must come BEFORE the `--` separator
    sep = cmd.index("--")
    for c in cmd:
        if c.startswith("--setenv=ANTHROPIC"):
            assert cmd.index(c) < sep


def test_forwards_claude_code_env_so_detached_run_emits_brief(monkeypatch):
    """The detached unit must inherit CLAUDECODE / session id so it
    still recognises Claude-Code orchestration and emits the deferred
    AI-brief request. Regression: an SRL-2015 --detach bundle produced
    no _ai_brief_request.json because these vars weren't forwarded."""
    monkeypatch.delenv("EL_DETACHED", raising=False)
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "sess-xyz")
    monkeypatch.setenv("AI_AGENT", "claude-code_2-1-139_agent")
    import shutil
    monkeypatch.setattr(shutil, "which",
                         lambda name: "/usr/bin/systemd-run"
                         if name == "systemd-run" else None)
    captured = {}
    monkeypatch.setattr(subprocess, "run",
                         lambda cmd, *a, **k: captured.__setitem__("cmd", cmd)
                         or type("R", (), {"returncode": 0})())
    monkeypatch.setattr("sys.argv",
                         ["/opt/EL/.venv/bin/el", "investigate-bundle", "b"])
    with pytest.raises(typer.Exit):
        cli._maybe_detach(True, "bundle-b")
    cmd = captured["cmd"]
    assert "--setenv=CLAUDECODE=1" in cmd
    assert "--setenv=CLAUDE_CODE_SESSION_ID=sess-xyz" in cmd
    assert "--setenv=AI_AGENT=claude-code_2-1-139_agent" in cmd


def test_foreground_fallback_when_spawn_fails(monkeypatch):
    """If systemd-run itself errors, degrade to foreground (return,
    don't raise) so the investigation still runs."""
    monkeypatch.delenv("EL_DETACHED", raising=False)
    import shutil
    monkeypatch.setattr(shutil, "which",
                         lambda name: "/usr/bin/systemd-run")

    def boom(cmd, *a, **k):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr("sys.argv",
                         ["/opt/EL/.venv/bin/el", "investigate", "/ev"])
    # Must NOT raise — falls through to foreground
    cli._maybe_detach(True, "investigate-case")
