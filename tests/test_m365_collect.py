"""M365 collector skill — unit tests.

Real Microsoft-Extractor-Suite invocation requires tenant credentials and
talks to the Microsoft Graph API. Tests cover env detection, opt-out path,
PowerShell snippet construction, and dataclass shape.
"""
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from el.skills import m365_collect as m


# --- is_configured ---------------------------------------------------

def test_is_configured_false_when_no_env(monkeypatch):
    for k in ("EL_M365_TENANT_ID", "EL_M365_APP_ID", "EL_M365_APP_SECRET",
               "EL_M365_USERNAME", "EL_M365_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    assert not m.is_configured()


def test_is_configured_true_with_app_creds(monkeypatch):
    monkeypatch.setenv("EL_M365_TENANT_ID", "tenant-guid")
    monkeypatch.setenv("EL_M365_APP_ID", "app-guid")
    monkeypatch.setenv("EL_M365_APP_SECRET", "secret")
    monkeypatch.delenv("EL_M365_USERNAME", raising=False)
    monkeypatch.delenv("EL_M365_PASSWORD", raising=False)
    assert m.is_configured()


def test_is_configured_true_with_userpass(monkeypatch):
    monkeypatch.setenv("EL_M365_TENANT_ID", "tenant-guid")
    monkeypatch.setenv("EL_M365_USERNAME", "alice@example.onmicrosoft.com")
    monkeypatch.setenv("EL_M365_PASSWORD", "p")
    monkeypatch.delenv("EL_M365_APP_ID", raising=False)
    monkeypatch.delenv("EL_M365_APP_SECRET", raising=False)
    assert m.is_configured()


def test_is_configured_false_without_tenant(monkeypatch):
    monkeypatch.delenv("EL_M365_TENANT_ID", raising=False)
    monkeypatch.setenv("EL_M365_APP_ID", "app-guid")
    monkeypatch.setenv("EL_M365_APP_SECRET", "s")
    assert not m.is_configured()


# --- collect: opt-out path -------------------------------------------

def test_collect_returns_unconfigured_when_no_env(tmp_path, monkeypatch):
    for k in ("EL_M365_TENANT_ID", "EL_M365_APP_ID", "EL_M365_APP_SECRET",
               "EL_M365_USERNAME", "EL_M365_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    result = m.collect(tmp_path / "out")
    assert result.configured is False
    assert "skipped" in result.note.lower() or "set EL_M365" in result.note


# --- _build_connect_command -----------------------------------------

def test_build_connect_uses_app_credentials(monkeypatch):
    monkeypatch.setenv("EL_M365_TENANT_ID", "tenant-guid")
    monkeypatch.setenv("EL_M365_APP_ID", "app-guid")
    monkeypatch.setenv("EL_M365_APP_SECRET", "secret-value")
    monkeypatch.delenv("EL_M365_USERNAME", raising=False)
    cmd = m._build_connect_command()
    assert "Connect-M365" in cmd
    assert "tenant-guid" in cmd
    assert "app-guid" in cmd
    assert "secret-value" in cmd


def test_build_connect_uses_userpass(monkeypatch):
    monkeypatch.setenv("EL_M365_TENANT_ID", "tenant")
    monkeypatch.setenv("EL_M365_USERNAME", "alice@example.com")
    monkeypatch.setenv("EL_M365_PASSWORD", "hunter2")
    monkeypatch.delenv("EL_M365_APP_ID", raising=False)
    monkeypatch.delenv("EL_M365_APP_SECRET", raising=False)
    cmd = m._build_connect_command()
    assert "Connect-M365" in cmd
    assert "alice@example.com" in cmd
    assert "hunter2" in cmd


def test_build_connect_raises_without_creds(monkeypatch):
    for k in ("EL_M365_APP_ID", "EL_M365_APP_SECRET",
               "EL_M365_USERNAME", "EL_M365_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("EL_M365_TENANT_ID", "tenant")
    with pytest.raises(m.M365CollectError):
        m._build_connect_command()


# --- collect with mocked pwsh ---------------------------------------

def test_collect_invokes_pwsh_with_full_script(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_M365_TENANT_ID", "tenant")
    monkeypatch.setenv("EL_M365_APP_ID", "app")
    monkeypatch.setenv("EL_M365_APP_SECRET", "secret")
    monkeypatch.delenv("EL_M365_USERNAME", raising=False)
    monkeypatch.delenv("EL_M365_PASSWORD", raising=False)

    captured: dict = {}

    class FakeCompleted:
        returncode = 0

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        # Simulate the JSON files Microsoft-Extractor-Suite would write.
        out_dir = tmp_path / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "ual.json").write_text("[]")
        (out_dir / "signins.json").write_text("[]")
        return FakeCompleted()

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    monkeypatch.setattr(m, "_pwsh", lambda: Path("/usr/bin/pwsh"))

    result = m.collect(tmp_path / "out")
    assert result.configured is True
    assert result.rc == 0
    assert result.auth_mode == "app"
    assert result.tenant_id == "tenant"
    # Should have invoked pwsh with the connect snippet + each command.
    script = captured["args"][-1]
    assert "Connect-M365" in script
    assert "Get-UAL" in script
    assert "Get-MailItemsAccessed" in script
    assert "Disconnect-M365" in script
    # Output dir gets quoted into the script.
    assert str(tmp_path / "out") in script.replace("''", "")
    # Two synthetic artifacts counted.
    assert result.artifact_count == 2


def test_collect_handles_pwsh_failure_rc(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_M365_TENANT_ID", "tenant")
    monkeypatch.setenv("EL_M365_APP_ID", "app")
    monkeypatch.setenv("EL_M365_APP_SECRET", "secret")

    class FakeFailing:
        returncode = 5

    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: FakeFailing())
    monkeypatch.setattr(m, "_pwsh", lambda: Path("/usr/bin/pwsh"))

    result = m.collect(tmp_path / "out")
    assert result.rc == 5
    assert "rc=5" in result.note


# --- as_evidence ------------------------------------------------------

def test_collection_as_evidence(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "ual.json").write_text("[]")
    coll = m.M365Collection(
        output_dir=out_dir,
        commands_run=["Get-UAL", "Get-EntraIDSignInLogs"],
        artifact_count=1, duration_seconds=42.5, rc=0,
        configured=True, tenant_id="tenant", auth_mode="app",
    )
    ev = coll.as_evidence()
    assert ev.tool == "m365_collect"
    assert ev.extracted_facts["artifact_count"] == 1
    assert ev.extracted_facts["auth_mode"] == "app"
    assert "Get-UAL" in ev.command


def test_collection_unconfigured_evidence_zero_pads(tmp_path):
    """When the output_dir doesn't exist on disk, sha is the zero sentinel."""
    coll = m.M365Collection(
        output_dir=tmp_path / "never-created", configured=False,
    )
    ev = coll.as_evidence()
    assert ev.output_sha256 == "0" * 64


# --- Real-binary smoke ----------------------------------------------

@pytest.mark.skipif(not __import__("shutil").which("pwsh"),
                    reason="pwsh not installed")
def test_pwsh_smoke():
    import subprocess
    r = subprocess.run(["pwsh", "--version"], capture_output=True, text=True,
                        timeout=10)
    assert "PowerShell" in (r.stdout + r.stderr)
