"""Tests for vol3 extras: ssdt/driverirp plugins added to WIN_PLUGINS
+ kernel-hook detector (_flag_kernel_hooks)."""
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.memory_forensicator import MemoryForensicatorAgent, WIN_PLUGINS
from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger
from el.skills.vol3 import PluginRun


def _plugin_run(plugin: str, rows: list[dict], tmp_path: Path) -> PluginRun:
    stdout = tmp_path / f"{plugin.replace('.', '_')}.json"
    stdout.write_text("[]")
    return PluginRun(
        plugin=plugin, image=tmp_path / "mem.img", rc=0,
        stdout_path=stdout, stderr_path=tmp_path / f"{plugin}.stderr",
        rows=rows, command=["vol"], version="2.27.0",
    )


def _ctx(tmp_path, monkeypatch, case_id="t-hook"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


# ---------------------------------------------------------------------------
# Plugin list carries the new additions
# ---------------------------------------------------------------------------

def test_win_plugins_includes_ssdt_and_driverirp():
    assert "windows.ssdt.SSDT" in WIN_PLUGINS
    assert "windows.driverirp.DriverIrp" in WIN_PLUGINS
    assert "windows.filescan.FileScan" in WIN_PLUGINS
    assert "windows.mftscan.MFTScan" in WIN_PLUGINS


# ---------------------------------------------------------------------------
# SSDT hook detector
# ---------------------------------------------------------------------------

def test_ssdt_clean_table_produces_no_findings(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [
        {"Index": 0, "Address": "0xfffff80001", "Module": "ntoskrnl.exe"},
        {"Index": 1, "Address": "0xfffff80002", "Module": "ntoskrnl.exe"},
        {"Index": 2, "Address": "0xfffff90000", "Module": "win32k.sys"},
    ]
    run = _plugin_run("windows.ssdt.SSDT", rows, tmp_path)
    agent = MemoryForensicatorAgent()
    assert agent._flag_kernel_hooks(ctx, "windows.ssdt.SSDT", run) == []


def test_ssdt_hook_to_rootkit_module_flagged(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [
        {"Index": 0, "Address": "0xfffff80001", "Module": "ntoskrnl.exe"},
        {"Index": 14, "Address": "0xfffffa8000", "Module": "evilrootkit.sys"},
        {"Index": 15, "Address": "0xfffffa8000", "Module": "evilrootkit.sys"},
    ]
    run = _plugin_run("windows.ssdt.SSDT", rows, tmp_path)
    agent = MemoryForensicatorAgent()
    findings = agent._flag_kernel_hooks(ctx, "windows.ssdt.SSDT", run)
    assert findings
    assert findings[0].confidence == "high"
    assert "H_ROOTKIT" in findings[0].hypotheses_supported
    assert "evilrootkit.sys" in findings[0].claim


def test_ssdt_unknown_module_flagged(tmp_path, monkeypatch):
    """vol3 can't resolve an address to a driver → it reports 'UNKNOWN'
    or blank. That itself is a rootkit smell (address lives in unlinked
    memory); we flag it."""
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [
        {"Index": 0, "Address": "0xfffffa9000", "Module": "UNKNOWN"},
    ]
    run = _plugin_run("windows.ssdt.SSDT", rows, tmp_path)
    findings = MemoryForensicatorAgent()._flag_kernel_hooks(
        ctx, "windows.ssdt.SSDT", run)
    assert findings


def test_ssdt_case_insensitive_module_match(tmp_path, monkeypatch):
    """Some vol3 versions render module names with different casing."""
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [
        {"Index": 0, "Address": "0xfffff80001", "Module": "NTOSKRNL.EXE"},
        {"Index": 1, "Address": "0xfffff80002", "Module": "Hal.dll"},
    ]
    run = _plugin_run("windows.ssdt.SSDT", rows, tmp_path)
    assert MemoryForensicatorAgent()._flag_kernel_hooks(
        ctx, "windows.ssdt.SSDT", run) == []


# ---------------------------------------------------------------------------
# DriverIrp hook detector (same logic, different plugin name)
# ---------------------------------------------------------------------------

def test_driverirp_hook_flagged(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [
        {"IRP": 0, "Address": "0xf00", "Module": "ntoskrnl.exe"},
        {"IRP": 14, "Address": "0xbad", "Module": "malware.sys"},
    ]
    run = _plugin_run("windows.driverirp.DriverIrp", rows, tmp_path)
    findings = MemoryForensicatorAgent()._flag_kernel_hooks(
        ctx, "windows.driverirp.DriverIrp", run)
    assert findings
    assert "malware.sys" in findings[0].claim


def test_driverirp_uses_owner_column_too(tmp_path, monkeypatch):
    """DriverIrp on some vol3 versions uses 'Owner' rather than
    'Module'. Detector must accept both."""
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [
        {"IRP": 0, "Address": "0xf00", "Owner": "ntoskrnl.exe"},
        {"IRP": 14, "Address": "0xbad", "Owner": "rootkit.sys"},
    ]
    run = _plugin_run("windows.driverirp.DriverIrp", rows, tmp_path)
    findings = MemoryForensicatorAgent()._flag_kernel_hooks(
        ctx, "windows.driverirp.DriverIrp", run)
    assert findings


def test_empty_rows_no_findings(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    run = _plugin_run("windows.ssdt.SSDT", [], tmp_path)
    assert MemoryForensicatorAgent()._flag_kernel_hooks(
        ctx, "windows.ssdt.SSDT", run) == []
