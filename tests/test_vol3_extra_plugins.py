"""T3-1 tests: vol3 modules/modscan/ldrmodules/handles/getsids wiring.

Pure unit tests for the two diff detectors — the other three plugins
(cmdline-handles-getsids) contribute rows for correlation later but
don't gain their own detector at this tier, so the test coverage
focuses on the diff-based findings (rootkit drivers + unlinked DLLs).
"""
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.memory_forensicator import MemoryForensicatorAgent, WIN_PLUGINS
from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger
from el.skills.vol3 import PluginRun


def _plugin_run(plugin: str, rows: list[dict], tmp_path: Path) -> PluginRun:
    """Build a PluginRun whose stdout file exists (as_evidence reads it
    for hashing). Rows live in memory; the JSON file is empty."""
    stdout = tmp_path / f"{plugin.replace('.', '_')}.json"
    stdout.write_text("[]")
    return PluginRun(
        plugin=plugin, image=tmp_path / "mem.img", rc=0,
        stdout_path=stdout, stderr_path=tmp_path / f"{plugin}.stderr",
        rows=rows, command=["vol"], version="2.27.0",
    )


def _ctx(tmp_path, monkeypatch, case_id="t-vol3-extra"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


# ---------------------------------------------------------------------------
# Plugin list now carries the 5 new plugin names
# ---------------------------------------------------------------------------

def test_win_plugins_includes_t3_1_additions():
    assert "windows.modules.Modules" in WIN_PLUGINS
    assert "windows.modscan.ModScan" in WIN_PLUGINS
    assert "windows.ldrmodules.LdrModules" in WIN_PLUGINS
    assert "windows.handles.Handles" in WIN_PLUGINS
    assert "windows.getsids.GetSIDs" in WIN_PLUGINS


# ---------------------------------------------------------------------------
# _diff_hidden_drivers
# ---------------------------------------------------------------------------

def test_hidden_drivers_detected_when_modscan_has_extra(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    modules = _plugin_run("windows.modules.Modules", [
        {"Name": "ntoskrnl.exe"},
        {"Name": "hal.dll"},
        {"Name": "tcpip.sys"},
    ], tmp_path)
    modscan = _plugin_run("windows.modscan.ModScan", [
        {"Name": "ntoskrnl.exe"},
        {"Name": "hal.dll"},
        {"Name": "tcpip.sys"},
        {"Name": "evilrootkit.sys"},      # hidden: in scan, not in walk
        {"Name": "another.sys"},
    ], tmp_path)
    agent = MemoryForensicatorAgent()
    findings = agent._diff_hidden_drivers(ctx, modules, modscan)
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert "H_ROOTKIT" in findings[0].hypotheses_supported
    assert "evilrootkit.sys" in findings[0].claim


def test_hidden_drivers_silent_when_sets_match(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [{"Name": "ntoskrnl.exe"}, {"Name": "hal.dll"}]
    modules = _plugin_run("windows.modules.Modules", rows, tmp_path)
    modscan = _plugin_run("windows.modscan.ModScan", rows, tmp_path)
    agent = MemoryForensicatorAgent()
    assert agent._diff_hidden_drivers(ctx, modules, modscan) == []


def test_hidden_drivers_insufficient_when_modules_empty(tmp_path, monkeypatch):
    """Parallels the hidden-process-diff guard: empty modules means
    tool failure, not "all drivers unlinked"."""
    ctx = _ctx(tmp_path, monkeypatch)
    modules = _plugin_run("windows.modules.Modules", [], tmp_path)
    modscan = _plugin_run("windows.modscan.ModScan",
                           [{"Name": "anything"}], tmp_path)
    agent = MemoryForensicatorAgent()
    findings = agent._diff_hidden_drivers(ctx, modules, modscan)
    assert findings and findings[0].confidence == "insufficient"


def test_hidden_drivers_ignores_anonymous_rows(tmp_path, monkeypatch):
    """Some vol3 rows come back with no Name/FullDllName/Path. Those
    shouldn't poison the set comparison with empty-string membership."""
    ctx = _ctx(tmp_path, monkeypatch)
    modules = _plugin_run("windows.modules.Modules", [
        {"Name": "ntoskrnl.exe"}, {"Offset": "0x123"},    # anon row
    ], tmp_path)
    modscan = _plugin_run("windows.modscan.ModScan", [
        {"Name": "ntoskrnl.exe"}, {"Offset": "0x456"},    # anon row
    ], tmp_path)
    agent = MemoryForensicatorAgent()
    # No real hidden driver — anon rows don't create a spurious hit
    assert agent._diff_hidden_drivers(ctx, modules, modscan) == []


# ---------------------------------------------------------------------------
# _flag_unlinked_dlls
# ---------------------------------------------------------------------------

def test_unlinked_dll_detected_asymmetric_list_membership(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [
        # Normal loader state — all three lists have it
        {"Pid": 100, "Process": "chrome.exe",
         "InLoad": True, "InInit": True, "InMem": True,
         "BaseName": "chrome.dll"},
        # Reflective-injection shape: missing from InLoad
        {"Pid": 7777, "Process": "svchost.exe",
         "InLoad": False, "InInit": True, "InMem": True,
         "BaseName": "meterpreter.dll"},
        # Another injected DLL in the same process
        {"Pid": 7777, "Process": "svchost.exe",
         "InLoad": False, "InInit": False, "InMem": True,
         "BaseName": "cs-beacon.dll"},
    ]
    run = _plugin_run("windows.ldrmodules.LdrModules", rows, tmp_path)
    agent = MemoryForensicatorAgent()
    findings = agent._flag_unlinked_dlls(ctx, run)
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert "H_PROCESS_INJECTION" in findings[0].hypotheses_supported
    assert "PID 7777" in findings[0].claim


def test_unlinked_dll_silent_on_all_true_rows(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [{"Pid": 100, "Process": "x.exe",
              "InLoad": True, "InInit": True, "InMem": True,
              "BaseName": f"d{i}.dll"} for i in range(50)]
    run = _plugin_run("windows.ldrmodules.LdrModules", rows, tmp_path)
    agent = MemoryForensicatorAgent()
    assert agent._flag_unlinked_dlls(ctx, run) == []


def test_unlinked_dll_silent_on_all_false_rows(tmp_path, monkeypatch):
    """All three lists False is not injection — it's tool failure /
    exited process. Detector must not false-fire."""
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [{"Pid": i, "Process": "x.exe",
              "InLoad": False, "InInit": False, "InMem": False,
              "BaseName": f"d{i}.dll"} for i in range(5)]
    run = _plugin_run("windows.ldrmodules.LdrModules", rows, tmp_path)
    agent = MemoryForensicatorAgent()
    assert agent._flag_unlinked_dlls(ctx, run) == []


def test_unlinked_dll_accepts_string_bool_forms(tmp_path, monkeypatch):
    """vol3 JSON sometimes renders bools as strings 'True'/'False'."""
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [
        {"Pid": 1, "Process": "x", "InLoad": "False",
         "InInit": "True", "InMem": "True"},
    ]
    run = _plugin_run("windows.ldrmodules.LdrModules", rows, tmp_path)
    agent = MemoryForensicatorAgent()
    findings = agent._flag_unlinked_dlls(ctx, run)
    assert findings
