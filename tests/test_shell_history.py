"""FOR508 ex 2.5 — cmdscan / consoles shell-history surfacing tests.

The detector takes vol3 cmdscan / consoles rows and emits one umbrella
finding plus one finding per matched keyword pattern. The umbrella
finding must fire on any non-empty output (shell history alone is
the load-bearing signal); per-keyword findings lift their specific
ACH hypotheses so credential-dumping / lateral-movement / LOTL /
anti-forensics all separate correctly in the ranking.
"""
from __future__ import annotations

from pathlib import Path

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


def _ctx(tmp_path, monkeypatch, case_id="t-shell-history"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "mem.img"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


# ---------------------------------------------------------------------------
# Plugin-list wiring (the SRL-2018 / SRL-2015 bundles run these two now)
# ---------------------------------------------------------------------------

def test_win_plugins_includes_cmdscan_and_consoles():
    assert "windows.cmdscan.CmdScan" in WIN_PLUGINS
    assert "windows.consoles.Consoles" in WIN_PLUGINS


# ---------------------------------------------------------------------------
# Umbrella finding — fires on ANY non-empty output
# ---------------------------------------------------------------------------

def test_umbrella_fires_on_any_recovered_command(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    run = _plugin_run("windows.cmdscan.CmdScan", [
        {"Process": "cmd.exe", "PID": 1234, "Command": "ipconfig /all"},
    ], tmp_path)
    findings = MemoryForensicatorAgent()._flag_shell_history(
        ctx, "windows.cmdscan.CmdScan", run)
    assert findings, "umbrella must fire on any recovered command"
    umbrella = findings[0]
    assert "Shell history recovered from RAM" in umbrella.claim
    assert "H_LIVING_OFF_THE_LAND" in umbrella.hypotheses_supported
    assert "H_CODE_EXECUTION" in umbrella.hypotheses_supported


def test_no_finding_when_rows_have_no_text(tmp_path, monkeypatch):
    """Rows that contain only numeric fields (no string cells) → no
    shell-history finding. Prevents false-fire on plugin outputs whose
    Command/ScreenBuffer columns happened to be empty."""
    ctx = _ctx(tmp_path, monkeypatch)
    run = _plugin_run("windows.consoles.Consoles", [
        {"PID": 1234, "CommandCount": 0},
    ], tmp_path)
    findings = MemoryForensicatorAgent()._flag_shell_history(
        ctx, "windows.consoles.Consoles", run)
    assert findings == []


def test_multiline_screen_buffer_splits_into_lines(tmp_path, monkeypatch):
    """consoles surfaces multi-line screen buffers; each line must be
    matched against the keyword library independently, otherwise a
    long buffer with one mimikatz line in the middle wouldn't trigger
    the credential-access lift."""
    ctx = _ctx(tmp_path, monkeypatch)
    run = _plugin_run("windows.consoles.Consoles", [
        {"ScreenBuffer": (
            "C:\\Users\\admin> dir\n"
            "Volume in drive C has no label.\n"
            "C:\\Users\\admin> mimikatz.exe\n"
            "  .#####.   mimikatz 2.2.0\n")},
    ], tmp_path)
    findings = MemoryForensicatorAgent()._flag_shell_history(
        ctx, "windows.consoles.Consoles", run)
    # Umbrella + at least one per-keyword finding
    assert any("Shell history recovered" in f.claim for f in findings)
    assert any("H_CREDENTIAL_ACCESS" in f.hypotheses_supported
               for f in findings)


# ---------------------------------------------------------------------------
# Keyword-driven hypothesis lifts
# ---------------------------------------------------------------------------

def test_mimikatz_lifts_credential_access(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    run = _plugin_run("windows.cmdscan.CmdScan", [
        {"Command": "mimikatz.exe sekurlsa::logonpasswords exit"},
    ], tmp_path)
    findings = MemoryForensicatorAgent()._flag_shell_history(
        ctx, "windows.cmdscan.CmdScan", run)
    cred = [f for f in findings
            if "H_CREDENTIAL_ACCESS" in f.hypotheses_supported]
    assert cred, "mimikatz line must produce H_CREDENTIAL_ACCESS finding"


def test_psexec_lifts_lateral_movement(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    run = _plugin_run("windows.cmdscan.CmdScan", [
        {"Command": "psexec \\\\target -u admin -p P@ss -d cmd.exe"},
    ], tmp_path)
    findings = MemoryForensicatorAgent()._flag_shell_history(
        ctx, "windows.cmdscan.CmdScan", run)
    lateral = [f for f in findings
               if "H_LATERAL_MOVEMENT" in f.hypotheses_supported]
    assert lateral, "psexec line must produce H_LATERAL_MOVEMENT finding"


def test_powershell_enc_lifts_lotl(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    run = _plugin_run("windows.cmdscan.CmdScan", [
        {"Command": "powershell -enc QQBCAEMA"},
    ], tmp_path)
    findings = MemoryForensicatorAgent()._flag_shell_history(
        ctx, "windows.cmdscan.CmdScan", run)
    lotl = [f for f in findings
            if "H_LIVING_OFF_THE_LAND" in f.hypotheses_supported]
    # Both the umbrella and the keyword finding tag LOTL; we want at
    # least two LOTL-tagged findings (umbrella + keyword) to confirm
    # the per-keyword path actually fired.
    assert len(lotl) >= 2


def test_wevtutil_cl_lifts_anti_forensics(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    run = _plugin_run("windows.cmdscan.CmdScan", [
        {"Command": "wevtutil cl Security"},
    ], tmp_path)
    findings = MemoryForensicatorAgent()._flag_shell_history(
        ctx, "windows.cmdscan.CmdScan", run)
    af = [f for f in findings
          if "H_ANTI_FORENSICS" in f.hypotheses_supported]
    assert af, "wevtutil cl must produce H_ANTI_FORENSICS finding"


def test_benign_session_only_gets_umbrella(tmp_path, monkeypatch):
    """A purely benign session (dir, cd, ipconfig) should still produce
    the umbrella finding — the operator presence is the signal — but
    NOT lift credential-access / lateral-movement / anti-forensics."""
    ctx = _ctx(tmp_path, monkeypatch)
    run = _plugin_run("windows.cmdscan.CmdScan", [
        {"Command": "dir C:\\Users"},
        {"Command": "cd C:\\Temp"},
        {"Command": "ipconfig"},
    ], tmp_path)
    findings = MemoryForensicatorAgent()._flag_shell_history(
        ctx, "windows.cmdscan.CmdScan", run)
    # Exactly one finding (the umbrella) — no keyword matches
    assert len(findings) == 1
    f = findings[0]
    assert "H_LIVING_OFF_THE_LAND" in f.hypotheses_supported
    assert "H_CREDENTIAL_ACCESS" not in f.hypotheses_supported
    assert "H_LATERAL_MOVEMENT" not in f.hypotheses_supported
    assert "H_ANTI_FORENSICS" not in f.hypotheses_supported


def test_keyword_deduplication_caps_per_label(tmp_path, monkeypatch):
    """50 mimikatz lines must NOT produce 50 findings — one per
    (hypothesis, label) pair is the contract. Otherwise a single
    long-running mimikatz session floods the ledger."""
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [{"Command": f"mimikatz #{i} sekurlsa::logonpasswords"}
            for i in range(50)]
    run = _plugin_run("windows.cmdscan.CmdScan", rows, tmp_path)
    findings = MemoryForensicatorAgent()._flag_shell_history(
        ctx, "windows.cmdscan.CmdScan", run)
    # Umbrella + ONE finding per matched label ("mimikatz" and "sekurlsa::")
    # — the regex matches both on every line, but the dedup table is
    # keyed on (hypothesis, label) so the count stays bounded.
    cred = [f for f in findings
            if "H_CREDENTIAL_ACCESS" in f.hypotheses_supported]
    # at most 2 cred findings (mimikatz label + sekurlsa:: label)
    assert len(cred) <= 2
