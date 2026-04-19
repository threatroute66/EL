"""PR-H: Hunt-Evil "Know Normal" process-tree anomaly matrix tests.

Tests the el.skills.process_profile.analyze() function against pslist-
shaped rows. Positive (abnormal process tree → anomaly fires) and
negative (clean Win10 pslist → no anomalies) coverage.
"""
import pytest

from el.skills.process_profile import ProcessAnomaly, analyze


def _row(name: str, pid: int, ppid: int, session: int = 0) -> dict:
    """Shape matches vol3 windows.pslist.PsList output."""
    return {
        "PID": pid, "PPID": ppid, "ImageFileName": name,
        "SessionId": session, "CreateTime": "2023-01-01T00:00:00+00:00",
        "ExitTime": None, "Threads": 1, "Handles": 1, "Wow64": False,
    }


def _clean_win10() -> list[dict]:
    """Minimal clean Win10 process tree satisfying every expected-profile
    rule. Based on Hunt Evil page 1."""
    return [
        _row("System",             4,    0),
        _row("smss.exe",           404,  4),
        _row("csrss.exe",          520,  404),      # Session 0
        _row("csrss.exe",          620,  404, 1),   # Session 1
        _row("wininit.exe",        580,  404),
        _row("services.exe",       700,  580),
        _row("lsass.exe",          720,  580),
        _row("winlogon.exe",       680,  404, 1),
        _row("svchost.exe",        900,  700),
        _row("svchost.exe",        920,  700),
        _row("svchost.exe",        940,  700),
        _row("svchost.exe",        960,  700),
        _row("runtimebroker.exe",  1100, 900),
        _row("taskhostw.exe",      1200, 900),
        _row("explorer.exe",       1500, 9999),     # userinit exited: PPID missing
        _row("chrome.exe",         2000, 1500),
    ]


# ---------------------------------------------------------------------------
# Clean-baseline guard
# ---------------------------------------------------------------------------

def test_clean_win10_tree_produces_no_anomalies():
    assert analyze(_clean_win10()) == []


# ---------------------------------------------------------------------------
# Singleton / count anomalies
# ---------------------------------------------------------------------------

def test_two_lsass_processes_flagged_high_priority():
    rows = _clean_win10() + [_row("lsass.exe", 7777, 580)]
    out = analyze(rows)
    lsass = [a for a in out if a.image_name == "lsass.exe"]
    assert lsass and lsass[0].reason == "count_high"
    assert "H_CREDENTIAL_ACCESS" in lsass[0].hypotheses


def test_two_services_exe_flagged():
    rows = _clean_win10() + [_row("services.exe", 8000, 580)]
    out = analyze(rows)
    services = [a for a in out if a.image_name == "services.exe"]
    assert services and services[0].reason == "count_high"


def test_two_wininit_exe_flagged():
    rows = _clean_win10() + [_row("wininit.exe", 8100, 404)]
    out = analyze(rows)
    wininit = [a for a in out if a.image_name == "wininit.exe"
               and a.reason == "count_high"]
    assert wininit


def test_missing_lsass_flagged_as_process_missing():
    """lsass.exe terminated (operator killed it after cred dump)."""
    rows = [r for r in _clean_win10() if r["ImageFileName"] != "lsass.exe"]
    out = analyze(rows)
    lsass = [a for a in out if a.image_name == "lsass.exe"]
    assert lsass and lsass[0].reason == "process_missing"


def test_csrss_min_count_respected():
    """csrss.exe needs ≥2. Single instance triggers count_low."""
    rows = [r for r in _clean_win10() if not
            (r["ImageFileName"] == "csrss.exe" and r["PID"] == 620)]
    out = analyze(rows)
    csrss = [a for a in out if a.image_name == "csrss.exe"]
    assert csrss and csrss[0].reason == "count_low"


# ---------------------------------------------------------------------------
# Parent-name masquerade detection
# ---------------------------------------------------------------------------

def test_lsass_with_wrong_parent_flagged():
    """Classic masquerade: lsass.exe spawned from cmd.exe or explorer.exe."""
    rows = _clean_win10()
    # Swap lsass's parent to a non-wininit process
    for r in rows:
        if r["ImageFileName"] == "lsass.exe":
            r["PPID"] = 2000   # chrome.exe from baseline
    out = analyze(rows)
    assert any(a.image_name == "lsass.exe"
               and a.reason == "unexpected_parent"
               and "H_CREDENTIAL_ACCESS" in a.hypotheses
               for a in out)


def test_svchost_from_explorer_is_flagged():
    rows = _clean_win10() + [_row("svchost.exe", 3333, 1500)]  # parent=explorer
    out = analyze(rows)
    svc = [a for a in out if a.image_name == "svchost.exe"
           and a.reason == "unexpected_parent"]
    assert svc


def test_taskhostw_with_wrong_parent_flagged():
    rows = _clean_win10() + [_row("taskhostw.exe", 4444, 1500)]
    out = analyze(rows)
    assert any(a.image_name == "taskhostw.exe"
               and a.reason == "unexpected_parent" for a in out)


# ---------------------------------------------------------------------------
# Tolerance: parent-may-exit processes
# ---------------------------------------------------------------------------

def test_explorer_with_missing_parent_not_flagged():
    """userinit.exe exits after launching explorer — the missing parent
    is the NORMAL state, not anomalous."""
    # _clean_win10() already includes explorer with PPID=9999 (not in rows)
    out = analyze(_clean_win10())
    assert not any(a.image_name == "explorer.exe" for a in out)


def test_winlogon_with_missing_parent_not_flagged():
    """smss.exe session-child exits too."""
    rows = [r for r in _clean_win10()
            if not (r["ImageFileName"] == "smss.exe")]
    rows.append(_row("winlogon.exe", 8200, 99999, 2))  # ppid not present
    out = analyze(rows)
    # Missing parent + parent_may_exit=True → no unexpected_parent
    assert not any(a.image_name == "winlogon.exe"
                   and a.reason == "unexpected_parent" for a in out)


# ---------------------------------------------------------------------------
# Agent-level integration
# ---------------------------------------------------------------------------

def test_memory_forensicator_emits_hunt_evil_findings(tmp_path, monkeypatch):
    """End-to-end: memory_forensicator._hunt_evil_process_matrix turns
    ProcessAnomaly into Finding with correct confidence + hypotheses."""
    from el.agents.base import AgentContext
    from el.agents.memory_forensicator import MemoryForensicatorAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills.vol3 import PluginRun

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-huntevil")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-huntevil", case_dir=m.case_dir,
                       input_path=src, manifest=m.__dict__)

    # Build a pslist with a clearly-masqueraded lsass.exe
    rows = _clean_win10() + [_row("lsass.exe", 6666, 1500)]  # parent=explorer
    stdout = tmp_path / "pslist.json"
    stdout.write_text("[]")
    run = PluginRun(
        plugin="windows.pslist.PsList", image=src, rc=0,
        stdout_path=stdout, stderr_path=tmp_path / "pslist.stderr",
        rows=rows, command=["vol", "..."], version="2.27.0",
    )
    findings = MemoryForensicatorAgent()._hunt_evil_process_matrix(ctx, run)
    assert findings, "expected at least one Hunt-Evil anomaly finding"
    # Count and masquerade finding(s); lsass-related are high-confidence
    lsass = [f for f in findings if "lsass.exe" in f.claim.lower()]
    assert lsass
    assert lsass[0].confidence == "high"
    assert "H_CREDENTIAL_ACCESS" in lsass[0].hypotheses_supported
