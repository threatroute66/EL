"""Tests for the Tier-3 memory-timeline skill (Roussev & Quates 2012,
Case 2 — daily RAM-snapshot diff against a clean baseline)."""
import json
from pathlib import Path

import pytest

from el.skills.memory_timeline import (
    build_timeline, extract_module_set, render_markdown,
)


def _write_case(base: Path, case_id: str, *,
                 pslist: list[dict] | None = None,
                 dlllist: list[dict] | None = None,
                 modules: list[dict] | None = None,
                 intake_utc: str = "2018-01-01T00:00:00") -> Path:
    """Build a minimal case dir shape EL's memory_timeline skill reads:
    manifest.json with intake_utc + analysis/memory_forensicator/*.json."""
    cd = base / case_id
    (cd / "analysis" / "memory_forensicator").mkdir(parents=True)
    (cd / "manifest.json").write_text(json.dumps({
        "case_id": case_id, "intake_utc": intake_utc,
    }))
    mf = cd / "analysis" / "memory_forensicator"
    (mf / "windows_pslist_PsList.json").write_text(
        json.dumps(pslist or []))
    (mf / "windows_dlllist_DllList.json").write_text(
        json.dumps(dlllist or []))
    (mf / "windows_modules_Modules.json").write_text(
        json.dumps(modules or []))
    return cd


def test_extract_module_set_walks_pslist_dlllist_modules(tmp_path):
    cd = _write_case(tmp_path, "c1",
        pslist=[{"PID": 4, "ImageFileName": "System"},
                 {"PID": 1000, "ImageFileName": "chrome.exe"}],
        dlllist=[{"PID": 1000, "Process": "chrome.exe",
                   "Path": "C:\\Windows\\System32\\ntdll.dll",
                   "Name": "ntdll.dll"}],
        modules=[{"FullDllName": "\\SystemRoot\\system32\\drivers\\ntfs.sys",
                   "Name": "ntfs.sys"}])
    m = extract_module_set(cd)
    # Normalised keys — forward slashes, lowercase
    assert "system" in m
    assert "chrome.exe" in m
    assert "c:/windows/system32/ntdll.dll" in m
    assert "\\systemroot\\system32\\drivers\\ntfs.sys".replace("\\", "/") in m


def test_build_timeline_uses_first_as_baseline_when_none_given(tmp_path):
    _write_case(tmp_path, "c-baseline",
        intake_utc="2018-11-16T00:00:00",
        dlllist=[{"Path": "C:\\Windows\\explorer.exe"}])
    _write_case(tmp_path, "c-day3",
        intake_utc="2018-11-18T00:00:00",
        dlllist=[
            {"Path": "C:\\Windows\\explorer.exe"},
            {"Path": "C:\\Users\\pat\\Downloads\\TrueCrypt Setup 6.3a.exe"},
        ])
    tl = build_timeline([
        tmp_path / "c-baseline", tmp_path / "c-day3"])
    assert tl.baseline_case_id == "c-baseline"
    assert len(tl.entries) == 1
    e = tl.entries[0]
    assert e.case_id == "c-day3"
    # The TrueCrypt download is novel vs baseline
    assert any("truecrypt" in p for p in e.novel_vs_baseline), \
        e.novel_vs_baseline
    # Explorer was in baseline → NOT novel
    assert all("explorer" not in p for p in e.novel_vs_baseline)


def test_build_timeline_explicit_baseline(tmp_path):
    _write_case(tmp_path, "baseline-disk",
        intake_utc="2018-01-01T00:00:00",
        dlllist=[{"Path": "C:\\Windows\\System32\\ntoskrnl.exe"}])
    _write_case(tmp_path, "ram-nov19",
        intake_utc="2018-11-19T00:00:00",
        dlllist=[
            {"Path": "C:\\Windows\\System32\\ntoskrnl.exe"},
            {"Path": "C:\\Program Files\\XP Advanced Keylogger\\DLLs\\ToolKeyloggerDLL.dll"},
        ])
    _write_case(tmp_path, "ram-dec07",
        intake_utc="2018-12-07T00:00:00",
        dlllist=[
            {"Path": "C:\\Windows\\System32\\ntoskrnl.exe"},
            {"Path": "C:\\Program Files\\RealVNC\\VNC4\\winvnc4.exe"},
        ])
    tl = build_timeline(
        [tmp_path / "ram-nov19", tmp_path / "ram-dec07"],
        baseline=tmp_path / "baseline-disk")
    assert tl.baseline_case_id == "baseline-disk"
    assert len(tl.entries) == 2
    e1, e2 = tl.entries
    assert any("keylogger" in p for p in e1.novel_vs_baseline)
    assert any("realvnc" in p for p in e2.novel_vs_baseline)
    # Day-to-day: keylogger was removed between nov19 and dec07
    assert any("keylogger" in p for p in e2.removed_vs_previous)
    # Day-to-day: RealVNC is novel in dec07 vs nov19
    assert any("realvnc" in p for p in e2.novel_vs_previous)


def test_build_timeline_sorts_chronologically(tmp_path):
    """Caller can pass cases in any order; skill sorts by intake_utc."""
    _write_case(tmp_path, "a-old", intake_utc="2018-11-01T00:00:00",
                 dlllist=[{"Path": "C:\\base.dll"}])
    _write_case(tmp_path, "b-new", intake_utc="2018-12-01T00:00:00",
                 dlllist=[{"Path": "C:\\base.dll"},
                           {"Path": "C:\\new.dll"}])
    # Pass in reverse chronological order — skill must still pick a-old
    # as baseline
    tl = build_timeline([tmp_path / "b-new", tmp_path / "a-old"])
    assert tl.baseline_case_id == "a-old"
    assert tl.entries[0].case_id == "b-new"
    assert any("new.dll" in p for p in tl.entries[0].novel_vs_baseline)


def test_build_timeline_handles_empty_module_set(tmp_path):
    """Case with no memory_forensicator output shouldn't crash."""
    _write_case(tmp_path, "empty", intake_utc="2018-01-01T00:00:00")
    _write_case(tmp_path, "full", intake_utc="2018-02-01T00:00:00",
                 dlllist=[{"Path": "C:\\x.exe"}])
    tl = build_timeline([tmp_path / "empty", tmp_path / "full"])
    # empty → baseline (0 modules), full → 1 novel
    assert tl.baseline_count == 0
    assert tl.entries[0].novel_vs_baseline == ["c:/x.exe"]


def test_render_markdown_highlights_suspicious_paths(tmp_path):
    _write_case(tmp_path, "baseline",
        intake_utc="2018-01-01", dlllist=[{"Path": "C:\\Windows\\ok.exe"}])
    _write_case(tmp_path, "day2",
        intake_utc="2018-01-02",
        dlllist=[{"Path": "C:\\Users\\Pat\\AppData\\Local\\Temp\\mal.exe"}])
    tl = build_timeline([tmp_path / "baseline", tmp_path / "day2"])
    md = render_markdown(tl)
    # Suspicious path wrapped in bold, not just backticks
    assert "**c:/users/pat/appdata/local/temp/mal.exe**" in md
    # Heading + summary present
    assert "# Memory Timeline" in md
    assert "novel vs baseline" in md


def test_render_markdown_empty_timeline(tmp_path):
    from el.skills.memory_timeline import Timeline
    tl = Timeline(baseline_case_id=None, baseline_count=0, entries=[])
    md = render_markdown(tl)
    assert "No baseline set" in md


def test_cli_timeline_memory_end_to_end(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from el.cli import app

    _write_case(tmp_path, "baseline",
        intake_utc="2018-11-16T00:00:00",
        dlllist=[{"Path": "C:\\Windows\\cmd.exe"}])
    _write_case(tmp_path, "snap-1",
        intake_utc="2018-11-18T00:00:00",
        dlllist=[
            {"Path": "C:\\Windows\\cmd.exe"},
            {"Path": "C:\\Users\\Public\\payload.exe"},
        ])
    out_path = tmp_path / "tl.md"
    runner = CliRunner()
    result = runner.invoke(app, [
        "timeline-memory", str(tmp_path / "snap-1"),
        "--baseline", str(tmp_path / "baseline"),
        "--out", str(out_path),
    ])
    assert result.exit_code == 0, result.output
    assert out_path.is_file()
    text = out_path.read_text()
    assert "snap-1" in text
    assert "payload.exe" in text
    # Console summary mentions baseline + snapshot counts
    assert "baseline" in result.output.lower()


def test_cli_timeline_memory_requires_two_cases(tmp_path):
    from typer.testing import CliRunner
    from el.cli import app
    runner = CliRunner()
    # Only one case, no --baseline — error path
    result = runner.invoke(app, ["timeline-memory", str(tmp_path)])
    assert result.exit_code != 0
