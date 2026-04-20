"""PR-I: Execution-artifact corroborator tests.

Build synthetic shimcache / prefetch / amcache / userassist CSVs under a
fake artifact analysis dir, then assert that the skill + agent pair
correctly groups by basename, counts sources, and escalates confidence.
"""
import csv
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.execution_corroborator import ExecutionCorroboratorAgent
from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger
from el.skills import execution_corroboration as xc


# ---------------------------------------------------------------------------
# Helpers to build CSVs in the expected EZ Tools shape
# ---------------------------------------------------------------------------

def _write_shimcache(path: Path, rows: list[tuple[str, str, str]]) -> None:
    """rows: (path, LastModifiedTimeUTC, Executed)"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ControlSet", "CacheEntryPosition", "Path",
                    "LastModifiedTimeUTC", "Executed", "Duplicate", "SourceFile"])
        for p, ts, executed in rows:
            w.writerow(["0", "0", p, ts, executed, "False", "SYSTEM"])


def _write_prefetch(path: Path, rows: list[tuple[str, str, str, str]]) -> None:
    """rows: (SourceFilename, ExecutableName, RunCount, LastRun)"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["SourceFilename", "ExecutableName", "Hash",
                    "Size", "Version", "RunCount", "LastRun"])
        for src, exe, rc, lr in rows:
            w.writerow([src, exe, "DEADBEEF", "12345", "Win10", rc, lr])


def _write_amcache(path: Path, rows: list[tuple[str, str]]) -> None:
    """rows: (LowerCaseLongPath, FileIDLastWriteTimestamp)"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ApplicationName", "ProgramId", "FileId",
                    "LowerCaseLongPath", "LongPath", "Name", "SHA1",
                    "FileIDLastWriteTimestamp", "Publisher"])
        for p, ts in rows:
            w.writerow(["App", "PID", "FID", p, p, p.rsplit("/", 1)[-1],
                        "aabbcc", ts, "TestPublisher"])


def _write_userassist(path: Path, rows: list[tuple[str, str]]) -> None:
    """rows: (ProgramName, ModifiedTime)"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Timestamp", "BatchKeyPath", "ProgramName",
                    "BatchValueName", "ModifiedTime"])
        for prog, ts in rows:
            w.writerow(["2023-01-01", "Software\\...\\UserAssist", prog, "", ts])


# ---------------------------------------------------------------------------
# Skill: correlate()
# ---------------------------------------------------------------------------

def test_correlate_groups_by_basename_across_sources(tmp_path):
    art = tmp_path / "analysis" / "windows_artifact"
    _write_shimcache(art / "shimcache" / "shimcache.csv",
                     [("C:\\Windows\\System32\\cmd.exe",
                       "2023-01-01", "True")])
    _write_prefetch(art / "prefetch" / "prefetch.csv",
                    [("C:\\Windows\\System32\\cmd.exe", "CMD.EXE",
                      "3", "2023-01-02T10:00:00")])
    _write_amcache(art / "amcache" / "UnassociatedFileEntries.csv",
                   [("c:\\windows\\system32\\cmd.exe", "2023-01-03")])

    entries, counts = xc.correlate(art)
    assert "cmd.exe" in entries
    cmd = entries["cmd.exe"]
    assert cmd.sources == {"shimcache", "prefetch", "amcache"}
    assert cmd.corroboration == 3
    assert cmd.hit_count == 3


def test_correlate_isolated_source_has_corroboration_one(tmp_path):
    """Prefetch entry alone → corroboration=1 → below min_sources=2
    threshold, but entry still present in returned dict."""
    art = tmp_path / "analysis" / "windows_artifact"
    _write_prefetch(art / "prefetch" / "prefetch.csv",
                    [("C:\\Users\\bob\\Desktop\\tool.exe", "TOOL.EXE",
                      "1", "2023-01-01")])
    entries, _ = xc.correlate(art)
    assert "tool.exe" in entries
    assert entries["tool.exe"].corroboration == 1


def test_user_writable_path_detection():
    assert xc.is_user_writable_path(
        "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe")
    assert xc.is_user_writable_path(
        "C:\\ProgramData\\sus\\dropper.exe")
    assert xc.is_user_writable_path(
        "c:\\users\\bob\\downloads\\payload.exe")
    # NOT user-writable
    assert not xc.is_user_writable_path(
        "C:\\Windows\\System32\\cmd.exe")


def test_amcache_unassociated_fullpath_column_parsed(tmp_path):
    """Real EZ Tools AmcacheParser output for UnassociatedFileEntries
    uses `FullPath` (capital F) — not LowerCaseLongPath, not LongPath,
    not Name. Before the fix, dmz-ftp and base-file parsed their
    Amcache hives successfully (30-519 entries) but every row dropped
    here because parse_amcache looked for the wrong column and the
    corroborator reported "1 source (shimcache)" with amcache silently
    contributing zero hits."""
    csv_path = tmp_path / "20260420203903_Amcache_UnassociatedFileEntries.csv"
    # Exact column layout observed on srl-dmz-ftp-disk (partial)
    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ProgramName", "ProgramID", "VolumeID",
                    "FileID", "FileIDLastWriteTimestamp", "SHA1",
                    "FullPath", "FileExtension"])
        w.writerow(["Unassociated", "", "vol-1", "fid-1",
                    "2018-03-14 14:01:17", "deadbeef",
                    "C:\\Program Files\\VMware\\vmtoolsd.exe", ".exe"])
        w.writerow(["Unassociated", "", "vol-1", "fid-2",
                    "2018-04-01 12:00:00", "cafebabe",
                    "C:\\Users\\alice\\AppData\\Local\\Temp\\dropper.exe",
                    ".exe"])

    hits = xc.parse_amcache(csv_path)
    assert len(hits) == 2, (
        f"parse_amcache dropped rows because FullPath fallback was "
        f"missing; got {len(hits)} hit(s) instead of 2")
    names = {h.name_lc for h in hits}
    assert "vmtoolsd.exe" in names
    assert "dropper.exe" in names
    # Confirm SHA1 still extracted from its expected column
    assert any(h.extra.get("SHA1") == "deadbeef" for h in hits)


def test_userassist_ignores_non_exe_rows(tmp_path):
    """CLSIDs and shortcuts sometimes appear in UserAssist — skip unless
    ProgramName ends with .exe."""
    art = tmp_path / "analysis" / "windows_artifact"
    _write_userassist(art / "registry" / "userassist" / "UserAssist.csv",
                      [("{CLSID-aaaa}.lnk", "2023-01-01"),
                       ("C:\\Users\\alice\\evil.exe", "2023-01-02")])
    entries, _ = xc.correlate(art)
    assert "evil.exe" in entries
    assert "{clsid-aaaa}.lnk" not in entries


# ---------------------------------------------------------------------------
# Agent: per-binary findings, noise suppression
# ---------------------------------------------------------------------------

def _ctx(tmp_path, monkeypatch, case_id="t-xc"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


def test_agent_emits_insufficient_when_no_csvs(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, "t-none")
    findings = ExecutionCorroboratorAgent().run(ctx)
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"


def test_agent_high_confidence_on_user_writable_path(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, "t-dropper")
    art = ctx.case_dir / "analysis" / "windows_artifact"
    _write_shimcache(art / "shimcache" / "shimcache.csv",
                     [("C:\\Users\\alice\\AppData\\Local\\Temp\\dropper.exe",
                       "2023-01-01", "True")])
    _write_prefetch(art / "prefetch" / "prefetch.csv",
                    [("C:\\Users\\alice\\AppData\\Local\\Temp\\dropper.exe",
                      "DROPPER.EXE", "1", "2023-01-01")])

    findings = ExecutionCorroboratorAgent().run(ctx)
    dropper = [f for f in findings if "dropper.exe" in f.claim.lower()]
    assert dropper
    # User-writable path still drives high-confidence tiering + the
    # "User-writable path — dropper-shape" phrase in the claim…
    assert dropper[0].confidence == "high"
    assert "User-writable path" in dropper[0].claim
    # …but the finding must NOT tag H_OPPORTUNISTIC_COMMODITY. This was
    # the rd-01 scoring bug: Chrome/Teams/Dashlane/OneDrive all install
    # to AppData (is_user_writable_path = True) and emitted +3 lifts
    # each, surpassing H_APT_ESPIONAGE on a clearly APT-shaped case.
    # Execution corroboration says "ran" — classification is left to
    # malware_triage / threat_hunter / disk_anomaly.
    assert "H_OPPORTUNISTIC_COMMODITY" not in dropper[0].hypotheses_supported


def test_agent_skips_noisy_systemxexe_in_system32(tmp_path, monkeypatch):
    """cmd.exe in System32 is noise — don't emit per-binary finding."""
    ctx = _ctx(tmp_path, monkeypatch, "t-noise")
    art = ctx.case_dir / "analysis" / "windows_artifact"
    _write_shimcache(art / "shimcache" / "shimcache.csv",
                     [("C:\\Windows\\System32\\cmd.exe", "2023-01-01", "True")])
    _write_prefetch(art / "prefetch" / "prefetch.csv",
                    [("C:\\Windows\\System32\\cmd.exe", "CMD.EXE",
                      "5", "2023-01-02")])
    findings = ExecutionCorroboratorAgent().run(ctx)
    # Summary finding is emitted; no per-binary cmd.exe finding
    summary = [f for f in findings if "distinct executable" in f.claim]
    assert summary
    per_bin = [f for f in findings if "Execution corroborated" in f.claim]
    assert not any("cmd.exe" in f.claim for f in per_bin)


def test_agent_flags_psexec_in_unusual_path(tmp_path, monkeypatch):
    """psexec.exe always lifts H_LATERAL_MOVEMENT + H_CREDENTIAL_ACCESS
    in the hypothesis slot, even when it's in a clean path, because the
    tool's presence alone is operationally meaningful."""
    ctx = _ctx(tmp_path, monkeypatch, "t-psexec")
    art = ctx.case_dir / "analysis" / "windows_artifact"
    _write_shimcache(art / "shimcache" / "shimcache.csv",
                     [("C:\\Users\\bob\\AppData\\Local\\Temp\\psexec.exe",
                       "2023-01-01", "True")])
    _write_prefetch(art / "prefetch" / "prefetch.csv",
                    [("C:\\Users\\bob\\AppData\\Local\\Temp\\psexec.exe",
                      "PSEXEC.EXE", "1", "2023-01-01")])
    findings = ExecutionCorroboratorAgent().run(ctx)
    psexec = [f for f in findings if "psexec.exe" in f.claim.lower()]
    assert psexec
    assert "H_LATERAL_MOVEMENT" in psexec[0].hypotheses_supported
    assert "H_CREDENTIAL_ACCESS" in psexec[0].hypotheses_supported


def test_agent_summary_finding_reports_counts(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, "t-summary")
    art = ctx.case_dir / "analysis" / "windows_artifact"
    _write_shimcache(art / "shimcache" / "shimcache.csv",
                     [("C:\\x\\a.exe", "2023-01-01", "True"),
                      ("C:\\x\\b.exe", "2023-01-02", "True")])
    _write_prefetch(art / "prefetch" / "prefetch.csv",
                    [("C:\\x\\a.exe", "A.EXE", "1", "2023-01-03")])

    findings = ExecutionCorroboratorAgent().run(ctx)
    summary = [f for f in findings if "distinct executable" in f.claim]
    assert summary
    facts = summary[0].evidence[0].extracted_facts
    assert facts["total_distinct_executables"] == 2
    assert facts["corroborated_count"] == 1
    assert facts["per_source_row_count"]["shimcache"] == 2
    assert facts["per_source_row_count"]["prefetch"] == 1
