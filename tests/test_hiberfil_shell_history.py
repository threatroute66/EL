"""FOR508 ex 2.5 follow-on — hibernation-file shell-history hook tests.

The hook reuses the module-level scoring helpers from
memory_forensicator (extract_shell_lines + keyword_hits) so anything
that comes back from vol3 cmdscan/consoles against hiberfil.sys
gets the same hypothesis-lifting treatment as live-RAM rows.

Tests focus on:
1. The pure helpers (extract_shell_lines / keyword_hits) — exposed at
   module level for cross-agent use.
2. The disk_forensicator hook's gating logic — silent when no
   hiberfil exists; insufficient finding when too small; runs vol3
   when the file is a viable size.
3. The end-to-end Finding shape — claim text must mention
   "HIBERNATION FILE" so the analyst can distinguish hiberfil-derived
   shell history from live-RAM shell history in the report.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from el.agents.base import AgentContext
from el.agents.disk_forensicator import DiskForensicatorAgent
from el.agents.memory_forensicator import (
    SHELL_KEYWORDS,
    extract_shell_lines,
    keyword_hits,
)
from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger, list_findings
from el.skills.vol3 import PluginRun


# ---------------------------------------------------------------------------
# Pure helpers (now module-level so disk_forensicator can import them)
# ---------------------------------------------------------------------------

def test_extract_shell_lines_walks_string_cells():
    rows = [
        {"PID": 1234, "Command": "ipconfig"},                      # one line
        {"ScreenBuffer": "C:\\> dir\nC:\\> mimikatz.exe"},         # two lines
        {"PID": 5, "EmptyCol": "   "},                              # ignored
        {"NonString": 42},                                          # ignored
    ]
    lines = extract_shell_lines(rows)
    assert "ipconfig" in lines
    assert "C:\\> mimikatz.exe" in lines
    assert "   " not in lines
    assert all(isinstance(l, str) for l in lines)


def test_keyword_hits_groups_by_hypothesis_label():
    lines = [
        "mimikatz.exe sekurlsa::logonpasswords",
        "mimikatz.exe lsadump::sam",
        "psexec \\\\target -u admin",
        "ipconfig /all",
    ]
    hits = keyword_hits(lines)
    # Same line matches both `mimikatz` and `sekurlsa::` keys → 2 keys
    assert ("H_CREDENTIAL_ACCESS", "mimikatz") in hits
    assert ("H_CREDENTIAL_ACCESS", "sekurlsa::") in hits
    assert ("H_LATERAL_MOVEMENT", "psexec") in hits
    # ipconfig matches no keyword
    assert all(label != "ipconfig" for (_, label) in hits)


def test_shell_keywords_module_export_matches_class_constant():
    """SHELL_KEYWORDS at module level must alias the class-private
    constant — disk_forensicator imports the module-level name."""
    from el.agents.memory_forensicator import MemoryForensicatorAgent
    assert SHELL_KEYWORDS is MemoryForensicatorAgent._SHELL_KEYWORDS


# ---------------------------------------------------------------------------
# disk_forensicator hook — gating logic
# ---------------------------------------------------------------------------

def _ctx(tmp_path, monkeypatch, case_id="t-hiberfil"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


def test_no_hiberfil_is_silent(tmp_path, monkeypatch):
    """A mount with no hiberfil.sys at root → no findings emitted.
    Common case (servers / disabled-hibernation hosts) — flooding the
    ledger with 'no hiberfil here' would be noise."""
    ctx = _ctx(tmp_path, monkeypatch)
    mount = tmp_path / "mount"; mount.mkdir()

    DiskForensicatorAgent()._run_hiberfil_shell_history(
        ctx, mount, label="testfs")
    assert list(list_findings(ctx.case_dir)) == []


def test_small_hiberfil_emits_insufficient(tmp_path, monkeypatch):
    """Hibernation enabled but file too small (<100 MiB) usually means
    it was reset / never used. Surface this as one insufficient
    finding so the analyst sees 'we looked'."""
    ctx = _ctx(tmp_path, monkeypatch)
    mount = tmp_path / "mount"; mount.mkdir()
    (mount / "hiberfil.sys").write_bytes(b"\x00" * 1024)   # 1 KiB

    DiskForensicatorAgent()._run_hiberfil_shell_history(
        ctx, mount, label="testfs")
    findings = list(list_findings(ctx.case_dir))
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"
    assert "too small" in findings[0].claim


def test_case_insensitive_filename(tmp_path, monkeypatch):
    """Match HIBERFIL.SYS / Hiberfil.sys variants too — older Windows
    case conventions vary."""
    ctx = _ctx(tmp_path, monkeypatch)
    mount = tmp_path / "mount"; mount.mkdir()
    (mount / "Hiberfil.sys").write_bytes(b"\x00" * 1024)

    DiskForensicatorAgent()._run_hiberfil_shell_history(
        ctx, mount, label="testfs")
    findings = list(list_findings(ctx.case_dir))
    # Should produce the "too small" insufficient finding — proves
    # the case-insensitive lookup found the file.
    assert any("too small" in f.claim for f in findings)


# ---------------------------------------------------------------------------
# Hook end-to-end: viable hiberfil + mocked vol3 → expected Finding shape
# ---------------------------------------------------------------------------

def test_viable_hiberfil_with_shell_history_emits_findings(
        tmp_path, monkeypatch):
    """Viable-size hiberfil.sys + mocked vol3 cmdscan returning a
    mimikatz line → umbrella finding (HIBERNATION FILE in claim) +
    keyword findings for the credential-access lift."""
    ctx = _ctx(tmp_path, monkeypatch)
    mount = tmp_path / "mount"; mount.mkdir()
    # Viable size ≥ 100 MiB. Use a sparse-style write so we don't
    # actually allocate 100 MiB on disk.
    hiber = mount / "hiberfil.sys"
    with hiber.open("wb") as fh:
        fh.seek(150 * 1024 * 1024 - 1)
        fh.write(b"\x00")

    # Mock vol3.run_plugin to return a CmdScan run with one mimikatz
    # line for cmdscan, and a no-rows run for consoles (so we exercise
    # both the success and "no rows" paths in one test).
    def fake_run_plugin(image, plugin, analysis, **kwargs):
        stdout = analysis / f"{plugin.replace('.', '_')}.json"
        analysis.mkdir(parents=True, exist_ok=True)
        stdout.write_text("[]")
        if plugin == "windows.cmdscan.CmdScan":
            rows = [{"Command": "mimikatz sekurlsa::logonpasswords"}]
        else:
            rows = []
        return PluginRun(
            plugin=plugin, image=image, rc=0,
            stdout_path=stdout,
            stderr_path=analysis / f"{plugin}.stderr",
            rows=rows, command=["vol"], version="2.27.0",
        )

    with patch("el.skills.vol3.run_plugin", side_effect=fake_run_plugin):
        DiskForensicatorAgent()._run_hiberfil_shell_history(
            ctx, mount, label="dc-disk")

    findings = list(list_findings(ctx.case_dir))
    # Umbrella + at least one keyword finding (mimikatz/sekurlsa::)
    assert any("HIBERNATION FILE" in f.claim
               and f.confidence == "high"
               and "H_LIVING_OFF_THE_LAND" in f.hypotheses_supported
               for f in findings), \
           "umbrella finding must mention HIBERNATION FILE"
    assert any("H_CREDENTIAL_ACCESS" in f.hypotheses_supported
               and "Hibernation-file shell-history keyword" in f.claim
               for f in findings), \
           "mimikatz line must lift H_CREDENTIAL_ACCESS via the hiberfil path"


def test_vol3_failure_emits_insufficient_not_raise(tmp_path, monkeypatch):
    """vol3 layer-detection failures on hiberfil.sys are common
    (compressed segments / build mismatch). Hook must emit an
    insufficient Finding rather than crashing the whole disk pipeline."""
    ctx = _ctx(tmp_path, monkeypatch)
    mount = tmp_path / "mount"; mount.mkdir()
    hiber = mount / "hiberfil.sys"
    with hiber.open("wb") as fh:
        fh.seek(150 * 1024 * 1024 - 1)
        fh.write(b"\x00")

    def fake_run_plugin(image, plugin, analysis, **kwargs):
        stdout = analysis / f"{plugin.replace('.', '_')}.json"
        analysis.mkdir(parents=True, exist_ok=True)
        stdout.write_text("")
        stderr = analysis / f"{plugin}.stderr"
        stderr.write_text("layer detection failed")
        return PluginRun(
            plugin=plugin, image=image, rc=2,
            stdout_path=stdout, stderr_path=stderr,
            rows=[], command=["vol"], version="2.27.0",
        )

    with patch("el.skills.vol3.run_plugin", side_effect=fake_run_plugin):
        # Must not raise
        DiskForensicatorAgent()._run_hiberfil_shell_history(
            ctx, mount, label="dc-disk")

    findings = list(list_findings(ctx.case_dir))
    insufficient = [f for f in findings if f.confidence == "insufficient"]
    assert insufficient, "vol3 rc!=0 must produce insufficient finding"
    assert any("could not parse hiberfil.sys" in f.claim
               for f in insufficient)
