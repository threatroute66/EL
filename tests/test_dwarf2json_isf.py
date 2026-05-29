"""dwarf2json / Linux-mem ISF support.

Windows memory needs no ISF (PDBs auto-download). Linux/macOS images need a
per-kernel ISF built with dwarf2json — EL surfaces that as an OPTIONAL tool
(el doctor probe) and degrades to a clear `insufficient` finding rather than
hard-failing. These tests pin that contract.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from el import tooling
from el.skills import vol3


def test_probe_dwarf2json_absent(monkeypatch):
    """No binary anywhere -> available=False, with build hint, non-fatal."""
    monkeypatch.setattr(tooling.shutil, "which", lambda _n: None)
    monkeypatch.setattr(tooling.Path, "is_file", lambda self: False)
    st = tooling.probe_dwarf2json()
    assert st.name == "dwarf2json"
    assert st.available is False
    assert "optional" in st.note.lower()
    assert "dwarf2json" in st.note


def test_probe_dwarf2json_present_at_opt(monkeypatch):
    """Found at /opt/dwarf2json/dwarf2json -> available=True."""
    monkeypatch.setattr(tooling.shutil, "which", lambda _n: None)
    monkeypatch.setattr(
        tooling.Path, "is_file",
        lambda self: str(self) == "/opt/dwarf2json/dwarf2json")
    st = tooling.probe_dwarf2json()
    assert st.available is True
    assert st.invocation == ["/opt/dwarf2json/dwarf2json"]


def test_dwarf2json_in_survey(monkeypatch):
    """Probe is wired into the doctor survey list."""
    names = {s.name for s in tooling.survey()}
    assert "dwarf2json" in names


def test_isf_remediation_mentions_dwarf2json():
    assert "dwarf2json" in vol3.ISF_REMEDIATION
    assert "ISF" in vol3.ISF_REMEDIATION


def _fake_run(tmp_path: Path, *, rc: int, rows: list, stderr: str) -> vol3.PluginRun:
    err = tmp_path / "x.stderr"
    err.write_text(stderr)
    out = tmp_path / "x.json"
    out.write_text("[]")
    return vol3.PluginRun(
        plugin="linux.pslist.PsList", image=tmp_path / "img",
        rc=rc, stdout_path=out, stderr_path=err, rows=rows,
        command=["vol"], version="2.27.0", streaming=False, row_count=0)


def test_isf_missing_detected(tmp_path):
    """A Linux plugin that failed on missing symbols is recognised."""
    run = _fake_run(
        tmp_path, rc=1, rows=[],
        stderr=("volatility3.framework.exceptions.UnsatisfiedException: "
                "Unable to validate the plugin requirements: "
                "['kernel.symbol_table']\nNo suitable ISF symbol table found"))
    assert vol3.isf_symbols_missing(run) is True


def test_isf_not_flagged_on_success(tmp_path):
    """A successful run (rows present) is never flagged as ISF-missing."""
    run = _fake_run(tmp_path, rc=0, rows=[{"PID": 1}], stderr="")
    assert vol3.isf_symbols_missing(run) is False


def test_isf_not_flagged_on_unrelated_error(tmp_path):
    """A generic non-symbol failure is not misattributed to ISF."""
    run = _fake_run(
        tmp_path, rc=1, rows=[],
        stderr="PermissionError: [Errno 13] cannot read image file")
    assert vol3.isf_symbols_missing(run) is False
