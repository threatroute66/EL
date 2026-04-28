"""Phase 1.5 integration tests for the executive HTML renderer.

Locks in the contract for `el/reporting/executive.py`:

  * Output is always a self-contained HTML file with all 6 expected
    sections.
  * Renders against a real ledger built by intake + a few finding
    inserts (no full Coordinator run needed).
  * Glossary appendix only contains terms actually used in the body.
  * Recommendations cite finding IDs that exist in the ledger.
  * CaseMetadata is honoured when present, falls back gracefully when
    absent (matches the engagement-level=CTF default of skipping
    optional case-context fields).
  * The `el report --executive` CLI flag plumbs the renderer.
"""
from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import pytest

from el.case_metadata import CaseMetadata, save as save_case_metadata
from el.evidence.ledger import insert as ledger_insert, list_findings, open_ledger
from el.evidence import intake as intake_mod
from el.reporting.executive import render_executive_html
from el.schemas.finding import EvidenceItem, Finding


# --- helpers ---------------------------------------------------------------

def _ev(human_summary: str | None = None) -> EvidenceItem:
    return EvidenceItem(
        tool="vol.py", version="2.20.0",
        command="windows.pstree", output_sha256="0" * 64,
        output_path="/tmp/x", human_summary=human_summary,
    )


def _seed_case(tmp_path: Path, case_id: str = "exec-test",
                extra_findings: list[Finding] | None = None) -> Path:
    """Build a minimal-but-real case directory: intake a dummy file,
    open the ledger, optionally insert some Findings."""
    src = tmp_path / "evidence.bin"
    src.write_bytes(b"hello world\n")
    m = intake_mod.intake(src, case_id=case_id)
    cd = Path(m.case_dir)
    if extra_findings:
        for f in extra_findings:
            ledger_insert(cd, f)
    return cd


@pytest.fixture(autouse=True)
def _isolated_case_root(tmp_path, monkeypatch):
    """Redirect intake to the tmp path so tests never write to /opt/EL/cases."""
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")


# --- core render -----------------------------------------------------------

def test_renders_html_with_all_six_sections(tmp_path):
    """Sparse case: no findings, no metadata. Must still produce a
    valid HTML file with the six expected section headings."""
    cd = _seed_case(tmp_path)
    out = render_executive_html(cd)
    assert out.exists()
    html = out.read_text()
    for heading in ("Case Details", "Executive Summary", "Findings",
                     "Conclusion", "Recommendations", "Appendix"):
        assert heading in html, f"missing section: {heading}"
    # Self-contained: embedded CSS, no external stylesheet
    assert "<style>" in html
    assert "<link " not in html or "rel='stylesheet'" not in html


def test_renders_well_formed_html_doctype_and_root(tmp_path):
    cd = _seed_case(tmp_path)
    out = render_executive_html(cd)
    html = out.read_text()
    assert html.strip().startswith("<!DOCTYPE html>")
    assert "<html lang='en'>" in html
    assert html.strip().endswith("</html>")


# --- case metadata --------------------------------------------------------

def test_case_metadata_surfaces_in_header(tmp_path):
    cd = _seed_case(tmp_path)
    meta = CaseMetadata(
        case_number="IR-2026-0001",
        incident_date=date(2026, 4, 15),
        investigator_name="M. Cingoz",
        objective_statement="Determine whether the laptop was used for data exfiltration.",
    )
    save_case_metadata(cd, meta)
    out = render_executive_html(cd)
    html = out.read_text()
    assert "IR-2026-0001" in html
    assert "2026-04-15" in html
    assert "M. Cingoz" in html
    assert "data exfiltration" in html
    # Title incorporates the case number
    assert "IR-2026-0001" in html.split("<title>")[1].split("</title>")[0]


def test_no_metadata_renders_without_optional_sections(tmp_path):
    """When CaseMetadata is empty (CTF default), the Objective section
    is skipped entirely rather than emitting a blank one."""
    cd = _seed_case(tmp_path)
    out = render_executive_html(cd)
    html = out.read_text()
    # Objective heading omitted (no objective_statement on metadata)
    assert "<h2>Objective</h2>" not in html
    # Investigator row omitted from Case Details when not supplied
    assert "Investigator" not in html


# --- findings + glossary integration --------------------------------------

def test_glossary_appendix_only_lists_used_terms(tmp_path):
    """The appendix must scan the rendered body and pick up only terms
    actually present, not the entire glossary."""
    f = Finding(
        case_id="exec-test", agent="disk_forensicator",
        claim="Disk anomaly [LSASS_OUTSIDE_SYSTEM32] in slot002",
        confidence="high", evidence=[_ev()],
        hypotheses_supported=["H_CREDENTIAL_ACCESS"],
    )
    cd = _seed_case(tmp_path, extra_findings=[f])
    out = render_executive_html(cd)
    html = out.read_text()
    # The translated form (from glossary) appears in the body
    assert "fake credential process" in html
    # The appendix lists the LSASS_OUTSIDE_SYSTEM32 entry (because it's
    # used in the rendered body via the translation)
    # We can verify by looking for the term inside a glossary-entry div
    matches = re.findall(
        r"<div class='glossary-entry'>.*?</div>",
        html, re.DOTALL,
    )
    # At minimum the body's translation should drive at least one
    # appendix entry.
    assert len(matches) >= 1
    # Non-used glossary terms should NOT appear in the appendix.
    # T1003.001 was never referenced — it must not be in the appendix.
    assert "T1003.001" not in html


def test_findings_use_human_summary_when_present(tmp_path):
    """human_summary is the agents' opt-in to clean exec prose; when
    set, the renderer prefers it over the raw analyst claim."""
    f = Finding(
        case_id="exec-test", agent="disk_forensicator",
        claim="Disk anomaly [LSASS_OUTSIDE_SYSTEM32] in slot002-off673792 — disguise of credential subsystem",
        confidence="high",
        evidence=[_ev(human_summary="A malicious copy of the Windows credential service was found in the wrong folder.")],
        hypotheses_supported=["H_CREDENTIAL_ACCESS"],
    )
    # Stuff a real timestamp into the evidence so chronological list picks it up.
    f.evidence[0].extracted_facts = {"ts_utc": "2024-04-01T12:00:00+00:00"}
    cd = _seed_case(tmp_path, extra_findings=[f])
    out = render_executive_html(cd)
    html = out.read_text()
    assert "malicious copy of the Windows credential service" in html
    # Internal token must not appear in the chronological body.
    # (It might appear inside the Findings section header lookup.)
    assert "slot002-off673792" not in html


# --- recommendations -------------------------------------------------------

def test_recommendations_section_cites_finding_ids(tmp_path):
    f = Finding(
        case_id="exec-test", agent="lateral_movement_analyst",
        claim="Lateral movement via PowerShell remoting",
        confidence="high", evidence=[_ev()],
        hypotheses_supported=["H_LATERAL_MOVEMENT"],
    )
    cd = _seed_case(tmp_path, extra_findings=[f])
    out = render_executive_html(cd)
    html = out.read_text()
    assert "Recommendations" in html
    # The triggered recommendation cites the finding ID
    assert f.finding_id in html
    # Advisory disclaimer is included
    assert "advisory" in html.lower()


def test_no_recommendations_renders_empty_message(tmp_path):
    """When no rule fires, the section emits a placeholder rather than
    being missing (so report layout stays consistent)."""
    cd = _seed_case(tmp_path)  # zero findings → zero recommendations
    out = render_executive_html(cd)
    html = out.read_text()
    assert "Recommendations" in html
    # Either empty-state message or zero recommendation blocks
    assert ("No specific recommendations" in html
            or 'class="recommendation"' not in html)


# --- CLI flag end-to-end --------------------------------------------------

def test_cli_executive_flag_emits_executive_html(tmp_path, monkeypatch):
    """`el report --executive` writes reports/executive.html."""
    from typer.testing import CliRunner
    from el.cli import app

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "dummy.bin"
    src.write_bytes(b"hi\n")
    m = intake_mod.intake(src, case_id="cli-exec")
    with open_ledger(m.case_dir):
        pass
    runner = CliRunner()
    result = runner.invoke(app, ["report", str(m.case_dir),
                                  "--executive", "--no-html"])
    assert result.exit_code == 0, result.output
    assert (Path(m.case_dir) / "reports" / "executive.html").exists()


def test_cli_default_omits_executive_html(tmp_path, monkeypatch):
    """Default `el report` (no --executive) does NOT emit the exec
    report — analyst flow stays unchanged for users who don't ask
    for the new tier."""
    from typer.testing import CliRunner
    from el.cli import app

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "dummy.bin"
    src.write_bytes(b"hi\n")
    m = intake_mod.intake(src, case_id="cli-no-exec")
    with open_ledger(m.case_dir):
        pass
    runner = CliRunner()
    result = runner.invoke(app, ["report", str(m.case_dir), "--no-html"])
    assert result.exit_code == 0, result.output
    assert not (Path(m.case_dir) / "reports" / "executive.html").exists()
