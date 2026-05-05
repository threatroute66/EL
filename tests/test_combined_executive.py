"""Combined executive (non-technical) report — multi-host equivalent of
the per-case executive.html / executive.pdf pairing.

Locks two contracts:
  1. ``combined_executive.html`` + ``combined_executive.pdf`` are emitted
     by ``el combined-report`` alongside the technical combined.html
     dashboard.
  2. The combined.html topbar gets a download-icon anchor pointing at
     ``combined_executive.pdf`` (mirrors the per-case case.html ↔
     executive.pdf pattern).
"""
import json
from pathlib import Path

import pytest

from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger


@pytest.fixture
def two_minimal_cases(tmp_path, monkeypatch):
    """Stand up two minimal case dirs with intake + empty ledgers — enough
    for combined_executive to load slices for."""
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "knowledge.sqlite"))
    case_dirs: list[Path] = []
    for cid, content in (("ce-a", b"a\n"), ("ce-b", b"b\n")):
        src = tmp_path / f"{cid}.bin"
        src.write_bytes(content)
        m = intake_mod.intake(src, case_id=cid)
        with open_ledger(m.case_dir):
            pass
        case_dirs.append(Path(m.case_dir))
    return tmp_path, case_dirs


def test_combined_executive_html_renders(two_minimal_cases):
    tmp_path, case_dirs = two_minimal_cases
    from el.reporting.combined_executive import render_combined_executive
    out = tmp_path / "_combined" / "ce" / "combined_executive.html"
    written = render_combined_executive(case_dirs, out, name="ce")
    assert written.is_file()
    text = written.read_text()
    # Headline + structural sections must appear.
    assert "<h1>ce</h1>" in text
    assert "Executive Summary" in text
    assert "Per-Host Attribution" in text
    assert "Drill-down to technical detail" in text
    # CSS embedded (no external dep).
    assert "<style>" in text


def test_combined_executive_pdf_renders(two_minimal_cases):
    tmp_path, case_dirs = two_minimal_cases
    from el.reporting.combined_executive import (
        render_combined_executive, render_combined_executive_pdf,
    )
    out = tmp_path / "_combined" / "ce" / "combined_executive.html"
    render_combined_executive(case_dirs, out, name="ce")
    pdf = render_combined_executive_pdf(out)
    assert pdf.is_file()
    assert pdf.stat().st_size > 1000   # non-trivial PDF
    # PDF magic
    head = pdf.read_bytes()[:8]
    assert head.startswith(b"%PDF-")


def test_combined_html_links_to_executive_pdf_when_supplied(two_minimal_cases):
    """When ``executive_pdf_path`` is passed to render_combined_html,
    the topbar gains a pdf-download anchor pointing at it."""
    from el.reporting.combined_html import render_combined_html
    tmp_path, case_dirs = two_minimal_cases
    out = tmp_path / "_combined" / "ce" / "combined.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    # Synthetic placeholder for the exec PDF (combined_html only checks
    # is_file()).
    fake_pdf = out.with_name("combined_executive.pdf")
    fake_pdf.write_bytes(b"%PDF-1.4\n%placeholder\n")
    render_combined_html(case_dirs, out, name="ce",
                         executive_pdf_path=fake_pdf)
    text = out.read_text()
    # Anchor appears in the header (before the <nav>).
    head = text.split("<nav")[0]
    assert "Executive PDF" in head
    assert "combined_executive.pdf" in head
    assert "pdf-download" in head


def test_combined_html_omits_executive_link_when_pdf_missing(two_minimal_cases):
    """No icon should render when the path doesn't exist on disk."""
    from el.reporting.combined_html import render_combined_html
    tmp_path, case_dirs = two_minimal_cases
    out = tmp_path / "_combined" / "ce" / "combined.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    # Pass a nonexistent path → topbar must not render the link.
    fake_pdf = out.with_name("does-not-exist.pdf")
    render_combined_html(case_dirs, out, name="ce",
                         executive_pdf_path=fake_pdf)
    text = out.read_text()
    head = text.split("<nav")[0]
    assert "Executive PDF" not in head


def test_render_combined_html_backwards_compatible(two_minimal_cases):
    """Legacy callers that omit executive_pdf_path must still work."""
    from el.reporting.combined_html import render_combined_html
    tmp_path, case_dirs = two_minimal_cases
    out = tmp_path / "_combined" / "ce" / "combined.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    written = render_combined_html(case_dirs, out, name="ce")
    assert written.is_file()
