"""Phase 2.5 tests for the executive PDF renderer.

The PDF is the printable / emailable form of the executive report.
These tests lock in:

  * render_executive_pdf produces a non-empty file with a %PDF-1.x
    header (validating the WeasyPrint pipeline + paged-media CSS).
  * Missing WeasyPrint raises WeasyPrintNotAvailable rather than
    crashing with an opaque ImportError; the CLI catches that to
    emit a yellow warning.
  * `el report --executive --pdf` plumbs through end-to-end.
  * The doctor probe reports WeasyPrint correctly.

WeasyPrint is a heavy dep (cairo/pango/gdk-pixbuf system libs); a
CI environment may not have it. Tests that need real rendering use
pytest.importorskip so the suite stays green where the lib is
absent, while still exercising the contract on hosts that have it
(the SIFT box, primary dev environment).
"""
from __future__ import annotations

from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def case_with_executive_html(tmp_path, monkeypatch):
    """Build a minimal case + render the executive HTML so the PDF
    renderer has a real input."""
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.reporting.executive import render_executive_html

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "evidence.bin"
    src.write_bytes(b"hello pdf\n")
    m = intake_mod.intake(src, case_id="pdf-test")
    with open_ledger(m.case_dir):
        pass
    out = render_executive_html(Path(m.case_dir))
    return Path(m.case_dir), out


# ---------------------------------------------------------------------------
# Real rendering — only when WeasyPrint is importable
# ---------------------------------------------------------------------------

def test_pdf_render_produces_valid_pdf(case_with_executive_html):
    pytest.importorskip("weasyprint")
    from el.reporting.executive_pdf import render_executive_pdf
    _case, html_path = case_with_executive_html
    pdf = render_executive_pdf(html_path)
    assert pdf.exists()
    head = pdf.read_bytes()[:8]
    assert head.startswith(b"%PDF-"), f"missing PDF magic: {head!r}"
    # Non-empty content (a 0-byte PDF is technically valid magic but useless).
    assert pdf.stat().st_size > 1024


def test_pdf_default_output_path_next_to_html(case_with_executive_html):
    pytest.importorskip("weasyprint")
    from el.reporting.executive_pdf import render_executive_pdf
    case_dir, html_path = case_with_executive_html
    pdf = render_executive_pdf(html_path)
    assert pdf == html_path.with_suffix(".pdf")
    assert pdf.parent == case_dir / "reports"


def test_pdf_explicit_output_path_respected(tmp_path, case_with_executive_html):
    pytest.importorskip("weasyprint")
    from el.reporting.executive_pdf import render_executive_pdf
    _case, html_path = case_with_executive_html
    custom = tmp_path / "deliverable.pdf"
    pdf = render_executive_pdf(html_path, output_path=custom)
    assert pdf == custom
    assert pdf.exists()


def test_pdf_missing_html_raises_filenotfound(tmp_path):
    pytest.importorskip("weasyprint")
    from el.reporting.executive_pdf import render_executive_pdf
    with pytest.raises(FileNotFoundError):
        render_executive_pdf(tmp_path / "does-not-exist.html")


# ---------------------------------------------------------------------------
# Graceful skip when WeasyPrint missing
# ---------------------------------------------------------------------------

def test_missing_weasyprint_raises_typed_error(monkeypatch, case_with_executive_html):
    """Simulate an environment without weasyprint — the renderer must
    raise WeasyPrintNotAvailable, NOT a bare ImportError."""
    from el.reporting import executive_pdf
    _case, html_path = case_with_executive_html

    def _no_wp():
        raise executive_pdf.WeasyPrintNotAvailable(
            "test-injected: weasyprint not importable"
        )

    monkeypatch.setattr(executive_pdf, "_try_import_weasyprint", _no_wp)
    with pytest.raises(executive_pdf.WeasyPrintNotAvailable):
        executive_pdf.render_executive_pdf(html_path)


# ---------------------------------------------------------------------------
# Doctor probe
# ---------------------------------------------------------------------------

def test_doctor_probe_reports_weasyprint():
    from el.tooling import probe_weasyprint
    status = probe_weasyprint()
    assert status.name == "weasyprint"
    # If the lib is present, available is True with a version; if
    # absent, available is False with an explanatory note. Either is
    # a valid outcome — we lock in only the shape of the report.
    if status.available:
        assert status.version
    else:
        assert "skip" in status.note.lower() or "PDF" in status.note


# ---------------------------------------------------------------------------
# CLI flag end-to-end
# ---------------------------------------------------------------------------

def test_cli_pdf_flag_emits_pdf(tmp_path, monkeypatch):
    pytest.importorskip("weasyprint")
    from typer.testing import CliRunner
    from el.cli import app
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "dummy.bin"
    src.write_bytes(b"hi\n")
    m = intake_mod.intake(src, case_id="cli-pdf")
    with open_ledger(m.case_dir):
        pass
    runner = CliRunner()
    result = runner.invoke(
        app, ["report", str(m.case_dir),
              "--executive", "--pdf", "--no-html"],
    )
    assert result.exit_code == 0, result.output
    pdf = Path(m.case_dir) / "reports" / "executive.pdf"
    assert pdf.exists()
    assert pdf.read_bytes()[:5] == b"%PDF-"


def test_cli_no_executive_skips_pdf(tmp_path, monkeypatch):
    """`--no-executive --pdf` is a no-op for the PDF side — there's
    no exec HTML to render from. Verifies the flag wiring respects
    the dependency ordering (exec→pdf)."""
    from typer.testing import CliRunner
    from el.cli import app
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "dummy.bin"
    src.write_bytes(b"hi\n")
    m = intake_mod.intake(src, case_id="cli-pdf-no-exec")
    with open_ledger(m.case_dir):
        pass
    runner = CliRunner()
    result = runner.invoke(
        app, ["report", str(m.case_dir), "--no-executive", "--pdf",
               "--no-html"],
    )
    assert result.exit_code == 0, result.output
    pdf = Path(m.case_dir) / "reports" / "executive.pdf"
    assert not pdf.exists()


def test_cli_default_emits_pdf_when_weasyprint_present(tmp_path, monkeypatch):
    """Default `el report` produces executive.pdf — the executive tier
    (HTML + PDF) is on by default in Phase 5."""
    pytest.importorskip("weasyprint")
    from typer.testing import CliRunner
    from el.cli import app
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "dummy.bin"
    src.write_bytes(b"hi\n")
    m = intake_mod.intake(src, case_id="cli-default-pdf")
    with open_ledger(m.case_dir):
        pass
    runner = CliRunner()
    result = runner.invoke(app, ["report", str(m.case_dir), "--no-html"])
    assert result.exit_code == 0, result.output
    pdf = Path(m.case_dir) / "reports" / "executive.pdf"
    assert pdf.exists()
    assert pdf.read_bytes()[:5] == b"%PDF-"
