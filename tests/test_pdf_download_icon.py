"""Phase 5 tests for the PDF download icon + auto-emit defaults.

Locks in:
  * `el report` (no flags) emits all four artifacts: report.md,
    case.html, executive.html, executive.pdf.
  * case.html nav contains a `pdf-download` link pointing to
    executive.pdf with the SVG icon and `download` attribute.
  * combined.html's per-case Hosts table includes a PDF link for
    every case that has executive.pdf rendered, and skips it for
    cases that don't.
"""
from __future__ import annotations

from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rendered_case(tmp_path, monkeypatch):
    """Run `el report` (defaults) on a minimal intaken case and
    return the case_dir Path. Skips when WeasyPrint is missing — the
    icon-target executive.pdf only exists when PDF rendering succeeds."""
    pytest.importorskip("weasyprint")
    from typer.testing import CliRunner
    from el.cli import app
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "ev.bin"
    src.write_bytes(b"phase5\n")
    m = intake_mod.intake(src, case_id="phase5-default")
    with open_ledger(m.case_dir):
        pass
    runner = CliRunner()
    result = runner.invoke(app, ["report", str(m.case_dir)])
    assert result.exit_code == 0, result.output
    return Path(m.case_dir)


# ---------------------------------------------------------------------------
# Phase 5.1: auto-emit defaults
# ---------------------------------------------------------------------------

def test_default_report_emits_all_four_artifacts(rendered_case):
    """The four artifacts of a complete case render: markdown,
    analyst HTML, executive HTML, executive PDF — all on by default."""
    reports = rendered_case / "reports"
    assert (reports / "report.md").exists()
    assert (reports / "case.html").exists()
    assert (reports / "executive.html").exists()
    assert (reports / "executive.pdf").exists()


# ---------------------------------------------------------------------------
# Phase 5.2: PDF link in case.html
# ---------------------------------------------------------------------------

def test_case_html_nav_has_pdf_download_link(rendered_case):
    html = (rendered_case / "reports" / "case.html").read_text()
    # The link points to executive.pdf (relative — same reports/ dir)
    assert 'href="executive.pdf"' in html
    # download attribute makes it download instead of preview
    assert "pdf-download" in html
    assert "download" in html  # the HTML attr; defensive
    # Inline SVG icon is present (path data)
    assert "M8 1v10M4 7.5l4 4 4-4M2 14.5h12" in html


def test_case_html_pdf_link_is_in_nav(rendered_case):
    """The PDF link must be inside the <nav> block, not elsewhere."""
    import re
    html = (rendered_case / "reports" / "case.html").read_text()
    nav = re.search(r"<nav>(.*?)</nav>", html, re.DOTALL)
    assert nav, "case.html must have a <nav> block"
    assert 'href="executive.pdf"' in nav.group(1)


# ---------------------------------------------------------------------------
# Phase 5.3: PDF link in combined.html
# ---------------------------------------------------------------------------

def test_combined_html_includes_pdf_link_when_pdf_present(tmp_path, monkeypatch):
    """When a per-case executive.pdf exists, combined.html's Hosts
    row for that case includes a download link with the icon."""
    pytest.importorskip("weasyprint")
    from typer.testing import CliRunner
    from el.cli import app
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    # Build two cases, render reports for both
    case_dirs: list[Path] = []
    for cid, content in (("phase5-a", b"a\n"), ("phase5-b", b"b\n")):
        src = tmp_path / f"{cid}.bin"
        src.write_bytes(content)
        m = intake_mod.intake(src, case_id=cid)
        with open_ledger(m.case_dir):
            pass
        runner = CliRunner()
        runner.invoke(app, ["report", str(m.case_dir)])
        case_dirs.append(Path(m.case_dir))

    # Run combined-report. The default --out is hardcoded to
    # /opt/EL/cases/_combined/, which would bleed test output into
    # the real cases dir; pass --out to keep the test isolated.
    out_md = tmp_path / "_combined" / "phase5-combined" / "report.md"
    runner = CliRunner()
    result = runner.invoke(app, [
        "combined-report",
        str(case_dirs[0]), str(case_dirs[1]),
        "--name", "phase5-combined",
        "--out", str(out_md),
    ])
    assert result.exit_code == 0, result.output

    combined_html = out_md.with_name("combined.html")
    assert combined_html.exists()
    html = combined_html.read_text()
    # The PDF link uses the shared CSS class
    assert "pdf-download" in html
    # And references each case's executive.pdf via relative path
    assert "executive.pdf" in html


def test_combined_html_skips_pdf_link_when_pdf_missing(tmp_path, monkeypatch):
    """When a case has no executive.pdf (e.g. rendered with
    --no-pdf), combined.html omits the download link rather than
    emitting a broken anchor."""
    from typer.testing import CliRunner
    from el.cli import app
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    case_dirs: list[Path] = []
    for cid, content in (("phase5-c", b"c\n"), ("phase5-d", b"d\n")):
        src = tmp_path / f"{cid}.bin"
        src.write_bytes(content)
        m = intake_mod.intake(src, case_id=cid)
        with open_ledger(m.case_dir):
            pass
        runner = CliRunner()
        # Explicitly suppress exec + pdf
        runner.invoke(app, ["report", str(m.case_dir),
                             "--no-executive", "--no-pdf"])
        case_dirs.append(Path(m.case_dir))
        # Sanity: no exec PDF was written
        assert not (Path(m.case_dir) / "reports" / "executive.pdf").exists()

    out_md = tmp_path / "_combined" / "phase5-no-pdf" / "report.md"
    runner = CliRunner()
    result = runner.invoke(app, [
        "combined-report",
        str(case_dirs[0]), str(case_dirs[1]),
        "--name", "phase5-no-pdf",
        "--out", str(out_md),
    ])
    assert result.exit_code == 0, result.output

    combined_html = out_md.with_name("combined.html")
    html = combined_html.read_text()
    # The CSS class definition lives in the embedded stylesheet (small
    # and harmless), but no actual <a class='pdf-download'> link element
    # should be rendered when none of the cases have an exec PDF.
    assert "class='pdf-download'" not in html
    assert 'class="pdf-download"' not in html
