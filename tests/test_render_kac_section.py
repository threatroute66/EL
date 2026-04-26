"""Smoke test: render_report inserts a KAC section between the
Diamond Model section and the Findings list.

Wires the new ``el.reporting.kac`` projection into the deterministic
report path in ``el.reporting.render`` (commit that introduced the
KAC template + Admiralty fields).
"""
from pathlib import Path

import pytest

from el.evidence.ledger import insert as insert_finding
from el.reporting.render import render_report
from el.schemas.finding import EvidenceItem, Finding


def _ev(**kw) -> EvidenceItem:
    base = dict(tool="vol3", version="2.20", command="vol3 ...",
                output_sha256="ab" * 32, output_path="/tmp/out.txt")
    base.update(kw)
    return EvidenceItem(**base)


def test_render_includes_kac_section(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "reports").mkdir()
    f = Finding(
        case_id="c1", agent="memory_forensicator",
        claim="vol3 hidden process candidate",
        confidence="low",
        evidence=[_ev()],
    )
    insert_finding(case_dir, f)
    md_path = render_report(
        case_dir=case_dir, case_id="c1",
        manifest={"input": "evidence.dmp"},
        iocs=None, techniques=None,
        ach_ranking=None, diagnostic=None,
    )
    md = md_path.read_text()
    assert "## Key Assumptions Check" in md
    # Baseline + 1 derived (low-confidence) assumption all show up
    assert "Intake correctly identified" in md
    assert "low-confidence claim" in md.lower()
    # The Tally line is the visual cue reviewers scan first
    assert "**Tally:**" in md
    # KAC must precede the Findings list (its purpose is to frame
    # them, not summarise after)
    assert md.index("## Key Assumptions Check") < md.index("## Findings")
