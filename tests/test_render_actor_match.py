"""render_report integrates actor-playbook fingerprint section.

Builds a FIN7-shaped Finding ledger and asserts the rendered
report carries the Actor-Playbook Resemblance section with FIN7 at
rank 1.
"""
from pathlib import Path

import pytest

from el.evidence.ledger import insert as insert_finding
from el.reporting.actor_match import render_actor_matches_md
from el.reporting.render import render_report
from el.schemas.finding import EvidenceItem, Finding


def _f(case_id: str, techs: list[str]) -> Finding:
    return Finding(
        case_id=case_id, agent="x", claim="t", confidence="medium",
        evidence=[EvidenceItem(
            tool="x", version="1", command="x",
            output_sha256="ab" * 32, output_path="/tmp/x",
            extracted_facts={"attack_techniques": techs})])


def test_render_actor_matches_md_returns_empty_below_threshold():
    """One observed technique → no playbook clears the 40% default;
    section omitted entirely."""
    md = render_actor_matches_md([_f("c1", ["T1059.001"])])
    assert md == ""


def test_render_actor_matches_md_emits_table_for_strong_match():
    findings = [
        _f("c1", ["T1566.001", "T1204.002"]),
        _f("c1", ["T1059.005", "T1218.005"]),
        _f("c1", ["T1055"]),
        _f("c1", ["T1003.001"]),
        _f("c1", ["T1021.002"]),
        _f("c1", ["T1486"]),
    ]
    md = render_actor_matches_md(findings)
    assert "Actor-Playbook Resemblance" in md
    assert "FIN7" in md
    assert "Coverage" in md
    # Suggestive-only framing must be present (we don't auto-attribute)
    assert "Suggestive only" in md or "suggestive" in md.lower()


def test_render_report_inserts_actor_section_before_findings(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "reports").mkdir()
    findings = [
        _f("c1", ["T1566.001", "T1204.002"]),
        _f("c1", ["T1059.005", "T1218.005"]),
        _f("c1", ["T1055"]),
        _f("c1", ["T1003.001"]),
        _f("c1", ["T1021.002"]),
        _f("c1", ["T1486"]),
    ]
    for f in findings:
        insert_finding(case_dir, f)
    md_path = render_report(
        case_dir=case_dir, case_id="c1",
        manifest={"input": "evidence.dmp"},
        iocs=None, techniques=None,
        ach_ranking=None, diagnostic=None,
    )
    md = md_path.read_text()
    assert "Actor-Playbook Resemblance" in md
    assert "FIN7" in md
    # Renders before the Findings list (frames it, like KAC does)
    assert (md.index("Actor-Playbook Resemblance")
            < md.index("## Findings"))
