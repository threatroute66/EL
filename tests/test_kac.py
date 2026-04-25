"""Key Assumptions Check (KAC) — structured-analytic-technique
template generation.

Closes the gap-doc Intel-depth bullet "KAC structured-technique
template". Tests cover:
  - baseline assumptions (always present, regardless of findings)
  - per-finding derivation: low-confidence claims, insufficient
    findings, external feeds, A2 heuristic evidence
  - markdown render: table shape, escape of pipes/newlines,
    tally line
  - extra-assumption appending
  - validation guards on the KACAssumption dataclass
"""
import pytest

from el.intel import kac
from el.intel.kac import KACAssumption, build_kac, baseline_count
from el.reporting.kac import render_kac_md
from el.schemas.finding import EvidenceItem, Finding


def _ev(**kw) -> EvidenceItem:
    base = dict(tool="vol3", version="2.20", command="vol3 ...",
                output_sha256="ab" * 32, output_path="/tmp/out.txt")
    base.update(kw)
    return EvidenceItem(**base)


def _f(claim: str, confidence: str, agent: str = "x",
        evidence: list | None = None) -> Finding:
    return Finding(
        case_id="c1", agent=agent, claim=claim,
        confidence=confidence,
        evidence=(evidence if evidence is not None else
                  ([_ev()] if confidence != "insufficient" else [])),
    )


# --- baseline assumptions -----------------------------------------------

def test_baseline_assumptions_non_empty():
    assert baseline_count() >= 5
    # Every baseline assumption must have a rationale pointer
    for a in kac.BASELINE_ASSUMPTIONS:
        assert a.rationale, f"baseline missing rationale: {a.text!r}"


def test_build_kac_with_no_findings_returns_baseline_only():
    out = build_kac()
    assert len(out) == baseline_count()


def test_build_kac_includes_top_hypothesis_assumption():
    out = build_kac(top_hypothesis="H_APT_ESPIONAGE")
    # baseline + 1 top-hypothesis assumption
    assert len(out) == baseline_count() + 1
    assert any("H_APT_ESPIONAGE" in a.text for a in out)


# --- per-finding derivation ---------------------------------------------

def test_low_confidence_finding_adds_assumption():
    findings = [_f("vol3 plugin saw a hidden process candidate",
                    "low", agent="memory_forensicator")]
    out = build_kac(findings)
    assert len(out) == baseline_count() + 1
    derived = out[baseline_count()]
    assert derived.confidence == "Caveats"
    assert derived.status == "Conditional"
    assert "memory_forensicator" in derived.rationale


def test_insufficient_finding_adds_gap_assumption():
    f = Finding(
        case_id="c1", agent="windows_artifact",
        claim="ESE recovery did not complete; UAL not parsed",
        confidence="insufficient",
    )
    out = build_kac([f])
    derived = out[baseline_count()]
    assert "gap" in derived.text.lower()
    assert derived.status == "Conditional"


def test_threat_feeds_finding_adds_feed_assumption_once():
    findings = [
        _f("MISP feed observed 203.0.113.5 in 2 prior cases",
           "low", agent="threat_feeds"),
        _f("MISP feed observed evil.example in 5 prior cases",
           "low", agent="threat_feeds"),
    ]
    out = build_kac(findings)
    feed_lines = [a for a in out if "MISP / TAXII" in a.text]
    # Even with 2 threat_feeds findings, the feed-trust assumption
    # is added once (de-duplicated on agent name)
    assert len(feed_lines) == 1


def test_a2_heuristic_evidence_adds_assumption():
    e = _ev(tool="yara", version="4.5",
            source_reliability="A", info_credibility="2")
    findings = [_f("YARA hit on 1 sample", "medium",
                    agent="threat_hunter", evidence=[e])]
    out = build_kac(findings)
    h_lines = [a for a in out if "YARA" in a.text or "Heuristic" in a.text]
    assert h_lines, "expected an A2-heuristic assumption"
    assert h_lines[0].status == "Conditional"


def test_a1_only_evidence_adds_no_heuristic_assumption():
    e = _ev(source_reliability="A", info_credibility="1")
    findings = [_f("EvtxECmd parsed 4624 success login", "high",
                    agent="windows_artifact", evidence=[e])]
    out = build_kac(findings)
    assert not any("Heuristic" in a.text for a in out)


def test_extra_assumptions_appended_last():
    extra = [KACAssumption(
        text="The network capture covers the full incident window.",
        confidence="Caveats", impact="High", status="Conditional",
        rationale="pcap manifest")]
    out = build_kac(extra=extra)
    assert out[-1].text.startswith("The network capture")


# --- KACAssumption validation ------------------------------------------

def test_kac_assumption_rejects_invalid_confidence():
    with pytest.raises(ValueError):
        KACAssumption(text="x", confidence="Maybe")


def test_kac_assumption_rejects_invalid_impact():
    with pytest.raises(ValueError):
        KACAssumption(text="x", impact="Critical")


def test_kac_assumption_rejects_invalid_status():
    with pytest.raises(ValueError):
        KACAssumption(text="x", status="Pending")


# --- markdown rendering ------------------------------------------------

def test_render_kac_produces_table():
    md = render_kac_md(top_hypothesis="H_NULL_BENIGN")
    assert "## Key Assumptions Check" in md
    assert "| # | Assumption" in md
    assert "| 1 |" in md
    assert "**Tally:**" in md


def test_render_header_level_configurable():
    md = render_kac_md(header_level=3)
    assert md.startswith("### Key Assumptions Check")


def test_render_escapes_pipes_in_text():
    extra = [KACAssumption(
        text="Pipe-bearing |claim| should not break the table",
        confidence="Solid", impact="Low", status="Valid",
        rationale="tests")]
    md = render_kac_md(extra=extra)
    # Find the row carrying our extra assumption
    line = next(L for L in md.splitlines()
                if "Pipe-bearing" in L)
    # All embedded pipes inside the cell are escaped
    assert "\\|claim\\|" in line


def test_render_escapes_newlines_in_rationale():
    extra = [KACAssumption(
        text="x", confidence="Solid", impact="Low", status="Valid",
        rationale="line1\nline2")]
    md = render_kac_md(extra=extra)
    # Newline replaced with space — markdown table integrity
    assert "line1\nline2" not in md
    assert "line1 line2" in md


def test_tally_line_counts_statuses():
    findings = [_f("low claim", "low"),
                Finding(case_id="c1", agent="x",
                        claim="gap", confidence="insufficient")]
    md = render_kac_md(findings)
    # baseline (all Valid) + 2 derived Conditional
    assert "2 Conditional" in md
