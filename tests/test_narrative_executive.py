"""Phase 1.1 contract tests for synthesize_executive().

The executive digest is a non-expert projection of the same
NarrativeReport the analyst tier consumes. These tests lock in the
contract: digest is jargon-free where the glossary covers, prefers
agent-supplied EvidenceItem.human_summary over raw claim text, and
sentence count stays in the 6-12 band.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from el.schemas.finding import EvidenceItem, Finding
from el.reporting.narrative import (
    BeatBlock,
    BEATS,
    ExecutiveDigest,
    NarrativeReport,
    synthesize_executive,
)


_FID_RE = re.compile(r"\[[0-9A-Z]{20,30}\]")


def _evidence(human_summary: str | None = None) -> EvidenceItem:
    return EvidenceItem(
        tool="vol.py", version="2.20.0",
        command="windows.pstree", output_sha256="0" * 64,
        output_path="/tmp/x", human_summary=human_summary,
    )


def _finding(
    *, claim: str = "x", confidence="high",
    hypotheses_supported: list[str] | None = None,
    human_summary: str | None = None,
) -> Finding:
    return Finding(
        case_id="c", agent="memory_forensicator", claim=claim,
        confidence=confidence,
        evidence=[_evidence(human_summary=human_summary)],
        hypotheses_supported=hypotheses_supported or [],
    )


def _empty_beat(b: str) -> BeatBlock:
    return BeatBlock(beat=b, heading=b, earliest=None, latest=None,
                     finding_count=0)


def _populated_beat(b: str, fs: list[Finding]) -> BeatBlock:
    return BeatBlock(beat=b, heading=b, earliest=None, latest=None,
                     finding_count=len(fs), top_findings=fs)


def _nr(
    *, leading: str | None = "H_APT_ESPIONAGE", score: int = 25, gap: int = 8,
    runner: str | None = "H_ANTI_FORENSICS", runner_score: int = 17,
    beats: list[BeatBlock] | None = None,
    insufficient: list[Finding] | None = None,
    time_range: tuple[str | None, str | None] = (None, None),
    prologue: dict[str, str] | None = None,
) -> NarrativeReport:
    return NarrativeReport(
        case_id="c", leading_hypothesis=leading, leading_score=score,
        leading_gap=gap, runner_up_hypothesis=runner,
        runner_up_score=runner_score,
        beats=beats or [_empty_beat(b) for b in BEATS],
        alt_beats=[], unresolved_count=0, insufficient_count=len(insufficient or []),
        attack_chain=[], evidence_time_range=time_range,
        prologue_facts=prologue or {},
        insufficient_findings=insufficient or [], pivots=[],
    )


# --- contract: digest shape -------------------------------------------------

def test_digest_returns_executive_digest():
    d = synthesize_executive(_nr())
    assert isinstance(d, ExecutiveDigest)
    assert d.headline
    assert d.confidence_phrase
    assert isinstance(d.summary_sentences, list)


def test_digest_paragraph_joins_sentences():
    d = synthesize_executive(_nr())
    para = d.as_paragraph()
    assert para
    for s in d.summary_sentences:
        assert s in para


# --- headline translation ---------------------------------------------------

def test_known_hypothesis_translates_to_plain_english():
    d = synthesize_executive(_nr(leading="H_APT_ESPIONAGE"))
    assert d.headline == "targeted intrusion"
    # And the headline should appear bolded in the first sentence.
    assert "targeted intrusion" in d.summary_sentences[0]
    # Internal hypothesis token must NOT appear in any sentence.
    for s in d.summary_sentences:
        assert "H_APT_ESPIONAGE" not in s


def test_no_leading_hypothesis_yields_neutral_headline():
    d = synthesize_executive(_nr(leading=None, score=0, gap=99, runner=None,
                                   runner_score=0))
    assert d.headline.lower().startswith("no primary explanation")


def test_unknown_hypothesis_id_falls_back_gracefully():
    """An unmapped H_FOO must not leak the raw token to the executive."""
    d = synthesize_executive(_nr(leading="H_NEVER_REGISTERED"))
    for s in d.summary_sentences:
        assert "H_NEVER_REGISTERED" not in s


# --- confidence phrases at thresholds --------------------------------------

@pytest.mark.parametrize("score,gap,expected_substr", [
    (0, 99, "too thin"),                            # no evidence
    (12, 7, "strongly supports"),                   # strong
    (5, 3, "moderately supports"),                  # moderate
    (2, 1, "preliminary"),                          # preliminary
])
def test_confidence_phrases_match_thresholds(score, gap, expected_substr):
    d = synthesize_executive(_nr(score=score, gap=gap))
    assert expected_substr in d.confidence_phrase


def test_score_zero_includes_rigor_disclaimer():
    """Forensic charter: never advocate a single conclusion when no
    hypothesis crossed the threshold."""
    d = synthesize_executive(_nr(score=0, gap=99))
    joined = " ".join(d.summary_sentences).lower()
    assert "does not advocate a single conclusion" in joined


# --- runner-up surfacing ---------------------------------------------------

def test_small_gap_surfaces_runner_up():
    d = synthesize_executive(_nr(
        leading="H_APT_ESPIONAGE", score=5, gap=1,
        runner="H_ANTI_FORENSICS", runner_score=4,
    ))
    joined = " ".join(d.summary_sentences)
    assert "evidence tampering" in joined  # plain-English form of H_ANTI_FORENSICS


def test_large_gap_does_not_surface_runner_up():
    d = synthesize_executive(_nr(
        leading="H_APT_ESPIONAGE", score=25, gap=8,
        runner="H_ANTI_FORENSICS", runner_score=17,
    ))
    joined = " ".join(d.summary_sentences)
    assert "evidence tampering" not in joined


# --- time range surfaces ---------------------------------------------------

def test_time_range_phrase_present_when_evidence_dated():
    d = synthesize_executive(_nr(
        time_range=("2024-04-01T00:00:00", "2024-04-30T23:59:59"),
    ))
    assert d.time_range_phrase
    joined = " ".join(d.summary_sentences)
    assert "2024-04-01" in joined
    assert "2024-04-30" in joined


def test_no_time_range_omits_phrase():
    d = synthesize_executive(_nr(time_range=(None, None)))
    assert d.time_range_phrase is None


# --- human_summary preferred over raw claim --------------------------------

def test_human_summary_prefers_over_raw_claim():
    """When an EvidenceItem has human_summary set, the digest uses it
    in beat sentences instead of running glossary-strip over the
    analyst claim. This is the agents' opt-in path to clean exec prose."""
    f = _finding(
        claim="Disk anomaly [LSASS_OUTSIDE_SYSTEM32] in slot002-off673792",
        human_summary="A malicious copy of the Windows credential service was found in the wrong folder.",
    )
    beats = [_empty_beat(b) for b in BEATS]
    # Replace the discovery beat with a populated one
    for i, bb in enumerate(beats):
        if bb.beat == "discovery":
            beats[i] = _populated_beat("discovery", [f])
    d = synthesize_executive(_nr(beats=beats))
    joined = " ".join(d.summary_sentences)
    assert "malicious copy of the Windows credential service" in joined
    # And the analyst-internal token must not have leaked through.
    assert "LSASS_OUTSIDE_SYSTEM32" not in joined
    assert "slot002-off673792" not in joined


def test_glossary_translates_when_no_human_summary():
    """Without human_summary, the digest falls back to glossary-strip
    over the claim. Known tokens get translated; unknown tokens fall
    through."""
    f = _finding(
        claim="lsass.exe found at LSASS_OUTSIDE_SYSTEM32 — disguise pattern",
    )
    beats = [_empty_beat(b) for b in BEATS]
    for i, bb in enumerate(beats):
        if bb.beat == "discovery":
            beats[i] = _populated_beat("discovery", [f])
    d = synthesize_executive(_nr(beats=beats))
    joined = " ".join(d.summary_sentences)
    assert "fake credential process" in joined  # glossary translation
    assert "LSASS_OUTSIDE_SYSTEM32" not in joined  # raw token gone


# --- sentence count + no leakage -------------------------------------------

def test_digest_sentence_count_in_band_for_populated_case():
    """Spec target is 8-12 sentences for a populated case. We assemble
    a case with multiple beats + a time range + open questions to
    exercise the full sentence-construction path."""
    f1 = _finding(claim="something ran", hypotheses_supported=["H_APT_ESPIONAGE"])
    f2 = _finding(claim="creds were dumped", hypotheses_supported=["H_CREDENTIAL_ACCESS"])
    f3 = _finding(claim="lateral move detected", hypotheses_supported=["H_LATERAL_MOVEMENT"])
    insufficient = [
        _finding(claim="missing data 1", confidence="insufficient"),
        _finding(claim="missing data 2", confidence="insufficient"),
    ]
    # Note: insufficient findings have no evidence, but our _finding
    # helper always attaches one. Strip evidence to satisfy the model.
    insufficient = [
        Finding(case_id="c", agent="x", claim=f.claim,
                confidence="insufficient")
        for f in insufficient
    ]
    beats = [_empty_beat(b) for b in BEATS]
    for i, bb in enumerate(beats):
        if bb.beat == "execution":
            beats[i] = _populated_beat("execution", [f1])
        elif bb.beat == "discovery":
            beats[i] = _populated_beat("discovery", [f2])
        elif bb.beat == "lateral":
            beats[i] = _populated_beat("lateral", [f3])
    d = synthesize_executive(_nr(
        beats=beats, insufficient=insufficient,
        time_range=("2024-04-01T00:00:00", "2024-04-30T00:00:00"),
    ))
    assert 6 <= len(d.summary_sentences) <= 12, (
        f"sentence count out of band for populated case: "
        f"{len(d.summary_sentences)}"
    )


def test_digest_sentence_count_floor_for_sparse_case():
    """Sparse case (no beats with findings, no time range, no open
    questions) gracefully degrades. The padding adds factual filler
    rather than inventing content; final length should still read as
    a coherent paragraph (≥3 sentences)."""
    d = synthesize_executive(_nr())
    assert len(d.summary_sentences) >= 3


def test_digest_contains_no_finding_ids():
    """The exec tier never shows ULID finding IDs — those belong in
    the analyst report."""
    f = _finding(claim="something happened")
    beats = [_empty_beat(b) for b in BEATS]
    for i, bb in enumerate(beats):
        if bb.beat == "execution":
            beats[i] = _populated_beat("execution", [f])
    d = synthesize_executive(_nr(beats=beats))
    para = d.as_paragraph()
    assert _FID_RE.search(para) is None, (
        f"finding-id leak in executive digest: {para}"
    )


def test_digest_contains_handoff_sentence():
    """The last sentence always points the reader to the analyst report
    + recommendations section so the exec digest is never a dead end."""
    d = synthesize_executive(_nr())
    last = d.summary_sentences[-1].lower()
    assert "recommendations" in last or "findings" in last


# --- affected assets surface from prologue facts ---------------------------

def test_affected_assets_lifted_from_prologue():
    d = synthesize_executive(_nr(prologue={"evidence": "laptop.E01"}))
    assert "laptop.E01" in d.affected_assets


def test_affected_assets_empty_when_no_prologue():
    d = synthesize_executive(_nr(prologue={}))
    assert d.affected_assets == []
