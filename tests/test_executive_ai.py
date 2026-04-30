"""Phase 10 tests for the AI-generated executive summary.

Locks in:
  * Cache key invalidation when findings change
  * Cache hit returns the same text without an API call
  * The DISCLAIMER_LABEL string surfaces in rendered HTML whenever
    the AI summary is present
  * Missing ANTHROPIC_API_KEY → fallback to deterministic digest;
    no exception, no silent feature loss
  * The findings payload sent to the LLM excludes knowledge_lookup
    chatter (Layer-3 cross-case context — not the case's own evidence)

The Anthropic API call itself is stubbed at the SDK level so the
test suite stays deterministic + offline.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from el.evidence import intake as intake_mod
from el.evidence.ledger import insert as ledger_insert
from el.reporting.executive_ai import (
    DISCLAIMER_LABEL,
    _CACHE_FILENAME,
    _compute_cache_key,
    _findings_for_prompt,
    synthesize_executive_ai,
)
from el.reporting.narrative import (
    BeatBlock,
    BEATS,
    NarrativeReport,
)
from el.schemas.finding import EvidenceItem, Finding


def _ev() -> EvidenceItem:
    return EvidenceItem(
        tool="x", version="1", command="y", output_sha256="0" * 64,
        output_path="/tmp/z",
    )


def _f(**kw) -> Finding:
    base = dict(case_id="ai-test", agent="a", claim="x",
                confidence="high", evidence=[_ev()],
                hypotheses_supported=[])
    base.update(kw)
    return Finding(**base)


def _empty_beats() -> list[BeatBlock]:
    return [BeatBlock(beat=b, heading=b, earliest=None, latest=None,
                      finding_count=0) for b in BEATS]


def _nr(**kw) -> NarrativeReport:
    base = dict(
        case_id="ai-test", leading_hypothesis="H_APT_ESPIONAGE",
        leading_score=25, leading_gap=8,
        runner_up_hypothesis="H_ANTI_FORENSICS", runner_up_score=17,
        beats=_empty_beats(), alt_beats=[],
        unresolved_count=0, insufficient_count=0,
        insufficient_findings=[],
    )
    base.update(kw)
    return NarrativeReport(**base)


@pytest.fixture
def case_dir(tmp_path):
    cd = tmp_path / "case"
    (cd / "reports").mkdir(parents=True)
    return cd


@pytest.fixture
def stub_anthropic(monkeypatch):
    """Replace anthropic.Anthropic so the SDK never makes a real
    network call. Returns a sentinel string the test can verify
    came from the stub."""
    calls: list[dict] = []

    class _Block:
        def __init__(self, text: str):
            self.text = text
            self.type = "text"

    class _Msg:
        def __init__(self, text: str):
            self.content = [_Block(text)]

    class _Messages:
        def __init__(self, fixed_text: str):
            self._text = fixed_text

        def create(self, **kwargs):
            calls.append(kwargs)
            return _Msg(self._text)

    class _Client:
        def __init__(self, **kwargs):
            self.messages = _Messages(
                "STUBBED AI SUMMARY — investigation describes a "
                "targeted intrusion with strong evidentiary support."
            )

    import anthropic
    monkeypatch.setattr(anthropic, "Anthropic", _Client)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-stub-key")
    return calls


# ---------------------------------------------------------------------------
# Cache key invariants
# ---------------------------------------------------------------------------

def test_cache_key_stable_across_calls_with_same_inputs():
    nr = _nr()
    findings = [_f(claim=f"finding {i}") for i in range(5)]
    a = _compute_cache_key(nr, findings)
    b = _compute_cache_key(nr, findings)
    assert a == b


def test_cache_key_invalidates_when_findings_change():
    nr = _nr()
    findings_a = [_f(claim=f"a-{i}") for i in range(3)]
    findings_b = [_f(claim=f"b-{i}") for i in range(3)]
    assert _compute_cache_key(nr, findings_a) != _compute_cache_key(nr, findings_b)


def test_cache_key_invalidates_when_leading_hypothesis_changes():
    findings = [_f() for _ in range(3)]
    nr_a = _nr(leading_hypothesis="H_APT_ESPIONAGE", leading_score=25)
    nr_b = _nr(leading_hypothesis="H_RANSOMWARE", leading_score=12)
    assert _compute_cache_key(nr_a, findings) != _compute_cache_key(nr_b, findings)


# ---------------------------------------------------------------------------
# Cache hit / miss + LLM call counting
# ---------------------------------------------------------------------------

def test_first_call_hits_api_and_writes_cache(case_dir, stub_anthropic):
    nr = _nr()
    findings = [_f(claim=f"x-{i}") for i in range(3)]
    result = synthesize_executive_ai(nr, findings, case_dir)
    assert result is not None
    text, meta = result
    assert "STUBBED AI SUMMARY" in text
    assert meta["cache"] == "miss"
    assert (case_dir / "reports" / _CACHE_FILENAME).exists()
    assert len(stub_anthropic) == 1     # one API call


def test_second_call_with_unchanged_inputs_hits_cache(case_dir, stub_anthropic):
    nr = _nr()
    findings = [_f(claim=f"x-{i}") for i in range(3)]
    synthesize_executive_ai(nr, findings, case_dir)
    text2, meta2 = synthesize_executive_ai(nr, findings, case_dir)
    assert meta2["cache"] == "hit"
    assert "STUBBED AI SUMMARY" in text2
    assert len(stub_anthropic) == 1     # SECOND call did not hit API


def test_changed_findings_invalidates_cache_triggers_new_call(case_dir, stub_anthropic):
    nr = _nr()
    findings_a = [_f(claim=f"a-{i}") for i in range(3)]
    synthesize_executive_ai(nr, findings_a, case_dir)
    findings_b = [_f(claim=f"b-{i}") for i in range(3)]
    text2, meta2 = synthesize_executive_ai(nr, findings_b, case_dir)
    assert meta2["cache"] == "miss"
    assert len(stub_anthropic) == 2     # cache was invalidated; API hit again


def test_regenerate_flag_bypasses_cache(case_dir, stub_anthropic):
    nr = _nr()
    findings = [_f(claim=f"x-{i}") for i in range(3)]
    synthesize_executive_ai(nr, findings, case_dir)
    synthesize_executive_ai(nr, findings, case_dir, regenerate=True)
    assert len(stub_anthropic) == 2     # regenerate forced a second call


# ---------------------------------------------------------------------------
# Fallback when API key absent
# ---------------------------------------------------------------------------

def test_missing_api_key_returns_none(case_dir, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    nr = _nr()
    findings = [_f() for _ in range(3)]
    assert synthesize_executive_ai(nr, findings, case_dir) is None


def test_api_call_failure_returns_none(case_dir, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-stub-key")
    import anthropic

    class _BoomMessages:
        def create(self, **kwargs):
            raise RuntimeError("test stub: simulated API failure")

    class _BoomClient:
        def __init__(self, **kwargs):
            self.messages = _BoomMessages()

    monkeypatch.setattr(anthropic, "Anthropic", _BoomClient)
    nr = _nr()
    findings = [_f() for _ in range(3)]
    assert synthesize_executive_ai(nr, findings, case_dir) is None


# ---------------------------------------------------------------------------
# LLM payload hygiene
# ---------------------------------------------------------------------------

def test_findings_for_prompt_drops_knowledge_lookup_chatter():
    findings = [
        _f(agent="disk_forensicator", claim="real signal"),
        _f(agent="knowledge_lookup", claim="cross-case overlap noise"),
        _f(agent="knowledge_lookup", claim="another noise"),
        _f(agent="lateral_movement_analyst", claim="another real signal"),
    ]
    selected = _findings_for_prompt(findings)
    assert all(f["agent"] != "knowledge_lookup" for f in selected)
    assert len(selected) == 2


def test_findings_for_prompt_orders_by_confidence():
    findings = [
        _f(claim="low signal", confidence="low"),
        _f(claim="medium signal", confidence="medium"),
        _f(claim="high signal", confidence="high"),
        Finding(case_id="ai-test", agent="a", claim="insufficient",
                confidence="insufficient"),
    ]
    selected = _findings_for_prompt(findings)
    confidences = [f["confidence"] for f in selected]
    assert confidences == ["high", "medium", "low", "insufficient"]


# ---------------------------------------------------------------------------
# Renderer integration: disclaimer label always present with AI summary
# ---------------------------------------------------------------------------

def test_renderer_includes_disclaimer_when_ai_summary_present(tmp_path, monkeypatch, stub_anthropic):
    """End-to-end: render a case where ANTHROPIC_API_KEY is set + the
    SDK is stubbed. The DISCLAIMER_LABEL must appear in the rendered
    executive HTML so a reader can't mistake the AI prose for the
    deterministic Findings section."""
    from el.reporting.executive import render_executive_html
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "ev.bin"
    src.write_bytes(b"hello\n")
    m = intake_mod.intake(src, case_id="ai-render-test")
    cd = Path(m.case_dir)
    with open_ledger(cd):
        pass
    out = render_executive_html(cd)
    html = out.read_text()
    assert DISCLAIMER_LABEL in html
    assert "STUBBED AI SUMMARY" in html
    assert "ai-disclaimer" in html


def test_renderer_no_disclaimer_when_no_api_key(tmp_path, monkeypatch):
    """Without the API key, the deterministic digest renders and the
    AI disclaimer is NOT shown — there's no AI text to disclaim."""
    from el.reporting.executive import render_executive_html
    from el.evidence.ledger import open_ledger

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "ev.bin"
    src.write_bytes(b"hello\n")
    m = intake_mod.intake(src, case_id="no-ai-test")
    cd = Path(m.case_dir)
    with open_ledger(cd):
        pass
    out = render_executive_html(cd)
    html = out.read_text()
    assert DISCLAIMER_LABEL not in html
    # The CSS class definition lives in the embedded stylesheet
    # (small + harmless), but no actual <div class='ai-disclaimer'>
    # element should be emitted when no AI summary fired.
    assert "<div class='ai-disclaimer'" not in html
    # Deterministic digest path renders the headline as <strong>...
    assert "<strong>" in html
