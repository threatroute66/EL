"""Phase 10 tests for the AI-generated executive brief (schema_version=2).

Locks in:
  * Cache key invalidation when findings change (and when the schema
    version bumps — covered by the v2 cache being incompatible with
    a v1 cache file)
  * Cache hit returns the same brief without an API call
  * The DISCLAIMER_LABEL string + per-section AI chip surface in the
    rendered HTML whenever the brief is present
  * Missing ANTHROPIC_API_KEY → fallback to deterministic digest;
    no exception, no silent feature loss
  * The findings payload sent to the LLM excludes knowledge_lookup
    chatter (Layer-3 cross-case context — not the case's own evidence)
  * Malformed JSON or empty-section briefs are rejected; the
    deterministic fallback renders instead — no half-rendered briefs

The Anthropic API call itself is stubbed at the SDK level so the
test suite stays deterministic + offline.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from el.evidence import intake as intake_mod
from el.reporting.executive_ai import (
    DEFER_ENV,
    DISCLAIMER_LABEL,
    SCHEMA_VERSION,
    SECTION_AI_CHIP,
    _CACHE_FILENAME,
    _REQUEST_FILENAME,
    _compute_cache_key,
    _findings_for_prompt,
    _parse_brief,
    ExecutiveBrief,
    synthesize_executive_ai,
)
from el.reporting.narrative import (
    BeatBlock,
    BEATS,
    NarrativeReport,
)
from el.schemas.finding import EvidenceItem, Finding


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------

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


def _valid_brief_json() -> str:
    """Realistic well-formed brief the stub LLM would return."""
    return json.dumps({
        "schema_version": SCHEMA_VERSION,
        "what_happened": (
            "STUBBED-WHAT-HAPPENED — the host shows signs consistent "
            "with a targeted intrusion across a 52-minute window."
        ),
        "what_was_taken": (
            "STUBBED-WHAT-WAS-TAKEN\n\n"
            "- Project KITT documentation\n"
            "- Project Megaforce specifications\n"
        ),
        "where_it_went": (
            "STUBBED-WHERE-IT-WENT\n\n"
            "| Channel | Destination | Evidence |\n"
            "|---|---|---|\n"
            "| Removable USB | Lexar serial AAZ62W7KENRSJLHY | confirmed |\n"
        ),
        "when_timeline": (
            "STUBBED-WHEN-TIMELINE\n\n"
            "| Date (UTC) | Window | What |\n"
            "|---|---|---|\n"
            "| 2020-11-14 | 03:51-04:43 | Exfiltration window |\n"
        ),
        "risk_implications": (
            "STUBBED-RISK-IMPLICATIONS\n\n"
            "1. Confirmed loss of confidentiality.\n"
            "2. Multi-account exfiltration platform.\n"
        ),
        "confidence_and_limits": (
            "STUBBED-CONFIDENCE-AND-LIMITS — memory image alone "
            "supports 'opened'; disk image required for 'copied'."
        ),
    })


@pytest.fixture(autouse=True)
def _isolate_claude_code_env(monkeypatch):
    """The defer path now also fires when EL detects it's running
    inside a Claude Code session (CLAUDECODE / AI_AGENT env). When
    pytest itself is invoked from inside a Claude Code session those
    vars leak into the tests and silently turn defer ON, masking the
    "defer disabled → no request file" contract. Default OFF for
    every test in this module; the Claude-Code-path tests below opt
    back in explicitly."""
    monkeypatch.delenv("CLAUDECODE", raising=False)
    monkeypatch.delenv("AI_AGENT", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_SESSION_ID", raising=False)


@pytest.fixture
def case_dir(tmp_path):
    cd = tmp_path / "case"
    (cd / "reports").mkdir(parents=True)
    return cd


@pytest.fixture
def stub_anthropic(monkeypatch):
    """Replace anthropic.Anthropic so the SDK never makes a real
    network call. Returns a list of recorded calls so tests can
    count API invocations.

    The default stub returns a valid ExecutiveBrief JSON payload so
    the parse + cache path exercises end-to-end. Tests that need a
    different payload re-patch the inner ``_text`` attribute.
    """
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
            self.messages = _Messages(_valid_brief_json())

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


def test_cache_key_includes_schema_version():
    """The schema_version is part of the cache key. A future
    contract bump (SCHEMA_VERSION 2 → 3) must invalidate every
    cached brief from the previous schema."""
    from el.reporting import executive_ai as ea
    nr = _nr()
    findings = [_f() for _ in range(3)]
    key_at_v2 = _compute_cache_key(nr, findings)
    # Simulate a contract bump and re-key
    original = ea.SCHEMA_VERSION
    try:
        ea.SCHEMA_VERSION = 99
        key_at_v99 = _compute_cache_key(nr, findings)
    finally:
        ea.SCHEMA_VERSION = original
    assert key_at_v2 != key_at_v99


# ---------------------------------------------------------------------------
# Cache hit / miss + LLM call counting
# ---------------------------------------------------------------------------

def test_first_call_hits_api_and_writes_cache(case_dir, stub_anthropic):
    nr = _nr()
    findings = [_f(claim=f"x-{i}") for i in range(3)]
    result = synthesize_executive_ai(nr, findings, case_dir)
    assert result is not None
    brief, meta = result
    assert isinstance(brief, ExecutiveBrief)
    assert "STUBBED-WHAT-HAPPENED" in brief.what_happened
    assert meta["cache"] == "miss"
    assert (case_dir / "reports" / _CACHE_FILENAME).exists()
    assert len(stub_anthropic) == 1


def test_second_call_with_unchanged_inputs_hits_cache(case_dir, stub_anthropic):
    nr = _nr()
    findings = [_f(claim=f"x-{i}") for i in range(3)]
    synthesize_executive_ai(nr, findings, case_dir)
    brief2, meta2 = synthesize_executive_ai(nr, findings, case_dir)
    assert meta2["cache"] == "hit"
    assert isinstance(brief2, ExecutiveBrief)
    assert "STUBBED-WHAT-HAPPENED" in brief2.what_happened
    assert len(stub_anthropic) == 1     # second call did not hit API


def test_changed_findings_invalidates_cache_triggers_new_call(case_dir, stub_anthropic):
    nr = _nr()
    findings_a = [_f(claim=f"a-{i}") for i in range(3)]
    synthesize_executive_ai(nr, findings_a, case_dir)
    findings_b = [_f(claim=f"b-{i}") for i in range(3)]
    brief2, meta2 = synthesize_executive_ai(nr, findings_b, case_dir)
    assert meta2["cache"] == "miss"
    assert len(stub_anthropic) == 2


def test_regenerate_flag_bypasses_cache(case_dir, stub_anthropic):
    nr = _nr()
    findings = [_f(claim=f"x-{i}") for i in range(3)]
    synthesize_executive_ai(nr, findings, case_dir)
    synthesize_executive_ai(nr, findings, case_dir, regenerate=True)
    assert len(stub_anthropic) == 2


# ---------------------------------------------------------------------------
# Schema validation — load-bearing for the multi-section refactor
# ---------------------------------------------------------------------------

def test_parse_brief_accepts_valid_payload():
    brief = _parse_brief(_valid_brief_json())
    assert brief is not None
    assert isinstance(brief, ExecutiveBrief)
    assert brief.schema_version == SCHEMA_VERSION


def test_parse_brief_rejects_malformed_json():
    assert _parse_brief("not json at all") is None
    assert _parse_brief("") is None
    assert _parse_brief("[]") is None     # array, not object


def test_parse_brief_rejects_empty_section():
    """An empty section blanks out a slot in the rendered brief —
    the validator must reject the whole payload so the fallback
    deterministic digest renders instead."""
    payload = json.loads(_valid_brief_json())
    payload["risk_implications"] = "   "      # whitespace only
    assert _parse_brief(json.dumps(payload)) is None


def test_parse_brief_rejects_missing_section():
    payload = json.loads(_valid_brief_json())
    del payload["confidence_and_limits"]
    # Pydantic's required-field validation kicks in
    assert _parse_brief(json.dumps(payload)) is None


def test_parse_brief_strips_codefence():
    """Some models still wrap JSON in ```json fences. Strip and parse."""
    payload = "```json\n" + _valid_brief_json() + "\n```"
    brief = _parse_brief(payload)
    assert brief is not None


def test_synth_returns_none_when_llm_returns_garbage(case_dir, monkeypatch):
    """A model that ignores the schema instruction and returns prose
    must trigger the deterministic fallback, NOT a half-rendered
    brief."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-stub-key")
    import anthropic

    class _BadMessages:
        def create(self, **kwargs):
            class _B:
                text = "I refuse to follow your schema, here is prose instead."
                type = "text"
            class _M:
                content = [_B()]
            return _M()

    class _BadClient:
        def __init__(self, **kwargs):
            self.messages = _BadMessages()

    monkeypatch.setattr(anthropic, "Anthropic", _BadClient)
    nr = _nr()
    findings = [_f() for _ in range(3)]
    assert synthesize_executive_ai(nr, findings, case_dir) is None


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
# Path 3 — defer-to-Claude-Code request file
# ---------------------------------------------------------------------------

def test_defer_writes_request_file_when_no_api_key(case_dir, monkeypatch):
    """When EL_AI_BRIEF_DEFER is on and ANTHROPIC_API_KEY is absent,
    synthesize_executive_ai must write the request file and return
    None — the Claude Code skill will fulfil it out of band."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv(DEFER_ENV, "1")
    nr = _nr()
    findings = [_f(claim=f"x-{i}") for i in range(3)]
    result = synthesize_executive_ai(nr, findings, case_dir)
    assert result is None     # deterministic fallback this render
    req_path = case_dir / "reports" / _REQUEST_FILENAME
    assert req_path.exists(), "defer mode must drop a request file"
    payload = json.loads(req_path.read_text())
    # Schema requirements the Claude Code skill depends on
    assert payload["request_version"] == 1
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["cache_key"] == _compute_cache_key(nr, findings)
    assert payload["output_path"].endswith(_CACHE_FILENAME)
    assert "system_prompt" in payload and payload["system_prompt"]
    assert "context" in payload
    assert payload["context"]["case_id"] == "ai-test"
    # The skill MUST be able to find finding records — payload hygiene
    assert isinstance(payload["context"]["top_findings"], list)
    assert all("agent" in f for f in payload["context"]["top_findings"])


def test_defer_disabled_means_no_request_file(case_dir, monkeypatch):
    """Defer is opt-in: without EL_AI_BRIEF_DEFER, no request file is
    written even when there's no API key. The existing silent-None
    behaviour is preserved for callers that haven't opted in."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv(DEFER_ENV, raising=False)
    nr = _nr()
    findings = [_f() for _ in range(3)]
    assert synthesize_executive_ai(nr, findings, case_dir) is None
    assert not (case_dir / "reports" / _REQUEST_FILENAME).exists()


def test_defer_request_not_written_when_api_key_present(case_dir, stub_anthropic, monkeypatch):
    """Defer is only the FALLBACK when there's no API key. With an
    API key set, the direct API path runs even if defer is enabled."""
    monkeypatch.setenv(DEFER_ENV, "1")     # opt in
    # stub_anthropic also sets ANTHROPIC_API_KEY
    nr = _nr()
    findings = [_f() for _ in range(3)]
    result = synthesize_executive_ai(nr, findings, case_dir)
    assert result is not None              # direct API path fired
    assert not (case_dir / "reports" / _REQUEST_FILENAME).exists()


def test_cache_hit_skips_defer_request_write(case_dir, stub_anthropic, monkeypatch):
    """If a previous fulfilment already populated the cache file,
    a subsequent render WITHOUT an API key + with defer enabled must
    NOT write a new request file — the cached brief already serves
    this render."""
    # First render: produce a cached brief via the stub API
    nr = _nr()
    findings = [_f(claim=f"x-{i}") for i in range(3)]
    synthesize_executive_ai(nr, findings, case_dir)
    assert (case_dir / "reports" / _CACHE_FILENAME).exists()

    # Second render: no API key, defer on. Cache hits → no request.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv(DEFER_ENV, "1")
    result = synthesize_executive_ai(nr, findings, case_dir)
    assert result is not None              # cache hit
    brief, meta = result
    assert meta["cache"] == "hit"
    assert not (case_dir / "reports" / _REQUEST_FILENAME).exists()


# ---------------------------------------------------------------------------
# Path 3b — Claude Code session is detected as a first-class AI path
# ---------------------------------------------------------------------------

def test_claude_code_env_auto_enables_request_file(case_dir, monkeypatch):
    """When CLAUDECODE=1 is in the subprocess environment (set by the
    Claude Code CLI), the request file must be written automatically
    without the operator passing --defer-ai-brief / EL_AI_BRIEF_DEFER.
    The brief is being generated by Claude either way — just via the
    skill instead of the SDK — so the path is first-class, not a
    "deferral the operator has to opt into"."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv(DEFER_ENV, raising=False)
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "test-session-abc")

    nr = _nr()
    findings = [_f(claim=f"x-{i}") for i in range(3)]
    result = synthesize_executive_ai(nr, findings, case_dir)

    assert result is None  # deterministic fallback this render
    req_path = case_dir / "reports" / _REQUEST_FILENAME
    assert req_path.exists(), \
        "Claude Code session detection must write the request file"
    payload = json.loads(req_path.read_text())
    assert payload["trigger"] == "claude_code_session"
    assert payload["trigger_session_id"] == "test-session-abc"


def test_ai_agent_prefix_also_triggers_claude_code_path(case_dir, monkeypatch):
    """Older Claude Code versions may not set CLAUDECODE but DO set
    AI_AGENT=claude-code_<version>_agent. Either marker is sufficient
    to trigger the path."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv(DEFER_ENV, raising=False)
    monkeypatch.delenv("CLAUDECODE", raising=False)
    monkeypatch.setenv("AI_AGENT", "claude-code_2-1-139_agent")

    nr = _nr()
    findings = [_f() for _ in range(3)]
    assert synthesize_executive_ai(nr, findings, case_dir) is None
    req_path = case_dir / "reports" / _REQUEST_FILENAME
    assert req_path.exists()
    payload = json.loads(req_path.read_text())
    assert payload["trigger"] == "claude_code_session"


def test_explicit_defer_flag_recorded_in_trigger(case_dir, monkeypatch):
    """When the operator passed --defer-ai-brief (outside a Claude
    Code session) the trigger field records explicit_defer_flag so
    downstream tooling can tell the two paths apart."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv(DEFER_ENV, "1")
    # _isolate_claude_code_env already cleared CLAUDECODE / AI_AGENT

    nr = _nr()
    findings = [_f() for _ in range(3)]
    assert synthesize_executive_ai(nr, findings, case_dir) is None
    payload = json.loads(
        (case_dir / "reports" / _REQUEST_FILENAME).read_text())
    assert payload["trigger"] == "explicit_defer_flag"
    assert payload["trigger_session_id"] == ""


def test_claude_code_path_does_not_override_api_key(case_dir, stub_anthropic,
                                                     monkeypatch):
    """If ANTHROPIC_API_KEY is set the direct SDK path always wins,
    even from inside a Claude Code session — operators with a key
    get the cheaper / faster direct path."""
    monkeypatch.setenv("CLAUDECODE", "1")
    nr = _nr()
    findings = [_f() for _ in range(3)]
    result = synthesize_executive_ai(nr, findings, case_dir)
    assert result is not None
    assert not (case_dir / "reports" / _REQUEST_FILENAME).exists()


def test_skill_response_round_trips_through_cache(case_dir, monkeypatch):
    """Simulate the Claude Code skill: read the request file, build
    a valid brief, write the response to output_path with matching
    cache_key, delete the request file. The next call to
    synthesize_executive_ai (without API key, defer still on) must
    cache-hit the response."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv(DEFER_ENV, "1")

    nr = _nr()
    findings = [_f(claim=f"x-{i}") for i in range(3)]

    # First render writes the request
    assert synthesize_executive_ai(nr, findings, case_dir) is None
    req_path = case_dir / "reports" / _REQUEST_FILENAME
    payload = json.loads(req_path.read_text())

    # Skill stand-in: write a valid response at output_path
    response = {
        "__cache_key": payload["cache_key"],
        "__model": "claude-opus-4-7",
        "__generated_utc": "2026-05-11T00:00:00+00:00",
        "brief": json.loads(_valid_brief_json()),
    }
    Path(payload["output_path"]).write_text(json.dumps(response, indent=2))
    req_path.unlink()

    # Second render: cache hit, no new request file
    result = synthesize_executive_ai(nr, findings, case_dir)
    assert result is not None
    brief, meta = result
    assert meta["cache"] == "hit"
    assert isinstance(brief, ExecutiveBrief)
    assert "STUBBED-WHAT-HAPPENED" in brief.what_happened
    assert not req_path.exists()


# ---------------------------------------------------------------------------
# Renderer integration — disclaimer + per-section chip + section bodies
# ---------------------------------------------------------------------------

def test_renderer_includes_disclaimer_and_all_sections(tmp_path, monkeypatch, stub_anthropic):
    """End-to-end: render a case where ANTHROPIC_API_KEY is set + the
    SDK is stubbed. The DISCLAIMER_LABEL must appear, every section's
    display title must appear, the per-section AI chip must appear,
    and the markdown table from where_it_went must render as <table>.
    """
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

    assert DISCLAIMER_LABEL in html, "non-removable disclaimer missing"
    # Every section's header from the stub payload renders
    assert "STUBBED-WHAT-HAPPENED" in html
    assert "STUBBED-WHAT-WAS-TAKEN" in html
    assert "STUBBED-WHERE-IT-WENT" in html
    assert "STUBBED-WHEN-TIMELINE" in html
    assert "STUBBED-RISK-IMPLICATIONS" in html
    assert "STUBBED-CONFIDENCE-AND-LIMITS" in html
    # Per-section chip on every section
    assert html.count(SECTION_AI_CHIP) == 6, (
        f"expected 6 AI chips (one per section), got "
        f"{html.count(SECTION_AI_CHIP)}"
    )
    # Markdown tables actually rendered as HTML tables
    assert "<table>" in html
    # Section CSS class and brief container CSS class present
    assert "ai-section" in html
    assert "ai-brief" in html


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
    assert "<div class='ai-disclaimer'" not in html
    # Deterministic digest path renders the headline as <strong>
    assert "<strong>" in html
    # No per-section AI chip
    assert SECTION_AI_CHIP not in html


def test_renderer_falls_back_when_brief_rejected(tmp_path, monkeypatch):
    """If the LLM call succeeds but returns a malformed brief, the
    renderer must fall through to the deterministic digest — not
    render a half-blank brief."""
    from el.reporting.executive import render_executive_html
    from el.evidence.ledger import open_ledger
    import anthropic

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-stub-key")

    class _GarbageMessages:
        def create(self, **kwargs):
            class _B:
                text = "{ malformed json"
                type = "text"
            class _M:
                content = [_B()]
            return _M()

    class _GarbageClient:
        def __init__(self, **kwargs):
            self.messages = _GarbageMessages()

    monkeypatch.setattr(anthropic, "Anthropic", _GarbageClient)
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "ev.bin"
    src.write_bytes(b"hello\n")
    m = intake_mod.intake(src, case_id="garbage-ai-test")
    cd = Path(m.case_dir)
    with open_ledger(cd):
        pass
    out = render_executive_html(cd)
    html = out.read_text()
    # Deterministic fallback rendered, no AI artefacts. The class name
    # `ai-section` lives in the always-embedded stylesheet (harmless),
    # but no actual <section class='ai-section'> element should exist.
    assert DISCLAIMER_LABEL not in html
    assert SECTION_AI_CHIP not in html
    assert "<section class='ai-section'>" not in html
