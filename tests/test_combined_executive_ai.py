"""Tests for combined_executive_ai — cross-host AI brief.

The combined dashboard previously had no AI synthesis of its own —
only per-host briefs were aggregated. This module produces a true
multi-host narrative (entry, lateral chain, data movement,
enterprise risk) that no per-host brief could on its own.

Pins:
  - schema rejects empty sections, accepts six-section payloads
  - cache key reflects bundle membership + per-case leading hyps
    + joint ACH leader (changes invalidate the cache deterministically)
  - cache read/write round-trip is lossless
  - defer-mode writes a request file with brief_kind == "combined_executive"
  - request file is self-describing (system_prompt + context + output_path)
    so the skill can fulfil without importing EL Python
  - no-API-key + defer-off returns None and writes nothing
  - context builder includes joint_ach + clock_baselines + shared_iocs
    + technique_union (the cross-host signals)
  - context builder degrades gracefully when those are None
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from el.reporting.combined_executive_ai import (
    CombinedExecutiveBrief,
    DEFER_ENV,
    SCHEMA_VERSION,
    _REQUEST_FILENAME,
    _compute_cache_key,
    _read_cache,
    _write_cache,
    build_context,
    synthesize_combined_executive_ai,
)


@pytest.fixture(autouse=True)
def _isolate_claude_code_env(monkeypatch):
    """Defer path now also fires on Claude Code detection — clear the
    env vars so "defer off → no request file" tests stay deterministic
    when pytest itself is invoked from inside a Claude Code session.
    Mirror of the same fixture in test_executive_ai.py."""
    monkeypatch.delenv("CLAUDECODE", raising=False)
    monkeypatch.delenv("AI_AGENT", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_SESSION_ID", raising=False)


@dataclass
class _StubSlice:
    case_id: str
    host_label: str = ""
    leading_hyp: str = ""
    leading_score: int = 0
    leading_gap: int = 0
    high_count: int = 0
    digest_text: str = ""

    def __post_init__(self):
        if not self.host_label:
            self.host_label = self.case_id


def _full_brief() -> dict:
    """Six-section payload that should pass validation cleanly."""
    return {
        "schema_version": 1,
        "cross_host_overview": "The attacker entered via DC and moved laterally.",
        "attack_chain": "| Step | Host | What | Evidence |\n|---|---|---|---|\n| 1 | dc | RDP login | confirmed |",
        "affected_hosts": "| Host | Role | Confidence | Key finding |\n|---|---|---|---|\n| dc | entry | high | EID 1149 ×87 |",
        "data_movement": "| From | To | Channel | Evidence |\n|---|---|---|---|\n| dc | nfury | SMB | plausible |",
        "enterprise_risk": "1. Domain controller credential theft.\n2. Lateral spread to workstations.",
        "confidence_and_gaps": "Per-host clocks all NT5DS-synced — timing trustworthy across the bundle.",
    }


# ---------------------------------------------------------------------------
# Schema — empty-section rejection
# ---------------------------------------------------------------------------

def test_schema_accepts_full_payload():
    b = CombinedExecutiveBrief.model_validate(_full_brief())
    b.reject_empty_sections()  # should not raise


def test_schema_rejects_empty_section():
    """Any single empty section must blow up the brief so the renderer
    falls back to deterministic — partial briefs are worse than no brief."""
    payload = _full_brief()
    payload["attack_chain"] = ""
    b = CombinedExecutiveBrief.model_validate(payload)
    with pytest.raises(ValueError, match="empty section.*attack_chain"):
        b.reject_empty_sections()


def test_schema_rejects_whitespace_only_section():
    payload = _full_brief()
    payload["enterprise_risk"] = "   \n   "
    b = CombinedExecutiveBrief.model_validate(payload)
    with pytest.raises(ValueError, match="empty section"):
        b.reject_empty_sections()


def test_schema_lists_every_empty_section_in_one_error():
    """Single combined ValueError listing all empty sections so the
    operator sees the full picture, not just the first failure."""
    payload = _full_brief()
    payload["attack_chain"] = ""
    payload["data_movement"] = ""
    b = CombinedExecutiveBrief.model_validate(payload)
    with pytest.raises(ValueError) as ei:
        b.reject_empty_sections()
    assert "attack_chain" in str(ei.value)
    assert "data_movement" in str(ei.value)


# ---------------------------------------------------------------------------
# Cache key — reflects bundle membership + leading hypotheses
# ---------------------------------------------------------------------------

def test_cache_key_stable_when_inputs_unchanged():
    slices = [_StubSlice("a", leading_hyp="H_X", leading_score=10),
              _StubSlice("b", leading_hyp="H_Y", leading_score=5)]
    k1 = _compute_cache_key("bundle", slices, ("H_X", 15))
    k2 = _compute_cache_key("bundle", slices, ("H_X", 15))
    assert k1 == k2


def test_cache_key_changes_when_case_added():
    s1 = [_StubSlice("a", leading_hyp="H_X")]
    s2 = [_StubSlice("a", leading_hyp="H_X"), _StubSlice("b", leading_hyp="H_Y")]
    assert _compute_cache_key("bundle", s1, None) \
        != _compute_cache_key("bundle", s2, None)


def test_cache_key_changes_when_leading_hyp_flips():
    s1 = [_StubSlice("a", leading_hyp="H_X")]
    s2 = [_StubSlice("a", leading_hyp="H_Y")]
    assert _compute_cache_key("bundle", s1, None) \
        != _compute_cache_key("bundle", s2, None)


def test_cache_key_changes_when_joint_leader_flips():
    slices = [_StubSlice("a", leading_hyp="H_X", leading_score=10)]
    assert _compute_cache_key("bundle", slices, ("H_X", 10)) \
        != _compute_cache_key("bundle", slices, ("H_Y", 12))


def test_cache_key_changes_when_bundle_name_changes():
    """A bundle renamed (e.g. srl-2015 → srl-2015-r9) should pick
    up a new cache entry. The bundle name often encodes the rerun
    suffix; sharing cache across reruns would surface stale prose."""
    slices = [_StubSlice("a", leading_hyp="H_X")]
    assert _compute_cache_key("bundle-r1", slices, None) \
        != _compute_cache_key("bundle-r2", slices, None)


def test_cache_key_invariant_to_case_order():
    """Bundle is a SET of cases — passing them in a different order
    shouldn't bust the cache."""
    s1 = [_StubSlice("a", leading_hyp="H_X"),
          _StubSlice("b", leading_hyp="H_Y")]
    s2 = list(reversed(s1))
    assert _compute_cache_key("bundle", s1, None) \
        == _compute_cache_key("bundle", s2, None)


# ---------------------------------------------------------------------------
# Cache read/write round-trip
# ---------------------------------------------------------------------------

def test_cache_round_trip(tmp_path):
    cache_path = tmp_path / "combined_executive_ai_brief.json"
    brief = CombinedExecutiveBrief.model_validate(_full_brief())
    _write_cache(cache_path, "key123", brief, "claude-haiku-test")
    key, loaded = _read_cache(cache_path)
    assert key == "key123"
    assert loaded is not None
    assert loaded.cross_host_overview == brief.cross_host_overview


def test_cache_read_returns_none_on_missing(tmp_path):
    key, brief = _read_cache(tmp_path / "does_not_exist.json")
    assert key is None and brief is None


def test_cache_read_returns_none_on_malformed_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{this is not valid json")
    key, brief = _read_cache(p)
    assert key is None and brief is None


def test_cache_read_returns_none_when_brief_section_missing(tmp_path):
    """Cache file with no `brief` key — treat as miss."""
    p = tmp_path / "stub.json"
    p.write_text(json.dumps({"__cache_key": "k", "__model": "m"}))
    key, brief = _read_cache(p)
    assert key is None and brief is None


def test_cache_read_returns_none_when_brief_fails_schema(tmp_path):
    """Cache file holds a brief that's missing a required section —
    treat as miss so the next render synthesises fresh."""
    payload = _full_brief()
    payload["enterprise_risk"] = ""
    p = tmp_path / "stale.json"
    p.write_text(json.dumps({
        "__cache_key": "k", "__model": "m",
        "brief": payload,
    }))
    key, brief = _read_cache(p)
    assert key is None and brief is None


# ---------------------------------------------------------------------------
# Defer mode — writes a self-describing request file
# ---------------------------------------------------------------------------

def test_defer_writes_request_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv(DEFER_ENV, "1")
    slices = [_StubSlice("a", leading_hyp="H_X", leading_score=10)]
    result = synthesize_combined_executive_ai(
        bundle_name="my-bundle", slices=slices, combined_dir=tmp_path,
    )
    assert result is None  # defer-mode never returns a brief synchronously
    req = tmp_path / _REQUEST_FILENAME
    assert req.exists()
    payload = json.loads(req.read_text())
    assert payload["brief_kind"] == "combined_executive"
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["output_path"].endswith("combined_executive_ai_brief.json")
    assert "system_prompt" in payload and payload["system_prompt"]
    assert payload["context"]["bundle_name"] == "my-bundle"


def test_no_defer_no_key_returns_none_without_writing(tmp_path, monkeypatch):
    """Default posture — no API key + defer off → None + no files."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv(DEFER_ENV, raising=False)
    slices = [_StubSlice("a")]
    result = synthesize_combined_executive_ai(
        bundle_name="my-bundle", slices=slices, combined_dir=tmp_path,
    )
    assert result is None
    assert not (tmp_path / _REQUEST_FILENAME).exists()


def test_defer_request_is_self_describing(tmp_path, monkeypatch):
    """Skill must be able to fulfil from the request alone — no
    Python imports. Verify all the load-bearing fields are present."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv(DEFER_ENV, "1")
    slices = [_StubSlice("a")]
    synthesize_combined_executive_ai(
        bundle_name="b", slices=slices, combined_dir=tmp_path,
    )
    payload = json.loads((tmp_path / _REQUEST_FILENAME).read_text())
    for field in ("cache_key", "system_prompt", "context",
                   "output_path", "schema_version", "brief_kind",
                   "instructions_for_responder"):
        assert field in payload, f"missing self-describing field: {field}"


# ---------------------------------------------------------------------------
# Cache hit short-circuits synthesis
# ---------------------------------------------------------------------------

def test_cache_hit_returns_brief_without_calling_api(tmp_path, monkeypatch):
    """When the cache file matches the desired key, no API/defer
    side-effect happens — synthesis returns the cached brief directly."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv(DEFER_ENV, "1")  # would normally write request
    slices = [_StubSlice("a", leading_hyp="H_X", leading_score=10)]
    joint = [{"hyp_id": "H_X", "score": 10}]
    expected_key = _compute_cache_key("b", slices, ("H_X", 10))
    cache_path = tmp_path / "combined_executive_ai_brief.json"
    cache_path.write_text(json.dumps({
        "__cache_key": expected_key, "__model": "cached",
        "__generated_utc": "2026-01-01T00:00:00+00:00",
        "brief": _full_brief(),
    }))
    result = synthesize_combined_executive_ai(
        bundle_name="b", slices=slices, combined_dir=tmp_path,
        joint_ach=joint,
    )
    assert result is not None
    brief, meta = result
    assert meta["cache"] == "hit"
    assert brief.cross_host_overview == _full_brief()["cross_host_overview"]
    # Defer would have written a request file — confirm it didn't
    assert not (tmp_path / _REQUEST_FILENAME).exists()


def test_regenerate_bypasses_cache(tmp_path, monkeypatch):
    """--regenerate-ai-summary path: even when the cache matches,
    we re-fire (in defer mode this means writing a fresh request)."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv(DEFER_ENV, "1")
    slices = [_StubSlice("a", leading_hyp="H_X", leading_score=10)]
    key = _compute_cache_key("b", slices, None)
    cache_path = tmp_path / "combined_executive_ai_brief.json"
    cache_path.write_text(json.dumps({
        "__cache_key": key, "__model": "cached",
        "__generated_utc": "2026-01-01T00:00:00+00:00",
        "brief": _full_brief(),
    }))
    result = synthesize_combined_executive_ai(
        bundle_name="b", slices=slices, combined_dir=tmp_path,
        regenerate=True,
    )
    assert result is None  # defer path returns None
    # The cache file is still there; defer wrote a fresh request
    # alongside it because we asked for regeneration.
    assert (tmp_path / _REQUEST_FILENAME).exists()


# ---------------------------------------------------------------------------
# build_context — packs cross-host signals into the prompt payload
# ---------------------------------------------------------------------------

def test_build_context_includes_per_host_summaries():
    slices = [_StubSlice("dc", leading_hyp="H_X", leading_score=10),
              _StubSlice("ws", leading_hyp="H_Y", leading_score=5)]
    ctx = build_context("bundle", slices)
    assert ctx["bundle_name"] == "bundle"
    assert ctx["host_count"] == 2
    assert {h["case_id"] for h in ctx["hosts"]} == {"dc", "ws"}


def test_build_context_carries_joint_ach_top5():
    slices = [_StubSlice("dc")]
    joint = [{"hyp_id": f"H_{i}", "score": 30 - i} for i in range(10)]
    ctx = build_context("b", slices, joint_ach=joint)
    assert len(ctx["joint_ach_top5"]) == 5
    assert ctx["joint_ach_top5"][0]["hyp_id"] == "H_0"


def test_build_context_carries_clock_baselines():
    """The clock-baselines block is forensically load-bearing for
    the AI brief's confidence_and_gaps section."""
    slices = [_StubSlice("dc")]
    clocks = {
        "rows": [{"host_label": "dc", "tz_display": "UTC"}],
        "alerts": [{"level": "warn", "text": "TZ split"}],
    }
    ctx = build_context("b", slices, clock_baselines=clocks)
    assert ctx["clock_baselines"]["alerts"][0]["level"] == "warn"


def test_build_context_carries_shared_iocs():
    slices = [_StubSlice("dc")]
    shared = {"96.255.98.154": ["dc", "nfury"],
              "evil.com": ["dc", "nromanoff", "nfury"]}
    ctx = build_context("b", slices, shared_iocs=shared)
    assert ctx["shared_iocs"]["96.255.98.154"] == ["dc", "nfury"]


def test_build_context_degrades_to_empty_collections_when_none():
    """All cross-host signals are optional — None should produce
    empty containers, not crash."""
    slices = [_StubSlice("dc")]
    ctx = build_context("b", slices)
    assert ctx["joint_ach_top5"] == []
    assert ctx["clock_baselines"] == {"rows": [], "alerts": []}
    assert ctx["shared_iocs"] == {}
    assert ctx["attack_technique_union_size"] == 0


def test_build_context_attack_technique_top_sorted_by_findings():
    slices = [_StubSlice("dc")]
    techs = {"T1": {"findings": 10}, "T2": {"findings": 50},
             "T3": {"findings": 30}}
    ctx = build_context("b", slices, technique_union=techs)
    # Highest-findings technique first
    assert ctx["attack_technique_top"][0][0] == "T2"
    assert ctx["attack_technique_union_size"] == 3
