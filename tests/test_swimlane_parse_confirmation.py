"""Tests for narrative.is_parse_confirmation + html.py swimlane filter.

Pins the rule that windows_artifact "parsed successfully" findings
are dropped from the kill-chain swimlane because they're metadata
about the parse, not discrete events. A registry hive's parse can
legitimately span the OS install (1999) → last-write (2008) range,
and plotting a single dot on the swimlane for that range either
stretches the axis across decades or misleads about a specific
attack event.

The per-key / per-record findings emitted alongside the parse
confirmation still land on the swimlane — they carry the real
forensic events.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from el.reporting.narrative import (
    is_parse_confirmation,
    is_swimlane_metadata,
)
from el.schemas.finding import EvidenceItem, Finding


def _mkf(*, agent: str, claim: str, conf: str = "high",
         hypotheses: list[str] | None = None,
         facts: dict | None = None) -> Finding:
    """Build a Finding that passes Pydantic validation."""
    ev = [EvidenceItem(
        tool="t", version="v1", command="t --x",
        output_sha256="0" * 64, output_path="/tmp/x",
        extracted_facts=facts or {"rc": 0},
    )] if conf != "insufficient" else []
    return Finding(
        case_id="t-case", agent=agent, claim=claim, confidence=conf,
        evidence=ev, hypotheses_supported=hypotheses or [],
    )


# ---------------------------------------------------------------------------
# is_parse_confirmation — predicate truth table
# ---------------------------------------------------------------------------

def test_recmd_parsed_successfully_is_parse_confirmation():
    f = _mkf(agent="windows_artifact",
             claim="RECmd batch (registry): parsed successfully",
             hypotheses=["H_DISK_ARTIFACTS"])
    assert is_parse_confirmation(f)


def test_evtxecmd_parsed_successfully_is_parse_confirmation():
    f = _mkf(agent="windows_artifact",
             claim="EvtxECmd (winevt): parsed successfully",
             hypotheses=["H_DISK_ARTIFACTS"])
    assert is_parse_confirmation(f)


def test_pecmd_appcompat_jlecmd_lecmd_rbcmd_all_match():
    """All EZT _try() wrappers share the same claim suffix — they
    must all be classified as parse confirmations."""
    for label in ("MFTECmd $MFT", "AmcacheParser (Amcache.hve)",
                  "PECmd Prefetch (Prefetch)",
                  "AppCompatCacheParser shimcache (SYSTEM)",
                  "SBECmd shellbags (registry)",
                  "JLECmd (jumplists)", "LECmd (lnk)",
                  "RBCmd (recyclebin)", "SrumECmd (SRUDB.dat)"):
        f = _mkf(agent="windows_artifact",
                 claim=f"{label}: parsed successfully",
                 hypotheses=["H_DISK_ARTIFACTS"])
        assert is_parse_confirmation(f), \
            f"expected parse-confirmation for {label}"


def test_insufficient_rc_failure_is_NOT_parse_confirmation():
    """When the parser fails (rc != 0 / EztError), the _try wrapper
    emits a different claim shape — `<label>: rc=…` or `<label>: <err>`.
    Those are diagnostic findings, not parse confirmations, but they
    don't land on the swimlane either (confidence='insufficient' has
    no evidence_time anyway). Pin the negative case so a future claim
    rephrase doesn't silently flip these into parse-confirmation."""
    f = _mkf(agent="windows_artifact",
             claim="RECmd batch (registry): rc=2 (see RECmd.stderr)",
             conf="insufficient")
    assert not is_parse_confirmation(f)


def test_other_windows_artifact_findings_are_NOT_parse_confirmation():
    """Per-record findings emitted alongside the parse confirmation
    (RecentDocs counts, IE5 cache suspicious URLs, BAM/DAM execution
    records, Windows Timeline suspicious-path entries) must stay on
    the swimlane — they're real events."""
    for claim in (
        "RecentDocs/OpenSave-MRU: 5 file-touch record(s) recovered",
        "IE5 cache suspicious URLs: 116 row(s) flagged",
        "BAM/DAM execution: 12 process(es)",
        "Windows Timeline suspicious-path: powershell from Temp",
    ):
        f = _mkf(agent="windows_artifact", claim=claim,
                 hypotheses=["H_APT_ESPIONAGE"])
        assert not is_parse_confirmation(f), \
            f"unexpected parse-confirmation for: {claim}"


def test_other_agents_emitting_parsed_successfully_are_NOT_skipped():
    """The predicate is scoped to windows_artifact. If some future
    agent legitimately emits a "parsed successfully" event-style
    finding (e.g. a custom EVTX parser), it should still land on
    the swimlane — scope creep should be a deliberate code change,
    not a silent string match."""
    f = _mkf(agent="memory_forensicator",
             claim="vol3.windows.malfind: parsed successfully",
             hypotheses=["H_APT_ESPIONAGE"])
    assert not is_parse_confirmation(f)


def test_predicate_handles_empty_or_partial_fields():
    """Defensive: even if a Finding somehow has an empty agent or
    claim (Pydantic validates non-empty, but evidence_time and other
    helpers handle truncated state gracefully — match that bar)."""
    # Constructing via Finding() requires non-empty agent + claim,
    # but the predicate must still return False for hostile inputs
    # if they're ever passed a dict-like with missing fields.
    class _Stub:
        agent = ""
        claim = ""
    assert not is_parse_confirmation(_Stub())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# html.py wiring — _finding_to_dict sets swimlane_eligible correctly
# ---------------------------------------------------------------------------

def test_finding_to_dict_marks_parse_confirmation_ineligible():
    from el.reporting.html import _finding_to_dict
    f = _mkf(agent="windows_artifact",
             claim="RECmd batch (registry): parsed successfully",
             hypotheses=["H_DISK_ARTIFACTS"])
    d = _finding_to_dict(f)
    assert d["swimlane_eligible"] is False


def test_finding_to_dict_marks_event_findings_eligible():
    from el.reporting.html import _finding_to_dict
    f = _mkf(agent="windows_artifact",
             claim="Windows Timeline suspicious-path: evil.exe",
             hypotheses=["H_APT_ESPIONAGE"])
    d = _finding_to_dict(f)
    assert d["swimlane_eligible"] is True


def test_backcompat_alias_still_works():
    """is_parse_confirmation is now an alias for is_swimlane_metadata.
    Pin so a future rename doesn't silently break callers that
    imported the old name."""
    assert is_parse_confirmation is is_swimlane_metadata


# ---------------------------------------------------------------------------
# Calibration baselines (phase=='time_baseline') are also metadata
# ---------------------------------------------------------------------------

def test_ewf_skew_baseline_is_swimlane_metadata():
    """disk_forensicator's EWF acquirer-vs-target clock-skew Finding
    carries `extracted_facts.phase == "time_baseline"` — same
    metadata category as a parse confirmation, must be skipped from
    the swimlane (otherwise a 0-skew finding would land at EL ingest
    time and clutter the strip)."""
    f = _mkf(agent="disk_forensicator",
             claim=("EWF acquirer-vs-target clock skew baseline: "
                    "0s — target's RTC matched the acquirer's reference"),
             facts={"phase": "time_baseline", "skew_seconds": 0})
    assert is_swimlane_metadata(f)


def test_time_baseline_finding_is_swimlane_metadata():
    """windows_artifact's TZ + W32Time baseline — same `phase`
    marker, same skip rule."""
    f = _mkf(agent="windows_artifact",
             claim=("Time-baseline (calibration only — no times "
                    "modified): TZ = GMT Standard Time"),
             facts={"phase": "time_baseline",
                     "tz_standard_name": "GMT Standard Time",
                     "w32time_type": "NTP"})
    assert is_swimlane_metadata(f)


def test_phase_marker_not_set_means_event_eligible():
    """Findings without the `phase` marker stay eligible — the
    `phase=="time_baseline"` opt-out has to be explicit."""
    f = _mkf(agent="disk_forensicator",
             claim="Disk anomaly [SVCHOST_OUTSIDE_SYSTEM32]",
             facts={"pattern_id": "SVCHOST_OUTSIDE_SYSTEM32",
                     "match_count": 1})
    assert not is_swimlane_metadata(f)


def test_other_phase_values_dont_match():
    """Only `phase == "time_baseline"` opts out. Other phase
    values (e.g. `phase == "ewfinfo"` used by an unrelated finding
    family) remain swimlane-eligible."""
    f = _mkf(agent="disk_forensicator",
             claim="EWF metadata captured",
             facts={"phase": "ewfinfo"})
    assert not is_swimlane_metadata(f)


def test_finding_to_dict_other_agents_default_eligible():
    """Non-windows_artifact findings always pass the predicate's
    'agent matches' branch, so they're always eligible regardless
    of claim text. Pin the field so a future predicate rewrite
    can't accidentally drop them."""
    from el.reporting.html import _finding_to_dict
    for agent in ("memory_forensicator", "disk_forensicator",
                   "email_forensicator", "network_analyst",
                   "lateral_movement_analyst"):
        f = _mkf(agent=agent,
                 claim="some event happened at 2008-07-20",
                 hypotheses=["H_APT_ESPIONAGE"])
        d = _finding_to_dict(f)
        assert d["swimlane_eligible"] is True, \
            f"non-windows_artifact agent {agent} should be eligible"
