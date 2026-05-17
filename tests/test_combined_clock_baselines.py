"""Tests for the cross-host clock-baseline aggregator that powers
the `#clocks` section of combined.html.

The aggregator walks each case's findings, extracts the
`phase == "time_baseline"` evidence, returns:
  - one row per case (missing-finding cases get a sentinel entry
    so the analyst sees the gap)
  - cross-host alerts naming the specific failure modes that
    actually matter forensically (TZ split, NoSync orphan, large
    skew, NTP-peer drift, missing baselines)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from el.reporting.combined import CaseSlice
from el.reporting.combined_html import (
    _clock_baselines,
    _clock_baselines_html,
)


def _slice(case_id: str, **baseline) -> CaseSlice:
    """Build a minimal CaseSlice carrying one or two time_baseline
    findings. Pass `tz_display_name`, `w32time_type`, etc. as kwargs
    for the TZ/W32Time baseline; pass `skew_seconds` for the EWF
    skew baseline (both can appear together — the agent emits one
    per source)."""
    findings = []
    tz_keys = {"tz_display_name", "tz_standard_name", "w32time_type",
               "w32time_ntp_server", "tz_active_bias_minutes",
               "w32time_config_last_write_utc"}
    if any(k in baseline for k in tz_keys):
        findings.append({
            "agent": "windows_artifact",
            "claim": "Time-baseline ...",
            "confidence": "high",
            "evidence": [{
                "extracted_facts": {
                    "phase": "time_baseline",
                    **{k: v for k, v in baseline.items() if k in tz_keys},
                },
            }],
        })
    if "skew_seconds" in baseline:
        findings.append({
            "agent": "disk_forensicator",
            "claim": "EWF skew baseline",
            "confidence": "high",
            "evidence": [{
                "extracted_facts": {
                    "phase": "time_baseline",
                    "skew_seconds": baseline["skew_seconds"],
                },
            }],
        })
    return CaseSlice(case_id=case_id, case_dir=Path("/tmp"),
                     findings=findings)


# ---------------------------------------------------------------------------
# Single-case → one row, no alerts (or "consistent" OK alert)
# ---------------------------------------------------------------------------

def test_single_case_consistent_emits_ok_alert():
    """One case, fully synced, zero skew — the aggregator emits a
    single 'consistent' OK alert so the analyst sees explicit
    confirmation rather than a blank panel."""
    c = _slice("srl-foo-host1", tz_display_name="UTC",
               w32time_type="NTP", w32time_ntp_server="time.windows.com",
               tz_active_bias_minutes=0, skew_seconds=0)
    data = _clock_baselines([c])
    assert len(data["rows"]) == 1
    row = data["rows"][0]
    assert row["tz_display"] == "UTC"
    assert row["sync_mode"] == "NTP"
    assert row["skew_seconds"] == 0
    assert data["alerts"][0]["level"] == "ok"


# ---------------------------------------------------------------------------
# Multi-host TZ split detection (the SRL-2015 scenario)
# ---------------------------------------------------------------------------

def test_tz_split_across_enterprise_emits_warn_alert():
    """SRL-2015 shape: DC in UTC, workstations in EST. Cross-host
    TZ disagreement is the most common failure mode for correlator
    work — must surface as a warn-level alert with both TZ names."""
    dc = _slice("srl-2015-dc", tz_display_name="UTC",
                w32time_type="NT5DS", tz_active_bias_minutes=0)
    ws = _slice("srl-2015-ws", tz_display_name="Eastern Standard Time",
                w32time_type="NT5DS", tz_active_bias_minutes=240)
    data = _clock_baselines([dc, ws])
    assert len(data["rows"]) == 2
    levels = [a["level"] for a in data["alerts"]]
    assert "warn" in levels
    tz_alert = next(a for a in data["alerts"] if "TZ split" in a["text"])
    assert "UTC" in tz_alert["text"]
    assert "Eastern Standard Time" in tz_alert["text"]


# ---------------------------------------------------------------------------
# NoSync orphan clock — drift unbounded, must be bad-level alert
# ---------------------------------------------------------------------------

def test_nosync_orphan_emits_bad_alert():
    """NoSync = the host wasn't time-syncing at all; drift
    accumulated. Forensically critical — wall-clock timestamps
    from this host can't be trusted for cross-host correlation."""
    synced = _slice("case-a", tz_display_name="UTC", w32time_type="NTP")
    orphan = _slice("case-b", tz_display_name="UTC",
                    w32time_type="NoSync")
    data = _clock_baselines([synced, orphan])
    bad = [a for a in data["alerts"] if a["level"] == "bad"]
    assert bad, "NoSync host must surface a bad-level alert"
    assert "drift is unbounded" in bad[0]["text"].lower()


def test_nosync_lists_specific_host_labels():
    """Alert text names the offending host so the analyst can find
    it without re-scanning the table."""
    a = _slice("c-syncd", tz_display_name="UTC", w32time_type="NT5DS")
    b = _slice("c-orphan-A", tz_display_name="UTC", w32time_type="NoSync")
    c = _slice("c-orphan-B", tz_display_name="UTC", w32time_type="NoSync")
    data = _clock_baselines([a, b, c])
    bad = next(x for x in data["alerts"] if x["level"] == "bad")
    # CaseSlice.host_label is the public-facing name; verify both
    # orphan hosts show up
    assert "orphan-A" in bad["text"]
    assert "orphan-B" in bad["text"]


# ---------------------------------------------------------------------------
# Large skew — acquirer-vs-target disagreement > 60s flagged bad
# ---------------------------------------------------------------------------

def test_large_skew_flagged_bad():
    """37-minute skew is well past the 60s "noise" threshold —
    must produce a bad alert calling out the magnitude."""
    a = _slice("case-bad-skew",
                tz_display_name="UTC", w32time_type="NTP",
                skew_seconds=37 * 60)
    data = _clock_baselines([a])
    bad = [x for x in data["alerts"] if x["level"] == "bad"]
    assert bad, "37-minute skew must produce a bad alert"
    assert "2220" in bad[0]["text"]


def test_zero_skew_does_not_flag():
    """0s skew is the M57 / SRL-2015 baseline shape — must NOT
    fire the large-skew alert."""
    a = _slice("case-clean", tz_display_name="UTC",
                w32time_type="NTP", skew_seconds=0)
    data = _clock_baselines([a])
    assert not any("skew" in x["text"].lower() and x["level"] == "bad"
                    for x in data["alerts"])


def test_small_skew_under_threshold_does_not_flag():
    """5s skew is within the 60s "noise floor" — no alert."""
    a = _slice("case-tiny", tz_display_name="UTC",
                w32time_type="NTP", skew_seconds=5)
    data = _clock_baselines([a])
    assert not any("skew" in x["text"].lower() and x["level"] == "bad"
                    for x in data["alerts"])


# ---------------------------------------------------------------------------
# Missing baselines — non-Windows / non-EWF hosts
# ---------------------------------------------------------------------------

def test_case_with_no_baseline_finding_appears_as_sentinel_row():
    """When a case has no time_baseline finding (Linux/macOS host
    or memory-only case), the aggregator emits a sentinel row so
    the analyst sees the gap rather than silently dropping that
    case from the matrix."""
    has = _slice("case-windows", tz_display_name="UTC",
                  w32time_type="NTP")
    none = CaseSlice(case_id="case-linux", case_dir=Path("/tmp"),
                     findings=[])
    data = _clock_baselines([has, none])
    assert len(data["rows"]) == 2
    missing_row = next(r for r in data["rows"] if r["missing"])
    assert missing_row["case_id"] == "case-linux"
    # Cross-host alert names the gap explicitly
    warn = [a for a in data["alerts"]
            if "No time-baseline" in a["text"]]
    assert warn
    assert "linux" in warn[0]["text"].lower()


# ---------------------------------------------------------------------------
# UTC-offset reconstruction from ActiveTimeBias
# ---------------------------------------------------------------------------

def test_utc_offset_pst():
    """PST = UTC-08:00. ActiveTimeBias = 480 (Windows convention:
    positive bias means clock is BEHIND UTC)."""
    c = _slice("ws", tz_display_name="Pacific Standard Time",
                w32time_type="NTP", tz_active_bias_minutes=480)
    data = _clock_baselines([c])
    assert data["rows"][0]["utc_offset"] == "UTC-08:00"


def test_utc_offset_bst_dst_active():
    """M57 winter would be UTC+00:00; during BST (DST active) the
    ActiveTimeBias = -60 → UTC+01:00."""
    c = _slice("uk-host", tz_display_name="GMT Standard Time",
                w32time_type="NTP", tz_active_bias_minutes=-60)
    data = _clock_baselines([c])
    assert data["rows"][0]["utc_offset"] == "UTC+01:00"


def test_utc_offset_utc_zero():
    c = _slice("dc", tz_display_name="UTC", w32time_type="NT5DS",
                tz_active_bias_minutes=0)
    data = _clock_baselines([c])
    assert data["rows"][0]["utc_offset"] == "UTC+00:00"


def test_utc_offset_jst():
    """JST = UTC+09:00, ActiveTimeBias = -540."""
    c = _slice("tokyo", tz_display_name="Tokyo Standard Time",
                w32time_type="NTP", tz_active_bias_minutes=-540)
    data = _clock_baselines([c])
    assert data["rows"][0]["utc_offset"] == "UTC+09:00"


# ---------------------------------------------------------------------------
# HTML renderer smoke
# ---------------------------------------------------------------------------

def test_html_renderer_contains_table_and_alerts():
    """End-to-end: aggregator output flows into the table + alert
    chip HTML. Pin a few must-have substrings so a refactor that
    drops them gets caught immediately."""
    dc = _slice("srl-dc", tz_display_name="UTC", w32time_type="NT5DS",
                tz_active_bias_minutes=0, skew_seconds=0)
    ws = _slice("srl-ws", tz_display_name="Eastern Standard Time",
                w32time_type="NT5DS", tz_active_bias_minutes=240,
                skew_seconds=0)
    html = _clock_baselines_html([dc, ws])
    # Table headers present
    assert "Host" in html and "TZ (display)" in html
    assert "UTC offset" in html and "Sync mode" in html
    # Per-host data
    assert "Eastern Standard Time" in html
    assert "UTC-04:00" in html
    # Alert pill for TZ split
    assert "clock-alert" in html
    assert "TZ split" in html


def test_html_empty_when_no_cases():
    html = _clock_baselines_html([])
    assert "No per-case time baselines" in html


def test_html_marks_nosync_with_warn_class():
    orphan = _slice("orphan", tz_display_name="UTC",
                    w32time_type="NoSync")
    html = _clock_baselines_html([orphan])
    assert "sync-warn" in html


def test_html_marks_ntp_synced_with_trust_class():
    synced = _slice("synced", tz_display_name="UTC", w32time_type="NTP")
    html = _clock_baselines_html([synced])
    assert "sync-trust" in html


def test_html_zero_skew_uses_green_class():
    """Sanity-check styling: 0s skew shows in the trusted-green
    class so the visual signal matches the textual content."""
    clean = _slice("clean", tz_display_name="UTC", w32time_type="NTP",
                   skew_seconds=0)
    html = _clock_baselines_html([clean])
    assert "skew-zero" in html
