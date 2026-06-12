"""Contract tests for the self-correction recorder.

EL self-corrects at runtime (a first interpretation/route is emitted, EL
detects it is wrong/unreachable, corrects, and continues). This module turns
those corrections into a first-class, auditable artifact. The tests lock in:

  * record_self_correction writes a structured JSONL row AND a compact
    `event=self_correction` audit line (which the execution-log builder lifts
    into reports/execution_log.jsonl);
  * load_self_corrections round-trips and aggregates bundle device sub-cases;
  * the recorder is best-effort — a write failure returns None, never raises;
  * the real triage banner-fallback path (vol3 no kernel → carve) emits a
    genuine self-correction end-to-end.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from el.self_correction import (
    MECHANISMS,
    SelfCorrection,
    load_self_corrections,
    record_self_correction,
)


def _ctx(case_dir: Path, case_id: str = "c"):
    return SimpleNamespace(case_id=case_id, case_dir=case_dir)


def _record(ctx, **over):
    base = dict(
        mechanism="memory_truncated_acquisition_fallback",
        trigger="vol3 built no kernel layer",
        initial="route to structured memory pipeline",
        detection="banner scan found Windows mem, no usable DTB",
        correction="reclassify as carve-only and route to carve",
        outcome="bulk_extractor recovers strings/credentials",
    )
    base.update(over)
    return record_self_correction(ctx, "triage", **base)


# ---------------------------------------------------------------------------
# record + load
# ---------------------------------------------------------------------------

def test_record_writes_jsonl_and_audit(tmp_path):
    sc = _record(_ctx(tmp_path), evidence_sha256="ab" * 32, refs=["F1"])
    assert sc is not None and sc.mechanism in MECHANISMS

    jl = tmp_path / "analysis" / "self_corrections.jsonl"
    assert jl.is_file()
    rec = json.loads(jl.read_text().splitlines()[0])
    assert rec["mechanism"] == "memory_truncated_acquisition_fallback"
    assert rec["agent"] == "triage"
    assert rec["evidence_sha256"] == "ab" * 32
    assert rec["refs"] == ["F1"]
    assert rec["utc"].endswith("+00:00") or rec["utc"].endswith("Z")

    # Compact audit event flows to the forensic audit log (→ execution_log.jsonl)
    audit = (tmp_path / "analysis" / "forensic_audit.log").read_text()
    assert "event=self_correction" in audit
    assert "mechanism=memory_truncated_acquisition_fallback" in audit


def test_load_round_trips_and_sorts(tmp_path):
    ctx = _ctx(tmp_path)
    _record(ctx, mechanism="memory_symbol_healing")
    _record(ctx, mechanism="paired_baseline_rescore")
    loaded = load_self_corrections(tmp_path)
    assert len(loaded) == 2
    assert all(isinstance(s, SelfCorrection) for s in loaded)
    # sorted ascending by utc (stable for same-second writes)
    assert loaded == sorted(loaded, key=lambda s: s.utc)
    assert {s.mechanism for s in loaded} == {
        "memory_symbol_healing", "paired_baseline_rescore"}


def test_load_aggregates_bundle_devices(tmp_path):
    # Each device of an investigate-bundle writes its own jsonl.
    for dev in ("steve-mem", "john-mem"):
        d = tmp_path / "devices" / dev
        _record(_ctx(d, f"narcos:{dev}"))
    # plus a top-level one
    _record(_ctx(tmp_path, "narcos"))
    loaded = load_self_corrections(tmp_path)
    assert len(loaded) == 3
    assert {s.case_id for s in loaded} == {
        "narcos", "narcos:steve-mem", "narcos:john-mem"}


def test_record_is_best_effort_on_bad_path(tmp_path):
    # case_dir is a *file*, so mkdir under analysis/ fails — recorder must
    # swallow it and return None rather than aborting the investigation.
    bad = tmp_path / "afile"
    bad.write_text("x")
    assert _record(_ctx(bad)) is None


def test_load_missing_returns_empty(tmp_path):
    assert load_self_corrections(tmp_path / "nope") == []


def test_mechanism_label_falls_back(tmp_path):
    sc = _record(_ctx(tmp_path))
    assert sc.mechanism_label() == MECHANISMS[sc.mechanism]
    unknown = SelfCorrection(
        utc="t", case_id="c", agent="a", mechanism="zzz", trigger="",
        initial_interpretation="", detection="", correction="", outcome="")
    assert unknown.mechanism_label() == "zzz"


# ---------------------------------------------------------------------------
# End-to-end: the real triage banner-fallback path records a correction
# ---------------------------------------------------------------------------

def test_triage_banner_fallback_records_self_correction(tmp_path, monkeypatch):
    """When vol3 automagic raises but the raw banner scan confirms Windows
    memory, triage re-routes to carve AND records a genuine self-correction
    (mechanism=memory_truncated_acquisition_fallback) linked to the emitted
    finding. Mirrors test_vol3_failure_with_banner_routes_to_carve."""
    from el.agents.base import AgentContext
    from el.agents.triage import TriageAgent
    from el.skills import vol3 as vol3_mod

    img = tmp_path / "john-mem.raw"
    img.write_bytes(b"\x00" * (4 * 1024 * 1024))
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "triage").mkdir(parents=True, exist_ok=True)
    ctx = AgentContext(
        case_id="narcos-full:john-mem", case_dir=case_dir, input_path=img,
        manifest={"input_path": str(img)},
    )

    def fake_detect_os(image, out_dir):
        raise vol3_mod.Vol3Error("no banner plugin produced usable output")

    def fake_banner(image, **kw):
        return vol3_mod.TruncatedMemoryProbe(
            is_windows_memory=True, build="10.0.17763", banner_offset=123,
            reason="Windows kernel banner found ... truncated acquisition.")

    monkeypatch.setattr(vol3_mod, "detect_os", fake_detect_os)
    monkeypatch.setattr(vol3_mod, "scan_windows_banner", fake_banner)

    out = TriageAgent()._maybe_run_vol3(ctx, case_dir / "analysis" / "triage")

    assert ctx.shared.get("evidence_kind") == "unallocated (carve-only)"
    corrections = load_self_corrections(case_dir)
    assert len(corrections) == 1
    c = corrections[0]
    assert c.mechanism == "memory_truncated_acquisition_fallback"
    assert c.agent == "triage"
    assert "10.0.17763" in c.detection
    # the correction links back to the insufficient finding triage emitted
    assert c.refs and any(f.finding_id == c.refs[0] for f in out)
