"""MVT skill — unit tests.

Tests parsing, dataclass behaviour, and detection harvesting against
synthetic MVT output dirs. Real-binary runs are gated behind a smoke test
because MVT against an actual iOS/Android dump is a multi-minute operation.
"""
import json
from pathlib import Path

import pytest

from el.skills import mvt as mvt_skill


# --- _which discovery ---------------------------------------------------

def test_which_finds_venv_binary():
    """mvt-ios / mvt-android should be discovered in the venv during normal runs."""
    try:
        p = mvt_skill._which("mvt-ios")
    except mvt_skill.MVTError:
        pytest.skip("MVT not installed in this venv")
    assert p.is_file()


def test_which_raises_when_missing(monkeypatch):
    import sys
    monkeypatch.setattr(sys, "executable", "/nonexistent-venv/bin/python")
    monkeypatch.setattr(mvt_skill.shutil, "which", lambda _: None)
    with pytest.raises(mvt_skill.MVTError):
        mvt_skill._which("mvt-ios")


# --- MVTDetection parsing -----------------------------------------------

def test_detection_from_full_json_obj():
    obj = {
        "matched_indicator": {"name": "pegasus_domain_xyz", "type": "domain"},
        "matched_value": "evil.example.com",
        "timestamp": "2024-01-01T12:34:56Z",
    }
    d = mvt_skill.MVTDetection.from_json_obj("safari_history", obj)
    assert d.module == "safari_history"
    assert d.indicator_name == "pegasus_domain_xyz"
    assert d.indicator_type == "domain"
    assert d.matched_value == "evil.example.com"
    assert "2024-01-01" in d.timestamp


def test_detection_handles_missing_matched_indicator():
    obj = {"value": "fallback.example.com"}
    d = mvt_skill.MVTDetection.from_json_obj("idb", obj)
    assert d.matched_value == "fallback.example.com"
    assert d.indicator_name == ""


def test_detection_truncates_long_matched_value():
    obj = {"matched_value": "x" * 1000}
    d = mvt_skill.MVTDetection.from_json_obj("m", obj)
    assert len(d.matched_value) <= 300


# --- _harvest_detections ------------------------------------------------

def test_harvest_detections_finds_detected_files(tmp_path):
    # MVT writes <module>_detected.json on hits.
    (tmp_path / "safari_history_detected.json").write_text(json.dumps([
        {"matched_indicator": {"name": "p_domain", "type": "domain"},
         "matched_value": "evil.example.com"},
        {"matched_indicator": {"name": "p_domain2", "type": "domain"},
         "matched_value": "bad.example.com"},
    ]))
    (tmp_path / "calls_detected.json").write_text(json.dumps(
        {"matched_indicator": {"name": "p_phone", "type": "phone"},
         "matched_value": "+15555550100"}
    ))
    # A non-detected file should be ignored.
    (tmp_path / "safari_history.json").write_text("[]")

    detections, files = mvt_skill._harvest_detections(tmp_path)
    assert len(detections) == 3
    modules = {d.module for d in detections}
    assert modules == {"safari_history", "calls"}
    assert len(files) == 2


def test_harvest_detections_handles_invalid_json(tmp_path):
    (tmp_path / "bad_detected.json").write_text("not-valid-json")
    (tmp_path / "good_detected.json").write_text(
        json.dumps({"matched_indicator": {"name": "x", "type": "y"},
                    "matched_value": "z"})
    )
    detections, _ = mvt_skill._harvest_detections(tmp_path)
    # bad file is skipped; good one parsed.
    assert len(detections) == 1
    assert detections[0].module == "good"


def test_harvest_detections_returns_empty_for_missing_dir(tmp_path):
    detections, files = mvt_skill._harvest_detections(tmp_path / "no-such-dir")
    assert detections == []
    assert files == []


# --- _harvest_modules_run ----------------------------------------------

def test_harvest_modules_run_lists_distinct(tmp_path):
    (tmp_path / "safari_history.json").write_text("[]")
    (tmp_path / "safari_history_detected.json").write_text("[]")
    (tmp_path / "calls.json").write_text("[]")
    modules = mvt_skill._harvest_modules_run(tmp_path)
    # Both safari_history and safari_history_detected map to "safari_history"
    assert set(modules) == {"safari_history", "calls"}


# --- _resolve_iocs_arg --------------------------------------------------

def test_resolve_iocs_arg_returns_empty_when_none():
    assert mvt_skill._resolve_iocs_arg(None) == []


def test_resolve_iocs_arg_handles_single_file(tmp_path):
    f = tmp_path / "pegasus.stix2"
    f.write_text("{}")
    args = mvt_skill._resolve_iocs_arg(f)
    assert args == ["-i", str(f)]


def test_resolve_iocs_arg_expands_directory(tmp_path):
    (tmp_path / "p.stix2").write_text("{}")
    (tmp_path / "q.stix2").write_text("{}")
    (tmp_path / "ignored.txt").write_text("not-an-ioc")
    args = mvt_skill._resolve_iocs_arg(tmp_path)
    # Two -i flags, alphabetically ordered.
    assert args.count("-i") == 2
    assert any("p.stix2" in a for a in args)
    assert any("q.stix2" in a for a in args)


# --- MVTRun dataclass + as_evidence ------------------------------------

def test_mvt_run_as_evidence_with_hits(tmp_path):
    detections = [
        mvt_skill.MVTDetection(module="safari_history",
                                 indicator_name="x", indicator_type="domain",
                                 matched_value="evil.example.com"),
        mvt_skill.MVTDetection(module="safari_history",
                                 indicator_name="y", indicator_type="domain",
                                 matched_value="bad.example.com"),
        mvt_skill.MVTDetection(module="calls",
                                 indicator_name="z", indicator_type="phone",
                                 matched_value="+1234567890"),
    ]
    run = mvt_skill.MVTRun(
        target_path=tmp_path / "ios.dump",
        output_dir=tmp_path,
        platform="ios", subcommand="check-fs",
        rc=0, modules_run=["safari_history", "calls"],
        detections=detections,
        output_sha256="c" * 64,
        command=["mvt-ios", "check-fs"],
    )
    ev = run.as_evidence()
    assert ev.tool == "mvt"
    assert ev.output_sha256 == "c" * 64
    assert ev.extracted_facts["detection_count"] == 3
    assert ev.extracted_facts["detection_modules"]["safari_history"] == 2
    assert ev.extracted_facts["platform"] == "ios"


def test_mvt_run_has_hits_and_summary():
    run_no_hits = mvt_skill.MVTRun(
        target_path=Path("/x"), output_dir=Path("/y"),
        platform="ios", subcommand="check-fs", rc=0,
    )
    assert not run_no_hits.has_hits()
    assert run_no_hits.detection_summary() == "no IOC matches"

    run_hits = mvt_skill.MVTRun(
        target_path=Path("/x"), output_dir=Path("/y"),
        platform="ios", subcommand="check-fs", rc=0,
        detections=[
            mvt_skill.MVTDetection("safari_history", "n", "t", "v"),
            mvt_skill.MVTDetection("safari_history", "n", "t", "v"),
            mvt_skill.MVTDetection("calls", "n", "t", "v"),
        ],
    )
    assert run_hits.has_hits()
    assert "safari_history" in run_hits.detection_summary()


# --- Smoke test: real binary --------------------------------------------

@pytest.mark.skipif(
    not Path("/opt/EL/.venv/bin/mvt-ios").is_file(),
    reason="mvt-ios not installed in venv",
)
def test_real_mvt_ios_version_smoke():
    import subprocess
    p = subprocess.run(
        ["/opt/EL/.venv/bin/mvt-ios",
         "--disable-update-check", "--disable-indicator-update-check",
         "version"],
        capture_output=True, text=True, timeout=10,
    )
    assert p.returncode == 0 or "version" in (p.stdout + p.stderr).lower()
