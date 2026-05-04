"""Hindsight skill — unit tests.

Tests parsing, profile detection, and dataclass behaviour against synthetic
profile dirs. The actual Hindsight run is gated behind a module-import smoke
test (hindsight requires Chromium profile data; we don't synthesise that).
"""
import json
from pathlib import Path

import pytest

from el.skills import hindsight as hs


# --- _which discovery ---------------------------------------------------

def test_which_finds_venv_script():
    """hindsight.py should be discovered in the venv bin/ during normal runs."""
    try:
        py, leading = hs._which()
    except hs.HindsightError:
        pytest.skip("Hindsight not installed in this venv")
    assert py.name in ("python", "python3", "python3.12")
    if leading:
        assert leading[0].endswith("hindsight.py")


def test_which_raises_when_missing(monkeypatch):
    """When the script is absent, _which raises HindsightError."""
    import sys
    fake_bin = Path("/nonexistent-venv/bin/python")
    monkeypatch.setattr(sys, "executable", str(fake_bin))
    monkeypatch.setattr(hs.shutil, "which", lambda _: None)
    with pytest.raises(hs.HindsightError):
        hs._which()


# --- Profile detection -------------------------------------------------

def test_looks_like_chromium_profile_true(tmp_path):
    (tmp_path / "History").write_bytes(b"\x00" * 16)
    (tmp_path / "Cookies").write_bytes(b"\x00" * 16)
    assert hs.looks_like_chromium_profile(tmp_path)


def test_looks_like_chromium_profile_false_no_cookies(tmp_path):
    (tmp_path / "History").write_bytes(b"\x00" * 16)
    assert not hs.looks_like_chromium_profile(tmp_path)


def test_looks_like_chromium_profile_with_default_subdir(tmp_path):
    default_dir = tmp_path / "Default"
    default_dir.mkdir()
    (default_dir / "History").write_bytes(b"\x00" * 16)
    (default_dir / "Cookies").write_bytes(b"\x00" * 16)
    assert hs.looks_like_chromium_profile(tmp_path)


def test_find_profiles_walks_tree(tmp_path):
    p1 = tmp_path / "Chrome" / "User Data" / "Default"
    p1.mkdir(parents=True)
    (p1 / "History").write_bytes(b"\x00" * 16)
    (p1 / "Cookies").write_bytes(b"\x00" * 16)
    p2 = tmp_path / "Edge" / "User Data" / "Profile 1"
    p2.mkdir(parents=True)
    (p2 / "History").write_bytes(b"\x00" * 16)
    (p2 / "Cookies").write_bytes(b"\x00" * 16)
    profiles = hs.find_profiles(tmp_path)
    paths = sorted(str(p) for p in profiles)
    assert any("Default" in s for s in paths)
    assert any("Profile 1" in s for s in paths)


def test_find_profiles_respects_max_depth(tmp_path):
    deep = tmp_path
    for i in range(8):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / "History").write_bytes(b"\x00" * 16)
    (deep / "Cookies").write_bytes(b"\x00" * 16)
    profiles = hs.find_profiles(tmp_path, max_depth=3)
    assert profiles == []


def test_find_profiles_handles_missing_root(tmp_path):
    assert hs.find_profiles(tmp_path / "does-not-exist") == []


# --- Run dataclass + as_evidence ---------------------------------------

def test_hindsight_run_as_evidence(tmp_path):
    out_jsonl = tmp_path / "out.jsonl"
    out_jsonl.write_text('{"type":"history","url":"https://example.com/"}\n')
    run = hs.HindsightRun(
        profile_dir=tmp_path,
        output_jsonl=out_jsonl,
        log_path=tmp_path / "h.log",
        rc=0,
        record_count=1,
        distinct_event_types=["history"],
        output_sha256="b" * 64,
        command=["python", "hindsight.py", "-i", str(tmp_path)],
    )
    ev = run.as_evidence()
    assert ev.tool == "hindsight"
    assert ev.output_sha256 == "b" * 64
    assert ev.extracted_facts["record_count"] == 1
    assert ev.extracted_facts["event_types"] == ["history"]


def test_hindsight_run_evidence_zero_pads_when_no_output():
    run = hs.HindsightRun(
        profile_dir=Path("/tmp/p"), output_jsonl=None, log_path=None, rc=2,
    )
    ev = run.as_evidence()
    assert ev.output_sha256 == "0" * 64


# --- iter_records JSONL parsing ----------------------------------------

def test_iter_records_yields_each_line(tmp_path):
    p = tmp_path / "out.jsonl"
    p.write_text(
        '{"type":"history","url":"https://a.com/"}\n'
        '{"type":"download","url":"https://b.com/x.zip"}\n'
        "\n"  # blank line — tolerated
        '{"type":"cookie","host":"c.com"}\n'
    )
    run = hs.HindsightRun(
        profile_dir=tmp_path, output_jsonl=p, log_path=None, rc=0,
    )
    records = list(run.iter_records())
    assert len(records) == 3
    assert records[0]["url"] == "https://a.com/"
    assert records[2]["host"] == "c.com"


def test_iter_records_skips_invalid_json(tmp_path):
    p = tmp_path / "out.jsonl"
    p.write_text(
        '{"good":1}\n'
        "not-json\n"
        '{"good":2}\n'
    )
    run = hs.HindsightRun(
        profile_dir=tmp_path, output_jsonl=p, log_path=None, rc=0,
    )
    records = list(run.iter_records())
    assert len(records) == 2
    assert records[0]["good"] == 1
    assert records[1]["good"] == 2


def test_iter_records_max_rows_cap(tmp_path):
    p = tmp_path / "out.jsonl"
    p.write_text("\n".join(json.dumps({"i": i}) for i in range(20)) + "\n")
    run = hs.HindsightRun(
        profile_dir=tmp_path, output_jsonl=p, log_path=None, rc=0,
    )
    records = list(run.iter_records(max_rows=5))
    assert len(records) == 5


# --- Module import smoke (real install only) ---------------------------

@pytest.mark.skipif(
    pytest.importorskip("pyhindsight", reason="pyhindsight not installed") is None,
    reason="pyhindsight not installed",
)
def test_pyhindsight_importable():
    import pyhindsight
    assert pyhindsight.__version__
