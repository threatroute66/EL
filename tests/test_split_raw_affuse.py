"""Split-raw (.001/.002/…) handling: TSK spans segments natively, but the
NTFS mount + bulk_extractor only see the first segment, so disk_forensicator
bridges the segments into one contiguous stream via affuse first.

Regression for the 2019 Narcos bundle: 30 GB disks split into 1.5 GB FTK
Imager segments mounted from `.001` failed ("NTFS signature missing"), so
the entire windows_artifact chain (and graph population) was skipped.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from el.skills import sleuthkit as sk


# --- is_split_raw detection ------------------------------------------------

def test_is_split_raw_true_for_first_segment(tmp_path):
    (tmp_path / "img.001").write_bytes(b"\x00")
    (tmp_path / "img.002").write_bytes(b"\x00")
    assert sk.is_split_raw(tmp_path / "img.001") is True


def test_is_split_raw_false_for_last_segment(tmp_path):
    (tmp_path / "img.001").write_bytes(b"\x00")
    (tmp_path / "img.002").write_bytes(b"\x00")
    # .002 has no .003 sibling → not a "first segment with a next"
    assert sk.is_split_raw(tmp_path / "img.002") is False


def test_is_split_raw_false_for_lone_segment(tmp_path):
    (tmp_path / "img.001").write_bytes(b"\x00")   # no .002
    assert sk.is_split_raw(tmp_path / "img.001") is False


def test_is_split_raw_handles_zero_based_segments(tmp_path):
    (tmp_path / "d.000").write_bytes(b"\x00")
    (tmp_path / "d.001").write_bytes(b"\x00")
    assert sk.is_split_raw(tmp_path / "d.000") is True


def test_is_split_raw_false_for_non_numeric_ext(tmp_path):
    (tmp_path / "disk.E01").write_bytes(b"\x00")
    (tmp_path / "disk.raw").write_bytes(b"\x00")
    assert sk.is_split_raw(tmp_path / "disk.E01") is False
    assert sk.is_split_raw(tmp_path / "disk.raw") is False


# --- affuse_mount subprocess wrapper ---------------------------------------

def test_affuse_mount_returns_unified_raw(tmp_path, monkeypatch):
    img = tmp_path / "img.001"
    img.write_bytes(b"\x00")
    mp = tmp_path / "mp"

    def _fake_run(cmd, **kw):
        # affuse exposes <firstsegment>.raw inside the mount point
        Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
        (Path(cmd[-1]) / "img.001.raw").write_bytes(b"\x00")
        class _P: returncode = 0; stdout = ""; stderr = ""
        return _P()

    monkeypatch.setattr(sk.subprocess, "run", _fake_run)
    raw = sk.affuse_mount(img, mp)
    assert raw.name == "img.001.raw"
    assert raw.exists()


def test_affuse_mount_raises_when_binary_missing(tmp_path, monkeypatch):
    img = tmp_path / "img.001"; img.write_bytes(b"\x00")
    def _missing(cmd, **kw):
        raise FileNotFoundError("affuse")
    monkeypatch.setattr(sk.subprocess, "run", _missing)
    with pytest.raises(sk.SleuthkitError, match="affuse not installed"):
        sk.affuse_mount(img, tmp_path / "mp")


def test_affuse_mount_raises_on_nonzero_rc(tmp_path, monkeypatch):
    img = tmp_path / "img.001"; img.write_bytes(b"\x00")
    def _fail(cmd, **kw):
        class _P: returncode = 1; stdout = ""; stderr = "boom"
        return _P()
    monkeypatch.setattr(sk.subprocess, "run", _fail)
    with pytest.raises(sk.SleuthkitError, match="affuse failed"):
        sk.affuse_mount(img, tmp_path / "mp")


def test_affuse_umount_calls_fusermount(tmp_path, monkeypatch):
    calls = []
    def _rec(cmd, **kw):
        calls.append(cmd)
        class _P: returncode = 0; stdout = ""; stderr = ""
        return _P()
    monkeypatch.setattr(sk.subprocess, "run", _rec)
    sk.affuse_umount(tmp_path / "mp")
    assert calls and calls[0][:2] == ["fusermount", "-u"]


# --- disk_forensicator bridges split-raw before walking --------------------

def test_disk_forensicator_bridges_split_raw(tmp_path, monkeypatch):
    """run() on a split-raw input affuse-bridges it and walks the UNIFIED
    stream, not the first segment — then unmounts affuse afterward."""
    from el.agents.disk_forensicator import DiskForensicatorAgent
    from el.agents.base import AgentContext

    img = tmp_path / "Narcos-1.001"
    img.write_bytes(b"\x00")
    case_dir = tmp_path / "case"
    (case_dir / "analysis").mkdir(parents=True)

    bridged = tmp_path / "case" / "raw" / "affuse" / "Narcos-1.001.raw"
    walked_with = {}
    umounted = {"n": 0}

    monkeypatch.setattr(sk, "is_split_raw", lambda p: True)
    monkeypatch.setattr(sk, "affuse_mount", lambda i, mp: bridged)
    monkeypatch.setattr(sk, "affuse_umount",
                        lambda mp: umounted.__setitem__("n", umounted["n"] + 1))

    agent = DiskForensicatorAgent()
    monkeypatch.setattr(
        agent, "_raw_disk_walk",
        lambda ctx, analysis, raw_image: walked_with.__setitem__("raw", raw_image) or [])

    ctx = AgentContext(case_id="t", case_dir=case_dir, input_path=img,
                       manifest={}, shared={"evidence_kind": "raw-disk (GPT)"})
    out = agent.run(ctx)

    # Walked the unified affuse stream, NOT the .001 first segment
    assert walked_with["raw"] == bridged
    # affuse was unmounted in the finally block
    assert umounted["n"] == 1
    # a high-confidence "bridged" finding was emitted
    assert any("bridged" in f.claim.lower() for f in out)


def test_disk_forensicator_falls_back_when_affuse_unavailable(tmp_path, monkeypatch):
    """If affuse isn't installed, run() falls back to the first segment and
    emits an honest 'insufficient' note rather than crashing."""
    from el.agents.disk_forensicator import DiskForensicatorAgent
    from el.agents.base import AgentContext

    img = tmp_path / "d.001"; img.write_bytes(b"\x00")
    case_dir = tmp_path / "case"; (case_dir / "analysis").mkdir(parents=True)
    walked_with = {}

    monkeypatch.setattr(sk, "is_split_raw", lambda p: True)
    def _boom(i, mp):
        raise sk.SleuthkitError("affuse not installed (apt install afflib-tools)")
    monkeypatch.setattr(sk, "affuse_mount", _boom)

    agent = DiskForensicatorAgent()
    monkeypatch.setattr(
        agent, "_raw_disk_walk",
        lambda ctx, analysis, raw_image: walked_with.__setitem__("raw", raw_image) or [])

    ctx = AgentContext(case_id="t", case_dir=case_dir, input_path=img,
                       manifest={}, shared={"evidence_kind": "raw-disk (GPT)"})
    out = agent.run(ctx)

    assert walked_with["raw"] == img            # fell back to the .001
    assert any("affuse bridge failed" in f.claim.lower() for f in out)
