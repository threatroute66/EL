"""Tests for el.intel.pair_detection.

The detector is a pure function over (name, path) tuples + filesystem
state; we drive it with files written into tmp_path so the assertions
about size / sidecar / mtime are real, not mocked.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from el.intel.pair_detection import (
    PairCandidate,
    detect_pairs,
    name_root,
    write_candidates,
)


# ---------------------------------------------------------------------
# name_root — the suffix-stripping helper
# ---------------------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("wkstn-01-mem", "wkstn-01"),
    ("wkstn-01-memory", "wkstn-01"),
    ("wkstn-01-pmem", "wkstn-01"),
    ("file-mem-snap5", "file"),
    ("file-mem-snapshot5", "file"),
    ("dc-mem", "dc"),
    ("rd-01-disk", "rd-01-disk"),         # disk suffix not stripped
    ("wkstn-01a", "wkstn-01"),
    ("wkstn-01b", "wkstn-01"),
    ("admin-memory", "admin"),
    ("FILE-MEM", "file"),                  # case-insensitive
    ("plain-host", "plain-host"),          # no suffix to strip
    ("hostimg", "host"),
    # cookie-cutter VM siblings must NOT collapse to the same root
])
def test_name_root_strips_known_suffixes(name, expected):
    assert name_root(name) == expected


def test_name_root_rejects_cookie_cutter_siblings():
    """wkstn-02 and wkstn-03 must NOT share a root — otherwise the
    detector would pair them as A/B of the same host, which they
    aren't. The whole heuristic falls apart if it over-matches here."""
    assert name_root("wkstn-02-mem") != name_root("wkstn-03-mem")
    assert name_root("wkstn-02-mem") == "wkstn-02"
    assert name_root("wkstn-03-mem") == "wkstn-03"


# ---------------------------------------------------------------------
# detect_pairs — the integration end of the detector
# ---------------------------------------------------------------------

def _mkfile(p: Path, size: int, content_seed: bytes = b"A") -> Path:
    """Write a file of exact byte size with a head sample driven by
    content_seed (so two files of equal size can still differ at
    head)."""
    p.parent.mkdir(parents=True, exist_ok=True)
    head = content_seed * 16   # first 16 bytes vary by seed
    body = b"\x00" * (size - len(head))
    p.write_bytes(head + body)
    return p


def test_detects_basic_wkstn_pair(tmp_path):
    """The canonical case: wkstn-01-mem and wkstn-01-memory of equal
    size, different content. Detector returns one PairCandidate."""
    a = _mkfile(tmp_path / "a" / "base-wkstn-01-mem.img", 4096, b"A")
    b = _mkfile(tmp_path / "b" / "base-wkstn-01-memory.img", 4096, b"B")

    pairs = detect_pairs([("wkstn-01-mem", str(a)),
                          ("wkstn-01-memory", str(b))])
    assert len(pairs) == 1
    pc = pairs[0]
    assert pc.name_root == "wkstn-01"
    assert pc.size_bytes == 4096
    assert {pc.authoritative_name, pc.baseline_name} == {
        "wkstn-01-mem", "wkstn-01-memory"}


def test_does_not_pair_when_sizes_differ(tmp_path):
    a = _mkfile(tmp_path / "a.img", 4096, b"A")
    b = _mkfile(tmp_path / "b.img", 8192, b"B")
    pairs = detect_pairs([("host-mem", str(a)), ("host-memory", str(b))])
    assert pairs == []


def test_does_not_pair_cookie_cutter_vms(tmp_path):
    """Two different hosts with the same RAM size (the lab/scenario
    failure mode) must NOT be paired — their roots are distinct."""
    a = _mkfile(tmp_path / "a.img", 4096, b"A")
    b = _mkfile(tmp_path / "b.img", 4096, b"B")
    pairs = detect_pairs([("wkstn-02-mem", str(a)),
                          ("wkstn-03-mem", str(b))])
    assert pairs == []


def test_does_not_pair_identical_files(tmp_path):
    """Two byte-identical files (e.g. a hardlink or a copy) are not
    a paired-capture opportunity — they're a deduplication case.
    Detector must skip them so the analyst doesn't waste a baseliner
    run on a guaranteed zero-byte diff."""
    a = _mkfile(tmp_path / "a.img", 4096, b"A")
    b = _mkfile(tmp_path / "b.img", 4096, b"A")  # same head sample
    pairs = detect_pairs([("host-mem", str(a)), ("host-memory", str(b))])
    assert pairs == []


def test_md5_sidecar_selects_authoritative(tmp_path):
    """When one side has a *.md5 acquisition sidecar (dc3dd / FTK
    Imager convention), it becomes authoritative even if it has the
    newer mtime."""
    a_dir = tmp_path / "loose"
    b_dir = tmp_path / "in_subdir"
    a = _mkfile(a_dir / "wkstn-01-mem.img", 4096, b"A")
    b = _mkfile(b_dir / "wkstn-01-memory.img", 4096, b"B")
    # md5 sidecar lives next to b — b should be authoritative.
    (b_dir / "wkstn-01-memory.md5").write_text("7586e0c...\n")
    # Make a older so the mtime tiebreaker would otherwise pick it.
    older = os.stat(a).st_atime - 7 * 24 * 3600
    os.utime(a, (older, older))

    pairs = detect_pairs([("wkstn-01-mem", str(a)),
                          ("wkstn-01-memory", str(b))])
    assert len(pairs) == 1
    pc = pairs[0]
    assert pc.authoritative_name == "wkstn-01-memory"
    assert pc.baseline_name == "wkstn-01-mem"
    assert pc.md5_sidecar_present_for == "wkstn-01-memory"
    assert "md5" in pc.reason.lower()


def test_older_mtime_authoritative_when_no_sidecar(tmp_path):
    """No sidecar on either side → older mtime is authoritative
    (the incident-era capture; the later capture is the
    candidate-for-clean-baseline)."""
    a = _mkfile(tmp_path / "old.img", 4096, b"A")
    b = _mkfile(tmp_path / "new.img", 4096, b"B")
    old_time = os.stat(a).st_atime - 365 * 24 * 3600
    os.utime(a, (old_time, old_time))

    pairs = detect_pairs([("host-mem", str(a)), ("host-memory", str(b))])
    assert len(pairs) == 1
    assert pairs[0].authoritative_name == "host-mem"
    assert pairs[0].baseline_name == "host-memory"
    assert pairs[0].md5_sidecar_present_for is None


def test_three_way_capture_pairs_extremes_and_notes_overflow(tmp_path):
    """3+ same-root captures: detector picks the mtime-extreme pair
    and records the rest as overflow notes so the analyst sees what
    wasn't paired."""
    a = _mkfile(tmp_path / "a.img", 4096, b"A")
    b = _mkfile(tmp_path / "b.img", 4096, b"B")
    c = _mkfile(tmp_path / "c.img", 4096, b"C")
    base = os.stat(a).st_atime
    os.utime(a, (base - 200, base - 200))
    os.utime(b, (base - 100, base - 100))
    os.utime(c, (base, base))

    pairs = detect_pairs([("host-mem", str(a)),
                          ("host-memory", str(b)),
                          ("host-pmem", str(c))])
    assert len(pairs) == 1
    pc = pairs[0]
    # Mtime-extreme pair → host-mem (oldest) + host-pmem (newest).
    assert {pc.authoritative_name, pc.baseline_name} == {"host-mem", "host-pmem"}
    assert any("host-memory" in n for n in pc.notes)


def test_skips_directories_and_zero_size(tmp_path):
    """Directories and zero-byte files are never pair candidates."""
    d = tmp_path / "iossysdiagnose"
    d.mkdir()
    empty = tmp_path / "empty.img"
    empty.write_bytes(b"")
    real = _mkfile(tmp_path / "real.img", 4096)

    pairs = detect_pairs([("dir-input", str(d)),
                          ("empty-input", str(empty)),
                          ("real-input", str(real))])
    assert pairs == []


def test_write_candidates_emits_json_even_when_empty(tmp_path):
    """The artefact must always land so analysts grepping for
    'was pair detection applied here' get a deterministic answer."""
    out = write_candidates(tmp_path, [])
    assert out.exists()
    import json
    payload = json.loads(out.read_text())
    assert payload["candidate_count"] == 0
    assert payload["candidates"] == []


def test_write_candidates_round_trips_pair(tmp_path):
    pc = PairCandidate(
        authoritative_name="wkstn-01-memory",
        authoritative_path="/x/wkstn-01-memory.img",
        baseline_name="wkstn-01-mem",
        baseline_path="/y/wkstn-01-mem.img",
        name_root="wkstn-01",
        size_bytes=4096,
        reason="md5 sidecar present on authoritative side",
        md5_sidecar_present_for="wkstn-01-memory",
        notes=[],
    )
    out = write_candidates(tmp_path, [pc])
    import json
    payload = json.loads(out.read_text())
    assert payload["candidate_count"] == 1
    got = payload["candidates"][0]
    assert got["authoritative_name"] == "wkstn-01-memory"
    assert got["baseline_name"] == "wkstn-01-mem"
    assert got["name_root"] == "wkstn-01"
