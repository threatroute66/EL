"""Tests for Tier 1 (similarity digest) + Tier 2 (stego carriers).

Motivated by Roussev & Quates 2012 "Content triage with similarity
digests: The M57 case study". Validates:
  - ssdeep digest + compare scale
  - perceptual-hash Hamming distance
  - stego-carrier pair detection (visually identical, byte-different)
  - knowledge DB round-trip for fuzzy hashes
  - cross-case similarity lookup excludes the current case
"""
import hashlib
import io
import os
import random
from pathlib import Path

import pytest

from el.skills import similarity_digest as sd


# ---------------------------------------------------------------------------
# ssdeep basics
# ---------------------------------------------------------------------------

def _write_bytes(path: Path, n: int, seed: int = 0) -> None:
    """Write `n` deterministic pseudo-random bytes so tests stay reproducible."""
    rng = random.Random(seed)
    path.write_bytes(bytes(rng.randrange(256) for _ in range(n)))


def test_ssdeep_identical_files_score_high(tmp_path):
    """Two files with identical content → ssdeep score 100."""
    a = tmp_path / "a.bin"; _write_bytes(a, 16 * 1024, seed=1)
    b = tmp_path / "b.bin"; b.write_bytes(a.read_bytes())
    da = sd.ssdeep_digest(a); db = sd.ssdeep_digest(b)
    assert da and db
    assert sd.ssdeep_compare(da, db) == 100


def test_ssdeep_uncorrelated_files_score_low(tmp_path):
    """Independent random files → strongly correlated would be a bug.
    Score must be 0 (uncorrelated) or very low (weak band)."""
    a = tmp_path / "a.bin"; _write_bytes(a, 16 * 1024, seed=1)
    b = tmp_path / "b.bin"; _write_bytes(b, 16 * 1024, seed=999)
    score = sd.ssdeep_compare(sd.ssdeep_digest(a), sd.ssdeep_digest(b))
    assert score <= 10, f"expected weak / uncorrelated, got {score}"


def test_ssdeep_rejects_files_below_minimum(tmp_path):
    """Files < 4 KB are below ssdeep's minimum — return None, not crash."""
    tiny = tmp_path / "tiny.bin"; tiny.write_bytes(b"x" * 100)
    assert sd.ssdeep_digest(tiny) is None


def test_ssdeep_modified_file_still_detected(tmp_path):
    """Modify the first 10% of a file — sdhash-style similarity should
    still detect substantial resemblance. This is the central value
    proposition of the paper."""
    a = tmp_path / "a.bin"; _write_bytes(a, 64 * 1024, seed=7)
    data = bytearray(a.read_bytes())
    # Change first 10% of the file
    for i in range(len(data) // 10):
        data[i] = (data[i] + 1) % 256
    b = tmp_path / "b.bin"; b.write_bytes(bytes(data))
    score = sd.ssdeep_compare(sd.ssdeep_digest(a), sd.ssdeep_digest(b))
    # Expect a positive score (even if not "strong"). Sha256 would miss
    # this completely; ssdeep sees the shared 90%.
    assert score > 0


def test_ssdeep_score_bands():
    assert sd.ssdeep_score_band(-1) == "invalid"
    assert sd.ssdeep_score_band(0) == "uncorrelated"
    assert sd.ssdeep_score_band(5) == "weak"
    assert sd.ssdeep_score_band(15) == "marginal"
    assert sd.ssdeep_score_band(80) == "strong"


# ---------------------------------------------------------------------------
# Perceptual image hash
# ---------------------------------------------------------------------------

def _write_img(path: Path, mode: str = "RGB", size=(32, 32),
                 color=(128, 64, 32)) -> None:
    from PIL import Image
    Image.new(mode, size, color).save(path)


def test_phash_identical_images_zero_distance(tmp_path):
    a = tmp_path / "a.png"; _write_img(a)
    b = tmp_path / "b.png"; _write_img(b)   # same bytes (deterministic PIL)
    pa, pb = sd.phash(a), sd.phash(b)
    assert pa and pb
    assert sd.phash_distance(pa, pb) == 0


def test_phash_very_different_images_far_apart(tmp_path):
    from PIL import Image
    a = tmp_path / "a.png"
    b = tmp_path / "b.png"
    # Very different pixel content
    Image.new("RGB", (64, 64), (255, 255, 255)).save(a)
    im = Image.new("RGB", (64, 64), (0, 0, 0))
    # Checkerboard-ish pattern
    for y in range(64):
        for x in range(64):
            if (x // 4 + y // 4) % 2:
                im.putpixel((x, y), (255, 0, 0))
    im.save(b)
    pa, pb = sd.phash(a), sd.phash(b)
    d = sd.phash_distance(pa, pb)
    assert d > 8, f"images this different should exceed threshold 8, got {d}"


def test_phash_non_image_returns_none(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("hi")
    assert sd.phash(p) is None


def test_phash_distance_invalid_returns_max():
    # Empty + length mismatch + non-hex input each return 64 (max)
    assert sd.phash_distance("", "abcd") == 64
    assert sd.phash_distance("abcd", "abcde") == 64
    assert sd.phash_distance("xyz!", "abcd") == 64


# ---------------------------------------------------------------------------
# Stego-carrier detection
# ---------------------------------------------------------------------------

def test_stego_carrier_pair_detected(tmp_path):
    """Two visually-identical images with a single byte modified in
    the trailing bytes (simulating a stego payload) should be flagged:
    pHash Hamming 0 but sha256 differs."""
    a = tmp_path / "photo1.png"; _write_img(a)
    b = tmp_path / "photo2.png"
    # Copy + append a comment chunk so sha256 differs but pixel content
    # is identical. PIL re-reading preserves pixel content regardless
    # of trailing bytes for most formats.
    raw = a.read_bytes()
    b.write_bytes(raw + b"\x00" * 32)
    pairs = sd.detect_stego_carrier_pairs(tmp_path)
    assert len(pairs) == 1
    p = pairs[0]
    assert p.hamming == 0
    assert p.sha256_a != p.sha256_b
    assert {Path(p.path_a).name, Path(p.path_b).name} == \
           {"photo1.png", "photo2.png"}


def test_stego_identical_bytes_not_flagged(tmp_path):
    """Byte-identical files must NOT be flagged — same sha256 = duplicate,
    not a stego carrier pair."""
    a = tmp_path / "a.png"; _write_img(a)
    b = tmp_path / "b.png"; b.write_bytes(a.read_bytes())
    assert sd.detect_stego_carrier_pairs(tmp_path) == []


def test_stego_unrelated_images_not_flagged(tmp_path):
    """Visually different images must not cross the Hamming threshold."""
    from PIL import Image
    a = tmp_path / "a.png"
    b = tmp_path / "b.png"
    Image.new("RGB", (64, 64), (0, 0, 0)).save(a)
    # Visually distinct pattern
    im = Image.new("RGB", (64, 64), (255, 255, 255))
    for y in range(64):
        for x in range(64):
            if (x + y) % 2:
                im.putpixel((x, y), (0, 0, 0))
    im.save(b)
    assert sd.detect_stego_carrier_pairs(tmp_path) == []


def test_stego_missing_dir_returns_empty(tmp_path):
    assert sd.detect_stego_carrier_pairs(tmp_path / "does-not-exist") == []


# ---------------------------------------------------------------------------
# Knowledge DB integration — fuzzy hash record + cross-case lookup
# ---------------------------------------------------------------------------

def test_knowledge_fuzzy_hash_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "k.sqlite"))
    from el import knowledge as kb
    a = tmp_path / "a.bin"; _write_bytes(a, 16 * 1024, seed=1)
    sha = hashlib.sha256(a.read_bytes()).hexdigest()
    digest = sd.ssdeep_digest(a)
    assert kb.record_fuzzy_hash(
        case_id="case-A", agent="test", sha256=sha, ssdeep=digest,
        file_size=a.stat().st_size, source_path=str(a))
    # Cross-case lookup from a DIFFERENT case: hits case-A
    hits = kb.lookup_similar_ssdeep(digest, current_case_id="case-B")
    assert len(hits) == 1
    assert hits[0]["case_id"] == "case-A"
    assert hits[0]["score"] == 100
    assert hits[0]["band"] == "strong"
    # Same case excluded
    assert kb.lookup_similar_ssdeep(digest, current_case_id="case-A") == []


def test_knowledge_fuzzy_hash_near_duplicate_match(tmp_path, monkeypatch):
    """The whole point: B doesn't share sha256 with A but shares ssdeep."""
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "k.sqlite"))
    from el import knowledge as kb
    a = tmp_path / "a.bin"; _write_bytes(a, 64 * 1024, seed=7)
    # Record A into the knowledge DB
    sha_a = hashlib.sha256(a.read_bytes()).hexdigest()
    kb.record_fuzzy_hash(case_id="case-A", agent="t",
                          sha256=sha_a, ssdeep=sd.ssdeep_digest(a))
    # Make B: A with 10% of bytes modified (ssdeep should match; sha differs)
    data = bytearray(a.read_bytes())
    for i in range(len(data) // 10):
        data[i] = (data[i] + 1) % 256
    b = tmp_path / "b.bin"; b.write_bytes(bytes(data))
    digest_b = sd.ssdeep_digest(b)
    hits = kb.lookup_similar_ssdeep(
        digest_b, current_case_id="case-B", threshold=1)
    assert hits, "near-duplicate should be found"
    assert hits[0]["case_id"] == "case-A"
    assert hits[0]["score"] > 0


def test_knowledge_phash_lookup_stego_carrier(tmp_path, monkeypatch):
    """Cross-case stego-carrier confirmation via phash registry."""
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "k.sqlite"))
    from el import knowledge as kb
    a = tmp_path / "a.png"; _write_img(a)
    pa = sd.phash(a)
    kb.record_fuzzy_hash(case_id="case-A", agent="t",
                          sha256="a" * 64, phash=pa)
    # Another case has the same image (identical pHash)
    hits = kb.lookup_similar_phash(pa, current_case_id="case-B")
    assert len(hits) == 1
    assert hits[0]["case_id"] == "case-A"
    assert hits[0]["hamming"] == 0


# ---------------------------------------------------------------------------
# Schema: fuzzy_hashes table is created lazily
# ---------------------------------------------------------------------------

def test_fuzzy_hashes_table_auto_created(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "k.sqlite"))
    from el import knowledge as kb
    # Record an IOC (existing path) — must also create fuzzy_hashes table
    kb.record_iocs("case-1", "t", {"ipv4": {"10.0.0.1"}})
    import sqlite3
    c = sqlite3.connect(tmp_path / "k.sqlite")
    cur = c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='fuzzy_hashes'")
    assert cur.fetchone() is not None
    c.close()
