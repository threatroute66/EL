"""TLSH fuzzy hash + cross-case knowledge-DB integration.

Driver: malware-family clustering across cases. ssdeep already covers
the content-triage axis; TLSH adds the locality-sensitive variant
that performs better on packed PE samples and has well-documented
distance thresholds for malware-family identification.

Tests cover:
- `tlsh_digest` produces a stable 70-char hex string for ≥50 B input
  and returns None for too-small / unreadable / low-entropy inputs
- `tlsh_distance` between identical content is 0; between very
  similar content is small; between unrelated is large
- `tlsh_score_band` maps to the canonical bands
- `record_fuzzy_hash(tlsh=...)` persists and `lookup_similar_tlsh`
  finds it from a different case
- Schema migration: an existing `fuzzy_hashes` table without a
  `tlsh` column gets the column added on next open
"""
import sqlite3
from pathlib import Path

import pytest

from el import knowledge as kb
from el.skills.similarity_digest import (
    tlsh_digest, tlsh_distance, tlsh_score_band,
)


# --- skill: tlsh_digest --------------------------------------------------

def test_tlsh_digest_produces_70_char_hex(tmp_path):
    # ≥50 bytes of moderate-entropy content
    p = tmp_path / "sample.bin"
    p.write_bytes(b"".join(bytes([i & 0xff, (i*7) & 0xff, (i*13) & 0xff])
                          for i in range(200)))
    h = tlsh_digest(p)
    assert h is not None
    assert isinstance(h, str)
    # python-tlsh emits "T1" + 70 hex chars
    assert len(h) >= 70


def test_tlsh_digest_too_small_returns_none(tmp_path):
    p = tmp_path / "tiny.bin"
    p.write_bytes(b"abc")  # < 50 B floor
    assert tlsh_digest(p) is None


def test_tlsh_digest_unreadable_returns_none(tmp_path):
    assert tlsh_digest(tmp_path / "does-not-exist.bin") is None


def test_tlsh_digest_zero_entropy_returns_none(tmp_path):
    # All-zero content has insufficient entropy for TLSH
    p = tmp_path / "zeros.bin"
    p.write_bytes(b"\x00" * 1024)
    assert tlsh_digest(p) is None


# --- skill: tlsh_distance + tlsh_score_band -----------------------------

def _entropic_payload(seed: int, n: int = 4096) -> bytes:
    """Reproducible high-entropy bytes via xorshift — enough randomness
    for TLSH's checksum + bucket selection but deterministic per seed."""
    state = seed | 1
    out = bytearray()
    for _ in range(n):
        state ^= (state << 13) & 0xffffffff
        state ^= (state >> 17)
        state ^= (state << 5) & 0xffffffff
        out.append(state & 0xff)
    return bytes(out)


def test_tlsh_distance_identical_is_zero(tmp_path):
    payload = _entropic_payload(42)
    a = tmp_path / "a.bin"; a.write_bytes(payload)
    b = tmp_path / "b.bin"; b.write_bytes(payload)
    da, db = tlsh_digest(a), tlsh_digest(b)
    assert da == db
    assert tlsh_distance(da, db) == 0


def test_tlsh_distance_unrelated_is_large(tmp_path):
    a = tmp_path / "a.bin"; a.write_bytes(_entropic_payload(1))
    b = tmp_path / "b.bin"; b.write_bytes(_entropic_payload(99999))
    da, db = tlsh_digest(a), tlsh_digest(b)
    d = tlsh_distance(da, db)
    assert d is not None
    assert d > 100, f"unrelated payloads should be >100 distance, got {d}"


def test_tlsh_score_band_thresholds():
    assert tlsh_score_band(None) == "unknown"
    assert tlsh_score_band(0) == "very-close-variant"
    assert tlsh_score_band(30) == "very-close-variant"
    assert tlsh_score_band(50) == "same-family-likely"
    assert tlsh_score_band(70) == "same-family-likely"
    assert tlsh_score_band(100) == "same-family-loose"
    assert tlsh_score_band(200) == "unrelated"


def test_tlsh_distance_returns_none_for_empty_input():
    assert tlsh_distance("", "T1abc") is None
    assert tlsh_distance(None, "T1abc") is None


# --- knowledge DB: record + lookup --------------------------------------

def test_record_and_lookup_tlsh_finds_match_across_cases(tmp_path):
    """A TLSH stored in case A is retrievable from case B's lookup
    when the digests are within `max_distance` and the case_id
    differs."""
    db = tmp_path / "test_kb.sqlite"

    # Synthesise two near-identical payloads so their TLSHes are
    # within the same-family threshold (≤70).
    base = _entropic_payload(7)
    near_dup = bytearray(base)
    # Change a small fraction of bytes — should keep distance small.
    for i in range(0, 50):
        near_dup[i] ^= 0x01
    a_path = tmp_path / "case_a.bin"; a_path.write_bytes(base)
    b_path = tmp_path / "case_b.bin"; b_path.write_bytes(bytes(near_dup))

    td_a = tlsh_digest(a_path); td_b = tlsh_digest(b_path)
    assert td_a and td_b
    d = tlsh_distance(td_a, td_b)
    assert d is not None and d <= 70, f"setup failed: distance={d}"

    kb.record_fuzzy_hash(
        case_id="case-A", agent="t",
        sha256="a" * 64, tlsh=td_a, file_size=len(base),
        source_path=str(a_path), db_path=db,
    )

    hits = kb.lookup_similar_tlsh(td_b, current_case_id="case-B",
                                    max_distance=70, db_path=db)
    assert any(h["case_id"] == "case-A" for h in hits)


def test_lookup_excludes_current_case(tmp_path):
    db = tmp_path / "kb.sqlite"
    payload = _entropic_payload(123)
    p = tmp_path / "x.bin"; p.write_bytes(payload)
    td = tlsh_digest(p)
    kb.record_fuzzy_hash(
        case_id="case-X", agent="t",
        sha256="b" * 64, tlsh=td, db_path=db,
    )
    # Looking up for case-X excludes its own hash
    assert kb.lookup_similar_tlsh(td, current_case_id="case-X",
                                    db_path=db) == []
    # But case-Y sees it (distance 0 → close-variant)
    hits = kb.lookup_similar_tlsh(td, current_case_id="case-Y", db_path=db)
    assert len(hits) == 1
    assert hits[0]["distance"] == 0
    assert hits[0]["band"] == "very-close-variant"


def test_lookup_above_threshold_excluded(tmp_path):
    db = tmp_path / "kb.sqlite"
    a = tmp_path / "a.bin"; a.write_bytes(_entropic_payload(1))
    b = tmp_path / "b.bin"; b.write_bytes(_entropic_payload(99999))
    td_a = tlsh_digest(a); td_b = tlsh_digest(b)
    kb.record_fuzzy_hash(case_id="case-A", agent="t",
                          sha256="c" * 64, tlsh=td_a, db_path=db)
    # td_b is far from td_a — should be excluded by max_distance
    assert kb.lookup_similar_tlsh(td_b, current_case_id="case-B",
                                    max_distance=30, db_path=db) == []


# --- schema migration ----------------------------------------------------

def test_legacy_schema_gets_tlsh_column(tmp_path):
    """An older knowledge.sqlite without the tlsh column must be
    upgraded transparently on the next open_db, not crash."""
    db = tmp_path / "legacy.sqlite"
    # Create the schema as it existed BEFORE the tlsh column was added.
    conn = sqlite3.connect(db)
    conn.executescript("""
    CREATE TABLE fuzzy_hashes (
        case_id       TEXT NOT NULL,
        sha256        TEXT NOT NULL,
        ssdeep        TEXT,
        phash         TEXT,
        file_size     INTEGER,
        source_path   TEXT,
        observed_utc  TEXT NOT NULL,
        agent         TEXT NOT NULL,
        sealed        INTEGER DEFAULT 0,
        PRIMARY KEY (case_id, sha256)
    );
    INSERT INTO fuzzy_hashes(case_id, sha256, ssdeep, observed_utc, agent)
        VALUES ('legacy', 'd' * 64, 'fakeSdeep', '2026-01-01T00:00:00', 't');
    """)
    conn.commit()
    conn.close()

    # Re-open via knowledge.open_db — should ALTER ADD COLUMN tlsh.
    with kb.open_db(db) as conn:
        cols = {row[1] for row in
                conn.execute("PRAGMA table_info(fuzzy_hashes)")}
    assert "tlsh" in cols

    # And new inserts can use the tlsh kw without error.
    inserted = kb.record_fuzzy_hash(
        case_id="post-migration", agent="t",
        sha256="e" * 64, tlsh="T1abc"*14, db_path=db,
    )
    assert inserted is True
