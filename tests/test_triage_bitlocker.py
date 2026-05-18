"""Tests for the BitLocker triage detector.

The BitLocker `-FVE-FS-` magic sits at file offset 0x03 (after the
3-byte JMP), not at byte 0 — so it doesn't fall out of the
MAGIC_HINTS prefix loop. A dedicated `_detect_bitlocker` checks
the offset-3 signature; if it fires, triage sets
`evidence_kind = "bitlocker"` and the downstream disk_forensicator
dispatcher routes to the dislocker unlock path.

Pins:
  - byte-3 detection (jmp + signature)
  - non-BitLocker volumes (NTFS, FAT32) don't trigger
  - too-short / unreadable files don't crash
  - evidence_kind round-trips through the agent run
"""
from __future__ import annotations

from pathlib import Path

import pytest

from el.agents.triage import _detect_bitlocker


# ---------------------------------------------------------------------------
# Direct unit tests for the detector
# ---------------------------------------------------------------------------

def test_detect_bitlocker_real_signature(tmp_path):
    p = tmp_path / "vol.bin"
    p.write_bytes(b"\xeb\x58\x90-FVE-FS-" + b"\x00" * 100)
    assert _detect_bitlocker(p) == "bitlocker"


def test_detect_bitlocker_skips_ntfs(tmp_path):
    """NTFS volumes carry `NTFS    ` at the same offset — must NOT
    fire (would route the wrong way through disk_forensicator)."""
    p = tmp_path / "ntfs.bin"
    p.write_bytes(b"\xeb\x52\x90NTFS    " + b"\x00" * 100)
    assert _detect_bitlocker(p) is None


def test_detect_bitlocker_skips_fat32(tmp_path):
    """Plain FAT32 boot sector (no BitLocker wrapping) — common on
    USB sticks, must NOT trigger the encryption-unlock path."""
    p = tmp_path / "fat.bin"
    p.write_bytes(b"\xeb\x58\x90MSDOS5.0" + b"\x00" * 100)
    assert _detect_bitlocker(p) is None


def test_detect_bitlocker_partial_signature_at_offset0(tmp_path):
    """A file that contains the bytes `-FVE-FS-` at offset 0 (not
    after a JMP) is NOT a BitLocker volume — the signature must
    sit at offset 0x03 specifically."""
    p = tmp_path / "stub.bin"
    p.write_bytes(b"-FVE-FS-data here")
    assert _detect_bitlocker(p) is None


def test_detect_bitlocker_too_short(tmp_path):
    """Files smaller than 11 bytes can't carry the signature —
    detector returns None, never IndexError."""
    p = tmp_path / "tiny.bin"
    p.write_bytes(b"\xeb\x58\x90")
    assert _detect_bitlocker(p) is None


def test_detect_bitlocker_missing_file_returns_none(tmp_path):
    """An unreadable / missing path must return None silently —
    triage's main loop catches OSError but the helper should also
    fail gracefully on its own."""
    assert _detect_bitlocker(tmp_path / "absent") is None


# ---------------------------------------------------------------------------
# Hypothesis registration smoke test
# ---------------------------------------------------------------------------

def test_h_disk_encrypted_hypothesis_registered():
    """H_DISK_ENCRYPTED must appear in the canonical hypothesis
    library so disk_forensicator.bitlocker findings tagged with it
    actually score (otherwise the tag is dead weight)."""
    from el.intel.hypotheses import HYPOTHESES
    ids = {h.hyp_id for h in HYPOTHESES}
    assert "H_DISK_ENCRYPTED" in ids


def test_h_disk_encrypted_scorer_lifts_only_on_tag():
    """Scorer must produce +1 ONLY when the finding carries the
    H_DISK_ENCRYPTED tag — not on tangentially-related disk
    findings. Pins the narrow-lift contract for this advisory
    hypothesis."""
    from el.intel.hypotheses import HYPOTHESES
    from el.schemas.finding import EvidenceItem, Finding
    hyp = next(h for h in HYPOTHESES if h.hyp_id == "H_DISK_ENCRYPTED")
    f_pos = Finding(
        case_id="t", agent="disk_forensicator",
        claim="BitLocker volume detected: ...",
        confidence="high",
        evidence=[EvidenceItem(tool="t", version="v", command="c",
                                output_sha256="0" * 64, output_path="/",
                                extracted_facts={"phase": "bitlocker_probe"})],
        hypotheses_supported=["H_DISK_ENCRYPTED"],
    )
    f_neg = Finding(
        case_id="t", agent="disk_forensicator",
        claim="Some other disk finding",
        confidence="high",
        evidence=[EvidenceItem(tool="t", version="v", command="c",
                                output_sha256="0" * 64, output_path="/",
                                extracted_facts={})],
        hypotheses_supported=["H_DISK_ARTIFACTS"],
    )
    assert hyp.score(f_pos) == 1
    assert hyp.score(f_neg) == 0
