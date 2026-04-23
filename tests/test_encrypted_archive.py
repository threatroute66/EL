"""Tests for the encrypted-archive detector.

The detector reads the ZIP local-file-header flag_bits. Standard library
zipfile doesn't write encrypted entries (it only reads them), so each
test builds a minimal ZIP at the byte level — a tiny local-file-header +
central directory with the encryption flag (bit 0) set.
"""
from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from el.skills import encrypted_archive as ea


def _write_plain_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("readme.txt", "hello")


def _write_encrypted_like_zip(path: Path, name: str = "secret.txt") -> None:
    """Build a ZIP whose single member has the encryption flag set.

    zipfile.setpassword() only encrypts on write with pyzipper/real ZipCrypto
    — we just need flag_bits & 0x01 to be observed, which is what EL's
    detector reads. So we post-process a plain ZIP and flip the flag byte
    in both the local header and the central directory.
    """
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(name, "doesnt-matter")
    raw = bytearray(path.read_bytes())

    # Local file header: signature PK\x03\x04, bytes 6-7 = GP flag. Flip bit 0.
    lfh = raw.find(b"PK\x03\x04")
    assert lfh >= 0
    flags = struct.unpack_from("<H", raw, lfh + 6)[0]
    struct.pack_into("<H", raw, lfh + 6, flags | 0x01)

    # Central directory: signature PK\x01\x02, bytes 8-9 = GP flag.
    cdh = raw.find(b"PK\x01\x02")
    assert cdh >= 0
    flags = struct.unpack_from("<H", raw, cdh + 8)[0]
    struct.pack_into("<H", raw, cdh + 8, flags | 0x01)

    path.write_bytes(bytes(raw))


def test_plain_zip_produces_no_hit(tmp_path):
    z = tmp_path / "plain.zip"
    _write_plain_zip(z)
    assert ea.scan_archive(z) is None


def test_encrypted_zip_detected(tmp_path):
    z = tmp_path / "Monthly_DB.zip"
    _write_encrypted_like_zip(z, "q1_ledger.xlsx")
    hit = ea.scan_archive(z)
    assert hit is not None
    assert hit.encrypted_count == 1
    assert "q1_ledger.xlsx" in hit.encrypted_members


def test_walk_finds_encrypted_zip_in_subdirectory(tmp_path):
    sub = tmp_path / "home" / "ivan" / ".custom"
    sub.mkdir(parents=True)
    _write_encrypted_like_zip(sub / "mycon.zip", "clients.db")
    _write_plain_zip(sub / "harmless.zip")
    hits = ea.walk(tmp_path)
    names = {h.archive_path.name for h in hits}
    assert "mycon.zip" in names
    assert "harmless.zip" not in names


def test_walk_ignores_non_zip_files(tmp_path):
    (tmp_path / "foo.bin").write_bytes(b"\x00\x01\x02")
    (tmp_path / "doc.pdf").write_bytes(b"%PDF-1.4\n")
    assert ea.walk(tmp_path) == []


def test_truncated_zip_fails_soft(tmp_path):
    bad = tmp_path / "broken.zip"
    bad.write_bytes(b"PK\x03\x04not-a-real-zip")
    assert ea.scan_archive(bad) is None
