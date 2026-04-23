"""Tests for the extension-vs-MIME mismatch detector."""
from __future__ import annotations

import shutil
import struct
import zipfile

import pytest

from el.skills import magic_mismatch as mm


pytestmark = pytest.mark.skipif(
    not shutil.which("file"),
    reason="`file` CLI not available on this host",
)


def test_pdf_with_txt_extension_flags(tmp_path):
    """BelkaCTF Kidnapper — extension mangling: a real PDF renamed .txt."""
    p = tmp_path / "letter.txt"
    p.write_bytes(b"%PDF-1.4\n%Fake PDF body\n" + b"\x00" * 100)
    hit = mm.scan_file(p)
    assert hit is not None
    assert hit.declared_ext == ".txt"
    assert "pdf" in hit.detected_mime


def test_plain_text_with_txt_extension_clean(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("hello world\n")
    assert mm.scan_file(p) is None


def test_zip_with_docx_extension_ok(tmp_path):
    """docx IS a zip internally; allow-listed as a matching family."""
    p = tmp_path / "report.docx"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("word/document.xml", "<x/>")
    assert mm.scan_file(p) is None


def test_walk_returns_multiple_mismatches(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"%PDF-1.4\n")
    # Minimal valid ZIP end-of-central-directory record so libmagic
    # confidently classifies it as application/zip.
    eocd = b"PK\x05\x06" + b"\x00" * 18
    (tmp_path / "b.log").write_bytes(eocd)
    (tmp_path / "c.txt").write_text("genuinely text")
    hits = mm.walk(tmp_path)
    names = {h.path.name for h in hits}
    assert "a.txt" in names
    assert "b.log" in names
    assert "c.txt" not in names


def test_unreadable_file_fails_soft(tmp_path):
    p = tmp_path / "empty.pdf"
    p.write_bytes(b"")
    hit = mm.scan_file(p)
    assert hit is None or hit.declared_ext == ".pdf"
