"""Chromium LevelDB parser tests.

Snappy is validated against hand-computed vectors; the .log reader against a
hand-built write-ahead log; the table reader + Snappy end-to-end against the
real Samsung-A53 Wordle store (skip-gated on the image being mounted).
"""
import struct
from pathlib import Path

import pytest

from el.skills import chromium_leveldb as ldb


# --- Snappy -----------------------------------------------------------------

def test_snappy_literal_only():
    # preamble len=3, literal tag (len-1)<<2=0x08, "ABC"
    assert ldb.snappy_decompress(b"\x03\x08ABC") == b"ABC"


def test_snappy_with_copy():
    # len=8, literal "ABCD", then 1-byte-offset copy len=4 offset=4 -> "ABCDABCD"
    assert ldb.snappy_decompress(b"\x08\x0CABCD\x01\x04") == b"ABCDABCD"


def test_snappy_long_literal():
    payload = b"X" * 100
    # len=100 (varint 0x64), literal len>=60: tag = (60<<2)|0 with extra-bytes
    # encoding -> ln field 60 means "1 extra length byte follows" (=59+1).
    comp = b"\x64" + bytes([(60 << 2)]) + bytes([100 - 1]) + payload
    assert ldb.snappy_decompress(comp) == payload


# --- value decoding ---------------------------------------------------------

def test_decode_storage_value_utf16():
    raw = b"\x00" + "héllo".encode("utf-16-le")
    assert ldb.decode_storage_value(raw) == "héllo"


def test_decode_storage_value_latin1_marker():
    raw = b"\x01" + "plain".encode("utf-8")
    assert ldb.decode_storage_value(raw) == "plain"


def test_decode_storage_value_raw():
    assert ldb.decode_storage_value(b"rawbytes") == "rawbytes"


# --- .log reader ------------------------------------------------------------

def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _put(key: bytes, val: bytes) -> bytes:
    return b"\x01" + _varint(len(key)) + key + _varint(len(val)) + val


def _delete(key: bytes) -> bytes:
    return b"\x00" + _varint(len(key)) + key


def _batch(seq: int, entries: list[bytes]) -> bytes:
    return struct.pack("<Q", seq) + struct.pack("<I", len(entries)) + b"".join(entries)


def _logrec(payload: bytes) -> bytes:
    # crc(4, ignored by reader) + length(2 LE) + type(1=FULL) + payload
    return b"\x00\x00\x00\x00" + struct.pack("<H", len(payload)) + b"\x01" + payload


def _make_leveldb_dir(tmp_path: Path) -> Path:
    d = tmp_path / "leveldb"
    d.mkdir()
    (d / "CURRENT").write_text("MANIFEST-000001\n")
    log = _logrec(_batch(1, [_put(b"k1", b"v1"), _put(b"k2", b"v2")]))
    log += _logrec(_batch(3, [_delete(b"k1")]))
    (d / "000001.log").write_bytes(log)
    return d


def test_log_reader_puts_and_deletes(tmp_path):
    d = _make_leveldb_dir(tmp_path)
    recs = ldb.read_log(d / "000001.log")
    puts = {r.key: r for r in recs if not r.deleted}
    assert puts[b"k1"].value == b"v1" and puts[b"k1"].seq == 1
    assert puts[b"k2"].value == b"v2" and puts[b"k2"].seq == 2
    dels = [r for r in recs if r.deleted]
    assert len(dels) == 1 and dels[0].key == b"k1" and dels[0].seq == 3


def test_parse_dir_latest_values_and_find(tmp_path):
    d = _make_leveldb_dir(tmp_path)
    run = ldb.parse(d, output_dir=tmp_path / "out")
    assert run.log_files == 1
    live = run.latest_values()
    # k1 was deleted at a higher seq -> not live; k2 live.
    assert b"k2" in live and b"k1" not in live
    assert run.find("v2") and run.find("v2")[0].key == b"k2"
    assert run.output_path.is_file()
    assert run.output_sha256 and run.output_sha256 != "0" * 64
    assert run.as_evidence().tool == "el.chromium_leveldb"


def test_find_leveldbs(tmp_path):
    d = _make_leveldb_dir(tmp_path)
    nested = tmp_path / "App" / "Local Storage" / "leveldb"
    nested.mkdir(parents=True)
    (nested / "CURRENT").write_text("x")
    found = ldb.find_leveldbs(tmp_path)
    assert d in found and nested in found


def test_bad_table_magic_raises(tmp_path):
    p = tmp_path / "bad.ldb"
    p.write_bytes(b"\x00" * 64)
    with pytest.raises(ldb.ChromiumLevelDBError):
        ldb.read_table(p)


def test_parse_missing_dir_raises(tmp_path):
    with pytest.raises(ldb.ChromiumLevelDBError):
        ldb.parse(tmp_path / "nope")


# --- real-data smoke (skipped unless the Samsung A53 image is present) ------

_WORDLE = Path(
    "/media/sansforensics/images/2026_Magnet_Virtual_Summit_CTF/SamsungA53/"
    "R5CW32F0PQH_files_full/data/data/com.nytimes.crossword/app_webview/"
    "Default/Local Storage/leveldb")


def _safe_is_file(p: Path) -> bool:
    try:
        return p.is_file()
    except OSError:
        return False


@pytest.mark.skipif(not _safe_is_file(_WORDLE / "CURRENT"),
                    reason="Samsung A53 image not mounted")
def test_real_wordle_store_decodes():
    run = ldb.parse(_WORDLE)
    assert run.total > 100 and run.table_files >= 1
    hits = run.find("games-state-wordleV2")
    assert hits
    # the snappy-compressed .ldb blocks must decode to readable JSON
    assert any("boardState" in r.value_text() for r in hits)
    # the first solved puzzle's winning word is recoverable from history
    assert any('"status":"WIN"' in r.value_text() and "colic" in r.value_text()
               for r in hits)
