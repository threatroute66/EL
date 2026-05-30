"""Chromium LevelDB parser — Local Storage / IndexedDB / Session Storage.

Chromium-family apps (Chrome, Samsung Internet, every Android WebView app,
Electron desktop apps) persist web-storage in LevelDB directories: a set of
``*.ldb`` sorted-table files plus a ``*.log`` write-ahead log, with
``CURRENT`` / ``MANIFEST-*`` / ``LOG``. The values hold app state that exists
nowhere else — game boards (Wordle), auth tokens, drafts, settings — and
``.ldb`` data blocks are Snappy- (or, on newer builds, Zstd-) compressed, so a
plain ``strings`` scan only recovers fragments.

No SIFT-bundled CLI reads this format, so this is a native parser (in the
spirit of the utmp / emlx parsers). It is dependency-light: a pure-Python
Snappy decompressor is built in, so the skill works with nothing installed;
``python-snappy`` / ``zstandard`` are used only if present (speed / Zstd
blocks).

Forensic stance: read-only, and it returns ALL records — including
superseded and tombstoned (deleted) keys recovered from old ``.ldb`` blocks —
because a stale/deleted value is evidence. ``latest_values()`` projects the
live state (newest sequence wins) when that's what you want.

Format references: LevelDB table & log format (Google), Chromium
Local Storage schema (ccl_chromium_reader by Alex Caithness).
"""
from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from el.schemas.finding import EvidenceItem

# Optional accelerators — never required.
try:                                  # pragma: no cover - presence varies
    import snappy as _snappy_lib       # python-snappy
except Exception:                     # pragma: no cover
    _snappy_lib = None
try:                                  # pragma: no cover
    import zstandard as _zstd_lib
except Exception:                     # pragma: no cover
    _zstd_lib = None


class ChromiumLevelDBError(Exception):
    pass


_TABLE_MAGIC = 0xdb4775248b80fb57      # LevelDB sstable footer magic
_LOG_BLOCK = 32768                     # LevelDB log physical block size


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def snappy_decompress(data: bytes) -> bytes:
    """Decompress a raw Snappy block (preamble length + literals/copies).
    Uses python-snappy when available, else a pure-Python implementation."""
    if _snappy_lib is not None:        # pragma: no cover - depends on env
        try:
            return _snappy_lib.decompress(data)
        except Exception:
            pass
    out = bytearray()
    _ulen, pos = _read_varint(data, 0)
    n = len(data)
    while pos < n:
        tag = data[pos]
        pos += 1
        t = tag & 0x03
        if t == 0:                     # literal
            ln = tag >> 2
            if ln < 60:
                ln += 1
            else:
                extra = ln - 59
                ln = int.from_bytes(data[pos:pos + extra], "little") + 1
                pos += extra
            out += data[pos:pos + ln]
            pos += ln
        else:                          # copy
            if t == 1:
                ln = 4 + ((tag >> 2) & 0x07)
                offset = ((tag >> 5) << 8) | data[pos]
                pos += 1
            elif t == 2:
                ln = (tag >> 2) + 1
                offset = int.from_bytes(data[pos:pos + 2], "little")
                pos += 2
            else:                      # t == 3
                ln = (tag >> 2) + 1
                offset = int.from_bytes(data[pos:pos + 4], "little")
                pos += 4
            start = len(out) - offset
            if start < 0:
                break                  # corrupt copy — stop leniently
            for i in range(ln):
                out.append(out[start + i])
    return bytes(out)


def _decompress_block(content: bytes, comp_type: int) -> bytes | None:
    if comp_type == 0:
        return content
    if comp_type == 1:
        try:
            return snappy_decompress(content)
        except Exception:
            return None
    if comp_type == 4:                 # zstd (newer Chromium)
        if _zstd_lib is None:
            return None
        try:                            # pragma: no cover - depends on env
            return _zstd_lib.ZstdDecompressor().decompress(content)
        except Exception:
            try:
                return _zstd_lib.ZstdDecompressor().stream_reader(
                    __import__("io").BytesIO(content)).read()
            except Exception:
                return None
    return None                        # 2=zlib (unused by Chromium LS) etc.


@dataclass
class LevelDBRecord:
    key: bytes
    value: bytes
    seq: int = 0
    deleted: bool = False
    source: str = ""                   # filename the record came from

    def key_text(self) -> str:
        return best_effort_text(self.key)

    def value_text(self) -> str:
        return decode_storage_value(self.value)


# --------------------------------------------------------------------------
# .ldb (sorted table) reader
# --------------------------------------------------------------------------

def _iter_block_entries(block: bytes) -> Iterator[tuple[bytes, bytes]]:
    """Yield (key, value) from a decompressed LevelDB data/index block."""
    if len(block) < 4:
        return
    num_restarts = struct.unpack("<I", block[-4:])[0]
    restart_arr = 4 + num_restarts * 4
    end = len(block) - restart_arr
    pos = 0
    last_key = b""
    while pos < end:
        shared, pos = _read_varint(block, pos)
        non_shared, pos = _read_varint(block, pos)
        vlen, pos = _read_varint(block, pos)
        key = last_key[:shared] + block[pos:pos + non_shared]
        pos += non_shared
        value = block[pos:pos + vlen]
        pos += vlen
        last_key = key
        yield key, value


def _read_block(data: bytes, offset: int, size: int) -> bytes | None:
    content = data[offset:offset + size]
    comp_type = data[offset + size]                 # 1-byte trailer: comp type
    return _decompress_block(content, comp_type)


def read_table(path: Path) -> list[LevelDBRecord]:
    """Parse one ``.ldb`` / ``.sst`` table into records (internal-key trailer
    stripped; tombstones flagged)."""
    data = Path(path).read_bytes()
    if len(data) < 48:
        return []
    footer = data[-48:]
    magic = struct.unpack("<Q", footer[-8:])[0]
    if magic != _TABLE_MAGIC:
        raise ChromiumLevelDBError(f"not a LevelDB table (bad magic): {path}")
    fp = 0
    _mi_off, fp = _read_varint(footer, fp)          # metaindex handle
    _mi_size, fp = _read_varint(footer, fp)
    idx_off, fp = _read_varint(footer, fp)          # index handle
    idx_size, fp = _read_varint(footer, fp)

    out: list[LevelDBRecord] = []
    index_block = _read_block(data, idx_off, idx_size)
    if index_block is None:
        return out
    src = Path(path).name
    for _sep_key, handle in _iter_block_entries(index_block):
        hp = 0
        blk_off, hp = _read_varint(handle, hp)
        blk_size, hp = _read_varint(handle, hp)
        try:
            block = _read_block(data, blk_off, blk_size)
        except Exception:
            continue
        if block is None:
            continue
        for ikey, value in _iter_block_entries(block):
            if len(ikey) < 8:
                continue
            user_key = ikey[:-8]
            trailer = int.from_bytes(ikey[-8:], "little")
            vtype = trailer & 0xFF
            seq = trailer >> 8
            out.append(LevelDBRecord(
                key=user_key, value=value, seq=seq,
                deleted=(vtype == 0), source=src))
    return out


# --------------------------------------------------------------------------
# .log (write-ahead memtable) reader
# --------------------------------------------------------------------------

def _parse_write_batch(payload: bytes, src: str,
                       out: list[LevelDBRecord]) -> None:
    if len(payload) < 12:
        return
    seq = int.from_bytes(payload[0:8], "little")
    count = int.from_bytes(payload[8:12], "little")
    pos = 12
    for _ in range(count):
        if pos >= len(payload):
            break
        tag = payload[pos]
        pos += 1
        try:
            if tag == 1:                            # kTypeValue (put)
                klen, pos = _read_varint(payload, pos)
                key = payload[pos:pos + klen]; pos += klen
                vlen, pos = _read_varint(payload, pos)
                val = payload[pos:pos + vlen]; pos += vlen
                out.append(LevelDBRecord(key=key, value=val, seq=seq,
                                         deleted=False, source=src))
            elif tag == 0:                          # kTypeDeletion
                klen, pos = _read_varint(payload, pos)
                key = payload[pos:pos + klen]; pos += klen
                out.append(LevelDBRecord(key=key, value=b"", seq=seq,
                                         deleted=True, source=src))
            else:
                break
        except IndexError:
            break
        seq += 1


def read_log(path: Path) -> list[LevelDBRecord]:
    """Parse one ``.log`` write-ahead log into records (FULL + fragmented
    records reassembled)."""
    data = Path(path).read_bytes()
    src = Path(path).name
    out: list[LevelDBRecord] = []
    frag = bytearray()
    pos = 0
    n = len(data)
    while pos + 7 <= n:
        if _LOG_BLOCK - (pos % _LOG_BLOCK) < 7:     # block trailer padding
            pos += _LOG_BLOCK - (pos % _LOG_BLOCK)
            continue
        length = int.from_bytes(data[pos + 4:pos + 6], "little")
        rtype = data[pos + 6]
        pos += 7
        payload = data[pos:pos + length]
        pos += length
        if rtype == 1:                              # FULL
            _parse_write_batch(payload, src, out)
        elif rtype == 2:                            # FIRST
            frag = bytearray(payload)
        elif rtype == 3:                            # MIDDLE
            frag += payload
        elif rtype == 4:                            # LAST
            frag += payload
            _parse_write_batch(bytes(frag), src, out)
            frag = bytearray()
        # rtype 0 = zero padding -> ignore
    return out


# --------------------------------------------------------------------------
# value / key decoders
# --------------------------------------------------------------------------

def best_effort_text(raw: bytes) -> str:
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace")


def decode_storage_value(raw: bytes) -> str:
    """Decode a Chromium storage value. Local Storage prefixes values with a
    1-byte marker: 0x00 = UTF-16LE, 0x01 = Latin-1/UTF-8. Other stores hold
    raw bytes; fall back to best-effort text."""
    if not raw:
        return ""
    head = raw[0]
    if head == 0x00:
        return raw[1:].decode("utf-16-le", "replace")
    if head == 0x01:
        try:
            return raw[1:].decode("utf-8")
        except UnicodeDecodeError:
            return raw[1:].decode("latin-1", "replace")
    return best_effort_text(raw)


# --------------------------------------------------------------------------
# directory-level API
# --------------------------------------------------------------------------

@dataclass
class LevelDBRun:
    db_dir: Path
    records: list[LevelDBRecord] = field(default_factory=list)
    table_files: int = 0
    log_files: int = 0
    output_path: Path | None = None
    output_sha256: str = ""
    note: str = ""

    @property
    def total(self) -> int:
        return len(self.records)

    def latest_values(self) -> dict[bytes, LevelDBRecord]:
        """Live state: highest-seq non-deleted record per key."""
        best: dict[bytes, LevelDBRecord] = {}
        for r in self.records:
            cur = best.get(r.key)
            if cur is None or r.seq >= cur.seq:
                best[r.key] = r
        return {k: r for k, r in best.items() if not r.deleted}

    def find(self, needle: str) -> list[LevelDBRecord]:
        """Records whose decoded key OR value contains *needle* (case-insensitive)."""
        t = needle.lower()
        out = []
        for r in self.records:
            if t in r.key_text().lower() or t in r.value_text().lower():
                out.append(r)
        return out

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="el.chromium_leveldb", version="0.1.0",
            command=f"parse leveldb -- {self.db_dir}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.db_dir),
            extracted_facts={
                "db_dir": str(self.db_dir),
                "record_count": self.total,
                "table_files": self.table_files,
                "log_files": self.log_files,
                "live_key_count": len(self.latest_values()),
                "note": self.note,
                **extra,
            },
        )


def find_leveldbs(root: Path) -> list[Path]:
    """Locate LevelDB directories (those containing a ``CURRENT`` file) under
    *root* — e.g. ``.../Local Storage/leveldb`` and ``.../IndexedDB/*.leveldb``."""
    root = Path(root)
    out: list[Path] = []
    if (root / "CURRENT").is_file():
        out.append(root)
    for cur in root.rglob("CURRENT"):
        if cur.is_file() and cur.parent not in out:
            out.append(cur.parent)
    return out


def parse(db_dir: Path, output_dir: Path | None = None) -> LevelDBRun:
    """Read every ``.ldb`` + ``.log`` in *db_dir* into a :class:`LevelDBRun`.
    Writes a JSONL dump of decoded records under *output_dir* when given.
    Lenient: a corrupt table/log is skipped, not fatal."""
    db_dir = Path(db_dir)
    if not db_dir.is_dir():
        raise ChromiumLevelDBError(f"not a directory: {db_dir}")

    run = LevelDBRun(db_dir=db_dir)
    for ldb in sorted(db_dir.glob("*.ldb")) + sorted(db_dir.glob("*.sst")):
        try:
            run.records.extend(read_table(ldb))
            run.table_files += 1
        except (ChromiumLevelDBError, OSError, IndexError, struct.error):
            continue
    for log in sorted(db_dir.glob("*.log")):
        try:
            run.records.extend(read_log(log))
            run.log_files += 1
        except (OSError, IndexError, struct.error):
            continue

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "leveldb_records.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for r in run.records:
                f.write(json.dumps({
                    "key": r.key_text(),
                    "value": r.value_text()[:4000],
                    "seq": r.seq,
                    "deleted": r.deleted,
                    "source": r.source,
                }, sort_keys=True) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run
