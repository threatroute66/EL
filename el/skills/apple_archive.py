"""Apple serialized-object decoders — NSKeyedArchiver + typedstream.

Two Apple formats hide forensic data inside opaque blobs that ``plistlib``
alone can't surface:

  * **NSKeyedArchiver** — a binary plist with ``$archiver`` / ``$objects`` /
    ``$top``, where objects reference each other by ``UID``. Instagram /
    Threads DM ``archive`` blobs, IG ranking graphs, ``state.plist`` files,
    ``SBClockData``, and countless iOS app caches use it. Resolving the UID
    object graph (with NSDictionary / NSArray / NSDate / NSData / cyclic
    refs) turns it into native Python.

  * **typedstream** (NSArchiver, ``\\x04\\x0bstreamtyped``) — the older format
    iMessage uses for a message's ``attributedBody`` (an NSAttributedString).
    On iOS 14+ the message ``text`` column is often NULL and the text lives
    only here.

No SIFT-bundled CLI decodes either, so this is a native decoder (like the
utmp / emlx / leveldb ones). Pure-Python, read-only, dependency-free.
"""
from __future__ import annotations

import hashlib
import json
import plistlib
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from el.schemas.finding import EvidenceItem

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
_TYPEDSTREAM_SIG = b"\x04\x0bstreamtyped"


class AppleArchiveError(Exception):
    pass


# ---------------------------------------------------------------------------
# format detection
# ---------------------------------------------------------------------------

def is_nskeyedarchiver(data) -> bool:
    if isinstance(data, dict):
        return "$objects" in data and "$top" in data
    if isinstance(data, (bytes, bytearray)):
        try:
            d = plistlib.loads(bytes(data))
        except Exception:
            return False
        return isinstance(d, dict) and "$objects" in d and "$top" in d
    return False


def is_typedstream(data) -> bool:
    return isinstance(data, (bytes, bytearray)) and bytes(data[:13]) == _TYPEDSTREAM_SIG


# ---------------------------------------------------------------------------
# NSKeyedArchiver
# ---------------------------------------------------------------------------

_DICT_CLASSES = {"NSDictionary", "NSMutableDictionary"}
_ARRAY_CLASSES = {"NSArray", "NSMutableArray", "NSSet", "NSMutableSet",
                  "NSOrderedSet", "NSMutableOrderedSet"}
_STRING_CLASSES = {"NSString", "NSMutableString"}
_DATA_CLASSES = {"NSData", "NSMutableData"}


def unarchive(data) -> Any:
    """Decode an NSKeyedArchiver plist (bytes or already-loaded dict) into a
    native Python object, resolving the UID graph. Cyclic references resolve
    to the same shared object. Raises :class:`AppleArchiveError` if the input
    isn't an NSKeyedArchiver."""
    if isinstance(data, (bytes, bytearray)):
        plist = plistlib.loads(bytes(data))
    else:
        plist = data
    if not (isinstance(plist, dict) and "$objects" in plist and "$top" in plist):
        raise AppleArchiveError("not an NSKeyedArchiver archive")

    objects = plist["$objects"]
    resolved: dict[int, Any] = {}

    def classname(ref) -> str:
        c = objects[ref.data] if isinstance(ref, plistlib.UID) else ref
        return c.get("$classname", "") if isinstance(c, dict) else str(c)

    def res(v) -> Any:
        if isinstance(v, plistlib.UID):
            return res_uid(v.data)
        if isinstance(v, dict):
            return {k: res(x) for k, x in v.items()}
        if isinstance(v, list):
            return [res(x) for x in v]
        return v

    def res_uid(idx: int) -> Any:
        if idx == 0:                         # $objects[0] == "$null"
            return None
        if idx in resolved:
            return resolved[idx]
        obj = objects[idx]

        if isinstance(obj, dict) and "$class" in obj:
            cls = classname(obj["$class"])
            if cls in _DICT_CLASSES:
                d: dict = {}
                resolved[idx] = d              # store before filling (cycles)
                for k, v in zip(obj.get("NS.keys", []), obj.get("NS.objects", [])):
                    key = res(k)
                    d[key if isinstance(key, (str, int, float, bool)) else str(key)] = res(v)
                return d
            if cls in _ARRAY_CLASSES:
                lst: list = []
                resolved[idx] = lst
                for v in obj.get("NS.objects", []):
                    lst.append(res(v))
                return lst
            if cls in _STRING_CLASSES:
                resolved[idx] = obj.get("NS.string", "")
                return resolved[idx]
            if cls in _DATA_CLASSES:
                resolved[idx] = bytes(obj.get("NS.data", b""))
                return resolved[idx]
            if cls == "NSDate":
                dt = _MAC_EPOCH + timedelta(seconds=float(obj.get("NS.time", 0)))
                resolved[idx] = dt
                return dt
            if cls == "NSUUID":
                ub = obj.get("NS.uuidbytes")
                resolved[idx] = str(_uuid.UUID(bytes=bytes(ub))) if ub else None
                return resolved[idx]
            if cls == "NSURL":
                d = {}
                resolved[idx] = d
                rel = res(obj.get("NS.relative"))
                base = res(obj.get("NS.base"))
                resolved[idx] = rel if not base else f"{base}{rel}"
                return resolved[idx]
            if cls == "NSNull":
                resolved[idx] = None
                return None
            # Unknown custom class: keep its fields so nothing is lost.
            d = {"$class": cls}
            resolved[idx] = d
            for k, v in obj.items():
                if k == "$class":
                    continue
                d[k] = res(v)
            return d

        if isinstance(obj, dict):
            d = {}
            resolved[idx] = d
            for k, v in obj.items():
                d[k] = res(v)
            return d

        resolved[idx] = obj
        return obj

    top = plist["$top"]
    if isinstance(top, dict):
        out = {k: res(v) for k, v in top.items()}
        if set(out.keys()) == {"root"}:
            return out["root"]
        return out
    return res(top)


def unarchive_file(path: Path) -> Any:
    return unarchive(Path(path).read_bytes())


# ---------------------------------------------------------------------------
# typedstream (iMessage attributedBody)
# ---------------------------------------------------------------------------

def imessage_text(blob: bytes) -> str:
    """Extract the message text from an iMessage ``attributedBody`` typedstream.

    The text is the NSString that follows the ``NSString`` /
    ``NSMutableString`` class marker, introduced by a ``+`` (0x2b) type byte
    and a typedstream length (1 byte, or 0x81+u16 / 0x82+u32 for longer
    strings). Falls back to the longest printable UTF-8 run if the structured
    read fails. Returns "" on anything unparseable."""
    if not isinstance(blob, (bytes, bytearray)):
        return ""
    blob = bytes(blob)
    for marker in (b"NSString", b"NSMutableString", b"NSAttributedString"):
        i = blob.find(marker)
        if i == -1:
            continue
        seg = blob[i + len(marker):]
        p = seg.find(b"\x2b")               # '+' start-of-string type byte
        if p == -1:
            continue
        seg = seg[p + 1:]
        if not seg:
            continue
        b0 = seg[0]
        if b0 == 0x81:
            length = int.from_bytes(seg[1:3], "little"); body = seg[3:3 + length]
        elif b0 == 0x82:
            length = int.from_bytes(seg[1:5], "little"); body = seg[5:5 + length]
        else:
            length = b0; body = seg[1:1 + length]
        if 0 < length == len(body):
            try:
                return body.decode("utf-8")
            except UnicodeDecodeError:
                return body.decode("utf-8", "replace")
    # Fallback: longest printable run that isn't a class/attribute name.
    import re
    runs = re.findall(rb"[\x20-\x7e]{3,}", blob)
    cand = [r for r in runs
            if not r.startswith(b"NS") and b"kIM" not in r
            and b"streamtyped" not in r and not r.startswith(b"__")]
    if cand:
        return max(cand, key=len).decode("utf-8", "replace")
    return ""


# ---------------------------------------------------------------------------
# dispatcher + file-level API
# ---------------------------------------------------------------------------

def decode(data) -> Any:
    """Decode either format: NSKeyedArchiver -> native object; typedstream ->
    extracted text. Raises :class:`AppleArchiveError` if neither matches."""
    if is_typedstream(data):
        return imessage_text(data)
    if is_nskeyedarchiver(data):
        return unarchive(data)
    raise AppleArchiveError("not an NSKeyedArchiver or typedstream blob")


def _json_default(o):
    if isinstance(o, (bytes, bytearray)):
        return "<%d bytes>" % len(o)
    if isinstance(o, datetime):
        return o.strftime("%Y-%m-%d %H:%M:%S")
    return str(o)


@dataclass
class ArchiveResult:
    source_path: Path
    fmt: str = ""                            # "nskeyedarchiver" | "typedstream"
    obj: Any = None
    output_path: Path | None = None
    output_sha256: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="el.apple_archive", version="0.1.0",
            command=f"decode {self.fmt} -- {self.source_path}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.source_path),
            extracted_facts={"source_path": str(self.source_path),
                             "format": self.fmt, **extra},
        )


def parse(path: Path, output_dir: Path | None = None) -> ArchiveResult:
    """Decode a single file (NSKeyedArchiver plist or typedstream blob) and,
    when *output_dir* is given, write the decoded object as JSON."""
    path = Path(path)
    if not path.is_file():
        raise AppleArchiveError(f"not a file: {path}")
    data = path.read_bytes()
    if is_typedstream(data):
        fmt, obj = "typedstream", imessage_text(data)
    elif is_nskeyedarchiver(data):
        fmt, obj = "nskeyedarchiver", unarchive(data)
    else:
        raise AppleArchiveError(f"unrecognised archive format: {path}")

    res = ArchiveResult(source_path=path, fmt=fmt, obj=obj)
    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / (path.name + ".decoded.json")
        out.write_text(json.dumps(obj, default=_json_default, indent=1,
                                  ensure_ascii=False))
        res.output_path = out
        res.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()
    return res
