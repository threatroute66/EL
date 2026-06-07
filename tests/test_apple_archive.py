"""Apple archive decoder tests — NSKeyedArchiver graph + iMessage typedstream.

Synthetic archives are hand-built (no Foundation needed); real-data smokes
(skip-gated on the iPhone image) prove it on an actual iMessage attributedBody
and an Instagram NSKeyedArchiver plist.
"""
import plistlib
from datetime import datetime
from pathlib import Path

import pytest

from el.skills import apple_archive as aa

UID = plistlib.UID


def _archive(objects: list) -> bytes:
    arch = {"$archiver": "NSKeyedArchiver", "$version": 100000,
            "$top": {"root": UID(1)}, "$objects": objects}
    return plistlib.dumps(arch, fmt=plistlib.FMT_BINARY)


# --- NSKeyedArchiver --------------------------------------------------------

def test_unarchive_simple_dict():
    data = _archive([
        "$null",
        {"$class": UID(4), "NS.keys": [UID(2)], "NS.objects": [UID(3)]},
        "greeting", "hello",
        {"$classname": "NSDictionary", "$classes": ["NSDictionary", "NSObject"]},
    ])
    assert aa.unarchive(data) == {"greeting": "hello"}


def test_unarchive_array_date_data_null():
    data = _archive([
        "$null",
        {"$class": UID(2), "NS.objects": [UID(3), UID(4), UID(5), UID(6)]},
        {"$classname": "NSArray", "$classes": ["NSArray", "NSObject"]},
        "item",
        {"$class": UID(7), "NS.time": 60.0},                 # NSDate -> +60s
        {"$class": UID(8), "NS.data": b"\x01\x02\x03"},       # NSData
        {"$class": UID(9)},                                   # NSNull
        {"$classname": "NSDate"}, {"$classname": "NSData"},
        {"$classname": "NSNull"},
    ])
    out = aa.unarchive(data)
    assert out[0] == "item"
    assert out[1] == datetime(2001, 1, 1, 0, 1, 0, tzinfo=out[1].tzinfo)
    assert out[2] == b"\x01\x02\x03"
    assert out[3] is None


def test_unarchive_handles_cycle():
    # An array whose only element is itself.
    data = _archive([
        "$null",
        {"$class": UID(2), "NS.objects": [UID(1)]},
        {"$classname": "NSArray", "$classes": ["NSArray", "NSObject"]},
    ])
    out = aa.unarchive(data)
    assert isinstance(out, list) and out[0] is out      # same object (cycle)


def test_unarchive_unknown_class_keeps_fields():
    data = _archive([
        "$null",
        {"$class": UID(2), "score": 0.9, "name": UID(3)},
        {"$classname": "IGCustomThing", "$classes": ["IGCustomThing"]},
        "neo",
    ])
    out = aa.unarchive(data)
    assert out["$class"] == "IGCustomThing"
    assert out["score"] == 0.9 and out["name"] == "neo"


def test_unarchive_rejects_non_archive():
    with pytest.raises(aa.AppleArchiveError):
        aa.unarchive(plistlib.dumps({"hello": "world"}))


def test_detection():
    arch = _archive(["$null", {"$class": UID(2), "NS.objects": []},
                     {"$classname": "NSArray"}])
    assert aa.is_nskeyedarchiver(arch)
    assert not aa.is_typedstream(arch)
    assert aa.is_typedstream(b"\x04\x0bstreamtyped\x81\xe8\x03")


# --- typedstream (iMessage attributedBody) ----------------------------------

def _typedstream_text(text: bytes) -> bytes:
    body = text
    if len(body) < 128:
        lenpart = bytes([len(body)])
    else:
        lenpart = b"\x81" + len(body).to_bytes(2, "little")
    return (b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84"
            b"NSMutableAttributedString\x00\x84\x84\x12NSAttributedString"
            b"\x00\x84\x84\x08NSObject\x00\x85\x92\x84\x84\x84"
            b"NSString\x01\x94\x84\x01\x2b" + lenpart + body)


def test_imessage_text_short():
    blob = _typedstream_text(b"Hello, Daniel!")
    assert aa.imessage_text(blob) == "Hello, Daniel!"


def test_imessage_text_long_length_prefix():
    text = b"X" * 300
    blob = _typedstream_text(text)
    assert aa.imessage_text(blob) == "X" * 300


def test_imessage_text_fallback():
    # No clean NSString marker -> longest printable run.
    blob = b"\x04\x0bstreamtyped\x00\x00the actual message body here\x00NSDictionary"
    assert "the actual message body here" in aa.imessage_text(blob)


def test_decode_dispatch_and_parse(tmp_path):
    blob = _typedstream_text(b"dispatch me")
    assert aa.decode(blob) == "dispatch me"
    p = tmp_path / "msg.typedstream"
    p.write_bytes(blob)
    res = aa.parse(p, output_dir=tmp_path / "out")
    assert res.fmt == "typedstream" and res.obj == "dispatch me"
    assert res.output_path.is_file()
    assert res.as_evidence().tool == "el.apple_archive"


# --- real-data smokes (skip-gated on the iPhone image) ----------------------

_IPHONE = Path("/media/sansforensics/images/2026_Magnet_Virtual_Summit_CTF/"
               "iPhone14Plus/00008110-0008196A2299401E_files_full")
_SMS = _IPHONE / "private/var/mobile/Library/SMS/sms.db"
_IGRANK = (_IPHONE / "private/var/mobile/Containers/Data/Application/"
           "5A92C2C1-E1D8-4943-B38A-D0A5DDFC4860/Library/Caches/79726424276/"
           "ig-ranking-data")


def _safe_is_file(p: Path) -> bool:
    try:
        return p.is_file()
    except OSError:
        return False


def _safe_is_dir(p: Path) -> bool:
    try:
        return p.is_dir()
    except OSError:
        return False


@pytest.mark.skipif(not _safe_is_file(_SMS), reason="iPhone image not mounted")
def test_real_imessage_attributedbody():
    import sqlite3
    c = sqlite3.connect(f"file:{_SMS}?immutable=1", uri=True)
    row = c.execute("SELECT attributedBody FROM message "
                    "WHERE attributedBody IS NOT NULL ORDER BY date LIMIT 1").fetchone()
    text = aa.imessage_text(row[0])
    assert "messaging" in text.lower()


@pytest.mark.skipif(not _safe_is_dir(_IGRANK), reason="iPhone image not mounted")
def test_real_nskeyedarchiver_plist():
    plist = next(_IGRANK.glob("*.plist"))
    obj = aa.unarchive(plist.read_bytes())
    assert isinstance(obj, dict) and obj.get("$class")
