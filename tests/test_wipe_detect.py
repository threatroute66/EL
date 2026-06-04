"""Contract for wipe_detect: separate a targeted in-place wipe from a benign
never-written stub, deterministically, from MFT metadata.

The wiped fixture is the real rocba ``fred.rocba@outlook.com.ost`` istat:
allocated, non-resident, init_size=24973312, all-zero content. The stub
fixture is its never-synced cousin (init_size 0) — the false-positive the
detector must NOT flag.
"""
from __future__ import annotations

from el.skills.wipe_detect import (
    parse_istat, classify, is_high_value, verdict_as_evidence,
    MIN_WIPED_INIT_BYTES,
)

# --- real istat output (trimmed) of the wiped OST --------------------------
WIPED_OST_ISTAT = """\
MFT Entry Header Values:
Entry: 124086        Sequence: 5
Allocated File
Links: 2

$STANDARD_INFORMATION Attribute Values:
Created:\t2020-10-27 03:10:51 (UTC)
File Modified:\t2020-11-14 14:11:49 (UTC)

$FILE_NAME Attribute Values:
Name: FREDRO~2.OST
Name: fred.rocba@outlook.com.ost

Attributes:
Type: $STANDARD_INFORMATION (16-0)   Name: N/A   Resident   size: 72
Type: $FILE_NAME (48-3)   Name: N/A   Resident   size: 90
Type: $DATA (128-4)   Name: N/A   Non-Resident   size: 33497088  init_size: 24973312
"""

# never-synced preallocated cache: present + allocated but init_size 0
STUB_ISTAT = """\
Allocated File
$FILE_NAME Attribute Values:
Name: fresh.ost
Attributes:
Type: $DATA (128-4)   Name: N/A   Non-Resident   size: 262144  init_size: 0
"""

# classic deletion: entry no longer allocated, $DATA still has runs
DELETED_ISTAT = """\
Not Allocated File
$FILE_NAME Attribute Values:
Name: secrets.docx
Attributes:
Type: $DATA (128-4)   Name: N/A   Non-Resident   size: 81920  init_size: 81920
"""

# healthy file with content present
INTACT_ISTAT = """\
Allocated File
$FILE_NAME Attribute Values:
Name: report.pst
Attributes:
Type: $DATA (128-4)   Name: N/A   Non-Resident   size: 1048576  init_size: 1048576
"""


def test_parse_extracts_data_attribute_and_names():
    rec = parse_istat(WIPED_OST_ISTAT)
    assert rec.allocated is True
    assert rec.non_resident is True
    assert rec.data_size == 33497088
    assert rec.init_size == 24973312
    assert "fred.rocba@outlook.com.ost" in rec.names


def test_parse_marks_deleted_entry_unallocated():
    rec = parse_istat(DELETED_ISTAT)
    assert rec.allocated is False
    assert rec.data_size == 81920


def test_wiped_in_place_is_high_confidence():
    rec = parse_istat(WIPED_OST_ISTAT)
    v = classify(rec, content_zero=True,
                 relpath="Users/fredr/.../fred.rocba@outlook.com.ost",
                 inode="124086")
    assert v.status == "wiped_in_place"
    assert v.confidence == "high"
    assert v.is_wipe
    assert "H_ANTI_FORENSICS" in v.hypotheses
    assert ("T1485", "Data Destruction") in v.attack_techniques


def test_never_written_stub_not_flagged():
    """The load-bearing false-positive guard: init_size=0 + zero content is a
    preallocated stub, NOT a wipe."""
    rec = parse_istat(STUB_ISTAT)
    v = classify(rec, content_zero=True, relpath="fresh.ost")
    assert v.status == "empty_stub"
    assert not v.is_wipe
    assert v.confidence == "insufficient"


def test_zero_content_below_threshold_not_wiped():
    rec = parse_istat(STUB_ISTAT)
    rec.init_size = MIN_WIPED_INIT_BYTES - 1
    v = classify(rec, content_zero=True, relpath="tiny.bin")
    assert not v.is_wipe


def test_deleted_recoverable_is_medium():
    rec = parse_istat(DELETED_ISTAT)
    v = classify(rec, content_zero=None, relpath="secrets.docx")
    assert v.status == "deleted_recoverable"
    assert v.confidence == "medium"
    assert v.is_wipe


def test_intact_file_not_flagged():
    rec = parse_istat(INTACT_ISTAT)
    v = classify(rec, content_zero=False, relpath="report.pst")
    assert v.status == "intact"
    assert not v.is_wipe


def test_high_value_targeting():
    assert is_high_value("Users/fredr/AppData/Local/Microsoft/Outlook/x.ost")
    assert is_high_value("Windows/System32/winevt/Logs/Security.evtx")
    assert is_high_value("Users/fredr/NTUSER.DAT")
    assert not is_high_value("Users/fredr/Pictures/cat.jpg")


def test_verdict_evidence_satisfies_contract():
    rec = parse_istat(WIPED_OST_ISTAT)
    v = classify(rec, content_zero=True, relpath="x.ost", inode="124086")
    ev = verdict_as_evidence(v, image="/cases/x/disk.raw")
    assert len(ev.output_sha256) == 64
    assert ev.extracted_facts["status"] == "wiped_in_place"


# iCloud/OneDrive Files-On-Demand placeholder: Reparse Point + Offline + all-zero
PLACEHOLDER_ISTAT = """\
Allocated File
$STANDARD_INFORMATION Attribute Values:
Flags: Archive, Sparse, Reparse Point, Offline
$FILE_NAME Attribute Values:
Name: EXFIL.pst
Attributes:
Type: $DATA (128-1)   Name: N/A   Non-Resident, Sparse   size: 16778240  init_size: 16778240
Type: $REPARSE_POINT (192-3)   Name: N/A   Resident   size: 208
"""


def test_cloud_placeholder_not_flagged_as_wipe():
    """Regression: an online-only iCloud/OneDrive placeholder reads all-zero with
    init_size>0 but is NOT a wipe (rocba-r2 iCloudDrive\\EXFIL.pst false positive)."""
    rec = parse_istat(PLACEHOLDER_ISTAT)
    assert rec.is_placeholder is True
    v = classify(rec, content_zero=True, relpath="iCloudDrive/EXFIL.pst")
    assert v.status == "cloud_placeholder"
    assert not v.is_wipe


def test_real_wipe_still_flagged_when_not_placeholder():
    # the genuine OST wipe has no reparse/offline flags → still wiped_in_place
    rec = parse_istat(WIPED_OST_ISTAT)
    assert rec.is_placeholder is False
    assert classify(rec, content_zero=True, relpath="x.ost").status == "wiped_in_place"
