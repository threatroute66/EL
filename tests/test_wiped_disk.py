"""Contract tests for the wiped-disk recovery + detection feature.

Grounded in the CIRCL "Recovering data from a wiped disk" exercise: an insider
interrupted while wiping his disk zeroed the protective MBR + primary GPT, but
the backup GPT survived (mmls recovers from it silently). Covers:
  * gpt_state — interrupted-wipe vs full-wipe vs healthy classification
  * luks      — LUKS1/LUKS2 header detection (version/uuid/cipher)
  * ntfs_vbr  — NTFS backup-VBR detection + read-only splice reconstruction
  * triage    — wiped primary GPT + backup → "raw-disk (GPT-damaged)" routing
  * ACH       — H_INSIDER_DEVICE_DESTRUCTION lift + benign refute + no
                over-trigger on benign "partition table parsed" findings
"""
from __future__ import annotations

import struct
import zlib

from el.skills import gpt_state, luks, ntfs_vbr
from el.agents.triage import _detect_raw_disk
from el.intel.ach import score_findings
from el.schemas.finding import EvidenceItem, Finding

SS = 512


# ---------------------------------------------------------------------------
# helpers — synthetic disk structures
# ---------------------------------------------------------------------------
def _gpt_header(my_lba: int = 1) -> bytes:
    """Minimal CRC-valid 512B GPT header sector."""
    hdr = bytearray(512)
    hdr[0:8] = b"EFI PART"
    hdr[8:12] = struct.pack("<I", 0x00010000)        # revision 1.0
    hdr[12:16] = struct.pack("<I", 92)               # header size
    hdr[24:32] = struct.pack("<Q", my_lba)           # MyLBA
    hdr[40:48] = struct.pack("<Q", 2)                # FirstUsableLBA
    crc = zlib.crc32(bytes(hdr[:92]) ) & 0xFFFFFFFF
    # recompute properly with CRC field zeroed (already zero in [16:20])
    hdr[16:20] = struct.pack("<I", crc)
    return bytes(hdr)


def _protective_mbr() -> bytes:
    mbr = bytearray(512)
    mbr[446 + 4] = 0xEE                               # protective type
    mbr[446 + 8:446 + 12] = struct.pack("<I", 1)      # LBA start
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr)


def _ntfs_vbr_sector() -> bytes:
    s = bytearray(512)
    s[0:3] = bytes([0xEB, 0x52, 0x90])
    s[3:11] = b"NTFS    "
    s[510:512] = b"\x55\xaa"
    return bytes(s)


def _write_image(path, *, sectors=64, mbr=None, primary=None, entries=None,
                 backup=None, fill=b"\x00"):
    buf = bytearray(fill * (sectors * SS) if len(fill) == 1 else fill)
    buf = bytearray(b"\x00" * (sectors * SS))
    if mbr is not None:
        buf[0:512] = mbr
    if primary is not None:
        buf[SS:SS * 2] = primary
    if entries is not None:
        buf[SS * 2:SS * 3] = entries
    if backup is not None:
        buf[(sectors - 1) * SS:sectors * SS] = backup
    path.write_bytes(bytes(buf))
    return path


# ---------------------------------------------------------------------------
# gpt_state
# ---------------------------------------------------------------------------
def test_interrupted_wipe_detected(tmp_path):
    img = _write_image(tmp_path / "wiped.raw",
                       backup=_gpt_header(my_lba=63))   # only backup survives
    st = gpt_state.inspect(img, SS)
    assert st.primary_gpt_status == "wiped"
    assert st.protective_mbr_status == "wiped"
    assert st.backup_gpt_status == "ok"
    assert st.interrupted_wipe and not st.full_wipe
    assert st.front_zero_sectors >= 3


def test_full_wipe_detected(tmp_path):
    img = _write_image(tmp_path / "full.raw")           # everything zero
    st = gpt_state.inspect(img, SS)
    assert st.primary_gpt_status == "wiped"
    assert st.backup_gpt_status == "absent"
    assert st.full_wipe and not st.interrupted_wipe


def test_healthy_gpt_not_flagged(tmp_path):
    img = _write_image(tmp_path / "ok.raw", mbr=_protective_mbr(),
                       primary=_gpt_header(), entries=b"\x11" * 512,
                       backup=_gpt_header(my_lba=63))
    st = gpt_state.inspect(img, SS)
    assert st.primary_gpt_status == "ok"
    assert st.primary_entries_status == "ok"
    assert not st.interrupted_wipe and not st.full_wipe


# ---------------------------------------------------------------------------
# luks
# ---------------------------------------------------------------------------
def test_luks2_detect(tmp_path):
    hdr = bytearray(512)
    hdr[0:6] = b"LUKS\xba\xbe"
    hdr[6:8] = struct.pack(">H", 2)
    hdr[168:204] = b"7a35ff77-7d8a-45d4-bc7b-84a94d21802e"
    img = tmp_path / "luks2.raw"
    img.write_bytes(b"\x00" * 4096 + bytes(hdr))
    info = luks.detect(img, 4096)
    assert info is not None and info.version == 2
    assert info.uuid == "7a35ff77-7d8a-45d4-bc7b-84a94d21802e"


def test_luks1_detect_carries_cipher(tmp_path):
    hdr = bytearray(512)
    hdr[0:6] = b"LUKS\xba\xbe"
    hdr[6:8] = struct.pack(">H", 1)
    hdr[8:40] = b"aes".ljust(32, b"\x00")
    hdr[40:72] = b"xts-plain64".ljust(32, b"\x00")
    hdr[72:104] = b"sha256".ljust(32, b"\x00")
    img = tmp_path / "luks1.raw"
    img.write_bytes(bytes(hdr))
    info = luks.detect(img, 0)
    assert info.version == 1 and info.cipher == "aes-xts-plain64"
    assert info.hash_spec == "sha256"


def test_non_luks_returns_none(tmp_path):
    img = tmp_path / "z.raw"
    img.write_bytes(b"\x00" * 1024)
    assert luks.detect(img, 0) is None


# ---------------------------------------------------------------------------
# ntfs_vbr
# ---------------------------------------------------------------------------
def test_is_ntfs_vbr():
    assert ntfs_vbr.is_ntfs_vbr(_ntfs_vbr_sector())
    assert not ntfs_vbr.is_ntfs_vbr(b"\x00" * 512)


def test_find_and_recover_backup_vbr(tmp_path):
    # partition: sectors 4..19 (16 sectors). primary VBR (sector 4) wiped,
    # backup VBR present at the last sector (19) with unique body in between.
    sectors = 24
    buf = bytearray(b"\x00" * sectors * SS)
    body_marker = b"\xAA" * SS
    buf[10 * SS:11 * SS] = body_marker             # some data mid-volume
    buf[19 * SS:20 * SS] = _ntfs_vbr_sector()      # backup VBR at volume end
    img = tmp_path / "ntfs.raw"
    img.write_bytes(bytes(buf))

    assert ntfs_vbr.find_backup_vbr(img, 4, 19, SS) == 19
    rec = ntfs_vbr.recover(img, 4, 19, tmp_path / "rec", SS)
    assert rec is not None
    derived = rec.derived_path.read_bytes()
    # recovered VBR spliced to offset 0 of the derived image
    assert ntfs_vbr.is_ntfs_vbr(derived[:512])
    assert rec.volume_bytes == (19 - 4 + 1) * SS


def test_recover_returns_none_when_no_backup_vbr(tmp_path):
    img = tmp_path / "wiped_part.raw"
    img.write_bytes(b"\x00" * 24 * SS)
    assert ntfs_vbr.recover(img, 4, 19, tmp_path / "r", SS) is None


# ---------------------------------------------------------------------------
# triage routing
# ---------------------------------------------------------------------------
def test_triage_routes_wiped_gpt(tmp_path):
    sectors = 4096          # > 1 MiB
    buf = bytearray(b"\x00" * sectors * SS)
    buf[(sectors - 1) * SS:(sectors - 1) * SS + 8] = b"EFI PART"
    img = tmp_path / "raw_wiped.img"
    img.write_bytes(bytes(buf))
    assert _detect_raw_disk(img) == "raw-disk (GPT-damaged)"


def test_triage_healthy_gpt_still_plain(tmp_path):
    sectors = 4096
    buf = bytearray(b"\x00" * sectors * SS)
    buf[512:520] = b"EFI PART"            # primary header present
    img = tmp_path / "raw_ok.img"
    img.write_bytes(bytes(buf))
    assert _detect_raw_disk(img) == "raw-disk (GPT)"


# ---------------------------------------------------------------------------
# ACH
# ---------------------------------------------------------------------------
def _ev():
    return EvidenceItem(tool="el.gpt_state", version="0", command="c",
                        output_sha256="0" * 64, output_path="/x")


def _score(findings, hyp):
    ranked, _ = score_findings(findings)
    row = next((r for r in ranked if r.hyp_id == hyp), None)
    return row.score if row else 0


def test_device_destruction_lifts_and_refutes_benign():
    wipe = Finding(case_id="c", agent="disk_forensicator", confidence="high",
                   claim="Interrupted disk wipe detected — primary GPT destroyed "
                         "but backup GPT intact.",
                   evidence=[_ev()],
                   hypotheses_supported=["H_ANTI_FORENSICS",
                                         "H_INSIDER_DEVICE_DESTRUCTION"])
    assert _score([wipe], "H_INSIDER_DEVICE_DESTRUCTION") >= 5  # +3 tag +2 phrase
    # refutes the null
    clean = Finding(case_id="c", agent="a", confidence="high",
                    claim="no non-baseline items observed; all signatures verified",
                    evidence=[_ev()])
    b0 = _score([clean], "H_BENIGN_NO_INCIDENT")
    b1 = _score([clean, wipe], "H_BENIGN_NO_INCIDENT")
    assert b1 < b0


def test_benign_partition_parse_does_not_lift_destruction():
    """The routine 'Partition table parsed: N usable partition(s)' finding
    must NOT lift device-destruction (the phrase guard is specific)."""
    parsed = Finding(case_id="c", agent="disk_forensicator", confidence="high",
                     claim="Partition table parsed: 2 usable partition(s)",
                     evidence=[_ev()], hypotheses_supported=["H_DISK_IMAGE"])
    assert _score([parsed], "H_INSIDER_DEVICE_DESTRUCTION") == 0


def test_generic_intrusion_does_not_lift_destruction():
    f = Finding(case_id="c", agent="a", confidence="high",
                claim="Process injection into lsass",
                evidence=[_ev()],
                hypotheses_supported=["H_PROCESS_INJECTION", "H_CREDENTIAL_ACCESS"])
    assert _score([f], "H_INSIDER_DEVICE_DESTRUCTION") == 0
