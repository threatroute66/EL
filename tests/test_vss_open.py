"""Geometry + error-classification contract for vss_diff.vss_open.

The subprocess plumbing (losetup/dmsetup) is exercised only at the agent
layer; here we lock the pure arithmetic that decides whether/how to build
the backup-VBR overlay. Numbers are the real rocba-cdrive case: a single
NTFS partition imaged 7 sectors short of its declared size, which hid all
5 shadow copies from libvshadow until repaired.
"""
from __future__ import annotations

import pytest

from el.skills.vss_diff import (
    VssError, plan_vss_repair, _is_backup_header_error,
)

# Real rocba-cdrive figures.
ROCBA_IMAGE_SIZE = 87431311360
ROCBA_TOTAL_SECTORS = 170764287          # from the primary VBR's BPB
ROCBA_BACKUP_ABS = ROCBA_TOTAL_SECTORS * 512   # = 87431314944


def _ntfs_vbr(bytes_per_sector: int = 512,
              total_sectors: int = ROCBA_TOTAL_SECTORS) -> bytes:
    b = bytearray(512)
    b[0:3] = b"\xEB\x52\x90"                 # x86 jump (is_ntfs_vbr requires 0xEB/0xE9)
    b[3:11] = b"NTFS    "
    b[0x0B:0x0D] = bytes_per_sector.to_bytes(2, "little")
    b[0x28:0x30] = total_sectors.to_bytes(8, "little")
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def test_truncated_image_plans_overlay_with_real_numbers():
    plan = plan_vss_repair(ROCBA_IMAGE_SIZE, _ntfs_vbr(), offset_bytes=0)
    assert plan.needs_repair
    assert plan.bytes_per_sector == 512
    assert plan.total_sectors == ROCBA_TOTAL_SECTORS
    assert plan.backup_vbr_abs_offset == ROCBA_BACKUP_ABS
    # device must reach one sector past the backup-VBR start
    assert plan.device_bytes_needed == ROCBA_BACKUP_ABS + 512
    # dm works in 512-byte sectors; image is exactly this many
    assert plan.image_sectors_512 == ROCBA_IMAGE_SIZE // 512 == 170764280
    # the VBR copy lands 7 sectors (3584 bytes) into the pad
    assert plan.backup_vbr_pad_offset == 3584
    # pad spans the shortfall (4096) + slack (8 sectors) → 16 sectors
    assert plan.pad_bytes == 8192
    assert plan.pad_sectors_512 == 16


def test_image_already_spanning_backup_needs_no_repair():
    full = ROCBA_BACKUP_ABS + 512        # exactly long enough to read the sector
    plan = plan_vss_repair(full, _ntfs_vbr(), offset_bytes=0)
    assert not plan.needs_repair
    assert plan.pad_bytes == 0
    assert plan.backup_vbr_pad_offset == -1


def test_offset_partition_shifts_backup_location():
    off = 1024 * 1024                    # volume starts 1 MiB into a whole-disk image
    plan = plan_vss_repair(ROCBA_IMAGE_SIZE + off, _ntfs_vbr(), offset_bytes=off)
    assert plan.backup_vbr_abs_offset == off + ROCBA_BACKUP_ABS
    assert plan.needs_repair               # image still ends before the shifted backup


def test_non_ntfs_vbr_rejected():
    with pytest.raises(VssError):
        plan_vss_repair(ROCBA_IMAGE_SIZE, b"\x00" * 512)


def test_implausible_bpb_rejected():
    with pytest.raises(VssError):
        plan_vss_repair(ROCBA_IMAGE_SIZE, _ntfs_vbr(bytes_per_sector=999))


def test_backup_header_error_is_recognised():
    # the exact libvshadow strings we must treat as "truncated, repair it"
    assert _is_backup_header_error(
        "unable to read backup NTFS volume header data at offset: 87431314944")
    assert _is_backup_header_error("invalid volume system signature")
    assert _is_backup_header_error(
        "libvshadow_volume_open_read_ntfs_volume_headers: unable to read NTFS volume header")


def test_unrelated_error_not_treated_as_truncation():
    # a genuine "no shadows" or tooling error must NOT trigger the overlay
    assert not _is_backup_header_error("No Volume Shadow Snapshots found.")
    assert not _is_backup_header_error("vshadowinfo not found on PATH")
