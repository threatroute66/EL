"""Tests for the NTFS mount fallback chain in el.skills.sleuthkit.

bitlocker-r2 surfaced the failure shape: `mount -o loop,offset=`
returns rc=32 when the source file is a FUSE-exposed virtual
file (the `dislocker-file` from dislocker-fuse). The kernel loop
device can't bind to a FUSE inode — loop wants a real backing
file that supports block-style pread.

ntfs-3g, the userspace NTFS driver, doesn't go through loop —
it operates on the file directly with its own block I/O. So the
fix is "try ntfs-3g first, fall back to kernel mount only when
ntfs-3g is missing or rejects the image."

These tests stub subprocess.run to assert the right command goes
first and the fallback only fires on failure. They don't actually
mount anything — that would need root + a real NTFS image.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from el.skills.sleuthkit import SleuthkitError, mount_ntfs


def _make_completed(rc: int, stderr: str = "", stdout: str = ""):
    """subprocess.CompletedProcess shape for mocked returns."""
    cp = subprocess.CompletedProcess(args=[], returncode=rc,
                                       stdout=stdout, stderr=stderr)
    return cp


# ---------------------------------------------------------------------------
# Order — ntfs-3g first
# ---------------------------------------------------------------------------

def test_mount_ntfs_tries_ntfs_3g_first(tmp_path):
    """At offset=0 ntfs-3g is invoked directly (Stage 1) — one call, no losetup.
    Kernel mount must NOT run unless ntfs-3g fails.

    Non-zero offsets use the losetup→ntfs-3g path (Stage 2); that is covered
    by test_mount_ntfs_losetup_path below.
    """
    img = tmp_path / "img.bin"
    img.write_bytes(b"\x00" * 4096)
    mp = tmp_path / "mnt"
    calls: list[list[str]] = []
    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return _make_completed(0)
    with patch("el.skills.sleuthkit.shutil.which",
                return_value="/usr/bin/ntfs-3g"), \
         patch("el.skills.sleuthkit.subprocess.run", side_effect=fake_run):
        mount_ntfs(img, 0, mp)  # offset=0 → Stage 1: direct ntfs-3g
    assert len(calls) == 1, f"expected 1 call, got {len(calls)}"
    # The single call must be ntfs-3g, not losetup or kernel mount
    assert "ntfs-3g" in " ".join(calls[0])
    assert "losetup" not in calls[0]
    assert "mount" not in [c for c in calls[0] if c == "mount"]


def test_mount_ntfs_losetup_path(tmp_path):
    """Non-zero offset: Stage 2 runs losetup first, then ntfs-3g on the loop
    device. Kernel mount must NOT run when both succeed."""
    img = tmp_path / "img.bin"
    img.write_bytes(b"\x00" * 4096)
    mp = tmp_path / "mnt"
    calls: list[list[str]] = []
    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        # losetup --find --show returns a loop device path on stdout
        if "losetup" in cmd:
            return _make_completed(0, stdout="/dev/loop9")
        return _make_completed(0)
    with patch("el.skills.sleuthkit.shutil.which",
                return_value="/usr/bin/ntfs-3g"), \
         patch("el.skills.sleuthkit.subprocess.run", side_effect=fake_run):
        mount_ntfs(img, 128, mp)  # offset=128 → Stage 2
    assert len(calls) == 2, f"expected 2 calls (losetup + ntfs-3g), got {len(calls)}"
    assert "losetup" in calls[0]
    assert "ntfs-3g" in " ".join(calls[1])
    # No kernel mount
    assert not any("mount" == c for c in calls[1])


def test_mount_ntfs_offset_correctly_computed(tmp_path):
    """offset_sectors × sector_size = offset_bytes. Verify the
    arithmetic flows through to the losetup argument (regression
    for a future off-by-512 bug).

    With the losetup Stage-2 path, the offset appears as
    ``--offset 65536`` (two separate argv tokens) in the losetup
    command, not as ``offset=65536`` in a kernel -o string.
    """
    img = tmp_path / "img.bin"
    img.write_bytes(b"\x00" * 4096)
    mp = tmp_path / "mnt"
    seen_cmd: list[list[str]] = []
    def fake_run(cmd, **kwargs):
        seen_cmd.append(list(cmd))
        if "losetup" in cmd:
            return _make_completed(0, stdout="/dev/loop9")
        return _make_completed(0)
    with patch("el.skills.sleuthkit.shutil.which",
                return_value="/usr/bin/ntfs-3g"), \
         patch("el.skills.sleuthkit.subprocess.run", side_effect=fake_run):
        # 128 sectors × 512 bytes = 65536 bytes
        mount_ntfs(img, 128, mp, sector_size=512)
    # First call is losetup — verify the offset bytes are correct
    losetup_cmd = seen_cmd[0]
    assert "losetup" in losetup_cmd
    assert "--offset" in losetup_cmd
    offset_idx = losetup_cmd.index("--offset")
    assert losetup_cmd[offset_idx + 1] == "65536"


def test_mount_ntfs_passes_ro_norecovery(tmp_path):
    """ro + norecovery are forensic-discipline non-negotiables —
    no journal replay, no write-back. Pin them so a future option
    refactor can't drop them."""
    img = tmp_path / "img.bin"
    img.write_bytes(b"\x00" * 4096)
    mp = tmp_path / "mnt"
    seen: list[str] = []
    def fake_run(cmd, **kwargs):
        seen.append(" ".join(cmd))
        return _make_completed(0)
    with patch("el.skills.sleuthkit.shutil.which",
                return_value="/usr/bin/ntfs-3g"), \
         patch("el.skills.sleuthkit.subprocess.run", side_effect=fake_run):
        mount_ntfs(img, 0, mp)
    assert "ro" in seen[0]
    assert "norecovery" in seen[0]


# ---------------------------------------------------------------------------
# Fallback — kernel mount when ntfs-3g fails or missing
# ---------------------------------------------------------------------------

def test_falls_back_to_kernel_mount_when_ntfs_3g_fails(tmp_path):
    """ntfs-3g rc != 0 should NOT raise — fall through to kernel
    mount. Captures the operationally common case where ntfs-3g
    rejects an option (e.g. unsupported encryption flavour) but
    the kernel loop path still works."""
    img = tmp_path / "img.bin"
    img.write_bytes(b"\x00" * 4096)
    mp = tmp_path / "mnt"
    call_seq: list[str] = []
    def fake_run(cmd, **kwargs):
        binary = cmd[1] if len(cmd) > 1 else cmd[0]
        if "ntfs-3g" in binary:
            call_seq.append("ntfs-3g")
            return _make_completed(15, stderr="some weird ntfs-3g error")
        if binary == "mount":
            call_seq.append("mount")
            return _make_completed(0)
        return _make_completed(1, stderr="unexpected")
    with patch("el.skills.sleuthkit.shutil.which",
                return_value="/usr/bin/ntfs-3g"), \
         patch("el.skills.sleuthkit.subprocess.run", side_effect=fake_run):
        mount_ntfs(img, 0, mp)
    assert call_seq == ["ntfs-3g", "mount"]


def test_falls_back_when_ntfs_3g_not_on_path(tmp_path):
    """No ntfs-3g binary → skip path 1, go straight to kernel
    mount. (SIFT ships ntfs-3g but a stripped CI container might
    not.)"""
    img = tmp_path / "img.bin"
    img.write_bytes(b"\x00" * 4096)
    mp = tmp_path / "mnt"
    call_seq: list[str] = []
    def fake_run(cmd, **kwargs):
        call_seq.append(cmd[1])  # "mount" or "ntfs-3g"
        return _make_completed(0)
    with patch("el.skills.sleuthkit.shutil.which", return_value=None), \
         patch("el.skills.sleuthkit.subprocess.run", side_effect=fake_run):
        mount_ntfs(img, 0, mp)
    assert call_seq == ["mount"]


def test_raises_with_both_error_messages_when_all_paths_fail(tmp_path):
    """When ntfs-3g fails AND kernel mount fails, the raised
    SleuthkitError must carry BOTH error strings so the analyst
    can debug which stack actually rejected the image."""
    img = tmp_path / "img.bin"
    img.write_bytes(b"\x00" * 4096)
    mp = tmp_path / "mnt"
    def fake_run(cmd, **kwargs):
        binary = cmd[1] if len(cmd) > 1 else cmd[0]
        if "ntfs-3g" in binary:
            return _make_completed(
                15, stderr="ntfs-3g: not an NTFS volume")
        if binary == "mount":
            return _make_completed(
                32, stderr="mount: wrong fs type")
        return _make_completed(1)
    with patch("el.skills.sleuthkit.shutil.which",
                return_value="/usr/bin/ntfs-3g"), \
         patch("el.skills.sleuthkit.subprocess.run", side_effect=fake_run):
        with pytest.raises(SleuthkitError) as ei:
            mount_ntfs(img, 0, mp)
    msg = str(ei.value)
    assert "ntfs-3g" in msg
    assert "kernel mount" in msg or "rc=32" in msg
    # Both error strings must surface
    assert "not an NTFS volume" in msg
    assert "wrong fs type" in msg


def test_ntfs_3g_success_does_not_invoke_kernel_mount(tmp_path):
    """Belt-and-braces: when ntfs-3g succeeds the kernel mount
    must NOT run (would re-mount over a successful mount, or
    waste a sudo prompt). Regression for ordering bugs."""
    img = tmp_path / "img.bin"
    img.write_bytes(b"\x00" * 4096)
    mp = tmp_path / "mnt"
    binaries_called: list[str] = []
    def fake_run(cmd, **kwargs):
        binaries_called.append(cmd[1] if len(cmd) > 1 else cmd[0])
        return _make_completed(0)
    with patch("el.skills.sleuthkit.shutil.which",
                return_value="/usr/bin/ntfs-3g"), \
         patch("el.skills.sleuthkit.subprocess.run", side_effect=fake_run):
        mount_ntfs(img, 0, mp)
    assert "mount" not in binaries_called
