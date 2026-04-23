"""LUKS unlock + mount tests.

Two layers:
  1. Fast unit tests for the error paths (no cryptsetup invocation):
     - LUKS magic detection on a fabricated header
     - mount_linux_ro correctly routes LUKS → raise-with-hint
     - mount_luks_ro validates the pass/key inputs before shelling out
  2. Real LUKS round-trip (sudo-gated): create a small LUKS container
     in a tmpfs-backed file, unlock it, write a canary file, unmount.
     Skipped when `cryptsetup` + `losetup` + sudo aren't available or
     the test isn't running with NOPASSWD sudo.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from el.skills.sleuthkit import (
    SleuthkitError, _peek_luks_magic,
    mount_linux_ro, mount_luks_ro, umount_luks,
)


# ---------------------------------------------------------------------------
# Unit tests — no external commands
# ---------------------------------------------------------------------------

def test_peek_luks_magic_recognises_v1_header(tmp_path):
    img = tmp_path / "fake.raw"
    # LUKS magic at offset 0
    img.write_bytes(b"LUKS\xba\xbe" + b"\x00" * 100)
    assert _peek_luks_magic(img, 0) is True


def test_peek_luks_magic_false_on_non_luks(tmp_path):
    img = tmp_path / "ext.raw"
    # ext superblock-ish random prefix
    img.write_bytes(b"\x00" * 1024 + b"some ext data")
    assert _peek_luks_magic(img, 0) is False


def test_peek_luks_magic_at_partition_offset(tmp_path):
    """LUKS header can live at a non-zero byte offset when the raw
    image has a partition table; verify the offset is honoured."""
    img = tmp_path / "img.raw"
    buf = bytearray(b"\x00" * (1024 * 1024))
    # Place LUKS magic at the 2048-sector (1 MiB) partition boundary
    buf[1024 * 1024 - 6:1024 * 1024] = b"LUKS\xba\xbe"
    # Actually put it at the intended offset inside the buffer
    buf[1024 * 1024:1024 * 1024 + 6] = b"LUKS\xba\xbe"
    img.write_bytes(bytes(buf))
    assert _peek_luks_magic(img, 1024 * 1024) is True
    assert _peek_luks_magic(img, 0) is False


def test_mount_linux_ro_raises_luks_hint(tmp_path):
    """A LUKS-shaped partition offered to mount_linux_ro must fail
    with a clear hint pointing at mount_luks_ro — not the kernel's
    generic `wrong fs type` error."""
    img = tmp_path / "luks.raw"
    img.write_bytes(b"LUKS\xba\xbe" + b"\x00" * 4096)
    with pytest.raises(SleuthkitError, match="LUKS"):
        mount_linux_ro(img, start_sector=0,
                       mount_point=tmp_path / "mnt")


def test_mount_luks_ro_rejects_missing_credentials(tmp_path):
    img = tmp_path / "luks.raw"
    img.write_bytes(b"LUKS\xba\xbe" + b"\x00" * 4096)
    with pytest.raises(SleuthkitError, match="passphrase .* key_file"):
        mount_luks_ro(img, start_sector=0,
                       mount_point=tmp_path / "mnt")


def test_mount_luks_ro_rejects_missing_key_file(tmp_path):
    img = tmp_path / "luks.raw"
    img.write_bytes(b"LUKS\xba\xbe" + b"\x00" * 4096)
    with pytest.raises(SleuthkitError, match="key_file not found"):
        mount_luks_ro(img, start_sector=0,
                       mount_point=tmp_path / "mnt",
                       key_file=tmp_path / "nope.key")


def test_mount_luks_ro_rejects_non_luks_image(tmp_path):
    """Even if a passphrase is given, refuse to shell out when the
    target partition doesn't carry LUKS magic — saves a pointless
    cryptsetup call."""
    img = tmp_path / "ext.raw"
    img.write_bytes(b"not luks" + b"\x00" * 4096)
    with pytest.raises(SleuthkitError, match="not a LUKS container"):
        mount_luks_ro(img, start_sector=0,
                       mount_point=tmp_path / "mnt",
                       passphrase="anything")


# ---------------------------------------------------------------------------
# End-to-end test — sudo + cryptsetup + losetup required
# ---------------------------------------------------------------------------

_NEED = ("cryptsetup", "losetup", "mkfs.ext4", "sudo")


def _have_cmds() -> bool:
    return all(shutil.which(c) for c in _NEED)


def _sudo_passwordless() -> bool:
    r = subprocess.run(["sudo", "-n", "true"],
                        capture_output=True, timeout=5)
    return r.returncode == 0


@pytest.mark.skipif(
    not (_have_cmds() and _sudo_passwordless()),
    reason="LUKS round-trip needs cryptsetup + losetup + mkfs.ext4 "
           "+ passwordless sudo")
def test_luks_roundtrip_real(tmp_path):
    """Build a 32 MiB LUKS1 container, format ext4 inside, unlock via
    mount_luks_ro, read a canary file, umount + close cleanly."""
    img = tmp_path / "luks.img"
    # 32 MiB sparse file
    with open(img, "wb") as f:
        f.truncate(32 * 1024 * 1024)
    passphrase = "correct horse battery staple"
    # Format LUKS1 (simpler + smaller than LUKS2 for small containers)
    r = subprocess.run(
        ["sudo", "cryptsetup", "luksFormat", "--type", "luks1",
         "--batch-mode", "--key-size", "256",
         "--iter-time", "100",       # keep test fast
         str(img)],
        input=(passphrase + "\n").encode(),
        capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr.decode(errors="replace")

    # Sanity — LUKS magic is at byte 0
    assert _peek_luks_magic(img, 0)

    # Open, format ext4, umount ours to set up the test source
    r = subprocess.run(
        ["sudo", "cryptsetup", "open", "--type", "luks1",
         str(img), "el_luks_test_setup"],
        input=(passphrase + "\n").encode(),
        capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    try:
        subprocess.run(
            ["sudo", "mkfs.ext4", "-q", "-F",
             "/dev/mapper/el_luks_test_setup"],
            check=True, capture_output=True, timeout=60)
        setup_mnt = tmp_path / "setup_mnt"
        setup_mnt.mkdir()
        subprocess.run(
            ["sudo", "mount", "/dev/mapper/el_luks_test_setup",
             str(setup_mnt)], check=True, timeout=30)
        subprocess.run(
            ["sudo", "tee", str(setup_mnt / "canary.txt")],
            input=b"hello from inside LUKS\n",
            check=True, capture_output=True, timeout=15)
        subprocess.run(["sudo", "umount", str(setup_mnt)],
                       check=True, timeout=30)
    finally:
        subprocess.run(
            ["sudo", "cryptsetup", "close", "el_luks_test_setup"],
            capture_output=True, timeout=30)

    # Now the real assertion: mount_luks_ro should unlock + mount
    target_mnt = tmp_path / "target_mnt"
    state = mount_luks_ro(
        img, start_sector=0,
        mount_point=target_mnt, passphrase=passphrase,
        mapper_name="el_luks_rotest")
    try:
        canary = (target_mnt / "canary.txt").read_bytes()
        assert b"hello from inside LUKS" in canary
        # Verify it's genuinely read-only — a write must fail
        with pytest.raises(OSError):
            (target_mnt / "shouldnt-write").write_bytes(b"x")
    finally:
        umount_luks(state)

    # Tear-down did its job — no stale loop / mapper references
    r = subprocess.run(["ls", "/dev/mapper/"], capture_output=True,
                        text=True)
    assert "el_luks_rotest" not in r.stdout
