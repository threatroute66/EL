"""Tests for el.skills.dislocker — BitLocker volume decryption.

Two layers:

  1. Pure-function helpers — header signature detection, metadata
     parsing regex set. Run without `dislocker` being installed by
     constructing synthetic byte streams + canned stderr blobs.

  2. Live integration smoke — only runs when both `dislocker-fuse`
     and `dislocker-metadata` are on PATH AND a real BitLocker
     image is available at /mnt/hgfs/hackathon/bitlocker. Skipped
     on CI / dev hosts that don't have the image staged.

Live tests deliberately exercise the FULL pipeline (probe →
mount → read decrypted byte → umount) against the operator's
hand-built image to catch any breakage in the subprocess plumbing
or the regex set that wouldn't show up on synthetic inputs.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from el.skills import dislocker


_REAL_IMAGE = Path("/mnt/hgfs/hackathon/bitlocker")
_REAL_KEY = "547657-457149-524821-193105-097801-509685-498465-216876"

_HAS_DISLOCKER = (shutil.which("dislocker-fuse") is not None
                   and shutil.which("dislocker-metadata") is not None)
_HAS_REAL_IMAGE = _REAL_IMAGE.exists() and _REAL_IMAGE.stat().st_size > 0


# ---------------------------------------------------------------------------
# is_bitlocker_signature — pure byte-level check, no binary needed
# ---------------------------------------------------------------------------

def test_is_bitlocker_signature_detects_fve(tmp_path):
    """The `-FVE-FS-` magic sits at file offset 0x03 (after the
    3-byte JMP). Any volume with that signature must be flagged."""
    p = tmp_path / "fake_bl.bin"
    p.write_bytes(b"\xeb\x52\x90-FVE-FS-" + b"\x00" * 100)
    assert dislocker.is_bitlocker_signature(p)


def test_is_bitlocker_signature_rejects_non_bitlocker(tmp_path):
    """NTFS volume header: jmp + 'NTFS    '. Must NOT trigger."""
    p = tmp_path / "fake_ntfs.bin"
    p.write_bytes(b"\xeb\x52\x90NTFS    " + b"\x00" * 100)
    assert not dislocker.is_bitlocker_signature(p)


def test_is_bitlocker_signature_rejects_missing_file(tmp_path):
    assert not dislocker.is_bitlocker_signature(tmp_path / "absent")


def test_is_bitlocker_signature_rejects_too_short(tmp_path):
    """Files shorter than 11 bytes can't carry the signature —
    handle gracefully."""
    p = tmp_path / "tiny.bin"
    p.write_bytes(b"\xeb\x52")
    assert not dislocker.is_bitlocker_signature(p)


# ---------------------------------------------------------------------------
# Metadata regex set — drive synthetic stderr through the parser
# ---------------------------------------------------------------------------

# Truncated but representative `dislocker-metadata` stderr, capturing
# every line the parser regex set looks at. Modeled on real output
# from the operator's image.
_FAKE_STDERR = """\
Mon May 18 18:53:35 2026 [INFO] dislocker by Romain Coltel, v0.7.2 (compiled for Linux/x86_64)
Mon May 18 18:53:35 2026 [INFO] Volume GUID (INFORMATION OFFSET) supported
Mon May 18 18:53:35 2026 [INFO] BitLocker metadata found and parsed.
Mon May 18 18:53:35 2026 [INFO] =====[ Volume header information ]=====
Mon May 18 18:53:35 2026 [INFO]   Signature: '-FVE-FS-'
Mon May 18 18:53:35 2026 [INFO]   Sector size: 0x0200 (512) bytes
Mon May 18 18:53:35 2026 [INFO]   Volume GUID: '4967D63B-2E29-4AD8-8399-F6A339E3D001'
Mon May 18 18:53:35 2026 [INFO] =====================[ BitLocker information structure ]=====================
Mon May 18 18:53:35 2026 [INFO]   Signature: '-FVE-FS-'
Mon May 18 18:53:35 2026 [INFO]   Current state: ENCRYPTED (4)
Mon May 18 18:53:35 2026 [INFO]   Encrypted volume size: 4294966784 bytes (0xfffffe00), ~4095 MB
Mon May 18 18:53:35 2026 [INFO]     Dataset GUID: 'F0EA764F-08FF-4198-91DC-60F78E86D881'
Mon May 18 18:53:35 2026 [INFO]     Encryption Type: AES-128-DIFFUSER (0x8000)
Mon May 18 18:53:35 2026 [INFO] =======[ Datum n°3 information ]=======
Mon May 18 18:53:35 2026 [INFO]    `--> ENTRY TYPE VMK
Mon May 18 18:53:35 2026 [INFO] Recovery Key GUID: 'AEF79D3D-9AD5-4CB3-8FDB-CCBFEB966F27'
Mon May 18 18:53:35 2026 [INFO] =======[ Datum n°4 information ]=======
Mon May 18 18:53:35 2026 [INFO]    `--> ENTRY TYPE VMK
Mon May 18 18:53:35 2026 [INFO] Recovery Key GUID: '51136D59-2C40-4B1C-8AD6-CFE89FD69D65'
"""


def _build_md_from_text(text: str, tmp_path: Path) -> dislocker.DislockerMetadata:
    """Run the parser regex set against synthetic text by writing
    the text to a file and constructing a DislockerMetadata via the
    same code path probe_metadata uses for the parse portion. We
    don't actually invoke dislocker-metadata so this works on hosts
    without the binary installed."""
    stdout_path = tmp_path / "probe.stdout"
    stdout_path.write_text(text)
    md = dislocker.DislockerMetadata(rc=0, raw_stdout_path=stdout_path)
    # Replicate the parser block from probe_metadata. We could
    # refactor that into a separate function and call directly, but
    # this keeps the test self-contained.
    if vm := dislocker._RE_VERSION.search(text):
        md.version_line = vm.group(1)
    if vm := dislocker._RE_VOLUME_GUID.search(text):
        md.volume_guid = vm.group(1)
    if vm := dislocker._RE_DATASET_GUID.search(text):
        md.dataset_guid = vm.group(1)
    if vm := dislocker._RE_ENC_TYPE.search(text):
        md.encryption_type = vm.group(1)
    if vm := dislocker._RE_STATE.search(text):
        md.state = vm.group(1)
    if vm := dislocker._RE_SECTOR_SIZE.search(text):
        md.sector_size = int(vm.group(1))
    if vm := dislocker._RE_VOLUME_SIZE.search(text):
        md.volume_size = int(vm.group(1))
    md.recovery_key_guids = sorted(set(dislocker._RE_REC_KEY_GUID.findall(text)))
    if "-FVE-FS-" in text:
        md.signature = "-FVE-FS-"
    return md


def test_parse_extracts_volume_guid(tmp_path):
    md = _build_md_from_text(_FAKE_STDERR, tmp_path)
    assert md.volume_guid == "4967D63B-2E29-4AD8-8399-F6A339E3D001"


def test_parse_extracts_dataset_guid(tmp_path):
    md = _build_md_from_text(_FAKE_STDERR, tmp_path)
    assert md.dataset_guid == "F0EA764F-08FF-4198-91DC-60F78E86D881"


def test_parse_extracts_encryption_type(tmp_path):
    md = _build_md_from_text(_FAKE_STDERR, tmp_path)
    assert md.encryption_type == "AES-128-DIFFUSER"


def test_parse_extracts_state(tmp_path):
    md = _build_md_from_text(_FAKE_STDERR, tmp_path)
    assert md.state == "ENCRYPTED"


def test_parse_extracts_sector_size(tmp_path):
    md = _build_md_from_text(_FAKE_STDERR, tmp_path)
    assert md.sector_size == 512


def test_parse_extracts_volume_size(tmp_path):
    md = _build_md_from_text(_FAKE_STDERR, tmp_path)
    assert md.volume_size == 4294966784


def test_parse_extracts_version(tmp_path):
    md = _build_md_from_text(_FAKE_STDERR, tmp_path)
    assert md.version_line == "v0.7.2"


def test_parse_extracts_all_recovery_key_guids(tmp_path):
    """Multiple Recovery Key GUIDs (one per protector) — all must
    survive deduplication into the sorted list."""
    md = _build_md_from_text(_FAKE_STDERR, tmp_path)
    assert md.recovery_key_guids == [
        "51136D59-2C40-4B1C-8AD6-CFE89FD69D65",
        "AEF79D3D-9AD5-4CB3-8FDB-CCBFEB966F27",
    ]


def test_parse_dedupes_repeated_guids(tmp_path):
    """A protector GUID appearing twice in stderr (Datum reference +
    matching VMK header) collapses to one entry. Real dislocker
    output prints the GUID once per Datum but defensively pin the
    dedup."""
    text = (_FAKE_STDERR
            + "  Recovery Key GUID: '51136D59-2C40-4B1C-8AD6-CFE89FD69D65'\n")
    md = _build_md_from_text(text, tmp_path)
    assert md.recovery_key_guids.count(
        "51136D59-2C40-4B1C-8AD6-CFE89FD69D65") == 1


def test_parse_handles_xts_aes(tmp_path):
    """Modern Windows (1511+) uses XTS-AES-128 / XTS-AES-256 instead
    of AES-128-DIFFUSER. Regex must capture those too."""
    text = _FAKE_STDERR.replace(
        "AES-128-DIFFUSER (0x8000)", "AES-XTS-128 (0x8004)")
    md = _build_md_from_text(text, tmp_path)
    assert md.encryption_type == "AES-XTS-128"


def test_parse_handles_decrypted_state(tmp_path):
    """A volume in the middle of decrypting / re-encrypting shows
    a different state. Regex must capture all caps + underscores."""
    text = _FAKE_STDERR.replace(
        "Current state: ENCRYPTED (4)",
        "Current state: SWITCH_ENCRYPTION_PAUSED (3)")
    md = _build_md_from_text(text, tmp_path)
    assert md.state == "SWITCH_ENCRYPTION_PAUSED"


def test_parse_empty_text_returns_empty_metadata(tmp_path):
    md = _build_md_from_text("", tmp_path)
    assert md.volume_guid == ""
    assert md.recovery_key_guids == []
    assert md.signature == ""


# ---------------------------------------------------------------------------
# Evidence shaping — credentials never appear in extracted_facts
# ---------------------------------------------------------------------------

def test_dislocker_mount_evidence_never_includes_password(tmp_path):
    """The DislockerMount.as_evidence() output is THE artifact that
    gets stored in the case ledger forever. It MUST NOT contain the
    recovery password — only a sha256 digest of it. Regression for
    any future change that accidentally serialises the raw key."""
    fake_decrypted = tmp_path / "dislocker-file"
    fake_decrypted.write_bytes(b"NTFS    " + b"\x00" * 1000)
    secret = "547657-457149-524821-193105-097801-509685-498465-216876"
    import hashlib
    digest = hashlib.sha256(secret.encode()).hexdigest()
    m = dislocker.DislockerMount(
        image_path=tmp_path / "image.bin",
        mount_point=tmp_path,
        decrypted_file=fake_decrypted,
        command=["dislocker-fuse", "-V", "image.bin",
                  f"-p{secret}", str(tmp_path)],
        stderr_path=tmp_path / "stderr.log",
        used_protector_kind="recovery_key",
        used_protector_digest=digest,
    )
    ev = m.as_evidence()
    serialised = repr(ev.extracted_facts)
    # The raw password MUST NOT appear in extracted_facts
    assert secret not in serialised
    # The digest MUST appear (auditability — case proves which key
    # was used without exposing the key)
    assert digest in serialised


def test_mount_requires_exactly_one_credential(tmp_path):
    """`mount` with zero or multiple credentials is a programmer
    bug — must raise immediately, not silently fall back."""
    img = tmp_path / "image.bin"
    img.write_bytes(b"\xeb\x52\x90-FVE-FS-" + b"\x00" * 1000)
    mp = tmp_path / "mnt"
    with pytest.raises(dislocker.DislockerError):
        dislocker.mount(img, mp)  # no credentials
    with pytest.raises(dislocker.DislockerError):
        dislocker.mount(img, mp,
                          recovery_password="x",
                          user_password="y")  # two credentials


# ---------------------------------------------------------------------------
# Live integration — skipped without dislocker AND the real image
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not (_HAS_DISLOCKER and _HAS_REAL_IMAGE),
                     reason="dislocker not installed or real image absent")
def test_live_probe_extracts_real_metadata(tmp_path):
    """Probe the actual operator-supplied BitLocker image. Pins the
    full plumbing (subprocess + stderr capture + regex parse) against
    real dislocker output, not synthetic. Will catch regex drift if
    a future dislocker release reshapes its output."""
    md = dislocker.probe_metadata(_REAL_IMAGE, tmp_path, timeout=60)
    assert md.signature == "-FVE-FS-"
    assert md.volume_guid == "4967D63B-2E29-4AD8-8399-F6A339E3D001"
    assert md.dataset_guid == "F0EA764F-08FF-4198-91DC-60F78E86D881"
    assert md.encryption_type == "AES-128-DIFFUSER"
    assert md.state == "ENCRYPTED"
    assert md.sector_size == 512
    assert md.volume_size == 4294966784
    assert "51136D59-2C40-4B1C-8AD6-CFE89FD69D65" in md.recovery_key_guids


@pytest.mark.skipif(not (_HAS_DISLOCKER and _HAS_REAL_IMAGE),
                     reason="dislocker not installed or real image absent")
def test_live_mount_unlock_and_umount(tmp_path):
    """Full pipeline: mount → confirm decrypted-file exists with
    NTFS header → umount cleanly. Validates the recovery-key path
    end-to-end. Uses /tmp for the mount point so we don't disturb
    the test workspace (FUSE mounts can't be cleaned by rmtree)."""
    mp = Path("/tmp/el-dislocker-test-mount")
    if mp.exists():
        dislocker.umount(mp)  # leftover from prior failure
    mp.mkdir(parents=True, exist_ok=True)
    try:
        m = dislocker.mount(_REAL_IMAGE, mp,
                              recovery_password=_REAL_KEY,
                              stderr_out=tmp_path / "stderr.log",
                              timeout=60)
        assert m.decrypted_file.exists()
        assert m.used_protector_kind == "recovery_key"
        # First 8 bytes after the JMP should be "NTFS    "
        head = m.decrypted_file.open("rb").read(11)
        assert head[3:11] == b"NTFS    "
    finally:
        assert dislocker.umount(mp)


@pytest.mark.skipif(not (_HAS_DISLOCKER and _HAS_REAL_IMAGE),
                     reason="dislocker not installed or real image absent")
def test_live_mount_with_wrong_key_raises(tmp_path):
    """Wrong recovery key must surface a DislockerError, not a
    silent rc=0 with a corrupt mount."""
    mp = Path("/tmp/el-dislocker-test-bad-key")
    if mp.exists():
        dislocker.umount(mp)
    mp.mkdir(parents=True, exist_ok=True)
    try:
        with pytest.raises(dislocker.DislockerError):
            dislocker.mount(_REAL_IMAGE, mp,
                              recovery_password=
                              "000000-000000-000000-000000-"
                              "000000-000000-000000-000000",
                              stderr_out=tmp_path / "stderr.log",
                              timeout=60)
    finally:
        dislocker.umount(mp)
