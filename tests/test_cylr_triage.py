"""Tests for the CyLR triage detector.

CyLR's offline-collector zip carries a canonical marker file at
the zip root: `CyLR_Collection_Log_<YYYY-MM-DD_HH-MM-SS>.log`. The
extracted tree mirrors a Linux filesystem root (`var/log/`, `etc/`,
`home/`, `root/`), so we route to LinuxForensicatorAgent after
auto-extract — every detector that handles `linux-fs-dir` already
works on the resulting tree.

Pins:
  - canonical marker file alone triggers detection
  - Linux-FS-root layout (≥5 var/log/etc/home/root entries) also triggers
  - non-CyLR zips (no marker, no FS-root signal) are rejected
  - missing/broken zip files return False, never raise
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from el.agents.triage import TriageAgent


def _make_zip(path: Path, contents: dict[str, bytes]) -> Path:
    """Build a zip with the given path → content map."""
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in contents.items():
            zf.writestr(name, data)
    return path


# ---------------------------------------------------------------------------
# Marker-file path — canonical CyLR signature
# ---------------------------------------------------------------------------

def test_marker_file_alone_triggers_detection(tmp_path):
    """The `CyLR_Collection_Log_<TS>.log` filename at the zip root
    is CyLR's canonical signature. Detection must fire on the
    marker alone, even without FS-root entries."""
    z = _make_zip(tmp_path / "collection.zip", {
        "CyLR_Collection_Log_2026-05-19_08-21-36.log":
            b"2026-05-19T08:20:58 [info] Collection complete.",
        "some/random/file.txt": b"x",
    })
    assert TriageAgent._archive_looks_cylr(z)
    assert TriageAgent._classify_cylr_zip(z) is not None


def test_marker_file_at_root_only_not_in_subdir(tmp_path):
    """The marker MUST be at the zip root, not in a subdir. A
    `Files/CyLR_Collection_Log_*.log` (CyLR's older v1 layout
    wouldn't match — we don't claim coverage for that variant
    here) should not trigger. Pin the positive case shape so a
    future schema-change in CyLR forces a deliberate code update."""
    z = _make_zip(tmp_path / "weird.zip", {
        "Files/CyLR_Collection_Log_2026-05-19.log": b"x",
    })
    # File starts with `Files/...` not bare `CyLR_Collection_Log_`,
    # so the prefix check fails. We don't claim CyLR v1 support.
    assert not TriageAgent._archive_looks_cylr(z)


# ---------------------------------------------------------------------------
# FS-root layout path — non-marker CyLR variants
# ---------------------------------------------------------------------------

def test_linux_fs_root_layout_triggers_detection(tmp_path):
    """Even without the canonical marker, a zip carrying 5+ entries
    with Linux FS-root prefixes (var/log / etc / home / root) is
    CyLR-shaped enough to route to LinuxForensicatorAgent."""
    contents = {
        "var/log/auth.log": b"x",
        "var/log/syslog": b"x",
        "var/log/kern.log": b"x",
        "etc/passwd": b"x",
        "etc/sudoers": b"x",
        "home/alice/.bash_history": b"x",
    }
    z = _make_zip(tmp_path / "fsroot.zip", contents)
    assert TriageAgent._archive_looks_cylr(z)
    assert TriageAgent._classify_cylr_zip(z) is not None


def test_few_fs_root_entries_below_threshold_rejected(tmp_path):
    """Only 1-2 FS-root-prefixed entries is too weak a signal —
    could be a partial backup, an extraction subset, anything.
    Threshold of 5 keeps false positives down."""
    contents = {
        "var/log/auth.log": b"x",
        "etc/passwd": b"x",
        "unrelated/file.txt": b"x",
    }
    z = _make_zip(tmp_path / "weak.zip", contents)
    assert not TriageAgent._archive_looks_cylr(z)


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

def test_random_zip_rejected(tmp_path):
    """Generic application zip (Word doc, source archive, etc.)
    must NOT trigger."""
    z = _make_zip(tmp_path / "docs.zip", {
        "[Content_Types].xml": b"<xml/>",
        "word/document.xml": b"<xml/>",
        "_rels/.rels": b"<xml/>",
    })
    assert not TriageAgent._archive_looks_cylr(z)


def test_velociraptor_zip_not_misclassified_as_cylr(tmp_path):
    """Velociraptor hunt zip carries hunt_info.json + per-client
    metadata — must NOT match the CyLR detector (we route those
    to a different agent via the existing Velociraptor path)."""
    z = _make_zip(tmp_path / "hunt.zip", {
        "hunt_info.json": b"{}",
        "rubicon-C.123/client_info.json": b"{}",
        "rubicon-C.123/results/Generic.System.Pstree.json": b"{}",
    })
    assert not TriageAgent._archive_looks_cylr(z)


def test_non_zip_extension_rejected(tmp_path):
    """A .tar.gz that happens to contain CyLR-shaped names shouldn't
    trigger — different unpacker path, different detector. Detector
    requires the `.zip` extension to limit scope."""
    p = tmp_path / "fake.tar.gz"
    p.write_bytes(b"\x1f\x8b\x08")   # gzip header bytes
    assert not TriageAgent._archive_looks_cylr(p)


def test_missing_zip_returns_false(tmp_path):
    assert not TriageAgent._archive_looks_cylr(tmp_path / "absent.zip")


def test_corrupt_zip_returns_false(tmp_path):
    """A file with .zip extension but unreadable as a zip archive
    must NOT crash the detector — fall back to False."""
    p = tmp_path / "broken.zip"
    p.write_bytes(b"PK\x03\x04 broken zip data follows ...")
    assert not TriageAgent._archive_looks_cylr(p)


# ---------------------------------------------------------------------------
# Boundary
# ---------------------------------------------------------------------------

def test_exactly_5_fs_root_entries_triggers(tmp_path):
    """Pin the threshold at 5 — anything ≥5 fires."""
    contents = {f"var/log/file{i}.log": b"x" for i in range(5)}
    z = _make_zip(tmp_path / "boundary.zip", contents)
    assert TriageAgent._archive_looks_cylr(z)
    assert TriageAgent._classify_cylr_zip(z) is not None


def test_4_fs_root_entries_does_not_trigger(tmp_path):
    """One below the threshold — does NOT fire."""
    contents = {f"var/log/file{i}.log": b"x" for i in range(4)}
    z = _make_zip(tmp_path / "below.zip", contents)
    assert not TriageAgent._archive_looks_cylr(z)


# ---------------------------------------------------------------------------
# Target-OS classification (Stage 2 of the detector)
# ---------------------------------------------------------------------------

def test_classify_linux_target(tmp_path):
    """Linux-FS-root layout → classify returns "linux" so dispatch
    routes to LinuxForensicatorAgent."""
    z = _make_zip(tmp_path / "linux.zip", {
        f"var/log/auth.log{i}": b"x" for i in range(6)
    } | {"etc/passwd": b"x"})
    assert TriageAgent._classify_cylr_zip(z) == "linux"


def test_classify_windows_target(tmp_path):
    """Drive-letter-prefixed Windows layout → classify returns
    "windows" so dispatch routes to WindowsArtifactAgent. This
    is the exact shape CyLR-for-Windows produces (`C/$MFT`,
    `C/Windows/System32/...`, `C/Users/...`)."""
    contents = {
        "C/$MFT": b"x",
        "C/$LogFile": b"x",
        "C/Windows/System32/config/SAM": b"x",
        "C/Windows/System32/winevt/Logs/Security.evtx": b"x",
        "C/Users/alice/NTUSER.DAT": b"x",
        "C/ProgramData/Microsoft/Windows/Start Menu/programs.txt": b"x",
    }
    z = _make_zip(tmp_path / "windows.zip", contents)
    assert TriageAgent._classify_cylr_zip(z) == "windows"


def test_classify_macos_target(tmp_path):
    """macOS layout uses `private/var/` + `System/Library/` +
    `Library/`. Threshold of 5 entries fires the macos branch."""
    contents = {
        f"private/var/log/system.log.{i}.gz": b"x" for i in range(3)
    } | {
        "System/Library/CoreServices/SystemVersion.plist": b"x",
        "Library/Preferences/com.apple.gpu.plist": b"x",
    }
    z = _make_zip(tmp_path / "macos.zip", contents)
    assert TriageAgent._classify_cylr_zip(z) == "macos"


def test_classify_windows_other_drive_letter(tmp_path):
    """CyLR can run from any drive letter — `D/Windows/`,
    `E/$MFT` should also classify as windows."""
    contents = {
        "D/$MFT": b"x", "D/$LogFile": b"x",
        "D/Windows/System32/config/SAM": b"x",
        "D/Users/alice/NTUSER.DAT": b"x",
        "D/ProgramData/Microsoft/file.txt": b"x",
        "D/$Recycle.Bin/desktop.ini": b"x",
    }
    z = _make_zip(tmp_path / "d_drive.zip", contents)
    assert TriageAgent._classify_cylr_zip(z) == "windows"


def test_classify_picks_dominant_platform_on_mixed(tmp_path):
    """Edge case: a zip with both Linux + Windows shapes (operator
    accidentally merged collections). Highest hit-count wins so
    the dispatcher routes to the agent with the most actionable
    content."""
    contents = (
        {f"C/Windows/file{i}.txt": b"x" for i in range(10)}
        | {f"var/log/file{i}.log": b"x" for i in range(2)}
    )
    z = _make_zip(tmp_path / "mixed.zip", contents)
    assert TriageAgent._classify_cylr_zip(z) == "windows"


def test_classify_marker_only_returns_unknown(tmp_path):
    """A zip with the marker file but NO platform-shaped paths
    (a heavily filtered CyLR run) returns the "unknown" sentinel
    so dispatch can degrade to LinuxForensicator (the most
    nondestructive walker on a heterogeneous tree)."""
    contents = {
        "CyLR_Collection_Log_2026-05-19.log": b"...",
        "weird-path/file": b"x",
    }
    z = _make_zip(tmp_path / "marker_only.zip", contents)
    assert TriageAgent._classify_cylr_zip(z) == "unknown"


def test_classify_non_cylr_returns_none(tmp_path):
    z = _make_zip(tmp_path / "random.zip", {"foo": b"x", "bar": b"y"})
    assert TriageAgent._classify_cylr_zip(z) is None
