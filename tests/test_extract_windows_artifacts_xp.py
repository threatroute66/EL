"""Regression tests for extract_windows_artifacts across Windows versions.

The original implementation hardcoded Win7+ paths (Windows/ capitalisation,
Users/ profile root, winevt/Logs/*.evtx) and silently extracted zero
artifacts from any XP/2003 image. Verified against the real M57-Jean E01:
the NTFS walk saw /WINDOWS/ (uppercase) and /Documents and Settings/ — the
hardcoded Path() concatenation is case-sensitive on Linux, so every lookup
missed.

These tests build both layouts as tmp fixtures, monkeypatch _sudo_cp to do
a plain copy (no sudo in CI), and assert the right artifact classes land
in exports/.
"""
from pathlib import Path
import shutil

import pytest

from el.skills import sleuthkit as sk


@pytest.fixture(autouse=True)
def _plain_cp(monkeypatch):
    """Skip the sudo-cp path in tests. The real skill uses sudo because
    the NTFS mount is root-owned; tests operate on normal tmpfs."""
    def _cp(src, dst):
        try:
            shutil.copy2(src, dst)
            return True
        except Exception:
            return False
    monkeypatch.setattr(sk, "_sudo_cp", _cp)


def _write(path: Path, content: bytes = b"hive-bytes") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _build_xp(root: Path) -> None:
    """Windows XP / 2003 layout: WINDOWS/, system32 lowercase, classic .evt,
    Documents and Settings/ profile root."""
    win = root / "WINDOWS"
    sys32 = win / "system32"
    cfg = sys32 / "config"
    _write(cfg / "SYSTEM")
    _write(cfg / "SOFTWARE")
    _write(cfg / "SECURITY")
    _write(cfg / "SAM")
    _write(cfg / "DEFAULT")
    _write(cfg / "AppEvent.Evt")
    _write(cfg / "SecEvent.Evt")
    _write(cfg / "SysEvent.Evt")

    pf = win / "Prefetch"
    _write(pf / "CMD.EXE-1234ABCD.pf")
    _write(pf / "NOTEPAD.EXE-DEADBEEF.pf")

    docs = root / "Documents and Settings"
    _write(docs / "Administrator" / "NTUSER.DAT")
    _write(docs / "Default User" / "NTUSER.DAT")  # should be skipped
    _write(docs / "All Users" / "NTUSER.DAT")      # should be skipped


def _build_win10(root: Path) -> None:
    """Windows 10 layout: Windows/, System32, winevt/Logs/, Users/ profile
    root, Amcache.hve, SRUDB.dat."""
    win = root / "Windows"
    sys32 = win / "System32"
    cfg = sys32 / "config"
    for h in ("SYSTEM", "SOFTWARE", "SECURITY", "SAM", "DEFAULT"):
        _write(cfg / h)

    _write(win / "AppCompat" / "Programs" / "Amcache.hve")

    pf = win / "Prefetch"
    _write(pf / "NOTEPAD.EXE-ABCDEF12.pf")

    logs = sys32 / "winevt" / "Logs"
    _write(logs / "Security.evtx")
    _write(logs / "System.evtx")
    _write(logs / "Application.evtx")

    _write(sys32 / "sru" / "SRUDB.dat")

    users = root / "Users"
    _write(users / "alice" / "NTUSER.DAT")
    _write(users / "bob" / "NTUSER.DAT")
    _write(users / "Public" / "NTUSER.DAT")   # skipped


def test_xp_layout_extracts_registry_evt_prefetch_ntuser(tmp_path):
    mount = tmp_path / "mnt"
    _build_xp(mount)
    exports = tmp_path / "exports"

    out = sk.extract_windows_artifacts(mount, exports)

    assert out.get("registry_hives") == 5, out
    assert out.get("evt_files") == 3, out
    assert out.get("prefetch_files") == 2, out
    # Administrator NTUSER, skipping Default User + All Users
    assert out.get("ntuser_hives") == 1, out
    # Amcache/SRUM only exist on post-XP — must not be reported
    assert "amcache" not in out
    assert "srum" not in out
    assert "evtx_files" not in out

    assert (exports / "registry" / "SYSTEM").is_file()
    assert (exports / "evt" / "SysEvent.Evt").is_file()
    assert (exports / "registry" / "NTUSER-Administrator.DAT").is_file()


def test_win10_layout_extracts_all_modern_artifacts(tmp_path):
    mount = tmp_path / "mnt"
    _build_win10(mount)
    exports = tmp_path / "exports"

    out = sk.extract_windows_artifacts(mount, exports)

    assert out.get("registry_hives") == 5, out
    assert out.get("amcache") == 1
    assert out.get("prefetch_files") == 1
    assert out.get("evtx_files") == 3
    assert out.get("srum") == 1
    assert out.get("ntuser_hives") == 2, out  # alice + bob (Public skipped)
    # No .evt on modern Windows
    assert "evt_files" not in out


def test_case_insensitive_resolution_handles_mixed_casing(tmp_path):
    """Simulate a weirdly cased NTFS filesystem (e.g. `WiNdOwS/SyStEm32/`) —
    still must resolve. Confirms we're not hardcoding a casing."""
    mount = tmp_path / "mnt"
    win = mount / "WiNdOwS"
    sys32 = win / "SyStEm32"
    cfg = sys32 / "CoNfIg"
    _write(cfg / "SYSTEM")
    _write(cfg / "SOFTWARE")

    out = sk.extract_windows_artifacts(mount, tmp_path / "exports")
    assert out.get("registry_hives") == 2


def test_empty_mount_returns_empty_dict(tmp_path):
    out = sk.extract_windows_artifacts(tmp_path / "mnt-empty", tmp_path / "exports")
    assert out == {}


def test_partial_layout_only_reports_what_exists(tmp_path):
    """Missing artifact classes must not raise or emit zero counts — they
    should simply be absent from the returned dict."""
    mount = tmp_path / "mnt"
    _write(mount / "Windows" / "System32" / "config" / "SYSTEM")

    out = sk.extract_windows_artifacts(mount, tmp_path / "exports")
    assert out == {"registry_hives": 1}


def test_dirty_hive_log1_log2_extracted_alongside_hive(tmp_path):
    """SRL-2018 wkstn-01 + base-file were live-imaged and both tripped
    EZ-Tools 'hive is dirty and no transaction logs were found — Aborting!'
    because extract_windows_artifacts didn't copy the LOG1/LOG2 companion
    files. This test locks in that fix: for every hive the extractor
    emits, any sibling .LOG / .LOG1 / .LOG2 must travel with it."""
    mount = tmp_path / "mnt"
    win = mount / "Windows"
    cfg = win / "System32" / "config"
    # Modern-Windows dual-log (LOG1/LOG2) dirty-hive shape
    for h in ("SYSTEM", "SOFTWARE", "SAM"):
        _write(cfg / h)
        _write(cfg / f"{h}.LOG1", b"log1-data")
        _write(cfg / f"{h}.LOG2", b"log2-data")
    # Amcache with LOG1 only (observed variant)
    _write(win / "AppCompat" / "Programs" / "Amcache.hve")
    _write(win / "AppCompat" / "Programs" / "Amcache.hve.LOG1", b"am-log")
    # Per-user NTUSER.DAT with LOG1/LOG2 — rename must follow
    users = mount / "Users"
    _write(users / "alice" / "NTUSER.DAT")
    _write(users / "alice" / "NTUSER.DAT.LOG1", b"alice-log1")
    _write(users / "alice" / "NTUSER.DAT.LOG2", b"alice-log2")

    exports = tmp_path / "exports"
    out = sk.extract_windows_artifacts(mount, exports)

    # Hive-count unchanged — LOGs don't inflate the count
    assert out.get("registry_hives") == 3, out
    assert out.get("amcache") == 1, out
    assert out.get("ntuser_hives") == 1, out

    reg = exports / "registry"
    for h in ("SYSTEM", "SOFTWARE", "SAM"):
        assert (reg / h).is_file()
        assert (reg / f"{h}.LOG1").is_file(), f"{h}.LOG1 missing — dirty hive would fail to parse"
        assert (reg / f"{h}.LOG2").is_file(), f"{h}.LOG2 missing — dirty hive would fail to parse"

    assert (reg / "Amcache.hve").is_file()
    assert (reg / "Amcache.hve.LOG1").is_file()

    # NTUSER LOGs renamed to follow the destination hive
    assert (reg / "NTUSER-alice.DAT").is_file()
    assert (reg / "NTUSER-alice.DAT.LOG1").is_file()
    assert (reg / "NTUSER-alice.DAT.LOG2").is_file()


def test_xp_single_log_form_also_copied(tmp_path):
    """XP/2003 uses a single HIVE.LOG rather than LOG1/LOG2. Detector
    must pick both forms so the fix works for legacy images too."""
    mount = tmp_path / "mnt"
    cfg = mount / "WINDOWS" / "system32" / "config"
    _write(cfg / "SYSTEM")
    _write(cfg / "SYSTEM.LOG", b"xp-style-log")

    exports = tmp_path / "exports"
    sk.extract_windows_artifacts(mount, exports)
    assert (exports / "registry" / "SYSTEM").is_file()
    assert (exports / "registry" / "SYSTEM.LOG").is_file()


def test_clean_hive_with_no_logs_still_copies_cleanly(tmp_path):
    """Boxes that were cleanly shut down have no LOG files. The extractor
    must not produce errors — missing logs are the normal case."""
    mount = tmp_path / "mnt"
    _write(mount / "Windows" / "System32" / "config" / "SYSTEM")
    # No .LOG / .LOG1 / .LOG2 present at all

    exports = tmp_path / "exports"
    out = sk.extract_windows_artifacts(mount, exports)
    assert out.get("registry_hives") == 1
    assert (exports / "registry" / "SYSTEM").is_file()
    # No spurious log files created
    assert not (exports / "registry" / "SYSTEM.LOG1").exists()


def test_skips_unreadable_directories(tmp_path, monkeypatch):
    """Don't crash if a child iterdir raises — should just skip."""
    mount = tmp_path / "mnt"
    _write(mount / "Windows" / "System32" / "config" / "SYSTEM")

    orig_iterdir = Path.iterdir

    def _maybe_fail(self):
        if self.name == "System32":
            raise PermissionError("not readable in test")
        return orig_iterdir(self)
    monkeypatch.setattr(Path, "iterdir", _maybe_fail)

    # Should not raise
    out = sk.extract_windows_artifacts(mount, tmp_path / "exports")
    # We won't find config because System32 was unreadable — but no crash
    assert isinstance(out, dict)
