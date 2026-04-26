"""iOS iTunes/Finder backup parser.

Synthetic Manifest.plist + Manifest.db fixtures for the always-on
suite, plus a corpus-gated smoke test against the real iPhone8,4
backup at ``/mnt/hgfs/hackathon/ios_13_4_1`` when present.
"""
import os
import plistlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from el.skills import ios_backup_parse as ib


def _write_manifest_plist(p: Path, *, encrypted: bool = False,
                           ios: str = "13.4.1",
                           device_name: str = "Test iPhone",
                           product_type: str = "iPhone8,4"):
    p.write_bytes(plistlib.dumps({
        "Version": "10.0",
        "IsEncrypted": encrypted,
        "WasPasscodeSet": True,
        "Date": datetime(2020, 4, 1, 12, 0, 0, tzinfo=timezone.utc),
        "Applications": {"com.apple.MobileSMS": {},
                          "com.whatsapp.WhatsApp": {}},
        "Lockdown": {
            "ProductVersion": ios,
            "ProductType": product_type,
            "DeviceName": device_name,
            "UniqueDeviceID": "abc123" + "0" * 34,
        },
        "BackupKeyBag": b"\x00" * 64,
    }))


def _write_manifest_db(p: Path, files: list[tuple[str, str, str, int]]):
    """``files`` is a list of (file_id, domain, relative_path, flags)
    tuples — flags 1=file, 2=dir, 4=symlink. Builds a minimal
    Manifest.db schema and inserts the rows."""
    conn = sqlite3.connect(p)
    try:
        conn.execute(
            "CREATE TABLE Files (fileID TEXT PRIMARY KEY, "
            "domain TEXT, relativePath TEXT, flags INTEGER, "
            "file BLOB)")
        for fid, dom, rel, flags in files:
            file_blob = plistlib.dumps({
                "$objects": [
                    "$null",
                    {"Size": 1024, "Mode": 33188,
                     "LastModified": 1585747200},
                ]
            })
            conn.execute(
                "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
                (fid, dom, rel, flags, file_blob))
        conn.commit()
    finally:
        conn.close()


# --- Metadata ----------------------------------------------------------

def test_read_metadata_unencrypted(tmp_path):
    bd = tmp_path / "backup"; bd.mkdir()
    _write_manifest_plist(bd / "Manifest.plist", encrypted=False)
    m = ib.read_metadata(bd)
    assert m.is_encrypted is False
    assert m.product_version == "13.4.1"
    assert m.device_name == "Test iPhone"
    assert m.product_type == "iPhone8,4"
    assert m.unique_device_id.startswith("abc123")
    assert m.application_count == 2
    assert m.backup_keybag_present is True
    assert m.backup_date_utc.startswith("2020-04-01T")


def test_read_metadata_encrypted(tmp_path):
    bd = tmp_path / "backup"; bd.mkdir()
    _write_manifest_plist(bd / "Manifest.plist", encrypted=True)
    m = ib.read_metadata(bd)
    assert m.is_encrypted is True


def test_read_metadata_handles_missing_plist(tmp_path):
    bd = tmp_path / "backup"; bd.mkdir()
    m = ib.read_metadata(bd)
    assert m.is_encrypted is False
    assert m.product_version == ""
    assert m.application_count == 0


def test_read_metadata_handles_corrupt_plist(tmp_path):
    bd = tmp_path / "backup"; bd.mkdir()
    (bd / "Manifest.plist").write_bytes(b"not a plist")
    m = ib.read_metadata(bd)
    # No raise — degrades to empty metadata
    assert m.product_version == ""


# --- File inventory ----------------------------------------------------

def test_list_files_basic(tmp_path):
    bd = tmp_path / "backup"; bd.mkdir()
    _write_manifest_db(bd / "Manifest.db", [
        ("a" * 40, "HomeDomain",
         "Library/SMS/sms.db", 1),
        ("b" * 40, "AppDomain-com.whatsapp.WhatsApp",
         "Documents/ChatStorage.sqlite", 1),
        ("c" * 40, "HomeDomain", "Library/SMS", 2),
    ])
    files = ib.list_files(bd)
    assert len(files) == 3
    by_dom = ib.by_domain(files)
    assert by_dom["HomeDomain"] == 2
    assert by_dom["AppDomain-com.whatsapp.WhatsApp"] == 1


def test_list_files_extracts_size_and_mode_from_blob(tmp_path):
    bd = tmp_path / "backup"; bd.mkdir()
    _write_manifest_db(bd / "Manifest.db", [
        ("a" * 40, "HomeDomain", "x.db", 1),
    ])
    files = ib.list_files(bd)
    assert files[0].file_size == 1024
    assert files[0].mode == 33188
    assert files[0].last_modified_utc == "1585747200"


def test_find_databases():
    sample = [
        ib.BackupFile(file_id="a", domain="d",
                      relative_path="Library/SMS/sms.db", flags=1),
        ib.BackupFile(file_id="b", domain="d",
                      relative_path="Documents/ChatStorage.sqlite",
                      flags=1),
        ib.BackupFile(file_id="c", domain="d",
                      relative_path="cache/image.png", flags=1),
    ]
    out = ib.find_databases(sample)
    assert len(out) == 2
    paths = {f.relative_path for f in out}
    assert "Library/SMS/sms.db" in paths
    assert "Documents/ChatStorage.sqlite" in paths


def test_find_in_domain():
    sample = [
        ib.BackupFile(domain="HomeDomain", relative_path="x"),
        ib.BackupFile(
            domain="AppDomain-com.apple.MobileSMS", relative_path="y"),
        ib.BackupFile(
            domain="AppDomain-com.whatsapp.WhatsApp", relative_path="z"),
    ]
    sms = ib.find_in_domain(sample, "mobilesms")
    assert len(sms) == 1
    wa = ib.find_in_domain(sample, "whatsapp")
    assert len(wa) == 1


def test_backup_file_stored_path(tmp_path):
    f = ib.BackupFile(file_id="ab" + "0" * 38)
    p = f.stored_path(tmp_path)
    # Apple stores files under <id[:2]>/<id>
    assert p.parent.name == "ab"
    assert p.name == "ab" + "0" * 38


def test_list_files_returns_empty_on_encrypted_manifest(tmp_path):
    """Encrypted Manifest.db isn't a valid SQLite header — sqlite3
    fails open or read. The skill returns [] rather than raising
    so the caller can pivot to decrypt_manifest_db."""
    bd = tmp_path / "backup"; bd.mkdir()
    (bd / "Manifest.db").write_bytes(b"\x00" * 4096)  # not SQLite
    assert ib.list_files(bd) == []


def test_list_files_missing_db(tmp_path):
    bd = tmp_path / "backup"; bd.mkdir()
    assert ib.list_files(bd) == []


# --- Decrypt path ------------------------------------------------------

def test_decrypt_without_iphone_backup_decrypt_lib(tmp_path,
                                                     monkeypatch):
    """When the optional decrypt library isn't installed the
    skill returns DecryptResult(success=False, error=<install
    hint>). We patch __import__ to simulate the missing dep."""
    bd = tmp_path / "backup"; bd.mkdir()
    (bd / "Manifest.db").write_bytes(b"\x00")
    real_import = __builtins__["__import__"] if isinstance(
        __builtins__, dict) else __import__

    def block(name, *args, **kwargs):
        if name == "iphone_backup_decrypt":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", block)
    r = ib.decrypt_manifest_db(bd, "anypass")
    assert r.success is False
    assert "iphone_backup_decrypt" in r.error


def test_decrypt_manifest_db_missing_returns_error(tmp_path):
    bd = tmp_path / "backup"; bd.mkdir()
    r = ib.decrypt_manifest_db(bd, "anypass")
    # Either lib missing or Manifest.db missing — both surface as
    # success=False with a diagnostic
    assert r.success is False
    assert r.error


# --- Corpus smoke ------------------------------------------------------

_REAL_BACKUP = ("/mnt/hgfs/hackathon/ios_13_4_1/iOS 13.4.1 Extraction/"
                 "iTunes Backup/c623fbd7e91b041e07a68f8523f53a35973e475d.zip")


@pytest.mark.skipif(not Path(_REAL_BACKUP).is_file(),
                     reason="real iOS 13.4.1 corpus not present")
def test_real_itunes_backup_metadata(tmp_path):
    """Pull the Manifest.plist out of the corpus zip and confirm
    the metadata reader extracts the expected device fields."""
    import zipfile
    with zipfile.ZipFile(_REAL_BACKUP) as zf:
        prefix = "c623fbd7e91b041e07a68f8523f53a35973e475d/"
        for n in ("Manifest.plist", "Manifest.db",
                   "Status.plist", "Info.plist"):
            try:
                with zf.open(prefix + n) as src, \
                        (tmp_path / n).open("wb") as dst:
                    dst.write(src.read())
            except KeyError:
                pass
    m = ib.read_metadata(tmp_path)
    assert m.is_encrypted is True              # known: this corpus is encrypted
    assert m.product_version == "13.4.1"
    assert m.product_type.startswith("iPhone")
    assert m.device_name                        # non-empty
    assert m.unique_device_id == \
        "c623fbd7e91b041e07a68f8523f53a35973e475d"
    assert m.application_count > 0
    # Manifest.db is encrypted — list_files should degrade to []
    files = ib.list_files(tmp_path)
    assert files == []
