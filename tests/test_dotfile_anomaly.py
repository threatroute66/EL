"""Tests for the dotfile-concealment detector."""
from __future__ import annotations

from el.skills import dotfile_anomaly as da


def test_benign_dotdirs_ignored(tmp_path):
    """Well-known config / cache dotfile dirs should not fire even when
    they contain archives (e.g. Mozilla profile zips, npm tarballs)."""
    cache = tmp_path / "home" / "alice" / ".cache" / "thunderbird"
    cache.mkdir(parents=True)
    (cache / "profile.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    mozilla = tmp_path / "home" / "alice" / ".mozilla"
    mozilla.mkdir(parents=True)
    (mozilla / "places.sqlite").write_bytes(b"SQLite format 3\x00")
    assert da.walk(tmp_path) == []


def test_custom_dotdir_with_archive_fires(tmp_path):
    """BelkaCTF Kidnapper: Ivan kept the monthly DB inside ~/.custom/."""
    custom = tmp_path / "home" / "ivan" / ".custom"
    custom.mkdir(parents=True)
    (custom / "Monthly_DB.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    (custom / "notes.txt").write_text("config")
    hits = da.walk(tmp_path)
    assert len(hits) == 1
    h = hits[0]
    assert h.user == "ivan"
    assert h.dotfile_dir.name == ".custom"
    assert h.suspicious_count == 1
    assert any(p.name == "Monthly_DB.zip" for p in h.suspicious_files)


def test_pdf_and_wav_in_hidden_dir_both_flagged(tmp_path):
    """Extension-mangled PDFs + WAV stego files — both surface as
    suspicious file types inside an unlisted dotfile dir."""
    secs = tmp_path / "home" / "ivan" / ".secs"
    secs.mkdir(parents=True)
    (secs / "letter.pdf").write_bytes(b"%PDF-1.4\n")
    (secs / "voice.wav").write_bytes(b"RIFF\x00\x00\x00\x00WAVE")
    hits = da.walk(tmp_path)
    assert len(hits) == 1
    assert hits[0].ext_counts.get(".pdf") == 1
    assert hits[0].ext_counts.get(".wav") == 1


def test_empty_dotdir_does_not_fire(tmp_path):
    """A hidden dir that only holds a .conf / .rc file is config, not
    concealment."""
    myrc = tmp_path / "home" / "ivan" / ".myrc"
    myrc.mkdir(parents=True)
    (myrc / "settings.conf").write_text("foo=1\n")
    assert da.walk(tmp_path) == []


def test_root_home_also_walked(tmp_path):
    """`/root` is a user home on many Linux installs — scan it too."""
    rsecs = tmp_path / "root" / ".stash"
    rsecs.mkdir(parents=True)
    (rsecs / "payload.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    hits = da.walk(tmp_path)
    assert len(hits) == 1
    assert hits[0].user == "root"
