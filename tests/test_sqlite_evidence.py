"""Tests for the evidence-SQLite copy-then-open helper (el.skills._sqlite).

Locks in the two guarantees that motivated the helper:

  * WAL-resident rows are visible (the macOS Reminders 0-vs-37 bug), which
    a plain ``?immutable=1`` open misses.
  * The evidence file and its directory are never mutated.
"""
import hashlib
import sqlite3
from pathlib import Path

import pytest

from el.skills._sqlite import (
    EvidenceDBError,
    copy_db_with_sidecars,
    open_evidence_db,
)


def _dir_fingerprint(d: Path) -> dict[str, str]:
    """Map of filename -> sha256 for every file directly in *d*."""
    out = {}
    for f in sorted(d.iterdir()):
        if f.is_file():
            out[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def _make_wal_db_with_uncheckpointed_rows(db: Path, n: int) -> list:
    """Create a WAL-mode DB whose rows live ONLY in the -wal sidecar (the
    main DB file never receives the table or rows).

    Returns a list of live connections that pin the WAL open — the caller
    MUST keep them open until done and close them in a finally. Two things
    keep the frames in the WAL: (a) the writer stays open with
    ``wal_autocheckpoint=0`` so nothing auto-checkpoints, and (b) a second
    connection holds an active read snapshot, which blocks any checkpoint
    from advancing past those frames.
    """
    w = sqlite3.connect(str(db))
    w.execute("PRAGMA journal_mode=WAL")
    w.execute("PRAGMA wal_autocheckpoint=0")
    w.execute("CREATE TABLE t (x INTEGER)")
    w.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(n)])
    w.commit()

    reader = sqlite3.connect(str(db))
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM t").fetchone()  # pin a read snapshot
    return [w, reader]


def _immutable_count(db: Path) -> int:
    """Row count seen by a stale ``?immutable=1`` reader (ignores the WAL)."""
    uri = f"file:{db.resolve()}?mode=ro&immutable=1"
    c = sqlite3.connect(uri, uri=True)
    try:
        return c.execute("SELECT COUNT(*) FROM t").fetchone()[0]
    except sqlite3.OperationalError:
        return 0  # table itself lives only in the WAL
    finally:
        c.close()


def test_wal_rows_visible_but_immutable_misses_them(tmp_path):
    db = tmp_path / "store.sqlite"
    pins = _make_wal_db_with_uncheckpointed_rows(db, 37)
    try:
        assert (db.with_name("store.sqlite-wal")).is_file()

        # The bug: an immutable reader sees a stale state (the table+rows are
        # in the WAL, which immutable=1 ignores).
        assert _immutable_count(db) < 37

        # The helper copies db + sidecars and sees the real, WAL-applied state.
        with open_evidence_db(db, workdir=tmp_path / "work") as conn:
            assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 37
    finally:
        for c in pins:
            c.close()


def test_evidence_dir_not_mutated(tmp_path):
    evdir = tmp_path / "evidence"
    evdir.mkdir()
    db = evdir / "m.sqlite"
    pins = _make_wal_db_with_uncheckpointed_rows(db, 5)
    try:
        before = _dir_fingerprint(evdir)
        with open_evidence_db(db, workdir=tmp_path / "work") as conn:
            conn.execute("SELECT COUNT(*) FROM t").fetchone()
        after = _dir_fingerprint(evdir)
        # No files added/removed and no byte changed in the evidence dir.
        assert before == after
    finally:
        for c in pins:
            c.close()


def test_workdir_copy_persists(tmp_path):
    db = tmp_path / "a.sqlite"
    c = sqlite3.connect(str(db))
    c.execute("CREATE TABLE t (x)")
    c.execute("INSERT INTO t VALUES (1)")
    c.commit()
    c.close()

    work = tmp_path / "work"
    with open_evidence_db(db, workdir=work) as conn:
        assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 1
    # With an explicit workdir, the working copy is kept for reproducibility.
    assert (work / "a.sqlite").is_file()


def test_ephemeral_copy_cleaned_up(tmp_path):
    db = tmp_path / "b.sqlite"
    c = sqlite3.connect(str(db))
    c.execute("CREATE TABLE t (x)")
    c.commit()
    c.close()

    captured = {}
    with open_evidence_db(db) as conn:
        # locate the temp copy via the connection's database list
        row = conn.execute("PRAGMA database_list").fetchone()
        captured["file"] = Path(row[2])
        assert captured["file"].is_file()
    # Ephemeral temp dir removed on exit.
    assert not captured["file"].exists()


def test_row_factory_applied(tmp_path):
    db = tmp_path / "c.sqlite"
    c = sqlite3.connect(str(db))
    c.execute("CREATE TABLE t (x, y)")
    c.execute("INSERT INTO t VALUES (1, 2)")
    c.commit()
    c.close()
    with open_evidence_db(db, row_factory=sqlite3.Row) as conn:
        r = conn.execute("SELECT x, y FROM t").fetchone()
        assert r["x"] == 1 and r["y"] == 2


def test_sidecars_copied_into_workdir(tmp_path):
    db = tmp_path / "d.sqlite"
    pins = _make_wal_db_with_uncheckpointed_rows(db, 3)
    try:
        work = tmp_path / "w"
        copied = copy_db_with_sidecars(db, work)
        assert copied == work / "d.sqlite"
        assert (work / "d.sqlite-wal").is_file()
    finally:
        for c in pins:
            c.close()


def test_copy_raises_on_missing_file(tmp_path):
    with pytest.raises(EvidenceDBError):
        copy_db_with_sidecars(tmp_path / "nope.sqlite", tmp_path / "w")


def test_custom_name(tmp_path):
    db = tmp_path / "orig.sqlite"
    c = sqlite3.connect(str(db))
    c.execute("CREATE TABLE t (x)")
    c.commit()
    c.close()
    copied = copy_db_with_sidecars(db, tmp_path / "w", name="renamed.sqlite")
    assert copied.name == "renamed.sqlite" and copied.is_file()
