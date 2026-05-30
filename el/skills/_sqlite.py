"""Safe evidence-SQLite access — copy-then-open with WAL sidecars.

Reading an evidence SQLite database has two failure modes that have each
bitten EL in real cases:

  1. **Stale reads.** Opening with ``?immutable=1`` tells SQLite to ignore
     the ``-wal`` / ``-shm`` sidecars entirely, so any rows that live only
     in an un-checkpointed write-ahead log are invisible. A macOS Reminders
     store read this way reported **0** reminders while the committed+WAL
     state held **37** — the rows were all in the ``-wal``.

  2. **Evidence mutation.** Opening the original file read/write (plain
     ``sqlite3.connect(path)``) lets SQLite create or roll the
     ``-wal`` / ``-shm`` / ``-journal`` sidecars *on the evidence*, breaking
     read-only chain-of-custody.

The fix both correctness- and integrity-wise is the same: copy the main DB
together with its ``-wal`` / ``-shm`` / ``-journal`` sidecars into a working
directory, then open the **copy**. SQLite folds the WAL in transparently on
the copy (so no rows are missed) and the evidence is never touched.

Usage::

    from el.skills._sqlite import open_evidence_db

    with open_evidence_db(reminders_db, workdir=case_analysis_dir) as conn:
        rows = conn.execute("SELECT ... FROM ZREMCDREMINDER").fetchall()

Pass ``workdir`` (e.g. ``<case_dir>/analysis/<agent>/``) to keep the working
copy for reproducibility; omit it for an ephemeral copy that is deleted when
the ``with`` block exits.
"""
from __future__ import annotations

import shutil
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

# Sidecar suffixes that carry committed-but-not-yet-checkpointed data
# (-wal/-shm) or an in-flight rollback journal (-journal). All must travel
# with the main DB or the copy reads a different state than the original.
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class EvidenceDBError(Exception):
    pass


def copy_db_with_sidecars(db_path: Path, workdir: Path,
                          *, name: str | None = None) -> Path:
    """Copy *db_path* and its ``-wal`` / ``-shm`` / ``-journal`` sidecars into
    *workdir*. Returns the path to the copied main DB. The evidence file is
    only ever read, never modified.

    Raises :class:`EvidenceDBError` if *db_path* is not a readable file.
    """
    db_path = Path(db_path)
    if not db_path.is_file():
        raise EvidenceDBError(f"not a file: {db_path}")
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    dest_name = name or db_path.name
    dest = workdir / dest_name
    try:
        shutil.copy2(db_path, dest)
    except OSError as e:
        raise EvidenceDBError(f"cannot copy {db_path}: {e}") from e

    for suffix in _SIDECAR_SUFFIXES:
        side = db_path.with_name(db_path.name + suffix)
        if side.is_file():
            try:
                shutil.copy2(side, workdir / (dest_name + suffix))
            except OSError:
                # A missing/locked sidecar is non-fatal: worst case we read
                # the main DB's last-checkpointed state, same as immutable.
                continue
    return dest


@contextmanager
def open_evidence_db(db_path: Path, *, workdir: Path | None = None,
                     name: str | None = None,
                     row_factory: type | None = None,
                     ) -> Iterator[sqlite3.Connection]:
    """Open a WAL-correct, evidence-safe connection to *db_path*.

    Copies the DB + sidecars (to *workdir* when given, else an ephemeral temp
    dir cleaned up on exit), then opens the copy so the write-ahead log is
    applied. The original evidence file is never opened by SQLite.

    The connection is yielded; it is closed (and any temp copy removed) when
    the ``with`` block exits. ``row_factory`` (e.g. ``sqlite3.Row``) is set on
    the connection when provided.
    """
    tmp: tempfile.TemporaryDirectory | None = None
    if workdir is None:
        tmp = tempfile.TemporaryDirectory(prefix="el-evdb-")
        target_dir = Path(tmp.name)
    else:
        target_dir = Path(workdir)

    conn: sqlite3.Connection | None = None
    try:
        copied = copy_db_with_sidecars(db_path, target_dir, name=name)
        # Open the COPY read/write — it is a throwaway working copy, so
        # letting SQLite touch its WAL/journal is harmless, and it lets the
        # engine fold the WAL into the page cache transparently.
        conn = sqlite3.connect(str(copied))
        if row_factory is not None:
            conn.row_factory = row_factory
        # Best-effort: fold the WAL into the main DB on the copy so the
        # working file is self-contained. Failure is non-fatal (queries
        # still see WAL frames via the connection).
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        yield conn
    finally:
        if conn is not None:
            conn.close()
        if tmp is not None:
            tmp.cleanup()
