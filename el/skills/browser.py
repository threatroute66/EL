"""Skill: browser history parsing.

Scope for PR-10: Firefox places.sqlite (the history + bookmarks DB that
every Gecko-based profile has at
  <profile>/places.sqlite
  XP   : Documents and Settings/<user>/Application Data/Mozilla/Firefox/Profiles/<id>.default/
  Win7+: Users/<user>/AppData/Roaming/Mozilla/Firefox/Profiles/<id>.default-release/

IE index.dat is intentionally out-of-scope for PR-10 — it needs pymsiecf
installed inside the EL venv (only the system-python bindings ship on
SIFT). Leave `ie_index_dat()` as a documented NotImplemented stub so the
callsite can be added later without touching the agent.

Firefox uses a PRTime epoch (microseconds since 1970-01-01 UTC) for
last_visit_date — we convert to a Python UTC datetime in-skill so callers
never have to remember the unit.

No LLM. No network. The sqlite3 connection is opened read-only (uri=True
with mode=ro) so we never write to the evidence copy.
"""
from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from el.schemas.finding import EvidenceItem


class BrowserError(RuntimeError):
    pass


@dataclass
class Visit:
    url: str
    title: str
    visit_count: int
    last_visit_utc: datetime | None
    source: str           # e.g. "firefox:places.sqlite" / "ie:index.dat"


@dataclass
class BrowserRun:
    source_path: Path
    source_kind: str      # "firefox" / "ie"
    visits: list[Visit]
    error: str | None = None

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        sha = hashlib.sha256(self.source_path.read_bytes()).hexdigest() \
            if self.source_path.is_file() else "0" * 64
        merged = {"source_kind": self.source_kind,
                  "visit_count": len(self.visits)}
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool=f"el.browser/{self.source_kind}", version="0.1.0",
            command=f"read_{self.source_kind}_history({self.source_path.name})",
            output_sha256=sha,
            output_path=str(self.source_path),
            extracted_facts=merged,
        )


def _prtime_to_utc(prtime: int | None) -> datetime | None:
    """Firefox places.sqlite stores timestamps as PRTime (microseconds
    since 1970-01-01 UTC). NULL is common for bookmarks that have no
    visit yet — return None in that case."""
    if not prtime:
        return None
    try:
        return datetime.fromtimestamp(prtime / 1_000_000, tz=timezone.utc)
    except Exception:
        return None


def firefox_places(places_sqlite: Path,
                    max_rows: int = 50_000) -> BrowserRun:
    """Parse places.sqlite. Handles two schema eras:

      Fx 3.0       : moz_places has url/title/visit_count but NO
                     last_visit_date — timestamps come from
                     moz_historyvisits.visit_date joined on place_id.
                     M57-Jean's image is this era.
      Fx 3.5 → now : moz_places.last_visit_date is present and can be
                     queried directly (much cheaper on big profiles).

    Opens the file read-only so we never mutate the evidence copy.
    """
    places_sqlite = Path(places_sqlite)
    if not places_sqlite.is_file():
        raise BrowserError(f"places.sqlite not found: {places_sqlite}")

    uri = f"file:{places_sqlite}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.DatabaseError as e:
        raise BrowserError(f"cannot open {places_sqlite}: {e}") from e

    try:
        has_lvd = _column_exists(conn, "moz_places", "last_visit_date")
        has_hv = _table_exists(conn, "moz_historyvisits")
        if has_lvd:
            cur = conn.execute(
                "SELECT url, COALESCE(title, ''), COALESCE(visit_count, 0), "
                "       last_visit_date "
                "FROM moz_places "
                "WHERE url IS NOT NULL AND url != '' "
                "ORDER BY last_visit_date DESC NULLS LAST "
                "LIMIT ?",
                (max_rows,),
            )
            rows = cur.fetchall()
        elif has_hv:
            # Pre-3.5 layout: LEFT JOIN to get the max(visit_date) per place.
            cur = conn.execute(
                "SELECT p.url, COALESCE(p.title, ''), "
                "       COALESCE(p.visit_count, 0), "
                "       MAX(hv.visit_date) AS lvd "
                "FROM moz_places p "
                "LEFT JOIN moz_historyvisits hv ON hv.place_id = p.id "
                "WHERE p.url IS NOT NULL AND p.url != '' "
                "GROUP BY p.id "
                "ORDER BY lvd DESC NULLS LAST "
                "LIMIT ?",
                (max_rows,),
            )
            rows = cur.fetchall()
        else:
            # Neither schema matches — emit a run with error set rather
            # than crash the investigation.
            return BrowserRun(
                source_path=places_sqlite, source_kind="firefox",
                visits=[],
                error="places.sqlite has neither last_visit_date column "
                      "nor moz_historyvisits table — unknown schema version",
            )
    except sqlite3.DatabaseError as e:
        return BrowserRun(source_path=places_sqlite, source_kind="firefox",
                          visits=[], error=str(e))
    finally:
        conn.close()

    visits = [
        Visit(url=r[0], title=r[1], visit_count=r[2] or 0,
              last_visit_utc=_prtime_to_utc(r[3]),
              source="firefox:places.sqlite")
        for r in rows
    ]
    return BrowserRun(source_path=places_sqlite, source_kind="firefox",
                      visits=visits)


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return any(row[1] == column for row in cur.fetchall())
    except sqlite3.DatabaseError:
        return False


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    try:
        cur = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (table,),
        )
        return cur.fetchone() is not None
    except sqlite3.DatabaseError:
        return False


def ie_index_dat(path: Path) -> BrowserRun:
    """IE Cache File (index.dat) parser. Currently stub — pymsiecf is on
    SIFT system-wide but not in the EL venv. Leaving the API hook so the
    browser_forensicator agent can opt in as soon as the binding is
    wired. Callers must catch BrowserError(code='unavailable')."""
    raise BrowserError("ie_index_dat: pymsiecf binding not available in "
                       "the EL venv (PR-10 ships Firefox only). Install "
                       "libmsiecf-python3 into the venv to enable.")
