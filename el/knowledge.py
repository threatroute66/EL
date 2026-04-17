"""Institutional knowledge store — cross-case IOC + attribution database.

Lives at ~/.el/knowledge.sqlite (per-user, persistent across project moves,
gitignored). Pure record-keeping: every IOC every case has ever extracted
gets a row with (value, type, case_id, observed_utc, agent, sealed).

Cross-case lookup is **suggestive only** — emits informational Findings
with `confidence='low'` so cross-case overlap is visible to the analyst
WITHOUT auto-lifting any hypothesis. The forensic conclusion in case B
must stand on case B's evidence; case A is context, not evidence.

Schema is intentionally narrow. Per-case forensic detail (hypothesis
ranking, ACH matrix, sealed report) stays in cases/<id>/ — only the
flat IOC lookup table is global.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


def _default_db_path() -> Path:
    """~/.el/knowledge.sqlite — overridable via EL_KNOWLEDGE_DB env var."""
    if env := os.environ.get("EL_KNOWLEDGE_DB"):
        return Path(env)
    base = Path.home() / ".el"
    base.mkdir(parents=True, exist_ok=True)
    return base / "knowledge.sqlite"


SCHEMA = """
CREATE TABLE IF NOT EXISTS ioc_observations (
    value         TEXT NOT NULL,
    ioc_type      TEXT NOT NULL,        -- ipv4 / ipv6 / domain / md5 / sha1 / sha256 / url / email
    case_id       TEXT NOT NULL,
    observed_utc  TEXT NOT NULL,
    agent         TEXT NOT NULL,
    sealed        INTEGER DEFAULT 0,    -- 1 once the source case is sealed
    PRIMARY KEY (value, ioc_type, case_id)
);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_observations(value);
CREATE INDEX IF NOT EXISTS idx_ioc_type  ON ioc_observations(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_case  ON ioc_observations(case_id);

CREATE TABLE IF NOT EXISTS family_attributions (
    family       TEXT NOT NULL,
    case_id      TEXT NOT NULL,
    observed_utc TEXT NOT NULL,
    agent        TEXT NOT NULL,
    snippet      TEXT,
    PRIMARY KEY (family, case_id)
);
CREATE INDEX IF NOT EXISTS idx_attr_family ON family_attributions(family);
"""


@contextmanager
def open_db(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    p = path or _default_db_path()
    conn = sqlite3.connect(p)
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def record_iocs(case_id: str, agent: str,
                iocs: dict[str, list[str] | set[str]],
                db_path: Path | None = None) -> int:
    """Insert (value, type, case_id) rows. Returns count of NEW rows."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    inserted = 0
    with open_db(db_path) as conn:
        for ioc_type, values in iocs.items():
            for v in values:
                if not v:
                    continue
                cur = conn.execute(
                    "INSERT OR IGNORE INTO ioc_observations "
                    "(value, ioc_type, case_id, observed_utc, agent) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (v, ioc_type, case_id, now, agent),
                )
                if cur.rowcount > 0:
                    inserted += 1
    return inserted


def record_family_attribution(case_id: str, agent: str, family: str,
                               snippet: str | None = None,
                               db_path: Path | None = None) -> bool:
    """Insert a family-attribution row. Returns True if newly inserted."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with open_db(db_path) as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO family_attributions "
            "(family, case_id, observed_utc, agent, snippet) "
            "VALUES (?, ?, ?, ?, ?)",
            (family, case_id, now, agent, snippet),
        )
        return cur.rowcount > 0


def lookup_iocs(values: list[str], current_case_id: str,
                db_path: Path | None = None) -> dict[str, list[dict]]:
    """For each value, return prior observations from OTHER cases.
    Returns {value: [{case_id, ioc_type, observed_utc, agent}, ...]}.
    Only includes hits where case_id != current_case_id."""
    if not values:
        return {}
    out: dict[str, list[dict]] = {}
    with open_db(db_path) as conn:
        # Chunk to keep IN clause manageable
        for i in range(0, len(values), 500):
            chunk = values[i:i + 500]
            placeholders = ",".join(["?"] * len(chunk))
            rows = conn.execute(
                f"SELECT value, ioc_type, case_id, observed_utc, agent "
                f"FROM ioc_observations "
                f"WHERE value IN ({placeholders}) AND case_id != ?",
                (*chunk, current_case_id),
            ).fetchall()
            for value, ioc_type, case_id, observed_utc, agent in rows:
                out.setdefault(value, []).append({
                    "case_id": case_id, "ioc_type": ioc_type,
                    "observed_utc": observed_utc, "agent": agent,
                })
    return out


def mark_case_sealed(case_id: str, db_path: Path | None = None) -> int:
    """Flip sealed=1 on every row from this case. Returns rows updated."""
    with open_db(db_path) as conn:
        cur = conn.execute(
            "UPDATE ioc_observations SET sealed=1 WHERE case_id=?", (case_id,))
        return cur.rowcount


def stats(db_path: Path | None = None) -> dict:
    """Summary counts for `el knowledge stats`."""
    with open_db(db_path) as conn:
        n_iocs = conn.execute("SELECT count(*) FROM ioc_observations").fetchone()[0]
        n_distinct = conn.execute(
            "SELECT count(DISTINCT value) FROM ioc_observations").fetchone()[0]
        n_cases = conn.execute(
            "SELECT count(DISTINCT case_id) FROM ioc_observations").fetchone()[0]
        n_attr = conn.execute("SELECT count(*) FROM family_attributions").fetchone()[0]
        type_counts = dict(conn.execute(
            "SELECT ioc_type, count(*) FROM ioc_observations GROUP BY ioc_type"
        ).fetchall())
    return {"total_observations": n_iocs, "distinct_iocs": n_distinct,
            "cases_recorded": n_cases, "family_attributions": n_attr,
            "type_breakdown": type_counts}
