from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from el.schemas.finding import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id   TEXT PRIMARY KEY,
    case_id      TEXT NOT NULL,
    agent        TEXT NOT NULL,
    claim        TEXT NOT NULL,
    confidence   TEXT NOT NULL,
    created_utc  TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_case  ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_agent ON findings(agent);
CREATE INDEX IF NOT EXISTS idx_findings_conf  ON findings(confidence);
"""


def ledger_path(case_dir: str | Path) -> Path:
    return Path(case_dir) / "findings.sqlite"


@contextmanager
def open_ledger(case_dir: str | Path) -> Iterator[sqlite3.Connection]:
    p = ledger_path(case_dir)
    conn = sqlite3.connect(p)
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def insert(case_dir: str | Path, finding: Finding) -> None:
    with open_ledger(case_dir) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO findings "
            "(finding_id, case_id, agent, claim, confidence, created_utc, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                finding.finding_id,
                finding.case_id,
                finding.agent,
                finding.claim,
                finding.confidence,
                finding.created_utc.isoformat(),
                finding.model_dump_json(),
            ),
        )


def list_findings(case_dir: str | Path, case_id: str | None = None) -> list[Finding]:
    with open_ledger(case_dir) as conn:
        if case_id:
            cur = conn.execute(
                "SELECT payload_json FROM findings WHERE case_id = ? ORDER BY created_utc",
                (case_id,),
            )
        else:
            cur = conn.execute("SELECT payload_json FROM findings ORDER BY created_utc")
        return [Finding.model_validate_json(row[0]) for row in cur.fetchall()]
