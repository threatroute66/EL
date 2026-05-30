"""macOS ExecPolicy (Gatekeeper / notarization scan cache) parser.

``/private/var/db/SystemPolicyConfiguration/ExecPolicy`` is the SQLite store
``syspolicyd`` writes when it scans an executable the first time it runs. Its
``executable_measurements_v2`` table is a per-binary forensic goldmine:

    file_identifier / bundle_identifier / bundle_version
    team_identifier / signing_identifier / cdhash        <- code identity
    is_signed / is_valid / is_quarantined                <- trust flags
    file_size / responsible_file_identifier
    timestamp / reported_timestamp                       <- first-scan / report

It is the authoritative on-disk source for an executable's **cdhash** and
whether it was **unsigned**, had an **invalid/revoked** signature, or carried
a **quarantine** xattr (came from the internet). No SIFT-bundled CLI extracts
these structured fields, so — like the utmp / ActivitiesCache parsers — this
is a deliberate native parser rather than a tool wrapper.

Reads via :func:`el.skills._sqlite.open_evidence_db` so the DB's ``-wal``
sidecar is applied (recent scans live there) and the evidence is never
modified.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from el.schemas.finding import EvidenceItem
from el.skills._sqlite import EvidenceDBError, open_evidence_db


class MacOSExecPolicyError(Exception):
    pass


# Candidate table names across macOS versions (newest first).
_MEASUREMENT_TABLES = ("executable_measurements_v2", "executable_measurements")

# Plausible epoch window so a garbage/huge value doesn't format to year 2200.
_EPOCH_MIN = 946_684_800        # 2000-01-01
_EPOCH_MAX = 4_102_444_800      # 2100-01-01


def _epoch_to_utc(value) -> str:
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return ""
    if not (_EPOCH_MIN <= ts <= _EPOCH_MAX):
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")


def _as_bool(value) -> bool | None:
    if value is None:
        return None
    try:
        return bool(int(value))
    except (TypeError, ValueError):
        return None


@dataclass
class ExecMeasurement:
    file_identifier: str = ""
    bundle_identifier: str = ""
    bundle_version: str = ""
    team_identifier: str = ""
    signing_identifier: str = ""
    cdhash: str = ""
    is_signed: bool | None = None
    is_valid: bool | None = None
    is_quarantined: bool | None = None
    file_size: int = 0
    responsible_file: str = ""
    scanned_utc: str = ""
    reported_utc: str = ""

    @property
    def is_suspicious(self) -> bool:
        """An executable Gatekeeper recorded as unsigned or with an
        invalid/revoked signature — the threat-relevant rows."""
        return self.is_signed is False or self.is_valid is False

    def as_dict(self) -> dict:
        return {
            "file_identifier": self.file_identifier,
            "bundle_identifier": self.bundle_identifier,
            "bundle_version": self.bundle_version,
            "team_identifier": self.team_identifier,
            "signing_identifier": self.signing_identifier,
            "cdhash": self.cdhash,
            "is_signed": self.is_signed,
            "is_valid": self.is_valid,
            "is_quarantined": self.is_quarantined,
            "file_size": self.file_size,
            "responsible_file": self.responsible_file,
            "scanned_utc": self.scanned_utc,
            "reported_utc": self.reported_utc,
        }


@dataclass
class ExecPolicyRun:
    db_path: Path
    measurements: list[ExecMeasurement] = field(default_factory=list)
    output_path: Path | None = None
    output_sha256: str = ""
    table_used: str = ""
    note: str = ""

    @property
    def total(self) -> int:
        return len(self.measurements)

    @property
    def unsigned(self) -> list[ExecMeasurement]:
        return [m for m in self.measurements if m.is_signed is False]

    @property
    def invalid(self) -> list[ExecMeasurement]:
        return [m for m in self.measurements if m.is_valid is False]

    @property
    def quarantined(self) -> list[ExecMeasurement]:
        return [m for m in self.measurements if m.is_quarantined is True]

    @property
    def suspicious(self) -> list[ExecMeasurement]:
        return [m for m in self.measurements if m.is_suspicious]

    def find_at(self, scanned_utc: str) -> list[ExecMeasurement]:
        """Measurements whose first-scan timestamp equals *scanned_utc*
        (``YYYY-MM-DD HH:MM:SS``). Handy for 'cdhash of the event at T'."""
        return [m for m in self.measurements if m.scanned_utc == scanned_utc]

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="el.macos_execpolicy", version="0.1.0",
            command=(f"SELECT * FROM {self.table_used or '?'} "
                     f"-- {self.db_path}"),
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.db_path),
            extracted_facts={
                "db_path": str(self.db_path),
                "table_used": self.table_used,
                "total_measurements": self.total,
                "unsigned_count": len(self.unsigned),
                "invalid_signature_count": len(self.invalid),
                "quarantined_count": len(self.quarantined),
                "note": self.note,
                **extra,
            },
        )


def find_execpolicy(macos_root: Path) -> Path | None:
    """Locate the ExecPolicy DB inside an extracted macOS filesystem."""
    macos_root = Path(macos_root)
    for rel in (
        ("private", "var", "db", "SystemPolicyConfiguration", "ExecPolicy"),
        ("var", "db", "SystemPolicyConfiguration", "ExecPolicy"),
    ):
        p = macos_root.joinpath(*rel)
        if p.is_file():
            return p
    # macos_root may itself be the SystemPolicyConfiguration dir or the file.
    if macos_root.name == "ExecPolicy" and macos_root.is_file():
        return macos_root
    direct = macos_root / "ExecPolicy"
    if direct.is_file():
        return direct
    return None


def _row_value(row: sqlite3.Row, *names):
    keys = row.keys()
    for n in names:
        if n in keys:
            return row[n]
    return None


def parse(db_path: Path, output_dir: Path | None = None) -> ExecPolicyRun:
    """Parse ExecPolicy's measurement table into :class:`ExecMeasurement`
    rows. Writes a JSONL dump under *output_dir* when given.

    Raises :class:`MacOSExecPolicyError` if the DB can't be opened or has no
    recognised measurement table.
    """
    db_path = Path(db_path)
    if not db_path.is_file():
        raise MacOSExecPolicyError(f"ExecPolicy DB not found: {db_path}")

    workdir = None
    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        workdir = output_dir / "_dbcopy"

    measurements: list[ExecMeasurement] = []
    table_used = ""
    try:
        with open_evidence_db(db_path, workdir=workdir,
                              row_factory=sqlite3.Row) as conn:
            existing = {
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            table = next((t for t in _MEASUREMENT_TABLES if t in existing),
                         None)
            if table is None:
                raise MacOSExecPolicyError(
                    f"no executable_measurements table in {db_path} "
                    f"(found: {sorted(existing)})")
            table_used = table
            for row in conn.execute(f"SELECT * FROM {table}"):
                measurements.append(ExecMeasurement(
                    file_identifier=str(_row_value(row, "file_identifier") or ""),
                    bundle_identifier=str(
                        _row_value(row, "bundle_identifier") or ""),
                    bundle_version=str(_row_value(row, "bundle_version") or ""),
                    team_identifier=str(
                        _row_value(row, "team_identifier") or ""),
                    signing_identifier=str(
                        _row_value(row, "signing_identifier") or ""),
                    cdhash=str(_row_value(row, "cdhash") or ""),
                    is_signed=_as_bool(_row_value(row, "is_signed")),
                    is_valid=_as_bool(_row_value(row, "is_valid")),
                    is_quarantined=_as_bool(
                        _row_value(row, "is_quarantined")),
                    file_size=int(_row_value(row, "file_size") or 0),
                    responsible_file=str(
                        _row_value(row, "responsible_file_identifier") or ""),
                    scanned_utc=_epoch_to_utc(_row_value(row, "timestamp")),
                    reported_utc=_epoch_to_utc(
                        _row_value(row, "reported_timestamp")),
                ))
    except EvidenceDBError as e:
        raise MacOSExecPolicyError(str(e)) from e
    except sqlite3.DatabaseError as e:
        raise MacOSExecPolicyError(
            f"cannot read ExecPolicy {db_path}: {e}") from e

    run = ExecPolicyRun(db_path=db_path, measurements=measurements,
                        table_used=table_used)

    if output_dir is not None:
        out = output_dir / "execpolicy_measurements.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for m in measurements:
                f.write(json.dumps(m.as_dict(), sort_keys=True) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run
