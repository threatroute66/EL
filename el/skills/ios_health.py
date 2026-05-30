"""iOS HealthKit parser — workouts + quantity-sample summary.

``/private/var/mobile/Library/Health/healthdb_secure.sqlite`` is the HealthKit
store. Two forensically useful slices:

  * ``workouts`` — one row per workout with ``total_distance`` (the
    authoritative per-workout distance).
  * ``quantity_samples`` (joined to ``samples`` for type + time) — the raw
    metric stream (steps, distance, energy, heart rate, …), keyed by an
    integer ``data_type``.

HealthKit does NOT store the data_type→identifier names in the DB (they are
hard-coded in the framework and shift between iOS versions), so this parser
reports raw ``data_type`` codes with per-type aggregates (count / min / max /
sum) rather than guessing labels — keeping it grounded and version-robust. A
small best-known label map is offered for convenience only.

Read-only via :mod:`el.skills._sqlite` (WAL-applied copy).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from el.schemas.finding import EvidenceItem
from el.skills._sqlite import EvidenceDBError, open_evidence_db

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

# Best-known HealthKit data_type codes (convenience labels only; the parser
# never relies on these for correctness).
KNOWN_TYPES = {
    7: "StepCount", 8: "DistanceWalkingRunning", 9: "HeartRate",
    10: "BasalEnergyBurned", 12: "FlightsClimbed", 13: "ActiveEnergyBurned",
}


class IOSHealthError(Exception):
    pass


def _abs_to_utc(value) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    try:
        return (_MAC_EPOCH + timedelta(seconds=v)).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class TypeAgg:
    data_type: int
    label: str
    count: int
    min_value: float
    max_value: float
    sum_value: float

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class HealthRun:
    db_path: Path
    workout_count: int = 0
    max_workout_distance: float | None = None
    type_aggs: list[TypeAgg] = field(default_factory=list)
    first_sample_utc: str = ""
    last_sample_utc: str = ""
    output_path: Path | None = None
    output_sha256: str = ""

    def agg(self, data_type: int) -> TypeAgg | None:
        return next((t for t in self.type_aggs if t.data_type == data_type), None)

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="el.ios_health", version="0.1.0",
            command=f"parse healthdb_secure.sqlite -- {self.db_path}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.db_path),
            extracted_facts={
                "db_path": str(self.db_path),
                "workout_count": self.workout_count,
                "max_workout_distance": self.max_workout_distance,
                "quantity_type_count": len(self.type_aggs),
                "first_sample_utc": self.first_sample_utc,
                "last_sample_utc": self.last_sample_utc,
                "top_types": {
                    f"{t.data_type}:{t.label}": {"count": t.count,
                                                 "max": round(t.max_value, 3)}
                    for t in sorted(self.type_aggs, key=lambda x: -x.count)[:8]},
                **extra,
            },
        )


def find_health_db(fs_root: Path) -> Path | None:
    fs_root = Path(fs_root)
    for rel in (("private", "var", "mobile", "Library", "Health",
                 "healthdb_secure.sqlite"),
                ("var", "mobile", "Library", "Health",
                 "healthdb_secure.sqlite")):
        p = fs_root.joinpath(*rel)
        if p.is_file():
            return p
    if fs_root.name == "healthdb_secure.sqlite" and fs_root.is_file():
        return fs_root
    direct = fs_root / "healthdb_secure.sqlite"
    return direct if direct.is_file() else None


def parse(db_path: Path, output_dir: Path | None = None) -> HealthRun:
    db_path = Path(db_path)
    if not db_path.is_file():
        raise IOSHealthError(f"healthdb_secure.sqlite not found: {db_path}")

    run = HealthRun(db_path=db_path)
    workdir = Path(output_dir) / "_dbcopy" if output_dir else None
    try:
        with open_evidence_db(db_path, workdir=workdir,
                              row_factory=sqlite3.Row) as conn:
            present = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}

            if "workouts" in present:
                cols = {r[1] for r in conn.execute("PRAGMA table_info(workouts)")}
                if "total_distance" in cols:
                    row = conn.execute(
                        "SELECT COUNT(*), MAX(total_distance) FROM workouts"
                    ).fetchone()
                    run.workout_count = row[0] or 0
                    run.max_workout_distance = row[1]

            if {"quantity_samples", "samples"} <= present:
                for r in conn.execute("""
                        SELECT s.data_type AS dt, COUNT(*) AS n,
                               MIN(q.quantity) AS mn, MAX(q.quantity) AS mx,
                               SUM(q.quantity) AS sm
                        FROM quantity_samples q JOIN samples s
                          ON q.data_id = s.data_id
                        GROUP BY s.data_type ORDER BY n DESC"""):
                    dt = int(r["dt"]) if r["dt"] is not None else -1
                    run.type_aggs.append(TypeAgg(
                        data_type=dt, label=KNOWN_TYPES.get(dt, ""),
                        count=r["n"] or 0,
                        min_value=float(r["mn"] or 0.0),
                        max_value=float(r["mx"] or 0.0),
                        sum_value=float(r["sm"] or 0.0)))

            if "samples" in present:
                row = conn.execute(
                    "SELECT MIN(start_date), MAX(start_date) FROM samples"
                ).fetchone()
                run.first_sample_utc = _abs_to_utc(row[0])
                run.last_sample_utc = _abs_to_utc(row[1])
    except EvidenceDBError as e:
        raise IOSHealthError(str(e)) from e
    except sqlite3.DatabaseError as e:
        raise IOSHealthError(f"cannot read {db_path}: {e}") from e

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "ios_health_summary.json"
        out.write_text(json.dumps({
            "workout_count": run.workout_count,
            "max_workout_distance": run.max_workout_distance,
            "first_sample_utc": run.first_sample_utc,
            "last_sample_utc": run.last_sample_utc,
            "type_aggs": [t.as_dict() for t in run.type_aggs],
        }, indent=1))
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run
