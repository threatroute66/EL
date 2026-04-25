"""Skill: load MITRE CAR (Cyber Analytics Repository) analytics.

CAR (https://car.mitre.org) is a public catalog of analytics indexed
by ATT&CK technique, written by the MITRE Corp. Each analytic is a
YAML / JSON file describing a hunt query (Splunk SPL, KQL, EQL,
pseudocode) plus the techniques + sub-techniques it covers.

We don't run CAR queries directly (they're vendor-language SPL/KQL).
What we DO do is surface CAR's coverage of the techniques observed
in this case — i.e. for each ATT&CK T-id the case's findings already
support, list the CAR analytics that hunt for it. The analyst gets a
ready-made hunt path: "you saw T1003.001 → here are CARs ID:4 + ID:9
covering it; pivot to your SIEM and run them."

Sibling format to SIGMA. The doc rationale:
  | MITRE CAR analytic import (line 162) — overlaps SIGMA but adds
  | a different rule library + cleaner ATT&CK indexing.

Pure-Python parser; no subprocess. Reads from a directory of CAR
analytic files (override via `EL_CAR_DIR`, fall back to
`/opt/EL/rules/car/`).
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


_DEFAULT_CAR_DIR = Path("/opt/EL/rules/car/")
_TID_RE = re.compile(r"\bT\d{4}(?:\.\d+)?\b")


@dataclass
class CarAnalytic:
    car_id: str                        # e.g. "CAR-2014-04-001"
    title: str
    description: str = ""
    technique_ids: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    source_path: Path | None = None


def _car_dir() -> Path:
    env = os.environ.get("EL_CAR_DIR")
    if env:
        p = Path(env)
        if p.is_dir():
            return p
    return _DEFAULT_CAR_DIR


def is_car_available() -> bool:
    return _car_dir().is_dir()


def _parse_one(payload: dict, source_path: Path) -> CarAnalytic | None:
    car_id = (payload.get("id") or payload.get("car_id")
              or source_path.stem)
    title = payload.get("title") or payload.get("name") or ""
    description = (payload.get("description")
                   or payload.get("notes") or "")
    if not title:
        return None

    # Technique IDs may live in a "coverage" array (canonical CAR
    # format), in "technique" / "techniques" string-or-list fields,
    # or as literal `Txxxx` mentions in the description.
    tids: set[str] = set()
    for key in ("coverage", "techniques", "technique", "att&ck"):
        v = payload.get(key)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    t = item.get("technique") or item.get("id")
                    if isinstance(t, str):
                        tids.update(_TID_RE.findall(t))
                elif isinstance(item, str):
                    tids.update(_TID_RE.findall(item))
        elif isinstance(v, str):
            tids.update(_TID_RE.findall(v))
    tids.update(_TID_RE.findall(description))

    tactics_raw = payload.get("tactics") or payload.get("tactic") or []
    if isinstance(tactics_raw, str):
        tactics_raw = [tactics_raw]
    platforms = payload.get("platforms") or payload.get("platform") or []
    if isinstance(platforms, str):
        platforms = [platforms]

    return CarAnalytic(
        car_id=str(car_id), title=str(title),
        description=str(description),
        technique_ids=sorted(tids),
        tactics=[str(t) for t in tactics_raw if t],
        platforms=[str(p) for p in platforms if p],
        source_path=source_path,
    )


def load_analytics(car_dir: Path | None = None) -> list[CarAnalytic]:
    """Walk `car_dir` (default: $EL_CAR_DIR or /opt/EL/rules/car/)
    for `.json` / `.yaml` / `.yml` analytic files. Empty list when
    the directory is missing — keeps the skill optional."""
    root = Path(car_dir) if car_dir else _car_dir()
    if not root.is_dir():
        return []
    out: list[CarAnalytic] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        suffix = p.suffix.lower()
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        try:
            if suffix == ".json":
                payload = json.loads(text)
            elif suffix in (".yaml", ".yml"):
                try:
                    import yaml
                except ImportError:
                    continue
                payload = yaml.safe_load(text)
            else:
                continue
        except (json.JSONDecodeError, Exception):
            continue
        if not isinstance(payload, dict):
            continue
        analytic = _parse_one(payload, p)
        if analytic:
            out.append(analytic)
    return out


def coverage_for_techniques(
    technique_ids: list[str], car_dir: Path | None = None,
) -> dict[str, list[CarAnalytic]]:
    """Given the set of ATT&CK T-ids observed in a case, return
    {tid: [CarAnalytic, ...]} listing every loaded analytic that
    covers it. Empty dict when no analytics load."""
    analytics = load_analytics(car_dir)
    if not analytics:
        return {}
    tid_set = set(technique_ids)
    out: dict[str, list[CarAnalytic]] = {}
    for a in analytics:
        for tid in a.technique_ids:
            if tid in tid_set:
                out.setdefault(tid, []).append(a)
    for tid in out:
        out[tid].sort(key=lambda x: x.car_id)
    return out


__all__ = [
    "CarAnalytic",
    "is_car_available", "load_analytics", "coverage_for_techniques",
]
