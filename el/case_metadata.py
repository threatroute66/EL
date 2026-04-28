"""Case metadata — analyst/stakeholder annotations on top of the
deterministic intake manifest.

`manifest.json` records WHAT was intaken (paths, hashes, sizes).
`case_metadata.json` records WHO is investigating, WHY, and WHAT
question the investigation is supposed to answer.

All fields are optional with sensible defaults so existing intake
flows keep working unchanged. The non-expert ("executive") report
uses these fields to populate Case Details, Objective & Scope, and
investigator attribution sections; if a field is None, the renderer
falls back to a neutral placeholder rather than failing.

The file lives at cases/<id>/case_metadata.json and is picked up by
seal.py automatically (it walks the whole case dir), so any change
to metadata between investigations alters the case's merkle root.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field


CASE_METADATA_FILENAME = "case_metadata.json"


class CaseMetadata(BaseModel):
    """Analyst-supplied case context. All fields optional."""

    case_number: str | None = None
    incident_date: date | None = None
    investigator_name: str | None = None
    objective_statement: str | None = None
    created_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def is_empty(self) -> bool:
        """True when no analyst-supplied fields are populated.
        Renderers can use this to suppress empty Case Details sections."""
        return not any([
            self.case_number,
            self.incident_date,
            self.investigator_name,
            self.objective_statement,
        ])


def path_for(case_dir: Path | str) -> Path:
    return Path(case_dir) / CASE_METADATA_FILENAME


def save(case_dir: Path | str, metadata: CaseMetadata) -> Path:
    """Write metadata to cases/<id>/case_metadata.json. Returns the path."""
    p = path_for(case_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(metadata.model_dump_json(indent=2))
    return p


def load(case_dir: Path | str) -> CaseMetadata:
    """Read metadata from cases/<id>/case_metadata.json.
    Returns an empty CaseMetadata if the file is missing — case_metadata
    is optional, so absence is normal for cases created before this
    feature shipped or for non-attributed runs (e.g., CTF practice)."""
    p = path_for(case_dir)
    if not p.exists():
        return CaseMetadata()
    return CaseMetadata.model_validate_json(p.read_text())
