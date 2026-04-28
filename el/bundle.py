"""Bundle support — multi-device cases as a single investigation.

A bundle case is one investigation built from N pieces of evidence
(typically: laptop disk image + phone filesystem + network capture
from the same incident). Each device runs through the existing
single-host pipeline unchanged, then a synthesis pass merges the
per-device findings into a bundle-level ledger that scoring + the
executive report run against.

Layout:
    cases/<bundle-id>/
    ├── bundle.json              # this module's manifest
    ├── case_metadata.json       # bundle-level CaseMetadata (Phase 0)
    ├── findings.sqlite          # synthesised union of per-device ledgers
    ├── manifest.json            # aggregated input metadata
    ├── analysis/  exports/  reports/  raw/
    └── devices/
        ├── laptop/              # exactly the shape of a single-host case dir
        │   ├── manifest.json
        │   ├── findings.sqlite
        │   ├── analysis/  exports/  reports/  raw/
        │   └── …
        └── phone/  …

Layer-3 contract preservation: every device in the bundle shares
the bundle's case_id (passed through with a `:device` suffix on the
sub-case) so knowledge.sqlite continues to treat the bundle as one
case. Cross-bundle overlap (different bundle, different bundle_id)
stays "suggestive only" via the existing knowledge_lookup path.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field


BUNDLE_FILENAME = "bundle.json"
DEVICE_CASE_ID_SEP = ":"


class DeviceEntry(BaseModel):
    """One device inside a bundle. Mirrors the per-device CaseManifest
    plus a couple of post-investigation fields (leading_hypothesis,
    leading_score) populated after the per-device coordinator run."""

    name: str
    case_id: str            # bundle-id:device-name
    input_path: str
    input_size_bytes: int = 0
    input_sha256: str = ""
    case_dir: str           # cases/<bundle>/devices/<name>
    investigated_utc: datetime | None = None
    leading_hypothesis: str | None = None
    leading_score: int = 0


class BundleManifest(BaseModel):
    """Top-level manifest for a bundle case."""

    bundle_id: str
    intake_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    devices: list[DeviceEntry] = Field(default_factory=list)
    synthesized_utc: datetime | None = None
    # Fields below are populated by the synthesis pass after every
    # device has run through the coordinator — kept on the manifest
    # so the bundle's executive report can render without re-scoring.
    total_findings: int = 0
    leading_hypothesis: str | None = None
    leading_score: int = 0

    def device(self, name: str) -> DeviceEntry | None:
        return next((d for d in self.devices if d.name == name), None)


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def bundle_path(case_dir: Path | str) -> Path:
    return Path(case_dir) / BUNDLE_FILENAME


def is_bundle(case_dir: Path | str) -> bool:
    return bundle_path(case_dir).exists()


def device_dir(case_dir: Path | str, device_name: str) -> Path:
    return Path(case_dir) / "devices" / device_name


def make_device_case_id(bundle_id: str, device_name: str) -> str:
    """Compose a sub-case ID for a device. Bundle-aware code looks
    for the separator to identify which findings came from a bundle."""
    return f"{bundle_id}{DEVICE_CASE_ID_SEP}{device_name}"


def parse_device_case_id(case_id: str) -> tuple[str, str] | None:
    """Inverse of make_device_case_id. Returns (bundle_id, device_name)
    when the case_id has the bundle separator, None otherwise. Used
    by knowledge_lookup to recognise bundle sub-cases as part of one
    parent investigation."""
    if DEVICE_CASE_ID_SEP not in case_id:
        return None
    bundle_id, _, device_name = case_id.partition(DEVICE_CASE_ID_SEP)
    if not bundle_id or not device_name:
        return None
    return bundle_id, device_name


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save(case_dir: Path | str, manifest: BundleManifest) -> Path:
    p = bundle_path(case_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(manifest.model_dump_json(indent=2))
    return p


def load(case_dir: Path | str) -> BundleManifest | None:
    """Read bundle.json. Returns None when the case is not a bundle —
    callers can `if load(cd) is None: …` to short-circuit bundle-
    specific code paths on single-host cases."""
    p = bundle_path(case_dir)
    if not p.exists():
        return None
    return BundleManifest.model_validate_json(p.read_text())


# ---------------------------------------------------------------------------
# Layout creation
# ---------------------------------------------------------------------------

def create_bundle_layout(case_root: Path | str, bundle_id: str) -> Path:
    """Build the cases/<bundle-id>/ + standard subdirs + devices/ shell.
    Returns the bundle case_dir Path. Idempotent — safe to re-run on an
    existing bundle dir."""
    case_dir = Path(case_root) / bundle_id
    for sub in ("analysis", "exports", "reports", "raw", "devices"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    return case_dir


def create_device_layout(case_dir: Path | str, device_name: str) -> Path:
    """Build cases/<bundle-id>/devices/<device-name>/ + the standard
    case-dir subdirs the existing Coordinator expects to write into.
    Returns the device case_dir Path."""
    dd = device_dir(case_dir, device_name)
    for sub in ("analysis", "exports", "reports", "raw"):
        (dd / sub).mkdir(parents=True, exist_ok=True)
    return dd


# ---------------------------------------------------------------------------
# Aggregated manifest
# ---------------------------------------------------------------------------

def aggregate_manifest(bundle: BundleManifest, case_dir: Path | str) -> dict:
    """Build a top-level manifest.json for the bundle by aggregating
    per-device manifests. Mirrors the single-host CaseManifest shape
    where it can; uses a synthetic input_path/sha256 to make it clear
    the bundle has multiple sources."""
    case_dir = Path(case_dir)
    total_size = sum(d.input_size_bytes for d in bundle.devices)
    return {
        "case_id": bundle.bundle_id,
        "intake_utc": bundle.intake_utc.isoformat(),
        "input_path": f"<bundle: {len(bundle.devices)} device(s)>",
        "input_size_bytes": total_size,
        "input_sha256": "",   # bundles don't have a single sha
        "input_sha1": "",
        "input_md5": "",
        "input_magic": "bundle",
        "case_dir": str(case_dir.resolve()),
        "device_count": len(bundle.devices),
        "devices": [
            {"name": d.name, "case_id": d.case_id,
             "input_path": d.input_path,
             "input_sha256": d.input_sha256,
             "size_bytes": d.input_size_bytes}
            for d in bundle.devices
        ],
    }


def write_aggregated_manifest(bundle: BundleManifest, case_dir: Path | str) -> Path:
    """Write cases/<bundle-id>/manifest.json so existing report
    machinery (which reads manifest.json for the case-glance section)
    works on bundles too."""
    p = Path(case_dir) / "manifest.json"
    p.write_text(json.dumps(aggregate_manifest(bundle, case_dir), indent=2))
    return p


__all__ = [
    "BundleManifest",
    "DeviceEntry",
    "BUNDLE_FILENAME",
    "bundle_path",
    "is_bundle",
    "device_dir",
    "make_device_case_id",
    "parse_device_case_id",
    "save",
    "load",
    "create_bundle_layout",
    "create_device_layout",
    "aggregate_manifest",
    "write_aggregated_manifest",
]
