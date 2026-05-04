"""TI push — submit per-case STIX 2.1 bundle to OpenCTI / MISP.

Closes the analyst-review loop: when EL finishes a case it already writes a
``reports/stix-bundle.json``. This skill optionally posts that bundle to a
configured OpenCTI or MISP instance so the org's threat-intel platform
sees EL findings without manual transformation.

**Strictly opt-in** — no env config means no push attempt, no errors.

OpenCTI auth (preferred for graph-relationship preservation):
    EL_OPENCTI_URL    — e.g. https://opencti.internal.lab
    EL_OPENCTI_TOKEN  — API token

MISP auth:
    EL_MISP_URL       — e.g. https://misp.internal.lab
    EL_MISP_KEY       — API key
    EL_MISP_VERIFY    — '0' to disable TLS verification (self-signed)

Both can be configured simultaneously — push() returns one TIPushResult per
target. The forensic chain stays linear: case → STIX → TIP. EL does NOT pull
*from* the TIP back into the per-case findings ledger (that would re-open
the Layer-3 boundary documented in CLAUDE.md).

Projects:
  - OpenCTI: https://github.com/OpenCTI-Platform/opencti
  - MISP:    https://github.com/MISP/MISP
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class TIPushError(Exception):
    pass


@dataclass
class TIPushResult:
    target: str                    # "opencti" or "misp"
    server_url: str
    bundle_path: Path
    bundle_sha256: str
    configured: bool = True
    rc: int = 0
    duration_seconds: float = 0.0
    indicator_count: int = 0
    misp_event_id: int | None = None
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool=f"ti_push.{self.target}",
            version="1.0",
            command=(f"POST {self.server_url} bundle={self.bundle_path.name} "
                     f"({self.bundle_sha256[:12]}...)"),
            output_sha256=self.bundle_sha256 or ("0" * 64),
            output_path=str(self.bundle_path),
            extracted_facts={
                "target": self.target,
                "server_url": self.server_url,
                "configured": self.configured,
                "rc": self.rc,
                "indicator_count": self.indicator_count,
                "misp_event_id": self.misp_event_id,
                "duration_seconds": round(self.duration_seconds, 2),
                "note": self.note,
                **extra,
            },
        )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _count_indicators(bundle_path: Path) -> int:
    """Best-effort: count `indicator` SDOs in a STIX 2.1 bundle."""
    try:
        data = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    objs = data.get("objects") if isinstance(data, dict) else None
    if not isinstance(objs, list):
        return 0
    return sum(1 for o in objs if isinstance(o, dict)
               and o.get("type") == "indicator")


# --- OpenCTI submission ---------------------------------------------------

def opencti_configured() -> bool:
    return bool(os.environ.get("EL_OPENCTI_URL")
                and os.environ.get("EL_OPENCTI_TOKEN"))


def push_to_opencti(bundle_path: Path,
                     *, timeout_seconds: int = 300) -> TIPushResult:
    """Submit *bundle_path* (a STIX 2.1 JSON file) to a configured OpenCTI.

    Uses pycti's BundlesSendingProcessor — the canonical async-friendly
    upload path. We block for completion (or *timeout_seconds*) so the
    coordinator can emit a meaningful finding.
    """
    bundle_path = Path(bundle_path)
    if not bundle_path.is_file():
        raise TIPushError(f"STIX bundle not found: {bundle_path}")

    server = os.environ.get("EL_OPENCTI_URL", "").rstrip("/")
    token = os.environ.get("EL_OPENCTI_TOKEN", "")
    sha = _sha256_file(bundle_path)
    indicator_count = _count_indicators(bundle_path)

    if not opencti_configured():
        return TIPushResult(
            target="opencti", server_url=server, bundle_path=bundle_path,
            bundle_sha256=sha, configured=False, rc=0,
            indicator_count=indicator_count,
            note=("EL_OPENCTI_URL + EL_OPENCTI_TOKEN not set — push is opt-in"),
        )

    started = time.time()
    try:
        from pycti import OpenCTIApiClient  # type: ignore
    except ImportError as e:
        raise TIPushError(f"pycti not installed: {e}")

    try:
        client = OpenCTIApiClient(url=server, token=token, log_level="error")
    except Exception as e:
        raise TIPushError(f"OpenCTI client init failed: {e}")

    try:
        bundle_text = bundle_path.read_text(encoding="utf-8")
    except OSError as e:
        raise TIPushError(f"bundle read failed: {e}")

    try:
        # send_stix2_bundle returns the list of created object IDs (or
        # raises on non-recoverable errors). Newer pycti versions also
        # support `update=True` for upserts.
        client.stix2.import_bundle_from_json(
            bundle_text,
            update=True,
        )
        rc = 0
        note = (f"submitted {indicator_count} indicator(s); "
                "OpenCTI applied the bundle synchronously")
    except Exception as e:
        rc = 1
        note = f"OpenCTI import_bundle_from_json failed: {e}"

    return TIPushResult(
        target="opencti", server_url=server, bundle_path=bundle_path,
        bundle_sha256=sha, configured=True, rc=rc,
        duration_seconds=time.time() - started,
        indicator_count=indicator_count, note=note,
    )


# --- MISP submission ------------------------------------------------------

def misp_configured() -> bool:
    return bool(os.environ.get("EL_MISP_URL")
                and os.environ.get("EL_MISP_KEY"))


def push_to_misp(bundle_path: Path,
                  *, event_info: str = "",
                  timeout_seconds: int = 300) -> TIPushResult:
    """Submit *bundle_path* (a STIX 2.1 JSON file) to a configured MISP.

    MISP's STIX2 import is a synchronous endpoint (``/events/upload_stix/2``)
    that returns the created event ID. We capture that into the result so
    the operator can deep-link from the EL finding.

    Args:
        bundle_path: STIX 2.1 JSON bundle.
        event_info: optional info-string for the new MISP event (defaults
            to the bundle filename).
        timeout_seconds: HTTP timeout.
    """
    bundle_path = Path(bundle_path)
    if not bundle_path.is_file():
        raise TIPushError(f"STIX bundle not found: {bundle_path}")

    server = os.environ.get("EL_MISP_URL", "").rstrip("/")
    key = os.environ.get("EL_MISP_KEY", "")
    verify = os.environ.get("EL_MISP_VERIFY", "1") != "0"
    sha = _sha256_file(bundle_path)
    indicator_count = _count_indicators(bundle_path)

    if not misp_configured():
        return TIPushResult(
            target="misp", server_url=server, bundle_path=bundle_path,
            bundle_sha256=sha, configured=False, rc=0,
            indicator_count=indicator_count,
            note=("EL_MISP_URL + EL_MISP_KEY not set — push is opt-in"),
        )

    started = time.time()
    try:
        from pymisp import PyMISP  # type: ignore
    except ImportError as e:
        raise TIPushError(f"pymisp not installed: {e}")

    try:
        client = PyMISP(url=server, key=key, ssl=verify, timeout=timeout_seconds)
    except Exception as e:
        raise TIPushError(f"MISP client init failed: {e}")

    info = event_info or f"EL case bundle {bundle_path.name}"
    try:
        # PyMISP's upload_stix() takes a file path AND a stix version.
        resp = client.upload_stix(path=str(bundle_path), version="2")
        # Response shape varies across MISP versions — robustly extract
        # the event id wherever it lands.
        event_id = None
        if isinstance(resp, dict):
            if "Event" in resp and isinstance(resp["Event"], dict):
                event_id = int(resp["Event"].get("id") or 0) or None
            elif "id" in resp:
                try:
                    event_id = int(resp["id"])
                except (TypeError, ValueError):
                    event_id = None
        rc = 0
        note = (f"event {event_id} created with {indicator_count} "
                f"indicator(s)" if event_id else
                f"upload accepted ({indicator_count} indicators) "
                "but no event_id parsed")
    except Exception as e:
        event_id = None
        rc = 1
        note = f"PyMISP upload_stix failed: {e}"

    return TIPushResult(
        target="misp", server_url=server, bundle_path=bundle_path,
        bundle_sha256=sha, configured=True, rc=rc,
        duration_seconds=time.time() - started,
        indicator_count=indicator_count,
        misp_event_id=event_id, note=note,
    )


# --- Combined dispatch ---------------------------------------------------

def push_all(bundle_path: Path,
              *, event_info: str = "") -> list[TIPushResult]:
    """Push to whichever TIPs are configured. Returns one result per target."""
    out: list[TIPushResult] = []
    if opencti_configured():
        try:
            out.append(push_to_opencti(bundle_path))
        except TIPushError as e:
            sha = _sha256_file(bundle_path) if bundle_path.is_file() else ""
            out.append(TIPushResult(
                target="opencti",
                server_url=os.environ.get("EL_OPENCTI_URL", ""),
                bundle_path=bundle_path, bundle_sha256=sha,
                configured=True, rc=2, note=str(e),
            ))
    if misp_configured():
        try:
            out.append(push_to_misp(bundle_path, event_info=event_info))
        except TIPushError as e:
            sha = _sha256_file(bundle_path) if bundle_path.is_file() else ""
            out.append(TIPushResult(
                target="misp",
                server_url=os.environ.get("EL_MISP_URL", ""),
                bundle_path=bundle_path, bundle_sha256=sha,
                configured=True, rc=2, note=str(e),
            ))
    return out


def any_configured() -> bool:
    return opencti_configured() or misp_configured()
