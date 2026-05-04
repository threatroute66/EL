"""Timesketch push skill — collaborative super-timeline review.

Uploads Plaso `.plaso` storage files (produced by `el.skills.plaso.log2timeline`)
to a configured Timesketch instance for collaborative analyst review.

Opt-in via environment variables:
    EL_TIMESKETCH_URL       (required) — e.g. https://timesketch.example.org
    EL_TIMESKETCH_TOKEN     (preferred) — API token (Timesketch >= 20240407)
    EL_TIMESKETCH_USERNAME  (alternative) — pair with EL_TIMESKETCH_PASSWORD
    EL_TIMESKETCH_PASSWORD  (alternative)
    EL_TIMESKETCH_VERIFY    (optional)  — set to '0' to disable TLS verification

When none of the above are set the skill returns a result with
``configured=False`` and the agent emits a single insufficient Finding —
no upload attempt, no errors. This is by design: Timesketch push is a
"close-the-loop" workflow integration, not core forensic analysis.

Project: https://timesketch.org
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class TimesketchError(Exception):
    pass


@dataclass
class TimesketchUpload:
    plaso_path: Path
    sketch_name: str
    sketch_id: int | None = None
    sketch_url: str | None = None
    timeline_id: int | None = None
    timeline_name: str | None = None
    configured: bool = True
    server_url: str = ""
    duration_seconds: float = 0.0
    plaso_size_bytes: int = 0
    plaso_sha256: str = ""
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="timesketch",
            version="20260312",
            command=f"timesketch upload {self.plaso_path.name} → "
                     f"sketch={self.sketch_name}",
            output_sha256=self.plaso_sha256 or ("0" * 64),
            output_path=self.sketch_url or str(self.plaso_path),
            extracted_facts={
                "configured": self.configured,
                "server_url": self.server_url,
                "sketch_name": self.sketch_name,
                "sketch_id": self.sketch_id,
                "sketch_url": self.sketch_url,
                "timeline_id": self.timeline_id,
                "timeline_name": self.timeline_name,
                "plaso_size_bytes": self.plaso_size_bytes,
                "duration_seconds": round(self.duration_seconds, 2),
                "note": self.note,
                **extra,
            },
        )


def is_configured() -> bool:
    """Whether enough env vars are set to attempt an upload."""
    if not os.environ.get("EL_TIMESKETCH_URL"):
        return False
    if os.environ.get("EL_TIMESKETCH_TOKEN"):
        return True
    if (os.environ.get("EL_TIMESKETCH_USERNAME")
            and os.environ.get("EL_TIMESKETCH_PASSWORD")):
        return True
    return False


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_client(server_url: str):
    """Construct an authenticated Timesketch API client from env vars.

    Imports lazily so the rest of EL doesn't pull in timesketch-api-client
    when nobody has configured Timesketch.
    """
    from timesketch_api_client import client as ts_client  # type: ignore

    verify = os.environ.get("EL_TIMESKETCH_VERIFY", "1") != "0"
    token = os.environ.get("EL_TIMESKETCH_TOKEN")
    if token:
        # Token-based auth (Timesketch >= 20240407)
        return ts_client.TimesketchApi(
            host_uri=server_url,
            username=os.environ.get("EL_TIMESKETCH_USERNAME", "el"),
            api_token=token,
            verify=verify,
            auth_mode="userpass",  # token sent via Authorization header
        )
    # Username + password fallback
    return ts_client.TimesketchApi(
        host_uri=server_url,
        username=os.environ["EL_TIMESKETCH_USERNAME"],
        password=os.environ["EL_TIMESKETCH_PASSWORD"],
        verify=verify,
        auth_mode="userpass",
    )


def _get_or_create_sketch(api, sketch_name: str):
    """Find a sketch with *sketch_name* (newest first) or create one."""
    # Newer client returns Sketch objects via .list_sketches(); iterate
    # to find by name. If absent, .create_sketch().
    try:
        for sketch in api.list_sketches():
            try:
                if sketch.name == sketch_name:
                    return sketch
            except Exception:
                continue
    except Exception:
        # If listing fails, fall through to creation attempt — better
        # than dying on a transient sketch-list error.
        pass
    return api.create_sketch(name=sketch_name,
                              description=f"EL case: {sketch_name}")


def push(plaso_path: Path,
          sketch_name: str,
          *,
          timeline_name: str | None = None,
          timeout_seconds: int = 1800) -> TimesketchUpload:
    """Upload a .plaso file to a Timesketch sketch.

    Args:
        plaso_path: produced by ``plaso.log2timeline()``.
        sketch_name: the Timesketch sketch to upload into. Created if absent.
        timeline_name: name for the timeline within the sketch
            (defaults to plaso file stem).
        timeout_seconds: upper bound on the upload + index wait.

    Returns a :class:`TimesketchUpload`. When env vars are missing, returns
    one with ``configured=False`` and a note — never raises.
    """
    plaso_path = Path(plaso_path)
    if not plaso_path.is_file():
        raise TimesketchError(f"plaso file not found: {plaso_path}")

    server_url = os.environ.get("EL_TIMESKETCH_URL", "")
    if not is_configured():
        return TimesketchUpload(
            plaso_path=plaso_path,
            sketch_name=sketch_name,
            configured=False,
            server_url=server_url,
            plaso_size_bytes=plaso_path.stat().st_size,
            note=("EL_TIMESKETCH_URL + (EL_TIMESKETCH_TOKEN or "
                  "EL_TIMESKETCH_USERNAME+PASSWORD) not set — Timesketch "
                  "push is opt-in"),
        )

    timeline_name = timeline_name or plaso_path.stem
    started = time.time()
    plaso_sha256 = _sha256_file(plaso_path)
    plaso_size = plaso_path.stat().st_size

    try:
        from timesketch_import_client import importer  # type: ignore
    except ImportError as e:
        raise TimesketchError(
            f"timesketch-import-client not installed: {e}"
        )

    try:
        api = _build_client(server_url)
    except Exception as e:
        raise TimesketchError(f"Timesketch authentication failed: {e}")

    try:
        sketch = _get_or_create_sketch(api, sketch_name)
    except Exception as e:
        raise TimesketchError(f"sketch lookup/create failed: {e}")

    try:
        with importer.ImportStreamer() as streamer:
            streamer.set_sketch(sketch)
            streamer.set_timeline_name(timeline_name)
            streamer.set_timestamp_description("plaso_event")
            streamer.add_file(str(plaso_path))
            timeline = streamer.timeline
    except Exception as e:
        raise TimesketchError(f"upload failed: {e}")

    duration = time.time() - started
    sketch_id = getattr(sketch, "id", None)
    sketch_url = (
        f"{server_url.rstrip('/')}/sketch/{sketch_id}" if sketch_id else None
    )
    timeline_id = getattr(timeline, "id", None) if timeline else None

    return TimesketchUpload(
        plaso_path=plaso_path,
        sketch_name=sketch_name,
        sketch_id=sketch_id,
        sketch_url=sketch_url,
        timeline_id=timeline_id,
        timeline_name=timeline_name,
        configured=True,
        server_url=server_url,
        duration_seconds=duration,
        plaso_size_bytes=plaso_size,
        plaso_sha256=plaso_sha256,
    )
