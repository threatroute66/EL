"""CAPE Sandbox REST API client — dynamic malware analysis (Cuckoo successor).

Wraps a configured CAPEv2 instance for dynamic-analysis submission of
suspicious binaries from a case's ``exports/``. Cuckoo went EOL in 2024;
CAPE is the OSS successor with active development (CAPE Sandbox, kevoreilly).

**Strictly opt-in** via env vars:
    EL_CAPE_URL      (required) — e.g. https://cape.internal.lab
    EL_CAPE_TOKEN    (preferred) — REST API token (Authorization header)
    EL_CAPE_VERIFY   (optional) — '0' to disable TLS verification

Without these set, the skill returns ``CAPESubmission(configured=False)`` and
the caller emits a single insufficient finding. CAPE submission is heavy
(5-10 minutes per sample); production callers should NOT block waiting for
completion synchronously — submit and capture the task ID, then poll later
via ``get_report()`` if results are available.

Project: https://github.com/kevoreilly/CAPEv2
REST API docs: https://capev2.readthedocs.io/en/latest/usage/api.html
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class CAPEError(Exception):
    pass


def is_configured() -> bool:
    return bool(os.environ.get("EL_CAPE_URL"))


def _server_url() -> str:
    url = os.environ.get("EL_CAPE_URL", "").rstrip("/")
    if not url:
        raise CAPEError("EL_CAPE_URL not set")
    return url


def _auth_headers() -> dict:
    """Return the Authorization headers if a token is configured."""
    token = os.environ.get("EL_CAPE_TOKEN")
    if token:
        return {"Authorization": f"Token {token}"}
    return {}


def _verify_ssl() -> bool:
    return os.environ.get("EL_CAPE_VERIFY", "1") != "0"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class CAPESubmission:
    """Result of a single-file submission to the CAPE API."""
    file_path: Path
    file_sha256: str
    task_id: int | None = None
    server_url: str = ""
    configured: bool = True
    duration_seconds: float = 0.0
    response_text: str = ""
    rc: int = 0
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="cape",
            version="capev2-rest",
            command=f"POST {self.server_url}/apiv2/tasks/create/file/ "
                     f"file={self.file_path.name}",
            output_sha256=self.file_sha256 or ("0" * 64),
            output_path=(f"{self.server_url}/submit/status/{self.task_id}"
                         if self.task_id else str(self.file_path)),
            extracted_facts={
                "configured": self.configured,
                "server_url": self.server_url,
                "task_id": self.task_id,
                "file_sha256": self.file_sha256,
                "file_size_bytes": self.file_path.stat().st_size
                                     if self.file_path.is_file() else 0,
                "duration_seconds": round(self.duration_seconds, 2),
                "note": self.note,
                **extra,
            },
        )


@dataclass
class CAPEReport:
    """A parsed CAPE analysis report (JSON) for one task."""
    task_id: int
    server_url: str
    status: str = ""              # e.g. "reported" / "running" / "pending"
    score: float = 0.0            # CAPE 0-10 maliciousness score
    family: str = ""              # detected malware family if identified
    signatures: list[str] = field(default_factory=list)
    behavior_summary: dict = field(default_factory=dict)
    raw_report_path: Path | None = None
    duration_seconds: float = 0.0
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        sha = "0" * 64
        if self.raw_report_path and self.raw_report_path.is_file():
            sha = _sha256_file(self.raw_report_path)
        return EvidenceItem(
            tool="cape",
            version="capev2-rest",
            command=f"GET {self.server_url}/apiv2/tasks/get/report/"
                     f"{self.task_id}/",
            output_sha256=sha,
            output_path=str(self.raw_report_path
                              or f"{self.server_url}/analysis/{self.task_id}/"),
            extracted_facts={
                "task_id": self.task_id,
                "status": self.status,
                "score": self.score,
                "family": self.family,
                "signature_count": len(self.signatures),
                "signatures": self.signatures[:25],
                "note": self.note,
                **extra,
            },
        )


def _http_request(method: str, url: str, *,
                   headers: dict | None = None,
                   data: bytes | None = None,
                   timeout: int = 30):
    """Minimal urllib wrapper (no requests dep) honouring EL_CAPE_VERIFY."""
    import ssl
    req = urllib.request.Request(url, method=method, data=data,
                                    headers=headers or {})
    ctx = None
    if not _verify_ssl():
        ctx = ssl._create_unverified_context()
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def submit_file(file_path: Path,
                *, package: str = "",
                machine: str = "",
                timeout_minutes: int = 5,
                http_timeout_seconds: int = 60) -> CAPESubmission:
    """Submit *file_path* to CAPE for dynamic analysis.

    Returns a :class:`CAPESubmission` with a ``task_id`` on success. Does NOT
    wait for the analysis to complete — call :func:`get_report` later.

    Args:
        file_path: a binary already extracted to disk by EL (case exports/).
        package: optional CAPE analysis package (e.g. 'exe', 'pdf', 'office').
        machine: optional CAPE VM machine name.
        timeout_minutes: passed to CAPE as the analysis timeout (server-side).
        http_timeout_seconds: cap on the upload HTTP call itself.
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        raise CAPEError(f"file not found: {file_path}")

    if not is_configured():
        return CAPESubmission(
            file_path=file_path,
            file_sha256=_sha256_file(file_path),
            configured=False,
            note=("EL_CAPE_URL not set — CAPE Sandbox submission is opt-in"),
        )

    started = time.time()
    server = _server_url()
    file_sha = _sha256_file(file_path)

    # Multipart form upload via stdlib (no requests dep).
    boundary = f"---el-cape-{int(time.time()*1000)}"
    payload_parts: list[bytes] = []
    file_bytes = file_path.read_bytes()
    payload_parts.append(
        f"--{boundary}\r\n".encode()
        + (f'Content-Disposition: form-data; name="file"; '
           f'filename="{file_path.name}"\r\n'
           f'Content-Type: application/octet-stream\r\n\r\n').encode()
        + file_bytes
        + b"\r\n"
    )
    if package:
        payload_parts.append(
            f"--{boundary}\r\n".encode()
            + b'Content-Disposition: form-data; name="package"\r\n\r\n'
            + package.encode() + b"\r\n"
        )
    if machine:
        payload_parts.append(
            f"--{boundary}\r\n".encode()
            + b'Content-Disposition: form-data; name="machine"\r\n\r\n'
            + machine.encode() + b"\r\n"
        )
    payload_parts.append(
        f"--{boundary}\r\n".encode()
        + b'Content-Disposition: form-data; name="timeout"\r\n\r\n'
        + str(timeout_minutes * 60).encode() + b"\r\n"
    )
    payload_parts.append(f"--{boundary}--\r\n".encode())
    payload = b"".join(payload_parts)

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(payload)),
        **_auth_headers(),
    }
    url = f"{server}/apiv2/tasks/create/file/"
    try:
        with _http_request("POST", url, headers=headers, data=payload,
                            timeout=http_timeout_seconds) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            rc = resp.getcode()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        raise CAPEError(f"submission failed: {e}")

    duration = time.time() - started
    task_id = None
    try:
        data = json.loads(body)
        task_id = (data.get("data", {}).get("task_ids", [None])[0]
                   or data.get("task_id")
                   or data.get("data"))
        if isinstance(task_id, dict):
            task_id = task_id.get("task_ids", [None])[0]
        if task_id is not None:
            task_id = int(task_id)
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    return CAPESubmission(
        file_path=file_path,
        file_sha256=file_sha,
        task_id=task_id,
        server_url=server,
        configured=True,
        duration_seconds=duration,
        response_text=body[:4096],
        rc=rc,
        note=("submitted; poll get_report() later — CAPE analysis takes "
               "minutes")
            if task_id else "submission accepted but no task_id parsed",
    )


def get_report(task_id: int,
                *, save_dir: Path | None = None,
                http_timeout_seconds: int = 60) -> CAPEReport:
    """Fetch and parse the CAPE report JSON for *task_id*.

    Args:
        task_id: returned by :func:`submit_file`.
        save_dir: if given, raw report JSON is written here for evidence.
        http_timeout_seconds: cap on the HTTP fetch.
    """
    if not is_configured():
        raise CAPEError("EL_CAPE_URL not set")
    started = time.time()
    server = _server_url()
    url = f"{server}/apiv2/tasks/get/report/{task_id}/"
    try:
        with _http_request("GET", url, headers=_auth_headers(),
                            timeout=http_timeout_seconds) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            rc = resp.getcode()
    except urllib.error.HTTPError as e:
        # 404 commonly means "still running"; surface as note rather than raise.
        return CAPEReport(
            task_id=task_id, server_url=server, status="not-ready",
            duration_seconds=time.time() - started,
            note=f"HTTP {e.code} from CAPE — analysis may not be complete yet",
        )
    except (urllib.error.URLError, OSError) as e:
        raise CAPEError(f"report fetch failed: {e}")

    raw_path = None
    if save_dir is not None:
        save_dir.mkdir(parents=True, exist_ok=True)
        raw_path = save_dir / f"cape_report_{task_id}.json"
        raw_path.write_text(body)

    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        return CAPEReport(
            task_id=task_id, server_url=server, status="parse-error",
            duration_seconds=time.time() - started, raw_report_path=raw_path,
            note=f"CAPE returned non-JSON body: {e}",
        )

    info = (data.get("info") or {}) if isinstance(data, dict) else {}
    sigs = data.get("signatures") if isinstance(data, dict) else None
    sig_names: list[str] = []
    if isinstance(sigs, list):
        for s in sigs:
            if isinstance(s, dict):
                name = s.get("name") or s.get("description") or ""
                if name:
                    sig_names.append(str(name)[:200])

    family = ""
    detections = data.get("detections") if isinstance(data, dict) else None
    if isinstance(detections, list) and detections:
        first = detections[0]
        if isinstance(first, dict):
            family = str(first.get("family") or first.get("name") or "")[:80]

    score = 0.0
    raw_score = data.get("score") if isinstance(data, dict) else None
    if isinstance(raw_score, (int, float)):
        score = float(raw_score)
    elif isinstance(info.get("score"), (int, float)):
        score = float(info["score"])

    behavior = data.get("behavior") if isinstance(data, dict) else None
    behavior_summary: dict = {}
    if isinstance(behavior, dict):
        summary = behavior.get("summary") or {}
        if isinstance(summary, dict):
            behavior_summary = {
                k: (len(v) if isinstance(v, list) else v)
                for k, v in list(summary.items())[:20]
            }

    return CAPEReport(
        task_id=task_id, server_url=server,
        status=str(info.get("status") or "reported"),
        score=score,
        family=family,
        signatures=sig_names,
        behavior_summary=behavior_summary,
        raw_report_path=raw_path,
        duration_seconds=time.time() - started,
    )


def wait_for_completion(task_id: int,
                          *, max_wait_seconds: int = 600,
                          poll_interval_seconds: int = 15) -> bool:
    """Block-poll CAPE for task completion. Returns True when reported."""
    if not is_configured():
        raise CAPEError("EL_CAPE_URL not set")
    server = _server_url()
    deadline = time.time() + max_wait_seconds
    while time.time() < deadline:
        url = f"{server}/apiv2/tasks/status/{task_id}/"
        try:
            with _http_request("GET", url, headers=_auth_headers(),
                                timeout=20) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            time.sleep(poll_interval_seconds)
            continue
        try:
            data = json.loads(body)
            status = (data.get("data") or data.get("status") or "")
            if isinstance(status, str) and status.lower() in ("reported", "completed"):
                return True
        except json.JSONDecodeError:
            pass
        time.sleep(poll_interval_seconds)
    return False
