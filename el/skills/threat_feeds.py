"""Skill: pull IOCs from MISP / TAXII servers into knowledge.sqlite.

Closes gap-doc Intel-depth bullet "MISP / TAXII feed integration into
knowledge.sqlite". The cross-case IOC lookup is the keystone of EL's
Layer-3 institutional knowledge; previously every row had to be born
from a real EL investigation. This skill lets operators seed the
table from authoritative external feeds so the *first* case to
encounter a known-bad indicator gets credit for the prior observation.

Two backends:

- **MISP** (REST API): ``POST /attributes/restSearch`` returns
  ``{response: {Attribute: [{value, type, category, comment, ...}]}}``.
  Auth via ``Authorization: <api-key>`` header. Map MISP attribute
  types to EL canonical IOC types (ip-src→ipv4, hostname→domain,
  md5/sha1/sha256→hash, url→url, …).

- **TAXII 2.x** (Collections + STIX 2 indicators):
  ``GET /collections/<id>/objects/`` returns a STIX bundle whose
  ``indicator`` SDOs carry a STIX pattern such as
  ``[file:hashes.MD5 = '...']`` or ``[ipv4-addr:value = '...']``.
  Pull the pattern objects, parse one IOC per pattern (the
  realistic subset — multi-clause patterns get logged but not
  exploded).

Cross-case contract preserved: feed rows are inserted under a
synthetic ``case_id`` of ``feed:misp:<server>`` or
``feed:taxii:<collection>``. ``lookup_iocs`` already filters
``case_id != current_case_id`` so feed observations surface as
prior context for any real case — they will NEVER score a
hypothesis (that's still Layer-1 / Layer-2 territory). They appear
in cross-case overlap Findings at ``confidence='low'`` exactly the
way another case's hits would.

Network calls are best-effort; binary failures (DNS, auth, TLS)
return ``FeedPullResult(ok=False, error=...)`` so the operator
sees the diagnostic but the rest of the investigation continues.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from el.knowledge import record_iocs


# MISP attribute-type → EL canonical IOC type. The full MISP list is
# ~150 types; this covers the ones the EL extractor produces, so a
# round-trip pull → record_iocs → lookup_iocs surfaces overlap on
# the same indicator key.
_MISP_TYPE_MAP = {
    "ip-src": "ipv4", "ip-dst": "ipv4",
    "ip-src|port": "ipv4", "ip-dst|port": "ipv4",
    "hostname": "domain", "domain": "domain",
    "domain|ip": "domain",
    "md5": "md5",
    "filename|md5": "md5",
    "sha1": "sha1",
    "filename|sha1": "sha1",
    "sha256": "sha256",
    "filename|sha256": "sha256",
    "url": "url", "uri": "url",
    "email-src": "email", "email-dst": "email", "email": "email",
}


@dataclass
class FeedIOC:
    value: str = ""
    ioc_type: str = ""              # ipv4 / domain / md5 / sha1 / sha256 / url / email
    source_type: str = ""           # raw MISP / STIX type for provenance
    source_label: str = ""          # e.g. event tag, indicator name


@dataclass
class FeedPullResult:
    backend: str = ""               # "misp" | "taxii"
    server: str = ""
    case_id: str = ""               # synthetic feed:<backend>:<server>
    iocs: list[FeedIOC] = field(default_factory=list)
    ok: bool = False
    error: str = ""
    rows_inserted: int = 0          # set by record() / pull_and_record()


# --- HTTP helper -----------------------------------------------------------


def _http_get(url: str, headers: dict[str, str],
               *, timeout: int = 30,
               body: bytes | None = None,
               method: str | None = None,
               verify_tls: bool = True) -> tuple[int, bytes]:
    """Minimal HTTP(S) GET/POST. Returns (status, body). Lets the
    caller decide TLS verification — internal MISP instances often
    self-sign."""
    req = urllib.request.Request(url, data=body, headers=headers,
                                 method=method or ("POST" if body else "GET"))
    ctx: ssl.SSLContext | None = None
    if not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                     context=ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b""


# --- MISP ------------------------------------------------------------------


def _normalise_misp_value(misp_type: str, raw: str) -> str:
    """``ip-src|port``, ``filename|md5`` etc carry both halves
    pipe-separated; we want the indicator side only."""
    if "|" in misp_type and "|" in raw:
        # The first half always corresponds to the first segment of
        # the type (ip / filename / domain). For type ``filename|md5``
        # we want the md5 — second segment. For ``ip-src|port`` we
        # want the ip — first segment.
        parts = raw.split("|", 1)
        if misp_type.startswith("filename"):
            return parts[1]
        return parts[0]
    return raw


def pull_misp(server_url: str, api_key: str,
               *, since_days: int | None = 30,
               limit: int = 5000,
               tags: list[str] | None = None,
               verify_tls: bool = True,
               timeout: int = 30) -> FeedPullResult:
    """Pull IOC attributes from a MISP server via the REST search
    endpoint.

    Parameters
    ----------
    server_url : base URL like ``https://misp.example.org``.
    api_key   : MISP automation key (Authorization header).
    since_days: server-side time filter (MISP ``last`` param).
    tags      : restrict to attributes whose event has any of these
                tags (e.g. ``["tlp:white", "ransomware"]``).
    verify_tls: set False for self-signed internal instances.

    Reads ``EL_MISP_URL`` / ``EL_MISP_KEY`` from env when the
    arguments are blank."""
    server_url = (server_url or os.environ.get("EL_MISP_URL", "")
                  ).rstrip("/")
    api_key = api_key or os.environ.get("EL_MISP_KEY", "")
    out = FeedPullResult(backend="misp", server=server_url,
                         case_id=f"feed:misp:{server_url}")
    if not server_url or not api_key:
        out.error = "missing server URL or API key"
        return out
    body = {"returnFormat": "json", "limit": limit,
            "type": list(_MISP_TYPE_MAP.keys())}
    if since_days is not None:
        body["last"] = f"{since_days}d"
    if tags:
        body["tags"] = tags
    headers = {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    url = f"{server_url}/attributes/restSearch"
    try:
        status, payload = _http_get(url, headers, body=json.dumps(body).encode(),
                                     timeout=timeout, verify_tls=verify_tls)
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        out.error = f"misp request failed: {e}"
        return out
    if status != 200:
        out.error = f"misp HTTP {status}"
        return out
    try:
        data = json.loads(payload.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        out.error = f"misp parse error: {e}"
        return out
    attrs = (data.get("response", {}).get("Attribute")
             or data.get("Attribute") or [])
    seen: set[tuple[str, str]] = set()
    for a in attrs:
        mt = a.get("type", "")
        et = _MISP_TYPE_MAP.get(mt)
        if not et:
            continue
        v = _normalise_misp_value(mt, a.get("value", "") or "")
        if not v:
            continue
        key = (et, v)
        if key in seen:
            continue
        seen.add(key)
        out.iocs.append(FeedIOC(
            value=v, ioc_type=et, source_type=mt,
            source_label=a.get("comment", "") or a.get("category", "")
        ))
    out.ok = True
    return out


# --- TAXII / STIX 2 --------------------------------------------------------

# Realistic single-clause patterns. STIX allows complex boolean
# expressions; this skill extracts the leaf indicator from the
# common shapes (the 95% case) and skips the rest. Multi-clause
# patterns can be widened later if a feed actually relies on them.
# Object path is one or more segments joined by ':' or '.'; each
# segment is either a bareword (word/hyphen) or a single-quoted
# token (OASIS uses ``file:hashes.'SHA-256'`` for hyphenated hash
# names). Value is single- or double-quoted.
_STIX_PATTERN_RE = re.compile(
    r"\[\s*((?:[\w-]+|'[^']+')(?:[:\.](?:[\w-]+|'[^']+'))*)"
    r"\s*=\s*['\"]([^'\"]+)['\"]")

_STIX_OBJ_TYPE_MAP = {
    "ipv4-addr:value": "ipv4",
    "ipv6-addr:value": "ipv6",
    "domain-name:value": "domain",
    "url:value": "url",
    "email-addr:value": "email",
    "file:hashes.md5": "md5",
    "file:hashes.MD5": "md5",
    "file:hashes.sha-1": "sha1",
    "file:hashes.SHA-1": "sha1",
    "file:hashes.'SHA-1'": "sha1",
    "file:hashes.sha-256": "sha256",
    "file:hashes.SHA-256": "sha256",
    "file:hashes.'SHA-256'": "sha256",
}


def _parse_stix_pattern(pattern: str) -> list[tuple[str, str, str]]:
    """Yield (object_path, value, ioc_type) for each leaf clause we
    recognise. Unrecognised paths are silently skipped."""
    out: list[tuple[str, str, str]] = []
    for path, value in _STIX_PATTERN_RE.findall(pattern or ""):
        et = _STIX_OBJ_TYPE_MAP.get(path)
        if not et:
            # Try a case-insensitive fallback for hash variants.
            et = _STIX_OBJ_TYPE_MAP.get(path.lower())
        if et and value:
            out.append((path, value, et))
    return out


def pull_taxii(discovery_url: str, collection_id: str,
                *, username: str | None = None,
                password: str | None = None,
                api_root: str = "api/v1",
                added_after: str | None = None,
                limit: int = 5000,
                verify_tls: bool = True,
                timeout: int = 60) -> FeedPullResult:
    """Pull STIX 2 indicators from a TAXII 2.x collection.

    ``discovery_url`` is the server base, e.g.
    ``https://taxii.example.org``. ``api_root`` is the per-server
    path prefix (defaults to ``api/v1`` which OASIS TAXII reference
    servers use). ``added_after`` filters to objects added after the
    ISO-8601 timestamp. Reads ``EL_TAXII_URL``, ``EL_TAXII_USER``,
    ``EL_TAXII_PASS``, ``EL_TAXII_COLLECTION`` from env when args
    omitted."""
    discovery_url = (discovery_url or os.environ.get("EL_TAXII_URL", "")
                     ).rstrip("/")
    collection_id = collection_id or os.environ.get(
        "EL_TAXII_COLLECTION", "")
    username = username if username is not None else \
        os.environ.get("EL_TAXII_USER")
    password = password if password is not None else \
        os.environ.get("EL_TAXII_PASS")
    out = FeedPullResult(backend="taxii", server=discovery_url,
                         case_id=f"feed:taxii:{collection_id}")
    if not discovery_url or not collection_id:
        out.error = "missing discovery URL or collection id"
        return out
    qs = f"?limit={limit}"
    if added_after:
        qs += f"&added_after={added_after}"
    url = (f"{discovery_url}/{api_root}/collections/"
           f"{collection_id}/objects/{qs}")
    headers = {"Accept": "application/taxii+json;version=2.1"}
    if username and password:
        import base64
        b = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {b}"
    try:
        status, payload = _http_get(url, headers, timeout=timeout,
                                     verify_tls=verify_tls)
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        out.error = f"taxii request failed: {e}"
        return out
    if status != 200:
        out.error = f"taxii HTTP {status}"
        return out
    try:
        data = json.loads(payload.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        out.error = f"taxii parse error: {e}"
        return out
    # TAXII 2.1: bundle-less envelope {"objects": [...], "more": bool}.
    # Older deployments wrap as a STIX bundle.
    objs = data.get("objects") or data.get("bundle", {}).get("objects") or []
    seen: set[tuple[str, str]] = set()
    for o in objs:
        if o.get("type") != "indicator":
            continue
        for path, value, et in _parse_stix_pattern(o.get("pattern", "")):
            key = (et, value)
            if key in seen:
                continue
            seen.add(key)
            out.iocs.append(FeedIOC(
                value=value, ioc_type=et, source_type=path,
                source_label=(o.get("name", "") or o.get("id", ""))
            ))
    out.ok = True
    return out


# --- record into knowledge.sqlite -----------------------------------------


def record(result: FeedPullResult,
            *, db_path: Path | None = None,
            agent: str = "threat_feeds") -> int:
    """Bulk-insert the pulled IOCs into knowledge.sqlite under the
    synthetic ``case_id`` (``feed:<backend>:<server>``). Returns
    count of newly-inserted rows. No-op when ``result.ok`` is False
    or the IOC list is empty."""
    if not result.ok or not result.iocs:
        return 0
    iocs: dict[str, list[str]] = {}
    for fi in result.iocs:
        iocs.setdefault(fi.ioc_type, []).append(fi.value)
    n = record_iocs(result.case_id, agent, iocs, db_path=db_path)
    result.rows_inserted = n
    return n


def pull_and_record(*, backend: str,
                     db_path: Path | None = None,
                     **kwargs) -> FeedPullResult:
    """End-to-end convenience: pull from ``misp`` or ``taxii`` and
    write to knowledge.sqlite in one call. ``kwargs`` flow through
    to the chosen pull function."""
    if backend == "misp":
        r = pull_misp(**kwargs)
    elif backend == "taxii":
        r = pull_taxii(**kwargs)
    else:
        return FeedPullResult(backend=backend,
                              error=f"unknown backend: {backend}")
    if r.ok:
        record(r, db_path=db_path)
    return r


__all__ = [
    "FeedIOC", "FeedPullResult",
    "pull_misp", "pull_taxii", "record", "pull_and_record",
]
