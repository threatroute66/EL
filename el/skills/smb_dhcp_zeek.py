"""Skill: SMB2 file-write + DHCP option-55 fingerprint detectors over
Zeek logs.

Closes two gap-doc Network-depth bullets:
- "SMB2 write-operation detection — lateral file-staging visibility" (line 149)
- "DHCP option 55 fingerprinting — device discovery from DHCP leases" (line 150)

Both ride on Zeek's existing per-protocol log files:
- ``smb_files.log`` columns: ts, uid, action, path, size, prev_name
  (the ``action`` value is one of SMB::FILE_OPEN / FILE_WRITE /
  FILE_CLOSE / FILE_DELETE / FILE_RENAME — we filter to writes).
- ``dhcp.log`` ``client_fqdn`` + ``params_list`` (option 55) columns.

Pure-text TSV readers; no scapy. Both skills return per-record
dataclasses ``MatchHit`` ready for the network_analyst to emit as
Findings.
"""
from __future__ import annotations

import csv
import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SmbWriteHit:
    src: str = ""                       # source IP (id.orig_h)
    dst: str = ""                       # SMB share host (id.resp_h)
    user: str = ""
    path: str = ""                      # file path on the share
    size: int = 0
    action: str = ""                    # FILE_WRITE / FILE_RENAME / FILE_DELETE


@dataclass
class DhcpFingerprint:
    src_mac: str = ""
    src_ip: str = ""
    client_fqdn: str = ""
    params_list: str = ""               # comma-joined option-55 codes
    likely_os: str = ""                 # heuristic guess


def _read_zeek_tsv(path: Path):
    """Stream Zeek's TSV with `#fields` header. Yields dicts."""
    if not path.is_file():
        return
    with path.open("r", errors="replace") as f:
        fields: list[str] = []
        for raw in f:
            line = raw.rstrip("\r\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if not fields:
                continue
            cols = line.split("\t")
            if len(cols) < len(fields):
                continue
            yield dict(zip(fields, cols))


# --- SMB2 write detector ----------------------------------------------------

_SMB_WRITE_ACTIONS = (
    "SMB::FILE_WRITE", "SMB::FILE_RENAME", "SMB::FILE_DELETE",
    "SMB::FILE_SET_INFO",
)


def detect_smb_writes(zeek_dir: Path,
                       *, min_count: int = 1,
                       max_hits: int = 200) -> list[SmbWriteHit]:
    """Read smb_files.log and surface FILE_WRITE / FILE_RENAME /
    FILE_DELETE rows. Lateral movement leaves a trail of SMB writes
    to ADMIN$ / C$ / IPC$ — those rows are the smoking gun the EVTX
    side sometimes misses.

    `min_count` lets the caller require N+ writes per (src,dst) pair
    before reporting (filters out one-off OS-driven writes); default
    1 emits everything for the agent to aggregate further.
    """
    p = Path(zeek_dir) / "smb_files.log"
    out: list[SmbWriteHit] = []
    if not p.is_file():
        return out
    by_pair: dict[tuple[str, str], list[SmbWriteHit]] = defaultdict(list)
    for row in _read_zeek_tsv(p):
        action = row.get("action", "") or row.get("Action", "")
        if action not in _SMB_WRITE_ACTIONS:
            continue
        try:
            size = int(row.get("size", "0") or 0)
        except ValueError:
            size = 0
        h = SmbWriteHit(
            src=row.get("id.orig_h", ""),
            dst=row.get("id.resp_h", ""),
            user=row.get("user", "") or row.get("client.user", ""),
            path=row.get("path", "") or row.get("name", ""),
            size=size, action=action,
        )
        by_pair[(h.src, h.dst)].append(h)
        if len(by_pair) > max_hits:
            break
    for pair, hits in by_pair.items():
        if len(hits) < min_count:
            continue
        out.extend(hits)
    return out[:max_hits]


# --- DHCP option-55 fingerprint detector -----------------------------------

# Tiny seed lookup of well-known option-55 patterns. Real fingerprint
# DBs are larger (Polarproxy / Zeek's own dhcp-fingerprint scripts);
# this catches the common attacker-OS signatures + benign Windows.
_DHCP_FINGERPRINTS = {
    "1,15,3,6,44,46,47,31,33,121,249,43": "Windows 10 / 11",
    "1,15,3,6,44,46,47,31,33,121,249,43,252": "Windows 10 / 11 (proxy)",
    "1,3,6,15,28": "Linux (older systemd-networkd)",
    "1,121,3,6,15,119,252,95,44,46": "macOS",
    "1,3,6,12,15,28,40,41,42,26,121,249,33,252,42,15,44,47": "Android",
    "1,33,3,6,15,28,51,58,59,119,121": "iOS",
}


def fingerprint_dhcp(zeek_dir: Path,
                      max_hits: int = 200) -> list[DhcpFingerprint]:
    """Read dhcp.log and emit DhcpFingerprint records keyed by
    (mac, ip, params_list). The ``likely_os`` is a heuristic match
    against the canonical fingerprint table — empty when the
    parameter-request list doesn't match a known pattern."""
    p = Path(zeek_dir) / "dhcp.log"
    out: list[DhcpFingerprint] = []
    if not p.is_file():
        return out
    seen: set[tuple[str, str, str]] = set()
    for row in _read_zeek_tsv(p):
        # Zeek 4.x emits 'requested_addr' / 'mac' / 'host_name' /
        # 'client_fqdn'; older versions use 'orig_h' / 'mac'.
        mac = row.get("mac", "") or row.get("client.mac", "")
        ip = (row.get("requested_addr", "")
              or row.get("client_addr", "")
              or row.get("id.orig_h", ""))
        fqdn = row.get("client_fqdn", "") or row.get("host_name", "")
        params = row.get("params_list", "") or row.get("client.params_list", "")
        # params often comes as space- or comma-separated; normalise
        params_norm = ",".join(t for t in params.replace(" ", ",").split(",") if t)
        key = (mac, ip, params_norm)
        if key in seen:
            continue
        seen.add(key)
        out.append(DhcpFingerprint(
            src_mac=mac, src_ip=ip,
            client_fqdn=fqdn, params_list=params_norm,
            likely_os=_DHCP_FINGERPRINTS.get(params_norm, ""),
        ))
        if len(out) >= max_hits:
            break
    return out


__all__ = [
    "SmbWriteHit", "DhcpFingerprint",
    "detect_smb_writes", "fingerprint_dhcp",
]
