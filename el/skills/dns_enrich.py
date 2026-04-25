"""Skill: forward / reverse DNS enrichment for IP-only IOCs.

Closes the gap-doc Detection-engineering deferred row "Forward/reverse
DNS enrichment on IP-only IOCs" (line 165).

Two modes, both opt-in (no live network lookup happens by default):

1. ``enrich_passive(ips, pdns_csv)`` — reads an operator-provided
   passive-DNS CSV (e.g. exported from VirusTotal, OTX, Farsight,
   PassiveTotal). Format: ``<value>\\t<type>\\t<rrname>\\t<rdata>``
   or any subset; we look for rows where rdata or rrname matches
   the IP.

2. ``enrich_live(ips)`` — uses Python's stdlib ``socket`` for
   PTR + forward A lookups. **Disabled unless** the env var
   ``EL_DNS_LIVE_LOOKUPS=1`` is set. Reason: live DNS leaks the
   investigator's interest into the operator's resolver chain and
   then into upstream DNS server logs — operators must opt in
   per-case.

Both modes return ``DnsEnrichment`` records keyed by IP.
"""
from __future__ import annotations

import csv
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DnsEnrichment:
    ip: str
    ptr_names: list[str] = field(default_factory=list)
    forward_confirmed: list[str] = field(default_factory=list)
    passive_rrnames: list[str] = field(default_factory=list)
    source: str = ""                       # "live" | "passive" | "both"
    error: str = ""


def is_live_enrichment_enabled() -> bool:
    """Live DNS lookups are gated. Operator opts in per-investigation
    via ``EL_DNS_LIVE_LOOKUPS=1``."""
    return os.environ.get("EL_DNS_LIVE_LOOKUPS") == "1"


def enrich_live(ips: list[str], *, timeout: float = 3.0
                ) -> dict[str, DnsEnrichment]:
    """PTR-then-forward lookup using stdlib socket. Skips when the
    opt-in env var isn't set (returns empty dict). Per-IP timeout
    cap so a slow resolver can't hang the case."""
    out: dict[str, DnsEnrichment] = {}
    if not is_live_enrichment_enabled():
        return out
    socket.setdefaulttimeout(timeout)
    try:
        for ip in ips:
            if not ip or ip in out:
                continue
            rec = DnsEnrichment(ip=ip, source="live")
            try:
                hostname, aliases, _ = socket.gethostbyaddr(ip)
                rec.ptr_names = sorted({hostname, *aliases})
            except (socket.herror, socket.gaierror, OSError) as e:
                rec.error = f"PTR failed: {e}"
                out[ip] = rec
                continue
            confirmed: list[str] = []
            for n in rec.ptr_names:
                try:
                    addrs = {info[4][0]
                             for info in socket.getaddrinfo(n, None)}
                    if ip in addrs:
                        confirmed.append(n)
                except (socket.herror, socket.gaierror, OSError):
                    pass
            rec.forward_confirmed = sorted(set(confirmed))
            out[ip] = rec
    finally:
        socket.setdefaulttimeout(None)
    return out


def enrich_passive(ips: list[str], pdns_csv: Path,
                    delimiter: str = "\t",
                    ) -> dict[str, DnsEnrichment]:
    """Read a passive-DNS CSV (TSV by default — VirusTotal /
    PassiveTotal export shape). Map each IP in `ips` to the rrnames
    that resolved to it.

    The CSV is expected to have a header row; we pick column names
    case-insensitively from {value, rdata, ip, address} for the IP
    side and {rrname, name, hostname, fqdn, query} for the name side.
    Rows without a recognisable IP / name are skipped.
    """
    out: dict[str, DnsEnrichment] = {ip: DnsEnrichment(ip=ip,
                                                          source="passive")
                                       for ip in ips if ip}
    pdns_csv = Path(pdns_csv)
    if not pdns_csv.is_file():
        return out

    ip_keys = ("rdata", "value", "ip", "address", "answer")
    name_keys = ("rrname", "name", "hostname", "fqdn", "query")
    try:
        with pdns_csv.open("r", errors="replace") as f:
            reader = csv.reader(f, delimiter=delimiter)
            try:
                header = [h.strip().lower() for h in next(reader)]
            except StopIteration:
                return out
            ip_col = next((header.index(k) for k in ip_keys
                            if k in header), None)
            name_col = next((header.index(k) for k in name_keys
                              if k in header), None)
            if ip_col is None or name_col is None:
                return out
            target_set = {ip for ip in ips if ip}
            for row in reader:
                if max(ip_col, name_col) >= len(row):
                    continue
                ip_v = row[ip_col].strip()
                if ip_v not in target_set:
                    continue
                name = row[name_col].strip()
                if not name:
                    continue
                rec = out.setdefault(ip_v, DnsEnrichment(
                    ip=ip_v, source="passive"))
                if name not in rec.passive_rrnames:
                    rec.passive_rrnames.append(name)
    except OSError:
        pass
    return out


def merge_enrichments(*sources: dict[str, DnsEnrichment]
                       ) -> dict[str, DnsEnrichment]:
    """Combine live + passive results into one map per IP, preserving
    every observed name."""
    out: dict[str, DnsEnrichment] = {}
    for src in sources:
        for ip, rec in src.items():
            tgt = out.setdefault(ip, DnsEnrichment(ip=ip))
            for n in rec.ptr_names:
                if n not in tgt.ptr_names:
                    tgt.ptr_names.append(n)
            for n in rec.forward_confirmed:
                if n not in tgt.forward_confirmed:
                    tgt.forward_confirmed.append(n)
            for n in rec.passive_rrnames:
                if n not in tgt.passive_rrnames:
                    tgt.passive_rrnames.append(n)
            existing = tgt.source.split("+") if tgt.source else []
            if rec.source and rec.source not in existing:
                existing.append(rec.source)
            tgt.source = "+".join(existing)
            if rec.error and not tgt.error:
                tgt.error = rec.error
    return out


__all__ = [
    "DnsEnrichment",
    "is_live_enrichment_enabled",
    "enrich_live", "enrich_passive", "merge_enrichments",
]
