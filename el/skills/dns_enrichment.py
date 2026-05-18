"""Case-local passive-DNS cross-reference index.

When EL extracts IOCs from a case it produces two parallel sets of
indicators: IP addresses and domain names. They're stored under
separate `iocs.json` buckets and rendered as separate sections of
the report — even when they came from the same DNS event in the
same pcap and they're literally the same forensic observation.

This skill closes the loop. It walks the case's DNS evidence
(Zeek `dns.log` answers field — already on disk under
`analysis/network_analyst/zeek/`), builds a (domain → set[ip]) +
(ip → set[domain]) cross-reference index, and surfaces enrichment
facts at finding time: "this 4.2.0.13 IP was the A-record for
evil.example during the case window" or "this evil.example domain
resolved to 4.2.0.13, 4.2.0.14 in pcap".

Pure case-local. No external DNS resolver is queried — that would
leak case identifiers to the analyst's recursive resolver and
risk tipping off the attacker if their C2 was still live. The
cost is that we only see what the case's own evidence captured;
the gain is forensic safety and reproducibility (the index is
deterministic given the same case dir).

For an explicit external-pivot pass (live PTR / passive-DNS feed
lookup) build a separate skill — this one stays air-gap-safe.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DnsIndex:
    """Two-way map between domains and IP addresses observed in
    the case's own DNS evidence.

    Each entry carries the set of evidence sources that contributed
    to the mapping (currently always `{"zeek_dns_log"}`; future
    sources — memory DNS cache, browser prefetch, Windows DNS
    client log — will append their own tag).
    """
    domain_to_ips: dict[str, set[str]] = field(default_factory=dict)
    ip_to_domains: dict[str, set[str]] = field(default_factory=dict)
    sources: dict[str, set[str]] = field(default_factory=dict)
    # Statistics — useful for the index-summary finding the
    # correlator emits so the analyst sees "DNS enrichment loaded
    # N answers from M sources" instead of guessing.
    record_count: int = 0
    source_files: list[str] = field(default_factory=list)

    def lookup_ips_for(self, domain: str) -> list[str]:
        return sorted(self.domain_to_ips.get(domain.lower().rstrip("."),
                                              set()))

    def lookup_domains_for(self, ip: str) -> list[str]:
        return sorted(self.ip_to_domains.get(ip.strip(), set()))

    def add(self, domain: str, ip: str, source: str) -> None:
        """Add a single (domain, ip) edge with a source tag.
        Public so future skills (memory DNS cache parser, etc.)
        can append to a single shared index."""
        d = (domain or "").lower().rstrip(".")
        i = (ip or "").strip()
        if not d or not i:
            return
        if not _looks_like_ip(i):
            return
        self.domain_to_ips.setdefault(d, set()).add(i)
        self.ip_to_domains.setdefault(i, set()).add(d)
        self.sources.setdefault(d, set()).add(source)
        self.sources.setdefault(i, set()).add(source)
        self.record_count += 1


def _looks_like_ip(value: str) -> bool:
    """Conservative — return True only for IPv4/IPv6 literals.
    Zeek's `answers` column mixes A / AAAA / CNAME / SOA / etc;
    we only want the address-resolution rows here. CNAMEs end up
    as alias domains; recursively walking them would explode the
    index size on a busy case for minimal forensic value, so we
    drop CNAME rows at this layer."""
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# Zeek TSV log header convention:
#   #fields\tts\tuid\tid.orig_h\t...\tquery\t...\tanswers\t...
# `_extract_column` in el.skills.zeek already handles this format;
# we reimplement here so this skill stays standalone (no
# circular import via the correlator path).
_ZEEK_FIELDS_RE = re.compile(rb"^#fields\t(.+)$")


def _parse_zeek_dns_log(path: Path) -> list[tuple[str, str]]:
    """Yield (query, answer) pairs from a Zeek dns.log. The
    `answers` column is comma-separated; explode it per IP. Caller
    is responsible for filtering CNAME aliases — we just return
    the raw column contents and let `_looks_like_ip` discriminate.
    """
    out: list[tuple[str, str]] = []
    try:
        raw = path.read_bytes()
    except OSError:
        return out
    fields: list[str] = []
    q_idx = a_idx = -1
    for line in raw.splitlines():
        if not line:
            continue
        if line.startswith(b"#fields"):
            m = _ZEEK_FIELDS_RE.match(line)
            if not m:
                continue
            try:
                fields = m.group(1).decode("utf-8", errors="ignore").split("\t")
            except Exception:
                fields = []
            try:
                q_idx = fields.index("query")
                a_idx = fields.index("answers")
            except ValueError:
                q_idx = a_idx = -1
            continue
        if line.startswith(b"#"):
            continue
        if q_idx < 0 or a_idx < 0:
            continue
        try:
            cols = line.decode("utf-8", errors="ignore").split("\t")
        except Exception:
            continue
        if max(q_idx, a_idx) >= len(cols):
            continue
        query = cols[q_idx].strip()
        answers = cols[a_idx].strip()
        if not query or answers in ("-", "", "(empty)"):
            continue
        for ans in answers.split(","):
            ans = ans.strip()
            if ans:
                out.append((query, ans))
    return out


def build_case_index(case_dir: str | Path) -> DnsIndex:
    """Walk a case's DNS evidence and return a DnsIndex.

    Current source: Zeek `dns.log` files under
    `analysis/network_analyst/zeek/` (NetworkAnalyst writes there
    when a pcap was investigated). Future sources can be added by
    appending more `dns.add(...)` calls before returning.

    Returns an empty index when no DNS evidence was extracted —
    the caller renders / scores accordingly (no enrichment
    available rather than missing-data crash).
    """
    case_dir = Path(case_dir)
    index = DnsIndex()
    # Zeek output lives under analysis/network_analyst/zeek/ on cases
    # where NetworkAnalyst processed a pcap. The directory may also
    # contain rotated dns.log.<n>.gz files on long pcaps; we only
    # look at the canonical dns.log + dns.NN:NN:NN-NN:NN:NN.log
    # rotation pattern (no gzip walking — those are usually big
    # enough that the analyst should re-run on extracted form).
    zeek_dirs = list((case_dir / "analysis").rglob("zeek"))
    for zdir in zeek_dirs:
        if not zdir.is_dir():
            continue
        for log_path in sorted(zdir.glob("dns*.log")):
            for query, answer in _parse_zeek_dns_log(log_path):
                index.add(query, answer, source="zeek_dns_log")
            if log_path.is_file():
                index.source_files.append(str(log_path))
    return index


def enrich_ioc(index: DnsIndex, ip_or_domain: str
                ) -> dict[str, list[str]]:
    """Return enrichment facts for a single IOC value. The dict's
    keys reflect WHICH direction the lookup hit so the caller can
    render the fact accurately ("4.2.0.13 resolved from evil.com"
    vs "evil.com resolved to 4.2.0.13").

    Empty dict when no in-case DNS evidence touches this value —
    rendered as no-enrichment, not as "no answer" (those are
    semantically different and a real DNS NXDOMAIN deserves its
    own finding shape).
    """
    out: dict[str, list[str]] = {}
    if _looks_like_ip(ip_or_domain):
        names = index.lookup_domains_for(ip_or_domain)
        if names:
            out["resolved_from"] = names
    else:
        ips = index.lookup_ips_for(ip_or_domain)
        if ips:
            out["resolved_to"] = ips
    return out


__all__ = ["DnsIndex", "build_case_index", "enrich_ioc"]
