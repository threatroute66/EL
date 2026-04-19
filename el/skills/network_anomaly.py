"""Skill: network-traffic anomaly detectors.

SANS Network Forensics poster lists 11 "Network Traffic Anomalies" that
an analyst should check in any capture. This skill implements the
subset that can be computed from data EL already has (Zeek http.log +
dns.log output from NetworkAnalyst):

  1. HTTP method ratio     — POST:GET skew indicates exfil or script
                              (normal browsing is GET-dominated)
  2. HTTP status distribution — many 4xx/5xx = scan/recon
  3. HTTP User-Agent sanity  — empty UA, curl/wget, single outlier UA
                              accounting for >50% of requests
  4. DNS short TTL          — TTL ≤ 60s is classic fast-flux / CDN-
                              disguised C2 rotation
  5. DNS top-domain skew    — one domain > 50% of all queries
                              (periodic C2 beacon)
  6. Zeek weird.log         — protocol violations Zeek flagged
                              natively (not a detector — a surfacer)

Skipped from the poster (would need enrichment EL doesn't currently
have): ASN lookups, WHOIS age, periodic-timing baselines.

Pure functions against parsed Zeek rows. Callers pass row dicts;
detectors return AnomalyHit dataclasses with claim-ready summaries.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


# --- Zeek TSV parser ------------------------------------------------------

def parse_zeek_log(log_path: Path) -> list[dict]:
    """Parse a Zeek TSV log into row dicts. Handles the Zeek header
    (#separator, #fields, #types) and ignores blank / comment lines.
    Returns [] on any parse failure so detectors don't crash on missing
    logs."""
    log_path = Path(log_path)
    if not log_path.is_file():
        return []
    try:
        lines = log_path.read_text(errors="ignore").splitlines()
    except Exception:
        return []
    separator = "\t"
    fields: list[str] = []
    rows: list[dict] = []
    for line in lines:
        if not line:
            continue
        if line.startswith("#separator"):
            val = line.split(" ", 1)[1].strip()
            # Value is "\x09" literal; interpret
            if val.startswith("\\x"):
                try:
                    separator = bytes.fromhex(val[2:]).decode()
                except Exception:
                    separator = "\t"
            continue
        if line.startswith("#fields"):
            fields = line.split(separator)[1:]
            continue
        if line.startswith("#"):
            continue
        if not fields:
            continue
        parts = line.split(separator)
        if len(parts) < len(fields):
            parts += [""] * (len(fields) - len(parts))
        row = {f: parts[i] for i, f in enumerate(fields)}
        rows.append(row)
    return rows


# --- Detector results -----------------------------------------------------

@dataclass
class AnomalyHit:
    anomaly_id: str
    summary: str
    confidence: str                   # "low" / "medium" / "high"
    hypotheses: list[str] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)
    facts: dict = field(default_factory=dict)


# --- HTTP method ratio ----------------------------------------------------

def detect_http_method_ratio(http_rows: list[dict],
                              min_requests: int = 30) -> list[AnomalyHit]:
    """Normal browsing is GET-dominated (>80%). A POST-heavy capture
    (POSTs ≥ 50% of non-trivial request volume) suggests scripted
    exfil or C2 beacon-POSTs."""
    if len(http_rows) < min_requests:
        return []
    methods = Counter((r.get("method") or "").upper() for r in http_rows)
    total = sum(methods.values())
    gets = methods.get("GET", 0)
    posts = methods.get("POST", 0)
    if posts == 0 or total == 0:
        return []
    post_share = posts / total
    get_share = gets / total
    if post_share >= 0.5 and post_share > get_share:
        return [AnomalyHit(
            anomaly_id="HTTP_POST_HEAVY",
            summary=(f"HTTP method ratio skewed to POST: {posts}/{total} "
                     f"({post_share:.0%}) POSTs vs {gets} GETs. Scripted / "
                     f"exfil pattern — normal browsing is >80% GET."),
            confidence="medium",
            hypotheses=["H_C2_OR_REVERSE_SHELL", "H_INSIDER_DATA_EXFIL"],
            attack=[("T1071.001", "Application Layer Protocol: Web Protocols"),
                    ("T1041", "Exfiltration Over C2 Channel")],
            facts={"gets": gets, "posts": posts, "total": total,
                   "post_share": round(post_share, 3)},
        )]
    return []


# --- HTTP status code ratio ----------------------------------------------

def detect_http_error_rate(http_rows: list[dict],
                            min_requests: int = 20) -> list[AnomalyHit]:
    """A high 4xx/5xx rate suggests scanning, discovery, or broken C2.
    Fires when ≥30% of responses are 4xx AND the capture has enough
    samples to be meaningful."""
    if len(http_rows) < min_requests:
        return []
    codes = []
    for r in http_rows:
        c = r.get("status_code") or ""
        try:
            codes.append(int(c))
        except ValueError:
            continue
    if not codes:
        return []
    n = len(codes)
    fourxx = sum(1 for c in codes if 400 <= c < 500)
    fivexx = sum(1 for c in codes if 500 <= c < 600)
    err_share = (fourxx + fivexx) / n
    if err_share >= 0.3 and (fourxx + fivexx) >= 10:
        return [AnomalyHit(
            anomaly_id="HTTP_ERROR_HEAVY",
            summary=(f"HTTP error rate {err_share:.0%} — {fourxx} × 4xx, "
                     f"{fivexx} × 5xx out of {n} responses. Scan / "
                     f"discovery / broken C2 pattern."),
            confidence="medium",
            hypotheses=["H_C2_OR_REVERSE_SHELL"],
            attack=[("T1595", "Active Scanning")],
            facts={"count_4xx": fourxx, "count_5xx": fivexx,
                   "total_responses": n, "error_share": round(err_share, 3)},
        )]
    return []


# --- HTTP User-Agent sanity ----------------------------------------------

_SUSPICIOUS_UA_SUBSTRINGS = (
    "curl/", "wget/", "python-requests/", "python-urllib/",
    "go-http-client", "java/", "winhttp", "powershell/",
    "microsoft-winhttprequest", "mozilla/4.0 (compatible; msie 7.0)",  # common hardcode
)


def detect_http_user_agent_anomalies(
    http_rows: list[dict], min_requests: int = 10,
) -> list[AnomalyHit]:
    """Two signals:
      (a) UA strings matching known scripted-client prefixes
      (b) A single UA accounting for ≥90% of requests with ≥30 requests —
          indicates scripted communication (normal web surfing shows
          many UAs as the browser does XHR/prefetch across sites)
    """
    if len(http_rows) < min_requests:
        return []
    out: list[AnomalyHit] = []
    uas = [(r.get("user_agent") or "").strip() for r in http_rows]
    uas = [u for u in uas if u and u != "-"]
    if not uas:
        return out
    # (a) scripted-client prefixes
    scripted_counts: Counter = Counter()
    for u in uas:
        ul = u.lower()
        for marker in _SUSPICIOUS_UA_SUBSTRINGS:
            if marker in ul:
                scripted_counts[marker] += 1
                break
    if scripted_counts:
        samples = ", ".join(f"{m}={n}" for m, n in scripted_counts.most_common(5))
        out.append(AnomalyHit(
            anomaly_id="HTTP_SCRIPTED_UA",
            summary=(f"Scripted-client User-Agent(s) observed: {samples}. "
                     f"Normal user traffic rarely includes curl/wget/"
                     f"python-requests / go-http-client — these are "
                     f"automation or malware indicators."),
            confidence="medium",
            hypotheses=["H_OPPORTUNISTIC_COMMODITY", "H_C2_OR_REVERSE_SHELL"],
            attack=[("T1071.001", "Application Layer Protocol: Web Protocols")],
            facts={"scripted_ua_counts": dict(scripted_counts)},
        ))
    # (b) single-UA dominance — only fires when the dominant UA is NOT a
    # legitimate browser. A single-site capture with a real browser
    # legitimately shows 100% Mozilla/Chrome/Edge/Safari over many
    # requests; we care about the scripted-client case where the
    # dominating UA is a tool/bot string.
    if len(uas) >= 30:
        top_ua, top_count = Counter(uas).most_common(1)[0]
        top_ua_lc = top_ua.lower()
        is_browser = any(b in top_ua_lc for b in (
            "mozilla/", "chrome/", "firefox/", "safari/", "edge/", "opera/",
            "trident/",  # IE
        ))
        if top_count / len(uas) >= 0.9 and not is_browser:
            out.append(AnomalyHit(
                anomaly_id="HTTP_SINGLE_UA_DOMINANCE",
                summary=(f"One non-browser User-Agent accounts for "
                         f"{top_count}/{len(uas)} ({top_count/len(uas):.0%}) "
                         f"of HTTP requests: {top_ua[:80]!r}. Single-UA "
                         f"dominance at this volume with a non-browser UA "
                         f"is scripted, not interactive."),
                confidence="low",
                hypotheses=["H_C2_OR_REVERSE_SHELL"],
                facts={"top_ua": top_ua, "dominance": round(top_count/len(uas), 3),
                       "total_requests_with_ua": len(uas)},
            ))
    return out


# --- DNS short-TTL + top-domain skew -------------------------------------

def _parse_ttls(ttls_field: str) -> list[float]:
    """Zeek TTLs field is a vector — rendered as "300.0,60.0,60.0".
    Also handles a single bare value or an unset "-"."""
    if not ttls_field or ttls_field == "-":
        return []
    out: list[float] = []
    for v in ttls_field.split(","):
        v = v.strip()
        if not v or v == "-":
            continue
        try:
            out.append(float(v))
        except ValueError:
            continue
    return out


def detect_dns_short_ttl(dns_rows: list[dict],
                          ttl_threshold_seconds: float = 60.0,
                          min_queries: int = 5) -> list[AnomalyHit]:
    """Short TTLs (≤60s) on DNS responses are rare outside of CDN
    pools; at scale they indicate fast-flux. Fires when ≥3 distinct
    domains resolve with short TTLs."""
    short_ttl_domains: Counter = Counter()
    for r in dns_rows:
        query = (r.get("query") or "").strip()
        if not query or query == "-":
            continue
        ttls = _parse_ttls(r.get("TTLs") or "")
        if not ttls:
            continue
        if min(ttls) <= ttl_threshold_seconds:
            short_ttl_domains[query] += 1
    if len(short_ttl_domains) >= 3:
        samples = ", ".join(f"{d} (×{n})"
                             for d, n in short_ttl_domains.most_common(5))
        return [AnomalyHit(
            anomaly_id="DNS_SHORT_TTL",
            summary=(f"{len(short_ttl_domains)} distinct domain(s) "
                     f"resolved with TTL ≤ {int(ttl_threshold_seconds)}s. "
                     f"Fast-flux / rapid-rotation DNS pattern. "
                     f"Samples: {samples}"),
            confidence="low",
            hypotheses=["H_C2_OR_REVERSE_SHELL"],
            attack=[("T1568.001", "Dynamic Resolution: Fast Flux DNS")],
            facts={"domain_count": len(short_ttl_domains),
                   "sample_domains": dict(short_ttl_domains.most_common(10))},
        )]
    return []


def detect_dns_domain_skew(dns_rows: list[dict],
                            dominance_threshold: float = 0.5,
                            min_queries: int = 30) -> list[AnomalyHit]:
    """If one query name accounts for more than `dominance_threshold`
    of all queries, that's either a misconfigured host OR a beaconing
    malware repeatedly resolving its C2."""
    queries = [(r.get("query") or "").strip() for r in dns_rows]
    queries = [q for q in queries if q and q != "-"]
    if len(queries) < min_queries:
        return []
    top_q, top_count = Counter(queries).most_common(1)[0]
    share = top_count / len(queries)
    if share >= dominance_threshold:
        return [AnomalyHit(
            anomaly_id="DNS_DOMAIN_SKEW",
            summary=(f"Single domain dominates DNS queries: {top_q!r} "
                     f"accounts for {top_count}/{len(queries)} "
                     f"({share:.0%}) of queries. Candidate C2 beacon "
                     f"or misconfigured poller."),
            confidence="low",
            hypotheses=["H_C2_OR_REVERSE_SHELL"],
            attack=[("T1071.004", "Application Layer Protocol: DNS")],
            facts={"top_domain": top_q, "count": top_count,
                   "total_queries": len(queries), "share": round(share, 3)},
        )]
    return []


# --- Top-level convenience ------------------------------------------------

def run_all(zeek_dir: Path) -> list[AnomalyHit]:
    """Parse http.log + dns.log from a Zeek output directory and run
    every detector. Missing logs are silent — caller gets [] for an
    encrypted or DNS-free capture."""
    zeek_dir = Path(zeek_dir)
    http_rows = parse_zeek_log(zeek_dir / "http.log")
    dns_rows = parse_zeek_log(zeek_dir / "dns.log")
    hits: list[AnomalyHit] = []
    hits.extend(detect_http_method_ratio(http_rows))
    hits.extend(detect_http_error_rate(http_rows))
    hits.extend(detect_http_user_agent_anomalies(http_rows))
    hits.extend(detect_dns_short_ttl(dns_rows))
    hits.extend(detect_dns_domain_skew(dns_rows))
    return hits
