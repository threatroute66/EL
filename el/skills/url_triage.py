"""Skill: behavioural URL triage.

Shape-agnostic detectors for evasive web traffic. Used by NetworkAnalyst
to spot suspicious characteristics that don't depend on a specific
malware family's URL regex — EK and commodity families mutate URL shapes
fast enough that fixed patterns lose quickly (observed in batch-2: PR-C
per-family fingerprints hit 2/25 on 2015-01 pcaps).

Two detectors in this skill:

  1. suspicious_tld(domain) — classifies TLDs into three buckets:
       "abuse"   — near-zero legitimate use (cheap registrars, bulk abuse)
                   .tk .ml .ga .cf .gq .co.vu
       "newgen"  — new-generic TLDs with heavy malicious-use ratio
                   .top .xyz .click .loan .work .science .stream .party …
       "ddns"    — dynamic-DNS provider domains
                   .duckdns.org .no-ip.biz .myftp.org .hopto.org .ddns.net …
       "mixed"   — suspicious-but-real (e.g. .rocks, .biz) — flagged only
                   when combined with another signal (caller's choice)
     Returns (bool, tuple[category, tld]) so the caller can distinguish.

  2. disposable_subdomain_cluster(hosts) — given a list of HTTP Host
     headers observed in a single capture, groups by registered parent
     and returns parents that have ≥3 distinct subdomains where each
     subdomain label has Shannon entropy ≥3.3 bits (random-alphanumeric
     shape). One compromised site rarely serves content via several
     random subdomains; EK landing hosts do (observed: Nuclear EK 2014).

Both detectors are pure functions — no I/O, no network, no state.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict


# ---------------------------------------------------------------------------
# Suspicious TLDs
# ---------------------------------------------------------------------------

# Freenom free-TLDs (.tk/.ml/.ga/.cf/.gq) + similar abuse-registrar fringe.
# Near-zero legitimate use in DFIR work.
_ABUSE_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq",
})

# New-generic TLDs with a disproportionate malicious-to-legit ratio per
# Spamhaus, SURBL, and public abuse reports. Not automatically bad, but
# a strong-enough prior that surfacing them in a DFIR context is worth
# the analyst's glance.
_NEWGEN_TLDS = frozenset({
    "top", "xyz", "click", "loan", "work", "science", "stream", "party",
    "trade", "racing", "accountant", "download", "cricket", "bid", "men",
    "faith", "ren", "mom", "lol", "wtf", "review", "win", "date", "kim",
    "gdn", "country", "cricket", "webcam", "pw",
})

# Dynamic-DNS provider domains. A C2 behind a DDNS host is noteworthy
# even when the hostname itself looks benign.
_DDNS_SUFFIXES = frozenset({
    "duckdns.org", "no-ip.biz", "no-ip.org", "no-ip.info", "no-ip.net",
    "myftp.org", "myftp.biz", "hopto.org", "zapto.org", "ddns.net",
    "sytes.net", "serveftp.com", "servebeer.com", "dyndns.org",
    "dyndns.info", "dyndns.tv", "homeip.net", "chickenkiller.com",
    "ignorelist.com", "jumpingcrab.com", "crabdance.com",
    "mooo.com", "strangled.net", "is-a-hacker.com",
    "co.vu",  # short URL / ddns hybrid used by ~2014 EKs
})

# Borderline — legitimately used but skewed enough that a hit combined
# with another signal (entropy, disposable-subdomains) should surface.
_MIXED_TLDS = frozenset({
    "rocks", "biz",
})


def _split_tld(domain: str) -> tuple[str, str]:
    """Strip any :port, lowercase, split into (registered_parent, tld).

    Handles second-level DDNS parents like "duckdns.org" by checking the
    full suffix first. Returns ("", "") if the input has no dot.
    """
    d = domain.strip().lower().rsplit(":", 1)[0]
    if "." not in d:
        return "", ""
    # Two-label DDNS / abuse suffix match (e.g. "foo.duckdns.org" → parent)
    for suffix in _DDNS_SUFFIXES:
        if d == suffix or d.endswith("." + suffix):
            return suffix, suffix
    labels = d.split(".")
    tld = labels[-1]
    parent = ".".join(labels[-2:]) if len(labels) >= 2 else d
    return parent, tld


def suspicious_tld(domain: str) -> tuple[bool, tuple[str, str] | None]:
    """Return (is_suspicious, (category, hit)) or (False, None).

    category ∈ {"abuse", "newgen", "ddns", "mixed"}.
    """
    parent, tld = _split_tld(domain)
    if not tld:
        return False, None
    if parent in _DDNS_SUFFIXES:
        return True, ("ddns", parent)
    if tld in _ABUSE_TLDS:
        return True, ("abuse", tld)
    if tld in _NEWGEN_TLDS:
        return True, ("newgen", tld)
    if tld in _MIXED_TLDS:
        return True, ("mixed", tld)
    return False, None


# ---------------------------------------------------------------------------
# Disposable-subdomain clustering
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Standard Shannon entropy of the character distribution, in bits."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Minimum entropy for a subdomain label to be considered "random-looking".
# Tuned on observed 2014-2015 EK subdomains. 3.0 bits comfortably clears
# legit short-word subs (webmail=2.52, accounts=2.25, customer=2.75)
# while still catching the English-like evasion shapes that 2015 Angler
# used (e.g. "hydroceppoweron" = 3.19 bits — pronounceable but random).
# The 10-char min-length filter handles short legitimate subs first.
_DISPOSABLE_ENTROPY_THRESHOLD = 3.0
_DISPOSABLE_MIN_LEN = 10
_DISPOSABLE_MIN_COUNT = 3   # need ≥3 to call it a cluster

# Known legitimate CDN / cloud provider suffixes — many have many random
# subdomains by design. Exempt them from the cluster check.
_CDN_EXEMPT_PARENTS = frozenset({
    "amazonaws.com", "cloudfront.net", "azureedge.net", "cloudapp.net",
    "cloudapp.azure.com", "appspot.com", "googleusercontent.com",
    "akamaiedge.net", "akamaihd.net", "akamaitechnologies.com",
    "akamaized.net", "edgesuite.net", "edgekey.net", "llnwd.net",
    "fastly.net", "fastlylb.net", "cdn.cloudflare.net", "cloudflare.com",
    "herokuapp.com", "herokudns.com", "githubusercontent.com",
    "digitaloceanspaces.com", "linodeobjects.com",
    "windows.net", "azurewebsites.net", "core.windows.net",
    "segment.io", "segment.com", "mktoresp.com", "googleapis.com",
})


def _is_cdn_exempt(parent: str) -> bool:
    parent = parent.lower()
    for ex in _CDN_EXEMPT_PARENTS:
        if parent == ex or parent.endswith("." + ex):
            return True
    return False


def _registered_parent(domain: str) -> str:
    """Best-effort registered-parent extraction (last two labels)."""
    d = domain.strip().lower().rsplit(":", 1)[0]
    labels = d.split(".")
    if len(labels) < 2:
        return d
    # Handle country-code TLDs that use three-label registrations
    # (.co.uk, .com.au, .co.jp, .org.uk, etc.) — use the last three
    # labels so we don't confuse "foo.co.uk" with a ccTLD.
    two_label_cctlds = {
        "co.uk", "co.jp", "co.kr", "co.nz", "co.in", "co.za", "co.id",
        "com.au", "com.br", "com.cn", "com.mx", "com.tw", "com.hk",
        "com.sg", "com.my", "com.vn", "com.tr",
        "org.uk", "org.au", "net.au", "ac.uk", "gov.uk", "gov.au",
    }
    last_two = ".".join(labels[-2:])
    if last_two in two_label_cctlds and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def disposable_subdomain_cluster(
    hosts: list[str],
    min_entropy: float = _DISPOSABLE_ENTROPY_THRESHOLD,
    min_label_len: int = _DISPOSABLE_MIN_LEN,
    min_count: int = _DISPOSABLE_MIN_COUNT,
) -> dict[str, list[str]]:
    """Group hosts by registered parent; return parents that have at
    least `min_count` distinct high-entropy subdomain labels.

    Skips known CDN / cloud-hosting parents (their random-subdomain
    design is benign).

    Returns {parent: [full_host, ...]} sorted by parent.
    """
    by_parent: dict[str, set[str]] = defaultdict(set)
    for h in hosts:
        if not h or "." not in h:
            continue
        parent = _registered_parent(h)
        if _is_cdn_exempt(parent):
            continue
        # Extract the leftmost labels (everything before the parent)
        h_lower = h.lower().rsplit(":", 1)[0]
        if not h_lower.endswith("." + parent) and h_lower != parent:
            continue
        sub_part = h_lower[:-(len(parent) + 1)] if h_lower != parent else ""
        if not sub_part:
            continue
        # Score the FIRST (leftmost) subdomain label — that's where
        # EK evasion concentrates; multi-label subdomains still count
        # if their leftmost label is disposable-looking.
        first_label = sub_part.split(".")[0]
        if len(first_label) < min_label_len:
            continue
        if shannon_entropy(first_label) < min_entropy:
            continue
        by_parent[parent].add(h_lower)

    return {
        parent: sorted(hosts)
        for parent, hosts in sorted(by_parent.items())
        if len(hosts) >= min_count
    }
