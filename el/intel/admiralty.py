"""NATO Admiralty-code source/info ratings for evidence provenance.

Closes gap-doc Intel-depth bullet "Admiralty-code source-reliability
tags on EvidenceItem". The existing ``EvidenceItem`` already records
tool / version / sha256, but downstream consumers (analyst writing
the case report, ACH challenger asking "how strong is this claim?")
have no machine-readable hint on whether the underlying source
deserves full trust or scepticism.

The Admiralty system pairs a letter (A-F) for source reliability
with a digit (1-6) for information credibility:

    A  Completely reliable     1  Confirmed by other sources
    B  Usually reliable        2  Probably true
    C  Fairly reliable         3  Possibly true
    D  Not usually reliable    4  Doubtfully true
    E  Unreliable              5  Improbable
    F  Reliability cannot be   6  Truth cannot be judged
       judged

EL extends both with ``X`` to indicate "explicitly unset" — the
default for callers that haven't been migrated to the new field.

Tier mapping (the rule of thumb for EL skill wrappers):

    Court-vetted binary parser   → A1
      vol3 plugins, EvtxECmd, MFTECmd, fls/mactime, regipy, plaso
    Heuristic / signature match  → A2
      yara_hunt, capa, sigma, family fingerprints, rule challenger
    Configuration / log scrape   → B2
      iis_w3c, webserver_access, auditd, linux_artifacts patterns
    External feed                → C2
      MISP / TAXII pulls — the source is reputable but EL did not
      directly observe the IOC. Cross-case overlap from feeds.
    Operator note / manual tag   → F3
      The analyst typed something into a Finding by hand.
    Unknown                      → X X
"""
from __future__ import annotations

from typing import Iterable


# Letter-grade source reliability.
SOURCE_RELIABILITY = ("A", "B", "C", "D", "E", "F", "X")
# Digit-grade information credibility.
INFO_CREDIBILITY = ("1", "2", "3", "4", "5", "6", "X")


# Tool → default (reliability, credibility) mapping. Anchored to the
# existing skill-wrapper module names so the helper is self-checking
# at refactor time. Anything not in this table falls back to ("X", "X")
# and the caller's job is to set it explicitly.
_TOOL_TIER: dict[str, tuple[str, str]] = {
    # A1: court-vetted binary parsers — direct, deterministic
    "vol3": ("A", "1"),
    "volatility3": ("A", "1"),
    "evtxecmd": ("A", "1"),
    "mftecmd": ("A", "1"),
    "amcacheparser": ("A", "1"),
    "recmd": ("A", "1"),
    "regipy": ("A", "1"),
    "fls": ("A", "1"),
    "icat": ("A", "1"),
    "mactime": ("A", "1"),
    "mmls": ("A", "1"),
    "plaso": ("A", "1"),
    "log2timeline": ("A", "1"),
    "psort": ("A", "1"),
    "ewfinfo": ("A", "1"),
    "ewfverify": ("A", "1"),
    "libfsapfs": ("A", "1"),
    "libvshadow": ("A", "1"),
    "libesedb": ("A", "1"),

    # A2: signature / heuristic match — strong but not deterministic
    "yara": ("A", "2"),
    "yara_hunt": ("A", "2"),
    "capa": ("A", "2"),
    "sigma": ("A", "2"),
    "diec": ("A", "2"),
    "detect_it_easy": ("A", "2"),
    "tlsh": ("A", "2"),
    "ssdeep": ("A", "2"),

    # B2: configuration/log scrapers — log content trustworthy but
    # the parser interprets human-formatted records
    "iis_w3c": ("B", "2"),
    "webserver_access": ("B", "2"),
    "auditd": ("B", "2"),
    "ausearch": ("B", "2"),
    "linux_artifacts": ("B", "2"),
    "linux_triage": ("B", "2"),
    "cloudtrail": ("B", "2"),
    "velociraptor": ("B", "2"),
    "zeek": ("B", "2"),

    # C2: external threat-intel feeds — trusted curators, EL didn't
    # directly observe
    "misp": ("C", "2"),
    "taxii": ("C", "2"),
    "threat_feeds": ("C", "2"),
    "umbrella_allowlist": ("C", "2"),

    # F3: operator notes — manual tags from the analyst
    "operator": ("F", "3"),
    "manual": ("F", "3"),
}


def for_tool(tool: str) -> tuple[str, str]:
    """Return the default (reliability, credibility) pair for a
    skill-wrapper or tool-binary name. Lookup is case-insensitive
    and ignores common version suffixes (``vol3-2.20`` → ``vol3``).
    Unknown tool → ``("X", "X")`` so the caller is forced to be
    explicit when this matters."""
    if not tool:
        return ("X", "X")
    key = tool.strip().lower()
    # Strip a trailing ``-<digits>`` (vol3-2.20.0 → vol3) and a
    # trailing ``.exe`` (Windows tool names sometimes carry it).
    if key.endswith(".exe"):
        key = key[:-4]
    if "-" in key:
        head, _ = key.split("-", 1)
        if head in _TOOL_TIER:
            return _TOOL_TIER[head]
    return _TOOL_TIER.get(key, ("X", "X"))


def is_valid(reliability: str, credibility: str) -> bool:
    return (reliability in SOURCE_RELIABILITY
            and credibility in INFO_CREDIBILITY)


def describe(reliability: str, credibility: str) -> str:
    """Return a human-readable label like 'A1 — Completely reliable,
    Confirmed' for use in reports."""
    rel_text = {
        "A": "Completely reliable",
        "B": "Usually reliable",
        "C": "Fairly reliable",
        "D": "Not usually reliable",
        "E": "Unreliable",
        "F": "Reliability cannot be judged",
        "X": "Unset",
    }.get(reliability, "Unknown")
    cred_text = {
        "1": "Confirmed",
        "2": "Probably true",
        "3": "Possibly true",
        "4": "Doubtfully true",
        "5": "Improbable",
        "6": "Truth cannot be judged",
        "X": "Unset",
    }.get(credibility, "Unknown")
    return f"{reliability}{credibility} — {rel_text}, {cred_text}"


def downgrade(rating: tuple[str, str], *, by: int = 1) -> tuple[str, str]:
    """Step the *credibility* digit down by ``by`` (worsening it).
    Useful when a finding inherits a high-tier tool's reliability
    but the specific match is heuristic — e.g. a vol3 plugin output
    fed into a regex extractor (the parse is A-grade, but the
    extraction step adds uncertainty)."""
    rel, cred = rating
    if cred not in ("1", "2", "3", "4", "5"):
        return rating
    new = str(min(6, int(cred) + by))
    return (rel, new)


def best(ratings: Iterable[tuple[str, str]]
          ) -> tuple[str, str]:
    """Return the strongest (lowest) rating across a set of evidence
    items. ``A1`` < ``A2`` < ``B1`` < ``X X``. Useful when a Finding
    aggregates multiple EvidenceItems and the analyst wants the
    headline-level rating."""
    best_r: tuple[str, str] | None = None
    for r in ratings:
        if not is_valid(*r):
            continue
        if best_r is None or _rank(r) < _rank(best_r):
            best_r = r
    return best_r or ("X", "X")


def _rank(rating: tuple[str, str]) -> tuple[int, int]:
    rel, cred = rating
    rel_rank = {c: i for i, c in enumerate("ABCDEFX")}.get(rel, 99)
    cred_rank = {c: i for i, c in enumerate("123456X")}.get(cred, 99)
    return (rel_rank, cred_rank)


__all__ = [
    "SOURCE_RELIABILITY", "INFO_CREDIBILITY",
    "for_tool", "is_valid", "describe", "downgrade", "best",
]
