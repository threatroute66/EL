"""Augment EL's IOC extraction with iocsearcher's broader type catalog.

iocsearcher (IMDEA Software Institute, MIT-licensed) detects ~50
IOC types out of the box. Most overlap with EL's `ioc_extract`
which has case-validated FP filters EL must keep (90+ regression
tests for `_NOISE_DOMAINS`, `_FILE_EXT_TLDS`, `_WINDOWS_INTERNALS_
PREFIXES`, IANA TLD allowlist, X.509 OID labels, version-string-
as-domain, crypto-curve-as-hash, source-kind awareness for
fls bodyfiles, cross-case rarity bucketing). Replacing EL's
filtered core extractor with iocsearcher would lose every one of
those guards.

This skill therefore wraps iocsearcher targeted ONLY at the IOC
types EL doesn't already extract, and merges them into the case's
iocs.json under new top-level keys. The targeted-types list is
intentionally minimal — the more we pull from iocsearcher, the
more case-validated noise filtering we'd need to add on top.

EL-canonical key → iocsearcher type:

  cryptocurrency  → bitcoincash, cardano, dashcoin, dogecoin,
                    ethereum, litecoin, monero, ripple, solana,
                    stellar, tezos, tron, zcash
                    (bitcoin is EL's existing `btc`, skipped here)
  onion           → onionAddress (Tor v3)
  cve             → cve  (CVE-YYYY-NNNN[N..])
  social_handle   → telegramHandle, twitterHandle, githubHandle,
                    whatsappHandle, linkedinHandle, instagramHandle,
                    pinterestHandle, facebookHandle, youtubeHandle,
                    youtubeChannel
  phone           → phoneNumber
  iban            → iban
  android_package → packageName
  attack_technique → ttp (MITRE T-IDs in report text)

Explicitly NOT pulled from iocsearcher (would clash with EL's
filtered core extractor and undo the 90+ FP regression tests):
  fqdn, url, ip4, ip4Net, ip6, email, md5, sha1, sha256, registry,
  bitcoin.

Explicitly out of EL's current IR scope (not added):
  copyright, trademark, uuid, nif, tox, googleAdsense / Analytics /
  TagManager, icp (China internet provider licenses), webmoney, arn.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable


# iocsearcher type → EL canonical bucket. None means the value is
# stored under its own key (e.g. iocsearcher `cve` → EL key `cve`).
_TYPE_TO_KEY: dict[str, str] = {
    # Cryptocurrencies — all collapse under one `cryptocurrency` bucket
    # because per-chain partitioning produces 13 sparse keys in iocs.json
    # for almost-every case. Analysts who need per-chain breakdown can
    # walk the underlying fact (the value string carries the chain
    # prefix where ambiguous; iocsearcher disambiguates by pattern).
    "bitcoincash":      "cryptocurrency",
    "cardano":          "cryptocurrency",
    "dashcoin":         "cryptocurrency",
    "dogecoin":         "cryptocurrency",
    "ethereum":         "cryptocurrency",
    "litecoin":         "cryptocurrency",
    "monero":           "cryptocurrency",
    "ripple":           "cryptocurrency",
    "solana":           "cryptocurrency",
    "stellar":          "cryptocurrency",
    "tezos":            "cryptocurrency",
    "tron":             "cryptocurrency",
    "zcash":            "cryptocurrency",
    # Tor — EL renames `onionAddress` to plain `onion` to match
    # community / report convention.
    "onionAddress":     "onion",
    # CVE references in malware analysis / sigma rules / forensic
    # reports the case has ingested.
    "cve":              "cve",
    # Social-platform handles all collapse under `social_handle` for
    # the same sparsity reason as cryptocurrency. Per-platform
    # breakdown is preserved inside the value (e.g. `@telegram:x`).
    "telegramHandle":   "social_handle",
    "twitterHandle":    "social_handle",
    "githubHandle":     "social_handle",
    "whatsappHandle":   "social_handle",
    "linkedinHandle":   "social_handle",
    "instagramHandle":  "social_handle",
    "pinterestHandle":  "social_handle",
    "facebookHandle":   "social_handle",
    "youtubeHandle":    "social_handle",
    "youtubeChannel":   "social_handle",
    # Financial / identity / mobile
    "phoneNumber":      "phone",
    "iban":             "iban",
    "packageName":      "android_package",
    # MITRE ATT&CK technique IDs cited in report text (sigma rule
    # descriptions, malware-family attributions, CTI snippets).
    # Complements the per-finding `attack_techniques` facts that the
    # agents emit directly.
    "ttp":              "attack_technique",
}

# The list of iocsearcher targets to pull. Derived from _TYPE_TO_KEY
# keys so they stay in sync.
EXTRA_TARGETS: tuple[str, ...] = tuple(sorted(_TYPE_TO_KEY.keys()))

# EL-canonical output keys, in stable order. The default-empty result
# shape is built from this so callers always get a dict with the
# expected keys (matching the pattern in ioc_extract._EMPTY_IOCS).
EXTRA_KEYS: tuple[str, ...] = tuple(sorted(set(_TYPE_TO_KEY.values())))


def _empty() -> dict[str, set[str]]:
    return {k: set() for k in EXTRA_KEYS}


# ---------------------------------------------------------------------------
# Per-text extraction
# ---------------------------------------------------------------------------

def extract_extras(text: str) -> dict[str, set[str]]:
    """Run iocsearcher targeted at the EL-augmenting types. Returns a
    dict keyed on EL-canonical bucket names with values as sets of
    deduplicated IOC strings. Empty buckets are still present in the
    output so the merge into iocs.json is monotonic.

    Failure modes (iocsearcher not installed / import error / pattern
    error) return an empty result rather than raising — keeps the
    main pipeline robust when this skill is unavailable.
    """
    if not text:
        return _empty()
    try:
        from iocsearcher.searcher import Searcher
    except ImportError:
        return _empty()

    s = Searcher()
    out = _empty()
    try:
        # iocsearcher's search_raw returns 4-tuples (type, value,
        # start, end). We only need (type, value); positions are
        # for highlighting which we don't surface here.
        for typ, value, *_ in s.search_raw(text, targets=EXTRA_TARGETS):
            key = _TYPE_TO_KEY.get(typ)
            if not key:
                continue
            out[key].add(value)
    except Exception:
        # iocsearcher pattern errors should not crash the pipeline.
        return _empty()
    return out


# ---------------------------------------------------------------------------
# Path-walking — mirrors ioc_extract.extract_from_paths
# ---------------------------------------------------------------------------

def extract_extras_from_paths(
    paths: Iterable[str | Path],
) -> dict[str, set[str]]:
    """Read each path once, run `extract_extras` over the text, union
    the results. Reuses ioc_extract's `_should_skip_path` so the
    same feedback-loop / binary-format guards apply (we don't want
    to scan `findings.sqlite` or the case's own `ach_matrix.json`
    looking for crypto-wallet addresses inside binary content).
    """
    from el.skills.ioc_extract import _should_skip_path

    merged: dict[str, set[str]] = _empty()
    seen: set[Path] = set()
    for p in paths:
        pth = Path(p)
        if pth in seen:
            continue
        seen.add(pth)
        skip, _reason = _should_skip_path(pth)
        if skip:
            continue
        try:
            text = pth.read_text(errors="ignore")
        except Exception:
            continue
        for k, v in extract_extras(text).items():
            merged.setdefault(k, set()).update(v)
    return merged


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "EXTRA_KEYS",
    "EXTRA_TARGETS",
    "extract_extras",
    "extract_extras_from_paths",
]
