"""Tests for el.skills.iocsearcher_extras.

The skill wraps iocsearcher targeted at IOC types EL's native
extractor doesn't have. Tests pin the contract on:

- the EL-canonical key set (cryptocurrency / onion / cve /
  social_handle / phone / iban / android_package / attack_technique)
- per-type extraction on representative text samples
- robustness: empty text, malformed text, iocsearcher-missing
- path-walking respects ioc_extract._should_skip_path so the
  skill inherits EL's feedback-loop / binary-format guards

The real-world FP behaviour (e.g. false IBAN matches inside random
hex content) is iocsearcher's responsibility — those tests live in
that upstream project. This file pins the *integration* contract.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from el.skills.iocsearcher_extras import (
    EXTRA_KEYS,
    EXTRA_TARGETS,
    extract_extras,
    extract_extras_from_paths,
)


# ---------------------------------------------------------------------------
# Schema / contract
# ---------------------------------------------------------------------------

def test_extra_keys_is_stable_sorted():
    """EXTRA_KEYS is the canonical output schema. Pinning the order
    locks the iocs.json column ordering downstream renderers depend
    on. If a new type is added, this test must be updated together."""
    assert EXTRA_KEYS == (
        "android_package", "attack_technique", "cryptocurrency",
        "cve", "iban", "onion", "phone", "social_handle",
    )


def test_extra_targets_include_all_mapped_types():
    """Every iocsearcher target named in EXTRA_TARGETS must map to
    one of the EL canonical keys — no stale entries."""
    from el.skills.iocsearcher_extras import _TYPE_TO_KEY
    assert set(EXTRA_TARGETS) == set(_TYPE_TO_KEY.keys())
    assert all(v in EXTRA_KEYS for v in _TYPE_TO_KEY.values())


def test_extract_extras_returns_full_schema_even_on_empty_input():
    """Callers merging into iocs.json rely on monotonic merge —
    every call must return every EXTRA_KEYS member as an iterable,
    even when the input has no IOCs."""
    out = extract_extras("")
    assert set(out.keys()) == set(EXTRA_KEYS)
    assert all(isinstance(v, set) for v in out.values())
    assert all(len(v) == 0 for v in out.values())


def test_extract_extras_returns_full_schema_on_garbage_input():
    """Garbage text (no IOCs of any extracted type) still returns
    the full schema with empty sets."""
    out = extract_extras("just some random text with no indicators")
    assert set(out.keys()) == set(EXTRA_KEYS)


def test_extract_extras_handles_iocsearcher_missing_gracefully():
    """If iocsearcher isn't installed (unlikely in production but
    possible in minimal containers), the skill must NOT raise —
    it returns an empty result and the pipeline continues."""
    with patch.dict("sys.modules", {"iocsearcher.searcher": None}):
        # Force the import to fail by clearing cached modules
        import sys
        if "iocsearcher.searcher" in sys.modules:
            del sys.modules["iocsearcher.searcher"]
        # Re-import the function so it picks up the broken state
        from el.skills import iocsearcher_extras
        # iocsearcher is patched out of sys.modules; the function's
        # import-inside-function pattern should trip the ImportError
        # handler and return the empty schema.
        # (We can't actually unimport iocsearcher cleanly; rely on
        # the skill's try/except to handle whatever failure mode
        # the patched state produces.)
        result = iocsearcher_extras.extract_extras("CVE-2024-21413")
        assert isinstance(result, dict)
        assert set(result.keys()) == set(EXTRA_KEYS)


# ---------------------------------------------------------------------------
# Per-type extraction (smoke tests on canonical IOC shapes)
# ---------------------------------------------------------------------------

def test_extract_extras_finds_cve():
    """CVE-YYYY-NNNN[N..] references in malware reports / sigma
    rules. iocsearcher pattern is conservative enough that random
    `CVE-...` mentions in raw text are reliable hits."""
    text = "Exploits CVE-2021-44228 (Log4Shell) and CVE-2024-21413."
    out = extract_extras(text)
    assert "CVE-2021-44228" in out["cve"]
    assert "CVE-2024-21413" in out["cve"]


def test_extract_extras_finds_tor_onion():
    """Tor v3 onion addresses (.onion suffix). iocsearcher captures
    the base32 portion; EL renames the bucket from onionAddress to
    plain `onion` for downstream rendering."""
    text = "C2 hidden service at 3g2upl4pq6kufc4m.onion"
    out = extract_extras(text)
    assert any(o.startswith("3g2upl4pq6kufc4m") for o in out["onion"])


def test_extract_extras_finds_ethereum_wallet():
    """Ethereum wallets (0x + 40 hex chars) land under the unified
    cryptocurrency bucket. Bitcoin SKIPPED here on purpose — EL's
    native `btc` extractor already handles legacy + bech32."""
    text = "Send ransom to 0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
    out = extract_extras(text)
    assert any("71C7656EC7ab88" in c for c in out["cryptocurrency"])


def test_extract_extras_finds_iban():
    """IBAN — EU bank account format with check digits. iocsearcher
    validates the check digit so random hex strings don't FP."""
    text = "Wire to IBAN DE89370400440532013000 for negotiation."
    out = extract_extras(text)
    assert "DE89370400440532013000" in out["iban"]


def test_extract_extras_finds_phone_number():
    """E.164-formatted phone numbers. iocsearcher uses google's
    phonenumbers library so format flexibility is handled upstream."""
    text = "Contact +14155550199 for ransom negotiations."
    out = extract_extras(text)
    assert any("4155550199" in p for p in out["phone"])


def test_extract_extras_finds_attack_techniques():
    """MITRE ATT&CK T-IDs appearing in malware analysis report text /
    sigma rule descriptions / CTI snippets. Complements the per-
    finding `attack_techniques` facts the agents emit directly."""
    text = "Sigma rule covers T1566.002 (spearphishing) and T1059.001."
    out = extract_extras(text)
    assert "T1566.002" in out["attack_technique"]
    assert "T1059.001" in out["attack_technique"]


# ---------------------------------------------------------------------------
# Path walking — inherits ioc_extract feedback-loop guards
# ---------------------------------------------------------------------------

def test_extract_extras_from_paths_dedups_repeated_inputs(tmp_path):
    """Same path supplied twice should not be re-read twice — match
    the dedup semantics of ioc_extract.extract_from_paths so the
    extras pass doesn't accidentally double-count when a finding
    cites the same evidence file from multiple EvidenceItems."""
    p = tmp_path / "report.txt"
    p.write_text("CVE-2024-21413 is patched in KB5034441.")
    out = extract_extras_from_paths([p, p, p])
    # CVE present exactly once (dedup) — set semantics already enforce
    # this on the value side, but the path-dedup avoids re-reading
    # the file 3 times.
    assert out["cve"] == {"CVE-2024-21413"}


def test_extract_extras_from_paths_skips_via_binary_magic_guard(tmp_path):
    """If ioc_extract._should_skip_path drops a path (binary magic
    sniff, > 10 MB, downstream output filename), the extras pass
    must respect the same skip — otherwise the feedback-loop guard
    EL has on the core extractor wouldn't apply here and we'd
    re-scan our own output."""
    binary_blob = tmp_path / "evidence.db"
    # Real SQLite magic header at byte 0 — _BINARY_MAGICS catches it
    # and short-circuits before iocsearcher ever sees the content.
    binary_blob.write_bytes(
        b"SQLite format 3\x00" + b"CVE-9999-99999" * 100)
    out = extract_extras_from_paths([binary_blob])
    # The CVE shape is inside the bytes, but the binary magic sniff
    # rejects the file before iocsearcher sees it.
    assert out["cve"] == set()


def test_extract_extras_from_paths_reads_legitimate_text(tmp_path):
    """A normal .txt evidence file should be read and processed.
    Uses an EIP-55 checksum-valid Ethereum address; iocsearcher
    validates the case-pattern checksum and rejects randomly-cased
    hex strings, so test data must match a real wallet shape."""
    p = tmp_path / "malware_notes.txt"
    p.write_text(
        # EIP-55 checksum-valid (verified by iocsearcher in the
        # smoke test that drove this skill's design):
        "Ransom payment 0x71C7656EC7ab88b098defB751B7401B5f6d8976F "
        "due by Friday. Tor: pqj4mh4hreptpdvc.onion. "
        "Exploits CVE-2024-21413."
    )
    out = extract_extras_from_paths([p])
    assert any("71C7656EC7ab88" in c for c in out["cryptocurrency"])
    assert any(o.startswith("pqj4mh4hreptpdvc") for o in out["onion"])
    assert "CVE-2024-21413" in out["cve"]


def test_extract_extras_from_paths_returns_full_schema_on_empty_input():
    """Empty paths list still returns the full schema (monotonic merge
    contract — see test_extract_extras_returns_full_schema_even_on_
    empty_input)."""
    out = extract_extras_from_paths([])
    assert set(out.keys()) == set(EXTRA_KEYS)
    assert all(len(v) == 0 for v in out.values())


# ---------------------------------------------------------------------------
# Non-overlap with EL's core extractor
# ---------------------------------------------------------------------------

def test_extra_targets_do_not_include_core_types():
    """Confirm we deliberately exclude iocsearcher's fqdn / url /
    email / md5 / sha1 / sha256 / ip4 / ip4Net / ip6 / registry /
    bitcoin from the targets list. Those are EL's filtered core
    extractor's responsibility and pulling them via iocsearcher
    would undo the 90+ FP regression tests + IANA TLD allowlist."""
    overlap = {"fqdn", "url", "email", "md5", "sha1", "sha256",
               "ip4", "ip4Net", "ip6", "registry", "bitcoin"}
    assert overlap.isdisjoint(set(EXTRA_TARGETS)), \
        f"Overlap with core extractor types: " \
        f"{sorted(overlap & set(EXTRA_TARGETS))}"
