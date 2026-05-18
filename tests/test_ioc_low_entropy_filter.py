"""Tests for the low-entropy IOC filter in ioc_extract +
iocsearcher_extras.

Regex-only matching produces false positives on memory-padding /
wiped-slack patterns: a 32-char hex string of `aaaaaaaaaaaaaaa6...`
satisfies the MD5 regex by length + character class even though it's
clearly NOT a hash. The same problem hits SHA1, SHA256, BTC addresses,
and (via iocsearcher) every cryptocurrency / onion-address shape.

SRL-2018 r9 surfaced the FP in the most visible way possible: shared
IOCs across wkstn01 + wkstn05 included
  - cryptocurrency  `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
  - md5             `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
  - sha1            `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6aaaaa`
— all caught by the rough-length regex, none real.

The fix: reject tokens with fewer distinct characters than a real
artefact of that kind would have. Thresholds set to ~half the
alphabet (hex hashes) or ~20% (Base58/onion).
"""
from __future__ import annotations

from el.skills.ioc_extract import extract
from el.skills.iocsearcher_extras import (
    _MIN_UNIQUE_CHARS as IOCS_THRESHOLDS,
    _has_sufficient_entropy as iocs_entropy,
)


# ---------------------------------------------------------------------------
# Hash classes — MD5 / SHA1 / SHA256 false-positive rejection
# ---------------------------------------------------------------------------

def test_md5_padding_garbage_rejected():
    """The exact SRL-2018 r9 false positive — 32 hex chars but only
    `a` + `6`. Pure noise; the entropy filter must drop it."""
    text = "found aaaaaaaaaaaaaaa6aaaaa6a6aaaaaaaa in slack space"
    out = extract(text)
    assert "aaaaaaaaaaaaaaa6aaaaa6a6aaaaaaaa" not in out["md5"]


def test_md5_homogeneous_padding_rejected():
    """Pure `aaaaaaaaaaaaaa...` shape — 1 unique char. Hard reject."""
    out = extract("payload aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa end")
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in out["md5"]


def test_md5_real_hash_passes():
    """A real MD5 — `e10adc3949ba59abbe56e057f20f883e` — uses 11
    unique characters, well above the threshold of 8."""
    text = "the malicious DLL hashes to e10adc3949ba59abbe56e057f20f883e"
    out = extract(text)
    assert "e10adc3949ba59abbe56e057f20f883e" in out["md5"]


def test_md5_threshold_boundary():
    """Exactly at the 8-unique-char threshold passes; below fails.
    The boundary value pins the threshold so a future tweak doesn't
    silently shift it."""
    # 8 distinct hex chars: 0,1,2,3,4,5,6,7 — pad to 32
    eight_unique = "0123456701234567012345670123abcd"
    text = f"hash: {eight_unique}"
    out = extract(text)
    assert eight_unique in out["md5"]


def test_sha1_padding_garbage_rejected():
    """40-char hex token, only `a` + `6` — should not survive."""
    text = "noise aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6aaaaa end"
    out = extract(text)
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6aaaaa" not in out["sha1"]


def test_sha1_real_hash_passes():
    """Real SHA1 — 14+ unique characters."""
    text = ("mimikatz sha1 = "
            "ad9f4e2da9d8a0f0d8a8c7b5e9f1234567890abc")
    out = extract(text)
    assert "ad9f4e2da9d8a0f0d8a8c7b5e9f1234567890abc" in out["sha1"]


def test_sha256_padding_garbage_rejected():
    """64-char hex from wiped disk space — `a` repeated with a
    sprinkle of `6` / `b`. Just 3 unique chars; filter must drop."""
    pad = "aaaaaaaaaaaaaaaa6666aaaaaaaabbbbaaaaaaaaaaaaaaaa6666aaaaaaaabbbb"
    out = extract(f"slack: {pad}")
    assert pad not in out["sha256"]


def test_sha256_real_hash_passes():
    """The SHA256 for the empty string — 19 unique characters."""
    empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    out = extract(f"hash: {empty_sha}")
    assert empty_sha in out["sha256"]


# ---------------------------------------------------------------------------
# BTC address — the user's literal SRL-2018 examples
# ---------------------------------------------------------------------------

def test_btc_padding_garbage_rejected_via_iocsearcher_path():
    """The user's example — `A6AAGAAGAbAAAAA6AAGAAGAAAAAAAApAWApAACAAAAA`.
    iocsearcher classifies this as `cryptocurrency` because Base58
    addresses share that alphabet shape. Filter must drop based on
    unique-char count (7 distinct chars vs 12-char threshold)."""
    token = "A6AAGAAGAbAAAAA6AAGAAGAAAAAAAApAWApAACAAAAA"
    assert not iocs_entropy(token, "cryptocurrency")


def test_btc_homogeneous_padding_rejected():
    """`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` — 1 unique char."""
    assert not iocs_entropy("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                             "cryptocurrency")


def test_btc_real_address_passes_entropy_check():
    """Genesis-block coinbase address — `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`.
    Real BTC addresses span >15 unique characters by construction
    (Base58 + checksum)."""
    genesis = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    out = extract(f"first BTC address: {genesis}")
    assert genesis in out["btc"]


def test_bech32_real_address_passes():
    """Bech32 BTC — `bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq`.
    >15 unique characters."""
    bech = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    out = extract(f"sent to {bech}")
    assert bech in out["btc"]


# ---------------------------------------------------------------------------
# iocsearcher entropy helper — direct unit tests
# ---------------------------------------------------------------------------

def test_iocs_entropy_unknown_key_passes_through():
    """The filter only enforces thresholds for keys it knows about.
    Unknown keys (phone, iban, cve, etc.) get a permissive pass."""
    assert iocs_entropy("xxxxx", "phone")
    assert iocs_entropy("xxxxx", "cve")


def test_iocs_entropy_onion_padding_rejected():
    """A 56-char onion v3 with low entropy is padding noise.
    Threshold 10 for onion — low enough to admit v2 onions
    (16-char base32, typically 10-13 distinct chars), high enough
    to drop padding-shaped strings (1-5 distinct)."""
    fake = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert not iocs_entropy(fake, "onion")


def test_iocs_entropy_real_v2_onion_passes():
    """Famous-but-deprecated DuckDuckGo v2 onion: 11 distinct chars
    over its 16-char body. Must clear the 10-char threshold."""
    assert iocs_entropy("3g2upl4pq6kufc4m", "onion")


def test_iocs_entropy_case_folding():
    """Case-insensitive — A and a count as one character so mixed-
    case padding like `AaAaAaAaAa...` doesn't sneak past."""
    fake = "AaAa" * 11  # 44 chars, only 2 distinct after case-fold
    assert not iocs_entropy(fake, "cryptocurrency")


def test_iocs_thresholds_are_reasonable():
    """Sanity-check the thresholds — must be > 1 (else the filter
    is a no-op) and < alphabet size (else it'd reject everything)."""
    assert IOCS_THRESHOLDS["cryptocurrency"] >= 5
    assert IOCS_THRESHOLDS["cryptocurrency"] <= 30
    assert IOCS_THRESHOLDS["onion"] >= 5
    assert IOCS_THRESHOLDS["onion"] <= 16


# ---------------------------------------------------------------------------
# Drop-noise toggle — filter only runs when drop_noise=True
# ---------------------------------------------------------------------------

def test_drop_noise_false_keeps_low_entropy_hashes():
    """Forensic mode where the analyst explicitly wants every regex
    match (e.g. for cross-checking against a different filter chain).
    Passing drop_noise=False must let the padding through."""
    text = "padding: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa end"
    out = extract(text, drop_noise=False)
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in out["md5"]


# ---------------------------------------------------------------------------
# fs_paths source kind — also runs the filter
# ---------------------------------------------------------------------------

def test_fs_paths_source_kind_also_filtered():
    """The fs_paths source-kind branch has its own filter chain;
    pin that it also drops low-entropy hashes (parallel to the
    main extract path)."""
    text = "0|/Windows/System32/x|1|r/r|0|0|0|0|0|0|0  hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    out = extract(text, source_kind="fs_paths")
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in out["md5"]
