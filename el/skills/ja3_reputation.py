"""JA3 / JA3S fingerprint reputation.

JA3 is a 32-char md5 of a TLS ClientHello's cipher-suite + extensions
tuple — stable per TLS-library build, so implant frameworks that
hardcode the handshake (Cobalt Strike, Meterpreter) leak an
identifiable fingerprint. EL's network_analyst already extracts JA3
via Zeek; this module turns each hash into one of three reputation
classes.

Reputation classes
------------------

- ``"known_bad"`` : Hash appears in a curated allowlist with explicit
  public attribution. Highest-confidence signal this module emits.
  Kept intentionally small — false-positive-averse per the project's
  no-sycophancy rule.

- ``"unknown"`` : Hash not on any list. May be benign (a non-browser
  HTTP client, an internal tool, a phone browser version we don't
  track) or may be implant traffic we haven't catalogued. The caller
  uses cross-case rarity from ``el.knowledge`` to gauge novelty.

- ``"benign_common"`` : Hash matches a well-documented stable client
  fingerprint (curl, wget, older Go net/http). Rarely worth emitting.

Sources
-------

The ``KNOWN_BAD_JA3`` table is hand-curated from abuse.ch SSLBlacklist
+ salesforce/ja3 repo + published research. Each row carries a
``source`` pointer so the analyst can verify before acting on the
finding. When a new implant JA3 is published with independent
corroboration, append; when a hash turns up in legitimate traffic,
remove.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class JA3Reputation:
    classification: str            # "known_bad" / "benign_common" / "unknown"
    label: str | None = None       # short human-readable family / tool
    source: str | None = None      # URL / citation — analyst-verifiable


# Known-bad. MD5-shape check (32 hex chars) is enforced; nothing else
# goes in without a public reference.
KNOWN_BAD_JA3: dict[str, tuple[str, str]] = {
    # Cobalt Strike default TLS profile (staged beacon). Widely
    # documented — salesforce/ja3 corpus, Splunk CSC hunting posts.
    "a0e9f5d64349fb13191bc781f81f42e1":
        ("Cobalt Strike default TLS profile",
         "https://github.com/salesforce/ja3"),
    # Metasploit reverse_https / Meterpreter default handshake. Same
    # provenance.
    "72a589da586844d7f0818ce684948eea":
        ("Meterpreter / Metasploit reverse_https default",
         "https://github.com/salesforce/ja3"),
    # Emotet banking trojan C2 — abuse.ch SSLBlacklist.
    "6734f37431670b3ab4292b8f60f29984":
        ("Emotet C2",
         "https://sslbl.abuse.ch/ja3-fingerprints/"),
    # TrickBot C2. Same source.
    "bd4c5fbce93a6f30bf9fab3af8496b94":
        ("TrickBot C2",
         "https://sslbl.abuse.ch/ja3-fingerprints/"),
}

# Benign-common. Kept small on purpose — the safer mechanism for
# benign suppression is cross-case rarity (a hash seen in ≥3 prior
# cases is likely a local stable client). Entries here are stable
# across years.
BENIGN_COMMON_JA3: dict[str, str] = {
    # curl/libcurl w/ OpenSSL 1.1.x — appears in every reasonable
    # corpus of Linux automation / CI traffic.
    "0f94a14c08c9bbcf8a8e23fe4a7f8fed": "curl / libcurl",
}


def _is_ja3_shape(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 32:
        return False
    return all(c in "0123456789abcdef" for c in value.lower())


def classify(ja3_hash: str) -> JA3Reputation:
    """Return a JA3Reputation for this hash. Unknown hashes get an
    ``"unknown"`` record — the caller then layers rarity from the
    knowledge DB on top."""
    if not _is_ja3_shape(ja3_hash):
        return JA3Reputation("unknown", None, None)
    norm = ja3_hash.lower()
    if norm in KNOWN_BAD_JA3:
        label, source = KNOWN_BAD_JA3[norm]
        return JA3Reputation("known_bad", label, source)
    if norm in BENIGN_COMMON_JA3:
        return JA3Reputation("benign_common", BENIGN_COMMON_JA3[norm], None)
    return JA3Reputation("unknown", None, None)


__all__ = [
    "JA3Reputation", "KNOWN_BAD_JA3", "BENIGN_COMMON_JA3", "classify",
]
