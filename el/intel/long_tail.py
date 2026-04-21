"""Long-tail IOC rarity scoring.

An IOC that shows up in 200 cases is noise — benign infrastructure
(Google DNS, Windows Update endpoints, telemetry beacons, certificate
authority URLs) visible in every enterprise capture. An IOC that
shows up in 1 case is the interesting tail of the distribution —
attacker-specific infrastructure.

This skill computes a rarity score per IOC value against EL's
cross-case knowledge store and buckets it:

  rare     (appeared in ≤ 2 prior cases)
  uncommon (3 – 10 prior cases)
  common   (11 – 50 prior cases)
  ubiquitous (>50 prior cases — likely benign infrastructure)

Consumers use this to:
  - Raise analyst attention on rare IOCs (bubble to top of the
    cross-case finding)
  - Suppress low-signal lifts for ubiquitous IOCs (e.g. 8.8.8.8,
    fonts.googleapis.com, time.windows.com)
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RarityScore:
    value: str
    case_count: int           # prior cases (excluding the current one)
    bucket: str               # rare / uncommon / common / ubiquitous


_RARE_MAX = 2
_UNCOMMON_MAX = 10
_COMMON_MAX = 50


def bucket_for_case_count(count: int) -> str:
    if count <= _RARE_MAX:
        return "rare"
    if count <= _UNCOMMON_MAX:
        return "uncommon"
    if count <= _COMMON_MAX:
        return "common"
    return "ubiquitous"


def score(value: str, prior_observations: list[dict]) -> RarityScore:
    """Given an IOC value and its prior-observation rows from
    knowledge.lookup_iocs, return a RarityScore. `prior_observations`
    is expected to be the list[dict] shape lookup_iocs returns:
    [{case_id, ioc_type, observed_utc, agent}, ...]
    """
    distinct_cases = {o.get("case_id") for o in prior_observations
                      if o.get("case_id")}
    # lookup_iocs already excludes the current case by design
    n = len(distinct_cases)
    return RarityScore(
        value=value,
        case_count=n,
        bucket=bucket_for_case_count(n),
    )


def score_many(lookup_result: dict[str, list[dict]],
               ) -> dict[str, RarityScore]:
    """Batch version — given the dict returned by knowledge.lookup_iocs,
    compute a RarityScore for each value."""
    return {v: score(v, observations)
            for v, observations in lookup_result.items()}


def should_suppress(bucket: str) -> bool:
    """Ubiquitous IOCs should not lift any hypothesis in a new case
    — they're noise. Everything rarer contributes (at baseline
    confidence)."""
    return bucket == "ubiquitous"


def confidence_modifier(bucket: str) -> str:
    """Optional lift on the finding confidence tier based on rarity.
    Rare = 'high' signal; common = 'low'; ubiquitous = 'insufficient'
    (suppress)."""
    return {
        "rare":       "high",
        "uncommon":   "medium",
        "common":     "low",
        "ubiquitous": "insufficient",
    }.get(bucket, "low")


__all__ = [
    "RarityScore",
    "bucket_for_case_count", "score", "score_many",
    "should_suppress", "confidence_modifier",
]
