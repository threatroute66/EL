"""Skill: load Cisco Umbrella's top-1M-domain ranking as an allowlist.

Closes the gap-doc Network-depth deferred bullet "TLS JA3/JA4 +
Umbrella-top-1M allowlisting for noise reduction" (line 155). The
JA3 known-bad / cross-case-rarity half landed in `9c2df40`; this is
the missing companion that lets `network_analyst` (and any other
domain-extracting detector) ask "is this domain in the top-N global
ranking?" before emitting a finding.

Format (operator pre-downloads from
http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv):

    1,google.com
    2,microsoft.com
    3,facebook.com
    ...

The allowlist file path is resolved from `EL_UMBRELLA_TOP1M`
(env var) or, as a fallback, `/opt/EL/rules/umbrella-top-1m.csv`.
Empty / missing → ``UmbrellaAllowlist.is_top()`` always returns
False (no suppression — defaults to "fire findings").
"""
from __future__ import annotations

import csv
import os
from dataclasses import dataclass, field
from pathlib import Path


_DEFAULT_PATH = Path("/opt/EL/rules/umbrella-top-1m.csv")


@dataclass
class UmbrellaAllowlist:
    csv_path: Path | None = None
    rank_by_domain: dict[str, int] = field(default_factory=dict)

    @property
    def loaded(self) -> bool:
        return bool(self.rank_by_domain)

    @property
    def size(self) -> int:
        return len(self.rank_by_domain)

    def is_top(self, domain: str, *, threshold: int = 50_000) -> bool:
        """True iff `domain` is in the top `threshold` ranked entries.
        Case-insensitive; trailing dot stripped (Zeek/Wireshark
        sometimes emit FQDNs with the root dot)."""
        if not domain or not self.rank_by_domain:
            return False
        d = domain.lower().rstrip(".")
        rank = self.rank_by_domain.get(d)
        return rank is not None and rank <= threshold

    def filter_to_long_tail(self, domains, *,
                             threshold: int = 50_000) -> list[str]:
        """Return the subset of `domains` NOT in the top-`threshold`
        ranking — i.e. the long-tail signal that's worth surfacing.
        Preserves input order; deduplicates."""
        seen = set()
        out: list[str] = []
        for d in domains:
            if not d:
                continue
            key = d.lower().rstrip(".")
            if key in seen:
                continue
            seen.add(key)
            if not self.is_top(key, threshold=threshold):
                out.append(d)
        return out


def resolve_csv_path() -> Path | None:
    """Operator-supplied path via env, falling back to the canonical
    /opt/EL/rules/umbrella-top-1m.csv. Returns None if neither
    points at a file."""
    env = os.environ.get("EL_UMBRELLA_TOP1M")
    if env:
        p = Path(env)
        if p.is_file():
            return p
    if _DEFAULT_PATH.is_file():
        return _DEFAULT_PATH
    return None


def load(csv_path: Path | None = None,
          *, max_entries: int = 1_000_000) -> UmbrellaAllowlist:
    """Load the Umbrella top-1m CSV into a rank lookup. Empty
    UmbrellaAllowlist when the file is missing — every call to
    is_top() then short-circuits to False, so the skill is
    side-effect-free when no list is staged."""
    p = csv_path or resolve_csv_path()
    al = UmbrellaAllowlist(csv_path=p)
    if p is None or not p.is_file():
        return al
    try:
        with p.open("r", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 2:
                    continue
                try:
                    rank = int(row[0])
                except ValueError:
                    continue
                domain = row[1].strip().lower().rstrip(".")
                if not domain:
                    continue
                # First occurrence wins (rank ascending in canonical
                # Umbrella export — but defensive against duplicates).
                if domain not in al.rank_by_domain:
                    al.rank_by_domain[domain] = rank
                if len(al.rank_by_domain) >= max_entries:
                    break
    except OSError:
        pass
    return al


# Process-level cache so the 50 MB CSV is read once per investigation
_cache: UmbrellaAllowlist | None = None


def cached() -> UmbrellaAllowlist:
    """Singleton accessor — reads the CSV once per process. Useful
    for high-throughput callers (every IOC extraction pass)."""
    global _cache
    if _cache is None:
        _cache = load()
    return _cache


__all__ = [
    "UmbrellaAllowlist", "resolve_csv_path", "load", "cached",
]
