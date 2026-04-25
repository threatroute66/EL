"""Umbrella top-1M allowlist skill — noise suppression for common
domains.

Closes gap-doc Network-depth bullet "TLS JA3/JA4 + Umbrella-top-1M
allowlisting for noise reduction" (line 155, the missing companion
to the JA3 known-bad / cross-case-rarity half shipped in 9c2df40).
"""
from pathlib import Path

import pytest

from el.skills import umbrella_allowlist as ua


def _write_csv(p: Path, rows: list[tuple[int, str]]):
    p.write_text("\n".join(f"{r},{d}" for r, d in rows) + "\n")


def test_load_basic(tmp_path):
    csv = tmp_path / "top.csv"
    _write_csv(csv, [(1, "google.com"), (2, "microsoft.com"),
                     (3, "facebook.com")])
    al = ua.load(csv)
    assert al.loaded is True
    assert al.size == 3
    assert al.rank_by_domain["google.com"] == 1
    assert al.rank_by_domain["microsoft.com"] == 2


def test_is_top_threshold(tmp_path):
    csv = tmp_path / "top.csv"
    _write_csv(csv, [(1, "google.com"), (50_000, "edge.example"),
                     (50_001, "longtail.example")])
    al = ua.load(csv)
    assert al.is_top("google.com") is True
    assert al.is_top("edge.example") is True              # exactly at threshold
    assert al.is_top("longtail.example") is False         # past threshold
    assert al.is_top("longtail.example", threshold=60_000) is True
    # Tighter threshold can demote a previously-suppressed domain
    assert al.is_top("edge.example", threshold=10_000) is False


def test_is_top_case_and_dot_normalisation(tmp_path):
    csv = tmp_path / "top.csv"
    _write_csv(csv, [(1, "google.com")])
    al = ua.load(csv)
    assert al.is_top("Google.COM") is True
    assert al.is_top("google.com.") is True               # trailing FQDN dot
    assert al.is_top("") is False
    assert al.is_top("not-listed.test") is False


def test_filter_to_long_tail_dedups(tmp_path):
    csv = tmp_path / "top.csv"
    _write_csv(csv, [(1, "google.com"), (2, "microsoft.com")])
    al = ua.load(csv)
    domains = ["google.com", "evil.example", "Google.COM",
               "microsoft.com", "evil.example", "rare.example"]
    out = al.filter_to_long_tail(domains)
    # google + microsoft suppressed; evil dedup'd; order preserved
    assert out == ["evil.example", "rare.example"]


def test_filter_to_long_tail_empty_allowlist(tmp_path):
    """No CSV staged → nothing suppressed (defaults to "fire findings")."""
    al = ua.UmbrellaAllowlist()
    domains = ["google.com", "evil.example"]
    assert al.filter_to_long_tail(domains) == ["google.com", "evil.example"]


def test_resolve_csv_path_env_precedence(tmp_path, monkeypatch):
    csv = tmp_path / "operator.csv"
    _write_csv(csv, [(1, "x.com")])
    monkeypatch.setenv("EL_UMBRELLA_TOP1M", str(csv))
    assert ua.resolve_csv_path() == csv


def test_resolve_csv_path_env_missing_falls_through(tmp_path,
                                                     monkeypatch):
    monkeypatch.setenv("EL_UMBRELLA_TOP1M", str(tmp_path / "absent.csv"))
    monkeypatch.setattr(ua, "_DEFAULT_PATH", tmp_path / "also-absent.csv")
    assert ua.resolve_csv_path() is None


def test_resolve_csv_path_default_fallback(tmp_path, monkeypatch):
    csv = tmp_path / "default.csv"
    _write_csv(csv, [(1, "y.com")])
    monkeypatch.delenv("EL_UMBRELLA_TOP1M", raising=False)
    monkeypatch.setattr(ua, "_DEFAULT_PATH", csv)
    assert ua.resolve_csv_path() == csv


def test_load_missing_file_safe(tmp_path):
    al = ua.load(tmp_path / "absent.csv")
    assert al.loaded is False
    assert al.is_top("anything.com") is False
    # filter is the identity when allowlist is empty
    assert al.filter_to_long_tail(["a.com", "b.com"]) == ["a.com", "b.com"]


def test_load_tolerates_malformed_rows(tmp_path):
    csv = tmp_path / "messy.csv"
    csv.write_text(
        "1,good.com\n"
        "notanint,broken.com\n"
        "\n"
        "2\n"                # rank only — no domain column
        "3,UPPERCASE.COM\n"  # domain normalised to lowercase
        "4,trailing-dot.com.\n"
        "5,\n"               # empty domain
    )
    al = ua.load(csv)
    assert al.size == 3
    assert "good.com" in al.rank_by_domain
    assert "uppercase.com" in al.rank_by_domain
    assert "trailing-dot.com" in al.rank_by_domain


def test_load_max_entries_cap(tmp_path):
    csv = tmp_path / "big.csv"
    _write_csv(csv, [(i, f"d{i}.example") for i in range(1, 1001)])
    al = ua.load(csv, max_entries=10)
    assert al.size == 10
    assert al.is_top("d1.example") is True
    assert al.is_top("d999.example") is False             # truncated out


def test_load_first_occurrence_wins(tmp_path):
    """Defensive against duplicate rows in the CSV — keep the first
    (canonical Umbrella exports are rank-ascending so first = best)."""
    csv = tmp_path / "dup.csv"
    csv.write_text("1,google.com\n7,google.com\n")
    al = ua.load(csv)
    assert al.rank_by_domain["google.com"] == 1


def test_cached_singleton(tmp_path, monkeypatch):
    csv = tmp_path / "cached.csv"
    _write_csv(csv, [(1, "cached.example")])
    monkeypatch.setenv("EL_UMBRELLA_TOP1M", str(csv))
    monkeypatch.setattr(ua, "_cache", None)
    a = ua.cached()
    b = ua.cached()
    assert a is b
    assert a.is_top("cached.example") is True
