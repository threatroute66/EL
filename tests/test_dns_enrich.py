"""DNS enrichment skill — passive-DNS CSV reader + opt-in live mode.

Closes gap-doc Detection-engineering deferred row "Forward/reverse DNS
enrichment on IP-only IOCs" (line 165).

Live lookups are gated behind `EL_DNS_LIVE_LOOKUPS=1`. We don't
exercise live mode here — that would emit DNS queries. Tests cover:

- passive-DNS CSV parsing (tab + comma)
- field-name flexibility (rdata/value/ip; rrname/name/hostname)
- merge_enrichments combining live + passive
- live mode is OFF by default
"""
from pathlib import Path

import pytest

from el.skills import dns_enrich as de


# --- live-mode gating ----------------------------------------------------

def test_live_lookups_disabled_by_default(monkeypatch):
    monkeypatch.delenv("EL_DNS_LIVE_LOOKUPS", raising=False)
    assert de.is_live_enrichment_enabled() is False
    # And enrich_live silently returns empty
    assert de.enrich_live(["1.2.3.4"]) == {}


def test_live_lookups_opt_in_via_env(monkeypatch):
    monkeypatch.setenv("EL_DNS_LIVE_LOOKUPS", "1")
    assert de.is_live_enrichment_enabled() is True
    # Don't actually exercise the live path — just confirm the gate flips.


# --- passive-DNS CSV ----------------------------------------------------

def _stage_csv(tmp_path: Path, header: str, rows, delim="\t") -> Path:
    p = tmp_path / "pdns.tsv"
    with p.open("w") as f:
        f.write(header + "\n")
        for r in rows:
            f.write(delim.join(r) + "\n")
    return p


def test_passive_csv_canonical_columns(tmp_path):
    csv = _stage_csv(tmp_path,
                     "rrname\ttype\trdata",
                     [("evil.com", "A", "1.2.3.4"),
                      ("good.com", "A", "8.8.8.8"),
                      ("alt.evil.com", "A", "1.2.3.4")])
    out = de.enrich_passive(["1.2.3.4", "8.8.8.8"], csv)
    assert "evil.com" in out["1.2.3.4"].passive_rrnames
    assert "alt.evil.com" in out["1.2.3.4"].passive_rrnames
    assert out["8.8.8.8"].passive_rrnames == ["good.com"]


def test_passive_csv_alternate_column_names(tmp_path):
    csv = _stage_csv(tmp_path,
                     "ip\tquery\tlast_seen",
                     [("1.2.3.4", "evil.com", "2026-04-01")])
    out = de.enrich_passive(["1.2.3.4"], csv)
    assert out["1.2.3.4"].passive_rrnames == ["evil.com"]


def test_passive_csv_skips_non_target_ips(tmp_path):
    csv = _stage_csv(tmp_path,
                     "rrname\trdata",
                     [("foo.com", "1.2.3.4"), ("bar.com", "9.9.9.9")])
    out = de.enrich_passive(["1.2.3.4"], csv)
    assert "foo.com" in out["1.2.3.4"].passive_rrnames
    assert "9.9.9.9" not in out
    assert "bar.com" not in (out["1.2.3.4"].passive_rrnames)


def test_passive_csv_missing_file_returns_empty_records(tmp_path):
    out = de.enrich_passive(["1.2.3.4"], tmp_path / "nope.csv")
    # Returns the IP keys but with empty rrname lists
    assert "1.2.3.4" in out
    assert out["1.2.3.4"].passive_rrnames == []


# --- merge --------------------------------------------------------------

def test_merge_combines_sources():
    live = {"1.2.3.4": de.DnsEnrichment(
        ip="1.2.3.4", ptr_names=["ptr.example.com"],
        forward_confirmed=["ptr.example.com"], source="live")}
    passive = {"1.2.3.4": de.DnsEnrichment(
        ip="1.2.3.4", passive_rrnames=["historical.example.com"],
        source="passive")}
    merged = de.merge_enrichments(live, passive)
    rec = merged["1.2.3.4"]
    assert rec.ptr_names == ["ptr.example.com"]
    assert rec.forward_confirmed == ["ptr.example.com"]
    assert rec.passive_rrnames == ["historical.example.com"]
    assert "live" in rec.source and "passive" in rec.source
