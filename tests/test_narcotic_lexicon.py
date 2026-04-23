"""Tests for the narcotic-lexicon scanner."""
from __future__ import annotations

from pathlib import Path

from el.skills import narcotic_lexicon as nl


def test_single_strain_alone_below_threshold(tmp_path):
    """One 'kush' mention is not evidence of dealing — the threshold
    requires ≥2 signals."""
    assert nl.scan_text("My yard smells like kush after the rain.") is None


def test_strain_plus_unit_fires(tmp_path):
    m = nl.scan_text("og kush 3.5g 35 per gram dm for more")
    assert m is not None
    assert "og kush" in m.strain_hits
    assert any(u.lower().endswith("g") or "gram" in u.lower()
                for u in m.unit_hits)


def test_price_per_unit_fires_on_dollar_notation():
    m = nl.scan_text("acapulco gold — $25/g or $180 per oz")
    assert m is not None
    assert m.strain_hits == ["acapulco gold"]
    assert len(m.price_hits) >= 1


def test_emoji_cipher_alone_below_threshold():
    """A snowflake emoji in a winter-themed blog is not narcotic evidence."""
    assert nl.scan_text("Winter is here ❄ the storm is beautiful") is None


def test_scan_walks_home_text_files(tmp_path):
    notes = tmp_path / "mynote" / "orders.txt"
    notes.parent.mkdir(parents=True)
    notes.write_text("og kush 5g client paid 80/g via btc\n"
                      "trainwreck 3.5g today\n")
    hits = nl.walk_files(tmp_path)
    assert len(hits) == 1
    assert hits[0].path.name == "orders.txt"


def test_binary_files_ignored(tmp_path):
    """Pdfs / images / zips are out of scope — the lexicon regex on
    compressed bytes produces noise."""
    (tmp_path / "x.pdf").write_bytes(b"%PDF-1.4\nog kush\n")
    (tmp_path / "x.zip").write_bytes(b"PK\x03\x04og kush 3.5g")
    assert nl.walk_files(tmp_path) == []


def test_signal_strength_high_requires_multiple_categories():
    m = nl.scan_text(
        "og kush 3.5g $35/g, trainwreck qp $1200, girl scout cookies 7g"
    )
    assert m is not None
    assert m.signal_strength == "high"
