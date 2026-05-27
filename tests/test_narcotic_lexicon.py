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


# ---------------------------------------------------------------------------
# Tier B — INCB Yellow List controlled-substance INNs
# ---------------------------------------------------------------------------

def test_specific_inn_with_price_is_standalone_strong():
    """A designer analogue (carfentanil) co-occurring with a price marker is
    high-confidence — near-zero benign-text incidence."""
    m = nl.scan_text("vendor list: carfentanil available, $80/g shipped")
    assert m is not None
    assert "carfentanil" in m.substance_hits
    assert m.signal_strength == "high"


def test_two_specific_inns_fire_alone():
    """Two designer analogues in one document clear the threshold with no
    other register — they are not medical/news vocabulary."""
    m = nl.scan_text("inventory: furanylfentanyl and isotonitazene in the cut")
    assert m is not None
    assert set(m.substance_hits) == {"furanylfentanyl", "isotonitazene"}


def test_common_inn_alone_is_gated_out():
    """A clinical note naming classic opiates is NOT a dealing signal —
    common INNs only count with co-occurrence."""
    assert nl.scan_text(
        "Patient prescribed morphine and codeine; methadone taper per protocol."
    ) is None


def test_common_inn_counts_with_co_occurrence():
    """Once another register is present (strain + price), common INNs
    corroborate and are surfaced."""
    m = nl.scan_text("got that og kush, also moving morphine + oxycodone $50/g")
    assert m is not None
    assert "morphine" in m.substance_hits and "oxycodone" in m.substance_hits


def test_medical_fentanils_stay_common_not_specific():
    """fentanyl/sufentanil/alfentanil/remifentanil appear in anesthesia
    text — they must be gated (COMMON), never standalone (SPECIFIC)."""
    from el.skills._yellow_list_inn import COMMON_INN, SPECIFIC_INN
    for med in ("fentanyl", "sufentanil", "alfentanil", "remifentanil"):
        assert med in COMMON_INN and med not in SPECIFIC_INN
    # carfentanil is the counter-example: designer/veterinary → SPECIFIC
    assert "carfentanil" in SPECIFIC_INN


def test_inn_word_boundary_no_substring_match():
    """'alfentanil' (a COMMON INN) alone must not match, and must not be
    mistaken for the SPECIFIC '…fentanil' analogues."""
    assert nl.scan_text("alfentanil used in anesthesia only") is None


def test_osac_stop_list_guards_positive_vocab():
    """The build-time guard: no single-word strain term may collide with
    OSAC forensic-lab jargon (minus allow-listed substances). Importing the
    module already runs the assert; this locks the contract explicitly."""
    from el.skills._osac_stoplist import ALLOW, STOP_TERMS
    guard = STOP_TERMS - ALLOW
    strain_single = {w for w in nl._STRAIN_WORDS if " " not in w}
    assert not (strain_single & guard)
    # the trap terms OSAC protects against are present in the stop-list
    assert {"tablets", "grains", "nuggets", "habit"} <= STOP_TERMS
    assert "cocaine" in ALLOW  # real substance OSAC also defines
