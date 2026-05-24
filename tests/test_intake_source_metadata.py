"""Contract tests for the Source.txt evidence-provenance convention.

Operator convention: drop a Source.txt file alongside the evidence
(in the directory for dir inputs, in the parent dir for file inputs)
with `Name: ...`, `Url: ...`, `Source: ...` lines. EL parses it at
intake time and persists the values into manifest.json so the report
can name the corpus / scenario without manual edits.

Locks in:
  * Canonical Source.txt parsed (LoneWolf example shape)
  * Variant filenames (SOURCE / PROVENANCE.txt) recognised
  * Variant keys (URL / Title / Origin) normalised to canonical
  * Missing file → all source_* manifest fields are None, no error
  * File-input mode looks in the parent directory
  * Best-effort: empty / malformed Source.txt does not raise
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from el.evidence import intake as intake_mod
from el.evidence.intake import (
    _parse_source_file,
    _read_source_metadata,
    intake,
)


# ---------------------------------------------------------------------------
# Parser-level tests (no I/O)
# ---------------------------------------------------------------------------

def test_parses_lonewolf_canonical_shape():
    """The exact LoneWolf Source.txt the operator dropped onto the
    USB image. Locks in the three canonical keys (Name / Url /
    Source) round-tripping into the manifest."""
    text = (
        'Name: "2018 Lone Wolf Scenario"\n'
        "Url: https://digitalcorpora.org/corpora/scenarios/"
        "2018-lone-wolf-scenario/\n"
        "Source: Digital Corpora\n"
    )
    out = _parse_source_file(text)
    assert out["source_name"] == "2018 Lone Wolf Scenario"
    assert out["source_url"] == (
        "https://digitalcorpora.org/corpora/scenarios/"
        "2018-lone-wolf-scenario/"
    )
    assert out["source_org"] == "Digital Corpora"


def test_parser_normalises_key_aliases():
    """In-the-wild Source.txt files vary the key casing and use
    synonyms (URL, Title, Origin). Parser folds them all to the
    canonical source_name / source_url / source_org."""
    text = (
        "TITLE: M57 Patents Scenario\n"
        "url: https://digitalcorpora.org/corpora/scenarios/m57-jean/\n"
        "Origin: NPS\n"
    )
    out = _parse_source_file(text)
    assert out["source_name"] == "M57 Patents Scenario"
    assert out["source_url"] == \
        "https://digitalcorpora.org/corpora/scenarios/m57-jean/"
    assert out["source_org"] == "NPS"


def test_parser_strips_quotes_around_value():
    """Single- and double-quoted values resolve to the unquoted
    string — they're a common cosmetic in operator-written files."""
    text = (
        "Name: 'BelkaCTF Kidnapper'\n"
        'Source: "Belkasoft"\n'
    )
    out = _parse_source_file(text)
    assert out["source_name"] == "BelkaCTF Kidnapper"
    assert out["source_org"] == "Belkasoft"


def test_parser_ignores_blank_lines_and_comments():
    text = (
        "# evidence provenance\n"
        "\n"
        "Name: SRL-2018 corpus\n"
        "# the URL is published at the SANS portal\n"
        "Url: https://sansforensics.example/srl-2018\n"
    )
    out = _parse_source_file(text)
    assert out["source_name"] == "SRL-2018 corpus"
    assert "source_org" not in out


def test_parser_ignores_unknown_keys():
    """Keys we don't have a canonical mapping for are silently
    skipped — they don't appear in the result, but the file as a
    whole still parses successfully."""
    text = (
        "Name: scenario\n"
        "Custodian: jdoe\n"        # not a known field
        "Acquisition-date: 2018-04-06\n"
        "Source: someorg\n"
    )
    out = _parse_source_file(text)
    assert out == {
        "source_name": "scenario",
        "source_org": "someorg",
    }


def test_parser_empty_input_returns_empty():
    assert _parse_source_file("") == {}
    assert _parse_source_file("\n\n# just comments\n") == {}


def test_parser_lines_without_colon_skipped():
    """A free-form note without `key: value` shape is ignored, not
    raised on. Source.txt files in the wild sometimes have a header
    paragraph at the top."""
    text = (
        "This file documents where the LoneWolf images were sourced.\n"
        "\n"
        "Name: Lone Wolf\n"
    )
    out = _parse_source_file(text)
    assert out == {"source_name": "Lone Wolf"}


# ---------------------------------------------------------------------------
# Filesystem-level discovery
# ---------------------------------------------------------------------------

def test_directory_input_finds_top_level_source_txt(tmp_path):
    """For a directory input, Source.txt at the top level of the
    input dir is the canonical location."""
    evidence_dir = tmp_path / "images"
    evidence_dir.mkdir()
    (evidence_dir / "disk.E01").write_bytes(b"\x00" * 64)
    (evidence_dir / "Source.txt").write_text(
        "Name: example\nSource: testcorpus\n")
    parsed, source_path = _read_source_metadata(evidence_dir)
    assert parsed == {"source_name": "example",
                       "source_org": "testcorpus"}
    assert source_path is not None
    assert source_path.name == "Source.txt"


def test_file_input_finds_sibling_source_txt(tmp_path):
    """For a file input, the Source.txt sitting next to the file in
    the same directory must be picked up — this is the common shape
    when the evidence is a single .E01 with a sibling provenance
    file."""
    evidence_dir = tmp_path / "images"
    evidence_dir.mkdir()
    e01 = evidence_dir / "disk.E01"
    e01.write_bytes(b"\x00" * 64)
    (evidence_dir / "Source.txt").write_text("Name: solo-file-case\n")
    parsed, source_path = _read_source_metadata(e01)
    assert parsed == {"source_name": "solo-file-case"}
    assert source_path is not None


def test_missing_source_txt_returns_empty(tmp_path):
    """No Source.txt → empty dict, None path. Must not raise — the
    convention is opt-in."""
    evidence_dir = tmp_path / "no_provenance"
    evidence_dir.mkdir()
    (evidence_dir / "disk.E01").write_bytes(b"\x00" * 64)
    parsed, source_path = _read_source_metadata(evidence_dir)
    assert parsed == {}
    assert source_path is None


def test_alternative_filenames_recognised(tmp_path):
    """`SOURCE.txt` / `SOURCE` / `PROVENANCE.txt` all act as
    valid Source.txt synonyms."""
    for fname in ("SOURCE.txt", "SOURCE", "PROVENANCE.txt",
                   "provenance.txt"):
        d = tmp_path / fname.replace(".", "_")
        d.mkdir()
        (d / fname).write_text("Name: variant\n")
        parsed, source_path = _read_source_metadata(d)
        assert parsed == {"source_name": "variant"}, fname
        assert source_path.name == fname


def test_canonical_source_txt_wins_over_variant(tmp_path):
    """When both `Source.txt` and `SOURCE` exist, the canonical
    `Source.txt` is read (it's first in the preference order)."""
    d = tmp_path / "case"
    d.mkdir()
    (d / "Source.txt").write_text("Name: canonical\n")
    (d / "SOURCE").write_text("Name: variant\n")
    parsed, source_path = _read_source_metadata(d)
    assert parsed == {"source_name": "canonical"}
    assert source_path.name == "Source.txt"


# ---------------------------------------------------------------------------
# End-to-end through intake()
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_case_root(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    yield tmp_path


def test_intake_writes_source_fields_into_manifest(isolated_case_root):
    """End-to-end: intake() on a directory with Source.txt produces
    a manifest.json carrying the parsed provenance keys."""
    evidence_dir = isolated_case_root / "images"
    evidence_dir.mkdir()
    (evidence_dir / "disk.E01").write_bytes(b"\x00" * 64)
    (evidence_dir / "Source.txt").write_text(
        'Name: "Lone Wolf"\n'
        "Url: https://digitalcorpora.org/corpora/scenarios/"
        "2018-lone-wolf-scenario/\n"
        "Source: Digital Corpora\n"
    )

    manifest = intake(evidence_dir, case_id="src-test")

    assert manifest.source_name == "Lone Wolf"
    assert manifest.source_org == "Digital Corpora"
    assert "lone-wolf-scenario" in manifest.source_url
    assert manifest.source_path.endswith("Source.txt")

    # Round-trips through the on-disk manifest.json
    persisted = json.loads(
        Path(manifest.case_dir, "manifest.json").read_text())
    assert persisted["source_name"] == "Lone Wolf"
    assert persisted["source_org"] == "Digital Corpora"


def test_intake_without_source_txt_leaves_fields_none(isolated_case_root):
    """Intake on a directory with no Source.txt: all four source_*
    fields are None, manifest still valid."""
    evidence_dir = isolated_case_root / "no_src"
    evidence_dir.mkdir()
    (evidence_dir / "disk.E01").write_bytes(b"\x00" * 64)

    manifest = intake(evidence_dir, case_id="no-src-test")

    assert manifest.source_name is None
    assert manifest.source_url is None
    assert manifest.source_org is None
    assert manifest.source_path is None
    # Hashing + base fields still populate normally
    assert manifest.input_sha256
    assert manifest.input_size_bytes > 0


def test_intake_on_single_file_finds_sibling_source(isolated_case_root):
    """File-input path: drop a Source.txt next to the .E01."""
    evidence_dir = isolated_case_root / "single"
    evidence_dir.mkdir()
    e01 = evidence_dir / "disk.E01"
    e01.write_bytes(b"\x00" * 64)
    (evidence_dir / "Source.txt").write_text(
        "Name: lone-file-case\n")

    manifest = intake(e01, case_id="single-file-src")
    assert manifest.source_name == "lone-file-case"
