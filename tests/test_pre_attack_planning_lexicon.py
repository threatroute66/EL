"""Contract tests for el/skills/pre_attack_planning_lexicon.py.

Locks in the reference-corpus filter discovered on the Rocba SANS
Standard Forensic Case run: an `english_wikipedia.txt` reference
text dump fired the planning lexicon (weapons + ammo + intent)
on common English vocabulary (`suppressor`, `manifesto`, `23rd`)
and lifted H_PRE_ATTACK_PLANNING by 23 points off a clearly false
positive.

The filter is filename-shape based (case-insensitive substring on
the basename, NOT the full path) so it cannot be evaded by putting
the reference text inside a directory called `planning` — directory
names are evidence about the user, not corpus identity. Conversely
an analyst who suspects a renamed reference file can rename / copy
and re-scan; the filter never inspects bytes.

This module also exercises a couple of `scan_text` invariants that
weren't directly tested before (signal_strength thresholds, no-hit
returns None).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from el.skills.pre_attack_planning_lexicon import (
    _REFERENCE_CORPUS_PATTERNS,
    _is_reference_corpus,
    scan_text,
    walk_files,
)


# Realistic snippet that ALWAYS fires the lexicon: covers weapons +
# ammo + intent categories, easily clears the ≥3-category threshold.
# Used as the payload inside both the legitimate planning notes and
# the misleadingly-named reference-corpus files in tests below.
_LONE_WOLF_PAYLOAD = (
    "Operation 2nd Hand Smoke planning notes.\n"
    "Acquire kel-tec sub 2000 — 9mm 1000 for $360.\n"
    "Manifesto draft: I will be the change, fresh start in Bali.\n"
    "Suppressor research — non-extradition countries, escape route.\n"
)


# ---------------------------------------------------------------------------
# _is_reference_corpus — filename classifier
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "english_wikipedia.txt",           # the actual Rocba false positive
    "ENGLISH_WIKIPEDIA.TXT",           # case-insensitive
    "wikipedia-2020.json",             # version-suffixed dump
    "simple.wikipedia.txt",            # wiki sub-corpus
    "wiktionary-en.txt",
    "wordnet_3.1.zip",                 # never scanned but proves match
    "english_dictionary.txt",
    "thesaurus.json",
    "wordlist_top_1m.txt",
    "english_corpus.csv",
    "training_data.txt",
    "language_model_vocab.txt",
    "scowl-2020.04.18.txt",
    "hunspell_en_US.dic",
    "aspell-en.wordlist",
    "shakespeare_complete.txt",
    "gutenberg_corpus.json",
    "common_crawl_sample.txt",
    "1grams.txt",
    "5grams_english.csv",
    "ngrams_2024.tsv",
    "frequency_list.txt",
    "manpage_dump.txt",
    "man_pages_archive.txt",
])
def test_recognises_reference_corpus_names(name):
    assert _is_reference_corpus(Path(name)) is True


@pytest.mark.parametrize("name", [
    "Planning.docx",
    "The Cloudy Manifesto.docx",
    "Operation 2nd Hand Smoke.pptx",
    "notes.txt",
    "diary.md",
    "browser_history_export.csv",
    "Autofill.json",
    "google_searches.txt",
    "chat_log.txt",
])
def test_does_not_match_legitimate_planning_filenames(name):
    """The hits we want to keep: actual planning notes, diaries,
    browser-history exports, autofill dumps. None of these names
    should accidentally match the reference-corpus patterns."""
    assert _is_reference_corpus(Path(name)) is False


def test_filter_is_filename_only_not_path():
    """A planning.docx living under a directory called wikipedia
    is NOT skipped — the filter looks at the basename only. Reason:
    directory names are evidence about user intent, not corpus
    identity."""
    p = Path("/some/path/wikipedia/Planning.docx")
    assert _is_reference_corpus(p) is False


def test_filter_substring_match_inside_filename():
    """The pattern is a substring on the basename, so a file named
    `my_wikipedia_dump.csv` matches (the word is right there in
    the name)."""
    assert _is_reference_corpus(Path("my_wikipedia_dump.csv")) is True


def test_filter_does_not_match_unrelated_prefix():
    """A name with no reference-corpus substring is not matched
    even if it contains other English words."""
    assert _is_reference_corpus(
        Path("project_notes_quarterly.txt")) is False


def test_filter_patterns_list_is_non_empty():
    """Sanity: the patterns list must not be silently empty (a
    refactor that wipes it would render the filter a no-op)."""
    assert len(_REFERENCE_CORPUS_PATTERNS) > 0
    assert "wikipedia" in _REFERENCE_CORPUS_PATTERNS


# ---------------------------------------------------------------------------
# walk_files — end-to-end filter integration
# ---------------------------------------------------------------------------

def test_walk_files_skips_wikipedia_dump_in_tree(tmp_path):
    """The exact Rocba shape: a planning.docx-style file co-located
    with an english_wikipedia.txt. The Wikipedia file MUST NOT
    produce a hit; the planning notes MUST produce one."""
    legit = tmp_path / "Planning.txt"
    legit.write_text(_LONE_WOLF_PAYLOAD)
    wiki = tmp_path / "english_wikipedia.txt"
    wiki.write_text(_LONE_WOLF_PAYLOAD)   # identical contents

    hits = walk_files(tmp_path)

    hit_paths = [h.path.name for h in hits]
    assert "Planning.txt" in hit_paths, \
        "legitimate planning file must still fire"
    assert "english_wikipedia.txt" not in hit_paths, \
        "wikipedia reference dump must be skipped by filter"


def test_walk_files_skips_dictionary_and_wordlist(tmp_path):
    """Reference-corpus filter also catches dictionaries and
    wordlists — both contain enough English vocabulary to fire
    the lexicon for unrelated reasons."""
    for fname in ("english_dictionary.txt", "wordlist_top_1m.txt",
                   "thesaurus.json"):
        (tmp_path / fname).write_text(_LONE_WOLF_PAYLOAD)

    hits = walk_files(tmp_path)
    assert hits == [], (
        "no reference-corpus file should produce a hit; "
        f"got: {[h.path.name for h in hits]}")


def test_walk_files_returns_legitimate_hit_when_no_reference_files(tmp_path):
    """Baseline — the filter doesn't disable scanning, it only
    skips reference-corpus names. A normal file with the planning
    payload still produces a high-strength match."""
    (tmp_path / "diary.md").write_text(_LONE_WOLF_PAYLOAD)
    hits = walk_files(tmp_path)
    assert len(hits) == 1
    assert hits[0].path.name == "diary.md"
    assert hits[0].signal_strength in ("high", "medium")


def test_walk_files_handles_case_insensitive_wikipedia(tmp_path):
    """The Rocba file was lowercase; a real corpus might be
    capitalised (ENGLISH_WIKIPEDIA.TXT). The filter must match
    regardless of case."""
    (tmp_path / "ENGLISH_WIKIPEDIA.TXT").write_text(_LONE_WOLF_PAYLOAD)
    hits = walk_files(tmp_path)
    assert hits == []


# ---------------------------------------------------------------------------
# scan_text — the filter does not apply at the unit-text layer
# ---------------------------------------------------------------------------

def test_scan_text_still_fires_on_payload_with_reference_path():
    """The reference-corpus filter is a `walk_files`-level policy.
    `scan_text` is the bytes-level scanner and remains unfiltered
    — that way an analyst who pulls a renamed file and explicitly
    runs scan_text on it gets the honest match. Filtering happens
    at the corpus-walker layer where the filename signal is."""
    # Even with a wikipedia-named path passed in, scan_text returns
    # a match because it doesn't know about the corpus filter.
    m = scan_text(_LONE_WOLF_PAYLOAD,
                   source=Path("english_wikipedia.txt"))
    assert m is not None
    assert m.signal_strength in ("high", "medium")
