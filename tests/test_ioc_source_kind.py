"""Regression tests for PR-6: source-aware IOC extraction.

M57-Jean blind run produced 6201 IOCs with cross-case overlaps listing
`default.css`, `style.css`, `stylesheet.css`, `index.html`, `layout.css`,
`template.css` as "domains seen previously in case pcap-2013-...". Root
cause: the domain regex matched file basenames in the 17 MB fls bodyfile
because (a) css/html/svg/etc. weren't in the file-extension filter, and
(b) the extractor had no way to know it was reading a filesystem path
listing where the entire concept of "domain" is misapplied.

This PR:
  - Expands _FILE_EXT_TLDS with commonly-slipping web/media/DB extensions
  - Adds source_kind param to extract(); "fs_paths" skips domain/url/email
    entirely and keeps only hash/ip/regkey/winpath
  - extract_from_paths classifies paths (fls_*, mactime_*, etc.) and
    applies source_kind automatically
  - extract_from_paths deduplicates input paths (multiple findings often
    reference the same 17 MB bodyfile — was being re-scanned each time)
"""
from pathlib import Path

import pytest

from el.skills.ioc_extract import (
    extract, extract_from_paths, _source_kind_for,
)


# ---------------------------------------------------------------------------
# The direct FP class: web/CSS/HTML filenames emitted as "domains"
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("basename", [
    "default.css", "style.css", "stylesheet.css", "styles.css",
    "template.css", "layout.css", "reset.css", "theme.css",
    "index.html", "about.html", "contact.html",
    "logo.svg", "icon.svg",
    "main.woff", "font.woff2", "display.ttf",
    "image.webp", "photo.webp",
    "track.mp3", "clip.mp4", "audio.wav",
    "app.js.map", "style.css.map",
    "readme.md",
    "data.sqlite", "cache.db",
])
def test_web_media_filenames_not_emitted_as_domains(basename):
    """Each of these slipped through as "domain" in the blind run."""
    path = f"0|/Users/Bob/Documents/web-project/{basename}|12345|r|0|0|0|0|0|0|0"
    out = extract(path)
    assert basename not in out["domain"], f"{basename} was emitted as domain"


# ---------------------------------------------------------------------------
# source_kind="fs_paths" — skip domain/url/email on bodyfile text
# ---------------------------------------------------------------------------

def test_fs_paths_mode_skips_domain_regex():
    """Even if css/html weren't in the filter, fs_paths mode should
    produce zero domains regardless of what the text contains."""
    body = (
        "0|/Users/Bob/site/default.css|1|r|0|0|0|0|0|0|0\n"
        "0|/Users/Bob/site/index.html|1|r|0|0|0|0|0|0|0\n"
        "0|/Users/Bob/site/not.actually.a.domain.example|1|r|0|0|0|0|0|0|0\n"
    )
    out = extract(body, source_kind="fs_paths")
    assert out["domain"] == set()
    assert out["url"] == set()
    assert out["email"] == set()


def test_fs_paths_mode_still_extracts_hashes_and_ips():
    """Hashes and IPs in fs_paths output ARE real (e.g. an IP or hash that
    appears in a filename or connection-log entry). Keep them.

    Real hash shape — `d41d8cd98f00b204e9800998ecf8427e` (MD5 of empty
    string, 12 unique chars). The earlier fixture used `"d" * 32` which
    looked like a hash to the regex but was 1 unique char; the low-
    entropy filter now correctly rejects that shape, so the fixture
    has to match what a real artefact would look like."""
    real_md5 = "d41d8cd98f00b204e9800998ecf8427e"
    body = (
        "0|/logs/connection-from-203.0.113.17 src|1|r|0|0|0|0|0|0|0\n"
        f"0|/tmp/{real_md5} payload|1|r|0|0|0|0|0|0|0\n"
    )
    out = extract(body, source_kind="fs_paths")
    assert "203.0.113.17" in out["ipv4"]
    assert real_md5 in out["md5"]


def test_fs_paths_mode_preserves_winpath_and_regkey():
    body = (
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        "C:\\Users\\Bob\\AppData\\Local\\Temp\\sample.exe\n"
    )
    out = extract(body, source_kind="fs_paths")
    assert any("HKLM" in r for r in out["regkey"])
    assert any("sample.exe" in w for w in out["winpath"])


def test_network_source_kind_preserves_full_extraction():
    """network source_kind should still extract domains etc."""
    text = "GET / HTTP/1.1\r\nHost: evil.example.com\r\nFrom: bob@corp.example\r\n"
    out = extract(text, source_kind="network")
    assert "evil.example.com" in out["domain"]
    assert "bob@corp.example" in out["email"]


def test_none_source_kind_is_legacy_full_extraction():
    """Back-compat: callers passing no source_kind get every IOC class."""
    text = "visit evil.example.com for payload"
    out = extract(text)
    assert "evil.example.com" in out["domain"]


# ---------------------------------------------------------------------------
# _source_kind_for — path-based classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("fls_o63.txt", "fs_paths"),
    ("fls.txt", "fs_paths"),
    ("mactime.txt", "fs_paths"),
    ("mactime.csv", "fs_paths"),
    ("mactime_part1.csv", "fs_paths"),
    ("directory-listing.txt", "fs_paths"),
    # Regular analysis files → legacy (None)
    ("dns-queries.json", None),
    ("http-hosts.csv", None),
    ("evtx.json", None),
    ("pslist.json", None),
    ("report.md", None),
])
def test_source_kind_classification_by_name(tmp_path, name, expected):
    p = tmp_path / name
    p.write_text("")
    assert _source_kind_for(p) == expected


# ---------------------------------------------------------------------------
# extract_from_paths deduplicates paths (perf + correctness)
# ---------------------------------------------------------------------------

def test_extract_from_paths_dedups_repeated_path(tmp_path):
    """Multiple findings often reference the same evidence file. Reading
    it once is correct and materially faster on large bodyfiles."""
    p = tmp_path / "big.txt"
    p.write_text("visit 203.0.113.17 or evil.example.com\n")

    reads = {"n": 0}
    orig = Path.read_text

    def _counting(self, *args, **kwargs):
        reads["n"] += 1
        return orig(self, *args, **kwargs)

    import pytest as _p
    with _p.MonkeyPatch().context() as mp:
        mp.setattr(Path, "read_text", _counting)
        # Same path referenced 3 times — should be read ONCE
        extract_from_paths([p, p, str(p)])

    assert reads["n"] == 1, f"expected 1 read, got {reads['n']}"


def test_extract_from_paths_applies_fs_paths_for_bodyfile(tmp_path):
    """End-to-end: a file named fls_o63.txt gets source_kind='fs_paths'
    automatically and its CSS/HTML basenames are NOT emitted as domains."""
    p = tmp_path / "fls_o63.txt"
    p.write_text("0|/site/default.css|1|r|0|0|0|0|0|0|0\n"
                 "0|/site/index.html|1|r|0|0|0|0|0|0|0\n")
    out = extract_from_paths([p])
    assert "default.css" not in out["domain"]
    assert "index.html" not in out["domain"]


def test_extract_from_paths_applies_full_extraction_for_network_file(tmp_path):
    p = tmp_path / "http-hosts.csv"
    p.write_text("timestamp,host,uri\n2026-04-18T10:00:00Z,evil.example.com,/a\n")
    out = extract_from_paths([p])
    assert "evil.example.com" in out["domain"]
