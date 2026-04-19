"""PR-10: Browser forensics skill + agent tests.

Firefox places.sqlite has a well-known schema (moz_places with
last_visit_date as PRTime microseconds). We build a tiny in-memory
sqlite file matching that schema and exercise:
  - firefox_places() parses URLs + timestamps + visit counts correctly
  - PRTime → UTC datetime conversion
  - BrowserForensicatorAgent emits findings for anon-share / forum-
    post-shape / consumer-webmail destinations at appropriate
    confidence levels
  - Volume finding always surfaces (establishes we parsed the history)
"""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.browser_forensicator import BrowserForensicatorAgent
from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger
from el.skills import browser


def _build_places(path: Path, rows: list[tuple[str, str, int, int | None]]) -> None:
    """Modern Firefox (3.5+) schema — last_visit_date on moz_places.
    rows: (url, title, visit_count, last_visit_prtime)"""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            last_visit_date INTEGER
        )
    """)
    conn.executemany(
        "INSERT INTO moz_places (url, title, visit_count, last_visit_date) "
        "VALUES (?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.close()


def _build_places_fx3(path: Path, rows: list[tuple[str, str, int, int | None]]) -> None:
    """Pre-3.5 Firefox schema — no last_visit_date on moz_places;
    timestamps live in moz_historyvisits.visit_date joined on place_id.
    M57-Jean's image uses this layout."""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url LONGVARCHAR,
            title LONGVARCHAR,
            rev_host LONGVARCHAR,
            visit_count INTEGER DEFAULT 0,
            hidden INTEGER DEFAULT 0 NOT NULL,
            typed INTEGER DEFAULT 0 NOT NULL,
            favicon_id INTEGER,
            frecency INTEGER DEFAULT -1 NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY,
            from_visit INTEGER,
            place_id INTEGER,
            visit_date INTEGER,
            visit_type INTEGER,
            session INTEGER
        )
    """)
    for i, (url, title, vc, lvd) in enumerate(rows, start=1):
        conn.execute(
            "INSERT INTO moz_places (id, url, title, visit_count) "
            "VALUES (?, ?, ?, ?)",
            (i, url, title, vc),
        )
        if lvd is not None:
            conn.execute(
                "INSERT INTO moz_historyvisits (place_id, visit_date, "
                "visit_type) VALUES (?, ?, 1)",
                (i, lvd),
            )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Skill: firefox_places()
# ---------------------------------------------------------------------------

def test_firefox_places_parses_basic_history(tmp_path):
    p = tmp_path / "places.sqlite"
    _build_places(p, [
        ("https://evil.example.com/forum/viewtopic.php?t=42",
         "Forum — Topic 42", 3, 1_200_000_000_000_000),
        ("https://gmail.com/mail/u/0/",
         "Gmail", 10, 1_210_000_000_000_000),
        ("https://news.example.org/story",
         "A story", 1, None),
    ])
    run = browser.firefox_places(p)
    assert run.source_kind == "firefox"
    assert len(run.visits) == 3
    urls = {v.url for v in run.visits}
    assert "https://evil.example.com/forum/viewtopic.php?t=42" in urls


def test_firefox_prtime_conversion_utc(tmp_path):
    p = tmp_path / "places.sqlite"
    # 1_200_000_000_000_000 µs since epoch ≈ 2008-01-10T21:20:00 UTC
    _build_places(p, [("https://ex.com/", "ex", 1, 1_200_000_000_000_000)])
    run = browser.firefox_places(p)
    v = run.visits[0]
    assert v.last_visit_utc is not None
    assert v.last_visit_utc.tzinfo == timezone.utc
    expected = datetime.fromtimestamp(1.2e9, tz=timezone.utc)
    assert v.last_visit_utc == expected


def test_firefox_places_handles_null_visit_date(tmp_path):
    p = tmp_path / "places.sqlite"
    _build_places(p, [("https://ex.com/", "ex", 0, None)])
    run = browser.firefox_places(p)
    assert run.visits[0].last_visit_utc is None


def test_firefox_places_missing_file_raises():
    with pytest.raises(browser.BrowserError):
        browser.firefox_places(Path("/nope/nope.sqlite"))


def test_firefox_places_corrupt_db_returns_error_in_run(tmp_path):
    """A broken sqlite file should NOT crash — the skill returns a
    BrowserRun with error set so the agent can emit an `insufficient`
    finding without blowing up the whole investigation."""
    p = tmp_path / "places.sqlite"
    p.write_bytes(b"not a real sqlite file")
    run = browser.firefox_places(p)
    assert run.error
    assert run.visits == []


def test_firefox_places_fx3_schema_via_historyvisits_join(tmp_path):
    """Pre-3.5 Firefox (the schema M57-Jean's image uses): no
    last_visit_date on moz_places; timestamps in moz_historyvisits.
    The skill must fall back to a LEFT JOIN and still produce visits."""
    p = tmp_path / "places.sqlite"
    _build_places_fx3(p, [
        ("http://65.19.164.93/Forum/phpBB2/viewtopic.php?t=3",
         "Forum", 2, 1_216_000_000_000_000),
        ("https://ex.com/", "ex", 1, 1_216_001_000_000_000),
        ("http://only-visited-count.example/", "vc", 5, None),
    ])
    run = browser.firefox_places(p)
    assert run.error is None
    assert len(run.visits) == 3
    urls = {v.url for v in run.visits}
    assert "http://65.19.164.93/Forum/phpBB2/viewtopic.php?t=3" in urls
    # Timestamp correctly pulled from moz_historyvisits
    forum = next(v for v in run.visits if "viewtopic" in v.url)
    assert forum.last_visit_utc is not None
    # Null-visit place still surfaces with last_visit_utc=None
    novisit = next(v for v in run.visits if v.url == "http://only-visited-count.example/")
    assert novisit.last_visit_utc is None


def test_firefox_places_unknown_schema_returns_error(tmp_path):
    """A DB with a moz_places table missing both last_visit_date AND
    moz_historyvisits should return an error in the BrowserRun rather
    than crash."""
    p = tmp_path / "places.sqlite"
    conn = sqlite3.connect(p)
    conn.execute("CREATE TABLE moz_places (id INTEGER, url TEXT, "
                 "title TEXT, visit_count INTEGER)")
    conn.commit()
    conn.close()
    run = browser.firefox_places(p)
    assert run.error
    assert "unknown schema" in run.error.lower() or "last_visit_date" in run.error.lower()


def test_ie_index_dat_raises_until_binding_wired(tmp_path):
    """PR-10 deliberately skips IE; the stub must raise BrowserError
    so a future patch flipping it to real behaviour is obvious."""
    p = tmp_path / "index.dat"
    p.write_bytes(b"x")
    with pytest.raises(browser.BrowserError, match="pymsiecf"):
        browser.ie_index_dat(p)


# ---------------------------------------------------------------------------
# Agent: destination bucketing + confidence levels
# ---------------------------------------------------------------------------

def _agent_ctx(tmp_path, monkeypatch, case_id="t-browser"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


def _seed_firefox_dir(tmp_path: Path, rows) -> Path:
    """Create the exports/windows-artifacts/browser/firefox/<prof>/places.sqlite
    layout the agent expects."""
    prof = tmp_path / "browser" / "firefox" / "jean--default"
    prof.mkdir(parents=True)
    _build_places(prof / "places.sqlite", rows)
    return tmp_path / "browser"


def test_agent_emits_insufficient_when_no_places_files(tmp_path, monkeypatch):
    ctx = _agent_ctx(tmp_path, monkeypatch, "t-empty")
    empty = tmp_path / "browser"; empty.mkdir()
    ctx.input_path = empty
    findings = BrowserForensicatorAgent().run(ctx)
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"


def test_agent_flags_anon_share_destinations(tmp_path, monkeypatch):
    ctx = _agent_ctx(tmp_path, monkeypatch, "t-share")
    root = _seed_firefox_dir(tmp_path, [
        ("https://pastebin.com/abc123", "Paste", 1, 1_210_000_000_000_000),
        ("https://file.io/XYZ", "File.io", 1, 1_210_001_000_000_000),
        ("https://news.example.org/", "news", 2, 1_210_002_000_000_000),
    ])
    ctx.input_path = root
    findings = BrowserForensicatorAgent().run(ctx)
    share = [f for f in findings if "anonymous file-share" in f.claim]
    assert share, f"expected anon-share finding; got {[f.claim for f in findings]}"
    assert share[0].confidence == "medium"
    assert "H_INSIDER_DATA_EXFIL" in share[0].hypotheses_supported


def test_agent_flags_forum_post_shape_destinations(tmp_path, monkeypatch):
    ctx = _agent_ctx(tmp_path, monkeypatch, "t-forum")
    root = _seed_firefox_dir(tmp_path, [
        ("http://65.19.164.93/Forum/phpBB2/viewtopic.php?t=3",
         "Forum", 2, 1_210_000_000_000_000),
        ("http://65.19.164.93/Forum/phpBB2/posting.php?mode=post&f=3",
         "Post", 1, 1_210_001_000_000_000),
    ])
    ctx.input_path = root
    findings = BrowserForensicatorAgent().run(ctx)
    forum = [f for f in findings if "forum / board post-shape" in f.claim]
    assert forum, f"expected forum-post finding; got {[f.claim for f in findings]}"
    assert "65.19.164.93" in forum[0].claim
    assert "H_INSIDER_DATA_EXFIL" in forum[0].hypotheses_supported


def test_agent_flags_consumer_webmail_low_no_hypothesis(tmp_path, monkeypatch):
    ctx = _agent_ctx(tmp_path, monkeypatch, "t-webmail")
    root = _seed_firefox_dir(tmp_path, [
        ("https://mail.google.com/mail/u/0/", "Gmail", 5, 1_210_000_000_000_000),
    ])
    ctx.input_path = root
    findings = BrowserForensicatorAgent().run(ctx)
    webmail = [f for f in findings if "consumer-webmail access" in f.claim]
    assert webmail
    assert webmail[0].confidence == "low"
    # Informational only — does NOT lift insider-exfil
    assert webmail[0].hypotheses_supported == []


def test_agent_emits_volume_finding_first(tmp_path, monkeypatch):
    """A volume finding always fires so 'insufficient' isn't the only
    shape when there's no category hit."""
    ctx = _agent_ctx(tmp_path, monkeypatch, "t-volume")
    root = _seed_firefox_dir(tmp_path, [
        ("https://news.example.org/one", "A", 1, 1_210_000_000_000_000),
        ("https://docs.example.org/two", "B", 1, 1_210_001_000_000_000),
    ])
    ctx.input_path = root
    findings = BrowserForensicatorAgent().run(ctx)
    vol = [f for f in findings if "Firefox history parsed" in f.claim]
    assert vol and vol[0].confidence == "high"
    assert "2 URL(s)" in vol[0].claim
