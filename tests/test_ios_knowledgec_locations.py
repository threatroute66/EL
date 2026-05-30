"""iOS knowledgeC + location-cache parser tests, plus agent wiring."""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from el.skills import ios_knowledgec as kc
from el.skills import ios_locations as il

_MAC_OFFSET = 978307200


def _abs(dt: datetime) -> float:
    return dt.replace(tzinfo=timezone.utc).timestamp() - _MAC_OFFSET


def _make_knowledgec(path: Path):
    c = sqlite3.connect(str(path))
    c.execute("""CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY,
        ZSTREAMNAME TEXT, ZVALUESTRING TEXT,
        ZSTARTDATE REAL, ZENDDATE REAL)""")
    s = _abs(datetime(2025, 12, 1, 10, 0, 0))
    rows = [
        ("/app/usage", "com.burbn.instagram", s, s + 300),       # 300s
        ("/app/usage", "com.burbn.instagram", s + 600, s + 900),  # +300s
        ("/app/usage", "com.atebits.Tweetie2", s + 1000, s + 1100),  # 100s
        ("/device/isLocked", "", s + 2000, s + 2000),
        ("/app/intents", "com.apple.Maps", s + 3000, s + 3010),
    ]
    c.executemany("INSERT INTO ZOBJECT (ZSTREAMNAME,ZVALUESTRING,ZSTARTDATE,"
                  "ZENDDATE) VALUES (?,?,?,?)", rows)
    c.commit(); c.close()


def _make_locations(path: Path):
    c = sqlite3.connect(str(path))
    c.execute("""CREATE TABLE CellLocation (MCC INT, MNC INT, LAC INT, CI INT,
        Timestamp REAL, Latitude REAL, Longitude REAL,
        HorizontalAccuracy REAL, Altitude REAL, Speed REAL, Course REAL,
        Confidence INT)""")
    t = _abs(datetime(2025, 12, 16, 22, 47, 24))
    c.execute("INSERT INTO CellLocation VALUES (310,260,11051,534,?,"
              "40.81182,-73.07980,500,0,0,0,70)", (t,))
    c.execute("INSERT INTO CellLocation VALUES (310,260,11051,999,?,"
              "41.0,-73.5,500,0,0,0,70)", (_abs(datetime(2025, 12, 16, 23, 0, 0)),))
    c.commit(); c.close()


# --- knowledgeC -------------------------------------------------------------

def test_knowledgec_parse_and_top_apps(tmp_path):
    db = tmp_path / "knowledgeC.db"
    _make_knowledgec(db)
    run = kc.parse(db, output_dir=tmp_path / "out")
    assert run.total == 5
    assert len(run.app_usage()) == 3
    top = dict(run.top_apps())
    assert top["com.burbn.instagram"] == 600.0      # 300 + 300
    assert top["com.atebits.Tweetie2"] == 100.0
    assert run.by_stream()["/app/usage"] == 3


def test_knowledgec_app_in_focus_at(tmp_path):
    db = tmp_path / "knowledgeC.db"
    _make_knowledgec(db)
    run = kc.parse(db)
    hits = run.app_in_focus_at("2025-12-01 10:02:00")   # within first IG window
    assert hits and hits[0].value == "com.burbn.instagram"


def test_knowledgec_evidence_and_discovery(tmp_path):
    root = tmp_path / "fs"
    d = root / "private" / "var" / "mobile" / "Library" / "CoreDuet" / "Knowledge"
    d.mkdir(parents=True)
    _make_knowledgec(d / "knowledgeC.db")
    assert kc.find_knowledgec(root) == d / "knowledgeC.db"
    run = kc.parse(d / "knowledgeC.db", output_dir=tmp_path / "o")
    ev = run.as_evidence()
    assert ev.extracted_facts["app_usage_events"] == 3
    assert ev.tool == "el.ios_knowledgec"


def test_knowledgec_missing_raises(tmp_path):
    with pytest.raises(kc.IOSKnowledgeCError):
        kc.parse(tmp_path / "nope.db")


# --- locations --------------------------------------------------------------

def test_locations_parse_and_near_time(tmp_path):
    db = tmp_path / "cache_encryptedB.db"
    _make_locations(db)
    run = il.parse(db, output_dir=tmp_path / "out")
    assert run.total == 2 and "CellLocation" in run.tables_read
    hits = run.near_time("2025-12-16 22:47:24", window_s=60)
    assert len(hits) == 1
    assert round(hits[0].latitude, 4) == 40.8118
    assert hits[0].cell == "310-260-11051-534"


def test_locations_date_range_and_evidence(tmp_path):
    db = tmp_path / "cache_encryptedB.db"
    _make_locations(db)
    run = il.parse(db, output_dir=tmp_path / "out")
    assert run.date_range()[0] == "2025-12-16 22:47:24"
    assert run.as_evidence().extracted_facts["point_count"] == 2


def test_locations_discovery(tmp_path):
    root = tmp_path / "fs"
    d = root / "private" / "var" / "root" / "Library" / "Caches" / "locationd"
    d.mkdir(parents=True)
    _make_locations(d / "cache_encryptedB.db")
    assert il.find_location_cache(root) == d / "cache_encryptedB.db"


def test_locations_missing_raises(tmp_path):
    with pytest.raises(il.IOSLocationsError):
        il.parse(tmp_path / "nope.db")


# --- agent wiring -----------------------------------------------------------

def _ctx(tmp_path, monkeypatch, case_id, root):
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "ev"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=root, manifest=m.__dict__)


def test_agent_emits_knowledgec_and_location_findings(tmp_path, monkeypatch):
    from el.agents.ios_forensicator import IOSForensicatorAgent
    root = tmp_path / "fs"
    kdir = root / "private/var/mobile/Library/CoreDuet/Knowledge"
    kdir.mkdir(parents=True)
    _make_knowledgec(kdir / "knowledgeC.db")
    ldir = root / "private/var/root/Library/Caches/locationd"
    ldir.mkdir(parents=True)
    _make_locations(ldir / "cache_encryptedB.db")

    ctx = _ctx(tmp_path, monkeypatch, "t-ios-kcloc", root)
    agent = IOSForensicatorAgent()
    kf = agent._run_knowledgec(ctx, root)
    lf = agent._run_locations(ctx, root)
    assert kf and "knowledgeC" in kf[0].claim
    assert lf and "location cache" in lf[0].claim and "fix" in lf[0].claim
