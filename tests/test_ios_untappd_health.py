"""iOS Untappd + Health extractor tests, plus agent wiring."""
import json
import plistlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from el.skills import ios_health as ih
from el.skills import untappd_ios as ut

_MAC_OFFSET = 978307200


# --- Untappd ----------------------------------------------------------------

def _make_untappd_cache(cache_dir: Path):
    fs = cache_dir / "fsCachedData"
    fs.mkdir(parents=True)
    payload = {"response": {
        # geo-IP block MUST NOT be read as a venue location:
        "data": {"city": "Burlington", "latitude": 44.47588, "longitude": -73.21207},
        "checkins": {"items": [
            {"beer": {"beer_name": "Misfit Love"},
             "venue": {"venue_name": "Foam Brewers",
                       "location": {"lat": 44.4792709, "lng": -73.2201462}},
             "rating_score": 4.75, "checkin_comment": "Yummy",
             "created_at": "Sat, 13 Dec 2025 18:00:00 +0000"},
            {"beer": {"beer_name": "Budweiser"},
             "venue": {"venue_name": "JP's Pub",
                       "location": {"lat": 44.4758453, "lng": -73.2134094}},
             "rating_score": 1.5, "checkin_comment": ""},
        ]}}}
    (fs / "AAAA-0001").write_text(json.dumps(payload))


def test_untappd_parse_checkins(tmp_path):
    cache = tmp_path / "com.untappdllc.com"
    _make_untappd_cache(cache)
    run = ut.parse(cache, output_dir=tmp_path / "out")
    assert run.total == 2
    by_beer = {c.beer: c for c in run.checkins}
    assert by_beer["Misfit Love"].venue == "Foam Brewers"
    assert round(by_beer["Misfit Love"].latitude, 4) == 44.4793
    assert by_beer["Misfit Love"].comment == "Yummy"
    assert by_beer["Misfit Love"].rating == 4.75


def test_untappd_geoip_not_a_venue(tmp_path):
    cache = tmp_path / "com.untappdllc.com"
    _make_untappd_cache(cache)
    run = ut.parse(cache)
    coords = {(round(c.latitude, 5), round(c.longitude, 5))
              for c in run.with_coords()}
    # the geo-IP centroid 44.47588/-73.21207 must NOT appear as a check-in
    assert (44.47588, -73.21207) not in coords
    assert (44.47927, -73.22015) in coords


def test_untappd_comments_and_venues(tmp_path):
    cache = tmp_path / "com.untappdllc.com"
    _make_untappd_cache(cache)
    run = ut.parse(cache)
    assert len(run.with_comments()) == 1
    assert run.with_comments()[0].beer == "Misfit Love"
    assert run.venues() == ["Foam Brewers", "JP's Pub"]
    assert run.as_evidence().extracted_facts["with_comments"] == 1


def test_untappd_find_cache(tmp_path):
    root = tmp_path / "fs"
    appdir = (root / "private" / "var" / "mobile" / "Containers" / "Data"
              / "Application" / "UUID-1")
    cache = appdir / "Library" / "Caches" / "com.untappdllc.com"
    cache.mkdir(parents=True)
    (appdir / ".com.apple.mobile_container_manager.metadata.plist").write_bytes(
        plistlib.dumps({"MCMMetadataIdentifier": "com.untappdllc.com"}))
    assert ut.find_untappd_cache(root) == cache


def test_untappd_missing_raises(tmp_path):
    with pytest.raises(ut.UntappdError):
        ut.parse(tmp_path / "nope")


# --- Health -----------------------------------------------------------------

def _abs(dt):
    return dt.replace(tzinfo=timezone.utc).timestamp() - _MAC_OFFSET


def _make_health(path: Path):
    c = sqlite3.connect(str(path))
    c.executescript("""
        CREATE TABLE workouts (data_id INTEGER, total_distance REAL);
        CREATE TABLE samples (data_id INTEGER PRIMARY KEY, start_date REAL,
                              end_date REAL, data_type INTEGER);
        CREATE TABLE quantity_samples (data_id INTEGER, quantity REAL,
                              original_quantity REAL, original_unit TEXT);
    """)
    c.execute("INSERT INTO workouts VALUES (100, 5012.5)")
    c.execute("INSERT INTO workouts VALUES (101, 3000.0)")
    s = _abs(datetime(2025, 11, 20, 16, 0, 0))
    for i, (dt, q) in enumerate([(8, 472.01), (8, 100.0), (7, 626.0),
                                 (9, 80.0)]):
        c.execute("INSERT INTO samples VALUES (?,?,?,?)", (i, s + i, s + i, dt))
        c.execute("INSERT INTO quantity_samples VALUES (?,?,?,?)",
                  (i, q, q, "m"))
    c.commit(); c.close()


def test_health_parse_workouts_and_types(tmp_path):
    db = tmp_path / "healthdb_secure.sqlite"
    _make_health(db)
    run = ih.parse(db, output_dir=tmp_path / "out")
    assert run.workout_count == 2
    assert run.max_workout_distance == 5012.5
    d8 = run.agg(8)
    assert d8 and d8.count == 2 and d8.max_value == 472.01
    assert d8.label == "DistanceWalkingRunning"
    assert run.first_sample_utc == "2025-11-20 16:00:00"


def test_health_evidence_and_discovery(tmp_path):
    root = tmp_path / "fs"
    d = root / "private" / "var" / "mobile" / "Library" / "Health"
    d.mkdir(parents=True)
    _make_health(d / "healthdb_secure.sqlite")
    assert ih.find_health_db(root) == d / "healthdb_secure.sqlite"
    run = ih.parse(d / "healthdb_secure.sqlite", output_dir=tmp_path / "o")
    ev = run.as_evidence()
    assert ev.extracted_facts["workout_count"] == 2
    assert ev.tool == "el.ios_health"


def test_health_missing_raises(tmp_path):
    with pytest.raises(ih.IOSHealthError):
        ih.parse(tmp_path / "nope.sqlite")


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


def test_agent_emits_untappd_and_health_findings(tmp_path, monkeypatch):
    from el.agents.ios_forensicator import IOSForensicatorAgent
    root = tmp_path / "fs"
    appdir = (root / "private/var/mobile/Containers/Data/Application/U1")
    cache = appdir / "Library" / "Caches" / "com.untappdllc.com"
    _make_untappd_cache(cache)
    (appdir / ".com.apple.mobile_container_manager.metadata.plist").write_bytes(
        plistlib.dumps({"MCMMetadataIdentifier": "com.untappdllc.com"}))
    hdir = root / "private/var/mobile/Library/Health"
    hdir.mkdir(parents=True)
    _make_health(hdir / "healthdb_secure.sqlite")

    ctx = _ctx(tmp_path, monkeypatch, "t-ios-utha", root)
    agent = IOSForensicatorAgent()
    uf = agent._run_untappd(ctx, root)
    hf = agent._run_health(ctx, root)
    assert uf and "Untappd:" in uf[0].claim and "check-in" in uf[0].claim
    assert hf and "iOS Health:" in hf[0].claim and "workout" in hf[0].claim
