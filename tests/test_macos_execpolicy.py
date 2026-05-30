"""macOS ExecPolicy parser tests — synthetic executable_measurements_v2."""
import sqlite3
from pathlib import Path

import pytest

from el.skills import macos_execpolicy as ep


def _make_execpolicy(db: Path):
    conn = sqlite3.connect(str(db))
    conn.execute("""
        CREATE TABLE executable_measurements_v2 (
            is_signed INTEGER, file_identifier TEXT, bundle_identifier TEXT,
            bundle_version TEXT, team_identifier TEXT, signing_identifier TEXT,
            cdhash TEXT, main_executable_hash TEXT, executable_timestamp INTEGER,
            file_size INTEGER, is_library INTEGER, is_used INTEGER,
            responsible_file_identifier TEXT, is_valid INTEGER,
            is_quarantined INTEGER, timestamp INTEGER, reported_timestamp INTEGER
        )
    """)
    rows = [
        # signed, valid, not quarantined  (a normal Apple-signed app)
        (1, "Terminal.app", "com.apple.Terminal", "455.1",
         "Apple", "com.apple.Terminal",
         "e279a92e6931158a56f3cf1ebb84ad282399c17e", "h", 1741418969,
         2207824, 0, 1, "", 1, 0, 1764624232, 1766049112),
        # unsigned interpreter run from Terminal
        (0, "ruby", "", "", "", "",
         "ac707f8487967595cca357ad3057fec1b151b6a31d4dfada7508c4769e4ed707",
         "h", 1759880905, 13650632, 0, 1, "Terminal.app", 0, 0,
         1764624300, 1766049112),
        # signed but quarantined (downloaded) app
        (1, "Asphalt.app", "com.gameloft.asphalt9mac", "471000",
         "TEAMID", "com.gameloft.asphalt9mac",
         "44887f4a2d5192c93198bd9b4c0ddb8944d06a72", "h", 1, 999, 0, 1, "",
         1, 1, 1764624287, 1766049112),
    ]
    conn.executemany(
        "INSERT INTO executable_measurements_v2 VALUES "
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()


def test_parse_extracts_measurements(tmp_path):
    db = tmp_path / "ExecPolicy"
    _make_execpolicy(db)
    run = ep.parse(db, output_dir=tmp_path / "out")

    assert run.total == 3
    assert run.table_used == "executable_measurements_v2"
    # cdhash round-trips for the signed app
    term = next(m for m in run.measurements if m.file_identifier == "Terminal.app")
    assert term.cdhash == "e279a92e6931158a56f3cf1ebb84ad282399c17e"
    assert term.is_signed is True and term.is_valid is True
    assert term.is_quarantined is False


def test_unsigned_and_quarantined_classification(tmp_path):
    db = tmp_path / "ExecPolicy"
    _make_execpolicy(db)
    run = ep.parse(db)

    assert [m.file_identifier for m in run.unsigned] == ["ruby"]
    assert [m.file_identifier for m in run.quarantined] == ["Asphalt.app"]
    # unsigned ruby is the only threat-relevant ("suspicious") row here.
    assert [m.file_identifier for m in run.suspicious] == ["ruby"]


def test_epoch_to_utc_and_find_at(tmp_path):
    db = tmp_path / "ExecPolicy"
    _make_execpolicy(db)
    run = ep.parse(db)

    term = next(m for m in run.measurements if m.file_identifier == "Terminal.app")
    # epoch 1764624232 == 2025-12-01 21:23:52 UTC
    assert term.scanned_utc == "2025-12-01 21:23:52"
    hits = run.find_at("2025-12-01 21:23:52")
    assert len(hits) == 1 and hits[0].cdhash == \
        "e279a92e6931158a56f3cf1ebb84ad282399c17e"


def test_output_jsonl_and_evidence(tmp_path):
    db = tmp_path / "ExecPolicy"
    _make_execpolicy(db)
    run = ep.parse(db, output_dir=tmp_path / "out")
    assert run.output_path.is_file()
    assert run.output_sha256 and run.output_sha256 != "0" * 64
    ev = run.as_evidence()
    assert ev.extracted_facts["unsigned_count"] == 1
    assert ev.extracted_facts["quarantined_count"] == 1
    assert ev.tool == "el.macos_execpolicy"


def test_find_execpolicy_under_fs_root(tmp_path):
    root = tmp_path / "fs"
    spc = root / "private" / "var" / "db" / "SystemPolicyConfiguration"
    spc.mkdir(parents=True)
    (spc / "ExecPolicy").write_bytes(b"x")
    found = ep.find_execpolicy(root)
    assert found == spc / "ExecPolicy"


def test_missing_db_raises(tmp_path):
    with pytest.raises(ep.MacOSExecPolicyError):
        ep.parse(tmp_path / "nope")


def test_no_measurement_table_raises(tmp_path):
    db = tmp_path / "ExecPolicy"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE settings (k TEXT)")
    conn.commit()
    conn.close()
    with pytest.raises(ep.MacOSExecPolicyError):
        ep.parse(db)


# ---------------------------------------------------------------------------
# Agent wiring: ExecPolicy + install.log produce findings even when the
# malicious-pattern suite finds nothing.
# ---------------------------------------------------------------------------

def test_agent_emits_execpolicy_and_install_log_findings(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents import macos_forensicator as mf
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"
    src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-mac-extra")
    with open_ledger(m.case_dir):
        pass

    exports = Path(m.case_dir) / "exports" / "macos-artifacts"
    spc = exports / "private" / "var" / "db" / "SystemPolicyConfiguration"
    spc.mkdir(parents=True)
    _make_execpolicy(spc / "ExecPolicy")
    # add an unsigned-AND-quarantined dropper so the per-executable lead fires
    conn = sqlite3.connect(str(spc / "ExecPolicy"))
    conn.execute(
        "INSERT INTO executable_measurements_v2 VALUES "
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (0, "Evil.app", "com.evil.dropper", "1.0", "", "", "deadbeef", "h",
         1, 1234, 0, 1, "", 0, 1, 1764624400, 1766049112))
    conn.commit()
    conn.close()
    logdir = exports / "private" / "var" / "log"
    logdir.mkdir(parents=True)
    (logdir / "install.log").write_text(
        '2025-11-20 09:29:25-08 MacBook-Pro installd[1]: '
        'Installed "DaftCloud" (4.1.8)\n')

    monkeypatch.setattr(mf.mt, "run_all", lambda _p: [])

    ctx = AgentContext(case_id="t-mac-extra", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"macos_artifacts_dir": str(exports)})
    findings = mf.MacOSForensicatorAgent().run(ctx)
    claims = [f.claim for f in findings]

    assert any("ExecPolicy:" in c for c in claims)
    # the unsigned-and-quarantined / invalid lead fires for the synthetic rows
    assert any("ExecPolicy flagged" in c for c in claims)
    assert any("install.log:" in c and "DaftCloud" in c for c in claims)
