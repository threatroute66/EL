"""Integration tests for the new IOSForensicator + AndroidForensicator
wire-ups: ALEAPP archive mode, iTunes backup parsing, sysdiagnose
triage, plus triage routing for the three new evidence kinds.
"""
import json
import plistlib
import sqlite3
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from el.agents.android_forensicator import AndroidForensicatorAgent
from el.agents.base import AgentContext
from el.agents.ios_forensicator import IOSForensicatorAgent
from el.agents.triage import TriageAgent
from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger
from el.skills import aleapp as aleapp_skill


def _make_case(tmp_path, monkeypatch, cid: str, src_name: str = "x.bin"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / src_name
    src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=cid)
    with open_ledger(m.case_dir):
        pass
    return src, m


def _ctx_for(case_id: str, case_dir: Path,
              input_path: Path, manifest: dict) -> AgentContext:
    return AgentContext(
        case_id=case_id, case_dir=case_dir,
        input_path=input_path, manifest=manifest)


# --- Triage routing -------------------------------------------------------


def test_triage_routes_sysdiagnose_tarball(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    # Build a minimal sysdiagnose tarball — content doesn't matter
    # for triage, only the filename signature.
    sd_root = tmp_path / "sysdiagnose_2025_test"
    sd_root.mkdir()
    (sd_root / "README.txt").write_text("sd")
    tarball = tmp_path / "sysdiagnose_2025_TEST_iPhone_OS.tar.gz"
    with tarfile.open(tarball, "w:gz") as tf:
        tf.add(sd_root, arcname="sysdiagnose_2025_TEST_iPhone_OS")
    m = intake_mod.intake(tarball, case_id="t-tri-sd")
    with open_ledger(m.case_dir):
        pass
    ctx = _ctx_for("t-tri-sd", Path(m.case_dir), tarball, m.__dict__)
    findings = TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "ios-sysdiagnose"
    assert any("sysdiagnose tarball" in f.claim for f in findings)


def test_triage_routes_itunes_backup_directory(tmp_path, monkeypatch):
    bd = tmp_path / "backup_dir"
    bd.mkdir()
    # Manifest.plist + Manifest.db at top level
    (bd / "Manifest.plist").write_bytes(plistlib.dumps({
        "Version": "10.0", "IsEncrypted": False,
        "Lockdown": {"ProductVersion": "13.4.1",
                      "ProductType": "iPhone8,4",
                      "DeviceName": "Test",
                      "UniqueDeviceID": "0" * 40}}))
    conn = sqlite3.connect(bd / "Manifest.db")
    conn.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, "
                  "domain TEXT, relativePath TEXT, flags INTEGER, "
                  "file BLOB)")
    conn.commit(); conn.close()

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "trigger.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-tri-itunes")
    with open_ledger(m.case_dir):
        pass
    ctx = _ctx_for("t-tri-itunes", Path(m.case_dir), bd, m.__dict__)
    findings = TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "itunes-backup"
    assert any("iTunes/Finder backup" in f.claim for f in findings)


def test_triage_routes_android_archive(tmp_path, monkeypatch):
    """A .tar containing data/system/packages.xml should route to
    android-archive."""
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    seed = tmp_path / "src"
    (seed / "data" / "system").mkdir(parents=True)
    (seed / "data" / "system" / "packages.xml").write_text(
        "<packages/>")
    archive = tmp_path / "android.tar"
    with tarfile.open(archive, "w") as tf:
        tf.add(seed / "data", arcname="data")
    m = intake_mod.intake(archive, case_id="t-tri-andr")
    with open_ledger(m.case_dir):
        pass
    ctx = _ctx_for("t-tri-andr", Path(m.case_dir), archive,
                    m.__dict__)
    findings = TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "android-archive"
    assert any("Android extraction archive" in f.claim
                for f in findings)


def test_archive_looks_android_negative_for_unrelated_zip(tmp_path):
    """A .zip with no Android markers should NOT trip the
    android-archive detector."""
    archive = tmp_path / "random.zip"
    import zipfile
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("foo/bar.txt", "hi")
    assert TriageAgent._archive_looks_android(archive) is False


# --- Android agent: ALEAPP wire-up ---------------------------------------


def test_android_agent_routes_archive_to_aleapp_path(tmp_path,
                                                       monkeypatch):
    """When the input is an archive, AndroidForensicatorAgent skips
    the FS-walk path and goes straight to ALEAPP."""
    src, m = _make_case(tmp_path, monkeypatch, "t-andr-arch",
                         "android.tar")
    # Make src an archive file (no real content needed — ALEAPP
    # call is monkeypatched below)
    src.write_text("not really a tarball")
    # ALEAPP missing → wrap emits one insufficient finding
    monkeypatch.setattr(aleapp_skill, "is_aleapp_available",
                         lambda: False)
    ctx = _ctx_for("t-andr-arch", Path(m.case_dir), src, m.__dict__)
    findings = AndroidForensicatorAgent().run(ctx)
    assert any("ALEAPP not installed" in f.claim for f in findings)


def test_android_agent_invokes_aleapp_on_archive(tmp_path,
                                                   monkeypatch):
    """When ALEAPP IS available, the wrap runs and emits a
    summary finding plus per-table findings."""
    src, m = _make_case(tmp_path, monkeypatch, "t-andr-arch-y",
                         "android.tar")
    src.write_text("placeholder")
    monkeypatch.setattr(aleapp_skill, "is_aleapp_available",
                         lambda: True)
    fake_dir = tmp_path / "ALEAPP"
    fake_dir.mkdir()
    (fake_dir / "aleapp.py").write_text("# fake")
    monkeypatch.setenv("EL_ALEAPP_DIR", str(fake_dir))

    def fake_proc(cmd, **kw):
        out_dir = Path(cmd[cmd.index("-o") + 1])
        report = out_dir / "ALEAPP_Reports_20250101"
        tsv = report / "_TSV_Exports"
        tsv.mkdir(parents=True)
        with (tsv / "Contacts.tsv").open("w", newline="") as f:
            import csv
            w = csv.writer(f, delimiter="\t")
            w.writerow(["name", "phone"])
            w.writerow(["Alice", "555"])
        return subprocess.CompletedProcess(
            args=cmd, returncode=0,
            stdout="ALEAPP v3.2 starting\n", stderr="")

    monkeypatch.setattr(aleapp_skill.subprocess, "run", fake_proc)
    ctx = _ctx_for("t-andr-arch-y", Path(m.case_dir), src,
                    m.__dict__)
    findings = AndroidForensicatorAgent().run(ctx)
    summary = [f for f in findings
                if "parsed" in f.claim and "module" in f.claim]
    contacts = [f for f in findings if "ALEAPP contacts" in f.claim]
    assert summary, "expected the ALEAPP summary Finding"
    assert summary[0].confidence == "high"
    assert contacts, "expected the per-table contacts Finding"


def test_android_agent_rejects_unknown_file_type(tmp_path,
                                                   monkeypatch):
    """A regular file that isn't a directory or supported archive
    should produce an insufficient finding, not crash."""
    src, m = _make_case(tmp_path, monkeypatch, "t-andr-bad",
                         "weird.dat")
    ctx = _ctx_for("t-andr-bad", Path(m.case_dir), src,
                    m.__dict__)
    findings = AndroidForensicatorAgent().run(ctx)
    assert findings[0].confidence == "insufficient"
    assert "supported archive" in findings[0].claim


# --- iOS agent: iTunes backup wire-up ------------------------------------


def _make_itunes_backup(d: Path, encrypted: bool = False):
    d.mkdir(parents=True, exist_ok=True)
    (d / "Manifest.plist").write_bytes(plistlib.dumps({
        "Version": "10.0",
        "IsEncrypted": encrypted,
        "WasPasscodeSet": True,
        "Date": datetime(2020, 4, 1, 12, 0, 0, tzinfo=timezone.utc),
        "Applications": {"com.apple.MobileSMS": {}},
        "Lockdown": {
            "ProductVersion": "13.4.1",
            "ProductType": "iPhone8,4",
            "DeviceName": "Test iPhone",
            "UniqueDeviceID": "ab" + "0" * 38,
        },
        "BackupKeyBag": b"\x00" * 32,
    }))
    if encrypted:
        # Write garbage bytes to mimic encrypted Manifest.db
        (d / "Manifest.db").write_bytes(b"\x00" * 4096)
    else:
        conn = sqlite3.connect(d / "Manifest.db")
        conn.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, "
                      "domain TEXT, relativePath TEXT, flags INTEGER, "
                      "file BLOB)")
        for fid, dom, rel in [
                ("a" * 40, "HomeDomain", "Library/SMS/sms.db"),
                ("b" * 40, "AppDomain-com.whatsapp.WhatsApp",
                 "Documents/ChatStorage.sqlite")]:
            conn.execute(
                "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
                (fid, dom, rel, 1,
                 plistlib.dumps({"$objects": [
                     "$null", {"Size": 1024, "Mode": 33188,
                                "LastModified": 1585747200}]})))
        conn.commit(); conn.close()


def test_ios_agent_unencrypted_itunes_backup_emits_metadata_and_inventory(
        tmp_path, monkeypatch):
    src, m = _make_case(tmp_path, monkeypatch, "t-ios-bk")
    bd = Path(m.case_dir) / "backup"
    _make_itunes_backup(bd, encrypted=False)
    ctx = _ctx_for("t-ios-bk", Path(m.case_dir), bd, m.__dict__)
    findings = IOSForensicatorAgent().run(ctx)
    metadata = [f for f in findings if "Test iPhone" in f.claim]
    inventory = [f for f in findings if "file inventory" in f.claim]
    assert metadata and metadata[0].confidence == "high"
    assert "13.4.1" in metadata[0].claim
    assert "iPhone8,4" in metadata[0].claim
    assert inventory and inventory[0].confidence == "medium"


def test_ios_agent_encrypted_itunes_backup_emits_blocker(tmp_path,
                                                          monkeypatch):
    src, m = _make_case(tmp_path, monkeypatch, "t-ios-bk-enc")
    bd = Path(m.case_dir) / "backup"
    _make_itunes_backup(bd, encrypted=True)
    ctx = _ctx_for("t-ios-bk-enc", Path(m.case_dir), bd, m.__dict__)
    findings = IOSForensicatorAgent().run(ctx)
    # Metadata Finding still emits (Manifest.plist is plaintext)
    assert any("encrypted" in f.claim.lower() for f in findings)
    # Inventory blocker Finding fires because Manifest.db is encrypted
    blockers = [f for f in findings if f.confidence == "insufficient"
                 and "Manifest.db" in f.claim]
    assert blockers
    assert "decrypt_manifest_db" in blockers[0].claim


# --- iOS agent: sysdiagnose wire-up --------------------------------------


def test_ios_agent_sysdiagnose_tarball_emits_metadata_and_jetsam(
        tmp_path, monkeypatch):
    src, m = _make_case(tmp_path, monkeypatch, "t-ios-sd")
    # Build a synthetic sysdiagnose tarball
    sd_root = tmp_path / "sysdiagnose_2025_TEST_iPhone_OS"
    cas = sd_root / "crashes_and_spins"; cas.mkdir(parents=True)
    header = {
        "bug_type": "298",
        "timestamp": "2025-01-01 12:00:00.00 +0000",
        "os_version": "iPhone OS 16.5 (20F66)",
        "incident_id": "SAMPLE",
    }
    body = {"product": "iPhone14,2",
            "largestProcess": "MyApp",
            "processes": [{"name": "MyApp", "pid": 1, "rpages": 9999}]}
    (cas / "JetsamEvent-2025-01-01-120000.ips").write_text(
        json.dumps(header) + "\n" + json.dumps(body))
    (sd_root / "system_logs.logarchive").mkdir()
    (sd_root / "system_logs.logarchive" / "tracev3").write_bytes(
        b"x" * 4096)
    tarball = tmp_path / "sysdiagnose_2025_TEST_iPhone_OS.tar.gz"
    with tarfile.open(tarball, "w:gz") as tf:
        tf.add(sd_root, arcname="sysdiagnose_2025_TEST_iPhone_OS")

    ctx = _ctx_for("t-ios-sd", Path(m.case_dir), tarball,
                    m.__dict__)
    findings = IOSForensicatorAgent().run(ctx)
    summary = [f for f in findings
                if "sysdiagnose triaged" in f.claim]
    jetsams = [f for f in findings if "Jetsam" in f.claim]
    log_marker = [f for f in findings
                   if "logarchive present" in f.claim]
    assert summary and summary[0].confidence == "high"
    assert "iPhone14,2" in summary[0].claim
    assert jetsams and "MyApp" in jetsams[0].claim
    assert log_marker
    assert log_marker[0].confidence == "insufficient"


def test_ios_agent_unknown_file_returns_insufficient(tmp_path,
                                                       monkeypatch):
    src, m = _make_case(tmp_path, monkeypatch, "t-ios-bad")
    # Plain file, not a sysdiagnose tarball, not a directory →
    # insufficient finding, not a crash.
    ctx = _ctx_for("t-ios-bad", Path(m.case_dir), src, m.__dict__)
    findings = IOSForensicatorAgent().run(ctx)
    assert findings[0].confidence == "insufficient"
    assert "supported iOS bundle" in findings[0].claim
