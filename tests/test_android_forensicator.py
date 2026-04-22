"""Android forensicator + triage tests."""
import sqlite3
from pathlib import Path

import pytest

from el.skills import android_triage as at


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)


# ---------------------------------------------------------------------------
# Detector 1: rooted_device
# ---------------------------------------------------------------------------

def test_magisk_db_flags_rooted(tmp_path):
    _write(tmp_path / "data" / "adb" / "magisk.db", "")
    hits = at.detect_rooted_device(tmp_path)
    assert hits
    assert hits[0].family == "rooted_device"


def test_magisk_modules_dir_flags_rooted(tmp_path):
    (tmp_path / "data" / "adb" / "modules" / "evil_module").mkdir(
        parents=True)
    hits = at.detect_rooted_device(tmp_path)
    assert hits
    assert "evil_module" in hits[0].sample_text


def test_no_magisk_no_hit(tmp_path):
    (tmp_path / "data" / "adb").mkdir(parents=True)
    assert at.detect_rooted_device(tmp_path) == []


# ---------------------------------------------------------------------------
# Detector 2: sideloaded APKs
# ---------------------------------------------------------------------------

_PACKAGES_XML_TEMPLATE = """\
<packages>
    <package name="com.example.play" codePath="/data/app/x-1"
             installer="com.android.vending" />
    <package name="com.example.sideloaded" codePath="/data/app/y-1"
             installer="com.topjohnwu.magisk" />
    <package name="com.asus.oem.app" codePath="/data/app/z-1"
             installer="com.asus.packageinstaller" />
    <package name="com.example.aosp" codePath="/system/app/w" />
</packages>
"""


def test_sideloaded_apk_flags_non_playstore_installer(tmp_path):
    _write(tmp_path / "data" / "system" / "packages.xml",
           _PACKAGES_XML_TEMPLATE)
    hits = at.detect_sideloaded_apks(tmp_path)
    assert hits
    assert "com.example.sideloaded" in hits[0].sample_text
    # Play Store + OEM-ASUS + AOSP entries must not fire
    assert "com.example.play" not in hits[0].sample_text
    assert "com.asus.oem.app" not in hits[0].sample_text
    assert "com.example.aosp" not in hits[0].sample_text


def test_sideloaded_no_packages_xml_no_hit(tmp_path):
    assert at.detect_sideloaded_apks(tmp_path) == []


def test_sideloaded_oem_installer_not_flagged(tmp_path):
    _write(tmp_path / "data" / "system" / "packages.xml",
           '<packages><package name="com.samsung.oem" codePath="/x" '
           'installer="com.samsung.android.app.store" /></packages>')
    assert at.detect_sideloaded_apks(tmp_path) == []


# ---------------------------------------------------------------------------
# Detector 3: /data/local/tmp executables
# ---------------------------------------------------------------------------

def test_data_local_tmp_elf_flagged(tmp_path):
    _write(tmp_path / "data" / "local" / "tmp" / "payload",
           b"\x7fELF" + b"\x00" * 100)
    hits = at.detect_data_local_tmp_executables(tmp_path)
    assert hits
    assert "payload" in hits[0].sample_text


def test_data_local_tmp_shell_script_flagged(tmp_path):
    _write(tmp_path / "data" / "local" / "tmp" / "run.sh",
           b"#!/system/bin/sh\necho pwned\n")
    hits = at.detect_data_local_tmp_executables(tmp_path)
    assert hits


def test_data_local_tmp_apk_flagged(tmp_path):
    # APKs are zip archives starting with PK\x03\x04
    _write(tmp_path / "data" / "local" / "tmp" / "dropped.apk",
           b"PK\x03\x04" + b"\x00" * 200)
    hits = at.detect_data_local_tmp_executables(tmp_path)
    assert hits


def test_data_local_tmp_text_file_not_flagged(tmp_path):
    _write(tmp_path / "data" / "local" / "tmp" / "notes.txt",
           "just a reminder\n")
    assert at.detect_data_local_tmp_executables(tmp_path) == []


def test_data_local_tmp_missing_dir_no_hit(tmp_path):
    assert at.detect_data_local_tmp_executables(tmp_path) == []


# ---------------------------------------------------------------------------
# Detector 4: messenger presence
# ---------------------------------------------------------------------------

def test_messenger_whatsapp_presence_flagged(tmp_path):
    _write(tmp_path / "data" / "data" / "com.whatsapp" / "databases"
           / "msgstore.db", b"SQLite format 3\x00")
    hits = at.detect_messenger_presence(tmp_path)
    assert hits
    assert "WhatsApp" in hits[0].sample_text


def test_messenger_signal_presence_flagged(tmp_path):
    _write(tmp_path / "data" / "data" / "org.thoughtcrime.securesms"
           / "databases" / "signal.db", b"SQLite format 3\x00")
    hits = at.detect_messenger_presence(tmp_path)
    assert hits
    assert "Signal" in hits[0].sample_text


def test_messenger_installed_no_db_no_hit(tmp_path):
    """Fresh install without any DB yet — no local evidence, no hit."""
    (tmp_path / "data" / "data" / "com.whatsapp").mkdir(parents=True)
    assert at.detect_messenger_presence(tmp_path) == []


def test_messenger_no_apps_no_hit(tmp_path):
    (tmp_path / "data" / "data" / "com.android.calculator2").mkdir(
        parents=True)
    assert at.detect_messenger_presence(tmp_path) == []


# ---------------------------------------------------------------------------
# run_all
# ---------------------------------------------------------------------------

def test_run_all_empty_no_hits(tmp_path):
    assert at.run_all(tmp_path) == []


def test_run_all_combines_families(tmp_path):
    _write(tmp_path / "data" / "adb" / "magisk.db", "")
    _write(tmp_path / "data" / "system" / "packages.xml",
           _PACKAGES_XML_TEMPLATE)
    _write(tmp_path / "data" / "data" / "com.whatsapp" / "databases"
           / "msgstore.db", b"SQLite format 3\x00")
    hits = at.run_all(tmp_path)
    families = {h.family for h in hits}
    assert "rooted_device" in families
    assert "sideloaded_apk" in families
    assert "messenger_presence" in families


# ---------------------------------------------------------------------------
# Triage routing
# ---------------------------------------------------------------------------

def test_triage_classifies_android_fs_dir(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.triage import TriageAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    # Build a minimal Android shape
    src = tmp_path / "android-image"
    _write(src / "data" / "system" / "packages.xml",
           _PACKAGES_XML_TEMPLATE)
    (src / "data" / "app").mkdir(parents=True)
    (src / "data" / "data" / "com.whatsapp").mkdir(parents=True)

    m = intake_mod.intake(src, case_id="t-android-triage")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-android-triage",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "android-fs-dir"


def test_triage_windows_artifacts_still_routed(tmp_path, monkeypatch):
    """Guard: adding android branch didn't break Windows detection."""
    from el.agents.base import AgentContext
    from el.agents.triage import TriageAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "win-artifacts"
    # Two MFT-adjacent artifact files
    (src / "registry").mkdir(parents=True)
    _write(src / "registry" / "SYSTEM", b"regf")
    _write(src / "registry" / "NTUSER.DAT", b"regf")
    _write(src / "registry" / "SOFTWARE", b"regf")
    m = intake_mod.intake(src, case_id="t-win-not-android")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-win-not-android",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "windows-artifacts-dir"


# ---------------------------------------------------------------------------
# Agent wiring
# ---------------------------------------------------------------------------

def test_agent_extracts_and_detects_end_to_end(tmp_path, monkeypatch):
    """Build a synthetic Android tree, run the agent, confirm it
    emits the extract-summary Finding plus per-detector Findings."""
    from el.agents.android_forensicator import AndroidForensicatorAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "android-image"
    _write(src / "data" / "system" / "packages.xml",
           _PACKAGES_XML_TEMPLATE)
    _write(src / "data" / "adb" / "magisk.db", "")
    _write(src / "data" / "data" / "com.whatsapp" / "databases"
           / "msgstore.db", b"SQLite format 3\x00")

    m = intake_mod.intake(src, case_id="t-android-agent")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-android-agent",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"evidence_kind": "android-fs-dir"})
    findings = AndroidForensicatorAgent().run(ctx)
    claims = [f.claim for f in findings]
    assert any("Android artifacts extracted" in c for c in claims)
    assert any("rooted_device" in c for c in claims)
    assert any("sideloaded_apk" in c for c in claims)
    assert any("messenger_presence" in c for c in claims)


def test_agent_insufficient_on_non_android_input(tmp_path, monkeypatch):
    from el.agents.android_forensicator import AndroidForensicatorAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "random-dir"
    src.mkdir()
    _write(src / "random.txt", "nothing to see")
    m = intake_mod.intake(src, case_id="t-android-miss")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-android-miss",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"evidence_kind": "android-fs-dir"})
    findings = AndroidForensicatorAgent().run(ctx)
    assert findings[0].confidence == "insufficient"
    assert "no Android artifacts recognised" in findings[0].claim


# ---------------------------------------------------------------------------
# Real-data smoke (skipped unless BelkaCTF Android image is at the
# known path)
# ---------------------------------------------------------------------------

_HACKATHON_ANDROID = Path("/mnt/hgfs/hackathon/android")


@pytest.mark.skipif(
    not (_HACKATHON_ANDROID.is_dir()
         and (_HACKATHON_ANDROID / "data" / "system" / "packages.xml").is_file()),
    reason="Hackathon Android tree not present",
)
def test_hackathon_android_extraction(tmp_path):
    from el.skills.android_artifacts import extract_android_artifacts
    extracted = extract_android_artifacts(_HACKATHON_ANDROID, tmp_path)
    assert any(v > 0 for v in extracted.values())
    hits = at.run_all(tmp_path)
    # At minimum the rooted-device detector should fire on this image
    assert any(h.family == "rooted_device" for h in hits)
