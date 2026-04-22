"""iOS forensicator + triage tests."""
import plistlib
from pathlib import Path

import pytest

from el.skills import ios_triage as it


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)


def _write_info_plist(path: Path, bundle_id: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        plistlib.dump({"CFBundleIdentifier": bundle_id,
                        "CFBundleName": path.parent.name.rsplit(".app", 1)[0]},
                       f)


# ---------------------------------------------------------------------------
# Detector 1: jailbreak_indicator
# ---------------------------------------------------------------------------

def test_cydia_flags_jailbreak(tmp_path):
    (tmp_path / "Applications" / "Cydia.app").mkdir(parents=True)
    hits = it.detect_jailbreak_indicator(tmp_path)
    assert hits
    assert hits[0].family == "jailbreak_indicator"
    assert "Cydia" in hits[0].sample_text


def test_var_jb_rootless_flags_jailbreak(tmp_path):
    (tmp_path / "private" / "var" / "jb").mkdir(parents=True)
    hits = it.detect_jailbreak_indicator(tmp_path)
    assert hits
    assert "rootless" in hits[0].sample_text.lower() or "/var/jb" in hits[0].sample_text


def test_apt_db_flags_jailbreak(tmp_path):
    (tmp_path / "private" / "var" / "lib" / "apt").mkdir(parents=True)
    hits = it.detect_jailbreak_indicator(tmp_path)
    assert hits


def test_no_jailbreak_markers_no_hit(tmp_path):
    # Stock iOS paths that should NOT fire
    (tmp_path / "Applications" / "AppStore.app").mkdir(parents=True)
    (tmp_path / "private" / "var" / "mobile").mkdir(parents=True)
    assert it.detect_jailbreak_indicator(tmp_path) == []


# ---------------------------------------------------------------------------
# Detector 2: sideloaded_app
# ---------------------------------------------------------------------------

def _mk_app(root: Path, guid: str, app_name: str, bundle_id: str,
             with_itunes_meta: bool) -> None:
    base = (root / "private" / "var" / "containers" / "Bundle"
            / "Application" / guid)
    app = base / f"{app_name}.app"
    app.mkdir(parents=True)
    _write_info_plist(app / "Info.plist", bundle_id)
    if with_itunes_meta:
        with (base / "iTunesMetadata.plist").open("wb") as f:
            plistlib.dump({"itemName": app_name,
                            "apple-id": "test@example.com"}, f)


def test_sideloaded_app_flagged_when_no_itunes_metadata(tmp_path):
    # App Store app (has iTunes metadata): NOT flagged
    _mk_app(tmp_path, "GUID-APPSTORE", "Signal",
            "org.whispersystems.signal", with_itunes_meta=True)
    # Apple first-party (no metadata but com.apple.*): NOT flagged
    _mk_app(tmp_path, "GUID-APPLE", "Compass",
            "com.apple.compass", with_itunes_meta=False)
    # Sideloaded (no metadata, non-Apple bundle id): FLAGGED
    _mk_app(tmp_path, "GUID-SIDELOADED", "EvilTool",
            "com.attacker.evil", with_itunes_meta=False)
    hits = it.detect_sideloaded_app(tmp_path)
    assert hits
    assert hits[0].event_count == 1
    assert "EvilTool" in hits[0].sample_text
    assert "Signal" not in hits[0].sample_text
    assert "Compass" not in hits[0].sample_text


def test_sideloaded_no_bundle_root_no_hit(tmp_path):
    assert it.detect_sideloaded_app(tmp_path) == []


def test_sideloaded_unreadable_info_plist_no_false_positive(tmp_path):
    base = (tmp_path / "private" / "var" / "containers" / "Bundle"
            / "Application" / "GUID-BAD")
    (base / "Broken.app").mkdir(parents=True)
    (base / "Broken.app" / "Info.plist").write_bytes(b"not a plist")
    assert it.detect_sideloaded_app(tmp_path) == []


# ---------------------------------------------------------------------------
# Detector 3: provisioning_profile
# ---------------------------------------------------------------------------

def test_provisioning_profile_present_flagged(tmp_path):
    pp = (tmp_path / "private" / "var" / "MobileDevice"
          / "ProvisioningProfiles")
    pp.mkdir(parents=True)
    (pp / "abcd1234.mobileprovision").write_bytes(b"\x00\x01\x02\x03")
    hits = it.detect_provisioning_profile_present(tmp_path)
    assert hits
    assert hits[0].event_count == 1


def test_provisioning_profile_empty_dir_no_hit(tmp_path):
    (tmp_path / "private" / "var" / "MobileDevice"
        / "ProvisioningProfiles").mkdir(parents=True)
    assert it.detect_provisioning_profile_present(tmp_path) == []


def test_provisioning_profile_missing_dir_no_hit(tmp_path):
    assert it.detect_provisioning_profile_present(tmp_path) == []


# ---------------------------------------------------------------------------
# Detector 4: messenger_presence
# ---------------------------------------------------------------------------

def test_messenger_signal_and_telegram_flagged(tmp_path):
    _mk_app(tmp_path, "GUID-SIGNAL", "Signal",
            "org.whispersystems.signal", with_itunes_meta=True)
    _mk_app(tmp_path, "GUID-TG", "Telegram",
            "ph.telegra.Telegraph", with_itunes_meta=True)
    hits = it.detect_messenger_presence(tmp_path)
    assert hits
    assert hits[0].event_count == 2
    assert "Signal" in hits[0].sample_text
    assert "Telegram" in hits[0].sample_text


def test_messenger_wickr_enterprise_flagged(tmp_path):
    _mk_app(tmp_path, "GUID-WICKR", "WickrEnterprise",
            "com.wickr.enterprise", with_itunes_meta=True)
    hits = it.detect_messenger_presence(tmp_path)
    assert hits
    assert "Wickr" in hits[0].sample_text


def test_messenger_privacy_tools_flagged(tmp_path):
    _mk_app(tmp_path, "GUID-ONION", "OnionBrowser",
            "com.onionbrowser.OnionBrowser", with_itunes_meta=True)
    _mk_app(tmp_path, "GUID-KEEPSAFE", "KeepSafe",
            "com.egis.photovault", with_itunes_meta=True)
    hits = it.detect_messenger_presence(tmp_path)
    assert hits
    assert hits[0].event_count == 2
    assert "Onion" in hits[0].sample_text
    assert "KeepSafe" in hits[0].sample_text


def test_messenger_no_matching_apps_no_hit(tmp_path):
    _mk_app(tmp_path, "GUID-WEATHER", "Weather",
            "com.apple.weather", with_itunes_meta=True)
    assert it.detect_messenger_presence(tmp_path) == []


def test_messenger_no_bundle_root_no_hit(tmp_path):
    assert it.detect_messenger_presence(tmp_path) == []


# ---------------------------------------------------------------------------
# run_all
# ---------------------------------------------------------------------------

def test_run_all_empty_no_hits(tmp_path):
    assert it.run_all(tmp_path) == []


def test_run_all_combines_families(tmp_path):
    # Jailbreak
    (tmp_path / "Applications" / "Cydia.app").mkdir(parents=True)
    # Signal
    _mk_app(tmp_path, "GUID-SIGNAL", "Signal",
            "org.whispersystems.signal", with_itunes_meta=True)
    # Sideloaded evil
    _mk_app(tmp_path, "GUID-EVIL", "EvilTool",
            "com.attacker.tool", with_itunes_meta=False)
    hits = it.run_all(tmp_path)
    families = {h.family for h in hits}
    assert "jailbreak_indicator" in families
    assert "messenger_presence" in families
    assert "sideloaded_app" in families


# ---------------------------------------------------------------------------
# Triage routing
# ---------------------------------------------------------------------------

def test_triage_classifies_ios_fs_dir(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.triage import TriageAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "ios-image"
    # Minimum 2 iOS signals
    (src / "private" / "var" / "mobile" / "Library").mkdir(parents=True)
    (src / "private" / "var" / "containers" / "Bundle"
        / "Application").mkdir(parents=True)
    (src / "private" / "var" / "installd").mkdir(parents=True)
    (src / "Applications" / "AppStore.app").mkdir(parents=True)

    m = intake_mod.intake(src, case_id="t-ios-triage")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-ios-triage",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "ios-fs-dir"


def test_triage_android_still_routed(tmp_path, monkeypatch):
    """Guard: adding iOS branch didn't break Android detection."""
    from el.agents.base import AgentContext
    from el.agents.triage import TriageAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "android-image"
    (src / "data" / "system").mkdir(parents=True)
    (src / "data" / "system" / "packages.xml").write_text("<packages/>")
    (src / "data" / "app").mkdir(parents=True)
    (src / "data" / "data" / "com.whatsapp").mkdir(parents=True)

    m = intake_mod.intake(src, case_id="t-android-still-ok")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-android-still-ok",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "android-fs-dir"


def test_triage_windows_still_routed(tmp_path, monkeypatch):
    """Guard: iOS branch doesn't false-positive on Windows artifacts."""
    from el.agents.base import AgentContext
    from el.agents.triage import TriageAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "win-artifacts"
    (src / "registry").mkdir(parents=True)
    (src / "registry" / "SYSTEM").write_bytes(b"regf")
    (src / "registry" / "NTUSER.DAT").write_bytes(b"regf")
    (src / "registry" / "SOFTWARE").write_bytes(b"regf")

    m = intake_mod.intake(src, case_id="t-win-not-ios")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-win-not-ios",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "windows-artifacts-dir"


# ---------------------------------------------------------------------------
# Agent wiring
# ---------------------------------------------------------------------------

def test_agent_extracts_and_detects_end_to_end(tmp_path, monkeypatch):
    """Build a synthetic iOS tree, run the agent, confirm it
    emits the extract-summary Finding plus per-detector Findings."""
    from el.agents.ios_forensicator import IOSForensicatorAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "ios-image"
    # SystemVersion.plist
    sv = src / "System" / "Library" / "CoreServices" / "SystemVersion.plist"
    sv.parent.mkdir(parents=True)
    with sv.open("wb") as f:
        plistlib.dump({"ProductVersion": "14.3",
                        "ProductBuildVersion": "18C66"}, f)
    # sms.db
    _write(src / "private" / "var" / "mobile" / "Library" / "SMS"
             / "sms.db",
             b"SQLite format 3\x00")
    # Signal app installed
    _mk_app(src, "GUID-SIGNAL", "Signal",
            "org.whispersystems.signal", with_itunes_meta=True)
    # Cydia present — jailbreak
    (src / "Applications" / "Cydia.app").mkdir(parents=True)

    m = intake_mod.intake(src, case_id="t-ios-agent")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-ios-agent",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"evidence_kind": "ios-fs-dir"})
    findings = IOSForensicatorAgent().run(ctx)
    claims = [f.claim for f in findings]
    assert any("iOS artifacts extracted" in c for c in claims)
    assert any("jailbreak_indicator" in c for c in claims)
    assert any("messenger_presence" in c for c in claims)


def test_agent_insufficient_on_non_ios_input(tmp_path, monkeypatch):
    from el.agents.ios_forensicator import IOSForensicatorAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "random-dir"
    src.mkdir()
    _write(src / "random.txt", "nothing to see")
    m = intake_mod.intake(src, case_id="t-ios-miss")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-ios-miss",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"evidence_kind": "ios-fs-dir"})
    findings = IOSForensicatorAgent().run(ctx)
    assert findings[0].confidence == "insufficient"
    assert "no iOS artifacts recognised" in findings[0].claim


# ---------------------------------------------------------------------------
# Real-data smoke (skipped unless the BelkaCTF iOS image is at the
# known path)
# ---------------------------------------------------------------------------

_HACKATHON_IOS = Path("/mnt/hgfs/hackathon/iOS 14-3 - Apple iPhone SE")


@pytest.mark.skipif(
    not (_HACKATHON_IOS.is_dir()
         and (_HACKATHON_IOS / "System" / "Library" / "CoreServices"
              / "SystemVersion.plist").is_file()),
    reason="Hackathon iOS tree not present",
)
def test_hackathon_ios_extraction(tmp_path):
    from el.skills.ios_artifacts import extract_ios_artifacts
    extracted = extract_ios_artifacts(_HACKATHON_IOS, tmp_path)
    assert any(v > 0 for v in extracted.values())
    hits = it.run_all(tmp_path)
    # At minimum the messenger detector should fire on this image
    # (Signal / Telegram / Wickr / etc. are installed)
    assert any(h.family == "messenger_presence" for h in hits)
