"""icloud_attribution skill — Apple ID + DSID recovery from the
iCloud-for-Windows config plists. Deterministic: synthetic plists built
with plistlib (covers binary + xml since plistlib reads both)."""
import plistlib
from pathlib import Path

from el.skills import icloud_attribution as ic


def _make_prefs(d: Path, apple_id="fred.rocba@gmail.com", dsid="17291291257"):
    d.mkdir(parents=True, exist_ok=True)
    # AOSKit: the Apple ID is a top-level KEY (value is an opaque token)
    plistlib.dump({apple_id: b"\x01\x00\x00\x00token"},
                  open(d / "com.apple.AOSKit.plist", "wb"))
    # iCloudWinPref: DSID embedded in a quota-service URL + storage quota
    plistlib.dump({
        "StorageData": {
            "entry_points": {
                "quota.app_details_url":
                    f"https://p38-quota.icloud.com:443/quotaservice/external/ios/{dsid}/deviceUdid/x"},
            "storage_data": {"quota_info_in_bytes": {
                "total_quota": 5368709120, "total_used": 373799232}},
        }}, open(d / "iCloudWinPref.plist", "wb"))
    return d


def test_recovers_apple_id_and_dsid(tmp_path):
    p = _make_prefs(tmp_path / "Preferences")
    r = ic.parse_icloud_attribution(p)
    assert r.apple_id == "fred.rocba@gmail.com"
    assert r.dsid == "17291291257"
    assert r.quota_total_bytes == 5368709120
    assert r.quota_used_bytes == 373799232
    assert r.found()
    assert set(r.sources) == {"com.apple.AOSKit.plist", "iCloudWinPref.plist"}


def test_find_prefs_dirs_locates_nested_config(tmp_path):
    nested = tmp_path / "icloud" / "fredr"
    _make_prefs(nested)
    dirs = ic.find_prefs_dirs(tmp_path)
    assert nested in dirs


def test_crash_safe_on_missing_dir(tmp_path):
    r = ic.parse_icloud_attribution(tmp_path / "nope")
    assert not r.found()
    assert r.apple_id is None and r.dsid is None


def test_crash_safe_on_corrupt_plist(tmp_path):
    d = tmp_path / "Preferences"
    d.mkdir()
    (d / "com.apple.AOSKit.plist").write_bytes(b"not a plist at all")
    (d / "iCloudWinPref.plist").write_bytes(b"\x00\x01garbage")
    r = ic.parse_icloud_attribution(d)
    assert not r.found()        # parsed gracefully to empty, no raise


def test_as_evidence_carries_ids(tmp_path):
    p = _make_prefs(tmp_path / "Preferences")
    r = ic.parse_icloud_attribution(p)
    ev = r.as_evidence()
    assert ev.extracted_facts["apple_id"] == "fred.rocba@gmail.com"
    assert ev.extracted_facts["dsid"] == "17291291257"
