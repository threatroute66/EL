"""macOS network-history parser tests — synthetic DHCP + known-networks."""
import plistlib
from datetime import datetime
from pathlib import Path

import pytest

from el.skills import macos_network_history as nh


def _write_plist(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(obj))


def _lease_dir(root: Path) -> Path:
    return root / "private" / "var" / "db" / "dhcpclient" / "leases"


def _known_net(root: Path) -> Path:
    return (root / "Library" / "Preferences"
            / "com.apple.wifi.known-networks.plist")


def _make_fs(root: Path):
    _write_plist(_lease_dir(root) / "en0.plist", {
        "IPAddress": "192.168.1.190",
        "RouterIPAddress": "192.168.1.1",
        "RouterHardwareAddress": bytes.fromhex("c404158ba58f"),
        "ClientIdentifier": bytes.fromhex("01560ca8b8133b"),
        "SSID": "OpenWrt-5G",
        "LeaseLength": 43200,
        "LeaseStartDate": datetime(2025, 12, 24, 21, 48, 49),
    })
    _write_plist(_known_net(root), {
        "wifi.network.ssid.OpenWrt-5G": {
            "AddedAt": datetime(2025, 12, 12, 21, 45, 20),
            "JoinedByUserAt": datetime(2025, 12, 12, 21, 45, 20),
            "JoinedBySystemAt": datetime(2025, 12, 24, 21, 48, 45),
            "UpdatedAt": datetime(2025, 12, 24, 21, 48, 45),
        },
        "wifi.network.ssid.PANERA": {
            "AddedAt": datetime(2025, 12, 10, 19, 31, 21),
            "JoinedByUserAt": datetime(2025, 12, 10, 19, 31, 21),
            "JoinedBySystemAt": datetime(2025, 12, 10, 21, 14, 10),
            "UpdatedAt": datetime(2025, 12, 10, 21, 14, 11),
        },
    })


def test_dhcp_lease_parsed(tmp_path):
    _make_fs(tmp_path)
    run = nh.parse(tmp_path)
    assert len(run.leases) == 1
    l = run.leases[0]
    assert l.interface == "en0"
    assert l.ip_address == "192.168.1.190"
    assert l.router_mac == "c4:04:15:8b:a5:8f"
    assert l.client_id == "01:56:0c:a8:b8:13:3b"
    assert l.ssid == "OpenWrt-5G"
    assert l.lease_start_utc == "2025-12-24 21:48:49"
    assert l.lease_length == 43200


def test_known_networks_parsed(tmp_path):
    _make_fs(tmp_path)
    run = nh.parse(tmp_path)
    nets = {n.ssid: n for n in run.networks}
    assert set(nets) == {"OpenWrt-5G", "PANERA"}
    assert nets["PANERA"].added_utc == "2025-12-10 19:31:21"
    assert nets["PANERA"].joined_by_system_utc == "2025-12-10 21:14:10"


def test_networks_joined_on(tmp_path):
    _make_fs(tmp_path)
    run = nh.parse(tmp_path)
    joined = [n.ssid for n in run.networks_joined_on("2025-12-10")]
    assert joined == ["PANERA"]


def test_timeline_sorted(tmp_path):
    _make_fs(tmp_path)
    run = nh.parse(tmp_path)
    tl = run.timeline()
    times = [t for t, _k, _d in tl]
    assert times == sorted(times)
    # the DHCP lease event is present with the router MAC in the detail
    assert any(k == "dhcp_lease" and "c4:04:15:8b:a5:8f" in d
               for _t, k, d in tl)


def test_output_and_evidence(tmp_path):
    _make_fs(tmp_path)
    run = nh.parse(tmp_path, output_dir=tmp_path / "out")
    assert run.output_path.is_file()
    assert run.output_sha256 and run.output_sha256 != "0" * 64
    ev = run.as_evidence()
    assert ev.extracted_facts["dhcp_lease_count"] == 1
    assert ev.extracted_facts["known_network_count"] == 2
    assert "c4:04:15:8b:a5:8f" in ev.extracted_facts["router_macs"]
    assert ev.tool == "el.macos_network_history"


def test_airport_prefs_fallback(tmp_path):
    # No known-networks.plist -> fall back to legacy airport preferences.
    ap = (tmp_path / "Library" / "Preferences" / "SystemConfiguration"
          / "com.apple.airport.preferences.plist")
    _write_plist(ap, {
        "RememberedNetworks": [
            {"SSIDString": "OldCafe",
             "LastConnected": datetime(2024, 1, 2, 3, 4, 5)},
        ],
    })
    run = nh.parse(tmp_path)
    assert [n.ssid for n in run.networks] == ["OldCafe"]
    assert run.networks[0].updated_utc == "2024-01-02 03:04:05"


def test_empty_when_no_artifacts(tmp_path):
    (tmp_path / "Users").mkdir()
    run = nh.parse(tmp_path)
    assert run.total == 0


def test_missing_root_raises(tmp_path):
    with pytest.raises(nh.MacOSNetworkHistoryError):
        nh.parse(tmp_path / "nope")


def test_agent_emits_network_history_finding(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents import macos_forensicator as mf
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"
    src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-mac-net")
    with open_ledger(m.case_dir):
        pass

    exports = Path(m.case_dir) / "exports" / "macos-artifacts"
    _make_fs(exports)
    monkeypatch.setattr(mf.mt, "run_all", lambda _p: [])

    ctx = AgentContext(case_id="t-mac-net", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"macos_artifacts_dir": str(exports)})
    findings = mf.MacOSForensicatorAgent().run(ctx)
    assert any("network history" in f.claim.lower()
               and "c4:04:15:8b:a5:8f" in f.claim for f in findings)
