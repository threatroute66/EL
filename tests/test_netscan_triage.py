"""PR-C: netscan beacon + lateral-admin-port detectors.

Validates el.skills.netscan_triage pure-function detectors and
memory_forensicator._netscan_triage wiring. Test data is patterned on
the SRL-2018 shakedown (wkstn-01 / wkstn-05 memory images where vol3
netscan was the only network visibility available).
"""
from pathlib import Path

from el.skills import netscan_triage


def _row(proto: str = "TCPv4", local: str = "172.16.7.11", lport: int = 55000,
         foreign: str = "172.16.4.10", fport: int = 8080,
         state: str = "CLOSED", pid: int = 2500) -> dict:
    return {
        "Proto": proto, "LocalAddr": local, "LocalPort": lport,
        "ForeignAddr": foreign, "ForeignPort": fport, "State": state,
        "PID": pid, "Owner": None, "Created": "2018-08-15T16:00:00+00:00",
    }


# ---------------------------------------------------------------------------
# Detector 1: repeat-endpoint beacon
# ---------------------------------------------------------------------------

def test_repeat_endpoint_beacon_fires_on_cluster():
    """SRL-2018 wkstn-01 shape: 16× outbound to same C2 IP+port."""
    rows = [_row(lport=55000 + i) for i in range(10)]
    hits = netscan_triage.detect_repeat_endpoint_beacon(rows)
    assert len(hits) == 1
    assert hits[0].foreign_addr == "172.16.4.10"
    assert hits[0].foreign_port == 8080
    assert hits[0].count == 10


def test_beacon_below_threshold_not_flagged():
    """wkstn-05 had 6× but default threshold is 4 — still fires.
    Below 4, we stay quiet."""
    rows = [_row(lport=55000 + i) for i in range(3)]
    assert netscan_triage.detect_repeat_endpoint_beacon(rows) == []


def test_beacon_detector_skips_admin_ports():
    """Admin ports go to the lateral detector; beacon must not
    double-flag them (would produce two findings for the same cluster)."""
    rows = [_row(foreign="172.16.5.21", fport=5985, lport=60000 + i)
            for i in range(8)]
    assert netscan_triage.detect_repeat_endpoint_beacon(rows) == []


def test_beacon_skips_loopback_and_wildcards():
    rows = [
        _row(foreign="0.0.0.0", fport=0, state="LISTENING"),
        _row(foreign="127.0.0.1", fport=631, lport=55000),
        _row(foreign="", fport=0),
        _row(foreign="224.0.0.22", fport=443, lport=55001),  # multicast
    ]
    # Add a real beacon cluster to confirm the detector still works
    rows.extend(_row(lport=56000 + i) for i in range(5))
    hits = netscan_triage.detect_repeat_endpoint_beacon(rows)
    assert len(hits) == 1
    assert hits[0].foreign_addr == "172.16.4.10"


def test_beacon_tracks_states_and_ports():
    rows = [
        _row(lport=55001, state="ESTABLISHED"),
        _row(lport=55002, state="CLOSED"),
        _row(lport=55003, state="CLOSED"),
        _row(lport=55004, state="CLOSED"),
    ]
    hits = netscan_triage.detect_repeat_endpoint_beacon(rows)
    assert hits[0].states == {"ESTABLISHED": 1, "CLOSED": 3}
    assert 55001 in hits[0].local_ports


# ---------------------------------------------------------------------------
# Detector 2: lateral-admin-port session
# ---------------------------------------------------------------------------

def test_lateral_winrm_fires_high_on_established():
    """Classic in-flight PowerShell Remoting lateral."""
    rows = [_row(foreign="172.16.5.21", fport=5985, state="ESTABLISHED")]
    hits = netscan_triage.detect_lateral_admin_port_session(rows)
    assert len(hits) == 1
    assert hits[0].service == "winrm_http"
    assert hits[0].established == 1


def test_lateral_smb_and_rdp_both_flagged():
    rows = [
        _row(foreign="172.16.5.20", fport=445, state="ESTABLISHED"),
        _row(foreign="172.16.5.25", fport=3389, state="ESTABLISHED"),
    ]
    hits = netscan_triage.detect_lateral_admin_port_session(rows)
    services = {h.service for h in hits}
    assert "smb" in services and "rdp" in services


def test_lateral_closed_only_still_flagged_no_established():
    """CLOSED connections indicate the session *was* there; we still
    flag it, but callers distinguish via hit.established."""
    rows = [_row(foreign="172.16.5.21", fport=5985, state="CLOSED")
            for _ in range(3)]
    hits = netscan_triage.detect_lateral_admin_port_session(rows)
    assert hits and hits[0].established == 0
    assert hits[0].count == 3


def test_lateral_ignores_non_admin_ports():
    rows = [_row(foreign="172.16.5.21", fport=8080, state="ESTABLISHED")]
    assert netscan_triage.detect_lateral_admin_port_session(rows) == []


# ---------------------------------------------------------------------------
# Clean baseline: no false positives on benign traffic
# ---------------------------------------------------------------------------

def test_clean_web_browsing_produces_no_beacon():
    """A user browsing hits many different external IPs; each one is
    seen only a handful of times. Beacon detector should stay quiet."""
    rows = []
    for i in range(20):
        # 20 different external hosts, 1-2 hits each on port 443
        rows.append(_row(foreign=f"203.0.113.{i+1}", fport=443,
                         lport=55000 + i, state="ESTABLISHED"))
        rows.append(_row(foreign=f"203.0.113.{i+1}", fport=443,
                         lport=55500 + i, state="CLOSED"))
    assert netscan_triage.detect_repeat_endpoint_beacon(rows) == []


def test_empty_rows_safe():
    assert netscan_triage.detect_repeat_endpoint_beacon([]) == []
    assert netscan_triage.detect_lateral_admin_port_session([]) == []


# ---------------------------------------------------------------------------
# Agent-level wiring: findings emitted, hypotheses tagged, confidence right
# ---------------------------------------------------------------------------

def _ctx(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-netscan-triage")
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id="t-netscan-triage", case_dir=m.case_dir,
                        input_path=src, manifest=m.__dict__)


def _run(rows, tmp_path):
    from el.skills.vol3 import PluginRun
    (tmp_path / "netscan.json").write_text("[]")
    return PluginRun(
        plugin="windows.netscan.NetScan", image=tmp_path / "x.bin", rc=0,
        stdout_path=tmp_path / "netscan.json",
        stderr_path=tmp_path / "netscan.stderr",
        rows=rows, command=["vol"], version="2.27.0",
    )


def test_wkstn_01_shape_fires_beacon_and_lateral(tmp_path, monkeypatch):
    """Reconstruct the actual wkstn-01 shakedown netscan pattern:
    repeated .4.10:8080 beacon + .5.21:5985 WinRM lateral."""
    from el.agents.memory_forensicator import MemoryForensicatorAgent

    ctx = _ctx(tmp_path, monkeypatch)
    rows = (
        [_row(foreign="172.16.4.10", fport=8080, lport=55000 + i)
         for i in range(16)]                                    # beacon × 16
        + [_row(foreign="172.16.5.21", fport=5985,
                state="ESTABLISHED", lport=56150)]              # WinRM lateral
    )
    run = _run(rows, tmp_path)
    findings = MemoryForensicatorAgent()._netscan_triage(ctx, run)
    assert findings, "expected beacon + lateral findings"

    beacons = [f for f in findings if "beacon" in f.claim.lower()]
    laterals = [f for f in findings if "lateral" in f.claim.lower()]
    assert beacons and laterals

    assert beacons[0].confidence == "high"     # 16 ≥ 10
    assert "H_C2_BEACONING" in beacons[0].hypotheses_supported

    assert laterals[0].confidence == "high"    # ESTABLISHED session
    assert "H_LATERAL_MOVEMENT" in laterals[0].hypotheses_supported


def test_empty_netscan_run_no_findings(tmp_path, monkeypatch):
    from el.agents.memory_forensicator import MemoryForensicatorAgent

    ctx = _ctx(tmp_path, monkeypatch)
    run = _run([], tmp_path)
    assert MemoryForensicatorAgent()._netscan_triage(ctx, run) == []


def test_benign_netscan_no_findings(tmp_path, monkeypatch):
    """Browsing-shape traffic (many distinct external endpoints, each
    seen once or twice) must not produce any findings."""
    from el.agents.memory_forensicator import MemoryForensicatorAgent

    ctx = _ctx(tmp_path, monkeypatch)
    rows = [_row(foreign=f"203.0.113.{i+1}", fport=443,
                 lport=55000 + i, state="ESTABLISHED")
            for i in range(15)]
    run = _run(rows, tmp_path)
    assert MemoryForensicatorAgent()._netscan_triage(ctx, run) == []
