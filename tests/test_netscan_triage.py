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


# ---------------------------------------------------------------------------
# Benign cloud/CDN beacon guard (Lone Wolf false positive, 2026-06)
# ---------------------------------------------------------------------------

def test_benign_cloud_provider_resolves_lonewolf_ips():
    """The actual Lone Wolf 'C2 beacon' destinations are legitimate cloud/CDN
    HTTPS endpoints (OneDrive/Office365/telemetry/CDN) on a cloud-heavy Win10
    host. benign_cloud_provider must recognise them on web ports."""
    bcp = netscan_triage.benign_cloud_provider
    assert bcp("13.89.184.76", 443) == "Microsoft"
    assert bcp("52.176.102.108", 443) == "Microsoft"
    assert bcp("204.79.197.213", 443) == "Microsoft"
    assert bcp("23.210.65.9", 443) == "Akamai"
    assert bcp("2620:100:601d:4::a27d:504", 443) == "Dropbox"


def test_benign_cloud_provider_scoped_to_web_ports_only():
    """A cloud-range IP on a non-web port stays suspicious — a beacon to
    13.89.x.x:4444 is NOT excused just because the IP is Microsoft's."""
    bcp = netscan_triage.benign_cloud_provider
    assert bcp("13.89.184.76", 4444) is None
    assert bcp("13.89.184.76", 8443) == "Microsoft"   # 8443 is a web port
    assert bcp("45.77.55.12", 443) is None            # non-cloud attacker IP
    assert bcp("185.220.101.5", 443) is None          # Tor-ish, non-cloud


def test_cloud_beacon_flagged_benign_attacker_beacon_not():
    """detect_repeat_endpoint_beacon must tag a cloud/CDN endpoint with
    cloud_provider (→ benign_cloud True) while a non-cloud repeat endpoint
    stays benign_cloud False so it still scores as C2."""
    cloud = [_row(foreign="13.89.184.76", fport=443, lport=50000 + i,
                  state="CLOSED") for i in range(52)]
    attacker = [_row(foreign="45.77.55.12", fport=8443, lport=51000 + i,
                     state="CLOSED") for i in range(12)]
    bc = netscan_triage.detect_repeat_endpoint_beacon(cloud)[0]
    bx = netscan_triage.detect_repeat_endpoint_beacon(attacker)[0]
    assert bc.benign_cloud is True and bc.cloud_provider == "Microsoft"
    assert bx.benign_cloud is False and bx.cloud_provider == ""


def test_cloud_beacon_emits_low_confidence_without_c2(tmp_path, monkeypatch):
    """Agent wiring: a benign-cloud beacon must emit at low confidence and
    must NOT lift H_C2_BEACONING; a non-cloud beacon in the same run still
    does. Regression for the Lone Wolf 'Azure C2' false positive."""
    from el.agents.memory_forensicator import MemoryForensicatorAgent
    rows = (
        [_row(foreign="13.89.184.76", fport=443, lport=50000 + i, state="CLOSED")
         for i in range(52)]                       # Microsoft cloud — benign
        + [_row(foreign="45.77.55.12", fport=8443, lport=51000 + i, state="CLOSED")
           for i in range(12)]                     # attacker C2 — must fire
    )
    beacons = netscan_triage.detect_repeat_endpoint_beacon(rows)
    cloud = [b for b in beacons if b.foreign_addr == "13.89.184.76"][0]
    c2 = [b for b in beacons if b.foreign_addr == "45.77.55.12"][0]
    assert cloud.benign_cloud and not c2.benign_cloud


# ---------------------------------------------------------------------------
# Weak web-residue guard + scorer keyword-trap (Lone Wolf residuals, 2026-06)
# ---------------------------------------------------------------------------

def test_weak_web_residue_downgrades_only_browsing_shape():
    """A public web-port beacon with low count + no in-flight session is
    leftover web browsing, not C2 — downgraded. But the SRL true positive
    (8080 / attributed / private), high-volume, established, internal, and
    non-web-port beacons must all still fire."""
    def rws(addr, port, n, state="CLOSED", pid=None):
        return [{"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 50000 + i,
                 "ForeignAddr": addr, "ForeignPort": port, "State": state,
                 "PID": pid} for i in range(n)]
    fire = netscan_triage.detect_repeat_endpoint_beacon
    # Downgraded (Lone Wolf residual shape)
    assert fire(rws("107.152.26.197", 443, 7))[0].weak_web_residue is True
    assert fire(rws("208.185.50.40", 443, 4))[0].weak_web_residue is True
    # Still fire (must NOT be low-signal)
    assert fire(rws("172.16.4.10", 8080, 10, pid=2500))[0].is_low_signal is False  # SRL TP
    assert fire(rws("45.77.55.12", 443, 15))[0].is_low_signal is False             # high-volume
    assert fire(rws("45.77.55.12", 443, 5, state="ESTABLISHED"))[0].is_low_signal is False
    assert fire(rws("172.16.9.9", 443, 6))[0].is_low_signal is False               # internal :443
    assert fire(rws("1.2.3.4", 4444, 6))[0].is_low_signal is False                 # non-web port


def test_low_signal_caveat_does_not_relift_c2_beaconing():
    """Regression for the keyword-in-caveat trap: the H_C2_BEACONING scorer
    is keyword-based, so a downgraded beacon's suppression text must NOT
    contain its trigger words ('beacon', 'c2 channel', 'periodic check-in',
    'suspicious destination ports') — otherwise the caveat re-lifts the very
    hypothesis it clears. The agent's low-signal claim is reproduced here."""
    from el.intel.hypotheses import _h_c2_beaconing
    from el.schemas.finding import Finding, EvidenceItem
    ev = EvidenceItem(tool="t", version="1", command="t",
                      output_sha256="x" * 64, output_path="/x")
    claim = ("Repeated HTTPS to 107.152.26.197:443 (7 connection(s); TCPv4; "
             "states: CLOSED=7) — low-volume HTTPS to a public web port with no "
             "in-flight session (CLOSED-only) — consistent with leftover "
             "ordinary web browsing. Treated as benign web/cloud traffic, not "
             "malicious command channel; pivot on the owning process if a "
             "hosted backdoor is suspected.")
    f = Finding(case_id="t", agent="memory_forensicator", confidence="low",
                claim=claim, evidence=[ev])
    assert _h_c2_beaconing(f) == 0, "low-signal caveat must not lift H_C2_BEACONING"
