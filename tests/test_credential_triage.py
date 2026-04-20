"""PR-E: credential-access detectors — 4625 burst, 4769 Kerberoasting,
4776 NTLM spray. Synthetic EvtxEvent fixtures that mirror the payload
shape observed in the SRL-2018 DC CSV (PayloadData1 'Target: ...',
PayloadData2 'Workstation/ServiceName/LogonType ...', PayloadData4
'TicketEncryptionType: ...').
"""
from pathlib import Path

from el.skills.credential_triage import (
    CredHit, detect_4625_password_burst,
    detect_4769_rc4_kerberoasting, detect_4776_ntlm_spray, run_all,
)
from el.skills.evtx_triage import EvtxEvent, by_channel_eid


def _ev(eid: int, payload_fields: list[str], channel: str = "Security",
        time: str = "2018-07-01T10:00:00Z") -> EvtxEvent:
    payload = {f"PayloadData{i+1}": (payload_fields[i] if i < len(payload_fields) else "")
               for i in range(6)}
    return EvtxEvent(
        time_created=time, event_id=eid, channel=channel,
        provider="Microsoft-Windows-Security-Auditing",
        computer="DC1", user_name="SYSTEM", map_description="",
        payload=payload, source_file="Security.evtx",
    )


# ---------------------------------------------------------------------------
# 4625 — failed logon bursts
# ---------------------------------------------------------------------------

def test_4625_brute_force_fires_on_10_same_target():
    events = [_ev(4625, [f"Target: .\\jsmith", "LogonType 3"])
              for _ in range(12)]
    idx = by_channel_eid(events)
    hits = detect_4625_password_burst(events, idx)
    brute = [h for h in hits if h.technique == "brute_force"]
    assert brute
    assert brute[0].top_targets[0] == (".\\jsmith", 12)
    assert "T1110.001" in [t for t, _ in brute[0].attack]


def test_4625_brute_force_below_threshold_silent():
    events = [_ev(4625, [f"Target: .\\jsmith", "LogonType 3"])
              for _ in range(5)]  # below 10
    idx = by_channel_eid(events)
    assert detect_4625_password_burst(events, idx) == []


def test_4625_password_spray_fires_on_5_distinct_targets():
    # One source (workstation BASE-MAIL) hits 6 distinct accounts
    events = [_ev(4625, [f"Target: .\\user{i}", "LogonType 3",
                         "FailureReason1: bad password", "",
                         "Workstation: BASE-MAIL"])
              for i in range(6)]
    idx = by_channel_eid(events)
    hits = detect_4625_password_burst(events, idx)
    spray = [h for h in hits if h.technique == "password_spray"]
    assert spray
    assert spray[0].top_sources[0][0] == "BASE-MAIL"
    assert spray[0].top_sources[0][1] == 6
    assert "T1110.003" in [t for t, _ in spray[0].attack]


def test_4625_spray_from_ip_source():
    """Payload missing Workstation: — IP extracted from payload text."""
    events = [_ev(4625, [f"Target: .\\acct{i}", "LogonType 3",
                         "", "", "IpAddress 192.0.2.50"])
              for i in range(7)]
    idx = by_channel_eid(events)
    hits = detect_4625_password_burst(events, idx)
    spray = [h for h in hits if h.technique == "password_spray"]
    assert spray
    assert spray[0].top_sources[0][0] == "192.0.2.50"


def test_4625_mixed_signal_both_findings():
    """One account hammered AND a spray from another source — both fire."""
    hammer = [_ev(4625, ["Target: .\\admin", "LogonType 3"])
              for _ in range(12)]
    spray = [_ev(4625, [f"Target: .\\user{i}", "LogonType 3", "",
                        "", "Workstation: EVIL-WS"])
             for i in range(7)]
    events = hammer + spray
    idx = by_channel_eid(events)
    techniques = {h.technique for h in detect_4625_password_burst(events, idx)}
    assert "brute_force" in techniques and "password_spray" in techniques


def test_4625_nothing_when_absent():
    assert detect_4625_password_burst([], {}) == []


# ---------------------------------------------------------------------------
# 4769 — RC4 Kerberoasting
# ---------------------------------------------------------------------------

def test_4769_rc4_kerberoasting_fires():
    events = []
    # 4 normal AES TGS requests
    for i in range(4):
        events.append(_ev(4769, [
            "Target: SHIELDBASE.LAN\\user@SHIELDBASE.LAN",
            f"ServiceName: SVC{i}",
            "ServiceSid: S-1-5-21-...",
            "TicketEncryptionType: AES256-CTS-HMAC-SHA1-96",
        ]))
    # 5 RC4 requests → Kerberoasting
    for i in range(5):
        events.append(_ev(4769, [
            "Target: SHIELDBASE.LAN\\attacker@SHIELDBASE.LAN",
            f"ServiceName: SQL-SVC-{i}",
            "ServiceSid: S-1-5-21-...",
            "TicketEncryptionType: RC4-HMAC",
        ]))
    idx = by_channel_eid(events)
    hits = detect_4769_rc4_kerberoasting(events, idx)
    assert len(hits) == 1
    assert hits[0].technique == "kerberoasting"
    assert hits[0].event_count == 5
    # 5 distinct SPNs
    assert len(hits[0].top_targets) == 5
    assert "T1558.003" in [t for t, _ in hits[0].attack]


def test_4769_rc4_below_threshold_silent():
    """Only 2 RC4 events (below min=3) — don't fire."""
    events = [_ev(4769, [
        "Target: X@Y", f"ServiceName: SVC{i}", "",
        "TicketEncryptionType: RC4-HMAC",
    ]) for i in range(2)]
    idx = by_channel_eid(events)
    assert detect_4769_rc4_kerberoasting(events, idx) == []


def test_4769_aes_only_no_false_positive():
    events = [_ev(4769, [
        "Target: X@Y", f"ServiceName: SVC{i}", "",
        "TicketEncryptionType: AES256-CTS-HMAC-SHA1-96",
    ]) for i in range(50)]
    idx = by_channel_eid(events)
    assert detect_4769_rc4_kerberoasting(events, idx) == []


def test_4769_hex_encryption_form_also_matches():
    """Some map files render RC4 as 0x17 (hex) — detector must catch both."""
    events = [_ev(4769, [
        "Target: X@Y", f"ServiceName: SVC{i}", "",
        "TicketEncryptionType: 0x17",
    ]) for i in range(4)]
    idx = by_channel_eid(events)
    hits = detect_4769_rc4_kerberoasting(events, idx)
    assert hits and hits[0].event_count == 4


# ---------------------------------------------------------------------------
# 4776 — NTLM spray
# ---------------------------------------------------------------------------

def test_4776_ntlm_spray_fires_on_multi_target_single_source():
    events = [_ev(4776, [
        f"Target: user{i}@shieldbase.lan",
        "Workstation: ATTACKER-WS",
        "Status: Status OK",
    ]) for i in range(7)]
    idx = by_channel_eid(events)
    hits = detect_4776_ntlm_spray(events, idx)
    assert hits and hits[0].top_sources[0] == ("ATTACKER-WS", 7)


def test_4776_single_target_no_spray():
    """Legitimate service account hammering one target should not fire."""
    events = [_ev(4776, [
        "Target: svc-healthmailbox@shieldbase.lan",
        "Workstation: BASE-MAIL",
        "Status: Status OK",
    ]) for _ in range(200)]
    idx = by_channel_eid(events)
    assert detect_4776_ntlm_spray(events, idx) == []


def test_4776_below_threshold_silent():
    """Only 3 distinct targets from one workstation (below min=5)."""
    events = [_ev(4776, [
        f"Target: user{i}@shieldbase.lan",
        "Workstation: WS1", "Status: Status OK",
    ]) for i in range(3)]
    idx = by_channel_eid(events)
    assert detect_4776_ntlm_spray(events, idx) == []


# ---------------------------------------------------------------------------
# run_all + agent wiring
# ---------------------------------------------------------------------------

def _write_csv(path: Path, rows: list[dict]) -> None:
    import csv
    cols = ["TimeCreated", "EventId", "Channel", "Provider", "Computer",
            "UserName", "MapDescription", "PayloadData1", "PayloadData2",
            "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6",
            "SourceFile"]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})


def _dc_csv_rows() -> list[dict]:
    """Realistic DC mix: aes-4769 baseline + rc4 kerberoasting + ntlm spray."""
    rows = []
    # 10 normal AES TGS requests
    for i in range(10):
        rows.append({
            "TimeCreated": "2018-07-01T10:00:00Z", "EventId": "4769",
            "Channel": "Security",
            "PayloadData1": "Target: SHIELDBASE.LAN\\u@SHIELDBASE.LAN",
            "PayloadData2": f"ServiceName: AES-SVC-{i}",
            "PayloadData4": "TicketEncryptionType: AES256-CTS-HMAC-SHA1-96",
        })
    # 4 RC4 Kerberoasting events
    for i in range(4):
        rows.append({
            "TimeCreated": "2018-07-01T10:00:00Z", "EventId": "4769",
            "Channel": "Security",
            "PayloadData1": "Target: SHIELDBASE.LAN\\attacker@SHIELDBASE.LAN",
            "PayloadData2": f"ServiceName: SQL-KERBER-{i}",
            "PayloadData4": "TicketEncryptionType: RC4-HMAC",
        })
    # NTLM spray from one workstation
    for i in range(6):
        rows.append({
            "TimeCreated": "2018-07-01T10:01:00Z", "EventId": "4776",
            "Channel": "Security",
            "PayloadData1": f"Target: user{i}@shieldbase.lan",
            "PayloadData2": "Workstation: ATTACKER-WS",
            "PayloadData3": "Status: Status OK",
        })
    return rows


def test_run_all_on_csv_produces_expected_hits(tmp_path):
    csv_path = tmp_path / "evtx_parsed.csv"
    _write_csv(csv_path, _dc_csv_rows())
    hits = run_all(csv_path)
    techniques = {h.technique for h in hits}
    assert "kerberoasting" in techniques
    assert "ntlm_spray" in techniques


def test_credential_analyst_agent_wiring(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.credential_analyst import CredentialAnalystAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-credential-agent")
    with open_ledger(m.case_dir):
        pass
    csv_path = (Path(m.case_dir) / "analysis" / "windows_artifact"
                / "evtx" / "evtx_parsed.csv")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    _write_csv(csv_path, _dc_csv_rows())

    ctx = AgentContext(case_id="t-credential-agent", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = CredentialAnalystAgent().run(ctx)
    assert findings
    kerber = [f for f in findings if "kerberoasting" in f.claim.lower()]
    assert kerber and kerber[0].confidence == "high"
    assert "H_CREDENTIAL_ACCESS" in kerber[0].hypotheses_supported
    spray = [f for f in findings if "ntlm_spray" in f.claim.lower()]
    assert spray
    assert "H_BRUTE_FORCE" in spray[0].hypotheses_supported


def test_credential_analyst_agent_insufficient_when_no_csv(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.credential_analyst import CredentialAnalystAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-no-csv")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-no-csv", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = CredentialAnalystAgent().run(ctx)
    assert findings and findings[0].confidence == "insufficient"


def test_credential_analyst_insufficient_when_no_threshold_crosses(tmp_path, monkeypatch):
    """Clean domain with normal AES-only 4769 baseline → no findings,
    but agent emits an insufficient so the case audit trail is complete."""
    from el.agents.base import AgentContext
    from el.agents.credential_analyst import CredentialAnalystAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-clean-dc")
    with open_ledger(m.case_dir):
        pass
    csv_path = (Path(m.case_dir) / "analysis" / "windows_artifact"
                / "evtx" / "evtx_parsed.csv")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    _write_csv(csv_path, [
        {"TimeCreated": "2018-07-01T10:00:00Z", "EventId": "4769",
         "Channel": "Security",
         "PayloadData1": "Target: X@Y",
         "PayloadData2": f"ServiceName: AES-{i}",
         "PayloadData4": "TicketEncryptionType: AES256-CTS-HMAC-SHA1-96"}
        for i in range(20)
    ])

    ctx = AgentContext(case_id="t-clean-dc", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = CredentialAnalystAgent().run(ctx)
    assert findings and findings[0].confidence == "insufficient"
    assert "no credential-access pattern crossed threshold" in findings[0].claim
