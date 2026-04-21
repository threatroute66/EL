"""Kerberos wire-level triage tests (Tier-1 #2 from the capability-gap
analysis). Mirrors the EVTX-based credential_triage test layout: pure
detector tests against synthetic Zeek kerberos.log rows, plus agent
wiring via NetworkAnalystAgent._run_kerberos_triage."""
from pathlib import Path

import pytest

from el.skills import kerberos_triage as kt


# --- Zeek TSV helpers -------------------------------------------------------

_HEADER = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tkerberos\n"
    "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
    "request_type\tclient\tservice\tsuccess\terror_msg\tcipher\t"
    "forwardable\trenewable\n"
)


def _write_log(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = ["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "request_type", "client", "service", "success", "error_msg",
            "cipher", "forwardable", "renewable"]
    with path.open("w") as f:
        f.write(_HEADER)
        for r in rows:
            f.write("\t".join(str(r.get(c, "-")) for c in cols) + "\n")


def _row(**k):
    base = dict(ts="1500000000.0", request_type="TGS",
                cipher="aes256-cts-hmac-sha1-96",
                success="T", client="alice@DOM", service="cifs/fs@DOM",
                forwardable="T", renewable="T", error_msg="-",
                **{"id.orig_h": "10.0.0.5", "id.orig_p": "49123",
                   "id.resp_h": "10.0.0.1", "id.resp_p": "88"})
    base.update(k)
    return base


# --- Parser ----------------------------------------------------------------

def test_parse_reads_zeek_header_and_rows(tmp_path):
    log = tmp_path / "kerberos.log"
    _write_log(log, [_row(client="bob@DOM")])
    rows = kt.parse_kerberos_log(log)
    assert rows and rows[0]["client"] == "bob@DOM"
    assert rows[0]["request_type"] == "TGS"


def test_parse_missing_file_returns_empty(tmp_path):
    assert kt.parse_kerberos_log(tmp_path / "does_not_exist.log") == []


# --- Detector 1: RC4 Kerberoasting ----------------------------------------

def test_rc4_tgs_kerberoasting_fires_on_rc4_cipher():
    rows = [
        _row(cipher="aes256-cts-hmac-sha1-96", service="http/sp@DOM"),
        _row(cipher="rc4-hmac", service="http/sp@DOM"),
        _row(cipher="rc4-hmac", service="mssql/spsql@DOM",
             client="attacker@DOM"),
    ]
    hits = kt.detect_rc4_tgs_kerberoasting(rows)
    assert len(hits) == 1
    assert hits[0].event_count == 2
    assert ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting") in hits[0].attack
    spns = dict(hits[0].top_targets)
    assert spns.get("http/sp@DOM") == 1
    assert spns.get("mssql/spsql@DOM") == 1


def test_rc4_tgs_etype_numeric_hex_also_flagged():
    """When symbol mapping is missing Zeek may render ETYPE as '0x17' or
    '23' (RC4-HMAC). Both must flag."""
    rows = [
        _row(cipher="0x17", service="http/sp@DOM"),
        _row(cipher="23", service="mssql/x@DOM"),
    ]
    hits = kt.detect_rc4_tgs_kerberoasting(rows)
    assert hits and hits[0].event_count == 2


def test_rc4_tgs_only_flags_tgs_not_as():
    """AS-REQ is authentication-to-KDC; Kerberoasting is TGS-REQ only.
    An AS-REQ in RC4 is legacy-client noise, not a downgrade attack."""
    rows = [_row(request_type="AS", cipher="rc4-hmac",
                 service="krbtgt/DOM@DOM")]
    assert kt.detect_rc4_tgs_kerberoasting(rows) == []


def test_rc4_tgs_silent_on_aes_only():
    rows = [_row(cipher="aes256-cts-hmac-sha1-96") for _ in range(50)]
    assert kt.detect_rc4_tgs_kerberoasting(rows) == []


# --- Detector 2: AS-REQ failure burst -------------------------------------

def test_as_req_brute_fires_on_ten_failures_per_client():
    rows = [_row(request_type="AS", success="F",
                 client="ceo@DOM", error_msg="PRE_AUTH_FAILED")
            for _ in range(12)]
    hits = kt.detect_as_req_failure_burst(rows)
    brute = [h for h in hits if h.technique == "kerberos_brute"]
    assert brute and brute[0].top_targets[0] == ("ceo@DOM", 12)


def test_as_req_spray_fires_on_five_distinct_clients_one_source():
    rows = [_row(request_type="AS", success="F",
                 client=f"svc_{i}@DOM",
                 **{"id.orig_h": "192.0.2.77"})
            for i in range(6)]
    hits = kt.detect_as_req_failure_burst(rows)
    spray = [h for h in hits if h.technique == "kerberos_spray"]
    assert spray and spray[0].top_sources[0] == ("192.0.2.77", 6)


def test_as_req_success_not_counted():
    rows = [_row(request_type="AS", success="T") for _ in range(50)]
    assert kt.detect_as_req_failure_burst(rows) == []


def test_as_req_below_thresholds_silent():
    rows = [_row(request_type="AS", success="F", client="ceo@DOM")
            for _ in range(3)]       # below 10
    rows += [_row(request_type="AS", success="F",
                  client=f"u{i}@DOM",
                  **{"id.orig_h": "192.0.2.1"}) for i in range(3)]  # below 5
    assert kt.detect_as_req_failure_burst(rows) == []


# --- Detector 3: krbtgt service in TGS-REQ --------------------------------

def test_krbtgt_tgs_fires():
    rows = [_row(service="krbtgt/DOM@DOM") for _ in range(2)]
    hits = kt.detect_krbtgt_service_ticket(rows)
    assert hits and hits[0].event_count == 2
    assert ("T1558.001", "Steal or Forge Kerberos Tickets: Golden Ticket") in hits[0].attack


def test_krbtgt_tgs_ignores_as_req():
    rows = [_row(request_type="AS", service="krbtgt/DOM@DOM")]
    assert kt.detect_krbtgt_service_ticket(rows) == []


def test_krbtgt_tgs_ignores_normal_spn():
    rows = [_row(service="cifs/fileserver@DOM")]
    assert kt.detect_krbtgt_service_ticket(rows) == []


# --- run_all wiring -------------------------------------------------------

def test_run_all_combines_detectors_on_real_log(tmp_path):
    log = tmp_path / "kerberos.log"
    _write_log(log, [
        _row(cipher="rc4-hmac", service="mssql/x@DOM"),
        _row(cipher="rc4-hmac", service="mssql/y@DOM"),
        _row(cipher="rc4-hmac", service="mssql/z@DOM"),
        *[_row(request_type="AS", success="F", client="vip@DOM")
          for _ in range(12)],
        _row(service="krbtgt/DOM@DOM"),
        _row(service="krbtgt/DOM@DOM"),
    ])
    hits = kt.run_all(log)
    techniques = {h.technique for h in hits}
    assert "kerberoasting" in techniques
    assert "kerberos_brute" in techniques
    assert "krbtgt_tgs" in techniques


def test_run_all_empty_log_empty_hits(tmp_path):
    assert kt.run_all(tmp_path / "nope.log") == []


# --- Agent wiring via NetworkAnalystAgent._run_kerberos_triage ---------

def _ctx(tmp_path, monkeypatch, case_id="t-krb"):
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "cap.pcap"
    src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


def test_agent_emits_findings_for_kerberos_hits(tmp_path, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.schemas.finding import EvidenceItem

    ctx = _ctx(tmp_path, monkeypatch)
    zeek_dir = tmp_path / "zeek"
    log = zeek_dir / "kerberos.log"
    _write_log(log, [
        _row(cipher="rc4-hmac", service="http/sp@DOM"),
        _row(cipher="rc4-hmac", service="mssql/x@DOM"),
        _row(cipher="rc4-hmac", service="mssql/y@DOM"),
    ])
    zeek_ev = EvidenceItem(
        tool="zeek", version="5.2.0",
        command="zeek -r cap.pcap", output_sha256="0" * 64,
        output_path=str(zeek_dir),
    )
    findings = NetworkAnalystAgent()._run_kerberos_triage(
        ctx, zeek_dir, zeek_ev)
    kerb = [f for f in findings if "kerberoasting" in f.claim.lower()]
    assert kerb
    assert kerb[0].confidence == "high"
    assert "H_CREDENTIAL_ACCESS" in kerb[0].hypotheses_supported


def test_agent_silent_when_no_kerberos_log(tmp_path, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.schemas.finding import EvidenceItem

    ctx = _ctx(tmp_path, monkeypatch, "t-krb-silent")
    zeek_dir = tmp_path / "zeek-empty"
    zeek_dir.mkdir()
    zeek_ev = EvidenceItem(
        tool="zeek", version="5.2.0",
        command="zeek -r cap.pcap", output_sha256="0" * 64,
        output_path=str(zeek_dir),
    )
    findings = NetworkAnalystAgent()._run_kerberos_triage(
        ctx, zeek_dir, zeek_ev)
    assert findings == []


def test_agent_silent_on_clean_aes_traffic(tmp_path, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.schemas.finding import EvidenceItem

    ctx = _ctx(tmp_path, monkeypatch, "t-krb-clean")
    zeek_dir = tmp_path / "zeek"
    _write_log(zeek_dir / "kerberos.log",
               [_row(cipher="aes256-cts-hmac-sha1-96") for _ in range(50)])
    zeek_ev = EvidenceItem(
        tool="zeek", version="5.2.0",
        command="zeek -r cap.pcap", output_sha256="0" * 64,
        output_path=str(zeek_dir),
    )
    findings = NetworkAnalystAgent()._run_kerberos_triage(
        ctx, zeek_dir, zeek_ev)
    # Clean AES-only traffic should not trigger anything
    assert findings == []
