"""Live end-to-end: synthesise a tiny pcap with scapy, run the coordinator,
assert that routing chose NetworkAnalyst and that the graph contains the
expected entities."""
from pathlib import Path

import pytest

from el.evidence import intake as intake_mod
from el.evidence.graph import open_graph
from el.evidence.ledger import list_findings
from el.orchestrator.coordinator import Coordinator
from el.orchestrator.states import State


@pytest.fixture
def isolated_cases(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    yield tmp_path


def _make_pcap(path: Path) -> None:
    from scapy.all import wrpcap
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP

    pkts = [
        IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=55512, dport=53) / DNS(rd=1, qd=DNSQR(qname="evil.example.com")),
        IP(src="10.0.0.5", dst="203.0.113.7") / TCP(sport=49152, dport=4444, flags="S"),
        IP(src="203.0.113.7", dst="10.0.0.5") / TCP(sport=4444, dport=49152, flags="SA"),
        IP(src="10.0.0.5", dst="203.0.113.7") / TCP(sport=49152, dport=4444, flags="A"),
    ]
    wrpcap(str(path), pkts)


def test_pcap_routes_to_network_analyst_and_populates_graph(isolated_cases, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    pcap_path = isolated_cases / "tiny.pcap"
    _make_pcap(pcap_path)

    result = Coordinator().investigate(pcap_path, case_id="t-net")

    assert result.investigator == "NetworkAnalystAgent"
    assert result.final_state == State.DONE

    rows = list_findings(Path(result.case_dir), case_id="t-net")
    network_findings = [f for f in rows if f.agent == "network_analyst"]
    assert any("Parsed" in f.claim and "packets" in f.claim for f in network_findings), \
        "expected a high-confidence packet-summary finding"
    assert any("4444" in f.claim for f in network_findings), \
        "expected the suspicious-port flag for dport 4444"

    db, conn = open_graph(Path(result.case_dir))
    r = conn.execute("MATCH (i:IPAddress) RETURN i.addr ORDER BY i.addr")
    addrs = []
    while r.has_next():
        addrs.append(r.get_next()[0])
    assert "10.0.0.5" in addrs and "203.0.113.7" in addrs and "8.8.8.8" in addrs

    r = conn.execute("MATCH (d:Domain) RETURN d.name")
    domains = []
    while r.has_next():
        domains.append(r.get_next()[0])
    assert "evil.example.com" in domains
