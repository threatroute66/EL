"""Port classification surfaced alongside beacon hits.

From SRL-2018 shakedown: `172.16.4.7:22233` on base-sp remained
"unexplained — not a known port and not traced to a specific service".
The beacon detector correctly flagged the repeat endpoint, but the
finding claim printed only the number 22233, burying the signal among
findings for 8080 / 5985 / 443 that look superficially similar.

These tests lock in that port_category() distinguishes
known-service-mapped ports from the registered-but-unknown bucket
where 22233-class C2 defaults live.
"""
from el.skills.netscan_triage import (
    BeaconHit, detect_repeat_endpoint_beacon,
    port_annotation, port_category,
)


# --- port_category ---------------------------------------------------------

def test_known_service_ports():
    for p, expect in [
        (80, "http"), (443, "https"), (3389, "rdp"),
        (5985, "winrm_http"), (8080, "http_alt"),
        (1433, "mssql"), (61613, "stomp"),
        (808, "ms_net_tcp"),   # SP WCF — legit inter-server
    ]:
        cat, svc = port_category(p)
        assert cat == "known", f"port {p}: expected known, got {cat}"
        assert svc == expect, f"port {p}: expected service {expect}, got {svc}"


def test_registered_unknown_ports_flagged():
    # 22233 is THE motivating case (SRL-2018 base-sp).
    # 4444, 31337 are classic malware defaults still in registered range.
    for p in (22233, 4444, 31337, 12345, 49150):
        cat, svc = port_category(p)
        assert cat == "registered", f"port {p}: expected registered, got {cat}"
        assert svc is None


def test_ephemeral_range():
    for p in (49152, 50000, 60000, 65000):
        cat, _ = port_category(p)
        assert cat == "ephemeral"


def test_well_known_unmapped():
    # Port in 1-1023 that we don't have in KNOWN_PORT_SERVICES should
    # still be distinguished from the registered range.
    cat, svc = port_category(17)  # QOTD — low enough, not in our map
    assert cat == "well_known"
    assert svc is None


def test_port_annotation_strings():
    assert port_annotation(5985) == "winrm_http"
    assert port_annotation(443) == "https"
    # The money case: 22233 must annotate visibly, not silently.
    ann = port_annotation(22233)
    assert "unregistered" in ann.lower(), f"annotation too quiet: {ann!r}"
    assert port_annotation(60123) == "ephemeral"


# --- BeaconHit integration -------------------------------------------------

def test_beacon_hit_exposes_port_label():
    # Synthesise 6 rows that beacon to a registered-unknown port —
    # exactly the SRL-2018 base-sp → 172.16.4.7:22233 shape.
    rows = [
        {"ForeignAddr": "172.16.4.7", "ForeignPort": 22233,
         "LocalPort": 51000 + i, "Proto": "TCPv4",
         "State": "ESTABLISHED", "PID": 4242}
        for i in range(6)
    ]
    hits = detect_repeat_endpoint_beacon(rows, min_count=4)
    assert len(hits) == 1
    b = hits[0]
    assert b.foreign_port == 22233
    assert b.port_category == "registered"
    assert "unregistered" in b.port_label.lower()


def test_beacon_hit_known_port_label():
    rows = [
        {"ForeignAddr": "172.16.4.10", "ForeignPort": 8080,
         "LocalPort": 52000 + i, "Proto": "TCPv4",
         "State": "ESTABLISHED", "PID": 1234}
        for i in range(6)
    ]
    hits = detect_repeat_endpoint_beacon(rows, min_count=4)
    assert len(hits) == 1
    assert hits[0].port_label == "http_alt"
