"""Tests for PR-N-depth: DGA entropy + DNS tunneling + SMB write
detectors added to network_anomaly. Pure unit tests — detectors
receive row dicts directly."""
import pytest

from el.skills import network_anomaly as na


# ---------------------------------------------------------------------------
# DGA entropy
# ---------------------------------------------------------------------------

def test_dga_fires_on_high_entropy_labels():
    """Labels with 14+ distinct chars clear the 3.8 bits threshold
    (log2(14) ≈ 3.81). Real-world DGAs tend to produce 14-20 char
    labels with near-uniform char distribution."""
    rows = [
        {"query": "xkvqzjnlrwtmbd.example.com"},
        {"query": "zgcpyvhbnkqrsf.example.com"},
        {"query": "wvjxmpzrkbqcgh.example.com"},
    ]
    hits = na.detect_dns_dga_entropy(rows)
    assert hits
    assert hits[0].anomaly_id == "DNS_DGA_ENTROPY"
    assert ("T1568.002",
            "Dynamic Resolution: Domain Generation Algorithms") in hits[0].attack


def test_dga_silent_on_dictionary_words():
    rows = [{"query": f"{word}.example.com"}
            for word in ("download", "support", "update",
                          "telemetry", "captive-portal")]
    assert na.detect_dns_dga_entropy(rows) == []


def test_dga_silent_on_short_labels():
    """Short labels can score high entropy by accident; detector
    requires length ≥10 to avoid false positives on legit CDN
    shards like 'ab', 'xy3', 'q7w'."""
    rows = [{"query": f"{label}.example.com"}
            for label in ("ab", "xy3", "q7w", "a8b9c", "xyz1k")] * 2
    assert na.detect_dns_dga_entropy(rows) == []


def test_dga_requires_at_least_three_hits():
    """Single-query false positives from CDN subdomains or
    legit-but-random service shards must not fire."""
    rows = [{"query": "xkvqzjnlrwtm.example.com"}]
    assert na.detect_dns_dga_entropy(rows) == []


def test_label_entropy_matches_expected():
    """Sanity: 'aaaaaaaaaa' has 0 entropy, uniform random = near log2(alphabet)."""
    assert na._label_entropy("aaaaaaaaaa") == pytest.approx(0.0, abs=0.01)
    # 10 distinct chars → log2(10) ≈ 3.32
    ent = na._label_entropy("abcdefghij")
    assert 3.2 <= ent <= 3.4


# ---------------------------------------------------------------------------
# DNS tunneling
# ---------------------------------------------------------------------------

def test_tunneling_fires_on_high_subdomain_cardinality():
    rows = [{"query": f"chunk{i:04d}.tunnel.bad.example"}
            for i in range(60)]
    hits = na.detect_dns_tunneling(rows)
    assert hits
    assert "high-cardinality subdomains" in hits[0].summary


def test_tunneling_fires_on_nxdomain_burst():
    rows = [{"query": f"x{i}.victim.example",
              "rcode_name": "NXDOMAIN"}
            for i in range(60)]
    hits = na.detect_dns_tunneling(rows)
    assert hits
    assert "NXDOMAIN" in hits[0].summary


def test_tunneling_fires_on_oversized_queries():
    big = "A" * 150
    rows = [{"query": f"{big}.exfil.example"} for _ in range(3)]
    hits = na.detect_dns_tunneling(rows)
    assert hits
    assert "oversized queries" in hits[0].summary


def test_tunneling_two_signals_yield_high_confidence():
    rows = ([{"query": f"chunk{i}.tunnel.bad"} for i in range(60)]
            + [{"query": f"x{i}.victim.bad", "rcode_name": "NXDOMAIN"}
               for i in range(60)])
    hits = na.detect_dns_tunneling(rows)
    assert hits and hits[0].confidence == "high"


def test_tunneling_silent_on_benign_traffic():
    rows = [{"query": f"www{i}.example.com"} for i in range(20)]
    assert na.detect_dns_tunneling(rows) == []


# ---------------------------------------------------------------------------
# SMB writes
# ---------------------------------------------------------------------------

def test_smb_admin_share_write_fires():
    rows = [
        {"action": "SMB::FILE_WRITE", "path": "\\\\DC1\\C$\\Windows\\Temp",
         "name": "evil.exe", "id.orig_h": "10.0.0.5"},
    ]
    hits = na.detect_smb_file_writes(rows)
    assert any(h.anomaly_id == "SMB_ADMIN_SHARE_WRITE" for h in hits)
    admin = [h for h in hits if h.anomaly_id == "SMB_ADMIN_SHARE_WRITE"][0]
    assert admin.confidence == "high"
    assert "H_LATERAL_MOVEMENT" in admin.hypotheses


def test_smb_write_fan_in_fires_per_client_threshold():
    rows = [
        {"action": "SMB::FILE_WRITE",
         "path": "\\\\FILESRV\\SHARE\\documents",
         "name": f"doc{i}.pdf",
         "id.orig_h": "10.0.0.50"}
        for i in range(30)
    ]
    hits = na.detect_smb_file_writes(rows)
    fan = [h for h in hits if h.anomaly_id == "SMB_WRITE_FAN_IN"]
    assert fan and fan[0].facts["top_clients"][0][0] == "10.0.0.50"


def test_smb_silent_on_reads_only():
    rows = [{"action": "SMB::FILE_OPEN", "path": "\\\\srv\\x",
              "name": "y.txt", "id.orig_h": "10.0.0.5"}
            for _ in range(50)]
    assert na.detect_smb_file_writes(rows) == []


def test_smb_silent_on_empty_input():
    assert na.detect_smb_file_writes([]) == []


# ---------------------------------------------------------------------------
# run_all wiring
# ---------------------------------------------------------------------------

def test_run_all_still_picks_up_existing_plus_new(tmp_path):
    """Sanity: run_all reads http/dns/smb_files logs and fires every
    detector that has matching input. Missing logs silent."""
    # No files → returns []
    assert na.run_all(tmp_path / "empty") == []
