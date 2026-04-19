"""PR-L: network-traffic anomaly detector tests.

Synthetic Zeek-format http.log + dns.log fixtures exercise each
detector's positive + negative. Confirms:
  - Normal browsing (GET-dominated, varied UAs, normal TTLs) = no hits
  - POST-heavy capture → HTTP_POST_HEAVY
  - scripted UA present → HTTP_SCRIPTED_UA
  - single UA > 90% of requests with ≥30 rows → HTTP_SINGLE_UA_DOMINANCE
  - 4xx ≥ 30% of ≥20 responses → HTTP_ERROR_HEAVY
  - 3+ domains with TTL ≤60s → DNS_SHORT_TTL
  - single domain > 50% of ≥30 queries → DNS_DOMAIN_SKEW
"""
from pathlib import Path

import pytest

from el.skills import network_anomaly as na


ZEEK_HTTP_HEADER = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\thttp\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
    "trans_depth\tmethod\thost\turi\treferrer\tversion\tuser_agent\t"
    "origin\trequest_body_len\tresponse_body_len\tstatus_code\n"
)

ZEEK_DNS_HEADER = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tdns\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
    "proto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\t"
    "rcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\n"
)


def _write_http(path: Path, rows: list[tuple[str, str, str]]) -> None:
    """rows: (method, user_agent, status_code)"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        f.write(ZEEK_HTTP_HEADER)
        for i, (method, ua, code) in enumerate(rows):
            f.write(
                f"1234567890.0\tC{i}\t10.0.0.5\t49152\t203.0.113.10\t80\t"
                f"1\t{method}\ttest.example\t/p\t-\t1.1\t{ua}\t-\t0\t0\t{code}\n")


def _write_dns(path: Path, rows: list[tuple[str, str]]) -> None:
    """rows: (query, ttls_csv)"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        f.write(ZEEK_DNS_HEADER)
        for i, (query, ttls) in enumerate(rows):
            f.write(
                f"1234567890.0\tD{i}\t10.0.0.5\t49152\t8.8.8.8\t53\tudp\t"
                f"{i}\t0.001\t{query}\t1\tC_INTERNET\t1\tA\t0\tNOERROR\t"
                f"F\tF\tT\tT\t0\t93.184.216.34\t{ttls}\n")


# ---------------------------------------------------------------------------
# Normal-traffic baseline guard
# ---------------------------------------------------------------------------

def test_normal_browsing_produces_no_anomalies(tmp_path):
    http = tmp_path / "http.log"
    dns = tmp_path / "dns.log"
    # 50 varied GETs with a typical browser UA, clean 200s
    _write_http(http, [
        ("GET",
         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/114.0 Safari/537.36",
         "200")
        for _ in range(50)
    ])
    _write_dns(dns, [
        ("www.google.com", "300.0"), ("example.com", "3600.0")
    ] * 10)
    hits = na.run_all(tmp_path)
    assert hits == []


# ---------------------------------------------------------------------------
# HTTP method ratio
# ---------------------------------------------------------------------------

def test_post_heavy_capture_fires(tmp_path):
    http = tmp_path / "http.log"
    _write_http(http, [("POST", "curl/7.80", "200")] * 40 + [("GET", "curl/7.80", "200")] * 5)
    (tmp_path / "dns.log").write_text(ZEEK_DNS_HEADER)
    hits = na.run_all(tmp_path)
    assert any(h.anomaly_id == "HTTP_POST_HEAVY" for h in hits)


def test_get_dominant_does_not_fire_post_heavy(tmp_path):
    http = tmp_path / "http.log"
    _write_http(http, [("GET", "Mozilla/5.0", "200")] * 50 + [("POST", "Mozilla/5.0", "200")] * 5)
    (tmp_path / "dns.log").write_text(ZEEK_DNS_HEADER)
    hits = na.run_all(tmp_path)
    assert not any(h.anomaly_id == "HTTP_POST_HEAVY" for h in hits)


# ---------------------------------------------------------------------------
# HTTP status distribution
# ---------------------------------------------------------------------------

def test_error_heavy_capture_fires(tmp_path):
    http = tmp_path / "http.log"
    _write_http(http,
                [("GET", "Mozilla/5.0", "404")] * 15
                + [("GET", "Mozilla/5.0", "200")] * 10)
    (tmp_path / "dns.log").write_text(ZEEK_DNS_HEADER)
    hits = na.run_all(tmp_path)
    assert any(h.anomaly_id == "HTTP_ERROR_HEAVY" for h in hits)


def test_low_error_rate_not_flagged(tmp_path):
    http = tmp_path / "http.log"
    _write_http(http,
                [("GET", "Mozilla/5.0", "200")] * 45
                + [("GET", "Mozilla/5.0", "404")] * 5)
    (tmp_path / "dns.log").write_text(ZEEK_DNS_HEADER)
    hits = na.run_all(tmp_path)
    assert not any(h.anomaly_id == "HTTP_ERROR_HEAVY" for h in hits)


# ---------------------------------------------------------------------------
# HTTP user-agent
# ---------------------------------------------------------------------------

def test_scripted_ua_fires(tmp_path):
    http = tmp_path / "http.log"
    _write_http(http, [("GET", "curl/7.80.0", "200")] * 20)
    (tmp_path / "dns.log").write_text(ZEEK_DNS_HEADER)
    hits = na.run_all(tmp_path)
    assert any(h.anomaly_id == "HTTP_SCRIPTED_UA" for h in hits)
    scripted = [h for h in hits if h.anomaly_id == "HTTP_SCRIPTED_UA"][0]
    assert "H_OPPORTUNISTIC_COMMODITY" in scripted.hypotheses


def test_python_requests_ua_fires(tmp_path):
    http = tmp_path / "http.log"
    _write_http(http, [("GET", "python-requests/2.28.1", "200")] * 15)
    (tmp_path / "dns.log").write_text(ZEEK_DNS_HEADER)
    hits = na.run_all(tmp_path)
    assert any(h.anomaly_id == "HTTP_SCRIPTED_UA" for h in hits)


def test_single_ua_dominance_fires(tmp_path):
    http = tmp_path / "http.log"
    _write_http(http,
                [("GET", "ExfilBot/1.0", "200")] * 35
                + [("GET", "Mozilla/5.0 Chrome", "200")] * 2)
    (tmp_path / "dns.log").write_text(ZEEK_DNS_HEADER)
    hits = na.run_all(tmp_path)
    assert any(h.anomaly_id == "HTTP_SINGLE_UA_DOMINANCE" for h in hits)


# ---------------------------------------------------------------------------
# DNS short TTL / domain skew
# ---------------------------------------------------------------------------

def test_short_ttl_multiple_domains_fires(tmp_path):
    (tmp_path / "http.log").write_text(ZEEK_HTTP_HEADER)
    dns = tmp_path / "dns.log"
    _write_dns(dns, [
        ("foo-evil.example", "30.0"),
        ("bar-evil.example", "60.0"),
        ("baz-evil.example", "45.0"),
        ("benign.example",   "3600.0"),
    ])
    hits = na.run_all(tmp_path)
    assert any(h.anomaly_id == "DNS_SHORT_TTL" for h in hits)


def test_single_short_ttl_does_not_fire(tmp_path):
    """One short-TTL domain (likely legit CDN) shouldn't flag."""
    (tmp_path / "http.log").write_text(ZEEK_HTTP_HEADER)
    dns = tmp_path / "dns.log"
    _write_dns(dns, [
        ("one-short.example", "30.0"),
        ("benign.example", "3600.0"),
    ])
    hits = na.run_all(tmp_path)
    assert not any(h.anomaly_id == "DNS_SHORT_TTL" for h in hits)


def test_dns_domain_skew_fires(tmp_path):
    (tmp_path / "http.log").write_text(ZEEK_HTTP_HEADER)
    dns = tmp_path / "dns.log"
    _write_dns(dns,
               [("c2.evil.example", "300.0")] * 35
               + [("www.google.com", "300.0")] * 5)
    hits = na.run_all(tmp_path)
    skew = [h for h in hits if h.anomaly_id == "DNS_DOMAIN_SKEW"]
    assert skew
    assert "H_C2_OR_REVERSE_SHELL" in skew[0].hypotheses


# ---------------------------------------------------------------------------
# Missing logs tolerance
# ---------------------------------------------------------------------------

def test_missing_logs_returns_empty(tmp_path):
    """Zeek sometimes produces no http.log / dns.log (fully-TLS capture).
    run_all must silently return [] rather than crash."""
    assert na.run_all(tmp_path) == []
