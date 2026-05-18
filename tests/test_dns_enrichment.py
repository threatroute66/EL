"""Tests for el.skills.dns_enrichment — case-local passive-DNS
cross-reference.

EL extracts IPs and domains into separate iocs.json buckets even
when they came from the same Zeek dns.log response row — the
forensic linkage was lost. This skill rebuilds it from the case's
own DNS evidence (Zeek dns.log answers field) and emits an index
the correlator uses to write RESOLVED_TO edges into the graph.

Pure case-local — no external resolver is queried. Pins:
  - Zeek TSV parsing (header-driven column index, multi-IP answers)
  - CNAME / SOA / TXT answers rejected at the index layer
  - Idempotent add (same (domain, ip) added twice → 1 edge each side)
  - Lookup methods return sorted, deduplicated lists
  - Missing / malformed log files don't raise
"""
from __future__ import annotations

from pathlib import Path

import pytest

from el.skills.dns_enrichment import (
    DnsIndex,
    _looks_like_ip,
    _parse_zeek_dns_log,
    build_case_index,
    enrich_ioc,
)


# ---------------------------------------------------------------------------
# _looks_like_ip — discriminates real addresses from CNAME aliases
# ---------------------------------------------------------------------------

def test_looks_like_ip_accepts_ipv4():
    assert _looks_like_ip("4.2.0.13")
    assert _looks_like_ip("192.168.30.10")


def test_looks_like_ip_accepts_ipv6():
    assert _looks_like_ip("2001:db8::1")


def test_looks_like_ip_rejects_cname_alias():
    """Zeek's `answers` column mixes A/AAAA/CNAME rows. CNAMEs are
    domain names not addresses — reject so they don't pollute the
    (domain → ip) index with (domain → domain) entries."""
    assert not _looks_like_ip("alias.example.com")
    assert not _looks_like_ip("cdn.cloudflare.net")


def test_looks_like_ip_rejects_empty_and_garbage():
    assert not _looks_like_ip("")
    assert not _looks_like_ip("-")
    assert not _looks_like_ip("(empty)")
    assert not _looks_like_ip("not-an-address")


# ---------------------------------------------------------------------------
# DnsIndex — add + lookup contract
# ---------------------------------------------------------------------------

def test_index_add_creates_both_directions():
    """A single add must populate both maps (domain→ip and ip→domain)."""
    idx = DnsIndex()
    idx.add("evil.example", "4.2.0.13", source="zeek_dns_log")
    assert idx.lookup_ips_for("evil.example") == ["4.2.0.13"]
    assert idx.lookup_domains_for("4.2.0.13") == ["evil.example"]


def test_index_add_case_folds_domain():
    """Real DNS is case-insensitive; the index normalises to lower
    so 'Evil.EXAMPLE' and 'evil.example' both resolve."""
    idx = DnsIndex()
    idx.add("Evil.EXAMPLE", "4.2.0.13", source="zeek_dns_log")
    assert idx.lookup_ips_for("evil.example") == ["4.2.0.13"]
    assert idx.lookup_ips_for("EVIL.EXAMPLE") == ["4.2.0.13"]


def test_index_strips_trailing_dot():
    """Zeek logs FQDNs with a trailing dot. Strip so 'evil.com.'
    and 'evil.com' don't fragment the index."""
    idx = DnsIndex()
    idx.add("evil.example.", "4.2.0.13", source="z")
    assert idx.lookup_ips_for("evil.example") == ["4.2.0.13"]


def test_index_add_multiple_ips_per_domain():
    """Round-robin DNS or CDN — one domain → many IPs. All must
    survive in the lookup."""
    idx = DnsIndex()
    for ip in ("4.2.0.13", "4.2.0.14", "4.2.0.15"):
        idx.add("cdn.example", ip, source="zeek_dns_log")
    assert idx.lookup_ips_for("cdn.example") == ["4.2.0.13",
                                                    "4.2.0.14",
                                                    "4.2.0.15"]


def test_index_add_multiple_domains_per_ip():
    """Shared-hosting IP — one IP backs many domains. Lookup
    surfaces all of them sorted."""
    idx = DnsIndex()
    for d in ("a.evil.com", "b.evil.com"):
        idx.add(d, "4.2.0.13", source="zeek_dns_log")
    assert idx.lookup_domains_for("4.2.0.13") == ["a.evil.com",
                                                    "b.evil.com"]


def test_index_idempotent_add():
    """Same (domain, ip) added twice produces 1 entry each side
    (set semantics) but the record_count counter increments each
    call — that's a STAT, not a uniqueness gate."""
    idx = DnsIndex()
    idx.add("evil.example", "4.2.0.13", source="z")
    idx.add("evil.example", "4.2.0.13", source="z")
    assert len(idx.lookup_ips_for("evil.example")) == 1
    assert idx.record_count == 2  # raw counter — usable for stats


def test_index_skips_non_ip_answer():
    """A CNAME alias passed as `ip` argument must NOT pollute the
    index — the IP-side lookup must remain free of domain names."""
    idx = DnsIndex()
    idx.add("evil.example", "cname-alias.cdn", source="z")
    assert idx.lookup_ips_for("evil.example") == []
    assert idx.ip_to_domains == {}


def test_index_skips_empty_inputs():
    idx = DnsIndex()
    idx.add("", "4.2.0.13", source="z")
    idx.add("evil.example", "", source="z")
    assert idx.record_count == 0


# ---------------------------------------------------------------------------
# Zeek dns.log parsing
# ---------------------------------------------------------------------------

# Real-shape Zeek dns.log (with #fields header)
_ZEEK_DNS_SAMPLE = """\
#separator \\x09
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool
1234567890.000\tabc\t10.0.0.1\t12345\t8.8.8.8\t53\tudp\t1\t0.001\tevil.example\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t4.2.0.13,4.2.0.14\t300.0,300.0\tF
1234567891.000\tdef\t10.0.0.1\t12346\t8.8.8.8\t53\tudp\t2\t0.002\tcdn.example\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t172.16.5.26\t60.0\tF
1234567892.000\tghi\t10.0.0.1\t12347\t8.8.8.8\t53\tudp\t3\t0.001\talias.example\t1\tC_INTERNET\t5\tCNAME\t0\tNOERROR\tF\tF\tT\tT\t0\treal.example\t60.0\tF
1234567893.000\tjkl\t10.0.0.1\t12348\t8.8.8.8\t53\tudp\t4\t0.001\tnxdomain.example\t1\tC_INTERNET\t1\tA\t3\tNXDOMAIN\tF\tF\tT\tT\t0\t-\t-\tF
"""


def test_parse_zeek_dns_log_extracts_a_records(tmp_path):
    p = tmp_path / "dns.log"
    p.write_text(_ZEEK_DNS_SAMPLE)
    pairs = _parse_zeek_dns_log(p)
    # 2 IPs for evil.example + 1 for cdn.example + 1 CNAME alias
    assert ("evil.example", "4.2.0.13") in pairs
    assert ("evil.example", "4.2.0.14") in pairs
    assert ("cdn.example", "172.16.5.26") in pairs


def test_parse_zeek_dns_log_includes_cname_rows(tmp_path):
    """Parser returns ALL answers — the caller (`DnsIndex.add` via
    `_looks_like_ip`) filters out non-IP rows. Pin that the parser
    itself stays format-agnostic so a future skill could plug into
    the CNAME chain if desired."""
    p = tmp_path / "dns.log"
    p.write_text(_ZEEK_DNS_SAMPLE)
    pairs = _parse_zeek_dns_log(p)
    # The CNAME row (alias → real) is in the raw output
    assert ("alias.example", "real.example") in pairs


def test_parse_zeek_dns_log_skips_nxdomain_dash(tmp_path):
    """A `-` in the answers column is Zeek's sentinel for "no
    answer" (NXDOMAIN, query timeout). Must not be returned as an
    answer."""
    p = tmp_path / "dns.log"
    p.write_text(_ZEEK_DNS_SAMPLE)
    pairs = _parse_zeek_dns_log(p)
    assert not any(p == "nxdomain.example" and a == "-"
                    for p, a in pairs)


def test_parse_zeek_dns_log_missing_file(tmp_path):
    """Missing log file returns empty list, never raises."""
    assert _parse_zeek_dns_log(tmp_path / "absent.log") == []


def test_parse_zeek_dns_log_no_fields_header(tmp_path):
    """A log without the #fields header (truncated / corrupted)
    can't be parsed; return empty rather than guess column order."""
    p = tmp_path / "broken.log"
    p.write_text("# something else\n1234\trandom\tdata\n")
    assert _parse_zeek_dns_log(p) == []


# ---------------------------------------------------------------------------
# build_case_index — walks the case's analysis dir
# ---------------------------------------------------------------------------

def test_build_case_index_walks_zeek_dir(tmp_path):
    """Place a Zeek dns.log under the canonical
    analysis/network_analyst/zeek/ path — build_case_index
    discovers + indexes it."""
    zdir = tmp_path / "analysis" / "network_analyst" / "zeek"
    zdir.mkdir(parents=True)
    (zdir / "dns.log").write_text(_ZEEK_DNS_SAMPLE)
    idx = build_case_index(tmp_path)
    assert idx.lookup_ips_for("evil.example") == ["4.2.0.13",
                                                    "4.2.0.14"]
    assert idx.lookup_domains_for("172.16.5.26") == ["cdn.example"]
    assert idx.source_files  # records which files contributed


def test_build_case_index_handles_no_zeek_data(tmp_path):
    """A case without any pcap evidence (disk-only investigation)
    has no zeek output. Index returns empty, never raises."""
    idx = build_case_index(tmp_path)
    assert idx.record_count == 0
    assert idx.domain_to_ips == {}


def test_build_case_index_walks_rotated_logs(tmp_path):
    """Zeek can produce dns.log.gz + dated rotation files. We
    only pick up the canonical `dns*.log` glob pattern (we don't
    walk .gz on purpose — long-running pcaps make them too big to
    decompress in-line during correlator). Pin the glob behaviour."""
    zdir = tmp_path / "analysis" / "network_analyst" / "zeek"
    zdir.mkdir(parents=True)
    (zdir / "dns.log").write_text(_ZEEK_DNS_SAMPLE)
    (zdir / "dns.12:00:00-13:00:00.log").write_text(_ZEEK_DNS_SAMPLE)
    idx = build_case_index(tmp_path)
    assert len(idx.source_files) == 2


# ---------------------------------------------------------------------------
# enrich_ioc — single-IOC lookup
# ---------------------------------------------------------------------------

def test_enrich_ioc_for_ip_returns_resolved_from():
    idx = DnsIndex()
    idx.add("evil.example", "4.2.0.13", source="z")
    out = enrich_ioc(idx, "4.2.0.13")
    assert out == {"resolved_from": ["evil.example"]}


def test_enrich_ioc_for_domain_returns_resolved_to():
    idx = DnsIndex()
    idx.add("evil.example", "4.2.0.13", source="z")
    idx.add("evil.example", "4.2.0.14", source="z")
    out = enrich_ioc(idx, "evil.example")
    assert out == {"resolved_to": ["4.2.0.13", "4.2.0.14"]}


def test_enrich_ioc_returns_empty_dict_on_miss():
    idx = DnsIndex()
    out = enrich_ioc(idx, "uncorrelated.example")
    assert out == {}


def test_enrich_ioc_handles_unknown_kind():
    """A value that's neither IP nor known domain returns empty;
    no enrichment available, but no crash."""
    idx = DnsIndex()
    out = enrich_ioc(idx, "some-random-string")
    assert out == {}
