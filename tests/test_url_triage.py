"""PR-E: behavioural URL triage — suspicious TLD classification and
disposable-subdomain cluster detection.

Grounded in real hosts from batch-1/batch-2 pcaps at /mnt/hgfs/pcaps/.
Targets the EK / commodity traffic class that PR-C's per-family URL
regexes missed on 2015-01 samples.
"""
import pytest

from el.skills.url_triage import (
    _registered_parent, disposable_subdomain_cluster, shannon_entropy,
    suspicious_tld,
)


# ---------------------------------------------------------------------------
# suspicious_tld — four risk categories
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("domain,category", [
    # abuse (Freenom free-TLDs)
    ("cheap-evil.tk", "abuse"),
    ("whatever.ml", "abuse"),
    ("dropper.ga", "abuse"),
    ("c2.cf", "abuse"),
    ("site.gq", "abuse"),
    # newgen (high-abuse-ratio nTLDs)
    ("attacker.top", "newgen"),
    ("phish.xyz", "newgen"),
    ("payload.click", "newgen"),
    ("landing.loan", "newgen"),
    ("exploit.pw", "newgen"),
    # ddns (dynamic DNS providers) — observed in 2014-12-17-Fiesta:
    # nrkuktxvn.myftp.org → parent=myftp.org
    ("nrkuktxvn.myftp.org", "ddns"),
    ("user123.duckdns.org", "ddns"),
    ("c2server.no-ip.biz", "ddns"),
    ("foo.hopto.org", "ddns"),
    ("seventhnamed.co.vu", "ddns"),   # 2014-12-10-Nuclear — co.vu is ddns-style
    # mixed (legit-but-skewed)
    ("evil.rocks", "mixed"),
    # From 2015-01-21-Angler: hydroceppoweron.metalmaidenphotography.rocks
    ("hydroceppoweron.metalmaidenphotography.rocks", "mixed"),
])
def test_suspicious_tld_classification(domain, category):
    is_sus, info = suspicious_tld(domain)
    assert is_sus, f"{domain} should be flagged"
    assert info is not None
    cat, _ = info
    assert cat == category, f"{domain} → {cat}, expected {category}"


@pytest.mark.parametrize("domain", [
    "www.google.com", "api.github.com", "microsoft.com",
    "www.scottishquality.com",   # 2014-12-07 Neutrino parent site (legit)
    "lodgemoornursery.co.uk",    # 2014-11-22 Angler compromised legit site
    "short",                     # no dot → not a domain
])
def test_benign_hosts_not_flagged(domain):
    is_sus, _ = suspicious_tld(domain)
    assert not is_sus, f"{domain} falsely flagged as suspicious TLD"


def test_ddns_parent_extracted_correctly():
    """Verify the returned hit is the DDNS PARENT, not the subdomain."""
    _, info = suspicious_tld("anything.duckdns.org")
    assert info == ("ddns", "duckdns.org")


# ---------------------------------------------------------------------------
# shannon_entropy + disposable_subdomain_cluster
# ---------------------------------------------------------------------------

def test_shannon_entropy_known_values():
    # Empty → 0
    assert shannon_entropy("") == 0.0
    # Uniform 4-char alphabet → 2.0 bits
    assert abs(shannon_entropy("abcd") - 2.0) < 1e-6
    # Single char → 0
    assert shannon_entropy("aaaa") == 0.0
    # High-entropy 32-char hex → near log2(16) = 4 (but only for uniform)
    assert shannon_entropy("0123456789abcdef" * 2) > 3.5


def test_disposable_cluster_nuclear_ek_shape():
    """From 2014-12-10-Nuclear-EK-traffic.pcap:
      byxswk7yqg0plq1u59l9npl.parkmedical.com.au
      byxswk7yqg0plq1u59l9npl1177542af60f24b98053e1eb7a699643c.parkmedical.com.au
    Plus a synthesised third under the same parent to hit min_count=3.
    """
    hosts = [
        "byxswk7yqg0plq1u59l9npl.parkmedical.com.au",
        "byxswk7yqg0plq1u59l9npl1177542af60f24b98053e1eb7a699643c.parkmedical.com.au",
        "qpx91zv3nkhg5j27l8pfw2rdm.parkmedical.com.au",
    ]
    clusters = disposable_subdomain_cluster(hosts)
    assert "parkmedical.com.au" in clusters
    assert len(clusters["parkmedical.com.au"]) == 3


def test_disposable_cluster_angler_rocks_shape():
    """From 2015-01-21-Angler-EK-traffic.pcap — three random leftmost
    labels under one .rocks parent."""
    hosts = [
        "hydroceppoweron.metalmaidenphotography.rocks",
        "wxfgrjbpmq78aa.metalmaidenphotography.rocks",
        "zvqlnktdgpbsx.metalmaidenphotography.rocks",
    ]
    clusters = disposable_subdomain_cluster(hosts)
    assert "metalmaidenphotography.rocks" in clusters


def test_disposable_cluster_needs_three_subs():
    """Two subs shouldn't trigger — single-compromised-site with a pair
    of random-ish hosts is noisier than useful."""
    hosts = [
        "wxfgrjbpmq78aa.example.com",
        "zvqlnktdgpbsx.example.com",
    ]
    assert disposable_subdomain_cluster(hosts) == {}


def test_disposable_cluster_legit_short_subs_skipped():
    """Short / dictionary-word subdomains like www/mail/api have low
    entropy and should not count as disposable."""
    hosts = [
        "www.example.com",
        "mail.example.com",
        "api.example.com",
        "shop.example.com",
        "cdn.example.com",
    ]
    assert disposable_subdomain_cluster(hosts) == {}


def test_disposable_cluster_cdn_exempt():
    """AWS / Cloudfront / Azure etc. legitimately serve via many random
    subdomains — shouldn't be classified as EK clusters."""
    hosts = [
        "d1a2b3c4e5f6g7h.cloudfront.net",
        "xyzabcdefghij.cloudfront.net",
        "pqrmnopqrstuvw.cloudfront.net",
        "foo123bar456baz.s3.amazonaws.com",
        "blob1abcdef.core.windows.net",
    ]
    assert disposable_subdomain_cluster(hosts) == {}


def test_registered_parent_handles_two_label_cctld():
    """co.uk / com.au / org.uk etc. are two-label ccTLDs — registered
    parent needs three labels of the domain, not two."""
    assert _registered_parent("foo.bar.co.uk") == "bar.co.uk"
    assert _registered_parent("x.site.com.au") == "site.com.au"
    # plain com → two labels
    assert _registered_parent("www.example.com") == "example.com"


# ---------------------------------------------------------------------------
# End-to-end through NetworkAnalystAgent
# ---------------------------------------------------------------------------

def test_network_analyst_emits_ddns_finding(tmp_path, monkeypatch):
    """Fiesta EK case: one *.myftp.org host should produce a DDNS
    suspicious-TLD finding at medium confidence with C2 hypothesis."""
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import network_extra as nx

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.pcap"; src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00"*60)
    m = intake_mod.intake(src, case_id="t-ddns")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-ddns", case_dir=m.case_dir,
                       input_path=src, manifest=m.__dict__)

    fake = nx.TsharkExtract(
        pcap=src, out_path=tmp_path / "tshark.json", rc=0,
        fields={
            "http.request.full_uri": ["http://nrkuktxvn.myftp.org/foo"],
            "http.host": ["nrkuktxvn.myftp.org"],
            "http.user_agent": ["Mozilla/4.0"],
            "tls.handshake.extensions_server_name": [],
            "x509sat.printableString": [],
        },
        command=["tshark"],
    )
    monkeypatch.setattr(nx, "extract_http_tls",
                        lambda pcap, out_dir, timeout=600: fake)

    findings = NetworkAnalystAgent()._run_tshark(ctx, tmp_path)
    sus = [f for f in findings if "Suspicious-TLD traffic (ddns)" in f.claim]
    assert sus
    assert sus[0].confidence == "medium"
    assert "H_C2_OR_REVERSE_SHELL" in sus[0].hypotheses_supported
    assert "myftp.org" in sus[0].claim
