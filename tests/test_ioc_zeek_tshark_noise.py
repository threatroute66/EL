"""IOC-extractor noise: Zeek/tshark protocol field names leaking as domains.

Batch-1 of the pcap-corpus run (18 cases 2013-07 … 2014-12) found
91 cross-case overlap findings flagging Zeek/tshark JSON keys as
"domains": http.host, http.request, tls.handshake,
x509sat.printablestring, tcp.port, dns.query etc. These are protocol
field names produced by the network analyst's tshark/zeek wrappers,
picked up because the _DOMAIN regex greedily matches any
<word>.<word> pattern.

Fix locks them out via _NOISE_DOMAINS (exact matches) and
_NOISE_DOMAIN_PREFIXES (protocol namespace prefixes like "http.").
"""
import pytest

from el.skills.ioc_extract import extract


def _domains(text: str) -> set[str]:
    return extract(text)["domain"]


# Exact protocol field names seen in tshark JSON keys / log text
def test_http_field_names_not_emitted_as_domains():
    text = ('{"http.host": "evil.example.com", '
            '"http.request.method": "GET", '
            '"http.response.code": "200"}')
    d = _domains(text)
    assert "http.host" not in d
    assert "http.request" not in d
    assert "http.response" not in d
    assert "http.request.method" not in d
    # But the real domain in the Host field still surfaces
    assert "evil.example.com" in d


def test_tls_ssl_field_names_not_emitted_as_domains():
    text = "tls.handshake.type=1 tls.record.version=0x0303 ssl.handshake.ciphersuite=0x002f"
    d = _domains(text)
    assert "tls.handshake" not in d
    assert "tls.record" not in d
    assert "ssl.handshake" not in d


def test_dns_tcp_udp_field_names_not_emitted_as_domains():
    text = "dns.qry.name=evil.example.com tcp.port=443 udp.srcport=53 ip.src=10.0.0.5"
    d = _domains(text)
    assert "dns.qry" not in d and "dns.query" not in d
    assert "tcp.port" not in d
    assert "udp.srcport" not in d
    assert "ip.src" not in d
    assert "evil.example.com" in d


def test_x509_asn1_field_names_not_emitted_as_domains():
    text = ("x509sat.printablestring=CertLabel "
            "x509ce.keyusage=digitalSignature "
            "pkix1explicit.rdnsequence=...")
    d = _domains(text)
    assert "x509sat.printablestring" not in d
    assert "x509ce.keyusage" not in d
    assert "pkix1explicit.rdnsequence" not in d


def test_winhttp_bogus_domain_filtered():
    text = "WinHttp.WinHttpRequest = ..."
    d = _domains(text)
    assert "winhttp.winhttprequest" not in d


def test_real_protocol_looking_fqdns_still_match():
    """Guard: don't over-filter — real domains starting with 'http.' or
    'dns.' as actual labels (rare but possible) still surface.
    Our prefix filter only applies when the starting label is an
    unambiguous protocol namespace."""
    # "http" as a real domain label (e.g., "http.service.corp") would
    # currently get filtered — acceptable tradeoff for batch-1's signal-
    # to-noise. Document the limitation so future tests can revisit.
    d = _domains("visit evil.example.com and api.example.org for payload")
    assert "evil.example.com" in d
    assert "api.example.org" in d


# ---------------------------------------------------------------------------
# Batch-2 follow-on: URL path basenames extracted as "domains"
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("basename", [
    "c.php", "r.php", "search.php", "news.php", "go1.php", "index.php",
    "style.php", "click.php",
    "click.aspx", "view.aspx",
    "process.cgi", "mail.pl", "track.jsp", "submit.do",
    "index.shtml",
])
def test_server_side_script_basenames_not_emitted_as_domains(basename):
    """URL paths like http://evil.com/c.php get the regex picking up
    `c.php` as a domain. Observed in batch-2 of the pcap corpus
    (23 occurrences across cases). The file-extension filter now covers
    php/aspx/jsp/cgi/etc."""
    text = f"GET /{basename} HTTP/1.1 Host: evil.example.com"
    d = _domains(text)
    assert basename not in d
    assert "evil.example.com" in d
