"""Regression tests captured from nrom-01 (Stark Research Labs APT case):
the IOC extractor was emitting OpenSSL X.509 OID-name strings as 'domains'
and secp256k1/secp256r1 curve generator constants as SHA-256 IOCs."""
from el.skills.ioc_extract import extract


def test_secp256k1_generator_constants_dropped():
    s = ("attacker hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
         "and curve constant 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    out = extract(s)
    assert "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" not in out["sha256"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in out["sha256"]


def test_x509_openssl_labels_not_emitted_as_domains():
    s = "OpenSSL: d.directoryname value.bykey p.prime name.fullname plus real.example.com"
    out = extract(s)
    for noisy in ("d.directoryname", "value.bykey", "p.prime", "name.fullname"):
        assert noisy not in out["domain"]
    assert "real.example.com" in out["domain"]


def test_openssl_org_filtered():
    out = extract("References www.openssl.org and evil.example.com")
    assert "www.openssl.org" not in out["domain"]
    assert "evil.example.com" in out["domain"]
