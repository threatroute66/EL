from el.skills.ioc_extract import extract, refang


def test_refang_normalizes_common_defangs():
    assert refang("evil[.]com") == "evil.com"
    assert refang("hxxps://1.2.3[.]4/payload") == "https://1.2.3.4/payload"
    assert refang("user[at]badco[.]io") == "user@badco.io"


def test_extracts_public_ipv4_and_drops_rfc1918():
    s = "callback to 8.8.8.8 and 192.168.1.1 and 203.0.113.7 and 10.0.0.5"
    out = extract(s)
    assert "8.8.8.8" in out["ipv4"]
    assert "203.0.113.7" in out["ipv4"]
    assert "192.168.1.1" not in out["ipv4"]
    assert "10.0.0.5" not in out["ipv4"]


def test_extracts_hashes_and_separates_lengths():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    s = f"hashes: {md5} {sha1} {sha256}"
    out = extract(s)
    assert md5 in out["md5"]
    assert sha1 in out["sha1"]
    assert sha256 in out["sha256"]


def test_drops_microsoft_noise_domains():
    s = "GET schemas.microsoft.com and evil.example.com"
    out = extract(s)
    assert "evil.example.com" in out["domain"]
    assert "schemas.microsoft.com" not in out["domain"]


def test_registry_keys_extracted():
    s = "modified HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    out = extract(s)
    assert any("HKLM" in k for k in out["regkey"])


def test_extracts_bitcoin_addresses_legacy_and_bech32():
    """BelkaCTF Kidnapper had the dealer's wallet addresses embedded in
    user notes and mbox attachments. Before this regex was added, those
    IOCs went completely uncaught."""
    legacy_p2pkh = "1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY"
    legacy_p2sh = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    bech32 = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    s = f"send to {legacy_p2pkh} or {legacy_p2sh} or {bech32}"
    out = extract(s)
    assert legacy_p2pkh in out["btc"]
    assert legacy_p2sh in out["btc"]
    assert bech32 in out["btc"]


def test_btc_legacy_noise_filter_rejects_non_mixed_strings():
    """Base58 regex alone matches random tokens. Require mixed-alphanumeric
    body (digit + upper + lower) to suppress obvious false positives."""
    # All-lowercase + digits — base58-valid but not plausibly a real address
    assert "1aaabbbcccdddee111122223333444455" not in extract(
        "noise 1aaabbbcccdddee111122223333444455 more").get("btc", set())
    # No digits — reject
    assert extract("1ABCDEFGHIJKLMNOPqrstuvwxyzABCDe").get("btc") == set()
    # Natural prose must not yield false positives
    assert extract(
        "The quick brown fox jumps over the lazy dog, eight times a day."
    ).get("btc") == set()
