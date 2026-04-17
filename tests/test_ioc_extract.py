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
