from el.skills.yara_hunt import generate_ioc_rules


def test_generates_hash_and_string_rules(tmp_path):
    iocs = {
        "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
        "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "domain": ["evil.example.com"],
        "ipv4": ["203.0.113.7"],
        "url": ["https://attacker.io/payload.exe"],
        "email": [],
        "sha1": [],
    }
    out = tmp_path / "case.yar"
    generate_ioc_rules(iocs, out, case_id="t-123")
    txt = out.read_text()
    assert 'import "hash"' in txt
    assert "hash.md5" in txt and "d41d8cd98f00b204e9800998ecf8427e" in txt
    assert "hash.sha256" in txt
    assert "evil.example.com" in txt
    assert "203.0.113.7" in txt
    assert 'rule EL_t_123_md5_000_' in txt
    assert "ascii nocase wide" in txt


def test_skips_malformed_hashes(tmp_path):
    iocs = {"md5": ["tooshort"], "sha1": [], "sha256": [], "domain": [], "ipv4": [], "url": [], "email": []}
    out = tmp_path / "case.yar"
    generate_ioc_rules(iocs, out, case_id="t")
    assert "tooshort" not in out.read_text()


def test_string_iocs_with_quotes_skipped(tmp_path):
    iocs = {"md5": [], "sha1": [], "sha256": [], "ipv4": [], "url": [], "email": [],
            "domain": ['evil"injection.com', "good.example.com"]}
    out = tmp_path / "case.yar"
    generate_ioc_rules(iocs, out, case_id="t")
    txt = out.read_text()
    assert "good.example.com" in txt
    assert 'evil"injection' not in txt
