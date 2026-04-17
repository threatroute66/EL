from el.skills.ioc_extract import extract


def test_filenames_with_known_extensions_not_emitted_as_domains():
    s = "saw evidence.pcap and report.json and dump.raw and shell.exe and notes.txt and good.example.com"
    out = extract(s)
    domains = out["domain"]
    for bogus in ("evidence.pcap", "report.json", "dump.raw", "shell.exe", "notes.txt"):
        assert bogus not in domains, f"{bogus} should be filtered"
    assert "good.example.com" in domains


def test_short_tld_still_extracts_real_domains():
    out = extract("contact: foo@evil.io and ping evil.co")
    assert "evil.io" in out["domain"]
    assert "evil.co" in out["domain"]
