"""IOC extractor regression tests captured from a real Windows memory image
(SANS Hackathon-2026 sample). These false positives slipped through earlier
heuristics and got published into iocs.json on a real run; lock them out."""
from el.skills.ioc_extract import extract


def test_timestamps_not_matched_as_ipv6():
    s = "log entry at 03:05:13 and 21:55:32 from process 1234"
    out = extract(s)
    assert "03:05:13" not in out["ipv6"]
    assert "21:55:32" not in out["ipv6"]


def test_real_ipv6_still_matches():
    s = "remote address ::1 and fe80::1 and 2001:0db8:85a3::8a2e:0370:7334"
    out = extract(s)
    assert any("2001" in v for v in out["ipv6"])


def test_volatility_plugin_names_not_emitted_as_domains():
    s = "windows.cmdline.cmdline windows.netscan.netscan windows.svcscan.svcscan"
    out = extract(s)
    for noisy in ("windows.cmdline.cmdline", "windows.netscan.netscan",
                  "windows.svcscan.svcscan"):
        assert noisy not in out["domain"]


def test_windows_internals_filtered():
    s = "loaded ntkrnlmp.pdb and fontdrvhost.ex and diagnosticshub.standardcollector.service"
    out = extract(s)
    for n in ("ntkrnlmp.pdb", "fontdrvhost.ex",
              "diagnosticshub.standardcollector.service"):
        assert n not in out["domain"]


def test_short_numeric_xxx_fragments_dropped():
    s = "fragment 1.xxx and 2.xxx in dump"
    out = extract(s)
    assert "1.xxx" not in out["domain"]
    assert "2.xxx" not in out["domain"]


def test_real_domains_still_pass_through_after_tightening():
    s = "callbacks to evil.example.com and c2.attacker.io"
    out = extract(s)
    assert "evil.example.com" in out["domain"]
    assert "c2.attacker.io" in out["domain"]
