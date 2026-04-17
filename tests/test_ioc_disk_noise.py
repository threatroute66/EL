"""Regression tests captured from the Jimmy Wilson E01 disk image:
fls bodyfile + mactime CSV produced version-number IPv4 false positives
(1.0.0.0, 3.4.2.6 = FTK Imager version) and .eml filenames mistaken
for FQDNs."""
from el.skills.ioc_extract import extract


def test_xyz_zero_zero_zero_version_strings_not_emitted_as_ipv4():
    """Drop only the clearest X.0.0.0 version-banner pattern (e.g. "Software
    1.0.0.0"). We deliberately do NOT filter X.Y.0.0 (e.g. "Windows 6.1.0.0")
    or X.Y.Z.W with all small octets (e.g. "FTK 3.4.2.6") — those filters
    would drop real public IPs (e.g. 1.2.3.4 is APNIC, 8.8.8.8 is Google).
    Some version-string IPv4 false positives in the catalog are acceptable;
    missing a real IP is not."""
    out = extract("Software 1.0.0.0 and FTK 3.0.0.0 and 8.0.0.0")
    for v in ("1.0.0.0", "3.0.0.0", "8.0.0.0"):
        assert v not in out["ipv4"]


def test_real_public_ipv4_still_extracted():
    s = "callbacks to 8.8.8.8 and 203.0.113.7 and 198.51.100.42"
    out = extract(s)
    for v in ("8.8.8.8", "203.0.113.7", "198.51.100.42"):
        assert v in out["ipv4"]


def test_eml_filenames_not_emitted_as_domains():
    s = ("found 00294823-00000006.eml and 0149685f-00000002.eml in "
         "Outlook export plus user.msg")
    out = extract(s)
    for f in ("00294823-00000006.eml", "0149685f-00000002.eml", "user.msg"):
        assert f not in out["domain"]


def test_hashes_are_case_folded_and_deduplicated():
    md5 = "48b76449f3d5fefa1133aa805e420f0fca643651".upper()  # actually SHA1 length, force md5 to 32
    md5_lower = "48b76449f3d5fefa1133aa805e4"  # 32 chars
    md5_upper = md5_lower.upper()
    s = f"hash {md5_lower} and again {md5_upper}"
    out = extract(s)
    sha1_lower = "48b76449f3d5fefa1133aa805e420f0fca643651"
    sha1_upper = sha1_lower.upper()
    s2 = f"sha1 {sha1_lower} and again {sha1_upper}"
    out2 = extract(s2)
    assert len(out2["sha1"]) == 1, f"expected 1 SHA1 after case-fold; got {out2['sha1']}"
