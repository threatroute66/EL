"""CapabilityAccessManager ConsentStore parser.

Closes the gap-doc Windows-artifact deferred row "CapabilityAccess —
SOFTWARE\\...\\CapabilityAccessManager\\ConsentStore — app permissions
audit" (line 105 / shortlist line 544).

Tests focus on the FILETIME decoder and the high-interest set lookup.
The full parser requires regipy + a real registry hive fixture; those
are exercised by the existing test_bam_dam.py-style integration tests
on real images.
"""
from el.skills import capability_access as ca


def test_filetime_zero_returns_empty():
    assert ca._filetime_to_utc(0) == ""
    assert ca._filetime_to_utc(None) == ""
    assert ca._filetime_to_utc(b"") == ""


def test_filetime_known_value():
    """Anchor the decoder against a known FILETIME → ISO8601 mapping.
    132495840000000000 → 2020-11-11T16:00:00 UTC (verified via
    Python's own datetime arithmetic from the 1601 epoch)."""
    assert ca._filetime_to_utc(132495840000000000).startswith("2020-11-11")


def test_filetime_buffer_form():
    """When regipy hands us the raw 8-byte buffer rather than an int
    (REG_BINARY values), we still decode."""
    val = 132495840000000000
    buf = val.to_bytes(8, "little")
    assert ca._filetime_to_utc(buf).startswith("2020-11-11")


def test_high_interest_set_covers_canonical_capabilities():
    for name in ("webcam", "microphone", "location", "contacts"):
        assert name in ca.HIGH_INTEREST_CAPABILITIES


def test_parse_software_hive_missing_file():
    """Real-world: hive path doesn't exist or regipy isn't installed →
    return empty rather than crash."""
    out = ca.parse_software_hive("/nonexistent/SOFTWARE")
    assert out == []


def test_capability_use_dataclass_fields():
    u = ca.CapabilityUse(
        capability="webcam", app="microsoft.windowscamera_8wekyb3d8bbwe",
        last_used_start_utc="2021-01-01T00:00:00+00:00",
        last_used_stop_utc="",
        in_use_at_acquisition=True,
    )
    assert u.in_use_at_acquisition
    assert u.last_used_stop_utc == ""
