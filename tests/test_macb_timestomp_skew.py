"""MACB timestomp-skew detector — regression on real anti-forensics data.

Background: Andrew Rathbun's Anti-Forensics-VHDX reference image
demonstrates the plausible-timestomping pattern (B-time set to a past
date while M/A/C are the real "now"). Our existing
SYSTEM_BINARY_ZERO_TIMESTAMPS detector only fires on the degenerate
case where all four MACB are zero — the jynxora M57 signature. Every
real anti-forensic tool (TimestompPro, SetMACE, PowerShell
`[DateTime]`) sets plausible timestamps, which this detector catches.

Fixture rows below are copied verbatim from the `fls` bodyfile we
produced when investigating `anti-forensics.vhdx` — so the test
doesn't depend on the image being present on disk.
"""
from el.skills.disk_anomaly import _scan_bodyfile_rowwise


# Real rows from /opt/EL/cases/anti-forensics-vhdx/analysis/disk_forensicator/fls_o128.txt
# Columns: 0|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
_RATHBUN_TIMESTOMPED = (
    "0|/This file was created on Computer A, copied to VHDX, then "
    "timestomped.txt|51-128-1|r/rrwxrwxrwx|0|0|323|1607871219|"
    "1607870412|1607870412|1481639605"
    # B=2016-12-13, M=2020-12-13 → 4-year skew (1461 days)
)
_RATHBUN_TIMESTOMPED_TWO = (
    "0|/This file was created on Computer A, timestomped, then copied "
    "to VHDX.txt|47-128-1|r/rrwxrwxrwx|0|0|321|1607871219|1607870411|"
    "1607870411|1544711605"
    # B=2018-12-13, M=2020-12-13 → ~2-year skew (728 days)
)
# Same image, not timestomped — real-shape control row.
_RATHBUN_NORMAL = (
    "0|/This file was created on Computer A and copied to VHDX.docx|"
    "45-128-3|r/rrwxrwxrwx|0|0|11819|1607871219|1607869726|1607869736|"
    "1607869663"
)


def test_timestomp_skew_fires_on_rathbun_timestomped_file():
    hits = _scan_bodyfile_rowwise(_RATHBUN_TIMESTOMPED)
    ids = [h.pattern_id for h in hits]
    assert "MACB_TIMESTOMP_SKEW" in ids, (
        f"expected MACB_TIMESTOMP_SKEW, got {ids}"
    )
    hit = next(h for h in hits if h.pattern_id == "MACB_TIMESTOMP_SKEW")
    assert any("timestomped" in m for m in hit.matches)
    assert any("skew" in m for m in hit.matches)
    # ATT&CK attribution must be T1070.006
    tids = [tid for tid, _ in hit.attack_techniques]
    assert "T1070.006" in tids


def test_timestomp_skew_fires_on_both_rathbun_timestomped_rows():
    text = _RATHBUN_TIMESTOMPED + "\n" + _RATHBUN_TIMESTOMPED_TWO
    hits = _scan_bodyfile_rowwise(text)
    hit = next(h for h in hits if h.pattern_id == "MACB_TIMESTOMP_SKEW")
    assert len(hit.matches) == 2


def test_normal_file_does_not_fire_skew():
    # B ≤ M with only seconds of spread — the expected shape for a
    # legitimately created-then-edited file. Must NOT trip the detector.
    hits = _scan_bodyfile_rowwise(_RATHBUN_NORMAL)
    assert not any(h.pattern_id == "MACB_TIMESTOMP_SKEW" for h in hits)


def test_skew_floor_is_seven_days():
    """A 6-day skew must NOT fire; 8-day skew must."""
    # B = 0, M = 6 days → under floor
    under = "0|/tmp/a.txt|1-128-1|r/r|0|0|100|1|518400|518400|1"
    # 8-day skew → over floor (B = 0, M = 691200 = 8 days)
    over = "0|/tmp/b.txt|2-128-1|r/r|0|0|100|1|691200|691200|1"
    assert not any(
        h.pattern_id == "MACB_TIMESTOMP_SKEW"
        for h in _scan_bodyfile_rowwise(under)
    )
    assert any(
        h.pattern_id == "MACB_TIMESTOMP_SKEW"
        for h in _scan_bodyfile_rowwise(over)
    )


def test_skew_does_not_fire_on_file_name_attribute_rows():
    # NTFS $FILE_NAME attribute rows often repeat timestamps — they're
    # not $DATA streams and must not be flagged.
    fname = (
        "0|/stomped.txt ($FILE_NAME)|51-48-2|r/r|0|0|212|1607870296|"
        "1607870296|1607870296|1481639605"
    )
    hits = _scan_bodyfile_rowwise(fname)
    assert not any(h.pattern_id == "MACB_TIMESTOMP_SKEW" for h in hits)


def test_skew_does_not_fire_on_directory_rows():
    # Directories have their own timestamp semantics — skip.
    d = (
        "0|/olddir|10-144-2|d/drwxrwxrwx|0|0|0|1607870000|1607870000|"
        "1607870000|100000"
    )
    hits = _scan_bodyfile_rowwise(d)
    assert not any(h.pattern_id == "MACB_TIMESTOMP_SKEW" for h in hits)


def test_skew_requires_all_timestamps_nonzero():
    # We already have SYSTEM_BINARY_ZERO_TIMESTAMPS for the all-zero
    # case. The skew detector must not overlap — zero-timestamp rows
    # should not also fire as skew (one signal, one finding).
    zero = "0|/WINDOWS/system32/a.dll|1-128-1|r/r|0|0|100|0|0|0|0"
    hits = _scan_bodyfile_rowwise(zero)
    assert not any(h.pattern_id == "MACB_TIMESTOMP_SKEW" for h in hits)
