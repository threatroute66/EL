"""Volume Shadow Copy enumeration via libvshadow's `vshadowinfo`.

Closes the gap-doc Windows-artifact deferred row "Volume Shadow Copy
mounting via vss_carver" (line 106 / shortlist line 544). This is the
detection half — listing shadow stores and surfacing them as
Findings. Full mount-and-walk pipeline against each shadow is a
future enhancement.
"""
from el.skills import vss


_SAMPLE_OUTPUT = """\
vshadowinfo 20240504

Volume Shadow Snapshot information:
\tNumber of stores:\t2

Store: 1
\tIdentifier\t\t: a1b2c3d4-e5f6-7788-99aa-bbccddeeff00
\tShadow copy set ID\t: f1f2f3f4-f5f6-f7f8-f9fa-fbfcfdfeff00
\tCreation time\t\t: Apr 25, 2026 12:34:56.789012 UTC
\tVolume size\t\t: 80 GiB (85899345920 bytes)

Store: 2
\tIdentifier\t\t: 11112222-3333-4444-5555-666677778888
\tShadow copy set ID\t: 99998888-7777-6666-5555-444433332222
\tCreation time\t\t: Apr 24, 2026 03:00:00.000000 UTC
\tVolume size\t\t: 80 GiB (85899345920 bytes)
"""


def test_parse_two_stores_extracts_metadata():
    stores = vss._parse(_SAMPLE_OUTPUT)
    assert len(stores) == 2
    s1, s2 = stores
    assert s1.index == 1
    assert s1.identifier == "a1b2c3d4-e5f6-7788-99aa-bbccddeeff00"
    assert "Apr 25, 2026" in s1.creation_time_utc
    assert s1.volume_size_bytes == 85899345920
    assert s2.index == 2
    assert s2.identifier == "11112222-3333-4444-5555-666677778888"


def test_parse_empty_output_returns_empty_list():
    assert vss._parse("") == []
    assert vss._parse("vshadowinfo 20240504\n\nNo Volume Shadow Snapshots Found\n") == []


def test_parse_preserves_raw_block_per_store():
    stores = vss._parse(_SAMPLE_OUTPUT)
    assert "Store: 1" in stores[0].raw_block
    assert "85899345920" in stores[0].raw_block
    # No leakage between stores
    assert "11112222" not in stores[0].raw_block


def test_list_shadows_handles_missing_binary(monkeypatch):
    monkeypatch.setattr(vss.shutil, "which", lambda _: None)
    try:
        vss.list_shadows("/nonexistent")
    except vss.VssError as e:
        assert "vshadowinfo" in str(e)
    else:
        raise AssertionError("expected VssError when vshadowinfo absent")
