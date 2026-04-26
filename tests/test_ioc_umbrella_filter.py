"""IOC extractor's opt-in Umbrella top-1M noise filter.

Wires el/skills/umbrella_allowlist into el/skills/ioc_extract via
the ``apply_umbrella_filter`` helper — long-tail-only domain (and
URL) extraction without modifying the default extract() behaviour.
"""
from pathlib import Path

import pytest

from el.skills import ioc_extract as ie
from el.skills import umbrella_allowlist as ua


@pytest.fixture(autouse=True)
def _staged_allowlist(tmp_path, monkeypatch):
    """Stage a small in-memory allowlist for every test in this file
    so we don't depend on a real Umbrella CSV."""
    csv = tmp_path / "umbrella.csv"
    csv.write_text(
        "1,google.com\n"
        "2,microsoft.com\n"
        "3,facebook.com\n"
        "4,akamai.net\n"
    )
    monkeypatch.setenv("EL_UMBRELLA_TOP1M", str(csv))
    monkeypatch.setattr(ua, "_cache", None)
    yield
    monkeypatch.setattr(ua, "_cache", None)


def test_filters_popular_domains_keeps_long_tail():
    iocs = {"domain": {"google.com", "evil.example", "microsoft.com",
                        "rare.company"}}
    out = ie.apply_umbrella_filter(iocs)
    assert out["domain"] == {"evil.example", "rare.company"}


def test_filters_url_by_host():
    iocs = {"url": {"https://google.com/search?q=x",
                     "http://evil.example/payload",
                     "https://microsoft.com/update"}}
    out = ie.apply_umbrella_filter(iocs)
    assert out["url"] == {"http://evil.example/payload"}


def test_other_ioc_classes_passthrough():
    iocs = {
        "ipv4": {"203.0.113.5"},
        "md5": {"ab" * 16},
        "domain": {"google.com", "evil.example"},
    }
    out = ie.apply_umbrella_filter(iocs)
    assert out["ipv4"] == {"203.0.113.5"}
    assert out["md5"] == {"ab" * 16}
    assert out["domain"] == {"evil.example"}


def test_threshold_kwarg(monkeypatch, tmp_path):
    csv = tmp_path / "u.csv"
    csv.write_text("1,google.com\n50000,edge.example\n80000,common.example\n")
    monkeypatch.setenv("EL_UMBRELLA_TOP1M", str(csv))
    monkeypatch.setattr(ua, "_cache", None)
    iocs = {"domain": {"google.com", "edge.example",
                        "common.example", "evil.example"}}
    # Default 50_000 → google + edge filtered, common kept (rank 80k)
    out = ie.apply_umbrella_filter(iocs)
    assert out["domain"] == {"common.example", "evil.example"}
    # Tighter 1_000 → only google filtered
    out2 = ie.apply_umbrella_filter(iocs, threshold=1_000)
    assert out2["domain"] == {"edge.example", "common.example",
                                "evil.example"}


def test_noop_when_allowlist_missing(monkeypatch, tmp_path):
    """No CSV staged → original IOCs returned unchanged."""
    monkeypatch.setenv("EL_UMBRELLA_TOP1M",
                        str(tmp_path / "absent.csv"))
    monkeypatch.setattr(ua, "_DEFAULT_PATH", tmp_path / "also-absent.csv")
    monkeypatch.setattr(ua, "_cache", None)
    iocs = {"domain": {"google.com", "evil.example"}}
    out = ie.apply_umbrella_filter(iocs)
    assert out["domain"] == {"google.com", "evil.example"}


def test_does_not_mutate_input():
    iocs = {"domain": {"google.com", "evil.example"}}
    snapshot = set(iocs["domain"])
    _ = ie.apply_umbrella_filter(iocs)
    assert iocs["domain"] == snapshot


def test_preserves_container_type():
    """Lists in → lists out; sets in → sets out."""
    iocs_set = {"domain": {"google.com", "evil.example"}}
    out_set = ie.apply_umbrella_filter(iocs_set)
    assert isinstance(out_set["domain"], set)
    iocs_list = {"domain": ["google.com", "evil.example"]}
    out_list = ie.apply_umbrella_filter(iocs_list)
    assert isinstance(out_list["domain"], list)
