"""Smoke tests for the newly added skills — verify they import and
expose the expected top-level callables. Actual end-to-end tests
against real samples will come when each is wired into an agent."""
import pytest


def test_bulk_extractor_importable():
    from el.skills import bulk_extractor as be
    assert hasattr(be, "scan")
    assert hasattr(be, "BulkRun")


def test_capa_importable():
    from el.skills import capa
    assert hasattr(capa, "analyze")
    assert hasattr(capa, "CapaResult")


def test_hayabusa_importable():
    from el.skills import hayabusa
    assert hasattr(hayabusa, "csv_timeline")
    assert hasattr(hayabusa, "HayabusaRun")


def test_tshark_importable():
    from el.skills import network_extra as nx
    assert hasattr(nx, "extract_http_tls")
    assert hasattr(nx, "replay_pcap")
    assert hasattr(nx, "TsharkExtract")
    assert hasattr(nx, "SuricataRun")


def test_file_carve_importable():
    from el.skills import file_carve
    assert hasattr(file_carve, "foremost")
    assert hasattr(file_carve, "CarveRun")


def test_hashing_importable():
    from el.skills import hashing
    assert hasattr(hashing, "hashdeep_one")
    assert hasattr(hashing, "ssdeep_one")
    assert hasattr(hashing, "ssdeep_compare")


def test_exiftool_importable():
    from el.skills import exiftool
    assert hasattr(exiftool, "metadata")
    assert hasattr(exiftool, "metadata_dir")


def test_floss_importable():
    from el.skills import floss
    assert hasattr(floss, "analyze")
    assert hasattr(floss, "FlossResult")


def test_doctor_reports_new_tools_present():
    """All newly installed tools should show up as 'available' in the
    tool survey."""
    from el.tooling import survey
    names = {s.name: s.available for s in survey()}
    for tool in ("tshark", "suricata", "foremost", "ssdeep", "hashdeep",
                 "exiftool", "hayabusa", "chainsaw", "capa", "floss",
                 "bulk_extractor"):
        assert tool in names, f"{tool} not in survey()"
        assert names[tool], f"{tool} probed but marked unavailable"
