"""Regression test from a real FTK Imager E01 (jimmy-01 case): the
EnCase magic is EVF\\x09\\x0d\\x0a\\xff\\x00, not EWF (EWF is the format
NAME, the bytes start with EVF). Triage must detect this and route to
DiskForensicatorAgent, not fall through to MemoryForensicatorAgent."""
from pathlib import Path

import pytest

from el.evidence import intake as intake_mod
from el.orchestrator.coordinator import Coordinator
from el.orchestrator.states import State


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


def test_evf_magic_routes_to_disk_forensicator(isolated, monkeypatch):
    """Verify routing only — DiskForensicator is selected. The fake 16-byte
    E01 isn't ewfmount-able, so we monkeypatch ewfmount to no-op so the
    test doesn't actually need root or a real EWF. This isolates the
    routing-decision contract from the mount-and-walk plumbing."""
    e01 = isolated / "test.E01"
    e01.write_bytes(b"EVF\x09\x0d\x0a\xff\x00\x01\x01\x00\x00\x00\x68\x65\x61")

    from el.skills import sleuthkit as sk
    def _stub_ewfmount(image, mount_point, timeout=60):
        raise sk.SleuthkitError("stub: ewfmount not invoked in unit tests")
    monkeypatch.setattr(sk, "ewfmount", _stub_ewfmount)

    result = Coordinator().investigate(e01, case_id="t-evf")
    assert result.investigator == "DiskForensicatorAgent", \
        f"E01 routed to {result.investigator!r} instead of DiskForensicator"
    assert result.final_state == State.DONE


def test_ewf_string_no_longer_matches():
    """Sanity: the old buggy 'EWF' prefix must NOT match by accident."""
    from el.agents.triage import MAGIC_HINTS
    fake = b"EWF\x09\x0d\x0a\xff\x00\x00\x00"
    matched = [label for sig, label in MAGIC_HINTS.items() if fake.startswith(sig)]
    assert matched == [], f"unexpected match on EWF prefix: {matched}"
