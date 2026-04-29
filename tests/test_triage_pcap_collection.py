"""Phase 7 contract tests for the directory-of-pcaps triage rule.

Locks in:
  * A directory containing ≥2 .pcap files is detected and routed to
    evidence_kind="pcap-collection".
  * mergecap is invoked; ctx.input_path is rewritten to the merged
    file so NetworkAnalystAgent (single-pcap input) can run unchanged.
  * KIND_TO_AGENT maps pcap-collection → NetworkAnalystAgent.
  * Single-pcap-in-a-dir does NOT trigger the rule (single files are
    handled by the magic-byte path on intake).
  * mergecap failure surfaces as `insufficient` rather than crashing.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.triage import TriageAgent


def _make_pcap_dir(tmp_path: Path, count: int) -> Path:
    """Build a directory with `count` files named *.pcap. Their
    contents are placeholder bytes — mergecap is stubbed in the
    tests so real pcap parsing isn't needed."""
    d = tmp_path / "captures"
    d.mkdir()
    for i in range(count):
        (d / f"net-{i:03d}.pcap").write_bytes(b"\xd4\xc3\xb2\xa1placeholder\n")
    return d


def _ctx(case_dir: Path, input_path: Path) -> AgentContext:
    return AgentContext(
        case_id="trc-test", case_dir=case_dir,
        input_path=input_path, manifest={"input_path": str(input_path)},
    )


@pytest.fixture
def stub_mergecap(monkeypatch):
    """Stub subprocess.run so mergecap doesn't actually need a real
    pcap parser — it just creates the target file and returns rc=0."""
    real_run = subprocess.run

    def fake_run(cmd, *args, **kwargs):
        if cmd and cmd[0] == "mergecap":
            # mergecap -w <out> <inputs...>
            try:
                idx = cmd.index("-w")
                out = Path(cmd[idx + 1])
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(b"\xd4\xc3\xb2\xa1merged\n")
            except Exception:
                pass

            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", fake_run)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_directory_of_two_pcaps_detected(tmp_path, stub_mergecap):
    pcaps = _make_pcap_dir(tmp_path, count=2)
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "triage").mkdir(parents=True)
    ctx = _ctx(case_dir, pcaps)
    findings = TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "pcap-collection"
    assert ctx.shared.get("merged_pcap_path")
    # The high-confidence detection finding is present
    assert any(
        f.confidence == "high"
        and "multi-pcap capture series" in (f.claim or "")
        for f in findings
    )


def test_directory_of_fifty_pcaps_detected(tmp_path, stub_mergecap):
    """The actual M57 case shape — 50 pcap files."""
    pcaps = _make_pcap_dir(tmp_path, count=50)
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "triage").mkdir(parents=True)
    ctx = _ctx(case_dir, pcaps)
    TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "pcap-collection"


def test_single_pcap_in_dir_not_detected(tmp_path, stub_mergecap):
    """A directory with only one pcap shouldn't fire — single files
    flow through the magic-byte detector at intake. The threshold of
    ≥2 avoids false positives on directories that happen to contain
    a stray pcap alongside other content."""
    pcaps = _make_pcap_dir(tmp_path, count=1)
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "triage").mkdir(parents=True)
    ctx = _ctx(case_dir, pcaps)
    TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") != "pcap-collection"


# ---------------------------------------------------------------------------
# Input path rewrite
# ---------------------------------------------------------------------------

def test_input_path_rewritten_to_merged_file(tmp_path, stub_mergecap):
    """After detection the ctx.input_path must point at the merged
    pcap so NetworkAnalystAgent (single-pcap input) sees a normal
    file, not the original directory."""
    pcaps = _make_pcap_dir(tmp_path, count=3)
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "triage").mkdir(parents=True)
    ctx = _ctx(case_dir, pcaps)
    TriageAgent().run(ctx)
    assert ctx.input_path != pcaps  # not the dir
    assert ctx.input_path.is_file()
    assert ctx.input_path.suffix == ".pcap"
    assert ctx.input_path.name == "merged.pcap"


def test_pcap_source_files_recorded_in_shared(tmp_path, stub_mergecap):
    pcaps = _make_pcap_dir(tmp_path, count=4)
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "triage").mkdir(parents=True)
    ctx = _ctx(case_dir, pcaps)
    TriageAgent().run(ctx)
    sources = ctx.shared.get("pcap_source_files")
    assert sources and len(sources) == 4
    # Sorted for determinism
    assert sources == sorted(sources)


# ---------------------------------------------------------------------------
# KIND_TO_AGENT routing
# ---------------------------------------------------------------------------

def test_kind_to_agent_routes_pcap_collection_to_network_analyst():
    from el.orchestrator.coordinator import KIND_TO_AGENT
    from el.agents.network_analyst import NetworkAnalystAgent
    assert KIND_TO_AGENT.get("pcap-collection") is NetworkAnalystAgent


# ---------------------------------------------------------------------------
# mergecap failure modes
# ---------------------------------------------------------------------------

def test_mergecap_failure_yields_insufficient(tmp_path, monkeypatch):
    pcaps = _make_pcap_dir(tmp_path, count=3)
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "triage").mkdir(parents=True)

    real_run = subprocess.run

    def fail_run(cmd, *args, **kwargs):
        if cmd and cmd[0] == "mergecap":
            class _R:
                returncode = 1
                stdout = ""
                stderr = "test stub: simulated mergecap failure"
            return _R()
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", fail_run)
    ctx = _ctx(case_dir, pcaps)
    findings = TriageAgent().run(ctx)
    # On failure the kind falls back to directory-unclassified rather
    # than mis-routing to network analyst with no pcap to read.
    assert ctx.shared.get("evidence_kind") == "directory-unclassified"
    assert any(
        f.confidence == "insufficient"
        and "mergecap failed" in (f.claim or "")
        for f in findings
    )


def test_mergecap_missing_yields_insufficient(tmp_path, monkeypatch):
    """When mergecap is not on the host (CI without wireshark), the
    rule degrades gracefully rather than crashing."""
    pcaps = _make_pcap_dir(tmp_path, count=3)
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "triage").mkdir(parents=True)

    real_run = subprocess.run

    def missing_run(cmd, *args, **kwargs):
        if cmd and cmd[0] == "mergecap":
            raise FileNotFoundError("mergecap")
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", missing_run)
    ctx = _ctx(case_dir, pcaps)
    findings = TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "directory-unclassified"
    assert any(
        f.confidence == "insufficient"
        and "mergecap unavailable" in (f.claim or "")
        for f in findings
    )
