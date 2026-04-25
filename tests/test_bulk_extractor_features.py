"""bulk_extractor output ingest — skill, triage, agent dispatch.

Driver: QNAP case 21APR_245. After bulk_extractor scanned the 1.74 TB
unparseable thin-LV (`/dev/loop20`), 20 MB of feature output landed in
/opt/EL/scratch/qnap/be_out — but `el investigate` against that dir
produced 7 skeleton findings, all `insufficient`, because no triage
kind matched. These tests lock in:

- The skill recognises a bulk_extractor output dir from the canonical
  feature filenames OR a `report.xml` manifest.
- `summarise()` parses histograms + counts per feature and per carved
  bucket, distinguishing populated from empty scanners.
- Triage routes such directories to evidence_kind=bulk-extractor-output.
- KIND_TO_AGENT dispatches to BulkExtractorFeaturesAgent.
- The agent emits one Finding per populated feature + carved bucket,
  with confidence keyed to forensic value (email/aes_keys/evtx-carved
  → high; domain/url/ip → medium).
"""
import pytest
from pathlib import Path

from el.agents.base import AgentContext
from el.agents.bulk_extractor_features_agent import (
    BulkExtractorFeaturesAgent,
)
from el.agents.triage import TriageAgent
from el.orchestrator.coordinator import KIND_TO_AGENT
from el.skills import bulk_extractor_features as bef


# Realistic bulk_extractor histogram fragments — shape exactly matches
# what we got from /dev/loop20 (5 banner lines + n=<count>\t<value>).
_HIST_HEADER = (
    "# BANNER FILE NOT PROVIDED (-b option)\n"
    "# BULK_EXTRACTOR-Version: 1.6.1\n"
    "# Feature-Recorder: domain\n"
    "# Filename: /dev/loop20\n"
    "# Histogram-File-Version: 1.1\n"
)


def _write_be_dir(tmp_path: Path, *,
                   email_lines=None,
                   domain_lines=None,
                   url_lines=None,
                   evtx_carved=False,
                   ccn_lines=None,
                   include_report_xml=False) -> Path:
    """Materialise a directory with the shape bulk_extractor would
    have written. Each *_lines arg is a list of (count, value) tuples
    that get rendered into a histogram file; an empty TSV is also
    created so the parser sees the scanner ran."""
    d = tmp_path / "be_out"
    d.mkdir()
    # Empty feature TSVs (every scanner writes one even when empty)
    for name in bef.CANONICAL_FEATURE_FILES:
        (d / name).touch()

    def _write_hist(name: str, rows):
        if rows is None:
            return
        path = d / f"{name}_histogram.txt"
        with path.open("w") as f:
            f.write(_HIST_HEADER)
            for cnt, val in rows:
                f.write(f"n={cnt}\t{val}\n")

    _write_hist("domain", domain_lines)
    _write_hist("email", email_lines)
    _write_hist("url", url_lines)
    _write_hist("ccn", ccn_lines)

    if evtx_carved:
        (d / "evtx_carved.txt").write_text(
            "# Feature-Recorder: evtx_carved\n"
            "1234\t<carved evtx record bytes>\t...\n"
        )
        (d / "evtx_carved").mkdir()
        (d / "evtx_carved" / "evtx_orphan_record_001").write_text("...")

    if include_report_xml:
        (d / "report.xml").write_text("<dfxml>…</dfxml>")
    return d


# --- skill: is_bulk_extractor_output -------------------------------------

def test_is_be_recognises_dir_with_report_xml(tmp_path):
    d = tmp_path / "be"
    d.mkdir()
    (d / "report.xml").write_text("<dfxml/>")
    assert bef.is_bulk_extractor_output(d)


def test_is_be_recognises_dir_with_three_canonical_files(tmp_path):
    d = tmp_path / "be"
    d.mkdir()
    for n in ("domain.txt", "email.txt", "url.txt"):
        (d / n).touch()
    assert bef.is_bulk_extractor_output(d)


def test_is_be_rejects_dir_with_only_two_files(tmp_path):
    d = tmp_path / "be"
    d.mkdir()
    (d / "domain.txt").touch()
    (d / "email.txt").touch()
    assert not bef.is_bulk_extractor_output(d)


def test_is_be_rejects_random_dir(tmp_path):
    d = tmp_path / "evidence"
    d.mkdir()
    (d / "foo.json").touch()
    assert not bef.is_bulk_extractor_output(d)


# --- skill: summarise() ---------------------------------------------------

def test_summarise_parses_histograms(tmp_path):
    d = _write_be_dir(
        tmp_path,
        email_lines=[(3, "alice@example.com"), (1, "bob@example.com")],
        domain_lines=[(189, "172.21.30.11"), (53, "ns.adobe.com"),
                       (11, "msab.com")],
    )
    s = bef.summarise(d)
    assert s.features["email"].unique_values == 2
    assert s.features["email"].top[0] == (3, "alice@example.com")
    assert s.features["domain"].unique_values == 3
    assert s.features["domain"].top[0] == (189, "172.21.30.11")


def test_summarise_distinguishes_empty_scanners(tmp_path):
    d = _write_be_dir(
        tmp_path,
        domain_lines=[(5, "example.com")],
    )
    s = bef.summarise(d)
    assert s.features["domain"].has_content
    assert not s.features["aes_keys"].has_content
    assert not s.features["telephone"].has_content


def test_summarise_counts_carved_records(tmp_path):
    d = _write_be_dir(tmp_path, evtx_carved=True)
    s = bef.summarise(d)
    assert s.carved["evtx_carved"].has_content
    assert s.carved["evtx_carved"].record_count >= 1
    assert s.carved["evtx_carved"].file_count >= 1


def test_summarise_records_report_xml(tmp_path):
    d = _write_be_dir(tmp_path, include_report_xml=True)
    s = bef.summarise(d)
    assert s.report_xml is not None
    assert s.report_xml.name == "report.xml"


# --- triage routing -------------------------------------------------------

def test_triage_routes_to_bulk_extractor_output(tmp_path):
    d = _write_be_dir(
        tmp_path,
        email_lines=[(3, "x@y.com")],
        domain_lines=[(5, "a.com")],
        url_lines=[(2, "http://a.com")],
    )
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "triage").mkdir(parents=True)
    ctx = AgentContext(
        case_id="t", case_dir=case_dir, input_path=d, manifest={},
    )
    TriageAgent().run(ctx)
    assert ctx.shared["evidence_kind"] == "bulk-extractor-output"


def test_kind_to_agent_routes_to_be_features_agent():
    assert KIND_TO_AGENT.get("bulk-extractor-output") is BulkExtractorFeaturesAgent


# --- agent: emits findings keyed by feature ------------------------------

def _agent_run(tmp_path: Path, **kwargs) -> list:
    d = _write_be_dir(tmp_path, **kwargs)
    case_dir = tmp_path / "case"
    (case_dir / "analysis").mkdir(parents=True, exist_ok=True)
    ctx = AgentContext(
        case_id="t", case_dir=case_dir, input_path=d, manifest={},
    )
    return BulkExtractorFeaturesAgent().run(ctx)


def test_agent_emits_high_for_email(tmp_path):
    findings = _agent_run(
        tmp_path,
        email_lines=[(3, "support@msab.com"), (2, "info@msab.com")],
    )
    high = [f for f in findings
            if f.confidence == "high"
            and "`email`" in f.claim and "scanner ran" not in f.claim]
    assert len(high) == 1
    assert "support@msab.com" in high[0].claim
    assert "H_BEC_ACCOUNT_TAKEOVER" in high[0].hypotheses_supported


def test_agent_emits_medium_for_domain(tmp_path):
    findings = _agent_run(
        tmp_path,
        domain_lines=[(189, "172.21.30.11"), (53, "ns.adobe.com")],
    )
    med = [f for f in findings
           if f.confidence == "medium" and "`domain`" in f.claim]
    assert len(med) == 1
    assert "172.21.30.11" in med[0].claim
    assert "189" in med[0].claim


def test_agent_emits_high_for_evtx_carved(tmp_path):
    findings = _agent_run(tmp_path, evtx_carved=True)
    high = [f for f in findings
            if f.confidence == "high"
            and "`evtx_carved`" in f.claim]
    assert len(high) == 1
    assert "H_ANTI_FORENSICS" in high[0].hypotheses_supported


def test_agent_emits_insufficient_for_empty_scanners(tmp_path):
    """The empty-scanner findings exist so the ledger documents what
    was searched and produced nothing — 'I don't know' as a first-class
    output, per the EL contract."""
    findings = _agent_run(
        tmp_path,
        domain_lines=[(1, "example.com")],
    )
    empty = [f for f in findings
             if f.confidence == "insufficient"
             and "scanner ran and produced no output" in f.claim]
    # All canonical features minus 'domain' should have one each.
    assert len(empty) == len(bef.CANONICAL_FEATURE_FILES) - 1


def test_agent_handles_dir_with_only_report_xml(tmp_path):
    """report.xml-only directory still produces the manifest finding,
    nothing else."""
    d = tmp_path / "be"
    d.mkdir()
    (d / "report.xml").write_text("<dfxml/>")
    case_dir = tmp_path / "case"
    (case_dir / "analysis").mkdir(parents=True)
    ctx = AgentContext(case_id="t", case_dir=case_dir,
                        input_path=d, manifest={})
    findings = BulkExtractorFeaturesAgent().run(ctx)
    manifest_findings = [f for f in findings
                          if "report.xml" in f.claim]
    assert len(manifest_findings) == 1
