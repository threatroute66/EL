"""Tier-1 web view tests — deterministic projection of Findings + ACH + IOCs."""
from pathlib import Path

import pytest
from pydantic import BaseModel

from el.reporting.html import render_html
from el.schemas.finding import EvidenceItem, Finding, RedReview


def _mk_finding(**kw) -> Finding:
    defaults = dict(
        case_id="t-html",
        agent="test_agent",
        claim="sample claim",
        confidence="high",
        evidence=[EvidenceItem(tool="t", version="0", command="echo",
                                output_sha256="0" * 64,
                                output_path="/tmp/x")],
        hypotheses_supported=[],
        hypotheses_refuted=[],
    )
    defaults.update(kw)
    return Finding(**defaults)


class _FakeRank(BaseModel):
    hyp_id: str
    name: str
    score: int
    supporting_findings: list = []
    refuting_findings: list = []


def test_render_empty_case(tmp_path):
    out = render_html(tmp_path, "empty-case", {"case_id": "empty-case"},
                      findings=[])
    assert out.exists()
    text = out.read_text()
    assert "empty-case" in text
    assert "<!DOCTYPE html>" in text
    assert "No IOCs extracted" in text
    assert "No hypotheses ranked" in text
    assert "<script" in text


def test_render_with_findings(tmp_path):
    findings = [
        _mk_finding(confidence="high", claim="rdp inbound anomaly"),
        _mk_finding(confidence="medium", claim="scheduled task oddity",
                    agent="windows_artifact"),
        _mk_finding(confidence="low", claim="benign background noise"),
        _mk_finding(confidence="insufficient",
                    claim="tool failed — insufficient evidence",
                    evidence=[]),
    ]
    ach = [_FakeRank(hyp_id="H_APT_ESPIONAGE", name="APT espionage", score=7),
           _FakeRank(hyp_id="H_BENIGN_NO_INCIDENT", name="benign", score=0)]
    iocs = {"ipv4": ["10.0.0.1", "192.168.1.2"],
            "domain": ["evil.example.com"]}
    techniques = {"T1021.001": {"name": "Remote Desktop Protocol",
                                 "evidence_finding_ids": ["x", "y"]}}

    out = render_html(tmp_path, "t-rich", {"case_id": "t-rich"},
                      findings=findings, ach_ranking=ach,
                      iocs=iocs, techniques=techniques)
    text = out.read_text()

    # Executive summary counts
    assert 'class="summary-card high"' in text
    # ACH ranking server-rendered (stable for deep-linking + SEO-free ability)
    assert "APT espionage" in text
    assert "H_APT_ESPIONAGE" in text
    # Finding claims embedded (via JSON data script) — the renderer inlines
    assert "rdp inbound anomaly" in text
    assert "scheduled task oddity" in text
    # IOC table
    assert "10.0.0.1" in text
    assert "evil.example.com" in text
    # ATT&CK link
    assert "attack.mitre.org/techniques/T1021/001" in text
    # Filter chips
    assert 'data-group="conf"' in text
    assert 'data-group="agent"' in text
    assert 'data-val="windows_artifact"' in text


def test_render_embeds_data_as_json_script(tmp_path):
    """The HTML must be self-contained: all finding data in a single
    <script type=application/json> so the page works from file://."""
    findings = [_mk_finding(claim="exfil over https")]
    out = render_html(tmp_path, "t-data", {"case_id": "t-data"},
                      findings=findings)
    text = out.read_text()
    import re
    m = re.search(r'<script id="data" type="application/json">(.+?)</script>',
                   text, re.DOTALL)
    assert m, "data script block missing"
    import json
    data = json.loads(m.group(1))
    assert data["case_id"] == "t-data"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["claim"] == "exfil over https"
    # Tier 2 addition: graph data is embedded (empty for this fixture)
    assert "graph" in data
    assert "nodes" in data["graph"]


def test_render_embeds_graph_section(tmp_path):
    """Tier 2: case.html must include the graph section + SVG pane hook."""
    out = render_html(tmp_path, "t-graph", {"case_id": "t-graph"},
                      findings=[_mk_finding()])
    text = out.read_text()
    assert 'id="graph"' in text
    assert 'id="graph-pane"' in text
    assert 'href="#graph"' in text


def test_render_tier3_heatmap_groups_by_tactic(tmp_path):
    """Tier 3: ATT&CK heatmap buckets techniques by primary tactic."""
    techniques = {
        "T1003.001": {"name": "LSASS Memory",
                       "evidence_finding_ids": ["a", "b", "c"]},
        "T1059.001": {"name": "PowerShell",
                       "evidence_finding_ids": ["x"]},
        "T1486":     {"name": "Data Encrypted for Impact",
                       "evidence_finding_ids": ["y", "z", "w", "v", "u"]},
    }
    out = render_html(tmp_path, "t-heat", {"case_id": "t-heat"},
                      findings=[_mk_finding()], techniques=techniques)
    text = out.read_text()
    # Section + tactic headings present
    assert 'id="heatmap"' in text
    assert "Credential Access" in text    # T1003.001 tactic
    assert "Execution" in text             # T1059.001 tactic
    assert "Impact" in text                # T1486 tactic
    # Heat-colour class on a 5-count technique
    assert "heat3" in text or "heat4" in text


def test_render_tier3_diamond_projection(tmp_path):
    """Tier 3: Diamond vertices populated from supporting findings + IOCs."""
    findings = [
        _mk_finding(claim="exfil via https", confidence="high",
                     hypotheses_supported=["H_APT_ESPIONAGE"]),
    ]
    ach = [_FakeRank(hyp_id="H_APT_ESPIONAGE", name="APT espionage", score=7)]
    iocs = {
        "ipv4": ["10.0.0.1", "203.0.113.77"],
        "domain": ["cmd.evil.example"],
    }
    out = render_html(tmp_path, "t-diam", {"case_id": "t-diam"},
                      findings=findings, ach_ranking=ach, iocs=iocs)
    text = out.read_text()
    assert 'id="diamond"' in text
    # Vertices present
    for v in ("Adversary", "Capability", "Infrastructure", "Victim"):
        assert v in text
    # External IP + domain on Adversary side; internal IP on Infrastructure
    assert "203.0.113.77" in text
    assert "cmd.evil.example" in text
    assert "10.0.0.1" in text
    # Case id is the victim fallback
    assert "t-diam" in text


def test_render_tier3_handles_empty_techniques(tmp_path):
    """Heatmap + Diamond both have graceful empty-state copy."""
    out = render_html(tmp_path, "empty-t3", {"case_id": "empty-t3"},
                      findings=[_mk_finding()])
    text = out.read_text()
    assert "No MITRE ATT&amp;CK techniques tagged" in text
    assert "No ACH ranking yet" in text


def test_render_with_explicit_graph(tmp_path):
    """Tier 2: caller can pass a prebuilt graph dict to skip the Kùzu query."""
    graph = {
        "nodes": [
            {"id": "host:h1", "type": "Host", "label": "h1", "attrs": {}},
            {"id": "ip:1.2.3.4", "type": "IPAddress",
             "label": "1.2.3.4", "attrs": {"version": 4}},
        ],
        "edges": [{"from": "host:h1", "to": "ip:1.2.3.4", "type": "RUNS_ON"}],
        "stats": {"total_nodes": 2, "total_edges": 1, "capped": False},
    }
    out = render_html(tmp_path, "t-g", {"case_id": "t-g"},
                      findings=[_mk_finding()], graph=graph)
    text = out.read_text()
    # Graph JSON round-trips through the embedded data block
    import re, json
    m = re.search(r'<script id="data" type="application/json">(.+?)</script>',
                   text, re.DOTALL)
    data = json.loads(m.group(1))
    assert data["graph"]["nodes"][0]["id"] == "host:h1"
    assert data["graph"]["edges"][0]["type"] == "RUNS_ON"


def test_render_no_external_fetch(tmp_path):
    """Self-contained: no <link rel=stylesheet> or <script src=> pointing
    off-origin. Works in a sealed tar.gz archive."""
    out = render_html(tmp_path, "sealed", {"case_id": "sealed"},
                      findings=[_mk_finding()])
    text = out.read_text()
    assert 'href="http' not in text.replace(
        'https://attack.mitre.org/techniques/', '')
    assert 'src="http' not in text
    assert 'rel="stylesheet"' not in text
    # MITRE ATT&CK links are allowed (external info links, not code loads)


def test_deep_link_fragment_matches_finding_ids(tmp_path):
    """`case.html#<finding_id>` opens that finding's drawer.
    The HTML must contain that finding_id referenced from the JS."""
    f = _mk_finding(claim="traceable")
    out = render_html(tmp_path, "deeplink", {"case_id": "deeplink"},
                      findings=[f])
    text = out.read_text()
    assert f.finding_id in text


def test_cli_report_emits_html_when_flag_set(tmp_path, monkeypatch):
    """End-to-end: el report --html writes case.html."""
    from typer.testing import CliRunner
    from el.cli import app
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import insert as ledger_insert, open_ledger
    from el.schemas.finding import Finding, EvidenceItem

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "dummy.bin"
    src.write_bytes(b"hello\n")
    m = intake_mod.intake(src, case_id="cli-html")
    with open_ledger(m.case_dir):
        pass
    ledger_insert(m.case_dir, Finding(
        case_id="cli-html", agent="t", claim="sample",
        confidence="high",
        evidence=[EvidenceItem(tool="t", version="0", command="x",
                                 output_sha256="0"*64,
                                 output_path="/tmp/x")],
    ))
    runner = CliRunner()
    result = runner.invoke(app, ["report", str(m.case_dir), "--html"])
    assert result.exit_code == 0, result.output
    html_file = Path(m.case_dir) / "reports" / "case.html"
    assert html_file.exists()
    content = html_file.read_text()
    assert "cli-html" in content


def test_cli_report_no_html_without_flag(tmp_path, monkeypatch):
    """Default `el report` does NOT emit case.html — keeps Markdown-only
    as the default surface."""
    from typer.testing import CliRunner
    from el.cli import app
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "dummy.bin"
    src.write_bytes(b"hi\n")
    m = intake_mod.intake(src, case_id="cli-nohtml")
    with open_ledger(m.case_dir):
        pass
    runner = CliRunner()
    result = runner.invoke(app, ["report", str(m.case_dir)])
    assert result.exit_code == 0, result.output
    assert not (Path(m.case_dir) / "reports" / "case.html").exists()
