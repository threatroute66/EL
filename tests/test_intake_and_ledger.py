from pathlib import Path

from el.evidence import intake as intake_mod
from el.evidence.intake import intake
from el.evidence.ledger import insert, list_findings
from el.evidence.graph import init_graph, open_graph
from el.schemas.finding import Finding, EvidenceItem


def test_intake_creates_workspace_and_hashes(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "evidence.bin"
    src.write_bytes(b"hello-locard")
    m = intake(src, case_id="c-test")
    cdir = Path(m.case_dir)
    assert (cdir / "manifest.json").exists()
    for sub in ("analysis", "exports", "reports", "raw"):
        assert (cdir / sub).is_dir()
    assert m.input_sha256 and len(m.input_sha256) == 64


def test_ledger_round_trip(tmp_path):
    cdir = tmp_path / "case"
    cdir.mkdir()
    f = Finding(
        case_id="c-test", agent="triage", claim="dummy",
        confidence="high",
        evidence=[EvidenceItem(tool="t", version="0", command="echo",
                               output_sha256="0" * 64, output_path="/tmp/x")],
    )
    insert(cdir, f)
    rows = list_findings(cdir, case_id="c-test")
    assert len(rows) == 1 and rows[0].finding_id == f.finding_id


def test_graph_schema_initializes(tmp_path):
    cdir = tmp_path / "case"
    cdir.mkdir()
    p = init_graph(cdir)
    assert p.exists()
    db, conn = open_graph(cdir)
    conn.execute("CREATE (h:Host {name:'H1', os:'linux'})")
    r = conn.execute("MATCH (h:Host) RETURN h.name")
    assert r.has_next()
