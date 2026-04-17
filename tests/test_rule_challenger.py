from el.challengers.rules import challenge
from el.schemas.finding import EvidenceItem, Finding


def _ev():
    return EvidenceItem(tool="t", version="0", command="x",
                        output_sha256="0" * 64, output_path="/tmp/x")


def test_office_spawn_shell_challenged():
    f = Finding(case_id="c", agent="memory", confidence="high",
                claim="Suspicious parent->child process pair(s) observed: winword.exe->[pid 4321] powershell.exe",
                evidence=[_ev()])
    status, _, checklist = challenge(f)
    assert status == "challenged"
    assert any("LogonType" in c or "logged in" in c for c in checklist)


def test_malfind_challenged():
    f = Finding(case_id="c", agent="memory", confidence="high",
                claim="malfind flagged 3 region(s) across processes: chrome.exe",
                evidence=[_ev()])
    status, notes, checklist = challenge(f)
    assert status == "challenged"
    assert "JIT" in notes


def test_clean_high_confidence_passes_when_dense():
    f = Finding(case_id="c", agent="triage", confidence="high",
                claim="Input identified as pcap (libpcap) from magic bytes",
                evidence=[_ev(), _ev()])
    status, _, _ = challenge(f)
    assert status == "passed"


def test_high_with_single_evidence_challenged():
    f = Finding(case_id="c", agent="triage", confidence="high",
                claim="Some unrelated grounded claim",
                evidence=[_ev()])
    status, notes, _ = challenge(f)
    assert status == "challenged"
    assert "single tool" in notes.lower() or "NO_EVIDENCE_NO_CLAIM" in notes


def test_low_confidence_always_challenged():
    f = Finding(case_id="c", agent="x", confidence="low",
                claim="something benign-looking", evidence=[_ev(), _ev()])
    status, _, checklist = challenge(f)
    assert status == "challenged"
    assert any("corroborat" in c.lower() or "independent" in c.lower() for c in checklist)


def test_insufficient_returns_unresolved():
    f = Finding(case_id="c", agent="x", confidence="insufficient", claim="no data")
    status, _, _ = challenge(f)
    assert status == "unresolved"
