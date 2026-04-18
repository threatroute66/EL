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


def test_high_attribution_with_single_evidence_challenged():
    """Attribution-shaped claims should still be challenged when evidence is thin."""
    f = Finding(case_id="c", agent="malware_triage", confidence="high",
                claim="Memory-region attribution: meterpreter markers identified as Metasploit",
                evidence=[_ev()])
    status, notes, _ = challenge(f)
    assert status == "challenged"
    assert "NO_EVIDENCE_NO_CLAIM" in notes


def test_high_routine_finding_NOT_challenged_for_single_evidence():
    """Routine plugin-output findings (single evidence by nature) shouldn't fire
    NO_EVIDENCE_NO_CLAIM. Audit Apr-2026 found 250 such false-positives across
    50 sampled cases when this rule was over-broad."""
    f = Finding(case_id="c", agent="memory_forensicator", confidence="high",
                claim="windows.pslist.PsList: 163 row(s) parsed",
                evidence=[_ev()])
    status, notes, _ = challenge(f)
    # Either passed or challenged on a different rule — but NOT on NO_EVIDENCE
    assert "NO_EVIDENCE_NO_CLAIM" not in notes


def test_low_with_hypothesis_tag_challenged():
    """Low-confidence findings that POINT at a hypothesis still need corroboration."""
    f = Finding(case_id="c", agent="x", confidence="low",
                claim="suggestive C2 pattern", evidence=[_ev()],
                hypotheses_supported=["H_C2_OR_REVERSE_SHELL"])
    status, _, checklist = challenge(f)
    assert status == "challenged"
    assert any("corroborat" in c.lower() or "independent" in c.lower() for c in checklist)


def test_low_routine_observation_NOT_challenged():
    """Low-confidence routine observations without hypothesis tags shouldn't be
    challenged for corroboration."""
    f = Finding(case_id="c", agent="triage", confidence="low",
                claim="Input has no recognised magic header — treating as opaque",
                evidence=[_ev()])  # no hypotheses_supported
    status, notes, _ = challenge(f)
    assert "LOW_CONFIDENCE_NEEDS_CORROBORATION" not in notes


def test_insufficient_returns_unresolved():
    f = Finding(case_id="c", agent="x", confidence="insufficient", claim="no data")
    status, _, _ = challenge(f)
    assert status == "unresolved"
