"""Regression tests captured from charlie-01 (2009 Windows memory image):
malfind hit lsass.exe (credential-dumping indicator). Three contracts:

1. MemoryForensicator emits a SECOND finding tagged H_CREDENTIAL_ACCESS
   when a credential-access target process (lsass/winlogon/services/csrss/
   wininit/smss) shows up in malfind output.
2. The MALFIND_JIT_FALSE_POSITIVE rule does NOT fire on credential-access
   target findings — JIT doesn't run in lsass.
3. ATT&CK mapping links H_CREDENTIAL_ACCESS to T1003.001 (LSASS Memory).
"""
from el.agents.memory_forensicator import MemoryForensicatorAgent
from el.challengers.rules import challenge
from el.intel.attack_map import map_finding
from el.schemas.finding import EvidenceItem, Finding


def _ev():
    return EvidenceItem(tool="t", version="0", command="x",
                        output_sha256="0" * 64, output_path="/tmp/x")


class _FakeRun:
    def __init__(self, rows):
        self.rows = rows
    def as_evidence(self, facts=None):
        return _ev()


def test_lsass_malfind_emits_credential_access_finding(tmp_path, monkeypatch):
    from el.evidence import intake as intake_mod
    from el.agents.base import AgentContext
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-cred")
    from el.evidence.ledger import open_ledger
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-cred", case_dir=tmp_path / "cases" / "t-cred",
                       input_path=src, manifest=m.__dict__)

    rows = [
        {"Process": "lsass.exe", "PID": 480},
        {"Process": "lsass.exe", "PID": 480},
        {"Process": "chrome.exe", "PID": 1234},
    ]
    findings = MemoryForensicatorAgent()._flag_malfind(ctx, _FakeRun(rows))
    cred = [f for f in findings if "H_CREDENTIAL_ACCESS" in f.hypotheses_supported]
    assert len(cred) == 1, f"expected 1 credential-access finding, got {len(cred)}"
    assert "lsass.exe" in cred[0].claim
    assert cred[0].confidence == "high"


def test_jit_rule_does_not_fire_on_credential_access_target():
    f = Finding(case_id="c", agent="memory_forensicator", confidence="high",
                claim="Code-injection in credential-access target process(es): lsass.exe×2. "
                      "These system processes do not run JIT-compiled code...",
                evidence=[_ev()],
                hypotheses_supported=["H_CREDENTIAL_ACCESS", "H_PROCESS_INJECTION"])
    status, notes, _ = challenge(f)
    assert "MALFIND_JIT_FALSE_POSITIVE" not in notes
    # NO_EVIDENCE_NO_CLAIM still fires (single evidence item) but JIT must not.


def test_credential_access_maps_to_t1003():
    f = Finding(case_id="c", agent="memory_forensicator", confidence="high",
                claim="Code-injection in credential-access target process(es): lsass.exe×2",
                evidence=[_ev()],
                hypotheses_supported=["H_CREDENTIAL_ACCESS"])
    pairs = map_finding(f)
    tids = {tid for tid, _ in pairs}
    assert "T1003.001" in tids
    assert "T1003" in tids
