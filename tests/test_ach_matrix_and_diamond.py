"""T4-1 tests: Heuer ACH consistency matrix + Diamond Model projection."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from el.reporting.ach_matrix import build_ach_matrix_markdown
from el.reporting.diamond import build_diamond_markdown
from el.schemas.finding import EvidenceItem, Finding, RedReview


def _finding(fid: str, claim: str = "x",
              deltas: dict[str, int] | None = None,
              supports: list[str] | None = None,
              evidence_facts: dict | None = None) -> Finding:
    ev = [EvidenceItem(
        tool="t", version="0", command="c", output_sha256="0" * 64,
        output_path="/x", extracted_facts=evidence_facts or {},
    )]
    return Finding(
        finding_id=fid, case_id="c", agent="t", confidence="high",
        claim=claim, evidence=ev,
        hypotheses_supported=supports or [],
        ach_score_delta=deltas or {},
        created_utc=datetime.now(timezone.utc),
    )


def _rank(hyp_id: str, name: str, score: int) -> SimpleNamespace:
    return SimpleNamespace(
        hyp_id=hyp_id, name=name, score=score,
        supporting_findings=[], refuting_findings=[],
    )


# ---------------------------------------------------------------------------
# ACH matrix
# ---------------------------------------------------------------------------

def test_matrix_renders_columns_in_ranking_order():
    ranking = [
        _rank("H_APT_ESPIONAGE", "Targeted intrusion", 22),
        _rank("H_LATERAL_MOVEMENT", "Lateral movement", 18),
        _rank("H_C2_BEACONING", "C2 beaconing", 6),
    ]
    f1 = _finding("01ABC", deltas={"H_APT_ESPIONAGE": 3,
                                     "H_LATERAL_MOVEMENT": 2,
                                     "H_C2_BEACONING": 0})
    f2 = _finding("01DEF", deltas={"H_APT_ESPIONAGE": -1,
                                     "H_C2_BEACONING": 3})
    lines = build_ach_matrix_markdown([f1, f2], ranking)
    matrix_text = "\n".join(lines)
    # Header order matches ranking order
    assert matrix_text.index("APT_ESPIONAGE") < matrix_text.index(
        "LATERAL_MOVEMENT") < matrix_text.index("C2_BEACONING")


def test_matrix_cells_use_signed_deltas_and_dashes():
    ranking = [_rank("H_A", "A", 5), _rank("H_B", "B", 3)]
    f = _finding("01Z", deltas={"H_A": 3, "H_B": 0})
    lines = build_ach_matrix_markdown([f], ranking)
    row = next(l for l in lines if "01Z" in l)
    assert "+3" in row
    assert "--" in row


def test_matrix_skips_findings_without_nonzero_deltas():
    ranking = [_rank("H_A", "A", 5)]
    f = _finding("01Z", deltas={"H_A": 0})
    assert build_ach_matrix_markdown([f], ranking) == []


def test_matrix_sorts_by_max_absolute_delta():
    ranking = [_rank("H_A", "A", 5), _rank("H_B", "B", 5)]
    small = _finding("01SMALL", deltas={"H_A": 1})
    big = _finding("01BIG", deltas={"H_A": -5})
    lines = build_ach_matrix_markdown([small, big], ranking)
    # The big-delta row appears first in the body
    body = [l for l in lines if l.startswith("| `01")]
    assert body[0].startswith("| `01BIG")


def test_matrix_escapes_pipe_in_claim_text():
    ranking = [_rank("H_A", "A", 5)]
    f = _finding("01Z", claim="contains | a pipe | char",
                  deltas={"H_A": 1})
    lines = build_ach_matrix_markdown([f], ranking)
    # The pipe in the claim must be backslash-escaped so it doesn't
    # break the markdown table row
    assert any(r"contains \| a pipe \| char" in l for l in lines)


def test_matrix_empty_ranking_returns_empty():
    assert build_ach_matrix_markdown(
        [_finding("x", deltas={"H_A": 3})], []) == []


# ---------------------------------------------------------------------------
# Diamond Model
# ---------------------------------------------------------------------------

def test_diamond_emits_adversary_capability_infrastructure_victim():
    ranking = [_rank("H_C2_BEACONING", "C2 beaconing", 9)]
    iocs = {
        "ipv4": ["203.0.113.10", "10.0.0.5"],           # public + internal
        "domain": ["evil.example.com"],
    }
    f = _finding(
        "01X", supports=["H_C2_BEACONING"],
        evidence_facts={"attack_techniques": ["T1071.001", "T1105"]},
    )
    lines = build_diamond_markdown([f], ranking, iocs,
                                     manifest={"case_id": "wkstn-01"})
    text = "\n".join(lines)
    assert "Adversary" in text and "203.0.113.10" in text
    assert "evil.example.com" in text
    assert "Capability" in text and "T1071.001" in text
    assert "Infrastructure" in text and "10.0.0.5" in text
    assert "Victim" in text and "wkstn-01" in text


def test_diamond_handles_no_public_attribution_surface():
    ranking = [_rank("H_LATERAL_MOVEMENT", "Lateral", 10)]
    iocs = {"ipv4": ["10.0.0.5", "172.16.4.6"]}
    f = _finding("01X", supports=["H_LATERAL_MOVEMENT"],
                  evidence_facts={"attack_techniques": ["T1021.002"]})
    lines = build_diamond_markdown([f], ranking, iocs, manifest={})
    text = "\n".join(lines)
    # Adversary row present but empty-annotated
    assert "no public IPs/domains observed" in text
    # Internal IPs still land in the Infrastructure row
    assert "10.0.0.5" in text
    assert "172.16.4.6" in text


def test_diamond_skips_when_no_supporting_findings():
    ranking = [_rank("H_APT_ESPIONAGE", "APT", 10)]
    # Finding supports a DIFFERENT hypothesis — none for the leader
    f = _finding("01X", supports=["H_BENIGN_NO_INCIDENT"])
    assert build_diamond_markdown([f], ranking, {}, manifest={}) == []


def test_diamond_skips_when_no_ranking():
    f = _finding("01X", supports=["H_A"])
    assert build_diamond_markdown([f], [], {}, manifest={}) == []


def test_diamond_extracts_user_principals_from_facts():
    ranking = [_rank("H_CREDENTIAL_ACCESS", "Cred access", 9)]
    f = _finding(
        "01X", supports=["H_CREDENTIAL_ACCESS"],
        evidence_facts={
            "attack_techniques": ["T1558.003"],
            "top_targets": [("spfarm@SHIELDBASE.LAN", 75),
                             ("nromanoff@SHIELDBASE.LAN", 20)],
        },
    )
    lines = build_diamond_markdown([f], ranking,
                                     {"ipv4": []}, manifest={})
    text = "\n".join(lines)
    assert "spfarm@SHIELDBASE.LAN".lower() in text.lower()
