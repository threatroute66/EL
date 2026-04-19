"""Tests for H_INSIDER_EMAIL_EXFIL hypothesis + ACH ranking.

Contract:
  - Hypothesis is registered
  - Display-name/SMTP mismatch finding lifts it at +3 (plus benign -3)
  - Sensitive-attachment-external finding lifts it at +3
  - An insider-email-exfil-shaped case puts H_INSIDER_EMAIL_EXFIL as
    the TOP hypothesis, above H_APT and H_BEC
  - H_INSIDER_DATA_EXFIL gets a small corroborating lift (+1) so the
    two insider hypotheses rank together
  - attack_map maps the new hypothesis to T1048.003 / T1534 / T1566.002
"""
from datetime import datetime, timezone

from el.intel.ach import score_findings
from el.intel.attack_map import HYPOTHESIS_MAP, map_case
from el.intel.hypotheses import HYPOTHESES, by_id
from el.schemas.finding import EvidenceItem, Finding


def _finding(claim: str, *, confidence="high", tags=None) -> Finding:
    return Finding(
        case_id="t-pr8", agent="email_forensicator",
        claim=claim, confidence=confidence,
        evidence=[EvidenceItem(
            tool="libpff/pffexport", version="20180714",
            command="pffexport",
            output_sha256="a" * 64,
            output_path="/tmp/fake.pst",
            extracted_facts={},
        )],
        hypotheses_supported=tags or [],
    )


def test_hypothesis_registered():
    h = by_id().get("H_INSIDER_EMAIL_EXFIL")
    assert h is not None
    assert "email" in h.description.lower()


def test_attack_map_covers_insider_email_exfil():
    techs = HYPOTHESIS_MAP["H_INSIDER_EMAIL_EXFIL"]
    tids = [tid for tid, _ in techs]
    assert "T1048.003" in tids
    assert "T1534" in tids
    assert "T1566.002" in tids


def test_mismatch_finding_lifts_new_hypothesis():
    f = _finding(
        "Email display-name/SMTP mismatch in jean.pst (Sent Items): "
        "sender=jean@m57.biz subject='RE: info'; recipient DISPLAYED as "
        "'alison@m57.biz' but ACTUALLY sent to 'tuckgorge@gmail.com' "
        "(display domain m57.biz ≠ actual gmail.com).",
        tags=["H_INSIDER_EMAIL_EXFIL", "H_BEC_ACCOUNT_TAKEOVER"],
    )
    ranked, _ = score_findings([f])
    by = {r.hyp_id: r for r in ranked}
    assert by["H_INSIDER_EMAIL_EXFIL"].score >= 3
    # Benign must be refuted
    assert by["H_BENIGN_NO_INCIDENT"].score < 0


def test_sensitive_attachment_finding_lifts_new_hypothesis():
    f = _finding(
        "Sensitive attachment → external recipient in jean.pst (Sent Items): "
        "sender=jean@m57.biz to tuckgorge@gmail.com; attachment(s): "
        "m57plan.xlsx (200000B). Consumer webmail destination.",
        tags=["H_INSIDER_EMAIL_EXFIL"],
    )
    ranked, _ = score_findings([f])
    by = {r.hyp_id: r for r in ranked}
    assert by["H_INSIDER_EMAIL_EXFIL"].score >= 3


def test_insider_email_exfil_ranks_above_apt_on_mailbox_case():
    """M57-Jean shape: two spoof-mismatch findings + one sensitive-
    attachment finding + the volume-parsed finding. H_INSIDER_EMAIL_EXFIL
    must rank above H_APT (which has nothing to lift it here) and above
    H_BEC (also lifted but without the keyword corroboration)."""
    findings = [
        _finding(
            "PST parsed (jean.pst): 258 message(s) across 10 folder(s) "
            "(Calendar, Contacts, Deleted Items, Drafts, Inbox…). "
            "Inferred local domain(s): m57.biz",
            tags=["H_MAILBOX_PARSED"],
        ),
        _finding(
            "Email display-name/SMTP mismatch in jean.pst (Sent Items): "
            "sender=jean@m57.biz subject='RE: Please send me the info'; "
            "recipient DISPLAYED as 'alison@m57.biz' but ACTUALLY sent to "
            "'tuckgorge@gmail.com' (display domain m57.biz ≠ actual gmail.com). "
            "Has 1 attachment(s). Classic impersonation / pretexting pattern.",
            tags=["H_INSIDER_EMAIL_EXFIL", "H_BEC_ACCOUNT_TAKEOVER"],
        ),
        _finding(
            "Email display-name/SMTP mismatch in jean.pst (Sent Items): "
            "sender=jean@m57.biz subject='RE: Thanks!' "
            "recipient DISPLAYED as 'alison@m57.biz' but ACTUALLY sent to "
            "'tuckgorge@gmail.com'.",
            tags=["H_INSIDER_EMAIL_EXFIL", "H_BEC_ACCOUNT_TAKEOVER"],
        ),
        _finding(
            "Sensitive attachment → external recipient in jean.pst "
            "(Sent Items): sender=jean@m57.biz to tuckgorge@gmail.com; "
            "attachment(s): m57plan.xlsx (297082B). Consumer webmail "
            "destination.",
            tags=["H_INSIDER_EMAIL_EXFIL"],
        ),
    ]

    ranked, _ = score_findings(findings)
    top = ranked[0]
    assert top.hyp_id == "H_INSIDER_EMAIL_EXFIL", (
        f"expected H_INSIDER_EMAIL_EXFIL top, got {top.hyp_id} "
        f"with rank {[(r.hyp_id, r.score) for r in ranked[:5]]}")

    # H_INSIDER_DATA_EXFIL must not be silent — mailbox-exfil is a
    # specialisation, so the generic insider should ride along.
    by = {r.hyp_id: r for r in ranked}
    assert by["H_INSIDER_DATA_EXFIL"].score > 0

    # H_APT must be lower than H_INSIDER_EMAIL_EXFIL on this case
    assert by["H_APT_ESPIONAGE"].score < top.score


def test_map_case_emits_insider_email_exfil_techniques():
    f = _finding(
        "Sensitive attachment → external recipient …",
        tags=["H_INSIDER_EMAIL_EXFIL"],
    )
    techniques = map_case([f])
    assert "T1048.003" in techniques
    assert "T1534" in techniques
