"""Recommendations engine for the executive (non-expert) report tier.

Maps the leading ACH hypothesis + present finding patterns to a small
list of plain-English next-step suggestions a stakeholder can act on.

Forensic discipline:
  * Every recommendation cites the finding_id(s) that triggered it.
    Analysts can trace any recommendation back to evidence.
  * No recommendation invents context the evidence didn't support.
  * Conservative wording — "consider", "review", not "do X immediately".
    The exec report includes a footer reminder that recommendations are
    advisory and final action belongs to the IR lead / stakeholder.
  * Rule set is intentionally small (≤10 patterns at launch). Each
    pattern represents a high-confidence mapping from a class of
    evidence to a class of action. Wide coverage at low precision is
    worse than narrow coverage at high precision — wrong
    recommendations destroy trust.

Each rule is a function `(nr, findings) -> Recommendation | None`. The
module runs every rule in a stable order and returns the non-None
results. Tests pin the order so reports don't churn between renders.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from el.schemas.finding import Finding


@dataclass
class Recommendation:
    """A single suggested next step.

    `action` is the plain-English imperative.
    `rationale` is one sentence explaining why this is suggested
       (e.g. "Findings show credential-access activity affecting
       this host's local accounts.").
    `triggered_by` is the list of finding IDs that fired this rule
       — the analyst trace-back path.
    `category` groups recommendations into the report's section
       headings: containment / investigation / remediation /
       reporting / hardening.
    """

    action: str
    rationale: str
    triggered_by: list[str] = field(default_factory=list)
    category: str = "investigation"


# ---------------------------------------------------------------------------
# Rule helpers
# ---------------------------------------------------------------------------

def _findings_with_hypothesis(findings: list[Finding], hyp: str) -> list[Finding]:
    return [f for f in findings if hyp in f.hypotheses_supported
            and f.confidence != "insufficient"]


def _findings_matching_claim(findings: list[Finding], *needles: str) -> list[Finding]:
    """Return findings whose claim contains any of the lowercase
    `needles`, excluding insufficient findings (which by contract
    have no evidence to act on)."""
    nl = [n.lower() for n in needles]
    out = []
    for f in findings:
        if f.confidence == "insufficient":
            continue
        claim = (f.claim or "").lower()
        if any(n in claim for n in nl):
            out.append(f)
    return out


def _ids(fs: list[Finding], cap: int = 3) -> list[str]:
    """Take up to `cap` finding IDs for the trigger trace-back. We
    don't dump every supporting ID into the executive report — three
    is enough for an analyst to walk back into the analyst tier."""
    return [f.finding_id for f in fs[:cap]]


# ---------------------------------------------------------------------------
# Rules. Each takes a NarrativeReport and the raw findings list and
# returns a Recommendation (or None when the trigger pattern isn't met).
# Order in the tuple at the bottom of this module pins report order.
# ---------------------------------------------------------------------------

def _rule_lateral_or_apt_isolate(nr, findings) -> Recommendation | None:
    fs = _findings_with_hypothesis(findings, "H_LATERAL_MOVEMENT")
    fs += _findings_with_hypothesis(findings, "H_APT_ESPIONAGE")
    if not fs:
        return None
    return Recommendation(
        category="containment",
        action="Consider isolating the affected host(s) from the network "
               "and rotating credentials for any user who logged in during "
               "the activity window.",
        rationale="Evidence indicates an attacker moved between systems or "
                  "established persistent footing; further pivoting is "
                  "possible until the host is contained.",
        triggered_by=_ids(fs),
    )


def _rule_credential_access_rotate(nr, findings) -> Recommendation | None:
    fs = _findings_with_hypothesis(findings, "H_CREDENTIAL_ACCESS")
    if not fs:
        return None
    return Recommendation(
        category="containment",
        action="Rotate credentials for accounts that authenticated to this "
               "host. Monitor for replay attempts using the new password "
               "policy.",
        rationale="Evidence shows credentials were extracted from this "
                  "system; any login that touched the host should be "
                  "treated as potentially exposed.",
        triggered_by=_ids(fs),
    )


def _rule_ransomware_disconnect(nr, findings) -> Recommendation | None:
    if nr.leading_hypothesis != "H_RANSOMWARE":
        return None
    fs = _findings_with_hypothesis(findings, "H_RANSOMWARE")
    if not fs:
        return None
    return Recommendation(
        category="containment",
        action="Disconnect the host from the network immediately. Preserve "
               "a memory image of any encrypted processes still running "
               "before powering off — encryption keys may still be in RAM.",
        rationale="Ransomware activity was detected; rapid isolation "
                  "prevents lateral encryption while live memory may "
                  "carry recoverable key material.",
        triggered_by=_ids(fs),
    )


def _rule_insider_exfil_legal_hold(nr, findings) -> Recommendation | None:
    fs = _findings_with_hypothesis(findings, "H_INSIDER_EMAIL_EXFIL")
    fs += _findings_with_hypothesis(findings, "H_INSIDER_DATA_EXFIL")
    if not fs:
        return None
    return Recommendation(
        category="reporting",
        action="Place an evidence preservation hold on the user's mailbox "
               "and cloud accounts, and review their activity for the "
               "indicated time window with HR or legal counsel as "
               "appropriate.",
        rationale="Findings indicate an insider was the actor; evidence "
                  "outside this host (mailbox audit logs, DLP records, "
                  "cloud-storage downloads) is needed to scope what left "
                  "the company.",
        triggered_by=_ids(fs),
    )


def _rule_anti_forensics_recover(nr, findings) -> Recommendation | None:
    fs = _findings_matching_claim(
        findings,
        "MACB_TIMESTOMP_SKEW", "SYSTEM_BINARY_ZERO",
        "security_log_cleared", "vssadmin_delete_shadows",
    )
    if not fs:
        return None
    return Recommendation(
        category="investigation",
        action="Attempt to recover the tampered or deleted artifacts from "
               "Volume Shadow Copies and unallocated space (`tsk_recover`, "
               "`bulk_extractor`). Pre-tampering hashes can corroborate "
               "or refute the leading theory.",
        rationale="Anti-forensic activity was detected; the original "
                  "artifacts may still exist in shadow copies or carved "
                  "remnants and would strengthen the chain of evidence.",
        triggered_by=_ids(fs),
    )


def _rule_persistence_remove(nr, findings) -> Recommendation | None:
    fs = _findings_with_hypothesis(findings, "H_PERSISTENCE_SERVICE")
    fs += _findings_with_hypothesis(findings, "H_PERSISTENCE_SCHEDULED_TASK")
    if not fs:
        return None
    return Recommendation(
        category="remediation",
        action="Remove the identified persistence mechanism and check for "
               "the same artifact pattern on adjacent hosts; attackers "
               "rarely install persistence on only one machine.",
        rationale="A persistence mechanism (Windows service or scheduled "
                  "task) was found; survival across reboots means the "
                  "compromise outlasts simple cleanup steps.",
        triggered_by=_ids(fs),
    )


def _rule_no_incident_archive(nr, findings) -> Recommendation | None:
    if nr.leading_hypothesis != "H_BENIGN_NO_INCIDENT":
        return None
    return Recommendation(
        category="reporting",
        action="Document the case as inconclusive / no evidence of "
               "compromise. Retain the evidence per chain-of-custody for "
               "re-review if new indicators surface.",
        rationale="No active-compromise pattern crossed the evidence "
                  "threshold; the prudent course is preservation rather "
                  "than action.",
        triggered_by=[],
    )


def _rule_insufficient_collect_more(nr, findings) -> Recommendation | None:
    """When the case is dominated by insufficient findings — meaning
    we couldn't ground claims — point at what's missing. This is the
    'collect more evidence' bucket."""
    if not nr.insufficient_findings:
        return None
    if nr.leading_score > 5:
        # We already have a well-supported leading hypothesis; the
        # insufficient findings are gaps, not the dominant signal.
        return None
    return Recommendation(
        category="investigation",
        action="Collect the additional data sources flagged as missing in "
               "the open-questions list (e.g., mailbox logs, network "
               "captures, memory image) before treating the leading "
               "theory as final.",
        rationale=f"{len(nr.insufficient_findings)} investigative thread(s) "
                  "are open because the data needed to answer them was not "
                  "in the collected evidence; conclusions are preliminary "
                  "until those gaps close.",
        triggered_by=_ids(nr.insufficient_findings),
    )


# Ordered tuple — pins report order so successive renders of the same
# case produce the same recommendation sequence (deterministic).
_RULES: tuple[Callable, ...] = (
    _rule_ransomware_disconnect,
    _rule_lateral_or_apt_isolate,
    _rule_credential_access_rotate,
    _rule_persistence_remove,
    _rule_anti_forensics_recover,
    _rule_insider_exfil_legal_hold,
    _rule_no_incident_archive,
    _rule_insufficient_collect_more,
)


def build_recommendations(nr, findings: list[Finding]) -> list[Recommendation]:
    """Run all rules in pinned order and return the non-None results.

    `nr` is a NarrativeReport (from synthesize()); `findings` is the
    full ledger. The function is pure — no I/O, no LLM, deterministic
    output for a given input.
    """
    out: list[Recommendation] = []
    for rule in _RULES:
        rec = rule(nr, findings)
        if rec is not None:
            out.append(rec)
    return out


# Stable footer string the renderer can quote verbatim. Keeping it
# here rather than in the renderer means the legal/IR-advice
# disclaimer is co-located with the rules that produce the advice.
ADVISORY_DISCLAIMER = (
    "Recommendations are advisory and based on the evidence available "
    "at the time of analysis. Final containment, remediation, and "
    "legal decisions belong to the incident-response lead or "
    "stakeholder. Each suggestion above is anchored to one or more "
    "findings in the analyst report; the underlying evidence should "
    "be reviewed before acting."
)


__all__ = [
    "Recommendation",
    "build_recommendations",
    "ADVISORY_DISCLAIMER",
]
