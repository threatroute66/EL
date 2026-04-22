"""Narrative synthesis — Executive Narrative generator.

Turns a case's Finding ledger + ACH ranking + IOC catalog into a
structured prose report that answers the six questions every DFIR
analyst asks:

  1. What system, whose, when
  2. Leading theory, and by how big a margin
  3. Trigger — the first compromise event reconstructible from evidence
  4. Attacker chain — execution → persistence → discovery → lateral
     → collection
  5. Impact — exfil / destruction / ransomware / lateral damage
  6. Current state + what we can't prove

Hard constraints inherited from EL's charter:

  * Every sentence that makes a factual claim ends with `[<finding_id>]`
    citations. Synthesis without citation is sycophancy.

  * When a beat has no supporting findings, the narrative says so
    explicitly ("The initial compromise vector is not reconstructible
    from the available evidence.") — consistent with
    confidence="insufficient" being a first-class output.

  * When the ACH gap between leader and runner-up is < 3, the
    narrative presents **both** hypotheses in parallel. M57-Jean is
    the motivating case: evidence supports both "insider exfil" and
    "external compromise + insider framed" and a report that picks
    one is dishonest.

  * Evidence timestamps — not EL's wall clock — order the narrative.
    `extracted_facts` is mined for real artifact times (ts_utc,
    create_time, LoadTime, last_write_utc, etc.); `created_utc` is
    only the fallback.

No LLM at synthesis time. Deterministic template-per-beat prose with
slots filled from the ledger. Red Reviewer may challenge the
narrative after the fact the same way it challenges findings today.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from el.schemas.finding import Finding


# ---------------------------------------------------------------------------
# Beat classification — which story beat does each finding belong to?
# ---------------------------------------------------------------------------

BEATS = (
    "prologue",      # what system, whose, when — triage + manifest
    "trigger",       # first compromise event (initial access)
    "execution",     # code execution, scripts, LOLBins
    "persistence",   # services / tasks / autoruns
    "discovery",     # account / network / system recon
    "lateral",       # lateral movement
    "collection",    # data staging
    "command_control",   # C2 beaconing / ingress tool transfer
    "impact",        # exfil / destruction / ransomware
    "aftermath",     # log-clearing / anti-forensics / residual indicators
)


# Map from hypothesis ID to the beat it most naturally belongs in.
# Order matters when a finding supports multiple hypotheses — first
# match wins (so put the more specific beat earlier).
_HYPOTHESIS_TO_BEAT: dict[str, str] = {
    "H_INITIAL_ACCESS_DOC_MACRO":          "trigger",
    "H_INITIAL_ACCESS_WEB":                "trigger",
    "H_INITIAL_ACCESS_PHISHING":           "trigger",
    "H_BRUTE_FORCE":                        "trigger",
    "H_PROCESS_INJECTION":                  "execution",
    "H_LIVING_OFF_THE_LAND":                "execution",
    "H_PROCESS_HOLLOWING":                  "execution",
    "H_PERSISTENCE_SCHEDULED_TASK":         "persistence",
    "H_PERSISTENCE_SERVICE":                "persistence",
    "H_PERSISTENCE_AUTORUN":                "persistence",
    "H_PERSISTENCE_STARTUP":                "persistence",
    "H_ACCOUNT_CREATED":                    "persistence",
    "H_CREDENTIAL_ACCESS":                  "discovery",
    "H_LATERAL_MOVEMENT":                   "lateral",
    "H_C2_OR_REVERSE_SHELL":                "command_control",
    "H_BEACONING":                          "command_control",
    "H_INSIDER_EMAIL_EXFIL":                "impact",
    "H_INSIDER_USB_EXFIL":                  "impact",
    "H_CLOUD_EXFIL":                        "impact",
    "H_RANSOMWARE":                         "impact",
    "H_DATA_DESTRUCTION":                   "impact",
    "H_APT_ESPIONAGE":                      "impact",
    "H_OPPORTUNISTIC_COMMODITY":            "impact",
    "H_LOG_CLEARED":                        "aftermath",
    "H_ANTI_FORENSICS":                     "aftermath",
}


# Map from ATT&CK technique → beat. Covers 103 of EL's emitted
# technique IDs; reuses the attack_tactics module's tactic lookup
# as a fallback so every technique lands somewhere.
_TACTIC_TO_BEAT: dict[str, str] = {
    "Initial Access":        "trigger",
    "Execution":             "execution",
    "Persistence":           "persistence",
    "Privilege Escalation":  "execution",
    "Defense Evasion":       "aftermath",
    "Credential Access":     "discovery",
    "Discovery":             "discovery",
    "Lateral Movement":      "lateral",
    "Collection":            "collection",
    "Command and Control":   "command_control",
    "Exfiltration":          "impact",
    "Impact":                "impact",
}


def _beat_from_finding(f: Finding) -> str:
    """Classify a finding into one of the 10 beats. Priority:
    (1) explicit hypothesis tag → beat, (2) ATT&CK technique → tactic
    → beat, (3) agent-name fallback."""
    for h in f.hypotheses_supported:
        if h in _HYPOTHESIS_TO_BEAT:
            return _HYPOTHESIS_TO_BEAT[h]
    # ATT&CK technique fallback via attack_tactics
    from el.intel.attack_tactics import tactic_for
    for ev in f.evidence:
        facts = ev.extracted_facts or {}
        for tid in (facts.get("attack_techniques") or
                     facts.get("attack_techniques_list") or []):
            tactic = tactic_for(str(tid))
            if tactic and tactic in _TACTIC_TO_BEAT:
                return _TACTIC_TO_BEAT[tactic]
    # Agent-name fallback
    agent = f.agent or ""
    if agent == "triage":                 return "prologue"
    if agent == "red_reviewer":           return "aftermath"
    if "memory" in agent:                 return "execution"
    if "network" in agent:                return "command_control"
    if "log_analyst" in agent:            return "discovery"
    if "lateral" in agent:                return "lateral"
    if "credential" in agent:             return "discovery"
    if "persistence" in agent or "autorun" in agent: return "persistence"
    if "cloud" in agent:                  return "impact"
    if "correlator" in agent:             return "prologue"
    if "threat_hunter" in agent:          return "execution"
    if "malware_triage" in agent:         return "execution"
    return "execution"      # default bucket — loud but rarely misleading


# ---------------------------------------------------------------------------
# Evidence-time extraction — prefer artifact time over EL's wall clock
# ---------------------------------------------------------------------------

_TIME_KEYS = (
    "ts_utc", "timestamp", "timestamp_utc",
    "create_time", "create_utc", "CreateTime",
    "last_write_utc", "last_write",
    "LoadTime", "Modified", "modified_utc",
    "earliest_ts", "first_seen_utc",
    "mactime_earliest", "m_earliest",
    "event_time_utc", "logon_time_utc",
    "observed_utc",
)


_ISO_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}T?\s?\d{0,2}:?\d{0,2}:?\d{0,2}(?:[Z+.\-]\d*)?)\b")


def _parse_any_dt(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        pass
    m = _ISO_RE.search(s)
    if not m:
        return None
    try:
        return datetime.fromisoformat(m.group(1).replace(" ", "T")
                                       .replace("Z", "+00:00"))
    except Exception:
        return None


def evidence_time(f: Finding) -> datetime | None:
    """Return the earliest artifact timestamp referenced by this
    finding's evidence, or None when no artifact time is embedded.
    Mines extracted_facts first (structured), then searches the claim
    text for a date pattern as last-resort."""
    candidates: list[datetime] = []
    for ev in f.evidence:
        facts = ev.extracted_facts or {}
        for k in _TIME_KEYS:
            v = facts.get(k)
            if not v:
                continue
            if isinstance(v, str):
                dt = _parse_any_dt(v)
                if dt:
                    candidates.append(dt)
    # Claim text as last resort
    if not candidates:
        dt = _parse_any_dt(f.claim or "")
        if dt:
            candidates.append(dt)
    if not candidates:
        return None
    return min(candidates)


def _time_str(f: Finding) -> str:
    dt = evidence_time(f)
    if dt:
        return dt.isoformat(timespec="seconds").replace("+00:00", "Z")
    if getattr(f, "created_utc", None):
        return f.created_utc.isoformat(timespec="seconds").replace(
            "+00:00", "Z")
    return "—"


# ---------------------------------------------------------------------------
# Diagnostic scoring — which findings anchor which beats
# ---------------------------------------------------------------------------

def _diagnostic_score(f: Finding) -> int:
    """ACH score-delta spread (max - min). Heuer's own metric for
    diagnosticity. Ties broken by confidence rank + evidence count."""
    delta = getattr(f, "ach_score_delta", None) or {}
    vals = list(delta.values())
    spread = (max([0, *vals]) - min([0, *vals])) if vals else 0
    conf_rank = {"high": 3, "medium": 2, "low": 1, "insufficient": 0}.get(
        f.confidence, 0)
    return spread * 10 + conf_rank + min(len(f.evidence), 3)


# ---------------------------------------------------------------------------
# Report dataclasses
# ---------------------------------------------------------------------------

@dataclass
class BeatBlock:
    beat: str
    heading: str
    earliest: str | None            # ISO timestamp, if any
    latest: str | None
    finding_count: int
    top_findings: list[Finding] = field(default_factory=list)
    paragraph: str = ""             # rendered prose with [fid] citations


@dataclass
class NarrativeReport:
    case_id: str
    leading_hypothesis: str | None
    leading_score: int
    leading_gap: int                # leader − runner-up
    runner_up_hypothesis: str | None
    runner_up_score: int
    beats: list[BeatBlock]
    alt_beats: list[BeatBlock]      # populated when gap < 3
    unresolved_count: int
    insufficient_count: int

    def as_markdown(self) -> str:
        return render_markdown(self)


# ---------------------------------------------------------------------------
# Per-beat prose templates
# ---------------------------------------------------------------------------

_BEAT_HEADING = {
    "prologue":        "What this case is",
    "trigger":         "Initial compromise",
    "execution":       "Code execution on the host",
    "persistence":     "Persistence mechanisms",
    "discovery":       "Reconnaissance + credential access",
    "lateral":         "Lateral movement",
    "collection":      "Data collection + staging",
    "command_control": "Command and control",
    "impact":          "Impact + exfiltration",
    "aftermath":       "Anti-forensics + residual indicators",
}


def _cite(f: Finding) -> str:
    """Inline citation `[<finding_id>]`."""
    return f"[{f.finding_id}]"


def _paragraph_for_beat(beat: str, fs: list[Finding]) -> str:
    """Build the prose paragraph for one beat from its top findings.
    The template is a simple natural-language scaffold with slot-fills;
    when no findings exist for a beat, emit an honest gap statement."""
    if not fs:
        if beat == "trigger":
            return ("The **initial compromise vector is not "
                    "reconstructible** from the available evidence "
                    "— no phishing, drive-by, brute-force, or valid-"
                    "account-abuse findings were produced. This is an "
                    "open question the investigation cannot yet close.")
        if beat == "impact":
            return ("**No impact evidence was surfaced.** Either the "
                    "action-on-objective step hasn't happened yet on "
                    "this host, or the evidence that would show it "
                    "(outbound network flows, cloud-log events, file-"
                    "encryption traces) is outside the collected scope.")
        return ""        # silent for beats that simply weren't hit

    earliest = min((evidence_time(f) for f in fs
                    if evidence_time(f)), default=None)
    when = (f"As of **{earliest.isoformat(timespec='seconds')}**"
            if earliest else "")

    bullets: list[str] = []
    for f in fs[:5]:
        when_f = ""
        dt = evidence_time(f)
        if dt:
            when_f = f" ({dt.isoformat(timespec='seconds')})"
        bullets.append(
            f"- {f.agent}: {f.claim.rstrip('.')}. {_cite(f)}{when_f}")

    lead = {
        "prologue":   "This case's evidence shape + triage classification:",
        "trigger":    f"{when + ', the' if when else 'The'} earliest "
                       f"compromise indicator visible in the ledger:",
        "execution":  "Code execution tied to the attacker chain:",
        "persistence": "Persistence artefacts — footholds the attacker "
                       "intended to survive reboot:",
        "discovery":  "Recon + credential-access activity:",
        "lateral":    "Host-to-host pivot evidence:",
        "collection": "Data staged for exfiltration:",
        "command_control": "Command-and-control / ingress-tool-transfer "
                       "indicators:",
        "impact":     "Action-on-objective:",
        "aftermath":  "Anti-forensics + residual indicators that outlive "
                       "the live compromise:",
    }.get(beat, "")

    return lead + "\n\n" + "\n".join(bullets)


# ---------------------------------------------------------------------------
# Report synthesis
# ---------------------------------------------------------------------------

def synthesize(
    case_id: str,
    findings: list[Finding],
    ach_ranking: list | None = None,
    iocs: dict | None = None,
    manifest: dict | None = None,
) -> NarrativeReport:
    ach_ranking = ach_ranking or []
    leader = ach_ranking[0] if ach_ranking else None
    runner = ach_ranking[1] if len(ach_ranking) > 1 else None

    by_beat: dict[str, list[Finding]] = {b: [] for b in BEATS}
    unresolved = 0
    insufficient = 0
    for f in findings:
        by_beat[_beat_from_finding(f)].append(f)
        if f.red_review and f.red_review.status == "unresolved":
            unresolved += 1
        if f.confidence == "insufficient":
            insufficient += 1

    # Sort each beat by diagnostic score (descending), then by evidence
    # time (ascending) so chronology carries within a beat.
    for b in BEATS:
        by_beat[b].sort(
            key=lambda f: (-_diagnostic_score(f),
                            evidence_time(f) or datetime.max.replace(tzinfo=timezone.utc)))

    beats: list[BeatBlock] = []
    for beat in BEATS:
        fs = by_beat[beat]
        times = [evidence_time(f) for f in fs if evidence_time(f)]
        earliest = min(times).isoformat(timespec="seconds") if times else None
        latest = max(times).isoformat(timespec="seconds") if times else None
        beats.append(BeatBlock(
            beat=beat, heading=_BEAT_HEADING[beat],
            earliest=earliest, latest=latest,
            finding_count=len(fs), top_findings=fs[:5],
            paragraph=_paragraph_for_beat(beat, fs),
        ))

    # Multi-hypothesis alternative view — populated when ACH gap < 3.
    alt_beats: list[BeatBlock] = []
    gap = (leader.score - runner.score) if (leader and runner) else 99
    if leader and runner and gap < 3:
        # Re-score findings from the runner-up's perspective. Same
        # beat assignment rules, different supporting-finding subset.
        alt_findings = [f for f in findings
                        if runner.hyp_id in f.hypotheses_supported]
        alt_by_beat: dict[str, list[Finding]] = {b: [] for b in BEATS}
        for f in alt_findings:
            alt_by_beat[_beat_from_finding(f)].append(f)
        for b in BEATS:
            alt_by_beat[b].sort(
                key=lambda f: (-_diagnostic_score(f),
                                evidence_time(f) or datetime.max.replace(tzinfo=timezone.utc)))
        for beat in BEATS:
            fs = alt_by_beat[beat]
            if not fs:
                continue
            alt_beats.append(BeatBlock(
                beat=beat, heading=_BEAT_HEADING[beat],
                earliest=None, latest=None,
                finding_count=len(fs), top_findings=fs[:3],
                paragraph=_paragraph_for_beat(beat, fs),
            ))

    return NarrativeReport(
        case_id=case_id,
        leading_hypothesis=leader.hyp_id if leader else None,
        leading_score=leader.score if leader else 0,
        leading_gap=gap if (leader and runner) else 99,
        runner_up_hypothesis=runner.hyp_id if runner else None,
        runner_up_score=runner.score if runner else 0,
        beats=beats,
        alt_beats=alt_beats,
        unresolved_count=unresolved,
        insufficient_count=insufficient,
    )


# ---------------------------------------------------------------------------
# Markdown + HTML renderers
# ---------------------------------------------------------------------------

def render_markdown(nr: NarrativeReport) -> str:
    lines: list[str] = []
    lines.append(f"# Executive Narrative — {nr.case_id}")
    lines.append("")
    lead_line = (f"Leading hypothesis: **{nr.leading_hypothesis}** "
                  f"(score {nr.leading_score})")
    if nr.runner_up_hypothesis:
        lead_line += (f", runner-up **{nr.runner_up_hypothesis}** "
                       f"(score {nr.runner_up_score}, gap {nr.leading_gap}).")
    else:
        lead_line += "."
    lines.append(lead_line)
    if nr.leading_gap < 3 and nr.runner_up_hypothesis:
        lines.append("")
        lines.append("⚠ **Hypothesis gap is small** — the evidence supports "
                     "more than one theory. Both are presented below. A "
                     "report that advocates only one is sycophantic.")
    lines.append("")

    for block in nr.beats:
        if block.finding_count == 0 and block.beat not in ("trigger", "impact"):
            continue          # silent beats stay silent
        lines.append(f"## {block.heading}")
        lines.append("")
        if block.earliest:
            lines.append(f"_Earliest evidence: {block.earliest}_")
            lines.append("")
        lines.append(block.paragraph)
        lines.append("")

    if nr.alt_beats:
        lines.append("---")
        lines.append("")
        lines.append(f"## Alternative narrative — {nr.runner_up_hypothesis}")
        lines.append("")
        lines.append("The evidence subset that would SUPPORT this runner-up "
                      "hypothesis, had the analyst chosen it as the leading "
                      "theory instead:")
        lines.append("")
        for block in nr.alt_beats:
            lines.append(f"### {block.heading}")
            lines.append("")
            lines.append(block.paragraph)
            lines.append("")

    if nr.unresolved_count or nr.insufficient_count:
        lines.append("## Open questions")
        lines.append("")
        if nr.unresolved_count:
            lines.append(f"- **{nr.unresolved_count} finding(s) remain with "
                          f"red_review status = unresolved** — synthesis "
                          f"was blocked on those at report time.")
        if nr.insufficient_count:
            lines.append(f"- **{nr.insufficient_count} finding(s) at "
                          f"confidence = insufficient** — these document "
                          f"what EL could not extract and exist so the gap "
                          f"is visible to the analyst. 'I don't know' is a "
                          f"first-class output.")
        lines.append("")
    return "\n".join(lines)


__all__ = [
    "BeatBlock", "NarrativeReport", "BEATS",
    "synthesize", "render_markdown",
    "evidence_time",
]
