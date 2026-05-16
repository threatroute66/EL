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
    # Cross-case overlap findings (Layer-3 institutional knowledge)
    # are context, not kill-chain evidence — route to prologue so the
    # swimlane Execution lane isn't dominated by IOC-store hits.
    if (f.agent or "") == "knowledge_lookup":
        return "prologue"
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
# Swimlane eligibility — exclude metadata findings that don't represent
# discrete events
# ---------------------------------------------------------------------------

def is_parse_confirmation(f: Finding) -> bool:
    """A "parse confirmation" finding tells the analyst that a forensic
    parser ran cleanly against an artifact and produced output — it's
    metadata about the parse, not an event in the attack timeline.

    The kill-chain swimlane is a per-event scatter plot; placing a
    parse-confirmation marker on it widens the time axis (registry
    hives can contain timestamps decades older than the incident) and
    inflates the event count without telling the analyst anything
    about what the attacker did. The per-key / per-record findings
    emitted alongside the parse-confirmation are the real events; they
    land on the swimlane in their own right.

    Concretely covers `windows_artifact._try()` outputs — RECmd batch,
    EvtxECmd, MFTECmd, AmcacheParser, PECmd, SBECmd, JLECmd, LECmd,
    RBCmd, etc. — whose claim always ends in "parsed successfully".
    """
    return (f.agent or "") == "windows_artifact" and \
        (f.claim or "").endswith(": parsed successfully")


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
    # Keys agents emit that are real artifact times — adding here
    # populates the Attack Event Timeline. `date_utc` is email
    # client_submit / delivery_time; `mtime_utc` is filesystem
    # last-modified; `first_ts_utc` / `last_ts_utc` are window edges
    # of an aggregated event stream (logon/process bursts).
    "date_utc", "mtime_utc", "mtime_latest_utc",
    "first_ts_utc", "last_ts_utc",
    "last_used_start_utc", "last_seen_utc",
    "backup_date_utc",
    # disk_anomaly hits emit earliest_utc / latest_utc when the
    # matched bodyfile row carries non-zero mactime columns. Added
    # after M57-Jean audit: 12 disk_forensicator anomaly findings
    # had mactime data on the matched line but no recognised time
    # key, so they fell back to EL ingest time and dropped off the
    # 2008 swimlane window.
    "earliest_utc", "latest_utc",
)


_ISO_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}T?\s?\d{0,2}:?\d{0,2}:?\d{0,2}(?:[Z+.\-]\d*)?)\b")


def _parse_any_dt(s: str) -> datetime | None:
    """Parse a string to a UTC-aware datetime. Naive timestamps are
    assumed UTC — agents are required to emit UTC by EL's charter, but
    several emit `2012-04-03 21:11:07.4823242` (no offset) which
    `datetime.fromisoformat` produces as naive. Mixing naive + aware
    in `min()` raises and previously aborted narrative synthesis."""
    def _ensure_utc(dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    try:
        return _ensure_utc(datetime.fromisoformat(s.replace("Z", "+00:00")))
    except Exception:
        pass
    m = _ISO_RE.search(s)
    if not m:
        return None
    try:
        return _ensure_utc(datetime.fromisoformat(
            m.group(1).replace(" ", "T").replace("Z", "+00:00")))
    except Exception:
        return None


def evidence_time(f: Finding) -> datetime | None:
    """Return the earliest artifact timestamp referenced by this
    finding's evidence, or None when no artifact time is embedded.
    Mines extracted_facts first (structured), then searches the claim
    text for a date pattern as last-resort."""
    # Layer-3 cross-case overlap findings carry `first_seen_utc` that
    # is the IOC's first ingest into ~/.el/knowledge.sqlite — meta-
    # time about EL's institutional knowledge store, not artifact
    # time on this host. Excluded so the Attack Event Timeline shows
    # only real-world events from the case under investigation.
    if f.agent == "knowledge_lookup":
        return None
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
    # Tier-2 narrative enrichments — populated by synthesize().
    # `attack_chain` is the ordered list of (tactic, [(tid, name)]) pairs
    # mined from per-finding ATT&CK mappings. `evidence_time_range` is
    # (earliest, latest) ISO across artifact-timed findings, drives the
    # one-line "Case spans …" header. `prologue_facts` carries the host
    # metadata pulled from the triage finding + manifest.
    attack_chain: list[tuple[str, list[tuple[str, str]]]] = field(default_factory=list)
    evidence_time_range: tuple[str | None, str | None] = (None, None)
    prologue_facts: dict[str, str] = field(default_factory=dict)
    insufficient_findings: list[Finding] = field(default_factory=list)
    pivots: list[str] = field(default_factory=list)

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


def _dedup_findings(fs: list[Finding]) -> list[tuple[Finding, list[str]]]:
    """Collapse byte-identical-claim findings into a single bullet,
    preserving order of first occurrence and accumulating the
    finding_ids of duplicates. Same agent + same claim = same bullet.
    Returns [(representative_finding, [duplicate_finding_ids])]."""
    seen: dict[tuple[str, str], int] = {}
    out: list[tuple[Finding, list[str]]] = []
    for f in fs:
        key = (f.agent or "", (f.claim or "").strip())
        if key in seen:
            out[seen[key]][1].append(f.finding_id)
        else:
            seen[key] = len(out)
            out.append((f, []))
    return out


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

    deduped = _dedup_findings(fs)
    bullets: list[str] = []
    for rep, dup_ids in deduped[:5]:
        when_f = ""
        dt = evidence_time(rep)
        if dt:
            when_f = f" ({dt.isoformat(timespec='seconds')})"
        dup_note = (f" _(+{len(dup_ids)} duplicate finding(s))_"
                    if dup_ids else "")
        bullets.append(
            f"- {rep.agent}: {rep.claim.rstrip('.')}. {_cite(rep)}{when_f}{dup_note}")

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

    # Attack chain — ordered list of (tactic, [(tid, name)]) pairs
    # mined from per-finding ATT&CK mappings. Tactic order follows
    # MITRE's kill-chain ordering so the chain reads left-to-right.
    attack_chain: list[tuple[str, list[tuple[str, str]]]] = []
    try:
        from el.intel.attack_map import map_finding
        from el.intel.attack_tactics import tactic_for, TACTICS as TACTIC_ORDER
        per_tactic: dict[str, dict[str, str]] = {}
        for f in findings:
            if f.confidence == "insufficient":
                continue
            for tid, name in map_finding(f):
                tac = tactic_for(tid) or "Unknown"
                per_tactic.setdefault(tac, {})[tid] = name
        for tac in TACTIC_ORDER:
            if tac in per_tactic:
                attack_chain.append((tac, sorted(per_tactic[tac].items())))
    except Exception:
        attack_chain = []

    # Earliest / latest artifact-time across the whole ledger.
    # timeline_synthesist's super-timeline finding carries Plaso's
    # absolute first/last events (Firefox cache expiration dates,
    # NTFS overflow rows from FILE_NAME attributes with 0xff…ff
    # timestamps, etc.) — those are real evidence-derived data but
    # they balloon the case-glance window from "when activity
    # happened on this host" to "every timestamp Plaso could parse".
    # The curated findings from the other agents are what an analyst
    # actually wants framing the case.
    all_times = [evidence_time(f) for f in findings
                  if evidence_time(f) and f.agent != "timeline_synthesist"]
    time_range = (
        min(all_times).isoformat(timespec="seconds") if all_times else None,
        max(all_times).isoformat(timespec="seconds") if all_times else None,
    )

    # Prologue facts — host metadata pulled from triage finding
    # extracted_facts + manifest. Cheap projection, no new probes.
    prologue_facts: dict[str, str] = {}
    if manifest:
        if manifest.get("input_path"):
            prologue_facts["evidence"] = str(manifest["input_path"]).split("/")[-1]
        if manifest.get("input_size_bytes"):
            sz = int(manifest["input_size_bytes"])
            prologue_facts["size"] = (f"{sz/1024/1024/1024:.2f} GiB"
                                       if sz > 1024**3
                                       else f"{sz/1024/1024:.1f} MiB")
        if manifest.get("input_sha256"):
            prologue_facts["sha256"] = str(manifest["input_sha256"])[:16] + "…"
    for f in findings:
        if f.agent != "triage":
            continue
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            if facts.get("matched"):
                prologue_facts["evidence_kind"] = str(facts["matched"])
        break
    # Confidence histogram
    conf_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0,
                                    "insufficient": 0}
    for f in findings:
        conf_counts[f.confidence] = conf_counts.get(f.confidence, 0) + 1
    prologue_facts["finding_mix"] = (
        f"high={conf_counts['high']}, medium={conf_counts['medium']}, "
        f"low={conf_counts['low']}, insufficient={conf_counts['insufficient']}")

    # Insufficient-confidence findings — explicit list (not just count).
    insufficient_findings = [f for f in findings
                              if f.confidence == "insufficient"]

    # Suggested pivots — heuristic next-steps drawn from anomaly
    # findings + insufficient-confidence gaps. Each pivot is concrete
    # and grounded in a specific finding_id; no LLM, no hallucination.
    pivots: list[str] = []
    seen_pivots: set[str] = set()
    for f in findings:
        claim = (f.claim or "").lower()
        agent = f.agent or ""
        if "exe_in_temp" in claim or "executable in user-writable temp" in claim:
            tag = "exe_in_temp"
            if tag not in seen_pivots:
                pivots.append(
                    f"Submit dropper(s) under user Temp to malware-lab "
                    f"sandbox + capa for behavioural fingerprint. "
                    f"Anchor: [{f.finding_id}]")
                seen_pivots.add(tag)
        elif "system_binary_zero" in claim or "macb_timestomp" in claim:
            tag = "anti_forensics"
            if tag not in seen_pivots:
                pivots.append(
                    f"Recover the wiped/timestomped system binaries from "
                    f"VSS or unallocated (`tsk_recover` or `bulk_extractor`) "
                    f"to obtain pre-tampering hashes. Anchor: [{f.finding_id}]")
                seen_pivots.add(tag)
        elif agent == "email_forensicator" and (
                "display-name" in claim or "spoofed" in claim):
            tag = "email_actor"
            if tag not in seen_pivots:
                pivots.append(
                    f"Pivot the spoofing correspondent through mail-flow "
                    f"logs / SPF / DKIM history to attribute the inbound "
                    f"sender. Anchor: [{f.finding_id}]")
                seen_pivots.add(tag)
        elif "cobalt_strike" in claim or "trickbot" in claim:
            tag = "malware_hunt"
            if tag not in seen_pivots:
                pivots.append(
                    f"Run the family-fingerprint hits against memory "
                    f"region dumps + a vetted CS/Trickbot ruleset (vt-yara, "
                    f"florian-roth) for a stronger second source. "
                    f"Anchor: [{f.finding_id}]")
                seen_pivots.add(tag)
    # Fallback when no recognised anomaly fired but insufficient findings exist
    if not pivots and insufficient_findings:
        pivots.append(
            "No structured pivots derived from current findings — review "
            "the insufficient list above; each documents a missing data "
            "source whose collection would unblock further analysis.")

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
        attack_chain=attack_chain,
        evidence_time_range=time_range,
        prologue_facts=prologue_facts,
        insufficient_findings=insufficient_findings,
        pivots=pivots,
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

    # Case header — single-glance metadata block. Pulls from manifest +
    # triage + finding-time range. Empty fields are silently omitted so
    # the block grows with available data and never lies about absent
    # state.
    if nr.prologue_facts or any(nr.evidence_time_range):
        lines.append("## Case at a glance")
        lines.append("")
        if nr.prologue_facts.get("evidence"):
            lines.append(f"- **Evidence**: `{nr.prologue_facts['evidence']}`")
        if nr.prologue_facts.get("evidence_kind"):
            lines.append(f"- **Kind**: {nr.prologue_facts['evidence_kind']}")
        if nr.prologue_facts.get("size"):
            lines.append(f"- **Size**: {nr.prologue_facts['size']}")
        if nr.prologue_facts.get("sha256"):
            lines.append(f"- **SHA-256**: `{nr.prologue_facts['sha256']}`")
        if nr.prologue_facts.get("finding_mix"):
            lines.append(f"- **Finding mix**: {nr.prologue_facts['finding_mix']}")
        if nr.evidence_time_range[0]:
            lines.append(
                f"- **Artifact-time span**: "
                f"`{nr.evidence_time_range[0]}` → "
                f"`{nr.evidence_time_range[1]}` "
                f"(when the events EL could timestamp actually happened)")
        lines.append("")

    # ATT&CK kill-chain — one-liner per tactic, linked technique IDs.
    # When empty, omitted entirely (no "Detected chain: nothing"
    # filler).
    if nr.attack_chain:
        lines.append("## Detected ATT&CK chain")
        lines.append("")
        chain_parts = []
        for tac, items in nr.attack_chain:
            tids = " · ".join(f"`{tid}`" for tid, _ in items[:3])
            extra = (f" _(+{len(items)-3})_" if len(items) > 3 else "")
            chain_parts.append(f"**{tac}** {tids}{extra}")
        lines.append(" → ".join(chain_parts))
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
        # Concrete enumeration so the analyst can act on each gap rather
        # than read a count and shrug. First evidence command is shown
        # so the gap has a re-run handle.
        if nr.insufficient_findings:
            for f in nr.insufficient_findings[:10]:
                cmd = ""
                if f.evidence:
                    cmd = (f.evidence[0].command or "")[:80]
                cmd_part = f" — `{cmd}…`" if cmd else ""
                lines.append(f"  - `{f.finding_id}` ({f.agent}): "
                              f"{f.claim.rstrip('.')}.{cmd_part}")
            if len(nr.insufficient_findings) > 10:
                lines.append(f"  - _… {len(nr.insufficient_findings)-10} more elided_")
            lines.append("")

    if nr.pivots:
        lines.append("## Suggested pivots")
        lines.append("")
        lines.append("Concrete next steps grounded in specific findings on "
                     "this case. Each pivot anchors to a finding_id so the "
                     "analyst can trace the rationale back to evidence, and "
                     "EL has not chased the pivot itself — it remains an "
                     "open lead.")
        lines.append("")
        for pivot in nr.pivots:
            lines.append(f"- {pivot}")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Executive (non-expert) digest
# ---------------------------------------------------------------------------
# Produces an 8–12 sentence prose summary suitable for stakeholders who
# can't read ATT&CK T-IDs, ACH hypothesis tags, or detector pattern codes.
# Operates over an already-built NarrativeReport so the analyst tier
# (synthesize + render_markdown) and the exec tier never disagree about
# the same case — both are deterministic projections of the same ledger.
#
# The exec tier intentionally drops:
#   * finding-id citations (the analyst report keeps them)
#   * agent names ("memory_forensicator" means nothing to a stakeholder)
#   * tool internals ("YARA hits", "iLEAPP modules") unless glossary-translated
#   * ACH gap arithmetic (replaced by qualitative confidence phrases)
# ---------------------------------------------------------------------------

from el.reporting import glossary as _glossary

# Strip [ULID] citations like [01KQ9HN2CBB9BYB3FKFF1TJKQH]
_FID_RE = re.compile(r"\s*\[[0-9A-Z]{20,30}\]")

# Patterns that show up inside analyst claims and look like noise to a
# stakeholder. Each is best-effort — the Right Fix™ is for agents to
# populate EvidenceItem.human_summary, which the digest prefers when
# set. These regexes only cleanse the fallback path.
_NOISE_RES = (
    re.compile(r"\bslot\d+-off\d+\b"),                     # disk slot offsets
    re.compile(r"\bEID \d+\b"),                            # event IDs
    re.compile(r"\b(?:first|last)=[\d :.\-+]+T?[\d :.]+"), # raw "first=..." stamps
    re.compile(r"\bSamples?:.*$"),                         # Sample-of: trailers
    re.compile(r"\b\d+ match\(es\)\.?"),                   # "8 match(es)."
    re.compile(r"\b\d+ row\(s\)\b"),                       # "12 row(s)"
    re.compile(r"\bsha256=[0-9a-f]{6,}…?"),                # truncated hashes
)


@dataclass
class ExecutiveDigest:
    """Non-expert digest of a NarrativeReport.

    `summary_sentences` is the load-bearing field — 8 to 12 short
    sentences that, read in order, tell a stakeholder what the
    investigation found without using DFIR jargon. The other fields
    surface specific details (affected hosts, activity window, open
    questions) that a renderer may choose to break out into their own
    sections of the executive HTML/PDF, instead of inlining."""

    headline: str
    confidence_phrase: str
    summary_sentences: list[str] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    time_range_phrase: str | None = None

    def as_paragraph(self) -> str:
        return " ".join(self.summary_sentences)


def _confidence_phrase(score: int, gap: int) -> str:
    """Map ACH score + gap to qualitative confidence language. The
    thresholds mirror what an analyst would call out informally — a
    leader with score=0 is admitting the evidence is inconclusive, a
    leader with both high score AND a wide gap from the runner-up is
    the cleanest 'strong' case."""
    if score <= 0:
        return "the evidence currently available is too thin to support a single conclusion"
    if score >= 10 and gap >= 5:
        return "the evidence strongly supports this explanation"
    if score >= 3 and gap >= 2:
        return "the evidence moderately supports this explanation"
    return "the evidence is preliminary and other explanations remain plausible"


def _strip_jargon(text: str) -> str:
    """Apply the glossary to a claim, replacing recognised tokens with
    plain-English equivalents. Also strips finding-id citations,
    common analyst-noise patterns (slot offsets, event IDs, raw
    timestamps), and collapses multiple spaces. Best-effort — unknown
    tokens fall through unchanged because the glossary refuses to
    invent translations.

    Agents that want clean exec-tier prose should populate
    EvidenceItem.human_summary; the executive digest prefers that
    over running this fallback over the analyst claim."""
    text = _FID_RE.sub("", text or "")
    # Replace each glossary-known token with its plain-English form.
    # Use the same regex the glossary uses to spot terms, so the swap
    # is consistent with what entries_used() reports.
    def _swap(match: re.Match) -> str:
        tok = match.group(0)
        return _glossary.translate(tok)
    out = _glossary._TOKEN_RE.sub(_swap, text)
    for nr in _NOISE_RES:
        out = nr.sub("", out)
    # After noise removal, sweep up orphan prepositions/colons left
    # behind (e.g. "in :" once a slot offset is gone, ":" floating
    # before a removed Sample list).
    out = re.sub(r"\bin\s*[:.](?:\s|$)", "", out)
    out = re.sub(r":\s*(?=[.,;]|$)", "", out)
    out = re.sub(r"\s+", " ", out).strip(" .,;:—-")
    return out


def _beat_lay_sentence(bb: "BeatBlock") -> str | None:
    """Build one plain-English sentence describing a beat's evidence,
    or None when the beat has no findings. Strips finding IDs and
    glossary-translates jargon. Used for the body of the digest."""
    if bb.finding_count == 0:
        return None
    # Take the highest-priority finding's claim, strip jargon, anchor
    # to a beat-specific lead-in. We don't quote analyst prose verbatim
    # because it carries internal token names like "T1003.001".
    if not bb.top_findings:
        return None
    rep = bb.top_findings[0]
    # Prefer an agent-supplied human_summary over the raw claim when
    # any evidence item carries one — that's the opt-in path for
    # exec-tier-quality prose (Phase 0.3). Falls back to glossary-
    # stripped claim otherwise.
    summary = next(
        (ev.human_summary for ev in (rep.evidence or [])
         if ev.human_summary), None,
    )
    claim_lay = summary or _strip_jargon(rep.claim or "")
    lead = {
        "trigger":   "Initial entry point: ",
        "execution": "Code that ran on the host included ",
        "persistence": "Persistence mechanism observed: ",
        "discovery":   "Reconnaissance and credential-access activity: ",
        "lateral":     "Movement to other hosts: ",
        "collection":  "Data collected on the host: ",
        "command_control": "Outbound control communication: ",
        "impact":      "Impact: ",
        "aftermath":   "Anti-forensic activity: ",
    }.get(bb.beat, "")
    sentence = f"{lead}{claim_lay}".rstrip(".") + "."
    # Cap sentence length so the digest stays scannable. Long claims
    # get truncated with an ellipsis rather than splitting prose mid-clause.
    if len(sentence) > 180:
        sentence = sentence[:177].rstrip(",;:— ") + "…"
    return sentence


def synthesize_executive(nr: NarrativeReport) -> ExecutiveDigest:
    """Build an executive (non-expert) digest from a NarrativeReport.

    Deterministic; no LLM. The analyst NarrativeReport is the input,
    the digest is a plain-English projection of the same data.
    """
    headline = (
        _glossary.translate(nr.leading_hypothesis)
        if nr.leading_hypothesis
        else "No primary explanation determined"
    )
    # If the glossary has no entry the translator returns the raw
    # hypothesis tag (H_FOO_BAR) — sand it down to "the leading theory"
    # rather than show internal codes.
    if headline.startswith("H_"):
        headline = "the leading theory cannot be summarised in plain language"

    confidence = _confidence_phrase(nr.leading_score, nr.leading_gap)

    sentences: list[str] = []

    # 1 — Headline + confidence
    sentences.append(
        f"This investigation's leading theory is **{headline}**, and "
        f"{confidence}."
    )

    # 2 — Optional runner-up call-out when ACH gap is small (forensic
    # rigor: we never advocate a single theory when the evidence is
    # genuinely close).
    if nr.leading_gap < 3 and nr.runner_up_hypothesis:
        runner_up_plain = _glossary.translate(nr.runner_up_hypothesis)
        if not runner_up_plain.startswith("H_"):
            sentences.append(
                f"A second explanation — {runner_up_plain} — is also "
                f"consistent with the evidence and cannot be ruled out."
            )

    # 3 — Time-range framing
    earliest, latest = nr.evidence_time_range
    if earliest and latest and earliest != latest:
        sentences.append(
            f"Evidence on the system spans {earliest[:10]} to {latest[:10]}."
        )
        time_phrase: str | None = f"{earliest[:10]} → {latest[:10]}"
    elif earliest:
        sentences.append(f"The earliest evidence is dated {earliest[:10]}.")
        time_phrase = earliest[:10]
    else:
        time_phrase = None

    # 4-6 — Body: lay description of up-to-three significant beats.
    # Pick the beats that actually hit findings, in narrative order.
    body_beats = [bb for bb in nr.beats
                   if bb.finding_count > 0
                   and bb.beat not in ("prologue",)]
    body_beats.sort(key=lambda bb: BEATS.index(bb.beat))
    for bb in body_beats[:4]:
        s = _beat_lay_sentence(bb)
        if s:
            sentences.append(s)

    # 7 — Affected assets (evidence file names — proxies for devices
    # the executive recognises by handle).
    affected: list[str] = []
    if nr.prologue_facts.get("evidence"):
        affected.append(str(nr.prologue_facts["evidence"]))

    # 8 — Open questions (translated insufficient findings).
    open_qs: list[str] = []
    for f in nr.insufficient_findings[:3]:
        clean = _strip_jargon(f.claim or "")
        if clean and clean not in open_qs:
            open_qs.append(clean.rstrip(".") + ".")
    if open_qs:
        sentences.append(
            f"{len(open_qs)} question(s) remain open because the data "
            f"needed to answer them was not in the collected evidence."
        )

    # 9 — Forensic-rigor disclaimer when score=0.
    if nr.leading_score <= 0:
        sentences.append(
            "Because no theory crossed a meaningful evidence threshold, "
            "this report does not advocate a single conclusion."
        )

    # Pad up to 5 sentences BEFORE the handoff so that handoff stays
    # last. The fillers are factual ("the analyst report preserves
    # full detail", confidence histogram callout) — never invented.
    _filler = [
        "Full technical detail is preserved in the analyst report "
        "(case.html / report.md) for forensic review.",
        f"Of {sum(1 for _ in nr.insufficient_findings) + nr.unresolved_count + 0} "
        "investigative threads, those without sufficient grounding are "
        "documented as open rather than guessed at.",
    ]
    fi = 0
    while len(sentences) < 5 and fi < len(_filler):
        sentences.append(_filler[fi])
        fi += 1

    # 10 — Hand-off (always last)
    sentences.append(
        "See the Findings section for the underlying evidence and the "
        "Recommendations section for next steps."
    )

    return ExecutiveDigest(
        headline=headline,
        confidence_phrase=confidence,
        summary_sentences=sentences,
        affected_assets=affected,
        open_questions=open_qs,
        time_range_phrase=time_phrase,
    )


__all__ = [
    "BeatBlock", "NarrativeReport", "BEATS",
    "synthesize", "render_markdown",
    "evidence_time",
    "ExecutiveDigest", "synthesize_executive",
]
