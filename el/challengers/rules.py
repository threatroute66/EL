"""Rule-Based Challenger.

Deterministic falsification baseline. Always runs. Fires per-claim-pattern
rules that produce a counter-explanation and a disconfirming-evidence
checklist. Output is in the same shape the LLM challenger would produce, so
the merge step is symmetric.

Rule design notes:
- Default posture is 'challenged' for any non-trivial high-confidence claim.
  A finding only earns 'passed' if no rule fires AND evidence is dense
  (>= 1 grounded item).
- Rules match against the claim text + the supporting hypotheses + tool
  output extracted_facts. They are intentionally narrow — broad rules
  would produce noise.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from el.schemas.finding import Finding


@dataclass
class RuleHit:
    rule_id: str
    counter_explanation: str
    disconfirming_checklist: list[str]


@dataclass
class Rule:
    rule_id: str
    description: str
    matches: Callable[[Finding], bool]
    counter_explanation: str
    disconfirming_checklist: list[str] = field(default_factory=list)


def _claim_has(*tokens: str) -> Callable[[Finding], bool]:
    pat = re.compile("|".join(re.escape(t) for t in tokens), re.IGNORECASE)
    return lambda f: bool(pat.search(f.claim))


def _supports(hyp_substr: str) -> Callable[[Finding], bool]:
    return lambda f: any(hyp_substr in h for h in f.hypotheses_supported)


RULES: list[Rule] = [
    Rule(
        rule_id="OFFICE_SPAWN_SHELL_BENIGN_AUTOMATION",
        description="Office app launching cmd/powershell may be legitimate IT automation",
        matches=lambda f: _claim_has("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")(f)
                          and _claim_has("cmd.exe", "powershell.exe")(f),
        counter_explanation=(
            "Office applications can legitimately spawn shells via signed macros, "
            "DLP agents, or admin-deployed VBA tooling. Spawn alone does not establish malice."
        ),
        disconfirming_checklist=[
            "Resolve the document path that was open in the parent Office process — is it on a controlled share or attached from email?",
            "Pull the cmdline of the spawned shell — is it base64/encoded, or a benign IT script path?",
            "Check Sysmon Event 1 / Security 4688 around the spawn time for the parent's command line",
            "Was the user logged in interactively (LogonType 2/10) or via batch/service at the time?",
        ],
    ),
    Rule(
        rule_id="MALFIND_JIT_FALSE_POSITIVE",
        description="malfind RWX regions can be legitimate JIT/CLR/V8 compilers",
        # Carve out credential-access targets: lsass/winlogon/services/csrss/
        # wininit/smss do NOT run JIT-compiled code, so the JIT counter-
        # explanation does not apply and this rule MUST NOT fire on them.
        matches=lambda f: (_claim_has("malfind")(f)
                           and "credential-access target" not in (f.claim or "").lower()
                           and not any(p in (f.claim or "").lower()
                                        for p in ("lsass.exe", "winlogon.exe",
                                                   "services.exe", "csrss.exe",
                                                   "wininit.exe", "smss.exe"))),
        counter_explanation=(
            "RWX/RX regions with no PE header are commonly produced by JIT runtimes "
            "(CLR, JScript, V8/Chromium, Java Hotspot, PyPy). Region presence alone is not injection."
        ),
        disconfirming_checklist=[
            "Identify the host process name — is it a known JIT runtime (chrome.exe, msedge.exe, w3wp.exe, java.exe, dotnet.exe, python.exe with JIT)?",
            "Dump the suspicious region and inspect for PE/shellcode signatures (capa, FLOSS, manualyze)",
            "Compare the VAD protection + tag against expected runtime behavior for that process",
            "Check process integrity (signed binary, expected parent, expected modules loaded)",
        ],
    ),
    Rule(
        rule_id="LOLBIN_CMDLINE_BENIGN_USE",
        description="LOLBIN cmdlines can serve admin tasks (rundll32, regsvr32, mshta, bitsadmin)",
        matches=_claim_has("rundll32.exe", "regsvr32.exe", "mshta.exe", "bitsadmin.exe"),
        counter_explanation=(
            "These binaries have legitimate uses: rundll32 invokes signed COM components, "
            "regsvr32 registers signed DLLs during install, BITS handles Windows Update."
        ),
        disconfirming_checklist=[
            "Resolve the full DLL/script being invoked — signed by whom?",
            "Compare cmdline against known LOLBAS abuse patterns (lolbas-project.github.io)",
            "Cross-check with installer or update activity in the same time window",
        ],
    ),
    Rule(
        rule_id="NETSCAN_CONNECTION_NEEDS_ENRICHMENT",
        description="A network connection alone is not evil — destination context required",
        matches=_claim_has("netscan", "connection", "tcp", "udp"),
        counter_explanation=(
            "Connections to public IPs are not inherently malicious. Without ASN, geolocation, "
            "and reputation context, this is an observation, not a finding of malice."
        ),
        disconfirming_checklist=[
            "Resolve the destination IP to ASN/owner — corporate proxy, CDN, cloud provider, residential?",
            "Check threat-intel reputation (passive DNS, VirusTotal, your team's blocklists)",
            "Correlate with process making the connection — is it a browser, an unknown binary, or a system service?",
        ],
    ),
    Rule(
        rule_id="LOW_CONFIDENCE_NEEDS_CORROBORATION",
        description="A low-confidence finding that POINTS at a hypothesis needs corroboration",
        # Only fire when the low finding has hypothesis tags (i.e. it's
        # claiming something about case-level attribution). Routine triage
        # observations like "Input has no recognised magic header" carry no
        # tags and shouldn't be challenged for corroboration.
        matches=lambda f: f.confidence == "low" and bool(f.hypotheses_supported),
        counter_explanation=(
            "A single low-confidence signal pointing at a hypothesis is not actionable. "
            "EL requires at least one independent corroborating artifact from a different "
            "agent or evidence source."
        ),
        disconfirming_checklist=[
            "Identify a second, independent evidence source (different host, different artifact class, different tool) that supports or refutes this claim",
        ],
    ),
    Rule(
        rule_id="NO_EVIDENCE_NO_CLAIM",
        description="High-confidence ATTRIBUTION findings with a single evidence item need a second source",
        # Fire only on attribution-shaped claims (a strong assertion that a
        # specific actor/family/technique is present). Generic plugin-output
        # findings ("X plugin parsed N rows") don't claim attribution and
        # legitimately have only the plugin output as evidence — challenging
        # them produces 250 noise events per sampled 50 cases (audit Apr-2026).
        matches=lambda f: (
            f.confidence == "high" and len(f.evidence) <= 1
            and any(kw in (f.claim or "").lower() for kw in (
                "attribut", "identified as", "indicates", "fingerprint",
                "leading hypothesis", "confirms", "credential-dumping",
                "process injection", "memory-region attribution",
            ))
        ),
        counter_explanation=(
            "An attribution-strength claim deserves a second source. A single tool's output "
            "(parser, plugin, or library) can produce confident-looking-but-spurious results "
            "via bugs, stale symbols, or version drift."
        ),
        disconfirming_checklist=[
            "Re-run the originating plugin/tool with a different version or ruleset",
            "Cross-check with a different tool that observes the same artifact "
            "(e.g. capa + family-fingerprint + ssdeep similarity, or pslist + psscan + pstree)",
        ],
    ),
]


def challenge(finding: Finding) -> tuple[str, str, list[str]]:
    """Return (status, notes, checklist) for a single finding.

    status:
      - 'unresolved' if confidence='insufficient' (not subject to challenge)
      - 'challenged' if any rule hits
      - 'passed'    if no rule hits AND evidence is non-empty
    """
    if finding.confidence == "insufficient":
        return "unresolved", "rule-based: not applicable to insufficient findings", []

    hits: list[Rule] = [r for r in RULES if r.matches(finding)]
    if not hits:
        if not finding.evidence:
            return "unresolved", "rule-based: no evidence to evaluate", []
        return "passed", "rule-based: no rule fired and evidence is present", []

    notes = "; ".join(f"[{r.rule_id}] {r.counter_explanation}" for r in hits)
    checklist: list[str] = []
    for r in hits:
        checklist.extend(r.disconfirming_checklist)
    seen = set()
    deduped = [c for c in checklist if not (c in seen or seen.add(c))]
    return "challenged", notes, deduped
