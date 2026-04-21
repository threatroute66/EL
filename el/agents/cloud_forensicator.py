"""Cloud Forensicator — dispatches on cloud-log shape.

V1: AWS CloudTrail, Azure sign-in logs (Entra / AAD), Microsoft 365
Unified Audit Log. Each kind has its own skill with pure-function
detectors; this agent sniffs the input's shape, routes to the skill,
and promotes detector hits to Findings. Future scope: Azure Activity
Logs, GCP Cloud Audit, Google Workspace Admin Audit / OAuth log.
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import azure_signin as asl
from el.skills import cloudtrail
from el.skills import m365_audit as ual


_CLOUDTRAIL_HINTS = (b'"eventName"', b'"eventSource"', b'"awsRegion"')


# Technique → hypothesis tags (used for both Azure sign-in + UAL hits).
_SIGNIN_TO_HYPOTHESIS: dict[str, list[str]] = {
    "signin_brute":      ["H_BRUTE_FORCE", "H_CREDENTIAL_ACCESS",
                           "H_BEC_ACCOUNT_TAKEOVER"],
    "signin_spray":      ["H_BRUTE_FORCE", "H_CREDENTIAL_ACCESS",
                           "H_BEC_ACCOUNT_TAKEOVER"],
    "legacy_auth":       ["H_BEC_ACCOUNT_TAKEOVER", "H_CREDENTIAL_ACCESS"],
    "risky_signin":      ["H_BEC_ACCOUNT_TAKEOVER", "H_CREDENTIAL_ACCESS"],
    "impossible_travel": ["H_BEC_ACCOUNT_TAKEOVER", "H_CREDENTIAL_ACCESS"],
}

_UAL_TO_HYPOTHESIS: dict[str, list[str]] = {
    "inbox_rule_forward_external": ["H_BEC_ACCOUNT_TAKEOVER",
                                      "H_INSIDER_EMAIL_EXFIL"],
    "mail_items_accessed_bulk":    ["H_BEC_ACCOUNT_TAKEOVER",
                                      "H_INSIDER_EMAIL_EXFIL"],
    "oauth_consent_grant":         ["H_CLOUD_PERSISTENCE",
                                      "H_BEC_ACCOUNT_TAKEOVER"],
    "signin_brute":                ["H_BRUTE_FORCE",
                                      "H_BEC_ACCOUNT_TAKEOVER"],
    "signin_spray":                ["H_BRUTE_FORCE",
                                      "H_BEC_ACCOUNT_TAKEOVER"],
}


def _detect_kind(path: Path) -> str:
    """Sniff the first 16 KB to route the log to the right parser."""
    try:
        with path.open("rb") as f:
            head = f.read(16_384)
    except OSError:
        return "unreadable"
    if any(h in head for h in _CLOUDTRAIL_HINTS):
        return "aws_cloudtrail"
    if asl.looks_like_signin_log(head):
        return "azure_signin"
    if ual.looks_like_ual(head):
        return "m365_ual"
    return "unknown"


class CloudForensicatorAgent(Agent):
    name = "cloud_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        kind = _detect_kind(ctx.input_path)
        if kind == "unreadable":
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Cannot read cloud-log input: {ctx.input_path}",
            ))]
        if kind == "aws_cloudtrail":
            return self._run_cloudtrail(ctx, analysis)
        if kind == "azure_signin":
            return self._run_azure_signin(ctx, analysis)
        if kind == "m365_ual":
            return self._run_m365_ual(ctx, analysis)
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="insufficient",
            claim=("Input does not match any known cloud-log shape "
                   "(AWS CloudTrail, Azure sign-in log, M365 UAL). "
                   "If this IS a cloud log, check it exports at least "
                   "the first record's distinguishing fields."),
        ))]

    # ----- AWS CloudTrail (unchanged path) -----

    def _run_cloudtrail(self, ctx: AgentContext, analysis) -> list[Finding]:
        try:
            s = cloudtrail.parse(ctx.input_path, analysis)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"CloudTrail parse failed: {e}",
            ))]
        ev = s.as_evidence()
        out: list[Finding] = []
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Parsed {s.record_count} CloudTrail record(s); "
                   f"{len(s.distinct_principals)} principal(s), "
                   f"{len(s.distinct_source_ips)} source IP(s), "
                   f"{len(s.distinct_regions)} region(s), "
                   f"{len(s.high_value_events)} high-value event(s)"),
            evidence=[ev], hypotheses_supported=["H_CLOUD_LOGS_AVAILABLE"],
        )))
        if s.failed_console_logins > 0:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=f"Failed console logins observed: {s.failed_console_logins}",
                evidence=[ev],
                hypotheses_supported=["H_BEC_ACCOUNT_TAKEOVER", "H_BRUTE_FORCE"],
            )))
        for hv_name in {e["name"] for e in s.high_value_events}:
            count = sum(1 for e in s.high_value_events if e["name"] == hv_name)
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=f"High-value CloudTrail event: {hv_name} (×{count})",
                evidence=[ev],
                hypotheses_supported=["H_BEC_ACCOUNT_TAKEOVER"]
                                       if hv_name in ("ConsoleLogin", "AssumeRole",
                                                       "CreateLoginProfile",
                                                       "DeactivateMFADevice")
                                       else ["H_CLOUD_PERSISTENCE"],
            )))
        return out

    # ----- Azure sign-in logs -----

    def _run_azure_signin(self, ctx: AgentContext, analysis) -> list[Finding]:
        record_count, hits = asl.run_all(ctx.input_path)
        ev = self._build_evidence(ctx, "azure_signin", record_count,
                                    len(hits), analysis)
        out: list[Finding] = []
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Parsed {record_count} Azure sign-in record(s); "
                   f"{len(hits)} detector(s) fired."),
            evidence=[ev], hypotheses_supported=["H_CLOUD_LOGS_AVAILABLE"],
        )))
        for h in hits:
            confidence = self._signin_confidence(h)
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"Azure sign-in [{h.technique}/{h.subtechnique}] — "
                       f"{h.description}"),
                evidence=[ev],
                hypotheses_supported=_SIGNIN_TO_HYPOTHESIS.get(
                    h.technique, ["H_BEC_ACCOUNT_TAKEOVER"]),
            )))
        return out

    def _signin_confidence(self, hit) -> str:
        # Risky-signin + impossible-travel + legacy-auth are all
        # unambiguous single-event triggers → high. Brute/spray use
        # the ≥3-entity / ≥50-event tier matching EVTX credential_analyst.
        if hit.technique in ("risky_signin", "impossible_travel",
                              "legacy_auth"):
            return "high"
        if (len(hit.top_principals) >= 3 or len(hit.top_sources) >= 3
                or hit.event_count >= 50):
            return "high"
        return "medium"

    # ----- M365 Unified Audit Log -----

    def _run_m365_ual(self, ctx: AgentContext, analysis) -> list[Finding]:
        tenant_domains = self._tenant_domains_from_ctx(ctx)
        record_count, hits = ual.run_all(ctx.input_path, tenant_domains)
        ev = self._build_evidence(ctx, "m365_ual", record_count,
                                    len(hits), analysis)
        out: list[Finding] = []
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Parsed {record_count} M365 UAL record(s); "
                   f"{len(hits)} detector(s) fired."),
            evidence=[ev], hypotheses_supported=["H_CLOUD_LOGS_AVAILABLE"],
        )))
        for h in hits:
            confidence = self._ual_confidence(h)
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"M365 UAL [{h.technique}/{h.subtechnique}] — "
                       f"{h.description}"),
                evidence=[ev],
                hypotheses_supported=_UAL_TO_HYPOTHESIS.get(
                    h.technique, ["H_BEC_ACCOUNT_TAKEOVER"]),
            )))
        return out

    def _ual_confidence(self, hit) -> str:
        # BEC-persistence rule creation + OAuth consent grant → high;
        # spray/brute use the ≥3-entity tier.
        if hit.technique in ("inbox_rule_forward_external",
                              "oauth_consent_grant"):
            return "high"
        if (len(hit.top_principals) >= 3 or len(hit.top_sources) >= 3
                or hit.event_count >= 50):
            return "high"
        return "medium"

    def _tenant_domains_from_ctx(self, ctx: AgentContext) -> set[str]:
        """The operator can supply tenant domains via ctx.shared so
        external-forward detection is tenant-accurate. If absent, the
        detector falls back to "all email targets look external,"
        which errs on the side of flagging."""
        raw = ctx.shared.get("tenant_domains")
        if not raw:
            return set()
        if isinstance(raw, (list, tuple, set)):
            return {str(d).lower() for d in raw}
        if isinstance(raw, str):
            return {d.strip().lower() for d in raw.split(",") if d.strip()}
        return set()

    def _build_evidence(self, ctx: AgentContext, kind: str,
                         records: int, hit_count: int,
                         analysis: Path) -> EvidenceItem:
        import hashlib
        h = hashlib.sha256()
        try:
            with ctx.input_path.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except OSError:
            pass
        return EvidenceItem(
            tool=f"el.cloud_forensicator.{kind}", version="0.1.0",
            command=f"parse_and_detect({ctx.input_path.name})",
            output_sha256=h.hexdigest() or "0" * 64,
            output_path=str(ctx.input_path),
            extracted_facts={
                "kind": kind,
                "record_count": records,
                "hit_count": hit_count,
            },
        )
