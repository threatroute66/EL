"""Cloud Forensicator — AWS CloudTrail (initial scope).

Routes on file content: a JSON file whose first non-whitespace token is
'{' and which contains '"Records"' and 'eventName' is treated as
CloudTrail. Future scope: Azure activity logs, GCP audit logs.
"""
from __future__ import annotations

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import cloudtrail


CT_HINTS = (b'"eventName"', b'"eventSource"', b'"awsRegion"')


class CloudForensicatorAgent(Agent):
    name = "cloud_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        try:
            with ctx.input_path.open("rb") as f:
                head = f.read(8192)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Cannot read input: {e}",
            ))]

        if not any(h in head for h in CT_HINTS):
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="Input does not look like CloudTrail (no eventName/eventSource/awsRegion)",
            ))]

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
