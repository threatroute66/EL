"""Disk Forensicator — Sleuth Kit + EZ Tools orchestration.

Current scope: raw disk images (dd / E01 mounted via ewfmount → raw).
For E01 inputs we surface the requirement for ewfmount as 'insufficient'
rather than silently degrading — keeps the contract honest.
"""
from __future__ import annotations

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import sleuthkit as sk


class DiskForensicatorAgent(Agent):
    name = "disk_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        kind = ctx.shared.get("evidence_kind") or ""
        if "EWF" in kind:
            try:
                info = sk.ewfinfo(ctx.input_path, analysis, timeout=60)
                if info.rc == 0:
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name, confidence="high",
                        claim=f"EWF metadata captured (acquisition hashes recorded in {info.stdout_path.name})",
                        evidence=[info.as_evidence({"phase": "ewfinfo"})],
                        hypotheses_supported=["H_DISK_IMAGE"],
                    )))
            except sk.SleuthkitError as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"ewfinfo unavailable: {e}",
                )))
            return out + [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="EWF (E01) input requires ewfmount to expose a raw stream before fls/mactime can run; "
                      "ewfinfo metadata captured but full filesystem walk is gated on mount step",
            ))]

        try:
            stat = sk.img_stat(ctx.input_path, analysis, timeout=60)
            ev = stat.as_evidence({"phase": "img_stat"})
            txt = stat.stdout_path.read_text(errors="ignore").lower()
            sector_size = 4096 if "4096" in txt and "sector size" in txt else 512
            ctx.shared["sector_size"] = sector_size
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=f"img_stat reports sector size = {sector_size}; "
                      "(per sleuthkit SKILL: 4K drives need offset = start_sector × 4096)",
                evidence=[ev],
            )))
        except sk.SleuthkitError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"img_stat unavailable: {e}",
            )))

        try:
            mmls_run = sk.mmls(ctx.input_path, analysis, timeout=120)
            ev = mmls_run.as_evidence({"phase": "partition_table"})
            if mmls_run.rc == 0:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim=f"Partition table parsed by mmls (see {mmls_run.stdout_path.name})",
                    evidence=[ev], hypotheses_supported=["H_DISK_IMAGE"],
                )))
            else:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"mmls returned rc={mmls_run.rc} — input may not be a multi-partition disk image",
                )))
        except sk.SleuthkitError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"mmls unavailable or failed: {e}",
            )))

        try:
            fls_run = sk.fls(ctx.input_path, analysis, timeout=1800)
            ev = fls_run.as_evidence({"phase": "filesystem_walk_bodyfile"})
            if fls_run.rc == 0 and fls_run.stdout_path.stat().st_size > 0:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim=f"fls produced bodyfile ({fls_run.stdout_path.stat().st_size} bytes)",
                    evidence=[ev], hypotheses_supported=["H_DISK_IMAGE"],
                )))
                try:
                    mt = sk.mactime(fls_run.stdout_path, analysis, timeout=600)
                    if mt.rc == 0 and mt.stdout_path.stat().st_size > 0:
                        out.append(self.emit(ctx, Finding(
                            case_id=ctx.case_id, agent=self.name, confidence="high",
                            claim="mactime CSV timeline generated from bodyfile",
                            evidence=[mt.as_evidence({"phase": "mactime_csv"})],
                        )))
                except sk.SleuthkitError as e:
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                        claim=f"mactime failed: {e}",
                    )))
            else:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"fls produced no usable output (rc={fls_run.rc}); "
                          "input is likely not a recognised filesystem image",
                )))
        except sk.SleuthkitError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"fls unavailable or failed: {e}",
            )))

        return out
