"""Disk Forensicator — Sleuth Kit + EZ Tools orchestration.

Current scope: raw disk images (dd / E01 mounted via ewfmount → raw).
For E01 inputs we surface the requirement for ewfmount as 'insufficient'
rather than silently degrading — keeps the contract honest.
"""
from __future__ import annotations

from pathlib import Path

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
            return self._handle_ewf(ctx, analysis)

        return out + self._raw_disk_walk(ctx, analysis, ctx.input_path)

    def _handle_ewf(self, ctx: AgentContext, analysis) -> list[Finding]:
        """E01 path: ewfinfo (metadata + chain of custody) → ewfmount → walk
        the exposed raw stream like any other disk image. Always unmounts
        in cleanup, even if downstream fls/mactime fail."""
        out: list[Finding] = []
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

        mount_point = Path("/tmp/el-mounts") / ctx.case_id
        try:
            raw = sk.ewfmount(ctx.input_path, mount_point, timeout=60)
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=f"E01 mounted via ewfmount; raw stream available at {raw}",
                evidence=[info.as_evidence({"phase": "ewfmount", "raw_device": str(raw)})],
            )))
        except sk.SleuthkitError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"ewfmount failed: {e}. Filesystem walk skipped.",
            )))
            return out

        try:
            out.extend(self._raw_disk_walk(ctx, analysis, raw))
        finally:
            sk.ewfumount(mount_point)
        return out

    def _raw_disk_walk(self, ctx: AgentContext, analysis, raw_image: Path) -> list[Finding]:
        """Walk a raw disk stream (.img, .dd, or ewfmount-exposed ewf1).
        img_stat → mmls → per-partition fls -o <offset> → mactime CSV."""
        out: list[Finding] = []
        try:
            stat = sk.img_stat(raw_image, analysis, timeout=60)
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

        partitions: list[dict] = []
        try:
            mmls_run = sk.mmls(raw_image, analysis, timeout=120)
            ev = mmls_run.as_evidence({"phase": "partition_table"})
            if mmls_run.rc == 0:
                partitions = sk.parse_mmls(mmls_run.stdout_path.read_text(errors="ignore"))
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim=f"Partition table parsed: {len(partitions)} usable partition(s)",
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

        # Per partition: fls -o <start_sector> → bodyfile → mactime
        # Per sleuthkit SKILL: -o flag is more reliable than loopback mount.
        if not partitions:
            try:
                fls_run = sk.fls(raw_image, analysis, timeout=1800)
                if fls_run.rc == 0 and fls_run.stdout_path.stat().st_size > 0:
                    out.extend(self._fls_to_timeline(ctx, fls_run, analysis,
                                                     part_label="whole-image"))
                else:
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                        claim=f"fls (no partition offset) produced no output (rc={fls_run.rc}); "
                              "image may have no recognised filesystem at offset 0",
                    )))
            except sk.SleuthkitError as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"fls unavailable: {e}",
                )))
            return out

        for p in partitions:
            label = f"slot{p['slot']}-off{p['start_sector']}"
            try:
                fls_run = sk.fls(raw_image, analysis,
                                 offset=p["start_sector"], timeout=1800)
            except sk.SleuthkitError as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"fls failed for partition {label} ({p['description']}): {e}",
                )))
                continue
            if fls_run.rc == 0 and fls_run.stdout_path.stat().st_size > 0:
                out.extend(self._fls_to_timeline(
                    ctx, fls_run, analysis, part_label=label,
                    desc=p["description"]))
            else:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"fls returned no rows for partition {label} ({p['description']}) "
                          f"— filesystem may be unreadable or unsupported",
                )))
        return out

    def _fls_to_timeline(self, ctx: AgentContext, fls_run: sk.TskRun, analysis,
                         part_label: str, desc: str = "") -> list[Finding]:
        out: list[Finding] = []
        ev_fls = fls_run.as_evidence({"phase": "filesystem_walk_bodyfile",
                                       "partition": part_label, "fs": desc})
        body_size = fls_run.stdout_path.stat().st_size
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"fls bodyfile produced for {part_label} ({desc}): {body_size} bytes",
            evidence=[ev_fls], hypotheses_supported=["H_DISK_IMAGE"],
        )))
        try:
            mt = sk.mactime(fls_run.stdout_path, analysis, timeout=600)
            if mt.rc == 0 and mt.stdout_path.stat().st_size > 0:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim=f"mactime CSV timeline generated from {part_label} bodyfile "
                          f"({mt.stdout_path.stat().st_size} bytes)",
                    evidence=[mt.as_evidence({"phase": "mactime_csv",
                                              "partition": part_label})],
                )))
            else:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"mactime returned no output for {part_label} (rc={mt.rc})",
                )))
        except sk.SleuthkitError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"mactime failed for {part_label}: {e}",
            )))
        return out
