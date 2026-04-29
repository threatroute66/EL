"""RecoveryAgent — automated artifact recovery when anti-forensic
signals fire.

Triggers when DiskForensicator's run produced one or more of:
  * MACB_TIMESTOMP_SKEW          — file timestamps tampered
  * SYSTEM_BINARY_ZERO_SIZE      — system binary contents emptied
  * SYSTEM_BINARY_ZERO_TIMESTAMPS — system binary timestamps zeroed
  * security_log_cleared          — Security event log wiped (EID 1102)
  * vssadmin_delete_shadows       — Volume Shadow Copies deleted

The detection means real artifacts have been hidden or destroyed;
the originals or related fragments may still exist in unallocated
space, slack, or volume shadow copies. This agent runs the two
court-vetted recovery tools (tsk_recover for filesystem-aware
recovery, bulk_extractor for content-blind feature carving) and
emits Findings for what was recovered.

Forensic discipline:
  * Recovered artifacts carry confidence='low' — they're real
    evidence but with weaker provenance than parsed filesystem entries.
  * Wall-time caps: 600s per partition for tsk_recover, 600s total
    for bulk_extractor. A noisy carve must not dominate the run.
  * Outputs land under cases/<id>/exports/recovery/, separately
    from analysis/ so a re-run of the agent is safe (we delete
    the prior recovery dir on entry).
  * If carving finds a file whose name matches a deleted/zeroed
    system binary referenced in the trigger findings, an additional
    "recovery corroborates anti-forensic activity" finding is emitted
    that links both finding_ids.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.evidence.ledger import list_findings
from el.schemas.finding import Finding


# Substring tokens we look for in disk_forensicator claim text. Match
# against the lowercased claim — these are the canonical detector
# pattern_id strings emitted by el.skills.disk_anomaly.
_TRIGGERS = (
    "macb_timestomp_skew",
    "system_binary_zero_size",
    "system_binary_zero_timestamps",
    "security_log_cleared",
    "vssadmin_delete_shadows",
)


# Curated bulk_extractor scanner set. The default-on set blows up
# runtime on any disk with significant slack/unallocated; we run
# only the scanners whose output is high-signal in DFIR. Comments
# in el/skills/bulk_extractor.py document the full valid set.
_BE_SCANNERS_DISABLE = (
    "aes",          # AES key carving — slow + low-signal for our purposes
    "wordlist",     # Default-off anyway, but explicit for clarity
    "hiberfile",    # Hibernation file processing — heavy
    "evtx",         # We already parse EVTX via EvtxECmd; redundant
    "httplogs",     # Heavy I/O on disk images; we use Zeek/Suricata for HTTP
)

# Hard wall-time caps (seconds). Keep recovery bounded.
_TSK_RECOVER_TIMEOUT = 600
_BULK_EXTRACTOR_TIMEOUT = 600


def _triggers_present(findings: list[Finding]) -> list[Finding]:
    """Return the subset of `findings` whose claim contains any of
    the trigger pattern tokens. These become the corroboration anchors."""
    hits: list[Finding] = []
    for f in findings:
        if (f.agent or "") != "disk_forensicator":
            continue
        if f.confidence == "insufficient":
            continue
        claim_lc = (f.claim or "").lower()
        if any(t in claim_lc for t in _TRIGGERS):
            hits.append(f)
    return hits


def _zeroed_or_wiped_basenames(triggers: list[Finding]) -> set[str]:
    """Pull basenames out of the SYSTEM_BINARY_ZERO_* trigger claims.
    Used downstream to cross-reference recovered files against the
    binaries that were wiped, surfacing corroboration when carve
    pulls one of them back from unallocated space.

    Case-insensitive on the prefix because Windows path casing
    varies by version: modern installs use "/Windows/System32/"
    while XP-era images (M57-Jean) use "/WINDOWS/system32/".
    The basename casing is preserved (lowered) so cross-reference
    against recovered file basenames stays consistent."""
    import re
    names: set[str] = set()
    pattern = re.compile(r"/windows/system32/([\w.\-]+)", re.IGNORECASE)
    for f in triggers:
        # Detector claims look like:
        #   "Disk anomaly [SYSTEM_BINARY_ZERO_SIZE] ... Samples:
        #    /Windows/System32/comres.dll (deleted); ..."
        for m in pattern.finditer(f.claim or ""):
            names.add(m.group(1).lower())
    return names


def _find_recovered_basenames(root: Path, target_names: set[str]) -> set[str]:
    """Targeted scan: for the specific small set of `target_names`
    (binary basenames extracted from anti-forensic trigger claims),
    walk the recovery tree once and return the subset that exist.

    Stops early once every target has been matched. The earlier
    "walk everything, intersect" approach was capped at 5000 files
    to bound runtime, but real recovery dirs (M57-Jean: 31,419
    files) overshoot the cap before reaching the wiped binaries
    in /WINDOWS/system32/, so the corroboration finding silently
    failed to fire. A name-targeted walk has no such pathology."""
    import os as _os
    found: set[str] = set()
    targets_lower = {n.lower() for n in target_names}
    if not targets_lower:
        return found
    for dirpath, _dirnames, filenames in _os.walk(root):
        for fn in filenames:
            low = fn.lower()
            if low in targets_lower:
                found.add(low)
                if found >= targets_lower:
                    return found
    return found


class RecoveryAgent(Agent):
    name = "recovery"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []

        # 1. Trigger gate. No anti-forensic signals → no recovery.
        all_findings = list_findings(ctx.case_dir, case_id=ctx.case_id)
        triggers = _triggers_present(all_findings)
        if not triggers:
            # Silent no-op — emitting a "skipped" finding adds noise
            # to every clean case. The recommendations rule already
            # knows to suppress the recovery pivot when no triggers
            # fired, so absence is the right signal.
            return out

        # 2. Locate the raw image. Re-mount the EWF if the input is
        # an .E01 (disk_forensicator unmounted before we got here).
        from el.skills import sleuthkit as sk
        raw_input = Path(ctx.shared.get("raw_input_path") or ctx.input_path)
        partitions = ctx.shared.get("partitions") or []

        mount_point = None
        if raw_input.suffix.lower() in (".e01", ".e02"):
            mount_point = Path("/tmp/el-mounts") / f"{ctx.case_id}-recovery"
            try:
                raw_image = sk.ewfmount(raw_input, mount_point, timeout=60)
            except Exception as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=(f"Anti-forensic triggers fired ({len(triggers)}) "
                            f"but recovery skipped: ewfmount failed ({e})."),
                )))
                return out
        else:
            raw_image = raw_input

        try:
            # 3. Set up output dirs. Idempotent: wipe a prior recovery
            # subtree so reruns don't double-count.
            recovery_root = Path(ctx.case_dir) / "exports" / "recovery"
            if recovery_root.exists():
                shutil.rmtree(recovery_root)
            tsk_root = recovery_root / "tsk_recover"
            be_root = recovery_root / "bulk_extractor"
            tsk_root.mkdir(parents=True, exist_ok=True)
            # NOTE: we don't create be_root — bulk_extractor refuses
            # to write into a non-empty dir, and creating it empty is
            # fine, but the wrapper does it. Keep be_root as the
            # target only.

            # 4. Per-partition tsk_recover into exports/recovery/tsk_recover/
            #    Each partition is independent; we keep going on individual
            #    failures. Mode "all" includes both allocated + unallocated;
            #    that's the right call here because anti-forensics may have
            #    moved files between states. Capture sample sizes for the
            #    Finding text.
            wiped_names = _zeroed_or_wiped_basenames(triggers)
            corroborated: list[tuple[str, str]] = []  # (filename, partition_slot)
            recovery_summaries: list[str] = []
            for p in partitions:
                slot = str(p.get("slot") or "0")
                start = int(p.get("start_sector") or 0)
                desc = str(p.get("description") or "")
                # Skip metadata + empty partitions — they have no
                # recoverable filesystem.
                if start <= 0 or "Unallocated" in desc or "Meta" in desc:
                    continue
                part_dir = tsk_root / f"slot{slot}"
                try:
                    run = sk.tsk_recover(
                        raw_image, part_dir, mode="all",
                        offset=start, timeout=_TSK_RECOVER_TIMEOUT,
                    )
                except Exception as e:
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="insufficient",
                        claim=(f"tsk_recover failed for slot{slot} "
                                f"({desc}): {e}"),
                    )))
                    continue
                # Count what landed
                file_count = sum(1 for _ in part_dir.rglob("*") if _.is_file())
                if file_count == 0:
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="insufficient",
                        claim=(f"tsk_recover slot{slot} ({desc}) recovered "
                                f"0 files (rc={run.rc}) — partition may be "
                                f"empty, encrypted, or filesystem unsupported."),
                        evidence=[run.as_evidence({"phase": "recovery",
                                                    "slot": slot,
                                                    "files_recovered": 0})],
                    )))
                    continue
                # Cross-reference recovered basenames against the wiped
                # system-binary names from triggers. Targeted scan —
                # only looks for the specific names we care about, no
                # full-tree walk required.
                if wiped_names:
                    recovered_matches = _find_recovered_basenames(
                        part_dir, wiped_names,
                    )
                    for n in recovered_matches:
                        corroborated.append((n, slot))
                recovery_summaries.append(
                    f"slot{slot} ({desc}): {file_count} files"
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="low",
                    claim=(f"Recovered {file_count} file(s) from slot{slot} "
                            f"({desc}) via tsk_recover. Files written to "
                            f"{part_dir}. Recovered evidence has weaker "
                            f"provenance than parsed-filesystem entries — "
                            f"treat as lead, not proof."),
                    evidence=[run.as_evidence({"phase": "recovery",
                                                "slot": slot,
                                                "files_recovered": file_count})],
                    hypotheses_supported=["H_ANTI_FORENSICS"],
                )))

            # 5. Corroboration findings — when carve recovered a file
            #    whose name matches a SYSTEM_BINARY_ZERO_* trigger, link
            #    the original anti-forensic finding to the recovered
            #    artifact. This is the "we ran recovery and it confirms
            #    the tampering" payoff.
            if corroborated:
                # Group by filename for readability.
                from collections import defaultdict
                by_name: dict[str, list[str]] = defaultdict(list)
                for name, slot in corroborated:
                    by_name[name].append(slot)
                anchor_ids = ", ".join(t.finding_id for t in triggers[:3])
                samples = "; ".join(
                    f"{n} (slot{','.join(slots)})"
                    for n, slots in sorted(by_name.items())[:5]
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="medium",
                    claim=(f"Recovery corroborates anti-forensic activity: "
                            f"{len(by_name)} system binary name(s) flagged "
                            f"as wiped/zeroed are also present in recovered "
                            f"unallocated space. Sample: {samples}. "
                            f"Anchored to triggers: {anchor_ids}."),
                    evidence=triggers[0].evidence[:1] if triggers[0].evidence else [],
                    hypotheses_supported=["H_ANTI_FORENSICS"],
                )))

            # 6. bulk_extractor on the whole raw stream. One run for
            #    the entire image — features merge across partitions.
            from el.skills import bulk_extractor as be
            try:
                be_run = be.scan(
                    raw_image, be_root,
                    disable_scanners=list(_BE_SCANNERS_DISABLE),
                    timeout=_BULK_EXTRACTOR_TIMEOUT,
                )
            except be.BulkExtractorError as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=f"bulk_extractor failed: {e}",
                )))
            else:
                features = be_run.features()
                if features:
                    top = ", ".join(
                        f"{k}={v}" for k, v in
                        sorted(features.items(), key=lambda kv: -kv[1])[:6]
                    )
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="low",
                        claim=(f"bulk_extractor surfaced {len(features)} "
                                f"feature class(es) from the raw stream. "
                                f"Top: {top}. Output: {be_root}."),
                        evidence=[be_run.as_evidence({"phase": "recovery"})],
                        hypotheses_supported=["H_ANTI_FORENSICS"],
                    )))
                else:
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="insufficient",
                        claim=("bulk_extractor ran but produced no "
                                "non-empty feature files — image may be "
                                "encrypted, sparse, or unreadable."),
                        evidence=[be_run.as_evidence({"phase": "recovery"})],
                    )))

        finally:
            # 7. Always tear down the mount even on failure.
            if mount_point is not None:
                try:
                    sk.ewfumount(mount_point)
                except Exception:
                    pass

        return out
