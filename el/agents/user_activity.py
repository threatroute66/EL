"""User-activity agent — per-Windows-user project-access timeline from RAM.

Chains after ``MemoryForensicatorAgent`` when the image is Windows. For
each per-user NTUSER hive found in memory, emits Findings for:

  * Office MRU per-file last-open timeline (Word/Excel/PowerPoint),
    decoded from the ``[F…][T<filetime>][O…]*path`` REG_SZ values.
    This is the highest-fidelity user-document timeline available
    from a memory image alone — every entry carries a FILETIME-level
    last-open timestamp tied to a specific Microsoft account.
  * Drive-letter ↔ USB-device map at acquisition (from
    ``MountedDevices``), so the agent can recognise paths that
    actually live on removable media.
  * Insider-staging signal — when an Office MRU path resolves to a
    removable drive letter *and* the path contains corporate-project
    fragments (e.g. ``SRL-Projects - Megaforce``), the agent emits a
    Finding tagged ``H_INSIDER_DATA_STAGING`` + ``H_INSIDER_DATA_EXFIL``.
  * TypedPaths — the most-recent folders the user typed into the
    Explorer address bar (intentional navigation signal).

Like every EL agent, this one is rule-based. The LLM does not score
or interpret here; ACH does the scoring downstream via the
hypothesis library.
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import user_activity_memory as ua
from el.skills import vol3


_MAX_TIMELINE_ROWS = 25         # rows quoted in the high-level claim
_MAX_STAGING_ROWS = 20          # ditto for staging-signal pretty list


class UserActivityAgent(Agent):
    """Per-user activity reconstruction from a Windows memory image."""

    name = "user_activity"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        if ctx.shared.get("mem_os") != "windows":
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=("UserActivityAgent only runs on Windows memory images; "
                       f"current OS family = {ctx.shared.get('mem_os')!r}."),
            ))]

        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        # 1. Hive enumeration. Re-use the MemoryForensicator's hivelist
        # output when present (cheap to re-parse from disk); otherwise
        # run vol3 fresh.
        memfor_dir = ctx.case_dir / "analysis" / "memory_forensicator"
        hivelist_json = memfor_dir / "windows_registry_hivelist_HiveList.json"
        if hivelist_json.is_file():
            import json
            try:
                rows = json.loads(hivelist_json.read_text())
            except json.JSONDecodeError:
                rows = []
        else:
            try:
                r = vol3.run_plugin(ctx.input_path,
                                     "windows.registry.hivelist",
                                     analysis, timeout=600)
                rows = r.rows
            except vol3.Vol3Error as e:
                return [self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=f"hivelist failed: {e}",
                ))]

        user_hives = ua.find_user_hives(rows)
        # Dedup on (user, file basename) — keep just NTUSER.DAT per user
        # for the printkey passes (UsrClass.dat is a separate sweep we
        # don't run yet).
        seen_users: set[str] = set()
        per_user_hives: list[ua.HiveSummary] = []
        for h in user_hives:
            if h.user.lower() in seen_users:
                continue
            if "ntuser.dat" not in h.file_full_path.lower():
                continue
            per_user_hives.append(h)
            seen_users.add(h.user.lower())

        if not per_user_hives:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("No per-user NTUSER.DAT hive found in memory — "
                       "either no user has logged on or the hive cells "
                       "have been paged out. No user-activity timeline "
                       "reconstructible."),
            ))]

        for hive in per_user_hives:
            try:
                run = ua.run_for_user(ctx.input_path, analysis, hive)
            except vol3.Vol3Error as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=f"user_activity skill failed for {hive.user}: {e}",
                )))
                continue

            out.extend(self._emit_office_mru(ctx, run))
            out.extend(self._emit_drive_map(ctx, run))
            out.extend(self._emit_typedpaths(ctx, run))
            out.extend(self._emit_staging(ctx, run))

        return out

    # ------------------------------------------------------------------
    # Per-section emitters

    def _emit_office_mru(self, ctx: AgentContext,
                          run: ua.UserActivityRun) -> list[Finding]:
        if not run.office_mru:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"User '{run.user}': no Office MRU items decoded. "
                       "Likely no Word/Excel/PowerPoint use, or the MRU "
                       "subkeys are not pool-resident in this memory image."),
            ))]
        files = [e for e in run.office_mru if e.kind == "File"]
        if not files:
            return []
        head = files[:_MAX_TIMELINE_ROWS]
        pretty = "; ".join(
            f"[{e.opened_utc}] {e.app}/{e.account} {e.path}"
            for e in head
        )
        extra = "" if len(files) <= _MAX_TIMELINE_ROWS else \
            f" (+{len(files) - _MAX_TIMELINE_ROWS} more)"
        ev = run.as_evidence(run.office_mru_path,
                              facts={"office_mru_count": len(run.office_mru),
                                     "file_items": len(files)})
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name,
            claim=(f"User '{run.user}' Office MRU timeline — "
                   f"{len(files)} file open(s) recovered with per-file "
                   f"FILETIME last-open. {pretty}{extra}"),
            confidence="high", evidence=[ev],
        ))]

    def _emit_drive_map(self, ctx: AgentContext,
                          run: ua.UserActivityRun) -> list[Finding]:
        if not run.drive_map:
            return []
        rows = "; ".join(f"{m.letter}: {m.backing}" for m in run.drive_map)
        usb_count = sum(1 for m in run.drive_map if m.usb_serial)
        ev = run.as_evidence(run.mounted_devices_path,
                              facts={"letters_total": len(run.drive_map),
                                     "letters_removable": usb_count})
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name,
            claim=(f"Drive-letter map at acquisition ({len(run.drive_map)} "
                   f"letter(s), {usb_count} removable): {rows}"),
            confidence="high" if usb_count else "low", evidence=[ev],
        ))]

    def _emit_typedpaths(self, ctx: AgentContext,
                          run: ua.UserActivityRun) -> list[Finding]:
        if not run.typedpaths:
            return []
        pretty = " | ".join(run.typedpaths)
        ev = run.as_evidence(run.typedpaths_path,
                              facts={"typedpaths_count": len(run.typedpaths)})
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name,
            claim=(f"User '{run.user}' TypedPaths — last folders typed "
                   f"into Explorer address bar: {pretty}"),
            confidence="medium", evidence=[ev],
        ))]

    def _emit_staging(self, ctx: AgentContext,
                        run: ua.UserActivityRun) -> list[Finding]:
        if not run.staging_signals:
            return []
        head = run.staging_signals[:_MAX_STAGING_ROWS]
        pretty = "; ".join(
            f"[{s.entry.opened_utc}] {s.entry.path} "
            f"(letter {s.letter} = USB {s.usb_serial})"
            for s in head
        )
        extra = "" if len(run.staging_signals) <= _MAX_STAGING_ROWS else \
            f" (+{len(run.staging_signals) - _MAX_STAGING_ROWS} more)"
        ev = run.as_evidence(run.office_mru_path,
                              facts={"signals": len(run.staging_signals),
                                     "letters": sorted({s.letter for s in run.staging_signals})})
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name,
            # The claim text intentionally includes 'usb', 'removable',
            # and 'stage' so the keyword-based H_INSIDER_DATA_EXFIL
            # scorer in el.intel.hypotheses lifts on this Finding
            # *in addition* to the explicit tag.
            claim=(f"Removable-media staging signal for user '{run.user}': "
                   f"{len(run.staging_signals)} corporate-project file(s) "
                   "opened from a removable USB drive letter — possible "
                   f"exfil staging. {pretty}{extra}"),
            confidence="high", evidence=[ev],
            hypotheses_supported=["H_INSIDER_DATA_STAGING",
                                   "H_INSIDER_DATA_EXFIL"],
        ))]


__all__ = ["UserActivityAgent"]
