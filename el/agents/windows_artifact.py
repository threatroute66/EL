"""Windows Artifact Agent — process an extracted-artifacts directory.

Expected input layout (any subset is OK; missing pieces become 'insufficient'
findings, not failures):

  <artifacts_dir>/
    mft/$MFT
    mft/$J                       (or $UsnJrnl/$J)
    registry/SYSTEM
    registry/SOFTWARE
    registry/SECURITY
    registry/SAM
    registry/Amcache.hve
    registry/<USER>/NTUSER.DAT   (and UsrClass.dat)
    Prefetch/  (or  prefetch/)
    winevt/Logs/  (or  evtx/)
    srum/SRUDB.dat
    recyclebin/
    jumplists/
    lnk/
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import ezt


def _findfirst(root: Path, *patterns: str) -> Path | None:
    for pat in patterns:
        for p in root.rglob(pat):
            if p.is_file():
                return p
    return None


def _finddir(root: Path, *names: str) -> Path | None:
    for n in names:
        for p in root.rglob(n):
            if p.is_dir():
                return p
    return None


class WindowsArtifactAgent(Agent):
    name = "windows_artifact"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        if not ctx.input_path.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="Windows Artifact Agent expects a directory input",
            ))]

        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)
        root = ctx.input_path

        out.extend(self._mft(ctx, root, analysis))
        out.extend(self._usnjrnl(ctx, root, analysis))
        out.extend(self._registry_batch(ctx, root, analysis))
        out.extend(self._amcache(ctx, root, analysis))
        out.extend(self._appcompat(ctx, root, analysis))
        out.extend(self._prefetch(ctx, root, analysis))
        out.extend(self._evtx(ctx, root, analysis))
        out.extend(self._srum(ctx, root, analysis))
        out.extend(self._shellbags(ctx, root, analysis))
        out.extend(self._jumplists(ctx, root, analysis))
        out.extend(self._lnk(ctx, root, analysis))
        out.extend(self._recyclebin(ctx, root, analysis))
        # BAM/DAM (SYSTEM hive) and Windows Timeline (ActivitiesCache.db)
        # — both already extracted by DiskForensicator; consume them here.
        out.extend(self._bam_dam(ctx, root, analysis))
        out.extend(self._win_timeline(ctx, root, analysis))
        out.extend(self._recent_docs(ctx, root, analysis))
        # T3-3: remote-access tooling (TeamViewer + AnyDesk) — any
        # inbound session from an unknown peer is high-signal even
        # when the tool is legitimately installed.
        out.extend(self._remote_access(ctx, root, analysis))

        if all(f.confidence == "insufficient" for f in out):
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"No recognised Windows artifacts found under {root.name}",
            )))
        return out

    def _try(self, ctx: AgentContext, label: str, fn) -> list[Finding]:
        try:
            run = fn()
        except ezt.EztError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"{label}: {e}",
            ))]
        if run.rc != 0:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"{label}: rc={run.rc} (see {run.stderr_path.name})",
            ))]
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"{label}: parsed successfully",
            evidence=[run.as_evidence()],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))]

    def _mft(self, ctx, root, analysis):
        p = _findfirst(root, "$MFT", "MFT")
        if not p:
            return []
        return self._try(ctx, f"MFTECmd $MFT ({p.name})",
                         lambda: ezt.run_mftecmd(p, analysis / "mft"))

    def _usnjrnl(self, ctx, root, analysis):
        p = _findfirst(root, "$J", "$UsnJrnl_$J", "UsnJrnl_J")
        if not p:
            return []
        return self._try(ctx, f"MFTECmd $UsnJrnl/$J ({p.name})",
                         lambda: ezt.run_usnjrnl(p, analysis / "usnjrnl"))

    def _registry_batch(self, ctx, root, analysis):
        d = _finddir(root, "registry", "Registry")
        if not d:
            return []
        return self._try(ctx, f"RECmd batch ({d.name})",
                         lambda: ezt.run_recmd(d, analysis / "registry"))

    def _amcache(self, ctx, root, analysis):
        p = _findfirst(root, "Amcache.hve", "amcache.hve")
        if not p:
            return []
        return self._try(ctx, f"AmcacheParser ({p.name})",
                         lambda: ezt.run_amcache(p, analysis / "amcache"))

    def _appcompat(self, ctx, root, analysis):
        p = _findfirst(root, "SYSTEM")
        if not p:
            return []
        return self._try(ctx, f"AppCompatCacheParser shimcache ({p.name})",
                         lambda: ezt.run_appcompat(p, analysis / "shimcache"))

    def _prefetch(self, ctx, root, analysis):
        d = _finddir(root, "Prefetch", "prefetch")
        if not d:
            return []
        return self._try(ctx, f"PECmd Prefetch ({d.name})",
                         lambda: ezt.run_pecmd(d, analysis / "prefetch"))

    def _evtx(self, ctx, root, analysis):
        d = _finddir(root, "evtx", "Logs", "winevt")
        if not d:
            d = root if any(p.suffix.lower() == ".evtx" for p in root.rglob("*.evtx")) else None
        if not d:
            return []
        return self._try(ctx, f"EvtxECmd ({d.name})",
                         lambda: ezt.run_evtxecmd(d, analysis / "evtx"))

    def _srum(self, ctx, root, analysis):
        p = _findfirst(root, "SRUDB.dat")
        if not p:
            return []
        software = _findfirst(root, "SOFTWARE")
        return self._try(ctx, f"SrumECmd ({p.name})",
                         lambda: ezt.run_srumecmd(p, analysis / "srum",
                                                   software_hive=software))

    def _shellbags(self, ctx, root, analysis):
        d = _finddir(root, "registry", "Registry")
        if not d:
            return []
        return self._try(ctx, f"SBECmd shellbags ({d.name})",
                         lambda: ezt.run_sbecmd(d, analysis / "shellbags"))

    def _jumplists(self, ctx, root, analysis):
        d = _finddir(root, "jumplists", "JumpLists",
                     "AutomaticDestinations", "CustomDestinations")
        if not d:
            return []
        return self._try(ctx, f"JLECmd ({d.name})",
                         lambda: ezt.run_jlecmd(d, analysis / "jumplists"))

    def _lnk(self, ctx, root, analysis):
        d = _finddir(root, "lnk", "Recent")
        if not d:
            return []
        return self._try(ctx, f"LECmd ({d.name})",
                         lambda: ezt.run_lecmd(d, analysis / "lnk"))

    def _recyclebin(self, ctx, root, analysis):
        d = _finddir(root, "recyclebin", "$Recycle.Bin")
        if not d:
            return []
        return self._try(ctx, f"RBCmd ({d.name})",
                         lambda: ezt.run_rbcmd(d, analysis / "recyclebin"))

    def _bam_dam(self, ctx, root, analysis):
        """Walk the SYSTEM hive's BAM/DAM subtree and surface per-user
        last-run executable evidence. Suspicious paths (Temp / AppData
        / Downloads / ProgramData) emit at high confidence tagged for
        H_APT_ESPIONAGE + H_PROCESS_INJECTION."""
        from el.schemas.finding import EvidenceItem
        from el.skills import bam_dam
        import hashlib

        system_hive = _findfirst(root, "SYSTEM")
        if not system_hive:
            return []
        entries = bam_dam.parse_system_hive(system_hive)
        if not entries:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"BAM/DAM: no entries parsed from {system_hive.name}. "
                       f"Expected on pre-Win10-1709 images or hives where "
                       f"BAM was cleared."),
            ))]
        summary = bam_dam.summarise(entries)
        ev = EvidenceItem(
            tool="el.bam_dam", version="0.1.0",
            command=f"parse_system_hive({system_hive.name})",
            output_sha256=hashlib.sha256(
                system_hive.read_bytes()).hexdigest(),
            output_path=str(system_hive),
            extracted_facts={
                "total_entries": summary.total_entries,
                "per_sid_counts": summary.per_sid,
                "suspicious_path_count": len(summary.suspicious),
            },
        )
        out = [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"BAM/DAM parsed: {summary.total_entries} last-run "
                   f"record(s) across {len(summary.per_sid)} user SID(s). "
                   f"Per-user execution ledger (Windows 10/11) — every "
                   f"executable each user ran, with last-run timestamp."),
            evidence=[ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))]
        if summary.suspicious:
            samples = "; ".join(
                f"{e.executable[-60:]} @ {e.last_run_utc[:19]}"
                for e in summary.suspicious[:5])
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"BAM/DAM suspicious-path execution: "
                       f"{len(summary.suspicious)} entry(ies) whose "
                       f"executable path sits in a user-writable "
                       f"marker dir (Temp / AppData / Downloads / "
                       f"ProgramData / Public). Samples: {samples}"),
                evidence=[ev],
                hypotheses_supported=["H_APT_ESPIONAGE",
                                       "H_PROCESS_INJECTION"],
            )))
        return out

    def _recent_docs(self, ctx, root, analysis):
        """Parse every NTUSER.DAT in exports/windows-artifacts/registry/
        for RecentDocs + OpenSave MRU entries. Emit one per-user
        summary + one suspicious-path finding when any entry points
        at a user-writable marker directory."""
        from el.schemas.finding import EvidenceItem
        from el.skills import recent_docs
        import hashlib

        reg_dir = _finddir(root, "registry", "Registry")
        if not reg_dir:
            return []
        ntusers = sorted(p for p in reg_dir.glob("NTUSER-*.DAT")
                         if p.is_file())
        if not ntusers:
            return []
        all_entries: list[recent_docs.RecentDocEntry] = []
        for hive in ntusers:
            all_entries.extend(recent_docs.parse_recentdocs(hive))
        if not all_entries:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"RecentDocs/OpenSave-MRU: {len(ntusers)} "
                       f"NTUSER.DAT hive(s) parsed but no MRU entries "
                       f"recovered. Hives may be dirty without LOG "
                       f"companions (see PR-A), or the user didn't "
                       f"interact via Explorer / common dialogs."),
            ))]
        summary = recent_docs.summarise(all_entries)

        hasher = hashlib.sha256()
        for p in ntusers:
            try:
                hasher.update(p.read_bytes())
            except OSError:
                continue
        ev = EvidenceItem(
            tool="el.recent_docs", version="0.1.0",
            command=f"parse_recentdocs(×{len(ntusers)} NTUSER hive(s))",
            output_sha256=hasher.hexdigest(),
            output_path=str(reg_dir),
            extracted_facts={
                "total_entries": summary.total_entries,
                "per_extension": summary.per_extension,
                "per_source": summary.per_source,
                "suspicious_count": len(summary.suspicious),
            },
        )
        out = [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"RecentDocs/OpenSave-MRU: {summary.total_entries} "
                   f"file-touch record(s) recovered from "
                   f"{len(ntusers)} NTUSER.DAT hive(s) "
                   f"(RecentDocs={summary.per_source.get('recentdocs', 0)}, "
                   f"OpenSaveMRU={summary.per_source.get('opensave', 0)}). "
                   f"Per-user file-access ledger — survives "
                   f"Timeline / Jump-List clearing."),
            evidence=[ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))]
        if summary.suspicious:
            sample = "; ".join(
                f"{e.filename[-60:]} @ {e.last_write_utc[:19] or '?'}"
                for e in summary.suspicious[:5])
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"RecentDocs/OpenSave-MRU suspicious-path "
                       f"entry: {len(summary.suspicious)} file "
                       f"reference(s) in user-writable marker dirs "
                       f"(Temp / AppData / Downloads / ProgramData / "
                       f"Public). Samples: {sample}"),
                evidence=[ev],
                hypotheses_supported=["H_APT_ESPIONAGE",
                                       "H_PROCESS_INJECTION"],
            )))
        return out

    def _remote_access(self, ctx, root, analysis):
        """Scan extracted remote_access/ for TeamViewer + AnyDesk logs.
        Inbound sessions always emit at high confidence (attacker-
        invoked tools often produce no other artifact), outbound
        AnyDesk at medium (legitimate admin use is common)."""
        from el.schemas.finding import EvidenceItem
        from el.skills import remote_access_apps as raa
        import hashlib

        ra_dir = _finddir(root, "remote_access")
        if not ra_dir:
            return []
        hits = raa.run_all(ra_dir)
        if not hits:
            return []
        # Build one shared evidence item hashing the whole dir
        hasher = hashlib.sha256()
        for p in sorted(ra_dir.rglob("*")):
            if p.is_file():
                try:
                    hasher.update(p.read_bytes())
                except OSError:
                    continue
        ev = EvidenceItem(
            tool="el.remote_access_apps", version="0.1.0",
            command=f"run_all({ra_dir.name})",
            output_sha256=hasher.hexdigest(),
            output_path=str(ra_dir),
            extracted_facts={
                "hit_count": len(hits),
                "apps": sorted({hit.app for hit in hits}),
            },
        )
        out = []
        for h in hits:
            # Inbound sessions are always high: an inbound TeamViewer
            # session from an unknown peer is exactly the shape of
            # attacker tooling, even on a box where TV is legitimately
            # installed. Outbound AnyDesk at medium — admin use
            # collides frequently with that pattern.
            if h.technique == "outbound_session":
                confidence = "medium"
            else:
                confidence = "high"
            peers = ", ".join(
                f"{peer} (×{count})" for peer, count in h.top_peers[:5])
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"Remote-access {h.app} {h.technique}: "
                       f"{h.event_count} session(s) recorded; "
                       f"first={h.first_seen or '?'}, "
                       f"last={h.last_seen or '?'}. Top peers: {peers}."),
                evidence=[ev],
                hypotheses_supported=["H_C2_OR_REVERSE_SHELL",
                                       "H_APT_ESPIONAGE",
                                       "H_LATERAL_MOVEMENT"],
            )))
        return out

    def _win_timeline(self, ctx, root, analysis):
        """Parse every ActivitiesCache.db under the timeline export dir.
        Emits one summary Finding plus one suspicious-entry finding
        when any activity's app/file/URI sits in a user-writable
        marker directory."""
        from el.schemas.finding import EvidenceItem
        from el.skills import win_timeline as wt
        import hashlib

        timeline_dir = _finddir(root, "timeline")
        if not timeline_dir:
            return []
        # extract_windows_artifacts prefixes each file with
        # `<user>--L.<user>--` for uniqueness, so the actual filename
        # looks like "alice--L.alice--ActivitiesCache.db". Glob for the
        # suffix rather than exact name, and exclude the -wal/-shm
        # sidecars which aren't standalone databases.
        dbs = sorted(
            p for p in timeline_dir.rglob("*ActivitiesCache.db")
            if p.is_file() and not p.name.endswith(("-wal", "-shm"))
        )
        if not dbs:
            return []
        all_entries: list[wt.TimelineEntry] = []
        for db in dbs:
            all_entries.extend(wt.parse_activities_cache(db))
        if not all_entries:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"Windows Timeline: found {len(dbs)} "
                       f"ActivitiesCache.db file(s) but none held a "
                       f"readable Activity table. DB may be corrupted "
                       f"or Timeline feature was disabled."),
            ))]
        suspicious = wt.suspicious_entries(all_entries)
        top_apps = wt.summarise_apps(all_entries, top_n=10)

        # Hash all DBs together for a single evidence item
        h = hashlib.sha256()
        for db in dbs:
            h.update(db.read_bytes())
        ev = EvidenceItem(
            tool="el.win_timeline", version="0.1.0",
            command=f"parse_activities_cache(×{len(dbs)})",
            output_sha256=h.hexdigest(),
            output_path=str(timeline_dir),
            extracted_facts={
                "db_count": len(dbs),
                "activity_count": len(all_entries),
                "suspicious_count": len(suspicious),
                "top_apps": top_apps,
            },
        )
        out = [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Windows Timeline parsed: {len(all_entries)} "
                   f"activity record(s) across {len(dbs)} "
                   f"ActivitiesCache.db file(s). Timeline records "
                   f"foreground-app usage + document / URI touches "
                   f"per user per foreground app."),
            evidence=[ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))]
        if suspicious:
            samples = "; ".join(
                f"{(e.app_path or e.file_path or e.target_uri)[-60:]} @ "
                f"{e.start_time_utc[:19] or e.last_modified_utc[:19]}"
                for e in suspicious[:5])
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Windows Timeline suspicious-path activity: "
                       f"{len(suspicious)} record(s) referencing an "
                       f"executable or file in a user-writable "
                       f"marker dir (Temp / AppData / Downloads / "
                       f"ProgramData / Public). Samples: {samples}"),
                evidence=[ev],
                hypotheses_supported=["H_APT_ESPIONAGE",
                                       "H_PROCESS_INJECTION"],
            )))
        return out
