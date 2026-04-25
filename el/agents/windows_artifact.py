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
from el.schemas.finding import EvidenceItem, Finding
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
        out.extend(self._ie_cache(ctx, root, analysis))
        # T3-3: remote-access tooling (TeamViewer + AnyDesk) — any
        # inbound session from an unknown peer is high-signal even
        # when the tool is legitimately installed.
        out.extend(self._remote_access(ctx, root, analysis))
        # IIS W3C logs under inetpub/logs/LogFiles — web-shell
        # uploads, admin-panel hits, scripted-client recon. First-
        # order evidence for every Windows web/mail/RDS server.
        out.extend(self._iis_w3c(ctx, root, analysis))
        # UWP / Cloud-Clipboard items — Win10 1809+ pinned + recent
        # clipboard contents under AppData\Local\Microsoft\Windows\
        # Clipboard\. High-signal user-activity artefact missed by
        # ActivitiesCache.db alone.
        out.extend(self._uwp_clipboard(ctx, root, analysis))
        # CapabilityAccessManager ConsentStore — last-used timestamps
        # for per-app sensitive capabilities (camera/mic/location/
        # contacts/files). Surfaces use by sandboxed UWP apps that
        # don't appear in Prefetch.
        out.extend(self._capability_access(ctx, root, analysis))
        # UAL .mdb under Windows\System32\LogFiles\Sum\ — Windows
        # Server per-user/per-IP role-access logs. Highest-signal
        # artifact on a server case for "who logged in from where".
        out.extend(self._ual(ctx, root, analysis))

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
            d = root if any(p.suffix.lower() == ".evtx"
                             for p in root.rglob("*")
                             if p.is_file()) else None
        if d:
            return self._try(ctx, f"EvtxECmd ({d.name})",
                             lambda: ezt.run_evtxecmd(d, analysis / "evtx"))
        # No EVTX found — fall back to XP / 2003 legacy .evt. This
        # closes the M57-Jean gap where credential_analyst and
        # lateral_movement_analyst landed on confidence=insufficient
        # because no evtx_parsed.csv existed. Converting the three
        # standard .evt files (SecEvent, AppEvent, SysEvent) into an
        # EvtxECmd-shaped CSV lets the downstream agents consume them.
        # Case-insensitive suffix match so we catch XP's `SecEvent.Evt`
        # / `.EVT` / etc. on case-sensitive Linux filesystems.
        evt_files = sorted([p for p in root.rglob("*")
                            if p.is_file()
                            and p.suffix.lower() == ".evt"])
        if evt_files:
            return self._convert_xp_evt(ctx, evt_files, analysis)
        return []

    def _convert_xp_evt(self, ctx, evt_files, analysis):
        from el.skills import xp_evt
        out: list[Finding] = []
        evtx_dir = analysis / "evtx"
        evtx_dir.mkdir(parents=True, exist_ok=True)
        csv_out = evtx_dir / "evtx_parsed.csv"
        parent_dir = evt_files[0].parent
        try:
            run = xp_evt.convert_all_evt(
                parent_dir, csv_out, evtx_dir / "raw")
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"XP .evt conversion failed: {e}",
            ))]
        if run.event_count == 0:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"Legacy .evt files present ({len(evt_files)} "
                       f"under {parent_dir.name}) but evtexport produced "
                       f"no parsable records."),
                evidence=[run.as_evidence()],
            ))]
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Legacy XP/2003 .evt → EVTX-shaped CSV conversion: "
                   f"{run.event_count} record(s) from "
                   f"{len(evt_files)} .evt file(s) at "
                   f"{parent_dir.name}. Downstream credential / lateral "
                   f"/ sigma analysts can now consume "
                   f"analysis/windows_artifact/evtx/evtx_parsed.csv."),
            evidence=[run.as_evidence()],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))
        return out

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

    def _ie_cache(self, ctx, root, analysis):
        """Parse legacy IE5 Content.IE5 / index.dat records. Surfaces
        tracker-sync URLs, raw-IP hosts, unusual TLDs — the M57-Jean
        jynxora signal (Content.IE5 session-hijack JS under the
        Administrator profile)."""
        from el.skills import ie_cache
        out: list[Finding] = []
        index_dats = ie_cache.find_index_dat_files(root)
        if not index_dats:
            return out
        all_items: list = []
        sources: list[str] = []
        out_dir = analysis / "ie_cache"
        out_dir.mkdir(parents=True, exist_ok=True)
        for i, idx in enumerate(index_dats[:50]):
            sources.append(str(idx))
            try:
                run = ie_cache.parse(
                    idx, out_dir / f"{i:03d}_{idx.parent.name}.txt")
            except Exception:
                continue
            all_items.extend(run.items)
        if not all_items:
            return out
        suspects = ie_cache.flag_suspects(all_items)
        # Volume finding
        summary_ev = EvidenceItem(
            tool="el.ie_cache", version="0.1.0",
            command=(f"msiecfexport over {len(index_dats)} "
                     f"index.dat file(s)"),
            output_sha256="0" * 64,
            output_path=str(out_dir),
            extracted_facts={
                "index_dat_count": len(index_dats),
                "item_count": len(all_items),
                "suspects_by_kind": {
                    k: sum(1 for s in suspects if s.kind == k)
                    for k in ("raw_ip", "unusual_tld",
                               "tracker_sync", "long_query")},
                "sources": sources[:10],
            },
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"IE5 Content.IE5 cache parsed: {len(index_dats)} "
                   f"index.dat file(s), {len(all_items)} record(s). "
                   f"Suspicious: "
                   f"{sum(1 for s in suspects if s.kind == 'raw_ip')} raw-IP, "
                   f"{sum(1 for s in suspects if s.kind == 'unusual_tld')} unusual-TLD, "
                   f"{sum(1 for s in suspects if s.kind == 'tracker_sync')} tracker-sync URL(s)."),
            evidence=[summary_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))
        if suspects:
            sample = "; ".join(
                f"[{s.kind}] {s.url[:80]} ({s.filename})"
                for s in suspects[:5])
            ev = EvidenceItem(
                tool="el.ie_cache", version="0.1.0",
                command="flag_suspects over parsed IE5 records",
                output_sha256="0" * 64,
                output_path=str(out_dir),
                extracted_facts={
                    "top_suspects": [
                        {"kind": s.kind, "url": s.url[:200],
                         "filename": s.filename,
                         "modified_utc": s.modified_utc,
                         "note": s.note}
                        for s in suspects[:30]
                    ],
                    "total_suspects": len(suspects),
                },
            )
            has_tracker = any(s.kind == "tracker_sync" for s in suspects)
            hyp = (["H_INITIAL_ACCESS_WEB", "H_BEC_ACCOUNT_TAKEOVER"]
                   if has_tracker
                   else ["H_OPPORTUNISTIC_COMMODITY"])
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"IE5 cache suspicious URLs: {len(suspects)} "
                       f"row(s) flagged ({sum(1 for s in suspects if s.kind == 'tracker_sync')} "
                       f"tracker-sync / session-hijack JS pattern(s), "
                       f"{sum(1 for s in suspects if s.kind == 'raw_ip')} raw-IP, "
                       f"{sum(1 for s in suspects if s.kind == 'unusual_tld')} unusual-TLD). "
                       f"Sample: {sample}"),
                evidence=[ev],
                hypotheses_supported=hyp,
            )))
        return out

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

    def _iis_w3c(self, ctx, root, analysis):
        """Scan extracted IIS logs under `inetpub/logs/LogFiles/W3SVC*/`.

        Emits one Finding per detector per site, confidence keyed to
        pattern severity (webshell-URI / upload-burst → high; admin-
        panel / scripted-offensive → high; generic scripted + verb-
        tunnel → medium). Silent when the directory isn't extracted
        (most non-server images don't have IIS)."""
        from el.schemas.finding import EvidenceItem
        from el.skills import iis_w3c
        import hashlib

        iis_root = None
        for candidate in (
            _finddir(root, "inetpub", "logs", "LogFiles"),
            _finddir(root, "inetpub", "LogFiles"),
            _finddir(root, "IIS", "Logs"),
            _finddir(root, "iis_logs"),
        ):
            if candidate:
                iis_root = candidate
                break
        if iis_root is None:
            return []

        results = iis_w3c.scan_tree(iis_root)
        if not results:
            return []

        # Dir-level hash for shared evidence record
        hasher = hashlib.sha256()
        for p in sorted(iis_root.rglob("u_ex*.log"))[:200]:
            try:
                hasher.update(p.read_bytes())
            except OSError:
                continue

        high_severity = {"W3C_WEBSHELL_URI_SHAPE",
                         "W3C_UPLOAD_POST_BURST",
                         "W3C_SCRIPTED_CLIENT_OFFENSIVE",
                         "W3C_ADMIN_URI_HIT"}
        out = []
        for r in results:
            if not r.hits:
                continue
            for h in r.hits:
                confidence = "high" if h.pattern_id in high_severity else "medium"
                sample = "; ".join(h.matches[:3])
                ev = EvidenceItem(
                    tool="el.iis_w3c", version="0.1.0",
                    command=f"scan_path({r.path.name})",
                    output_sha256=hasher.hexdigest(),
                    output_path=str(r.path),
                    extracted_facts={
                        "pattern_id": h.pattern_id,
                        "match_count": h.count,
                        "parsed_rows": r.parsed_rows,
                        "techniques": [tid for tid, _ in h.attack_techniques],
                    },
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence=confidence,
                    claim=(f"IIS W3C log [{h.pattern_id}] in "
                           f"{r.path.name}: {h.description}. "
                           f"{h.count} match(es). Samples: {sample}."),
                    evidence=[ev],
                    hypotheses_supported=h.hypotheses,
                )))
        return out

    def _ual(self, ctx, root, analysis):
        """Parse every UAL .mdb extracted into exports/ual/ via
        esedbexport, surface the CLIENTS table top-N rows as
        Findings. One Finding per .mdb (rollup) plus per-row Findings
        for the top access-count rows."""
        from el.schemas.finding import EvidenceItem
        from el.skills import ual as ual_skill
        import hashlib

        ual_dir = _finddir(root, "ual")
        if not ual_dir:
            return []
        if not ual_skill.is_ual_available():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("UAL .mdb files extracted but `esedbexport` not "
                       "on PATH (install libesedb-tools — SIFT default)."),
            ))]

        export_dir = analysis / "ual"
        out = []
        for mdb in sorted(ual_dir.glob("*.mdb")):
            db = ual_skill.export_database(mdb, export_dir)
            sha = hashlib.sha256(mdb.read_bytes()[:64*1024]).hexdigest()
            if db.error:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=(f"UAL {mdb.name} export failed: {db.error}"),
                    evidence=[EvidenceItem(
                        tool="esedbexport", version="libesedb-tools",
                        command=f"esedbexport -T … {mdb.name}",
                        output_sha256=sha, output_path=str(mdb),
                        extracted_facts={"error": db.error})],
                )))
                continue
            sample = "; ".join(
                f"{a.address} ({a.username or '?'}, {a.total_accesses}×)"
                for a in db.accesses[:5]
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="high" if db.accesses else "low",
                claim=(f"UAL {mdb.name}: {len(db.table_files)} table(s) "
                       f"exported; CLIENTS rows = {len(db.accesses)}. "
                       f"Top: {sample}" if db.accesses else
                       f"UAL {mdb.name}: parsed but CLIENTS table empty "
                       "(server hadn't logged any role accesses yet)."),
                evidence=[EvidenceItem(
                    tool="el.ual", version="0.1.0",
                    command=f"export_database({mdb.name})",
                    output_sha256=sha, output_path=str(mdb),
                    extracted_facts={
                        "tables": sorted(db.table_files.keys()),
                        "client_rows": len(db.accesses),
                        "top_5_addresses": [
                            a.address for a in db.accesses[:5]],
                    })],
                hypotheses_supported=["H_DISK_ARTIFACTS",
                                       "H_LATERAL_MOVEMENT"],
            )))
        return out

    def _capability_access(self, ctx, root, analysis):
        """Parse the SOFTWARE hive's CapabilityAccessManager
        ConsentStore. One Finding per (capability, app) pair with a
        last-used timestamp. Currently-in-use apps (LastUsedTimeStop=0
        with a non-zero LastUsedTimeStart) get high confidence — at
        acquisition time the camera / microphone / location was
        actually live."""
        from el.schemas.finding import EvidenceItem
        from el.skills import capability_access as ca
        import hashlib

        software = _findfirst(root, "SOFTWARE")
        if not software:
            return []
        try:
            uses = ca.parse_software_hive(software)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"CapabilityAccess parse failed: {e}",
            ))]
        if not uses:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("CapabilityAccess: SOFTWARE hive parsed but the "
                       "ConsentStore subtree is empty (pre-Win10-1903 "
                       "build, or the hive snapshot predates app "
                       "activity)."),
            ))]

        sha = hashlib.sha256(software.read_bytes()).hexdigest()
        in_use = [u for u in uses if u.in_use_at_acquisition]
        out = []
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="medium",
            claim=(f"CapabilityAccess: {len(uses)} app/capability "
                   f"record(s) under {len(set(u.capability for u in uses))} "
                   f"capabilities; {len(in_use)} were live at "
                   f"acquisition time."),
            evidence=[EvidenceItem(
                tool="el.capability_access", version="0.1.0",
                command="parse_software_hive(SOFTWARE)",
                output_sha256=sha,
                output_path=str(software),
                extracted_facts={
                    "uses_total": len(uses),
                    "in_use_at_acquisition": len(in_use),
                    "capabilities": sorted(set(u.capability for u in uses)),
                })],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        # In-use-at-acquisition is the highest-signal subset: camera /
        # microphone / location was being used right when the box was
        # imaged. One Finding per such record, capped to keep the
        # ledger tight.
        for u in in_use[:30]:
            high = u.capability.lower() in ca.HIGH_INTEREST_CAPABILITIES
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="high" if high else "medium",
                claim=(f"CapabilityAccess in-use at acquisition: "
                       f"{u.app} held {u.capability} "
                       f"(LastUsedStart={u.last_used_start_utc}, "
                       f"Stop=0 → still active)"),
                evidence=[EvidenceItem(
                    tool="el.capability_access", version="0.1.0",
                    command=f"capability={u.capability} app={u.app}",
                    output_sha256=sha, output_path=str(software),
                    extracted_facts={
                        "capability": u.capability,
                        "app": u.app,
                        "last_used_start_utc": u.last_used_start_utc,
                    })],
                hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
        return out

    def _uwp_clipboard(self, ctx, root, analysis):
        """Walk the per-user clipboard subtrees that
        `extract_windows_artifacts` staged under
        `windows-artifacts/uwp-clipboard/<user>/Clipboard/` and emit one
        Finding per clipboard format-file. Pinned items get medium
        confidence (deliberate user retention), recent items get low
        (rolling-window state)."""
        from el.schemas.finding import EvidenceItem
        from el.skills import uwp_clipboard as cb
        import hashlib

        cb_root = _finddir(root, "uwp-clipboard")
        if cb_root is None:
            cb_root = _finddir(root, "windows-artifacts", "uwp-clipboard")
        if cb_root is None:
            return []

        items = cb.walk_extracted_clipboard(cb_root)
        if not items:
            return []

        # One summary + per-item findings (capped to keep ledger tidy)
        out = []
        pinned = [i for i in items if i.pinned]
        recent = [i for i in items if not i.pinned]
        sha = hashlib.sha256(
            "|".join(str(i.format_file) for i in items).encode()
        ).hexdigest()
        summary_ev = EvidenceItem(
            tool="el.uwp_clipboard", version="0.1.0",
            command=f"walk_extracted_clipboard({cb_root.name})",
            output_sha256=sha,
            output_path=str(cb_root),
            extracted_facts={
                "items_total": len(items),
                "pinned": len(pinned),
                "recent": len(recent),
                "users": sorted({i.user for i in items}),
            },
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="medium",
            claim=(f"Windows Cloud-Clipboard: {len(items)} format-file(s) "
                   f"across {len(set(i.user for i in items))} user "
                   f"profile(s) — {len(pinned)} pinned + "
                   f"{len(recent)} recent. Pinned items are "
                   f"deliberately retained by the user; recent items "
                   f"are the rolling 7-day buffer."),
            evidence=[summary_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        for it in (pinned + recent)[:30]:   # cap per case
            try:
                ev_sha = hashlib.sha256(
                    it.format_file.read_bytes()).hexdigest()
            except OSError:
                ev_sha = "0" * 64
            ev = EvidenceItem(
                tool="el.uwp_clipboard", version="0.1.0",
                command=f"clipboard format file: {it.format_label}",
                output_sha256=ev_sha,
                output_path=str(it.format_file),
                extracted_facts={
                    "user": it.user,
                    "pinned": it.pinned,
                    "format": it.format_label,
                    "size": it.size,
                    "mtime_utc": it.mtime_utc,
                    "sample": it.sample,
                },
            )
            conf = "medium" if it.pinned else "low"
            sample_text = (it.sample or "(non-text format)").replace(
                "\n", " ")[:120]
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=conf,
                claim=(f"Cloud-Clipboard {'pinned' if it.pinned else 'recent'} "
                       f"item: user={it.user}, format={it.format_label}, "
                       f"size={it.size}, mtime={it.mtime_utc or '?'}. "
                       f"Sample: {sample_text!r}"),
                evidence=[ev],
                hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
        return out
