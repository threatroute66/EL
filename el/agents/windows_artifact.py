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
from el.skills import csv_time_window, ezt


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


def _find_registry_dir(root: Path) -> Path | None:
    """Locate the directory containing system registry hives (SYSTEM,
    SOFTWARE, ...). DiskForensicator extracts them to a curated
    `registry/` dir; KAPE preserves the native Windows layout at
    `<drive>/Windows/System32/config/`. Try the curated name first, then
    fall back to the native location."""
    d = _finddir(root, "registry", "Registry")
    if d is not None:
        return d
    for p in root.rglob("System32/config/SYSTEM"):
        if p.is_file():
            return p.parent
    return None


def _kape_drive_root(kape_root: Path) -> Path | None:
    """Return the first drive-letter subdir under a KAPE output root
    that contains a Windows/ tree. None if not a KAPE shape."""
    for letter in ("C", "D", "E", "F"):
        d = kape_root / letter
        if d.is_dir() and (d / "Windows").is_dir():
            return d
    return None


def _stage_kape_layout(kape_root: Path, staged: Path) -> dict[str, int]:
    """Build a curated DiskForensicator-shaped symlink tree from a KAPE
    output dir into *staged*. Symlinks only — the original KAPE input
    is never modified or copied. After staging, the rest of
    WindowsArtifactAgent can treat *staged* as its `root` and existing
    parsers (which were built for DiskForensicator's layout) work
    unchanged. Returns per-artifact counts for evidence reporting."""
    counts: dict[str, int] = {
        "mft": 0, "usnjrnl": 0, "registry_hives": 0,
        "amcache": 0, "user_ntusers": 0, "user_usrclass": 0,
        "prefetch": 0, "winevt": 0, "srum": 0, "recyclebin": 0,
        "lnk_users": 0, "jumplists_users": 0,
        "ie_cache_users": 0, "clipboard_users": 0,
    }
    drive = _kape_drive_root(kape_root)
    if drive is None:
        return counts
    staged.mkdir(parents=True, exist_ok=True)

    def _link(src: Path, dst: Path) -> bool:
        if not src.exists():
            return False
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            if dst.is_symlink() or dst.exists():
                dst.unlink()
            dst.symlink_to(src.resolve())
            return True
        except OSError:
            return False

    if _link(drive / "$MFT", staged / "mft" / "$MFT"):
        counts["mft"] = 1
    # KAPE / KAPE-Targets can spell the $UsnJrnl:$J ADS several ways
    # because the literal colon is reserved on Linux filesystems.
    for jname in ("$J", "UsnJrnl_$J", "$UsnJrnl%3A$J", "$UsnJrnl_J"):
        for src in (drive / "$Extend" / jname, drive / jname):
            if _link(src, staged / "mft" / "$J"):
                counts["usnjrnl"] = 1
                break
        if counts["usnjrnl"]:
            break

    cfg = drive / "Windows" / "System32" / "config"
    for hive in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY"):
        if _link(cfg / hive, staged / "registry" / hive):
            counts["registry_hives"] += 1
    if _link(drive / "Windows" / "appcompat" / "Programs" / "Amcache.hve",
              staged / "registry" / "Amcache.hve"):
        counts["amcache"] = 1

    users_dir = drive / "Users"
    if users_dir.is_dir():
        for user_dir in sorted(users_dir.iterdir()):
            if not user_dir.is_dir():
                continue
            user = user_dir.name
            # Per-user registry hives — flatten into staged/registry/
            # with the same naming DiskForensicator uses
            # (NTUSER-<user>.DAT / UsrClass-<user>.DAT) so the existing
            # recent_docs glob (`NTUSER-*.DAT`) Just Works.
            if _link(user_dir / "NTUSER.DAT",
                      staged / "registry" / f"NTUSER-{user}.DAT"):
                counts["user_ntusers"] += 1
            if _link(user_dir / "AppData" / "Local" / "Microsoft"
                      / "Windows" / "UsrClass.dat",
                      staged / "registry" / f"UsrClass-{user}.DAT"):
                counts["user_usrclass"] += 1
            # Per-user Recent → lnk/<user>/ (LECmd -d recurses)
            recent = (user_dir / "AppData" / "Roaming" / "Microsoft"
                       / "Windows" / "Recent")
            if recent.is_dir() and _link(recent, staged / "lnk" / user):
                counts["lnk_users"] += 1
            # Per-user jumplists (Automatic + Custom) → jumplists/<user>-<kind>/
            jl_any = False
            for sub, tag in (("AutomaticDestinations", "automatic"),
                              ("CustomDestinations", "custom")):
                if _link(recent / sub,
                          staged / "jumplists" / f"{user}-{tag}"):
                    jl_any = True
            if jl_any:
                counts["jumplists_users"] += 1
            # Per-user IE/Edge legacy cache. find_index_dat_files
            # matches `content.ie5` / `history.ie5` / `cookies` as
            # substring of the lowercased full path, so the staged
            # directory name only needs to contain that token.
            ie_any = False
            ie_base = (user_dir / "AppData" / "Local" / "Microsoft"
                        / "Windows" / "Temporary Internet Files")
            for sub, tag in (("Content.IE5", "content.ie5"),
                              ("History.IE5", "history.ie5")):
                if _link(ie_base / sub,
                          staged / "ie_cache" / f"{user}-{tag}"):
                    ie_any = True
            ck = (user_dir / "AppData" / "Roaming" / "Microsoft"
                   / "Windows" / "Cookies")
            if _link(ck, staged / "ie_cache" / f"{user}-cookies"):
                ie_any = True
            if ie_any:
                counts["ie_cache_users"] += 1
            # Per-user UWP clipboard → uwp-clipboard/<user>/Clipboard/
            cb = (user_dir / "AppData" / "Local" / "Microsoft"
                   / "Windows" / "Clipboard")
            if cb.is_dir() and _link(
                    cb, staged / "uwp-clipboard" / user / "Clipboard"):
                counts["clipboard_users"] += 1

    if _link(drive / "Windows" / "Prefetch", staged / "Prefetch"):
        counts["prefetch"] = 1
    if _link(drive / "Windows" / "System32" / "winevt" / "Logs",
              staged / "winevt" / "Logs"):
        counts["winevt"] = 1
    if _link(drive / "Windows" / "System32" / "sru" / "SRUDB.dat",
              staged / "srum" / "SRUDB.dat"):
        counts["srum"] = 1
    if _link(drive / "$Recycle.Bin", staged / "$Recycle.Bin"):
        counts["recyclebin"] = 1
    return counts


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

        # KAPE preflight — if Triage tagged this as a KAPE collection,
        # build a curated-layout symlink tree under raw/kape-staged/ so
        # all per-user artifacts (NTUSER MRU, LNK Recent, jumplists,
        # IE cache, UWP clipboard) get walked rather than just the
        # first user the rglob-based finders happen to hit. The
        # original KAPE input is never written to.
        if ctx.shared.get("evidence_kind") == "kape-triage":
            staged = ctx.case_dir / "raw" / "kape-staged"
            counts = _stage_kape_layout(ctx.input_path, staged)
            if any(counts.values()):
                import hashlib as _hl
                ev = EvidenceItem(
                    tool="el.kape_stage", version="0.1.0",
                    command=(f"symlink curated layout from "
                              f"{ctx.input_path} → {staged}"),
                    output_sha256=_hl.sha256(
                        repr(sorted(counts.items())).encode()
                    ).hexdigest(),
                    output_path=str(staged),
                    extracted_facts=counts,
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="high",
                    claim=(f"KAPE curated-layout staging: "
                           f"NTUSER hives={counts['user_ntusers']}, "
                           f"UsrClass={counts['user_usrclass']}, "
                           f"LNK Recent users={counts['lnk_users']}, "
                           f"jumplist users={counts['jumplists_users']}, "
                           f"IE cache users={counts['ie_cache_users']}, "
                           f"clipboard users={counts['clipboard_users']}. "
                           f"Per-user artifacts now enumerated rather "
                           f"than first-match-only."),
                    evidence=[ev],
                    hypotheses_supported=["H_DISK_ARTIFACTS"],
                )))
                root = staged

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
        # Time-baseline (SYSTEM hive: TimeZoneInformation + W32Time
        # config). Emits a single per-case calibration Finding the
        # analyst can refer to when reading any other artifact time
        # — tells them the configured TZ + whether the clock was
        # NTP-synced (drift bounded) or NoSync (drift unbounded).
        # See el/skills/time_baseline.py for the doc string on why
        # this is a "document, don't correct" emission.
        out.extend(self._time_baseline(ctx, root, analysis))
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
        # Inventory-style findings for the small artifact buckets:
        # WER crash queue, thumb caches, SmartScreen AppCache.
        out.extend(self._inventory_finds(ctx, root))

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
        # Mine the parsed CSV output for an artifact-time window so this
        # "parsed successfully" finding lands on the kill-chain swimlane
        # at the artifact's real-world time range (e.g. EVTX 2008-07-19
        # → 2008-07-22) instead of falling back to EL's ingest time
        # (2026-…). Bounded helper — caps at 50 MB / 200k rows per file
        # so an EvtxECmd 5 GB output doesn't OOM the agent.
        facts: dict[str, str] = {}
        window = csv_time_window.scan_files(run.output_files)
        if window is not None:
            earliest, latest = window
            facts["earliest_utc"] = earliest.isoformat()
            if latest != earliest:
                facts["latest_utc"] = latest.isoformat()
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"{label}: parsed successfully",
            evidence=[run.as_evidence(facts=facts or None)],
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
        d = _find_registry_dir(root)
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
        d = _find_registry_dir(root)
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
            # Earliest modified_utc across suspects → top-level mtime_utc
            # so the kill-chain swimlane can place this finding on the
            # real-world clock. Per-suspect modified_utc is nested in
            # top_suspects[]; evidence_time mining only inspects
            # top-level keys, so an explicit lift is required.
            mtimes = [s.modified_utc for s in suspects if s.modified_utc]
            facts: dict = {
                "top_suspects": [
                    {"kind": s.kind, "url": s.url[:200],
                     "filename": s.filename,
                     "modified_utc": s.modified_utc,
                     "note": s.note}
                    for s in suspects[:30]
                ],
                "total_suspects": len(suspects),
            }
            if mtimes:
                facts["mtime_utc"] = min(mtimes)
                facts["mtime_latest_utc"] = max(mtimes)
            ev = EvidenceItem(
                tool="el.ie_cache", version="0.1.0",
                command="flag_suspects over parsed IE5 records",
                output_sha256="0" * 64,
                output_path=str(out_dir),
                extracted_facts=facts,
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

    def _time_baseline(self, ctx, root, analysis):
        """Read the SYSTEM hive for TimeZoneInformation + W32Time
        config, emit a single Finding documenting the system's
        configured TZ + sync state. The analyst uses this baseline
        to interpret any FAT / EXIF / Office-metadata local-time
        values elsewhere in the case. We deliberately do NOT modify
        artifact times — automated correction would invalidate the
        chain of custody for a delta the baseline alone can't
        precisely measure."""
        from el.schemas.finding import EvidenceItem
        from el.skills import time_baseline
        import hashlib

        system_hive = _findfirst(root, "SYSTEM")
        if not system_hive:
            return []
        tb = time_baseline.parse_system_hive(system_hive)
        if not tb.have_anything:
            note = "; ".join(tb.notes) if tb.notes else "no readable keys"
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"Time-baseline: SYSTEM hive opened but "
                       f"TimeZoneInformation + W32Time keys absent — "
                       f"clock calibration unavailable ({note})."),
            ))]
        # Build a readable one-liner for the report. Bias semantics:
        # Windows stores Bias / ActiveTimeBias as POSITIVE minutes when
        # the local clock is BEHIND UTC (e.g. PST=480, GMT=0, JST=-540).
        # Our parser already folds the unsigned-DWORD encoding back to
        # signed; for the narrative we flip the sign so a non-DFIR
        # reader sees the familiar UTC offset convention.
        utc_offset_h = ""
        if tb.tz_active_bias_minutes is not None:
            mins = -tb.tz_active_bias_minutes
            sign = "+" if mins >= 0 else "-"
            utc_offset_h = (f"UTC{sign}{abs(mins)//60:02d}:"
                            f"{abs(mins)%60:02d}")
        tz_summary = (f"{tb.tz_display_name or 'unknown TZ'}"
                      f" (active offset {utc_offset_h or 'unknown'})")
        last_change = (f"; W32Time config last touched "
                       f"{tb.w32time_config_last_write_utc[:19]}"
                       if tb.w32time_config_last_write_utc else "")
        ev = EvidenceItem(
            tool="el.time_baseline", version="0.1.0",
            command=f"parse_system_hive({system_hive.name})",
            output_sha256=hashlib.sha256(
                system_hive.read_bytes()).hexdigest(),
            output_path=str(system_hive),
            extracted_facts={
                "control_set": tb.control_set,
                "tz_standard_name": tb.tz_standard_name,
                "tz_daylight_name": tb.tz_daylight_name,
                "tz_key_name": tb.tz_key_name,
                "tz_display_name": tb.tz_display_name,
                "tz_bias_minutes": tb.tz_bias_minutes,
                "tz_active_bias_minutes": tb.tz_active_bias_minutes,
                "w32time_type": tb.w32time_type,
                "w32time_ntp_server": tb.w32time_ntp_server,
                "w32time_config_last_write_utc":
                    tb.w32time_config_last_write_utc,
                "sync_state": tb.sync_state_label,
                "phase": "time_baseline",
            },
        )
        # Sync state drives a single-bit clock-trust signal:
        #   NTP / NT5DS → drift bounded, clock trustworthy
        #   NoSync       → drift unbounded, treat times with caution
        #   anything else → unknown — surface but don't editorialise
        trust = "trustworthy" if tb.w32time_type.upper() in (
            "NTP", "NT5DS") else "drift unbounded — treat with caution" \
            if tb.w32time_type.upper() == "NOSYNC" else "trust unknown"
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Time-baseline (calibration only — no times modified): "
                   f"TZ = {tz_summary}; sync = {tb.sync_state_label}; "
                   f"clock {trust}{last_change}. Apply this when reading "
                   f"any FAT / EXIF / Office-metadata local-time values."),
            evidence=[ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))]

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

    def _inventory_finds(self, ctx, root):
        """Emit one Finding per non-empty inventory bucket: WER crash
        reports, thumb caches, SmartScreen AppCache. Each is a
        directory + file-count signal — full per-record parsers can
        come later when a real case demands them."""
        from el.schemas.finding import EvidenceItem
        import hashlib

        out = []
        buckets = [
            ("wer", "Windows Error Reporting crash queue",
             "Crashes often coincide with exploitation attempts "
             "(unhandled exceptions in shellcode, DLL hijacks). "
             "Each subdir is one crash; Report.wer text gives the "
             "crashing executable + reason.",
             ["H_DISK_ARTIFACTS", "H_PROCESS_INJECTION"]),
            ("thumbcache", "Windows Explorer thumb caches",
             "Embedded-JPEG thumbnails of files the user opened. "
             "Survives deletion of the source — useful when a file "
             "was wiped but its thumbnail is still cached.",
             ["H_DISK_ARTIFACTS"]),
            ("smartscreen", "SmartScreen AppCache reputation log",
             "Records SmartScreen-vetted downloads + reputation "
             "decisions. Useful for tracking what Windows Defender's "
             "URL/file-reputation service saw on this host.",
             ["H_DISK_ARTIFACTS"]),
        ]
        for sub, label, why, hyps in buckets:
            d = _finddir(root, sub)
            if d is None:
                d = _finddir(root, "windows-artifacts", sub)
            if d is None:
                continue
            files = [f for f in d.rglob("*") if f.is_file()]
            if not files:
                continue
            sample = ", ".join(sorted({f.parent.name for f in files})[:5])
            sha_seed = "|".join(sorted(str(f) for f in files))
            sha = hashlib.sha256(sha_seed.encode()).hexdigest()
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="medium",
                claim=(f"{label}: {len(files)} file(s) extracted "
                       f"under {d.name}/. {why} "
                       f"Subdirs sampled: {sample}."),
                evidence=[EvidenceItem(
                    tool="el.windows_artifact", version="0.1.0",
                    command=f"inventory({sub})",
                    output_sha256=sha, output_path=str(d),
                    extracted_facts={
                        "bucket": sub,
                        "file_count": len(files),
                        "subdirs_sample": sorted({
                            f.parent.name for f in files})[:8],
                    })],
                hypotheses_supported=hyps,
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
