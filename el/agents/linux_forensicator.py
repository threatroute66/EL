"""LinuxForensicator — consume the exports dir DiskForensicator
emits for Linux disk images, run the triage-detector suite, promote
hits into Findings.

Chained from the coordinator after DiskForensicator when
`ctx.shared["linux_artifacts_dir"]` is set (parallel to how
WindowsArtifactAgent is chained off `artifacts_dir`).

Confidence tiering per family:
  reverse_shell / credential_access / ld_so_preload — always high
    (single hit is unambiguous)
  ssh_brute / ssh_spray — high when the detector fires (thresholds
    already filter noise)
  persistence_{ssh,cron} / defense_evasion — high
  download_cradle / base64_pipe / priv_esc — medium (can be
    legitimate admin activity in isolation)
  cron_suspicious_path — medium
  ssh_authorized_keys_anomaly — medium (pentester-comment signal is
    strong; sheer key count can be noisy on shared hosts)
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import linux_triage as lt
from el.skills.father_rootkit_detection import detect_father_rootkit


_HIGH_FAMILIES = {
    "reverse_shell", "credential_access", "ld_so_preload",
    "ssh_brute", "ssh_spray", "persistence_ssh", "persistence_cron",
    "defense_evasion",
}


class LinuxForensicatorAgent(Agent):
    name = "linux_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        # Four input modes:
        # (1) Chained from DiskForensicator with extracted artifacts
        #     under <case_dir>/exports/linux-artifacts/ — the original
        #     wiring; ctx.shared["linux_artifacts_dir"] points there.
        # (2) Triage routed evidence_kind in {linux-fs-dir, qnap-nas-dir}
        #     — ctx.input_path is the mounted filesystem root itself,
        #     so we point the detectors directly at it. Validated on
        #     QNAP case 21APR_245 (mounted DataVol1).
        # (3) UAC collection artifacts from LiveResponseCollector
        #     — ctx.shared["uac_collection"] contains UAC output structure
        # (4) Default fallback: <case_dir>/exports/linux-artifacts/.
        kind = ctx.shared.get("evidence_kind") or ""

        # Check for UAC collection mode first
        if kind == "uac-collection" or ctx.shared.get("uac_collection"):
            return self._run_uac_analysis(ctx)

        exports = ctx.shared.get("linux_artifacts_dir")
        if not exports and kind in ("linux-fs-dir", "qnap-nas-dir"):
            exports = ctx.input_path
        # CyLR zip — auto-extract once into <case>/raw/cylr/ then
        # point the detectors at the resulting tree (which IS a
        # Linux FS root by construction: var/log/, etc/, home/...).
        # Idempotent: a re-render that finds the directory already
        # populated skips the extract.
        if not exports and kind == "cylr-collection":
            import zipfile
            extracted_dir = ctx.case_dir / "raw" / "cylr"
            extracted_dir.mkdir(parents=True, exist_ok=True)
            # Detect "already-extracted" by checking for the canonical
            # marker file at the expected location — re-extracting a
            # 24 MB zip every render is wasteful.
            already_extracted = any(
                extracted_dir.glob("CyLR_Collection_Log_*.log"))
            if not already_extracted:
                try:
                    with zipfile.ZipFile(ctx.input_path) as zf:
                        zf.extractall(extracted_dir)
                except (zipfile.BadZipFile, OSError) as e:
                    return [self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="insufficient",
                        claim=(f"CyLR zip extraction failed: {e}. "
                               "Pre-extract the archive and re-investigate "
                               "the resulting directory."),
                    ))]
            exports = extracted_dir
        if not exports:
            default = ctx.case_dir / "exports" / "linux-artifacts"
            if default.is_dir() and any(default.rglob("*")):
                exports = default
            else:
                return [self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=("LinuxForensicator: no Linux artifacts "
                           "directory produced by upstream "
                           "DiskForensicator. This case either isn't a "
                           "Linux disk image or the extraction failed."),
                ))]
        exports = Path(exports)

        hits = lt.run_all(exports)
        out: list[Finding] = []
        if not hits:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"LinuxForensicator: walked extracted artifacts at "
                       f"{exports.name}/ — no malicious-pattern / "
                       f"brute-force / preload / authorized-key / "
                       f"cron-suspicious hits from the linux_triage "
                       f"pattern library. Absence of evidence; not "
                       f"evidence of absence. utmp/wtmp/btmp + "
                       f"systemd-journal passes below still run."),
            )))

        # Shared evidence — hash the MANIFEST.txt the extractor wrote
        manifest = exports / "MANIFEST.txt"
        sha = "0" * 64
        if manifest.is_file():
            sha = hashlib.sha256(manifest.read_bytes()).hexdigest()

        for h in hits:
            confidence = "high" if h.family in _HIGH_FAMILIES else "medium"
            facts = {
                "family": h.family,
                "matched_pattern": h.matched_pattern,
                "event_count": h.event_count,
                "top_users": h.top_users,
                "source_files": h.source_files[:5],
                "attack_techniques": [t for t, _ in h.attack],
                "sample_text_head": h.sample_text[:200],
            }
            ev = EvidenceItem(
                tool="el.linux_triage", version="0.1.0",
                command=f"run_all({exports.name})",
                output_sha256=sha, output_path=str(manifest),
                extracted_facts=facts,
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"Linux {h.family}: {h.event_count} event(s) "
                       f"matched pattern {h.matched_pattern!r}. "
                       f"ATT&CK: "
                       f"{', '.join(t for t, _ in h.attack) or '-'}. "
                       f"Sample: {h.sample_text[:150]!r}"
                       + (f" (users: {', '.join(h.top_users[:3])})"
                          if h.top_users else "")),
                evidence=[ev],
                hypotheses_supported=lt.hypotheses_for(h.family)
                                       or ["H_APT_ESPIONAGE"],
            )))

        # Per-skill calls are wrapped so a single PermissionError
        # (root-only file in a mounted filesystem like QNAP's
        # .qcodesigning) doesn't take out the whole agent. The
        # offending skill emits an `insufficient` finding documenting
        # the gap; downstream skills still run.
        def _safe(label: str, fn, *args):
            try:
                return fn(*args)
            except (PermissionError, OSError) as e:
                return [self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=(f"{label}: skipped — filesystem walk hit "
                           f"a permission/IO error ({e}). Mount input "
                           "with broader read access or extract the "
                           "tree with `sudo cp -a` first."),
                ))]

        # utmp/wtmp/btmp binary parsing — login session forensics
        out.extend(_safe("utmp/wtmp/btmp",
                          self._analyze_utmp_family, ctx, exports))
        # systemd-journal — sshd/sudo/unit-start extraction
        out.extend(_safe("systemd-journal",
                          self._analyze_systemd_journal, ctx, exports))
        # Dotfile concealment directories (user parking binaries/archives/
        # PDFs/media inside a hidden dotfile dir — BelkaCTF-Kidnapper style)
        out.extend(_safe("dotfile-concealment",
                          self._analyze_dotfile_concealment, ctx, exports))
        # Encrypted ZIP archives (password-locked members)
        out.extend(_safe("encrypted-archives",
                          self._analyze_encrypted_archives, ctx, exports))
        # Extension-vs-MIME mismatch (extension-mangling concealment)
        out.extend(_safe("magic-mismatch",
                          self._analyze_magic_mismatch, ctx, exports))
        # Narcotic-lexicon keyword scan over user-home text files
        out.extend(_safe("narcotic-lexicon",
                          self._analyze_narcotic_lexicon, ctx, exports))
        # Thunderbird mbox walker — attachments + narcotic/BTC in bodies
        out.extend(_safe("thunderbird-mbox",
                          self._analyze_thunderbird_mbox, ctx, exports))
        # auditd structured event extraction (ausearch wrapper +
        # pure-python fallback over /var/log/audit/audit.log*)
        out.extend(_safe("auditd",
                          self._analyze_auditd, ctx, exports))
        # nginx / Apache access-log anomaly detector
        out.extend(_safe("webserver-access",
                          self._analyze_webserver_access, ctx, exports))
        # Rootkit scanners (chkrootkit / rkhunter / Lynis) — best-effort
        # against the mounted root. Each gracefully degrades when the
        # binary isn't installed.
        out.extend(_safe("rootkit-scanners",
                          self._analyze_rootkit_scanners, ctx, exports))
        # Father rootkit detection (LD_PRELOAD hijacking, magic GID, backdoor ports)
        out.extend(_safe("father-rootkit",
                          self._analyze_father_rootkit, ctx, exports))
        return out

    def _run_uac_analysis(self, ctx: AgentContext) -> list[Finding]:
        """
        Run Linux forensic analysis on UAC collection artifacts.

        Uses UAC live response data instead of traditional disk extraction,
        analyzing process snapshots, network connections, system files,
        and bodyfile timeline data collected by UAC.
        """
        out: list[Finding] = []
        uac_collection = ctx.shared.get("uac_collection")

        if not uac_collection:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim="LinuxForensicator UAC mode: no UAC collection data available",
            ))]

        # Extract UAC collection directory as analysis target
        uac_dir = Path(uac_collection.output_dir)

        # Run Father rootkit detection on full UAC structure
        # (includes chkrootkit/, live_response/, etc.)
        try:
            father_result = detect_father_rootkit(uac_dir.parent)
            if any([father_result.preload_path, father_result.config_gid,
                   father_result.source_port, father_result.silly_txt_present]):

                confidence = "high"
                claim_parts = []

                if father_result.preload_path:
                    claim_parts.append(f"LD_PRELOAD configuration at {father_result.preload_path}")
                if father_result.config_gid:
                    claim_parts.append(f"magic GID {father_result.config_gid}")
                if father_result.source_port:
                    claim_parts.append(f"SSH backdoor port {father_result.source_port}")
                if father_result.silly_txt_present:
                    claim_parts.append("credential harvest log present")

                evidence = father_result.as_evidence({
                    "uac_source": True,
                    "detection_method": "enhanced_multi_directory_search",
                })

                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence=confidence,
                    claim=f"Father rootkit detected: {'; '.join(claim_parts)}",
                    evidence=[evidence],
                    hypotheses_supported=["H_APT_ESPIONAGE", "H_PROCESS_INJECTION"],
                    hypotheses_refuted=["H_BENIGN_NO_INCIDENT"]
                )))

        except Exception as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"Father rootkit detection failed on UAC data: {e}",
            )))

        # Analyze UAC live response artifacts if available
        if uac_collection.live_response_dir:
            out.extend(self._analyze_uac_live_response(ctx, uac_collection))

        # Analyze UAC bodyfile if available
        if uac_collection.bodyfile_path:
            out.extend(self._analyze_uac_bodyfile(ctx, uac_collection))

        # Run malicious pattern detection on UAC text files
        out.extend(self._analyze_uac_pattern_detection(ctx, uac_collection))

        return out

    def _analyze_utmp_family(self, ctx: AgentContext,
                              exports: Path) -> list[Finding]:
        """Parse /var/log/wtmp + /var/log/btmp + /var/run/utmp. Emits:
          - volume finding per file
          - high-confidence brute-force finding if btmp has >= 5
            failed attempts against one account from one source
          - medium-confidence remote-root-login finding per wtmp row
          - medium credential-stuffing finding if one user auths from
            many sources
        """
        from el.skills import utmp as utmp_skill
        import hashlib
        out: list[Finding] = []
        candidates = [
            ("btmp", exports / "var" / "log" / "btmp"),
            ("wtmp", exports / "var" / "log" / "wtmp"),
            ("utmp", exports / "var" / "run" / "utmp"),
            # Some extracts route these to /exports/linux-artifacts/var/log/
            ("btmp", exports / "log" / "btmp"),
            ("wtmp", exports / "log" / "wtmp"),
        ]
        seen_paths: set[str] = set()
        btmp_records: list = []
        wtmp_records: list = []
        for kind, path in candidates:
            if not path.is_file():
                continue
            if str(path) in seen_paths:
                continue
            seen_paths.add(str(path))
            recs = utmp_skill.parse_file(path)
            if not recs:
                continue
            if kind == "btmp":
                btmp_records.extend(recs)
            elif kind == "wtmp":
                wtmp_records.extend(recs)
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            ev = EvidenceItem(
                tool="el.utmp", version="0.1.0",
                command=f"parse_file({kind}:{path.name})",
                output_sha256=sha, output_path=str(path),
                extracted_facts={
                    "kind": kind,
                    "record_count": len(recs),
                    "earliest": min((r.ts_utc for r in recs
                                       if r.ts_utc), default=""),
                    "latest": max((r.ts_utc for r in recs
                                     if r.ts_utc), default=""),
                    "distinct_users": len({r.user for r in recs
                                             if r.user}),
                    "sample": [
                        {"type": r.type_name, "user": r.user,
                         "tty": r.tty, "host": r.host,
                         "ts": r.ts_utc}
                        for r in recs[:5]
                    ],
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"{kind} parsed ({path.name}): {len(recs)} "
                       f"record(s) across "
                       f"{len({r.user for r in recs if r.user})} "
                       f"distinct user(s)."),
                evidence=[ev],
                hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))

        # Brute-force bursts from btmp
        if btmp_records:
            bursts = utmp_skill.failed_auth_bursts(btmp_records, threshold=5)
            for b in bursts:
                ev = EvidenceItem(
                    tool="el.utmp", version="0.1.0",
                    command="failed_auth_bursts(btmp)",
                    output_sha256="0" * 64,
                    output_path=str(exports),
                    extracted_facts={
                        "user": b.user, "source_host": b.source_host,
                        "count": b.count,
                        "first_ts_utc": b.first_ts_utc,
                        "last_ts_utc": b.last_ts_utc,
                        "sample_ttys": b.sample_ttys,
                    },
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="high",
                    claim=(f"btmp failed-auth burst: {b.count} failed "
                           f"login(s) for user {b.user!r} from "
                           f"{b.source_host!r} between {b.first_ts_utc} "
                           f"and {b.last_ts_utc} — brute-force or "
                           f"password-spray signature."),
                    evidence=[ev],
                    hypotheses_supported=["H_BRUTE_FORCE"],
                )))

        # Root-direct-remote-logins from wtmp
        if wtmp_records:
            roots = utmp_skill.root_direct_logins(wtmp_records)
            if roots:
                ev = EvidenceItem(
                    tool="el.utmp", version="0.1.0",
                    command="root_direct_logins(wtmp)",
                    output_sha256="0" * 64,
                    output_path=str(exports),
                    extracted_facts={
                        "count": len(roots),
                        "sample": [
                            {"ts": r.ts_utc, "tty": r.tty,
                             "host": r.host or r.addr, "pid": r.pid}
                            for r in roots[:5]
                        ],
                    },
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="medium",
                    claim=(f"wtmp: {len(roots)} direct remote root "
                           f"login(s) recorded. On hardened Linux hosts "
                           f"PermitRootLogin is typically `no`; remote "
                           f"root logins indicate either relaxed sshd "
                           f"config or compromise. Sample host: "
                           f"{(roots[0].host or roots[0].addr)!r} at "
                           f"{roots[0].ts_utc}."),
                    evidence=[ev],
                    hypotheses_supported=["H_LATERAL_MOVEMENT",
                                           "H_CREDENTIAL_ACCESS"],
                )))

            # Source-diversity signal (same user, many sources)
            div = utmp_skill.source_diversity(wtmp_records)
            for user, sources in div.items():
                if len(sources) < 10:
                    continue
                ev = EvidenceItem(
                    tool="el.utmp", version="0.1.0",
                    command="source_diversity(wtmp)",
                    output_sha256="0" * 64,
                    output_path=str(exports),
                    extracted_facts={
                        "user": user,
                        "source_count": len(sources),
                        "sample_sources": sorted(sources)[:10],
                    },
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="medium",
                    claim=(f"wtmp source-diversity: user {user!r} "
                           f"authenticated from {len(sources)} distinct "
                           f"source hosts/IPs — credential-stuffing or "
                           f"access-broker pattern."),
                    evidence=[ev],
                    hypotheses_supported=["H_BRUTE_FORCE"],
                )))
        return out

    def _analyze_systemd_journal(self, ctx: AgentContext,
                                   exports: Path) -> list[Finding]:
        """Walk /var/log/journal/ + run journalctl over it; emit
        sshd + sudo findings."""
        from el.skills import systemd_journal as jnl
        out: list[Finding] = []
        journal_candidates = [
            exports / "var" / "log" / "journal",
            exports / "log" / "journal",
        ]
        journal_dir = next(
            (p for p in journal_candidates if p.is_dir()), None)
        if not journal_dir:
            return out
        entries = jnl.parse_journal_dir(journal_dir)
        if not entries:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"systemd journal directory present at "
                       f"{journal_dir.name} but `journalctl` returned "
                       f"no records (timeout / permission / "
                       f"unreadable format)."),
            ))]

        ssh_events = jnl.extract_ssh_auth(entries)
        sudo_events = jnl.extract_sudo_invocations(entries)

        # Volume finding
        ev_summary = EvidenceItem(
            tool="el.systemd_journal", version="0.1.0",
            command=f"journalctl -o json on {journal_dir.name}",
            output_sha256="0" * 64, output_path=str(journal_dir),
            extracted_facts={
                "entry_count": len(entries),
                "ssh_event_count": len(ssh_events),
                "sudo_event_count": len(sudo_events),
                "distinct_units": len(
                    {e.unit for e in entries if e.unit}),
            },
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"systemd journal parsed: {len(entries)} entry(ies), "
                   f"{len(ssh_events)} ssh auth event(s), "
                   f"{len(sudo_events)} sudo/su invocation(s)."),
            evidence=[ev_summary],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        # SSH brute-force aggregation
        failed = [s for s in ssh_events if s.kind == "failed"]
        if len(failed) >= 5:
            by_source: dict[str, int] = {}
            for s in failed:
                if s.source_host:
                    by_source[s.source_host] = (
                        by_source.get(s.source_host, 0) + 1)
            top_sources = sorted(
                by_source.items(), key=lambda kv: -kv[1])[:5]
            ev = EvidenceItem(
                tool="el.systemd_journal", version="0.1.0",
                command="extract_ssh_auth(failed filter)",
                output_sha256="0" * 64, output_path=str(journal_dir),
                extracted_facts={
                    "failed_count": len(failed),
                    "top_source_hosts": top_sources,
                    "sample_events": [
                        {"user": s.user, "src": s.source_host,
                         "ts": s.ts_utc}
                        for s in failed[:10]
                    ],
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"systemd-journal sshd: {len(failed)} failed "
                       f"password event(s). Top source(s): "
                       f"{', '.join(f'{h}({c})' for h, c in top_sources)}."),
                evidence=[ev],
                hypotheses_supported=["H_BRUTE_FORCE"],
            )))

        # Sudo escalations
        if sudo_events:
            root_targets = [s for s in sudo_events
                             if s.as_user == "root"]
            ev = EvidenceItem(
                tool="el.systemd_journal", version="0.1.0",
                command="extract_sudo_invocations",
                output_sha256="0" * 64, output_path=str(journal_dir),
                extracted_facts={
                    "total_events": len(sudo_events),
                    "escalations_to_root": len(root_targets),
                    "distinct_invokers": len(
                        {s.user for s in sudo_events if s.user}),
                    "sample_commands": [
                        {"user": s.user, "as_user": s.as_user,
                         "cmd": s.command[:120], "ts": s.ts_utc}
                        for s in sudo_events[:8]
                    ],
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"systemd-journal sudo: {len(sudo_events)} "
                       f"sudo/su invocation(s), {len(root_targets)} "
                       f"escalation(s) to root across "
                       f"{len({s.user for s in sudo_events if s.user})} "
                       f"distinct invoker(s)."),
                evidence=[ev],
                hypotheses_supported=["H_LIVING_OFF_THE_LAND"],
            )))
        return out

    def _analyze_dotfile_concealment(self, ctx: AgentContext,
                                      exports: Path) -> list[Finding]:
        """Surface dotfile directories being used to park
        binaries / archives / office docs / media (concealment vector
        distinct from straight malware drop sites)."""
        from el.skills import dotfile_anomaly as da
        hits = da.walk(exports)
        out: list[Finding] = []
        for h in hits:
            ext_summary = ", ".join(f"{ext}={n}" for ext, n in
                                     sorted(h.ext_counts.items(),
                                            key=lambda kv: -kv[1])[:5])
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Dotfile concealment: {h.dotfile_dir.name} "
                       f"(user={h.user}) holds {h.suspicious_count} "
                       f"non-config file(s) out of {h.total_files}: "
                       f"{ext_summary}. Dotfile dirs outside the known "
                       f"config/cache allow-list rarely carry archives / "
                       f"PDFs / media in normal use."),
                evidence=[h.as_evidence()],
                hypotheses_supported=["H_INSIDER_DATA_EXFIL",
                                       "H_OPPORTUNISTIC_COMMODITY"],
            )))
        return out

    def _analyze_encrypted_archives(self, ctx: AgentContext,
                                     exports: Path) -> list[Finding]:
        """Flag ZIP archives containing password-protected entries."""
        from el.skills import encrypted_archive as ea
        hits = ea.walk(exports)
        out: list[Finding] = []
        for h in hits:
            sample = ", ".join(h.encrypted_members[:3])
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Encrypted archive: {h.archive_path.name} contains "
                       f"{h.encrypted_count}/{h.total_members} "
                       f"password-protected member(s): {sample}"
                       f"{' …' if h.encrypted_count > 3 else ''}. "
                       f"Encrypted ZIPs on a user desktop are an "
                       f"anti-forensic signal — ordinary workflows rarely "
                       f"produce them."),
                evidence=[h.as_evidence()],
                hypotheses_supported=["H_INSIDER_DATA_EXFIL"],
            )))
        return out

    def _analyze_magic_mismatch(self, ctx: AgentContext,
                                 exports: Path) -> list[Finding]:
        """Flag files whose declared extension disagrees with the MIME
        type that `file(1)` detects. Only surface when ≥1 hit fires."""
        from el.skills import magic_mismatch as mm
        try:
            hits = mm.walk(exports)
        except mm.MagicError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"magic_mismatch: {e} — skip extension-mangling scan.",
            ))]
        out: list[Finding] = []
        # Collapse bulk findings — one finding per case summarizing N
        # mismatches, plus a compact sample. Avoids findings-storm when
        # the image has thousands of spurious mismatches (it won't;
        # the MIME allow-list is narrow).
        if not hits:
            return out
        sample = [(str(h.path.name), h.declared_ext, h.detected_mime)
                   for h in hits[:5]]
        # Hash of the hit list for reproducibility
        import hashlib as _h
        seed = "\n".join(f"{h.path}|{h.declared_ext}|{h.detected_mime}"
                          for h in hits).encode()
        ev = EvidenceItem(
            tool="file(1)", version=mm._file_version(),
            command="file --mime-type (walk)",
            output_sha256=_h.sha256(seed).hexdigest(),
            output_path=str(exports),
            extracted_facts={"mismatch_count": len(hits),
                              "sample": sample,
                              "paths": [str(h.path) for h in hits[:25]]},
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="medium",
            claim=(f"Extension-vs-MIME mismatch: {len(hits)} file(s) "
                   f"declared one extension but were detected as a "
                   f"different format by file(1). Sample: {sample}. "
                   f"Extension mangling is a deliberate concealment move."),
            evidence=[ev],
            hypotheses_supported=["H_INSIDER_DATA_EXFIL"],
        )))
        return out

    def _analyze_narcotic_lexicon(self, ctx: AgentContext,
                                    exports: Path) -> list[Finding]:
        """Scan user text files for narcotic-trade keywords (strain names,
        unit/weight markers, price-per-unit patterns, emoji ciphers)."""
        from el.skills import narcotic_lexicon as nl
        homes = exports / "home"
        if not homes.is_dir():
            return []
        hits = nl.walk_files(homes)
        out: list[Finding] = []
        for m in hits:
            sig = m.signal_strength
            conf = "high" if sig == "high" else "medium"
            sample_strains = ", ".join(m.strain_hits[:3]) or "-"
            sample_units = ", ".join(m.unit_hits[:3]) or "-"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=conf,
                claim=(f"Narcotic-lexicon match in {m.path.name}: "
                       f"{len(m.strain_hits)} strain/product term(s), "
                       f"{len(m.unit_hits)} weight marker(s), "
                       f"{len(m.price_hits)} price-per-unit pattern(s). "
                       f"Strains: [{sample_strains}]. "
                       f"Units: [{sample_units}]."),
                evidence=[m.as_evidence()],
                hypotheses_supported=["H_INSIDER_DATA_EXFIL",
                                       "H_OPPORTUNISTIC_COMMODITY"],
            )))
        return out

    def _analyze_thunderbird_mbox(self, ctx: AgentContext,
                                   exports: Path) -> list[Finding]:
        """Walk Thunderbird mbox trees under /home/*/.thunderbird/ and
        surface messages with attachments; flag bodies matching
        narcotic-lexicon or BTC regex as a second pass."""
        from el.skills import thunderbird_mbox as tb
        from el.skills import narcotic_lexicon as nl
        from el.skills import ioc_extract as iex
        profiles = sorted((exports / "home").glob("*/.thunderbird"))
        if not profiles:
            return []
        out: list[Finding] = []
        for prof in profiles:
            run = tb.walk(prof)
            if not run.messages:
                continue
            attached = [m for m in run.messages if m.has_attachments]
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Thunderbird mail parsed "
                       f"({prof.parent.name}): {len(run.messages)} "
                       f"message(s) across {len(run.mbox_paths)} mbox "
                       f"file(s), {len(attached)} with attachment(s)."),
                evidence=[run.as_evidence()],
                hypotheses_supported=[],
            )))
            # Second-pass: narcotic / BTC in body + attachment names
            for m in run.messages:
                body = " ".join([m.subject] + [a.filename
                                                for a in m.attachments])
                nmatch = nl.scan_text(body, source=m.mbox_path)
                btcs = iex.extract(body).get("btc", set())
                if nmatch is None and not btcs:
                    continue
                iocs = []
                if nmatch is not None:
                    iocs.append(f"strains={nmatch.strain_hits[:3]}"
                                 if nmatch.strain_hits else "")
                    iocs.append(f"units={nmatch.unit_hits[:3]}"
                                 if nmatch.unit_hits else "")
                if btcs:
                    iocs.append(f"btc={sorted(btcs)[:3]}")
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="medium",
                    claim=(f"Thunderbird message with narcotic/BTC "
                           f"signal — folder={m.folder!r}, "
                           f"subject={m.subject[:80]!r}. "
                           f"{', '.join(x for x in iocs if x)}."),
                    evidence=[run.as_evidence(facts={
                        "match_folder": m.folder,
                        "match_subject": m.subject[:200],
                        "match_message_id": m.message_id,
                        "attachment_count": len(m.attachments),
                    })],
                    hypotheses_supported=["H_INSIDER_DATA_EXFIL",
                                           "H_OPPORTUNISTIC_COMMODITY"],
                )))
        return out

    def _analyze_auditd(self, ctx: AgentContext,
                         exports: Path) -> list[Finding]:
        """Read /var/log/audit/audit.log* (raw + .gz rotations) and
        surface aggregations + suspicious-execve hits as Findings.
        See el/skills/auditd.py for the parser; this is the
        finding-emission glue."""
        from el.skills import auditd as ad
        # Locate the audit dir under both extraction layouts.
        candidates = [exports / "var" / "log" / "audit",
                       exports / "log" / "audit",
                       exports / "audit"]
        audit_dir = next((p for p in candidates if p.is_dir()), None)
        if audit_dir is None:
            return []
        events = ad.parse_audit_dir(audit_dir)
        if not events:
            return []
        out: list[Finding] = []
        # First file's sha256 is enough to anchor the evidence chain;
        # parse_audit_dir already sorts events globally.
        sample_file = next(iter(audit_dir.glob("audit.log*")), None)
        sha = "0" * 64
        if sample_file is not None and sample_file.is_file():
            sha = hashlib.sha256(sample_file.read_bytes()).hexdigest()
        bt = ad.by_type(events)
        bu = ad.by_user(events)
        bk = ad.by_key(events)
        ev_summary = EvidenceItem(
            tool="el.auditd", version="0.1.0",
            command=f"parse_audit_dir({audit_dir})",
            output_sha256=sha,
            output_path=str(sample_file or audit_dir),
            extracted_facts={
                "audit_dir": str(audit_dir),
                "event_count": len(events),
                "type_breakdown": dict(sorted(
                    bt.items(), key=lambda kv: -kv[1])[:10]),
                "top_users": dict(sorted(
                    bu.items(), key=lambda kv: -kv[1])[:10]),
                "top_keys": dict(sorted(
                    bk.items(), key=lambda kv: -kv[1])[:10]),
            },
            source_reliability="B", info_credibility="2",
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name,
            confidence="medium",
            claim=(f"auditd: parsed {len(events)} structured event(s) "
                   f"across {len(list(audit_dir.glob('audit.log*')))} "
                   f"audit log file(s). Top types: "
                   f"{', '.join(f'{k}={v}' for k, v in sorted(bt.items(), key=lambda kv: -kv[1])[:5])}."),
            evidence=[ev_summary],
            hypotheses_supported=[],
        )))
        sus = ad.suspicious_executions(events)
        if sus:
            samples = [
                f"argv0={(e.argv[0] if e.argv else e.exe)!r} "
                f"uid={e.auid or e.uid} pid={e.pid}"
                for e in sus[:5]
            ]
            ev_sus = EvidenceItem(
                tool="el.auditd", version="0.1.0",
                command=f"suspicious_executions({audit_dir})",
                output_sha256=sha,
                output_path=str(sample_file or audit_dir),
                extracted_facts={
                    "hit_count": len(sus),
                    "samples": samples,
                },
                source_reliability="B", info_credibility="2",
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="high",
                claim=(f"auditd: {len(sus)} EXECVE event(s) match the "
                       f"watchlist of post-exploit / persistence-abuse "
                       f"binaries (nc, socat, msfvenom, chattr, base64, "
                       f"useradd, etc.). Samples: "
                       f"{'; '.join(samples)}."),
                evidence=[ev_sus],
                hypotheses_supported=["H_LIVING_OFF_THE_LAND",
                                        "H_C2_OR_REVERSE_SHELL"],
            )))
        return out

    def _analyze_webserver_access(self, ctx: AgentContext,
                                    exports: Path) -> list[Finding]:
        """nginx/Apache access-log scanner. Finds webshell URIs,
        scripted-client UAs, admin-path hits, 4xx recon bursts,
        verb tunnels, and POST upload bursts."""
        from el.skills import webserver_access as wa
        candidates = [exports / "var" / "log",
                       exports / "log",
                       exports]
        results: list = []
        for c in candidates:
            if not c.is_dir():
                continue
            results = wa.scan_tree(c)
            if results:
                break
        if not results:
            return []
        out: list[Finding] = []
        for r in results:
            if not r.hits:
                continue
            sha = "0" * 64
            if Path(r.path).is_file():
                sha = hashlib.sha256(
                    Path(r.path).read_bytes()).hexdigest()
            for h in r.hits:
                # WEB_SCRIPTED_CLIENT_GENERIC and WEB_VERB_TUNNEL are
                # informational; the others are concrete attacker shape.
                conf = "medium" if h.pattern_id in (
                    "WEB_SCRIPTED_CLIENT_GENERIC", "WEB_VERB_TUNNEL"
                ) else "high"
                ev = EvidenceItem(
                    tool="el.webserver_access", version="0.1.0",
                    command=f"scan_path({r.path.name})",
                    output_sha256=sha, output_path=str(r.path),
                    extracted_facts={
                        "pattern_id": h.pattern_id,
                        "hit_count": h.count,
                        "samples": h.matches[:5],
                        "attack_techniques": [t for t, _ in h.attack_techniques],
                    },
                    source_reliability="B", info_credibility="2",
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence=conf,
                    claim=(f"Webserver {h.pattern_id}: {h.count} "
                           f"hit(s) in {r.path.name}. {h.description}"),
                    evidence=[ev],
                    hypotheses_supported=h.hypotheses or ["H_APT_ESPIONAGE"],
                )))
        return out

    def _analyze_rootkit_scanners(self, ctx: AgentContext,
                                    exports: Path) -> list[Finding]:
        """chkrootkit / rkhunter / Lynis. Each scanner targets the
        mounted root via its --rootdir flag; output is parsed into
        Finding(severity, message). Always emits a per-tool summary
        even when the scanner isn't installed (audit-trail clarity)."""
        from el.skills import rootkit_scanners as rs
        out_dir = ctx.case_dir / "analysis" / "rootkit_scanners"
        results = rs.run_all(exports, out_dir=out_dir)
        out: list[Finding] = []
        for r in results:
            if not r.available:
                # The scanner wasn't installed — surface the gap so
                # the audit trail records that we tried.
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=(f"rootkit-scan {r.tool}: scanner not "
                           f"installed on this SIFT. {r.error}"),
                )))
                continue
            sha = "0" * 64
            if r.raw_path and Path(r.raw_path).is_file():
                sha = hashlib.sha256(
                    Path(r.raw_path).read_bytes()).hexdigest()
            ev = EvidenceItem(
                tool=f"el.rootkit_scanners.{r.tool}", version="0.1.0",
                command=f"run_{r.tool}({exports.name})",
                output_sha256=sha, output_path=r.raw_path or str(exports),
                extracted_facts={
                    "vulnerable_count": r.vulnerable_count,
                    "warning_count": r.warning_count,
                    "samples": [str(f) for f in r.findings[:8]],
                },
                source_reliability="B", info_credibility="2",
            )
            if r.vulnerable_count:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="high",
                    claim=(f"rootkit-scan {r.tool}: "
                           f"{r.vulnerable_count} vulnerable / "
                           f"infected hit(s), {r.warning_count} "
                           f"warning(s). Investigate top items: "
                           f"{'; '.join(str(f)[:120] for f in r.findings[:3])}."),
                    evidence=[ev],
                    hypotheses_supported=["H_ROOTKIT",
                                            "H_PERSISTENCE_SERVICE"],
                )))
            elif r.warning_count:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="medium",
                    claim=(f"rootkit-scan {r.tool}: "
                           f"{r.warning_count} warning(s), no confirmed "
                           f"infection. Top: "
                           f"{'; '.join(str(f)[:120] for f in r.findings[:3])}."),
                    evidence=[ev],
                    hypotheses_supported=[],
                )))
            else:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="low",
                    claim=(f"rootkit-scan {r.tool}: clean run, "
                           f"no findings."),
                    evidence=[ev],
                    hypotheses_supported=[],
                )))
        return out

    def _analyze_father_rootkit(self, ctx: AgentContext,
                                exports: Path) -> list[Finding]:
        """
        Detect Father rootkit using specialized detection patterns.

        Father rootkit (https://github.com/mav8557/Father) uses LD_PRELOAD
        hijacking for persistence and stealth. Key indicators:
        - /etc/ld.so.preload pointing to libymv.so.3
        - Magic GID 7823 for file/process hiding
        - Source port 48411 for SSH backdoor activation
        - Password harvesting log at /tmp/silly.txt
        """
        out: list[Finding] = []

        try:
            # Use evidence root (could be mounted filesystem or extracted artifacts)
            evidence_root = ctx.input_path if (ctx.input_path / "[root]").exists() else exports

            father_evidence = detect_father_rootkit(evidence_root)

            # LD_PRELOAD hijacking detection
            if father_evidence.preload_path:
                claim = "Father rootkit LD_PRELOAD hijacking detected"
                confidence = "high"

                if father_evidence.rootkit_md5:
                    claim += f" (MD5: {father_evidence.rootkit_md5})"

                if father_evidence.rootkit_path:
                    claim += f" — library at {father_evidence.rootkit_path}"

                ev = EvidenceItem(
                    tool="father_rootkit_detection", version="0.1.0",
                    command="detect_father_rootkit(ld_preload_analysis)",
                    output_sha256=hashlib.sha256(str(father_evidence).encode()).hexdigest()[:16],
                    output_path=father_evidence.preload_path,
                    extracted_facts={
                        "rootkit_family": "Father",
                        "persistence_method": "LD_PRELOAD hijacking",
                        "config_gid": father_evidence.config_gid,
                        "source_port": father_evidence.source_port,
                        "shell_password": father_evidence.shell_pass,
                        "env_variable": father_evidence.env_var,
                        "technique": "T1055.012"  # Process Injection: Dynamic linker hijacking
                    },
                )

                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence=confidence, claim=claim, evidence=[ev],
                    hypotheses_supported=["H_ROOTKIT", "H_PERSISTENCE_SERVICE", "H_APT_ESPIONAGE"],
                    ach_score_delta={"H_ROOTKIT": +3, "H_PERSISTENCE_SERVICE": +2}
                )))

            # Backdoor configuration detection
            if father_evidence.source_port or father_evidence.config_gid:
                config_details = []
                if father_evidence.config_gid:
                    config_details.append(f"magic GID {father_evidence.config_gid}")
                if father_evidence.source_port:
                    config_details.append(f"backdoor source port {father_evidence.source_port}")
                if father_evidence.shell_pass:
                    config_details.append(f"shell password '{father_evidence.shell_pass}'")

                claim = f"Father rootkit configuration — {', '.join(config_details)}"

                ev = EvidenceItem(
                    tool="father_rootkit_detection", version="0.1.0",
                    command="detect_father_rootkit(config_analysis)",
                    output_sha256=hashlib.sha256(claim.encode()).hexdigest()[:16],
                    output_path=father_evidence.preload_path or str(evidence_root),
                    extracted_facts={
                        "backdoor_activation": "SSH connection from source port",
                        "hiding_mechanism": "Magic GID file/process concealment",
                        "attack_technique": "T1014, T1055.012"
                    },
                )

                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="high", claim=claim, evidence=[ev],
                    hypotheses_supported=["H_ROOTKIT", "H_BACKDOOR"],
                    ach_score_delta={"H_ROOTKIT": +2, "H_BACKDOOR": +2}
                )))

            # Credential harvesting detection
            if father_evidence.silly_txt_present:
                claim = "Father rootkit credential harvesting active (/tmp/silly.txt)"

                ev = EvidenceItem(
                    tool="father_rootkit_detection", version="0.1.0",
                    command="detect_father_rootkit(credential_harvest)",
                    output_sha256=hashlib.sha256("silly.txt_detected".encode()).hexdigest()[:16],
                    output_path="/tmp/silly.txt",
                    extracted_facts={
                        "harvest_method": "PAM function hooking",
                        "log_location": "/tmp/silly.txt",
                        "technique": "T1555, T1003"  # Credentials from Password Stores
                    },
                )

                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="high", claim=claim, evidence=[ev],
                    hypotheses_supported=["H_CREDENTIAL_ACCESS", "H_ROOTKIT"],
                    ach_score_delta={"H_CREDENTIAL_ACCESS": +3, "H_ROOTKIT": +1}
                )))

            # Boot errors indicating incomplete rootkit installation
            if father_evidence.preload_errors:
                error_sample = father_evidence.preload_errors[0][:150]
                claim = f"Father rootkit deployment errors detected — {len(father_evidence.preload_errors)} error(s)"

                ev = EvidenceItem(
                    tool="father_rootkit_detection", version="0.1.0",
                    command="detect_father_rootkit(error_analysis)",
                    output_sha256=hashlib.sha256(str(father_evidence.preload_errors).encode()).hexdigest()[:16],
                    output_path="/var/log/boot.log",
                    extracted_facts={
                        "error_count": len(father_evidence.preload_errors),
                        "sample_error": error_sample,
                        "deployment_status": "Partially failed"
                    },
                )

                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="medium", claim=claim, evidence=[ev],
                    hypotheses_supported=["H_ROOTKIT"],
                    ach_score_delta={"H_ROOTKIT": +1}
                )))

        except Exception as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"Father rootkit detection failed: {e}"
            )))

        return out

    def _analyze_uac_live_response(self, ctx: AgentContext, uac_collection) -> list[Finding]:
        """Analyze UAC live response artifacts for suspicious activity."""
        out: list[Finding] = []
        live_response_dir = Path(uac_collection.live_response_dir)

        if not live_response_dir.exists():
            return out

        # Analyze process snapshots for suspicious activity
        process_dir = live_response_dir / "process"
        if process_dir.exists():
            suspicious_processes = []

            for ps_file in process_dir.glob("ps_*.txt"):
                try:
                    content = ps_file.read_text(encoding='utf-8', errors='ignore')

                    # Look for suspicious process patterns
                    lines = content.splitlines()
                    for line in lines:
                        # Father rootkit indicators
                        if "7823" in line:  # Magic GID
                            suspicious_processes.append(f"Process with magic GID 7823: {line.strip()}")

                        # Suspicious process names/paths
                        if any(pattern in line.lower() for pattern in [
                            "/tmp/", "/dev/shm/", "/.hidden", "/var/tmp/"
                        ]):
                            if not any(benign in line.lower() for benign in [
                                "systemd", "dbus", "getty", "cron"
                            ]):
                                suspicious_processes.append(f"Suspicious path process: {line.strip()}")

                except Exception:
                    continue

            if suspicious_processes:
                evidence = {
                    "tool": "uac_live_response",
                    "description": f"Suspicious processes in {process_dir}",
                    "path": str(process_dir),
                    "suspicious_count": len(suspicious_processes),
                    "sample_processes": suspicious_processes[:5]
                }

                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="medium",
                    claim=f"UAC Live Response: {len(suspicious_processes)} suspicious process(es) detected",
                    evidence=[evidence],
                    hypotheses_supported=["H_APT_ESPIONAGE"],
                )))

        # Analyze network connections for backdoor patterns
        network_dir = live_response_dir / "network"
        if network_dir.exists():
            backdoor_connections = []

            for net_file in network_dir.glob("*.txt"):
                try:
                    content = net_file.read_text(encoding='utf-8', errors='ignore')

                    # Look for Father rootkit backdoor port
                    if "48411" in content:  # Father default backdoor port
                        backdoor_connections.append("Father rootkit backdoor port 48411 detected")

                    # Look for other suspicious ports
                    for line in content.splitlines():
                        if any(port in line for port in [":3333", ":4444", ":5555", ":8080"]):
                            if "LISTEN" in line or "ESTABLISHED" in line:
                                backdoor_connections.append(f"Suspicious network connection: {line.strip()}")

                except Exception:
                    continue

            if backdoor_connections:
                evidence = {
                    "tool": "uac_live_response",
                    "description": f"Suspicious network connections in {network_dir}",
                    "path": str(network_dir),
                    "connection_count": len(backdoor_connections),
                    "sample_connections": backdoor_connections[:5]
                }

                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="high",
                    claim=f"UAC Live Response: {len(backdoor_connections)} suspicious network connection(s) detected",
                    evidence=[evidence],
                    hypotheses_supported=["H_APT_ESPIONAGE", "H_C2_BEACONING"],
                )))

        return out

    def _analyze_uac_bodyfile(self, ctx: AgentContext, uac_collection) -> list[Finding]:
        """Analyze UAC bodyfile for timeline anomalies."""
        out: list[Finding] = []
        bodyfile_path = Path(uac_collection.bodyfile_path)

        if not bodyfile_path.exists():
            return out

        try:
            # Basic bodyfile statistics
            file_size = bodyfile_path.stat().st_size
            line_count = 0
            recent_activity = []

            with open(bodyfile_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_count += 1

                    # Look for recent file activity in suspicious locations
                    if any(path in line for path in ["/tmp/", "/dev/shm/", "/var/tmp/"]):
                        recent_activity.append(line.strip())

                    # Limit sample collection for performance
                    if len(recent_activity) >= 20:
                        break

            evidence = {
                "tool": "uac_bodyfile",
                "description": f"Filesystem timeline from {bodyfile_path}",
                "path": str(bodyfile_path),
                "size_bytes": file_size,
                "entry_count": line_count,
                "suspicious_activity_count": len(recent_activity),
                "sample_activity": recent_activity[:10]
            }

            confidence = "medium" if recent_activity else "low"
            claim = f"UAC Bodyfile: {line_count:,} filesystem entries analyzed"
            if recent_activity:
                claim += f", {len(recent_activity)} suspicious file activities in temporary directories"

            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence=confidence,
                claim=claim,
                evidence=[evidence],
                hypotheses_supported=["H_APT_ESPIONAGE"] if recent_activity else [],
            )))

        except Exception as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"UAC bodyfile analysis failed: {e}",
            )))

        return out

    def _analyze_uac_pattern_detection(self, ctx: AgentContext, uac_collection) -> list[Finding]:
        """Run malicious pattern detection on UAC text artifacts."""
        out: list[Finding] = []
        uac_dir = Path(uac_collection.output_dir)

        try:
            # Import pattern detection from linux_triage
            from el.skills import linux_triage as lt

            # Run pattern detection on UAC directory
            hits = lt.run_all(uac_dir)

            if not hits:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=f"UAC Pattern Detection: no malicious patterns detected in {len(list(uac_dir.rglob('*.txt')))} text files",
                )))
                return out

            # Process pattern hits
            manifest_path = uac_dir / "collection_manifest.txt"
            sha = "0" * 64
            if manifest_path.exists():
                sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

            for hit in hits:
                confidence = "high" if hit.family in _HIGH_FAMILIES else "medium"
                facts = {
                    "family": hit.family,
                    "matched_pattern": hit.matched_pattern,
                    "event_count": hit.event_count,
                    "top_users": hit.top_users,
                    "source_files": hit.source_files[:5],
                    "attack_techniques": [t for t, _ in hit.attack],
                    "sample_text_head": hit.sample_text[:200],
                    "uac_source": True,
                }

                evidence = EvidenceItem(
                    tool="el.linux_triage", version="0.1.0",
                    command=f"run_all(uac:{uac_dir.name})",
                    output_sha256=sha, output_path=str(manifest_path),
                    extracted_facts=facts,
                )

                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence=confidence,
                    claim=(f"UAC Pattern Detection - {hit.family}: {hit.event_count} event(s) "
                           f"matched pattern {hit.matched_pattern!r}. "
                           f"ATT&CK: {', '.join(t for t, _ in hit.attack) or '-'}. "
                           f"Sample: {hit.sample_text[:150]!r}"
                           + (f" (users: {', '.join(hit.top_users[:3])})"
                              if hit.top_users else "")),
                    evidence=[evidence],
                    hypotheses_supported=lt.hypotheses_for(hit.family) or ["H_APT_ESPIONAGE"],
                )))

        except Exception as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"UAC pattern detection failed: {e}",
            )))

        return out
