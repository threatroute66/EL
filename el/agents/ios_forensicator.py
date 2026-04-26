"""IOSForensicator — primary investigator for iOS filesystem tree inputs.

iOS cases arrive as already-extracted filesystem trees (checkm8 /
GrayKey / Cellebrite / advanced-logical extraction), not as block
images. No mount needed — the agent walks the input dir, runs
`extract_ios_artifacts` to produce the sealed exports subtree, then
runs `ios_triage.run_all` for detection.

Routed from Triage when `ctx.shared["evidence_kind"] == "ios-fs-dir"`
(parallel to how `android-fs-dir` routes to AndroidForensicatorAgent
and `windows-artifacts-dir` routes to WindowsArtifactAgent).

Confidence tiers:
  jailbreak_indicator → medium (informational — jailbroken ≠ compromised,
    but flips the threat model; iOS sandbox is weakened or absent)
  sideloaded_app → high (on iOS the only non-App-Store path is
    enterprise provisioning / TestFlight / dev signing — each a
    deliberate threat-model shift)
  provisioning_profile → medium (stock consumer iOS has none;
    presence = enterprise MDM or dev/sideload tooling)
  messenger_presence → low (purely informational pivot)
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import ios_artifacts as ia
from el.skills import ios_triage as it


_CONFIDENCE_BY_FAMILY = {
    "jailbreak_indicator":    "medium",
    "sideloaded_app":         "high",
    "provisioning_profile":   "medium",
    "messenger_presence":     "low",
}


class IOSForensicatorAgent(Agent):
    name = "ios_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        src = ctx.input_path
        # Sysdiagnose tarball — Apple's support bundle, not a
        # filesystem dump. Different shape, different parser.
        if (src.is_file()
                and src.name.startswith("sysdiagnose_")
                and (str(src).endswith(".tar.gz")
                     or str(src).endswith(".tgz"))):
            return self._run_sysdiagnose(ctx, src)
        # iTunes / Finder backup directory — Manifest.db + hash-named
        # blob tree, not a real filesystem.
        if src.is_dir() and self._is_itunes_backup_dir(src):
            return self._run_itunes_backup(ctx, src)
        if not src.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("IOSForensicator: input is not a directory or "
                       "supported iOS bundle (sysdiagnose tar.gz). "
                       "iOS cases arrive as file-system trees "
                       "(checkm8 / GrayKey / Cellebrite output), "
                       "iTunes/Finder backup directories, or "
                       "sysdiagnose tarballs."),
            ))]

        exports = ctx.case_dir / "exports" / "ios-artifacts"
        try:
            counts = ia.extract_ios_artifacts(src, exports)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"iOS extraction errored: {e}",
            ))]

        out: list[Finding] = []
        if not counts:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"IOSForensicator: walked {src.name} but no iOS "
                       f"artifacts recognised (no System/Library/"
                       f"CoreServices/SystemVersion.plist, no /private/"
                       f"var/mobile/Library/ DBs, no /private/var/"
                       f"containers/Bundle/Application/ bundles). "
                       f"Likely not an iOS filesystem tree."),
            )))
            return out

        listing = "\n".join(sorted(
            str(p.relative_to(exports))
            for p in exports.rglob("*") if p.is_file()))
        listing_path = exports / "MANIFEST.txt"
        listing_path.parent.mkdir(parents=True, exist_ok=True)
        listing_path.write_text(listing)
        summary_ev = EvidenceItem(
            tool="el.ios_artifacts", version="0.1.0",
            command=f"extract_ios_artifacts({src.name})",
            output_sha256=hashlib.sha256(listing.encode()).hexdigest(),
            output_path=str(listing_path),
            extracted_facts=counts,
        )
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"iOS artifacts extracted from {src.name}: {summary}"),
            evidence=[summary_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        hits = it.run_all(exports)
        for h in hits:
            confidence = _CONFIDENCE_BY_FAMILY.get(h.family, "medium")
            ev = EvidenceItem(
                tool="el.ios_triage", version="0.1.0",
                command=f"run_all({exports.name}, family={h.family})",
                output_sha256=summary_ev.output_sha256,
                output_path=str(listing_path),
                extracted_facts={
                    "family": h.family,
                    "matched_pattern": h.matched_pattern,
                    "event_count": h.event_count,
                    "source_files": h.source_files[:5],
                    "attack_techniques": [t for t, _ in h.attack],
                    "sample_text_head": h.sample_text[:200],
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence=confidence,
                claim=(f"iOS {h.family}: {h.event_count} signal(s); "
                       f"{h.matched_pattern}. "
                       f"ATT&CK: "
                       f"{', '.join(t for t, _ in h.attack) or '-'}. "
                       f"Sample: {h.sample_text[:150]!r}"),
                evidence=[ev],
                hypotheses_supported=it.hypotheses_for(h.family)
                                       or ["H_DISK_ARTIFACTS"],
            )))

        # iLEAPP wrap — Brignoni's 80+-artifact parser. Skips silently
        # when iLEAPP isn't installed; emits one finding per surfaced
        # high-value artifact (calls, SMS, Safari history, locations,
        # app installs, Wi-Fi). Storage cost: ~tens of MB of TSV/HTML
        # under <case_dir>/exports/ileapp/.
        out.extend(self._run_ileapp(ctx, src))
        return out

    # Per-artifact display names + confidences. iLEAPP names its TSV
    # files in a stable scheme; we surface a curated subset.
    _ILEAPP_HIGH_VALUE = {
        # filename substring → (display label, confidence, hypotheses)
        "Call History":           ("call history",        "medium", []),
        "SMS messages":           ("SMS / iMessage",      "medium", []),
        "iMessage":               ("iMessage threads",    "medium", []),
        "Calendar":               ("calendar events",     "low",    []),
        "Contacts":               ("contacts",            "low",    []),
        "Safari Browsing History": ("Safari history",     "medium", []),
        "Safari History":         ("Safari history",      "medium", []),
        "Wifi Networks":          ("Wi-Fi network history", "medium",
                                    ["H_DISK_ARTIFACTS"]),
        "WiFi":                   ("Wi-Fi network history", "medium",
                                    ["H_DISK_ARTIFACTS"]),
        "Locations":              ("location history",    "medium", []),
        "Significant Locations":  ("significant locations",
                                   "medium", []),
        "Installed Apps":         ("installed apps",      "low",
                                    ["H_DISK_ARTIFACTS"]),
        "Application State":      ("app last-state",      "low",    []),
        "Knowledge":              ("KnowledgeC events",   "low",    []),
        "Apple Pay":              ("Apple Pay transactions",
                                   "medium", []),
        "AirDrop":                ("AirDrop transfers",   "medium", []),
        "Bluetooth":              ("Bluetooth pairings",  "low",    []),
    }

    def _run_ileapp(self, ctx: AgentContext, src: Path) -> list[Finding]:
        from el.skills import ileapp as ileapp_skill
        if not ileapp_skill.is_ileapp_available():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("iLEAPP not installed at /opt/iLEAPP "
                       "(or `EL_ILEAPP_DIR`). Skipping the 80+-artifact "
                       "Brignoni parser pass; the four built-in "
                       "detectors above still ran."),
            ))]

        out_dir = ctx.case_dir / "exports" / "ileapp"
        try:
            r = ileapp_skill.run(src, out_dir)
        except ileapp_skill.ILeappError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"iLEAPP failed: {e}",
            ))]

        out: list[Finding] = []
        # One summary finding for the whole run
        populated_count = sum(1 for t in r.tables if t.populated)
        ev = EvidenceItem(
            tool="iLEAPP", version=r.version or "unknown",
            command=f"ileapp.py -t fs -i {src.name} -o {out_dir.name}",
            output_sha256=hashlib.sha256(
                r.stdout_path.read_bytes() if r.stdout_path.exists()
                else b"").hexdigest(),
            output_path=str(r.report_dir),
            extracted_facts={
                "tables": len(r.tables),
                "populated_tables": populated_count,
                "rc": r.rc,
            },
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"iLEAPP v{r.version or '?'} parsed {len(r.tables)} "
                   f"artifact module(s); {populated_count} populated. "
                   f"Report: {r.report_dir.name}"),
            evidence=[ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        # Per-artifact findings for the curated high-value subset
        for table in r.tables:
            if not table.populated:
                continue
            label, conf, hyps = (None, "low", [])
            for needle, (lbl, c, h) in self._ILEAPP_HIGH_VALUE.items():
                if needle.lower() in table.name.lower():
                    label, conf, hyps = lbl, c, h
                    break
            if label is None:
                continue   # skip non-curated tables — would flood the ledger
            sample = ""
            if table.rows:
                # First row's column-1 value is usually the most-recent
                # / first event — useful for the claim.
                cols_to_show = min(3, len(table.headers))
                sample = " | ".join(
                    table.rows[0][i] for i in range(cols_to_show)
                    if i < len(table.rows[0])
                )[:200]
            tev = EvidenceItem(
                tool="iLEAPP", version=r.version or "unknown",
                command=f"_TSV/{table.name}",
                output_sha256=hashlib.sha256(
                    table.path.read_bytes()).hexdigest(),
                output_path=str(table.path),
                extracted_facts={
                    "artifact": label, "rows": table.total_rows,
                    "headers": table.headers[:8],
                    "truncated": table.truncated,
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=conf,
                claim=(f"iLEAPP {label}: {table.total_rows} row(s) "
                       f"parsed from {table.name}"
                       + (f" (sample: {sample!r})" if sample else "")
                       + (" [truncated to 5000 rows for display]"
                          if table.truncated else "")),
                evidence=[tev],
                hypotheses_supported=hyps,
            )))
        return out

    # --- iTunes / Finder backup support -----------------------------

    @staticmethod
    def _is_itunes_backup_dir(d: Path) -> bool:
        """Recognise an iTunes/Finder backup by the canonical
        Manifest.plist + Manifest.db pair at the top level."""
        return ((d / "Manifest.plist").is_file()
                and (d / "Manifest.db").is_file())

    def _run_itunes_backup(self, ctx: AgentContext,
                             src: Path) -> list[Finding]:
        """Parse an iTunes/Finder backup directory. Emits:
          - device-metadata Finding (high) — iOS version, product,
            UDID, encryption flag, application count, backup date
          - file-inventory Finding (medium) when Manifest.db reads
            successfully (unencrypted backup OR
            decrypt_manifest_db pre-staged a plaintext copy)
          - encryption-blocked Finding (insufficient) when
            Manifest.db is encrypted and no decrypted copy is
            available — points the operator at decrypt_manifest_db.
        """
        from el.skills import ios_backup_parse as ib
        out: list[Finding] = []
        md = ib.read_metadata(src)
        plist_path = src / "Manifest.plist"
        sha = hashlib.sha256(plist_path.read_bytes()).hexdigest()
        meta_ev = EvidenceItem(
            tool="el.ios_backup_parse", version="0.1.0",
            command=f"read_metadata({src.name})",
            output_sha256=sha, output_path=str(plist_path),
            extracted_facts={
                "is_encrypted": md.is_encrypted,
                "product_version": md.product_version,
                "product_type": md.product_type,
                "device_name": md.device_name,
                "unique_device_id": md.unique_device_id,
                "backup_date_utc": md.backup_date_utc,
                "application_count": md.application_count,
                "was_passcode_set": md.was_passcode_set,
                "backup_version": md.backup_version,
            },
            source_reliability="A", info_credibility="1",
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"iTunes/Finder backup parsed: {md.device_name!r} "
                   f"({md.product_type}) running iOS "
                   f"{md.product_version}, "
                   f"{'encrypted' if md.is_encrypted else 'unencrypted'}, "
                   f"backup_date={md.backup_date_utc}, "
                   f"{md.application_count} apps backed up."),
            evidence=[meta_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))
        # File inventory — works on unencrypted Manifest.db only
        files = ib.list_files(src)
        if files:
            db_path = src / "Manifest.db"
            db_sha = hashlib.sha256(db_path.read_bytes()).hexdigest()
            doms = ib.by_domain(files)
            dbs = ib.find_databases(files)
            inv_ev = EvidenceItem(
                tool="el.ios_backup_parse", version="0.1.0",
                command=f"list_files({src.name})",
                output_sha256=db_sha, output_path=str(db_path),
                extracted_facts={
                    "file_count": len(files),
                    "database_count": len(dbs),
                    "top_domains": dict(sorted(
                        doms.items(), key=lambda kv: -kv[1])[:10]),
                    "sample_databases": [
                        {"domain": f.domain,
                         "relative_path": f.relative_path}
                        for f in dbs[:10]
                    ],
                },
                source_reliability="A", info_credibility="1",
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="medium",
                claim=(f"iTunes backup file inventory: {len(files)} "
                       f"file(s) across {len(doms)} domain(s); "
                       f"{len(dbs)} SQLite database(s) for pivot. "
                       f"Top domains: "
                       f"{', '.join(d for d, _ in sorted(doms.items(), key=lambda kv: -kv[1])[:5])}."),
                evidence=[inv_ev],
                hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
        elif md.is_encrypted:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("iTunes backup is encrypted — Manifest.db "
                       "cannot be read until decrypted. Stage the "
                       "operator-known passcode and run "
                       "ios_backup_parse.decrypt_manifest_db; the "
                       "device-metadata above is from the "
                       "always-readable Manifest.plist."),
            )))
        return out

    # --- iOS sysdiagnose support ------------------------------------

    def _run_sysdiagnose(self, ctx: AgentContext,
                          src: Path) -> list[Finding]:
        """Triage an iOS sysdiagnose tarball. Emits:
          - device-metadata Finding (high) from the first parseable
            IPS record (iOS version + product type)
          - per-Jetsam Finding (low) capping at 5 — anomalous
            largest-process attribution surfaces spyware-relevant
            memory pressure
          - Unified-Log marker Finding (insufficient) when
            system_logs.logarchive is present (replay needs macOS
            ``log show``)
        """
        from el.skills import sysdiagnose as sd_skill
        out: list[Finding] = []
        extract_dir = ctx.case_dir / "exports" / "sysdiagnose"
        try:
            root = sd_skill.extract(src, extract_dir)
        except (OSError, Exception) as e:                  # noqa: BLE001
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"sysdiagnose extraction failed: {e}",
            ))]
        idx = sd_skill.index(root)
        sha = hashlib.sha256(
            str(idx.subsystems).encode()).hexdigest()
        meta = sd_skill.device_metadata(idx)
        meta_ev = EvidenceItem(
            tool="el.sysdiagnose", version="0.1.0",
            command=f"index({root.name})",
            output_sha256=sha, output_path=str(root),
            extracted_facts={
                "subsystems": idx.subsystems,
                "file_count": idx.file_count,
                "bytes_total": idx.bytes_total,
                "ips_record_count": len(idx.ips_files),
                **meta,
            },
            source_reliability="A", info_credibility="1",
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"iOS sysdiagnose triaged: {idx.file_count} files "
                   f"across {len(idx.subsystems)} subsystem(s); "
                   f"device={meta.get('product','?')}, "
                   f"os={meta.get('os_version','?')}; "
                   f"{len(idx.ips_files)} IPS record(s)."),
            evidence=[meta_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))
        # Unified log archive marker
        if idx.has_logarchive:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"system_logs.logarchive present "
                       f"({idx.logarchive_bytes:,} bytes) — Unified "
                       f"Log replay requires macOS `log show`. "
                       f"Static .log files alongside the archive "
                       f"are still readable; the .ips JSON records "
                       f"in crashes_and_spins/ are the pivot."),
            )))
        # Jetsam events — surface up to 5; each one fingerprints
        # which app was killed for memory pressure
        jetsams = sd_skill.find_jetsam_events(idx, max_records=20)
        for j in jetsams[:5]:
            j_ev = EvidenceItem(
                tool="el.sysdiagnose", version="0.1.0",
                command=f"parse_ips({j.path.name})",
                output_sha256=hashlib.sha256(
                    j.path.read_bytes()).hexdigest()
                if j.path.is_file() else "0" * 64,
                output_path=str(j.path),
                extracted_facts={
                    "bug_type": j.bug_type,
                    "incident_id": j.incident_id,
                    "timestamp": j.timestamp,
                    "largest_process": j.largest_process,
                    "process_count": len(j.body.get("processes", []) or []),
                },
                source_reliability="A", info_credibility="1",
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="low",
                claim=(f"Jetsam (low-memory kill) at {j.timestamp}: "
                       f"largestProcess={j.largest_process!r}. "
                       "Anomalous resident-page growth on a single "
                       "app can be a spyware fingerprint when "
                       "paired with a sideloaded-app or MDM signal."),
                evidence=[j_ev],
                hypotheses_supported=[],
            )))
        if len(jetsams) > 5:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="low",
                claim=(f"sysdiagnose contains {len(jetsams)} Jetsam "
                       f"events (showed top 5 above). High overall "
                       f"jetsam volume indicates sustained memory "
                       f"pressure — pivot to ios_triage / iLEAPP "
                       f"signals to triage which apps drove it."),
            )))
        return out
