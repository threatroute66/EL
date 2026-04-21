"""Disk Forensicator — Sleuth Kit + EZ Tools orchestration.

Current scope: raw disk images (dd / E01 mounted via ewfmount → raw).
For E01 inputs we surface the requirement for ewfmount as 'insufficient'
rather than silently degrading — keeps the contract honest.
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import bulk_extractor as be_skill, disk_anomaly, exiftool as exif_skill, sleuthkit as sk


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
                    # No partition table = single filesystem at offset 0.
                    # Try mounting + extracting artifacts the same way we do per-partition.
                    extracted = self._extract_ntfs_artifacts(
                        ctx, raw_image,
                        partition={"slot": "0", "start_sector": 0,
                                    "description": "whole-image (no partition table)"},
                        sector_size=sector_size,
                        label="whole-image-off0")
                    if extracted:
                        ctx.shared["artifacts_dir"] = str(extracted)
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

        sector_size = ctx.shared.get("sector_size", 512)
        artifact_dirs: list[Path] = []        # Windows-shaped only
        linux_dirs: list[Path] = []            # Linux ext{2,3,4}
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
            desc = p["description"]
            fls_ok = (fls_run.rc == 0
                      and fls_run.stdout_path.stat().st_size > 0)
            if fls_ok:
                out.extend(self._fls_to_timeline(
                    ctx, fls_run, analysis, part_label=label,
                    desc=desc))

            # APFS is not supported by Sleuth Kit's fls, so fls_ok is
            # always False for APFS partitions. Route to fsapfsmount
            # directly — don't gate the extraction on fls.
            apfs_partition = (
                "disk image" in desc.lower() or "apfs" in desc.lower())

            if fls_ok and ("NTFS" in desc or "Basic data" in desc):
                extracted = self._extract_ntfs_artifacts(
                    ctx, raw_image, p, sector_size, label)
                if extracted:
                    artifact_dirs.append(extracted)
            elif fls_ok and ("Linux" in desc or "ext" in desc.lower()):
                extracted = self._extract_linux_artifacts_partition(
                    ctx, raw_image, p, sector_size, label)
                if extracted:
                    linux_dirs.append(extracted)
                    # Mark the family so LinuxForensicator knows to
                    # run. Deliberately NOT setting artifacts_dir —
                    # that would mislead the Windows-artifact chain
                    # into parsing a Linux tree as if it were NTFS.
                    ctx.shared["linux_artifacts_dir"] = str(extracted)
            elif apfs_partition:
                # GPT partition labeled "disk image" on a Mac is
                # the APFS container. fsapfsmount (libfsapfs-tools)
                # reads it directly; no fls dependency.
                extracted = self._extract_macos_artifacts_partition(
                    ctx, raw_image, p, sector_size, label)
                if extracted:
                    ctx.shared["macos_artifacts_dir"] = str(extracted)
            elif not fls_ok:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=(f"fls returned no rows for partition {label} "
                           f"({desc}) — filesystem may be unreadable or "
                           f"unsupported"),
                )))

        if artifact_dirs:
            ctx.shared["artifacts_dir"] = str(artifact_dirs[0])
            # The grounded "artifacts extracted" finding is emitted from
            # _extract_ntfs_artifacts itself (with the file-listing manifest
            # as evidence). No separate summary needed here.

        # bulk_extractor: feature-class carving across the raw stream.
        # Cheap supplement to fls + WindowsArtifactAgent — picks up
        # emails / URLs / domains / IPv4 / CCN / BTC from unallocated
        # space and slack that the FS walk misses.
        out.extend(self._run_bulk_extractor(ctx, raw_image, analysis))
        # exiftool: metadata sweep across extracted artifacts (Windows
        # OR Linux) to surface authoring fingerprints (Office Author,
        # PDF Producer, camera serial, GPS) that suggest data origin /
        # transfer paths. Worth running on Linux extract trees too —
        # /home/*/Documents often contains office docs with metadata.
        sweep_dirs = artifact_dirs + linux_dirs
        if sweep_dirs:
            out.extend(self._run_exiftool(ctx, sweep_dirs[0]))
        return out

    def _run_bulk_extractor(self, ctx: AgentContext, raw_image,
                             analysis) -> list[Finding]:
        out: list[Finding] = []
        be_dir = analysis / "bulk_extractor"
        try:
            # Leave `enable_scanners=None` to run BE's full default scanner
            # set (email, net, accts, httplogs, evtx, winprefetch, winlnk,
            # winpe, exif, pdf, json, sqlite, ntfs*, zip/gzip/rar). Explicitly
            # enable `outlook` — default-off — so we also carve Outlook PST
            # fragments from unallocated space (critical for email-exfil cases
            # like M57-Jean). The .features() summary below picks up whatever
            # feature files land in be_dir regardless of which scanner wrote
            # them, so nothing downstream needs tuning.
            r = be_skill.scan(raw_image, be_dir,
                              enable_scanners=["outlook"],
                              threads=4, timeout=3600)
        except be_skill.BulkExtractorError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"bulk_extractor unavailable or failed: {e}",
            )))
            return out
        feats = r.features()
        if not feats:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"bulk_extractor swept {raw_image.name}: no feature hits "
                      "(image may be small, encrypted, or unallocated-poor)",
                evidence=[r.as_evidence()],
            )))
            return out
        total = sum(feats.values())
        summary = ", ".join(f"{k}={v}" for k, v in
                             sorted(feats.items(), key=lambda kv: -kv[1])[:8])
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"bulk_extractor carved {total} feature(s) across "
                  f"{len(feats)} class(es): {summary}",
            evidence=[r.as_evidence()],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))
        return out

    def _run_exiftool(self, ctx: AgentContext, target_dir: Path) -> list[Finding]:
        out: list[Finding] = []
        try:
            metas = exif_skill.metadata_dir(target_dir, max_files=500,
                                             timeout=600)
        except exif_skill.ExifError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"exiftool unavailable or failed on {target_dir.name}: {e}",
            )))
            return out
        if not metas:
            return out

        # Aggregate authorship fingerprints across all files
        from collections import Counter
        authors: Counter = Counter()
        producers: Counter = Counter()
        gps_files: list[str] = []
        camera_serials: Counter = Counter()
        for path, m in metas.items():
            for k in ("Author", "Creator", "LastModifiedBy"):
                v = m.get(k)
                if v and isinstance(v, str):
                    authors[v.strip()] += 1
            for k in ("Producer", "CreatorTool", "Software"):
                v = m.get(k)
                if v and isinstance(v, str):
                    producers[v.strip()] += 1
            if m.get("GPSPosition") or m.get("GPSLatitude"):
                gps_files.append(path)
            v = m.get("SerialNumber") or m.get("CameraSerialNumber")
            if v:
                camera_serials[str(v).strip()] += 1

        import hashlib
        from el.schemas.finding import EvidenceItem
        # Persist a compact JSON summary as the evidence record
        import json
        summary_path = (ctx.case_dir / "analysis" / self.name /
                         "exiftool-summary.json")
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_payload = {
            "files_scanned": len(metas),
            "authors": dict(authors.most_common(20)),
            "producers": dict(producers.most_common(20)),
            "camera_serials": dict(camera_serials.most_common(10)),
            "gps_files": gps_files[:20],
        }
        summary_path.write_text(json.dumps(summary_payload, indent=2))
        ev = EvidenceItem(
            tool="exiftool", version="present",
            command=f"exiftool -j -r {target_dir}",
            output_sha256=hashlib.sha256(
                summary_path.read_bytes()).hexdigest(),
            output_path=str(summary_path),
            extracted_facts=summary_payload,
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"exiftool sweep of {target_dir.name}: {len(metas)} file(s); "
                  f"{len(authors)} unique author(s), {len(producers)} unique "
                  f"producer(s), {len(gps_files)} file(s) with GPS",
            evidence=[ev], hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        # If any single author/producer dominates, that's an attribution
        # signal — surface as a separate finding so it can corroborate
        # other agents' authorship hypotheses.
        if authors:
            top_author, top_n = authors.most_common(1)[0]
            if top_n >= 3:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="medium",
                    claim=f"exiftool: dominant document author/creator "
                          f"'{top_author}' across {top_n} file(s)",
                    evidence=[ev],
                )))
        return out

    def _extract_linux_artifacts_partition(
        self, ctx: AgentContext, raw_image: Path, partition: dict,
        sector_size: int, label: str,
    ) -> Path | None:
        """Loop-mount the Linux ext2/ext3/ext4 partition ro,noexec and
        copy IR artifacts via `extract_linux_artifacts`. Mirrors the
        NTFS path but the downstream chained agent is
        LinuxForensicatorAgent rather than WindowsArtifactAgent.
        """
        from el.skills import linux_artifacts as la
        fs_mount = Path("/tmp/el-mounts") / f"{ctx.case_id}-fs-{label}"
        exports_dir = ctx.case_dir / "exports" / "linux-artifacts"
        try:
            sk.mount_linux_ro(raw_image, partition["start_sector"],
                                fs_mount, sector_size=sector_size,
                                timeout=120)
        except sk.SleuthkitError as e:
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"Linux mount failed for {label} "
                       f"({partition['description']}): {e}"),
            ))
            return None
        try:
            extracted = la.extract_linux_artifacts(fs_mount, exports_dir)
        except Exception as e:
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"Linux artifact extraction errored for "
                       f"{label}: {e}"),
            ))
            sk.umount(fs_mount)
            return None
        sk.umount(fs_mount)
        if not extracted:
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"Linux partition {label} mounted but no "
                       f"recognised IR artifacts found (no /etc, no "
                       f"/var/log, no /home profiles)."),
            ))
            return None

        from el.schemas.finding import EvidenceItem
        import hashlib
        listing = "\n".join(sorted(
            str(p.relative_to(exports_dir))
            for p in exports_dir.rglob("*") if p.is_file()))
        listing_path = exports_dir / "MANIFEST.txt"
        listing_path.parent.mkdir(parents=True, exist_ok=True)
        listing_path.write_text(listing)
        ev = EvidenceItem(
            tool="el.disk_forensicator", version="0.1.0",
            command=f"la.extract_linux_artifacts({label})",
            output_sha256=hashlib.sha256(listing.encode()).hexdigest(),
            output_path=str(listing_path),
            extracted_facts=extracted,
        )
        summary = ", ".join(f"{k}={v}" for k, v in sorted(extracted.items()))
        self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Linux artifacts extracted from {label}: {summary}"),
            evidence=[ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))
        return exports_dir

    def _extract_macos_artifacts_partition(
        self, ctx: AgentContext, raw_image: Path, partition: dict,
        sector_size: int, label: str,
    ) -> Path | None:
        """Mount the APFS Data volume (volume 1 on a standard Big Sur+
        install) via `fsapfsmount` and copy IR artifacts via
        `extract_macos_artifacts`. Mirrors the Linux path structure.
        """
        from el.skills import macos_artifacts as ma
        fs_mount = Path("/tmp/el-mounts") / f"{ctx.case_id}-fs-{label}"
        exports_dir = ctx.case_dir / "exports" / "macos-artifacts"
        try:
            sk.mount_apfs_ro(raw_image, partition["start_sector"],
                               fs_mount, volume_index=1,
                               sector_size=sector_size, timeout=120)
        except sk.SleuthkitError as e:
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"APFS mount failed for {label} "
                       f"({partition['description']}): {e}. "
                       f"Requires libfsapfs-tools (apt install "
                       f"libfsapfs-tools)."),
            ))
            return None
        try:
            extracted = ma.extract_macos_artifacts(fs_mount, exports_dir)
        except Exception as e:
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"macOS artifact extraction errored for "
                       f"{label}: {e}"),
            ))
            sk.umount(fs_mount)
            return None
        sk.umount(fs_mount)
        if not extracted:
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"APFS partition {label} mounted but no "
                       f"recognised IR artifacts found (no /Users, "
                       f"no /Library/LaunchAgents, no /private/etc). "
                       f"Maybe wrong volume index — try another "
                       f"volume in the container."),
            ))
            return None

        from el.schemas.finding import EvidenceItem
        import hashlib
        listing = "\n".join(sorted(
            str(p.relative_to(exports_dir))
            for p in exports_dir.rglob("*") if p.is_file()))
        listing_path = exports_dir / "MANIFEST.txt"
        listing_path.parent.mkdir(parents=True, exist_ok=True)
        listing_path.write_text(listing)
        ev = EvidenceItem(
            tool="el.disk_forensicator", version="0.1.0",
            command=f"ma.extract_macos_artifacts({label})",
            output_sha256=hashlib.sha256(listing.encode()).hexdigest(),
            output_path=str(listing_path),
            extracted_facts=extracted,
        )
        summary = ", ".join(f"{k}={v}" for k, v in sorted(extracted.items()))
        self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"macOS artifacts extracted from {label}: {summary}"),
            evidence=[ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))
        return exports_dir

    def _extract_ntfs_artifacts(self, ctx: AgentContext, raw_image: Path,
                                 partition: dict, sector_size: int,
                                 label: str) -> Path | None:
        """Mount the NTFS partition read-only and copy known forensic
        artifacts (registry hives, MFT-via-SLA, EVTX, Prefetch, SRUM,
        per-user NTUSER.DAT) into the case exports/ directory.

        Returns the artifacts directory if anything was extracted, else None.
        Always unmounts in cleanup.
        """
        # IMPORTANT: kernel mount target must NOT be inside the ewfmount FUSE
        # mount (FUSE doesn't allow mkdir there — ENOSYS). Use a sibling dir.
        fs_mount = Path("/tmp/el-mounts") / f"{ctx.case_id}-fs-{label}"
        exports_dir = ctx.case_dir / "exports" / "windows-artifacts"
        try:
            sk.mount_ntfs(raw_image, partition["start_sector"], fs_mount,
                          sector_size=sector_size, timeout=60)
        except sk.SleuthkitError as e:
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"NTFS mount failed for {label} ({partition['description']}): {e}",
            ))
            return None

        try:
            extracted = sk.extract_windows_artifacts(fs_mount, exports_dir)
        except Exception as e:
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Artifact extraction errored for {label}: {e}",
            ))
            sk.umount(fs_mount)
            return None

        sk.umount(fs_mount)

        if not extracted:
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"NTFS partition {label} mounted but no recognised Windows "
                      "artifacts found (no Windows/System32/config, no Prefetch, no winevt/Logs)",
            ))
            return None

        summary = ", ".join(f"{k}={v}" for k, v in sorted(extracted.items()))
        from el.schemas.finding import EvidenceItem
        import hashlib
        # Treat the extracted exports dir as the evidence (its file listing
        # serves as the provenance record)
        listing = "\n".join(sorted(str(p.relative_to(exports_dir))
                                    for p in exports_dir.rglob("*") if p.is_file()))
        listing_path = exports_dir / "MANIFEST.txt"
        listing_path.write_text(listing)
        ev = EvidenceItem(
            tool="el.disk_forensicator", version="0.1.0",
            command=f"sk.extract_windows_artifacts({label})",
            output_sha256=hashlib.sha256(listing.encode()).hexdigest(),
            output_path=str(listing_path),
            extracted_facts=extracted,
        )
        self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"Windows artifacts extracted from {label}: {summary}",
            evidence=[ev], hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))
        return exports_dir

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

        # Disk-side anomaly detection: walk the bodyfile for suspicious path
        # patterns (PsExec, PyInstaller temp dirs, masqueraded svchost/lsass,
        # scheduled-task persistence, ransomware-tooling traces, …).
        out.extend(self._scan_disk_anomalies(ctx, fls_run.stdout_path, part_label))
        return out

    def _scan_disk_anomalies(self, ctx: AgentContext, bodyfile_path,
                              part_label: str) -> list[Finding]:
        out: list[Finding] = []
        try:
            hits = disk_anomaly.scan_file(bodyfile_path)
        except Exception as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"disk-anomaly scan failed for {part_label}: {e}",
            )))
            return out
        if not hits:
            return out

        import hashlib
        for h in hits:
            sample = "; ".join(h.matches[:3])
            facts = {"pattern_id": h.pattern_id,
                     "match_count": len(h.matches),
                     "samples": h.matches[:5],
                     "partition": part_label}
            ev = EvidenceItem(
                tool="el.disk_anomaly", version="0.1.0",
                command=f"disk_anomaly.scan_file({bodyfile_path.name})",
                output_sha256=hashlib.sha256(
                    bodyfile_path.read_bytes()[:1024 * 1024]).hexdigest(),
                output_path=str(bodyfile_path),
                extracted_facts=facts,
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Disk anomaly [{h.pattern_id}] in {part_label}: {h.description}. "
                       f"{len(h.matches)} match(es). Samples: {sample}"),
                evidence=[ev], hypotheses_supported=h.hypotheses,
            )))
        return out
