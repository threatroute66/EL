"""Disk Forensicator — Sleuth Kit + EZ Tools orchestration.

Current scope: raw disk images (dd / E01 mounted via ewfmount → raw).
For E01 inputs we surface the requirement for ewfmount as 'insufficient'
rather than silently degrading — keeps the contract honest.
"""
from __future__ import annotations

import os
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import (
    bulk_extractor as be_skill, disk_anomaly, disk_convert,
    exiftool as exif_skill, sleuthkit as sk,
)


class DiskForensicatorAgent(Agent):
    name = "disk_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        kind = ctx.shared.get("evidence_kind") or ""
        if "EWF" in kind:
            return self._handle_ewf(ctx, analysis)
        if kind.startswith(("vhdx", "vhd", "vmdk")):
            return self._handle_vm_disk(ctx, analysis, kind)
        if kind == "bitlocker":
            return self._handle_bitlocker(ctx, analysis)

        return out + self._raw_disk_walk(ctx, analysis, ctx.input_path)

    def _handle_vm_disk(self, ctx: AgentContext, analysis: Path,
                        kind: str) -> list[Finding]:
        """VMDK / VHD / VHDX → raw via qemu-img, then reuse the raw walk.

        Keeps the evidence contract intact: the original file is never
        touched; the converted raw lives under `<case_dir>/raw/` so the
        hash trail covers both the source (intake manifest) and the
        working copy (conversion evidence)."""
        out: list[Finding] = []
        raw_dir = ctx.case_dir / "raw"
        try:
            result = disk_convert.convert_to_raw(
                ctx.input_path, source_kind=kind, out_dir=raw_dir,
            )
        except disk_convert.DiskConvertError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"{kind} input detected but conversion to raw "
                       f"failed: {e}. Downstream filesystem walk "
                       "skipped — install qemu-utils or pre-convert."),
            )))
            return out

        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"{kind} converted to raw via qemu-img "
                   f"(v{result.qemu_img_version}); proceeding with "
                   f"mmls + per-partition fls on {result.raw_path.name}"),
            evidence=[result.as_evidence({"phase": "vm_disk_convert"})],
            hypotheses_supported=["H_DISK_IMAGE"],
        )))
        return out + self._raw_disk_walk(ctx, analysis, result.raw_path)

    def _handle_bitlocker(self, ctx: AgentContext,
                            analysis: Path) -> list[Finding]:
        """BitLocker volume path: probe header → unlock with operator-
        supplied recovery key(s) → walk decrypted volume like raw.

        Credential sources, checked in order:
          1. ctx.shared['bitlocker_recovery_keys'] — list[str] of
             48-digit passwords (typically 1; supplying multiple
             handles the multi-protector case).
          2. EL_BITLOCKER_RECOVERY_KEYS env var — comma-separated.

        Without credentials we emit a high-confidence `H_DISK_ENCRYPTED`
        finding reporting the volume GUID + key-protector GUIDs so the
        analyst knows WHICH recovery key to retrieve, then stop —
        downstream filesystem walks would be meaningless on encrypted
        ciphertext."""
        from el.skills import dislocker as dl
        out: list[Finding] = []

        # Phase 1: probe metadata — always runs, no credentials needed.
        try:
            md = dl.probe_metadata(ctx.input_path, analysis,
                                     timeout=120)
        except dl.DislockerError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"BitLocker probe failed: {e}. Install "
                       "`dislocker` (apt: dislocker on SIFT) to enable "
                       "BitLocker handling."),
            )))
            return out
        if not md.recovery_key_guids:
            # No protectors parsed — likely a corrupt header or a
            # signature collision (extremely unlikely false positive).
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"`-FVE-FS-` signature detected but "
                       "`dislocker-metadata` could not extract any "
                       "key-protector GUIDs from the FVE metadata. "
                       "Header may be corrupt or this is a "
                       "non-BitLocker volume that happens to carry the "
                       "magic. Raw walk SKIPPED to avoid analysing "
                       "ciphertext."),
                evidence=[md.as_evidence()],
            )))
            return out

        # Surface the probe result first — analyst sees the volume
        # is BitLocker, knows which protector GUIDs to find keys for.
        protectors_summary = (
            f"{len(md.recovery_key_guids)} recovery-key protector(s)"
            f"{' + TPM' if md.has_tpm_protector else ''}"
            f"{' + password' if md.has_password_protector else ''}"
            f"{' + BEK' if md.has_bek_protector else ''}")
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"BitLocker volume detected: "
                   f"{md.encryption_type or 'unknown encryption'}, "
                   f"state={md.state or '?'}, volume size "
                   f"{md.volume_size:,} bytes, "
                   f"GUID={md.volume_guid or '?'}; "
                   f"protectors: {protectors_summary} "
                   f"(GUIDs: {', '.join(md.recovery_key_guids)})"),
            evidence=[md.as_evidence()],
            hypotheses_supported=["H_DISK_ENCRYPTED"],
        )))

        # Phase 2: gather credentials. Operator may supply 0+ recovery
        # passwords via ctx.shared or env. We do NOT try every key
        # against every protector — dislocker tries them all internally
        # and rejects with rc!=0 if none match.
        recovery_keys: list[str] = list(
            ctx.shared.get("bitlocker_recovery_keys") or [])
        env_keys = (os.environ.get("EL_BITLOCKER_RECOVERY_KEYS") or "").strip()
        if env_keys:
            for k in env_keys.split(","):
                k = k.strip()
                if k:
                    recovery_keys.append(k)
        if not recovery_keys:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("BitLocker recovery key not supplied — filesystem "
                       "walk skipped. Provide via "
                       "ctx.shared['bitlocker_recovery_keys'] (list[str] "
                       "of 48-digit passwords) or the "
                       "EL_BITLOCKER_RECOVERY_KEYS env var "
                       "(comma-separated). Match a key to one of the "
                       f"protector GUIDs above: "
                       f"{', '.join(md.recovery_key_guids)}"),
            )))
            return out

        # Phase 3: try recovery keys until one unlocks. Multiple keys
        # supplied = the operator has keys for several protectors and
        # doesn't know which one this volume belongs to (multi-host
        # bundle). Try each; first match wins.
        mount_point = Path("/tmp/el-bitlocker") / ctx.case_id
        unlocked: dl.DislockerMount | None = None
        last_error = ""
        for pw in recovery_keys:
            try:
                unlocked = dl.mount(ctx.input_path, mount_point,
                                      recovery_password=pw,
                                      stderr_out=analysis / "dislocker-fuse.stderr",
                                      timeout=60)
                break
            except dl.DislockerError as e:
                last_error = str(e)
                # Wrong key for this protector — try next.
                dl.umount(mount_point)
                continue
        if unlocked is None:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"BitLocker unlock failed with "
                       f"{len(recovery_keys)} candidate recovery key(s) "
                       f"against {len(md.recovery_key_guids)} protector "
                       f"GUID(s) — none matched. Last dislocker error: "
                       f"{last_error[:200]}. Verify keys against the "
                       f"protector GUIDs and re-run."),
            )))
            return out
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"BitLocker volume unlocked via recovery key "
                   f"(protector kind: {unlocked.used_protector_kind}, "
                   f"sha256 of supplied key: "
                   f"{unlocked.used_protector_digest[:16]}…); "
                   f"decrypted stream available at "
                   f"{unlocked.decrypted_file}."),
            evidence=[unlocked.as_evidence()],
            hypotheses_supported=["H_DISK_ENCRYPTED"],
        )))

        # Phase 4: standard raw-disk walk against the decrypted file.
        try:
            out.extend(self._raw_disk_walk(
                ctx, analysis, unlocked.decrypted_file))
        finally:
            dl.umount(mount_point)
        return out

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
                # Acquirer-vs-target clock skew baseline. The two
                # header dates in ewfinfo stdout are emitted by libewf
                # in the acquirer's local TZ with no TZ tag, so each
                # individual value isn't UTC-anchored — but their
                # DELTA is TZ-independent and the first calibration
                # point analysts need before reading any FAT / EXIF /
                # Office-metadata local-time values.
                out.extend(self._ewf_skew_baseline(ctx, info.stdout_path))
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

    def _ewf_skew_baseline(self, ctx: AgentContext,
                            ewfinfo_stdout: Path) -> list[Finding]:
        """Parse ewfinfo stdout for the (Acquisition date, System date)
        delta, emit a baseline Finding. The DELTA itself is TZ-
        independent — the same forensic value regardless of which TZ
        libewf used to render either timestamp."""
        from el.skills import ewf_skew
        skew = ewf_skew.parse_file(ewfinfo_stdout)
        if not skew.have_skew:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("EWF acquirer-vs-target clock skew baseline: "
                       "ewfinfo stdout did not carry both Acquisition "
                       "date and System date — calibration baseline "
                       "unavailable from EWF header alone (analyst "
                       "should look for an external reference)."),
            ))]
        # Plain-English summary the analyst reads at the top of the
        # report. Sign convention: positive = target clock was AHEAD
        # of the acquirer's reference (rare, usually wrong system
        # time); negative = target was BEHIND.
        if skew.skew_seconds == 0:
            verdict = ("0s — target's RTC matched the acquirer's "
                       "reference clock at acquisition")
        else:
            direction = "behind" if skew.skew_seconds > 0 else "ahead of"
            verdict = (f"{abs(skew.skew_seconds)}s — target's RTC was "
                       f"{direction} the acquirer's reference clock")
        import hashlib
        try:
            sha = hashlib.sha256(ewfinfo_stdout.read_bytes()).hexdigest()
        except OSError:
            sha = "0" * 64
        ev = EvidenceItem(
            tool="el.ewf_skew", version="0.1.0",
            command=f"parse_file({ewfinfo_stdout.name})",
            output_sha256=sha,
            output_path=str(ewfinfo_stdout),
            extracted_facts={
                "acquisition_date": skew.acquisition_date_raw,
                "system_date": skew.system_date_raw,
                "skew_seconds": skew.skew_seconds,
                "phase": "time_baseline",
            },
        )
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"EWF acquirer-vs-target clock skew baseline: "
                   f"{verdict}. Acquisition date {skew.acquisition_date_raw!r}, "
                   f"system date {skew.system_date_raw!r}. Use this delta "
                   f"to calibrate any FAT / EXIF / Office-metadata local-"
                   f"time values in the case."),
            evidence=[ev],
            hypotheses_supported=["H_DISK_IMAGE"],
        ))]

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
                # Stash in shared state so the recovery pass (which
                # remounts the EWF after disk_forensicator unmounts)
                # can run tsk_recover per partition without re-running mmls.
                ctx.shared["partitions"] = partitions
                ctx.shared["raw_input_path"] = str(ctx.input_path)
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
            # ReFS pre-check — Sleuth Kit can't read ReFS, so fls
            # would just fail with rc=1 and the analyst would see
            # "fls failed" with no explanation. Detect the signature
            # first and route to refsprogs (the userspace ReFS
            # toolset) which CAN walk it. See el.skills.refsprogs.
            try:
                from el.skills import refsprogs as rp
                if rp.is_refs_signature(
                        raw_image,
                        offset=p["start_sector"] * sector_size):
                    out.extend(self._walk_refs_partition(
                        ctx, raw_image, p, sector_size, analysis, label))
                    continue
            except Exception:
                # Defensive — a refs-check failure must NEVER block
                # the normal fls path for other partition types.
                pass
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

    def _walk_refs_partition(
            self, ctx: AgentContext, raw_image: Path, partition: dict,
            sector_size: int, analysis: Path, label: str
    ) -> list[Finding]:
        """ReFS partition walk via refsprogs (userspace ReFS toolset).
        Sleuth Kit + Linux kernel have no ReFS support, so this is the
        only path EL has to read Windows 11 Dev Drives + Server 2016+
        ReFS volumes.

        Carves the partition out of the raw image first (refsprogs has
        no offset flag — expects a standalone ReFS volume), runs
        refsinfo → refslabel → refsls, emits one finding per stage.
        Confidence is `medium` per the upstream caveat that refsprogs
        coverage is best-effort.
        """
        from el.skills import refsprogs as rp
        out: list[Finding] = []
        carved = analysis / f"refs-{label}.raw"
        try:
            rp.carve_partition(
                raw_image,
                partition_start_sector=partition["start_sector"],
                partition_length_sectors=partition["length_sectors"],
                sector_size=sector_size, out_path=carved)
        except OSError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"ReFS partition {label} ({partition['description']}) "
                       f"detected but carve-to-raw failed: {e}. "
                       "Walk skipped — needs disk space equal to the "
                       "partition's declared size."),
            ))]
        # Verify signature on the carved file too — protects against
        # mmls reporting a length that doesn't actually contain the
        # FS magic at the carved start.
        if not rp.is_refs_signature(carved):
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"ReFS signature detected at partition {label} "
                       "but disappeared after carve — partition table "
                       "metadata may be inconsistent. Walk skipped."),
            )))
            return out

        # Phase 1: refsinfo
        try:
            info = rp.probe_volume(carved, analysis, timeout=120)
        except rp.RefsprogsError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"ReFS partition {label}: refsinfo failed — {e}. "
                       "Install refsprogs (build from "
                       "https://github.com/unsound/refsprogs) to enable "
                       "ReFS walk."),
            )))
            return out
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="medium",
            claim=(f"ReFS partition {label} ({partition['description']}): "
                   f"version {info.refs_version}, "
                   f"sector_size={info.sector_size}, "
                   f"cluster_size={info.cluster_size}, "
                   f"{info.sector_count:,} sectors, "
                   f"serial={info.volume_serial}. "
                   "Walked via refsprogs (best-effort — upstream "
                   "warns ReFS on-disk format is reverse-engineered)."),
            evidence=[info.as_evidence()],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        # Phase 2: refslabel
        label_str = rp.read_label(carved)
        if label_str:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"ReFS partition {label} volume label: "
                       f"{label_str!r}"),
            )))

        # Phase 3: refsls walk → directory listing
        try:
            listing = rp.walk(carved, analysis)
        except rp.RefsprogsError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"ReFS partition {label}: refsls failed — {e}"),
            )))
            return out
        sample_entries = "; ".join(
            f"{e['name']} ({e['size_bytes']}B)"
            for e in listing.entries[:5])
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="medium",
            claim=(f"ReFS partition {label}: "
                   f"{listing.entry_count} file/dir entries listed via "
                   f"refsls -l -R"
                   f"{' (TRUNCATED at cap)' if listing.truncated else ''}"
                   f". Sample: {sample_entries}"),
            evidence=[listing.as_evidence()],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
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
        # Volume Shadow Copy enumeration BEFORE the live-FS mount.
        # vshadowinfo reads the VSS metadata directly off the raw
        # stream — no kernel mount needed — so it works whether or
        # not we successfully mount the partition afterwards. Each
        # snapshot listed here is a separate point-in-time view of
        # registry / EVTX / user files the analyst can re-acquire by
        # vshadowmount-ing the store and re-running the disk pipeline
        # against it (full pipeline integration is future work).
        try:
            from el.skills import vss
            shadows = vss.list_shadows(
                raw_image, offset=partition["start_sector"] * sector_size,
                timeout=60,
            )
            if shadows:
                from el.schemas.finding import EvidenceItem
                import hashlib
                sample = "; ".join(
                    f"#{s.index} ({s.creation_time_utc or '?'}, "
                    f"{s.volume_size_bytes // (1024**3)} GiB)"
                    for s in shadows[:5]
                )
                self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="medium",
                    claim=(f"Volume Shadow Copies on {label}: "
                           f"{len(shadows)} snapshot(s) present. "
                           f"Each is a distinct point-in-time view of "
                           f"the volume — registry / EVTX / user files "
                           f"may differ between acquisition and the "
                           f"snapshot timestamps. "
                           f"Snapshots: {sample}"
                           f"{' …' if len(shadows) > 5 else ''}. "
                           "Mount via `vshadowmount` to re-run this "
                           "pipeline against any individual snapshot."),
                    evidence=[EvidenceItem(
                        tool="vshadowinfo", version="libvshadow-tools",
                        command=(f"vshadowinfo -o "
                                  f"{partition['start_sector']*sector_size} "
                                  f"<raw>"),
                        output_sha256=hashlib.sha256(
                            "|".join(s.identifier for s in shadows).encode()
                        ).hexdigest(),
                        output_path=str(raw_image),
                        extracted_facts={
                            "shadow_count": len(shadows),
                            "shadow_ids": [s.identifier for s in shadows][:10],
                            "creation_times": [
                                s.creation_time_utc for s in shadows][:10],
                        })],
                    hypotheses_supported=["H_DISK_ARTIFACTS"],
                ))
        except Exception:
            # vshadowinfo failures are not fatal — non-VSS volumes are
            # the common case.
            pass

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

        # FOR508 ex 3.1b: cross-snapshot artifact diff. Compare a small
        # forensically-critical artefact set (RecentFileCache, Amcache,
        # Security/System/Application EVTX, scheduled-task .job files)
        # against each VSS snapshot — anything present in shadow but
        # absent or shrunk on the live FS is anti-forensic erasure
        # (operator scrubbed the live copy but did not clean shadows).
        # Run BEFORE the live unmount so fs_mount is still a valid
        # fingerprint source.
        try:
            self._run_vss_diff(ctx, raw_image, partition, sector_size,
                                fs_mount, label)
        except Exception as e:
            # Diff failures are not fatal — non-VSS volumes are common,
            # and the per-snapshot mount can fail on any number of
            # transient FUSE / sudo issues.
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"VSS cross-snapshot diff skipped for {label}: "
                       f"{type(e).__name__}: {str(e)[:160]}"),
            ))

        # FOR508 ex 2.5: hibernation-file shell history. C:\hiberfil.sys
        # is a frozen RAM snapshot from the moment the host last
        # hibernated; running vol3 cmdscan/consoles against it surfaces
        # commands typed *before* the live capture's RAM was acquired —
        # which is often when the operator was actually working. Run
        # while fs_mount is still up so we can stat hiberfil.sys
        # directly via the mounted filesystem.
        try:
            self._run_hiberfil_shell_history(ctx, fs_mount, label)
        except Exception as e:
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"Hibernation shell-history extraction skipped for "
                       f"{label}: {type(e).__name__}: {str(e)[:160]}"),
            ))

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

    def _run_vss_diff(self, ctx: AgentContext, raw_image: Path,
                      partition: dict, sector_size: int,
                      live_mount: Path, label: str) -> None:
        """FOR508 ex 3.1b: enumerate VSS snapshots on this partition,
        loop-mount each one, fingerprint the forensic-critical artefact
        list on live + snapshot, emit one Finding per non-trivial diff
        (deleted-in-live, shrunk-in-live, content-changed).

        Best-effort throughout — no snapshots, no permission, no NTFS
        parser on the snapshot device, etc., are all soft failures
        (the caller wraps this in a try/except that emits one
        insufficient-evidence Finding for the whole step).
        """
        from el.skills import vss_diff
        offset_bytes = partition["start_sector"] * sector_size

        snapshots = vss_diff.vshadowinfo(
            raw_image, offset_bytes=offset_bytes, timeout=60)
        if not snapshots:
            return  # non-VSS volume — nothing to diff

        # Mount all snapshots once via vshadowmount; per-snapshot NTFS
        # mounts loop on the resulting vss<N> device files.
        vss_root = Path("/tmp/el-mounts") / f"{ctx.case_id}-vss-{label}"
        vss_diff.vshadowmount(raw_image, vss_root,
                               offset_bytes=offset_bytes, timeout=60)

        try:
            # Fingerprint the live side once (same artefact set per snapshot).
            live_fp = vss_diff.fingerprint(live_mount, side="live")

            for snap in snapshots:
                vss_dev = vss_root / f"vss{snap.number}"
                if not vss_dev.exists():
                    continue
                snap_mount = (Path("/tmp/el-mounts")
                              / f"{ctx.case_id}-vss-{label}-fs{snap.number}")
                try:
                    # Snapshot device is already a single-volume stream
                    # (libvshadow exposes the unwrapped NTFS), so pass
                    # offset_sectors=0.
                    sk.mount_ntfs(vss_dev, offset_sectors=0,
                                   mount_point=snap_mount,
                                   sector_size=sector_size, timeout=60)
                except sk.SleuthkitError as e:
                    self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="insufficient",
                        claim=(f"VSS snapshot {snap.number} on {label} "
                               f"failed to mount: {e}"),
                    ))
                    continue

                try:
                    snap_fp = vss_diff.fingerprint(
                        snap_mount, side=f"snapshot:{snap.number}")
                    diffs = vss_diff.diff_fingerprints(
                        live_fp, snap_fp, snapshot_number=snap.number)
                    for d in diffs:
                        ev = vss_diff.diff_as_evidence(d, raw_image)
                        # Severity → hypothesis mapping. deleted_in_live
                        # is the load-bearing case; shrunk/changed are
                        # corroborative.
                        hyp = ["H_SHADOW_COPY_ARTIFACT_DELETED",
                               "H_ANTI_FORENSICS"]
                        if d.relpath.lower().endswith(".evtx"):
                            hyp.append("H_LOG_CLEARED")
                        sev_label = {
                            "deleted_in_live":
                                "PRESENT in shadow, ABSENT on live FS",
                            "shrunk_in_live":
                                "live FS smaller than shadow",
                            "changed":
                                "content differs (size matches)",
                        }.get(d.severity, d.severity)
                        self.emit(ctx, Finding(
                            case_id=ctx.case_id, agent=self.name,
                            confidence="high",
                            claim=(f"VSS diff on {label}: "
                                   f"`{d.relpath}` — {sev_label} "
                                   f"(snapshot #{snap.number}, "
                                   f"Δ={d.delta_bytes} bytes). "
                                   f"Anti-forensic erasure shape — "
                                   f"operator likely scrubbed the live "
                                   f"copy but did not clean shadows."),
                            evidence=[ev],
                            hypotheses_supported=hyp,
                        ))
                finally:
                    sk.umount(snap_mount)
        finally:
            vss_diff.fusermount_unmount(vss_root)

    def _run_hiberfil_shell_history(self, ctx: AgentContext,
                                     live_mount: Path, label: str) -> None:
        """FOR508 ex 2.5 follow-on: vol3 cmdscan + consoles on
        ``hiberfil.sys`` from the mounted live filesystem. Vol3
        automagic detects the hibernation layer directly — no
        Vol2-era ``imagecopy`` step needed.

        Best-effort throughout: missing hiberfil, wrong size, vol3
        layer-detection failure, and "ran but returned no rows" all
        produce informational Findings rather than raising. This is
        the freebie tier of the workbook follow-on; we want it to
        be silent on hosts where hibernation isn't enabled.
        """
        from el.skills import vol3

        # Hibernation file lives at the partition root. Some Windows
        # configurations ship hiberfil.sys but with hibernation disabled
        # (file shrinks to ~16 MB or stays at "no valid signature").
        # We require ≥100 MiB before bothering with vol3 — small files
        # are guaranteed not to contain command-history structures.
        candidates = [
            live_mount / "hiberfil.sys",
            live_mount / "Hiberfil.sys",
            live_mount / "HIBERFIL.SYS",
        ]
        hiberfil = next((p for p in candidates if p.is_file()), None)
        if hiberfil is None:
            return  # silent — common case

        try:
            size = hiberfil.stat().st_size
        except OSError:
            return
        if size < 100 * 1024 * 1024:
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"Hibernation file present on {label} but too small "
                       f"({size} bytes < 100 MiB) — hibernation likely "
                       f"disabled on this host."),
            ))
            return

        analysis = ctx.case_dir / "analysis" / self.name / "hiberfil"
        analysis.mkdir(parents=True, exist_ok=True)

        # Reuse the same scoring path as live-RAM cmdscan/consoles via
        # the module-level helpers we exported from memory_forensicator.
        from el.agents.memory_forensicator import (
            extract_shell_lines, keyword_hits)

        for plugin in ("windows.cmdscan.CmdScan", "windows.consoles.Consoles"):
            try:
                run = vol3.run_plugin(hiberfil, plugin, analysis,
                                       timeout=900)
            except vol3.Vol3Error as e:
                self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=(f"vol3 {plugin} on hiberfil.sys ({label}) "
                           f"failed: {e}"),
                ))
                continue
            if run.rc != 0:
                # vol3 layer-detection failure on hiberfil.sys is common
                # (compressed segments, version mismatches). Treat as
                # insufficient — the live-RAM path still ran.
                self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=(f"vol3 {plugin} could not parse hiberfil.sys on "
                           f"{label} (rc={run.rc}). Hibernation files use "
                           f"a compressed layer vol3 can't always decode "
                           f"without an exact build symbol match — see "
                           f"{run.stderr_path.name}."),
                ))
                continue

            lines = extract_shell_lines(run.rows)
            if not lines:
                continue   # silent — boring "ran but no rows"

            plugin_short = plugin.split(".")[-1]
            umbrella_ev = run.as_evidence({
                "source": "hiberfil.sys", "host_label": label,
                "recovered_lines": len(lines), "sample": lines[:5],
            })
            self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Shell history recovered from HIBERNATION FILE "
                       f"({label}) via {plugin_short}: {len(lines)} "
                       f"non-empty line(s). These are commands the operator "
                       f"typed BEFORE the live RAM capture — frequently "
                       f"the most operationally interesting window."),
                evidence=[umbrella_ev],
                hypotheses_supported=["H_LIVING_OFF_THE_LAND",
                                       "H_CODE_EXECUTION"],
            ))

            for (hyp, kw_label), matched in keyword_hits(lines).items():
                ev = run.as_evidence({
                    "source": "hiberfil.sys", "host_label": label,
                    "keyword": kw_label, "hits": len(matched),
                    "sample": matched[:3],
                })
                self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim=(f"Hibernation-file shell-history keyword "
                           f"[{kw_label}]: {len(matched)} line(s) match "
                           f"in {plugin_short} output on {label}. "
                           f"Sample: {matched[0]!r}"),
                    evidence=[ev],
                    hypotheses_supported=[hyp],
                ))

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
        from datetime import datetime as _dt, timezone as _tz
        for h in hits:
            sample = "; ".join(h.matches[:3])
            facts = {"pattern_id": h.pattern_id,
                     "match_count": len(h.matches),
                     "samples": h.matches[:5],
                     "partition": part_label}
            # Surface earliest mtime as artifact time so the kill-chain
            # swimlane and Attack Event Timeline can place this anomaly
            # on the real-world clock. Only row-wise detectors populate
            # earliest_unix; path-pattern hits leave it None.
            if h.earliest_unix:
                facts["mtime_utc"] = _dt.fromtimestamp(
                    h.earliest_unix, tz=_tz.utc).isoformat()
            if h.latest_unix and h.latest_unix != h.earliest_unix:
                facts["mtime_latest_utc"] = _dt.fromtimestamp(
                    h.latest_unix, tz=_tz.utc).isoformat()
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
