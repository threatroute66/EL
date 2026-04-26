"""AndroidForensicator — primary investigator for Android filesystem
tree inputs.

Android cases typically arrive as already-extracted file-system
trees (Belkasoft output / UFED Reader export / adb pull of /data
and /storage). No mounting needed — the agent walks the input dir,
runs `extract_android_artifacts` to produce the sealed exports
subtree, then runs `android_triage.run_all` for detection.

Routed from Triage when `ctx.shared["evidence_kind"] == "android-fs-dir"`
(parallel to how `windows-artifacts-dir` routes to
WindowsArtifactAgent).

Confidence tiers:
  rooted_device → medium (informational — rooted ≠ compromised, but
    flips the threat model)
  sideloaded_apk → high (the primary delivery vector for Android
    malware in the wild)
  data_local_tmp_executable → high (attacker shell staging)
  messenger_presence → low (purely informational)
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import android_artifacts as aa
from el.skills import android_triage as at


def _describe_node(p: Path) -> str:
    """One-word label for a non-regular FS node — used in YAFFS2
    merge error strings."""
    try:
        st = p.stat()
    except OSError:
        return "unknown"
    import stat
    if stat.S_ISFIFO(st.st_mode):
        return "FIFO"
    if stat.S_ISSOCK(st.st_mode):
        return "socket"
    if stat.S_ISCHR(st.st_mode):
        return "char-device"
    if stat.S_ISBLK(st.st_mode):
        return "block-device"
    return "special"


_CONFIDENCE_BY_FAMILY = {
    "rooted_device":              "medium",
    "sideloaded_apk":             "high",
    "data_local_tmp_executable":  "high",
    "messenger_presence":         "low",
}


class AndroidForensicatorAgent(Agent):
    name = "android_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        src = ctx.input_path
        # ALEAPP-only path: input is a .tar/.zip/.gz archive of an
        # Android extraction (Magnet Acquire / UFED export). The
        # archive-mode wrap drives ALEAPP directly without
        # filesystem extract — the wrap handles unpacking.
        if src.is_file() and src.suffix.lower() in (
                ".tar", ".zip", ".gz"):
            return self._run_aleapp(ctx, src)
        # MTD/YAFFS2 bundle path: input is a directory of mtdN.dd
        # raw partition dumps (old-Android phones, Case2-style).
        # Run the YAFFS2 extract first; if any partition produces a
        # filesystem tree, re-point src at the merged extract dir
        # and let the standard android-artifacts walker take over.
        if src.is_dir() and (
                ctx.shared.get("evidence_kind") == "android-mtd-bundle"):
            yaffs_findings, redirected = self._run_yaffs2_bundle(
                ctx, src)
            if redirected is not None:
                src = redirected               # downstream walks the extract
                pre_findings = yaffs_findings
            else:
                # Nothing extracted — return only the YAFFS2 findings
                # (each will be insufficient or low-confidence).
                return yaffs_findings
        else:
            pre_findings: list[Finding] = []
        if not src.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("AndroidForensicator: input is not a directory "
                       "or supported archive (.tar / .zip / .gz / "
                       "MTD/YAFFS2 bundle). Android cases arrive as "
                       "file-system trees (Belkasoft / UFED / adb-"
                       "pull), Magnet/UFED archive bundles, or "
                       "old-Android mtd*.dd partition dumps."),
            ))]

        exports = ctx.case_dir / "exports" / "android-artifacts"
        try:
            counts = aa.extract_android_artifacts(src, exports)
        except Exception as e:
            return pre_findings + [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"Android extraction errored: {e}",
            ))]
        out: list[Finding] = list(pre_findings)
        if not counts:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"AndroidForensicator: walked {src.name} but no "
                       f"Android artifacts recognised (no data/system/"
                       f"packages.xml, no data/data/ per-app dirs, no "
                       f"data/adb/, no data/local/tmp/). Likely not an "
                       f"Android filesystem tree."),
            )))
            return out

        listing = "\n".join(sorted(
            str(p.relative_to(exports))
            for p in exports.rglob("*") if p.is_file()))
        listing_path = exports / "MANIFEST.txt"
        listing_path.parent.mkdir(parents=True, exist_ok=True)
        listing_path.write_text(listing)
        summary_ev = EvidenceItem(
            tool="el.android_artifacts", version="0.1.0",
            command=f"extract_android_artifacts({src.name})",
            output_sha256=hashlib.sha256(listing.encode()).hexdigest(),
            output_path=str(listing_path),
            extracted_facts=counts,
        )
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Android artifacts extracted from {src.name}: "
                   f"{summary}"),
            evidence=[summary_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        hits = at.run_all(exports)
        for h in hits:
            confidence = _CONFIDENCE_BY_FAMILY.get(h.family, "medium")
            ev = EvidenceItem(
                tool="el.android_triage", version="0.1.0",
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
                claim=(f"Android {h.family}: {h.event_count} "
                       f"signal(s); {h.matched_pattern}. "
                       f"ATT&CK: "
                       f"{', '.join(t for t, _ in h.attack) or '-'}. "
                       f"Sample: {h.sample_text[:150]!r}"),
                evidence=[ev],
                hypotheses_supported=at.hypotheses_for(h.family)
                                       or ["H_DISK_ARTIFACTS"],
            )))
        # ALEAPP wrap — Brignoni's 150+-artifact Android parser.
        # Skips silently when ALEAPP isn't installed; emits one
        # Finding per surfaced high-value artefact (contacts2,
        # mmssms, Chrome history, app-data DBs, Wi-Fi config).
        out.extend(self._run_aleapp(ctx, src))
        return out

    # ALEAPP TSV name → (display label, confidence, hypotheses).
    # Curated to high-signal artefacts so the ledger doesn't flood
    # on the 150+ tables ALEAPP can produce. Names are substring-
    # matched case-insensitive against table.name.
    _ALEAPP_HIGH_VALUE = {
        "Contacts":               ("contacts",            "low",    []),
        "SMS":                    ("SMS / MMS",           "medium", []),
        "MMS":                    ("SMS / MMS",           "medium", []),
        "Call":                   ("call history",        "medium", []),
        "Chrome":                 ("Chrome history",      "medium", []),
        "Chrome History":         ("Chrome history",      "medium", []),
        "Browser":                ("browser history",     "medium", []),
        "WhatsApp":               ("WhatsApp messages",   "medium", []),
        "Telegram":               ("Telegram messages",   "medium", []),
        "Signal":                 ("Signal messages",     "medium", []),
        "Installed Apps":         ("installed apps",      "low",
                                    ["H_DISK_ARTIFACTS"]),
        "Package":                ("package inventory",   "low",
                                    ["H_DISK_ARTIFACTS"]),
        "WiFi":                   ("Wi-Fi configuration", "medium",
                                    ["H_DISK_ARTIFACTS"]),
        "Wifi":                   ("Wi-Fi configuration", "medium",
                                    ["H_DISK_ARTIFACTS"]),
        "Bluetooth":              ("Bluetooth pairings",  "low",    []),
        "Location":               ("location history",    "medium", []),
        "Locations":              ("location history",    "medium", []),
        "Notification":           ("notification history","low",    []),
        "Logcat":                 ("logcat snapshots",    "low",    []),
    }

    @staticmethod
    def _merge_yaffs2_tree(src: Path, dst: Path) -> list[str]:
        """Walk a YAFFS2 extract and copy every regular file +
        directory into ``dst``, skipping special files (FIFOs,
        sockets, character devices) that ``shutil.copy*`` can't
        handle. Returns a list of human-readable per-file error
        strings (empty when the merge was clean).

        Old Android NAND dumps faithfully preserved by unyaffs2
        carry FIFOs (e.g. ``misc/ril/pppd-notifier.fifo``) and
        Unix domain sockets (``misc/ril/RIL_RDS_SOCKET``) — these
        are runtime IPC nodes, not data, so we skip them rather
        than letting copytree explode."""
        import shutil as _shutil
        errors: list[str] = []
        src = Path(src)
        for path in src.rglob("*"):
            try:
                rel = path.relative_to(src)
            except ValueError:
                continue
            target = dst / rel
            try:
                if path.is_symlink():
                    # Preserve symlinks as link content rather than
                    # following them.
                    if target.exists() or target.is_symlink():
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(path.readlink())
                elif path.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                elif path.is_file():
                    if target.exists():
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    _shutil.copy2(path, target)
                else:
                    # FIFO, socket, character/block device —
                    # log + skip.
                    errors.append(
                        f"skipped special file: "
                        f"{rel} ({_describe_node(path)})")
            except OSError as e:
                errors.append(
                    f"copy {rel} → {target.name}: {e}")
        return errors

    @staticmethod
    def _yaffs2_role(extract_root: Path) -> str | None:
        """Sniff the Android partition role from a YAFFS2 extract's
        top-level directories. Returns ``"system"``, ``"data"``,
        ``"cache"``, or None when the role is ambiguous.

        - system partition: build.prop + framework/ + (app/ or bin/
                            or lib/) at root → "system"
        - data partition:   data/ + app/ + dalvik-cache/ OR
                            ``data/system/packages.xml`` directly
                            visible → "data"
        - cache partition:  download/ + recovery/ + lost+found at
                            root with no other markers → "cache"
        """
        d = Path(extract_root)
        if not d.is_dir():
            return None
        names = {p.name for p in d.iterdir()}
        # Strong system signal — build.prop is exclusive to /system
        if ("build.prop" in names
                and ("framework" in names or "app" in names
                     or "lib" in names)):
            return "system"
        # Data partition shape — Android puts /data contents at root
        # of the userdata YAFFS2 (so root has app/, data/, system/,
        # dalvik-cache/, app-private/ etc.). The discriminator from
        # /system is the absence of build.prop + presence of
        # dalvik-cache/ or app-private/.
        if ("dalvik-cache" in names or "app-private" in names
                or "anr" in names
                or (d / "data" / "system"
                    / "packages.xml").is_file()):
            return "data"
        # Cache partition shape
        if names <= {"download", "recovery", "lost+found",
                      "lost.dir", "fota"}:
            return "cache"
        return None

    def _run_yaffs2_bundle(self, ctx: AgentContext, bundle: Path
                            ) -> tuple[list[Finding], Path | None]:
        """Extract YAFFS2-shaped partitions from an MTD bundle via
        unyaffs. Returns ``(findings, extracted_root)``. The
        extracted_root is the merged FS that the standard
        android-artifacts walker should consume; None when no
        partition produced files (caller emits the YAFFS2 findings
        and bails)."""
        from el.skills import yaffs2 as y_skill
        out: list[Finding] = []
        extract_root = ctx.case_dir / "exports" / "yaffs2"
        extract_root.mkdir(parents=True, exist_ok=True)
        # Per-partition extract; merged into a single FS root for
        # the downstream walker. Mounting the system + userdata
        # partitions side-by-side under one root mirrors the way
        # Android lays them at runtime.
        merged = ctx.case_dir / "exports" / "yaffs2-merged"
        merged.mkdir(parents=True, exist_ok=True)
        res = y_skill.walk_bundle(bundle, extract_root)
        if not res.extractions:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"MTD bundle at {bundle.name}: no YAFFS2-"
                       f"shaped partitions detected by the "
                       f"heuristic detector across "
                       f"{len(list(bundle.glob('mtd*.dd')))} mtd*.dd "
                       f"file(s). The dump may use a non-default "
                       f"page/OOB geometry, or only the bootloader "
                       f"+ kernel partitions are present."),
            )))
            return out, None
        any_success = False
        for ex in res.extractions:
            sha = "0" * 64
            try:
                sha = hashlib.sha256(
                    ex.image_path.read_bytes()[:4096]
                ).hexdigest()
            except OSError:
                pass
            ev = EvidenceItem(
                tool="unyaffs", version="0.9.7",
                command=f"unyaffs {ex.image_path.name} "
                         f"{ex.out_dir.name}",
                output_sha256=sha,
                output_path=str(ex.out_dir),
                extracted_facts={
                    "image": ex.image_path.name,
                    "rc": ex.rc,
                    "file_count": ex.file_count,
                    "bytes_extracted": ex.bytes_extracted,
                    "error": ex.error[:500],
                },
                source_reliability="A", info_credibility="1",
            )
            if ex.success:
                any_success = True
                # ex.error on success carries the success note —
                # "extracted via unyaffs (-b -c 2 -s 64)" or
                # "extracted via unyaffs2 (-p 2048 -s 64)" —
                # plumb it into the Finding claim so the analyst
                # sees which extractor + geometry won.
                tool_note = ex.error or "via extractor"
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="high",
                    claim=(f"YAFFS2 partition {ex.image_path.name} "
                           f"{tool_note}: "
                           f"{ex.file_count} file(s), "
                           f"{ex.bytes_extracted:,} byte(s)."),
                    evidence=[ev],
                    hypotheses_supported=["H_DISK_ARTIFACTS"],
                )))
                # Merge into the unified FS root. A YAFFS2 image is
                # the *contents* of an Android partition mounted at
                # a role-specific path (/system, /data, /cache), so
                # the extract's top-level dirs map differently per
                # role. We sniff the role from the extracted shape
                # and re-mount it under the right role-named
                # subdirectory so the downstream android-artifacts
                # walker (which hunts for "data/system/packages.xml"
                # etc.) can find its markers regardless of which
                # partition contributed them.
                role = self._yaffs2_role(ex.out_dir)
                target_root = (merged / role) if role else merged
                target_root.mkdir(parents=True, exist_ok=True)
                merge_errs = self._merge_yaffs2_tree(
                    ex.out_dir, target_root)
                if merge_errs:
                    # Most errors are special-file warts (FIFOs /
                    # sockets like pppd-notifier.fifo /
                    # RIL_RDS_SOCKET that unyaffs2 faithfully
                    # preserved from the original NAND). They're
                    # noise for the artefacts walker — log them
                    # but don't fail the whole extract.
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="low",
                        claim=(f"YAFFS2 merge of "
                               f"{ex.image_path.name} skipped "
                               f"{len(merge_errs)} special-file "
                               f"entries (FIFOs / sockets / "
                               f"unreadable nodes); rest of "
                               f"the partition merged into "
                               f"{merged.name}/{role or ''}. "
                               f"Sample: "
                               f"{merge_errs[0][:140]}"),
                        evidence=[ev],
                    )))
            else:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=(f"YAFFS2 partition "
                           f"{ex.image_path.name} extract failed: "
                           f"{ex.error[:200]}"),
                    evidence=[ev],
                )))
        return out, merged if any_success else None

    def _run_aleapp(self, ctx: AgentContext, src: Path
                    ) -> list[Finding]:
        from el.skills import aleapp as aleapp_skill
        if not aleapp_skill.is_aleapp_available():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("ALEAPP not installed at /opt/ALEAPP "
                       "(or `EL_ALEAPP_DIR`). Skipping the 150+-"
                       "artifact Brignoni parser pass; the four "
                       "built-in detectors above still ran."),
            ))]
        out_dir = ctx.case_dir / "exports" / "aleapp"
        try:
            r = aleapp_skill.run(src, out_dir)
        except aleapp_skill.ALeappError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"ALEAPP failed: {e}",
            ))]
        out: list[Finding] = []
        populated = sum(1 for t in r.tables if t.populated)
        ev = EvidenceItem(
            tool="ALEAPP", version=r.version or "unknown",
            command=(f"aleapp.py -t {aleapp_skill.detect_mode(src)} "
                      f"-i {src.name} -o {out_dir.name}"),
            output_sha256=hashlib.sha256(
                r.stdout_path.read_bytes() if r.stdout_path.exists()
                else b"").hexdigest(),
            output_path=str(r.report_dir),
            extracted_facts={
                "tables": len(r.tables),
                "populated_tables": populated,
                "rc": r.rc,
            },
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"ALEAPP v{r.version or '?'} parsed "
                   f"{len(r.tables)} artefact module(s); "
                   f"{populated} populated. "
                   f"Report: {r.report_dir.name}"),
            evidence=[ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))
        for table in r.tables:
            if not table.populated:
                continue
            label, conf, hyps = (None, "low", [])
            for needle, (lbl, c, h) in self._ALEAPP_HIGH_VALUE.items():
                if needle.lower() in table.name.lower():
                    label, conf, hyps = lbl, c, h
                    break
            if label is None:
                continue
            sample = ""
            if table.rows:
                cols_to_show = min(3, len(table.headers))
                sample = " | ".join(
                    table.rows[0][i] for i in range(cols_to_show)
                    if i < len(table.rows[0])
                )[:200]
            tev = EvidenceItem(
                tool="ALEAPP", version=r.version or "unknown",
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
                claim=(f"ALEAPP {label}: {table.total_rows} row(s) "
                       f"parsed from {table.name}"
                       + (f" (sample: {sample!r})" if sample else "")
                       + (" [truncated for display]"
                          if table.truncated else "")),
                evidence=[tev],
                hypotheses_supported=hyps,
            )))
        return out
