"""ArtifactRecoveryAgent — targeted recovery of a wiped high-value artifact.

Complements (does not duplicate) RecoveryAgent. RecoveryAgent does a *broad*
tsk_recover + bulk_extractor sweep when generic anti-forensic signals fire.
This agent is *targeted*: it detects a specific high-value artifact (Outlook
OST/PST, registry hive, EVTX, browser DB …) whose content was destroyed in
place — the wipe_detect signature: allocated, non-resident, init_size>0, all-
zero content — and then attempts to recover *that artifact* with a precise,
confidence-honest escalation:

    1. wipe_detect   — confirm the wipe from MFT metadata (always; cheap; high
                       confidence). The init_size is a fossil proving real data
                       once existed; the never-written-stub guard keeps benign
                       empty caches from firing.
    2. VSS recovery  — open the shadow store (vss_open hardens libvshadow
                       against the truncated-image backup-VBR failure) and pull
                       the newest *pre-wipe* copy that still has valid content
                       (header-validated → guards against MFT-inode reuse).
                       A clean recovered copy is high confidence.
    3. carve pivot   — when no snapshot predates the wipe (a competent wiper
                       beats VSS, as on the rocba case where all 5 snapshots
                       were already zero), surface the carve pivot. The actual
                       bulk_extractor carve runs only under EL_ARTIFACT_CARVE=1
                       so the default pipeline stays bounded; recovered
                       fragments are medium/low, never dressed up as the file.

Cross-device note: in a bundle, the strongest carve source for a wiped mail
cache is often the *memory* image, which a per-device agent can't reach. That
remains a bundle-level orchestration hook; here the carve pivot is scoped to
the disk's own raw stream (pagefile / hiberfil / unallocated).
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import sleuthkit as sk
from el.skills import wipe_detect

# Cap how many high-value paths we metadata-probe per partition — a guard
# against a pathological MFT, not a real limit (istat is sub-second).
MAX_CANDIDATES = 250

# Leading magic bytes that confirm a recovered stream really is the artifact
# we expected (so an MFT-inode reused for a different file in an older
# snapshot can't masquerade as a successful recovery). Keyed by extension /
# name fragment, matched case-insensitively against the relpath.
_MAGIC: tuple[tuple[str, bytes], ...] = (
    (r"\.ost$", b"!BDN"),
    (r"\.pst$", b"!BDN"),
    (r"\.evtx$", b"ElfFile\x00"),
    (r"(NTUSER\.DAT|UsrClass\.dat|[/\\](SYSTEM|SOFTWARE|SECURITY|SAM))$", b"regf"),
    (r"\.sqlite$", b"SQLite format 3\x00"),
    (r"places\.sqlite$", b"SQLite format 3\x00"),
)


@dataclass
class Candidate:
    """One high-value file to probe, located from a disk_forensicator fls
    bodyfile. ``offset_sectors`` is the partition start (TSK ``-o``)."""
    relpath: str
    inode: str
    offset_sectors: int


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested; no subprocess / filesystem)
# ---------------------------------------------------------------------------

# fls -m bodyfile line: MD5|/path/name|inode|mode|uid|gid|size|atime|...
_BODYFILE_RE = re.compile(r"^[^|]*\|([^|]+)\|([0-9]+-[0-9]+-[0-9]+)\|")


def parse_bodyfile_targets(text: str, offset_sectors: int) -> list[Candidate]:
    """Extract high-value-artifact candidates from an fls ``-m`` bodyfile.

    Keeps only paths matching wipe_detect.HIGH_VALUE_TARGETS, de-duplicates on
    (relpath, inode), and skips ADS / orphan rows whose name carries a TSK
    annotation in parentheses (``($FILE_NAME)`` / ``(deleted-realloc)``)."""
    seen: set[tuple[str, str]] = set()
    out: list[Candidate] = []
    for line in text.splitlines():
        m = _BODYFILE_RE.match(line)
        if not m:
            continue
        relpath, inode = m.group(1), m.group(2)
        if relpath.rstrip().endswith(")") and "(" in relpath.rsplit("/", 1)[-1]:
            continue
        if not wipe_detect.is_high_value(relpath):
            continue
        key = (relpath, inode)
        if key in seen:
            continue
        seen.add(key)
        out.append(Candidate(relpath=relpath, inode=inode,
                             offset_sectors=offset_sectors))
    # Priority-order so a wiped OST/hive/EVTX is never crowded out of the cap
    # by hundreds of low-tier .sqlite / .lnk / Recent rows. Stable sort keeps
    # bodyfile order within a tier.
    out.sort(key=lambda c: wipe_detect.target_priority(c.relpath))
    return out[:MAX_CANDIDATES]


def expected_magic(relpath: str) -> bytes | None:
    """The leading bytes a valid copy of *relpath* should start with, or None
    when the type has no cheap magic to check."""
    for pat, magic in _MAGIC:
        if re.search(pat, relpath, re.I):
            return magic
    return None


def header_matches(data: bytes, relpath: str) -> bool:
    """True when *data* starts with the expected magic for *relpath* — or when
    the type has no known magic (then any non-empty data passes)."""
    magic = expected_magic(relpath)
    if magic is None:
        return bool(data)
    return data[:len(magic)] == magic


def _offset_from_bodyfile_name(name: str) -> int:
    """disk_forensicator writes fls output to ``fls.txt`` (whole image, offset
    0) or ``fls_o<sectors>.txt`` (partition). Recover the sector offset."""
    m = re.search(r"_o(\d+)", name)
    return int(m.group(1)) if m else 0


# --- cleared-log recovery ---------------------------------------------------

# Event logs whose clearing (EID 1102 / wevtutil cl) is forensically
# load-bearing and recoverable from a pre-clearing shadow copy. Matched as a
# path suffix (case-insensitive). Security is the prime target; System/App
# carry service-install + crash evidence the attacker may also have cleared.
CLEARED_LOG_TARGETS = (
    "winevt/Logs/Security.evtx",
    "winevt/Logs/System.evtx",
)
# A shadow copy of the log must exceed the (cleared) live log by both a ratio
# and an absolute margin before we treat it as a recoverable pre-clearing copy
# — guards against normal log growth looking like a clearing.
_CLEARED_RATIO = 1.5
_CLEARED_MIN_DELTA = 4 * 1024 * 1024
# Tokens that mean "a Windows event log was cleared" in a ledger claim.
_CLEARING_TOKENS = ("security_log_cleared", "log cleared", "eid 1102",
                    "1102", "audit log cleared")

# fls -m bodyfile w/ size: MD5|path|inode|mode|uid|gid|SIZE|atime|mtime|...
_BODYFILE_SIZE_RE = re.compile(
    r"^[^|]*\|([^|]+)\|([0-9]+-[0-9]+-[0-9]+)\|[^|]*\|[^|]*\|[^|]*\|([0-9]+)\|")


def find_log_entry(bodyfile_text: str, target_suffix: str):
    """Return (relpath, inode, size) for the first bodyfile row whose path ends
    with ``target_suffix`` (a cleared-log path), else None. Used to read the
    live (cleared) log's inode + size without extracting it."""
    t = target_suffix.replace("\\", "/").lower()
    for line in bodyfile_text.splitlines():
        m = _BODYFILE_SIZE_RE.match(line)
        if not m:
            continue
        relpath = m.group(1)
        if relpath.replace("\\", "/").lower().endswith(t) and "($FILE_NAME)" not in relpath:
            return (relpath, m.group(2), int(m.group(3)))
    return None


def select_pre_clearing(live_size: int, snaps,
                        ratio: float = _CLEARED_RATIO,
                        min_delta: int = _CLEARED_MIN_DELTA):
    """Given the (cleared) live-log size and a list of (snapshot_number, size),
    return the NEWEST snapshot_number whose log is substantially larger than
    live — the latest pre-clearing copy — or None when no snapshot qualifies."""
    for num, size in sorted(snaps, key=lambda x: -x[0]):
        if size >= live_size * ratio and (size - live_size) >= min_delta:
            return num
    return None


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class ArtifactRecoveryAgent(Agent):
    name = "artifact_recovery"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        partitions = ctx.shared.get("partitions")
        if not partitions:
            return out                      # disk-only; silent on non-disk cases

        candidates = self._collect_candidates(ctx)
        log_clearing = self._log_clearing_detected(ctx)
        # Run when there's an in-place wipe to chase OR a cleared event log to
        # recover from a shadow copy. Either is enough to justify mounting.
        if not candidates and not log_clearing:
            return out

        sector_size = int(ctx.shared.get("sector_size") or 512)
        raw_input = Path(ctx.shared.get("raw_input_path") or ctx.input_path)
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        mount_point = None
        if raw_input.suffix.lower() in (".e01", ".e02"):
            mount_point = Path("/tmp/el-mounts") / f"{ctx.case_id}-artrec"
            try:
                raw_image = sk.ewfmount(raw_input, mount_point, timeout=60)
            except Exception as e:
                return [self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"Wipe scan skipped: ewfmount failed ({e})."))]
        else:
            raw_image = raw_input

        try:
            for cand in candidates:
                verdict = self._classify(raw_image, cand, analysis)
                if verdict is None or not verdict.is_wipe:
                    continue
                out.append(self._emit_wipe(ctx, raw_image, cand, verdict, analysis))
                # Recovery escalation only for in-place wipes (a normal delete
                # is RecoveryAgent's tsk_recover territory, not VSS-targeted).
                if verdict.status != "wiped_in_place":
                    continue
                recovered = self._recover_via_vss(
                    ctx, raw_image, cand, sector_size, analysis)
                out.extend(recovered)
                if not any(f.confidence == "high" for f in recovered):
                    out.append(self._carve_pivot(ctx, raw_image, cand))
            # Cleared event logs are NOT zeroed in place (a cleared log is a
            # fresh, smaller, valid EVTX), so wipe_detect classifies them
            # 'intact' and the loop above skips them. Recover them from the
            # newest pre-clearing shadow copy instead.
            if log_clearing:
                out.extend(self._recover_cleared_logs(
                    ctx, raw_image, sector_size, analysis))
        finally:
            if mount_point is not None:
                try:
                    sk.ewfumount(mount_point)
                except Exception:
                    pass
        return out

    # -- candidate collection ------------------------------------------------

    def _collect_candidates(self, ctx: AgentContext) -> list[Candidate]:
        """Reuse disk_forensicator's fls bodyfiles (no second full-tree walk):
        glob them out of its analysis dir and parse for high-value paths."""
        df_dir = ctx.case_dir / "analysis" / "disk_forensicator"
        cands: list[Candidate] = []
        for body in sorted(df_dir.glob("fls*.txt")):
            try:
                text = body.read_text(errors="replace")
            except OSError:
                continue
            cands.extend(parse_bodyfile_targets(
                text, _offset_from_bodyfile_name(body.name)))
        return cands

    # -- per-candidate classification ---------------------------------------

    def _classify(self, raw_image: Path, cand: Candidate,
                  analysis: Path) -> wipe_detect.WipeVerdict | None:
        off = cand.offset_sectors or None
        try:
            run = sk.istat(raw_image, cand.inode, analysis, offset=off,
                           label=f"istat_{cand.inode.replace('-', '_')}")
        except sk.SleuthkitError:
            return None
        rec = wipe_detect.parse_istat(run.stdout_path.read_text(errors="replace"))
        rec.inode = cand.inode
        # Only pay for an icat zero-probe on the wipe-suspect shape
        # (allocated + non-resident + initialized) — intact/resident files
        # are classified straight to "intact" without reading content.
        content_zero: bool | None = None
        if (rec.allocated and rec.non_resident
                and rec.init_size and rec.init_size >= wipe_detect.MIN_WIPED_INIT_BYTES):
            content_zero = sk.content_is_zero(raw_image, cand.inode, offset=off)
        v = wipe_detect.classify(rec, content_zero, relpath=cand.relpath,
                                 inode=cand.inode)
        v._istat_path = run.stdout_path   # type: ignore[attr-defined]
        return v

    def _emit_wipe(self, ctx: AgentContext, raw_image: Path, cand: Candidate,
                   verdict: wipe_detect.WipeVerdict, analysis: Path) -> Finding:
        istat_path = getattr(verdict, "_istat_path", None)
        ev = wipe_detect.verdict_as_evidence(verdict, raw_image, istat_path)
        conf = verdict.confidence
        return self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence=conf,
            claim=(f"Artifact wipe [{verdict.status}] — `{cand.relpath}` "
                   f"(inode {cand.inode}): {verdict.reason}."),
            evidence=[ev],
            hypotheses_supported=verdict.hypotheses,
        ))

    # -- VSS recovery --------------------------------------------------------

    def _recover_via_vss(self, ctx: AgentContext, raw_image: Path,
                         cand: Candidate, sector_size: int,
                         analysis: Path) -> list[Finding]:
        """Open the shadow store and pull the newest pre-wipe copy of the
        artifact that still validates. Returns the Findings emitted (a high-
        confidence recovery, or an insufficient 'VSS exhausted' note)."""
        from el.skills import vss_diff
        out: list[Finding] = []
        offset_bytes = cand.offset_sectors * sector_size
        work = analysis / "vss_work"
        vss_root = Path("/tmp/el-mounts") / f"{ctx.case_id}-artrec-vss"
        recovery_dir = ctx.case_dir / "exports" / "recovery" / "artifact_recovery"
        recovery_dir.mkdir(parents=True, exist_ok=True)
        basename = cand.relpath.replace("\\", "/").rstrip("/").split("/")[-1]

        try:
            vol = vss_diff.vss_open(raw_image, work, offset_bytes=offset_bytes)
        except vss_diff.VssError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"VSS recovery of `{cand.relpath}` unavailable: {e}")))]

        try:
            if not vol.snapshots:
                return [self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=(f"No Volume Shadow Copies on this volume — cannot "
                           f"recover wiped `{cand.relpath}` from a snapshot.")))]
            try:
                vss_diff.vshadowmount(vol.device, vss_root, offset_bytes=0,
                                      timeout=60)
            except vss_diff.VssError as e:
                return [self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"vshadowmount failed for `{cand.relpath}`: {e}"))]

            checked: list[str] = []
            for snap in sorted(vol.snapshots, key=lambda s: s.number, reverse=True):
                dev = vss_root / f"vss{snap.number}"
                if not dev.exists():
                    continue
                inode = self._find_inode(dev, basename, analysis)
                if not inode:
                    continue
                if sk.content_is_zero(dev, inode) is True:
                    checked.append(f"#{snap.number}={snap.creation_utc}(zeroed)")
                    continue
                dest = recovery_dir / f"snap{snap.number}_{basename}"
                try:
                    n = sk.icat_extract(dev, inode, dest)
                except sk.SleuthkitError:
                    continue
                head = dest.read_bytes()[:32] if dest.is_file() else b""
                if n == 0 or not header_matches(head, cand.relpath):
                    checked.append(f"#{snap.number}(invalid)")
                    continue
                sha = hashlib.sha256(dest.read_bytes()).hexdigest()
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim=(f"RECOVERED wiped `{cand.relpath}` from VSS snapshot "
                           f"#{snap.number} ({snap.creation_utc}) — pre-wipe copy, "
                           f"{n} bytes, header-validated. Written to {dest}. "
                           f"sha256={sha}."),
                    evidence=[wipe_detect.EvidenceItem(
                        tool="libvshadow+sleuthkit", version="vss_open+icat",
                        command=(f"vss_open({raw_image.name}) | vshadowmount | "
                                 f"icat vss{snap.number} {inode}"),
                        output_sha256=sha, output_path=str(dest),
                        extracted_facts={"snapshot": snap.number,
                                         "snapshot_utc": snap.creation_utc,
                                         "bytes": n, "relpath": cand.relpath})],
                    hypotheses_supported=["H_ANTI_FORENSICS"],
                )))
                return out
            # walked every snapshot, none had valid pre-wipe content
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"VSS exhausted for `{cand.relpath}`: all "
                       f"{len(vol.snapshots)} snapshot(s) already post-wipe "
                       f"({'; '.join(checked) or 'file absent in snapshots'}). "
                       f"The wipe predates the earliest shadow copy."))))
            return out
        finally:
            vss_diff.fusermount_unmount(vss_root)
            vss_diff.vss_close(vol)

    def _find_inode(self, dev: Path, basename: str, analysis: Path) -> str | None:
        """Locate *basename*'s inode inside a snapshot device via an fls
        bodyfile (snapshot is an unwrapped NTFS volume → offset 0)."""
        try:
            run = sk.fls(dev, analysis, offset=None, recursive=True, timeout=1800)
        except sk.SleuthkitError:
            return None
        target = basename.lower()
        for line in run.stdout_path.read_text(errors="replace").splitlines():
            m = _BODYFILE_RE.match(line)
            if not m:
                continue
            relpath, inode = m.group(1), m.group(2)
            if relpath.replace("\\", "/").rstrip("/").split("/")[-1].lower() == target:
                return inode
        return None

    # -- carve pivot (gated) -------------------------------------------------

    def _carve_pivot(self, ctx: AgentContext, raw_image: Path,
                     cand: Candidate) -> Finding:
        """When VSS can't recover the artifact, either run a bounded carve
        (EL_ARTIFACT_CARVE=1) or surface the pivot as an insufficient finding
        with the exact next step — never a silent gap."""
        if os.environ.get("EL_ARTIFACT_CARVE") == "1":
            from el.skills import bulk_extractor as be
            from el.agents.recovery import _BE_SCANNERS_DISABLE, _bulk_extractor_timeout_for
            be_root = (ctx.case_dir / "exports" / "recovery"
                       / "artifact_recovery" / "carve")
            try:
                size = raw_image.stat().st_size
            except OSError:
                size = 0
            try:
                # keep the email/rfc822 scanners ON (drop the heavy ones) — the
                # wiped artifact is usually a mail cache; addresses + headers in
                # pagefile/hiberfil/unallocated are the recoverable fragments.
                run = be.scan(raw_image, be_root,
                              disable_scanners=list(_BE_SCANNERS_DISABLE),
                              timeout=_bulk_extractor_timeout_for(size))
            except be.BulkExtractorError as e:
                return self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"Carve fallback for `{cand.relpath}` failed: {e}"))
            feats = run.features()
            return self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="low" if feats else "insufficient",
                claim=(f"Carve fallback for wiped `{cand.relpath}`: "
                       f"bulk_extractor surfaced {len(feats)} feature class(es) "
                       f"from the raw stream (pagefile/hiberfil/unallocated). "
                       f"Fragments only — weaker provenance than a file. "
                       f"Output: {be_root}."),
                evidence=[run.as_evidence({"phase": "artifact_carve"})],
                hypotheses_supported=["H_ANTI_FORENSICS"]))
        return self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="insufficient",
            claim=(f"`{cand.relpath}` was wiped and no pre-wipe shadow copy "
                   f"survives. Carve pivot (not auto-run; set EL_ARTIFACT_CARVE=1): "
                   f"bulk_extractor over the raw stream + the bundle's memory "
                   f"image for cached pages / message fragments.")))

    # -- cleared event-log recovery ------------------------------------------

    def _log_clearing_detected(self, ctx: AgentContext) -> bool:
        """True when the ledger carries an event-log-clearing signal (EID 1102,
        emitted by lateral_movement_analyst). This is the trigger for cleared-
        log recovery — a cleared log is valid+small, so wipe_detect never fires
        on it."""
        from el.evidence.ledger import list_findings
        for f in list_findings(ctx.case_dir, case_id=ctx.case_id):
            if (f.confidence or "") == "insufficient":
                continue
            c = (f.claim or "").lower()
            if any(tok in c for tok in _CLEARING_TOKENS):
                return True
        return False

    def _recover_cleared_logs(self, ctx: AgentContext, raw_image: Path,
                              sector_size: int, analysis: Path) -> list[Finding]:
        """Recover a cleared Windows event log from the newest pre-clearing
        shadow copy. The cleared live log is a fresh, smaller, valid EVTX; a
        shadow copy taken before the clearing still holds the full log. We read
        the live log's inode+size from disk_forensicator's bodyfile, then walk
        the shadow copies (newest first) sizing the SAME inode via istat — and
        recover the latest copy that is substantially larger (the pre-clearing
        log)."""
        from el.skills import vss_diff
        out: list[Finding] = []
        df_dir = ctx.case_dir / "analysis" / "disk_forensicator"
        bodies: dict[int, str] = {}
        for b in sorted(df_dir.glob("fls*.txt")):
            try:
                bodies[_offset_from_bodyfile_name(b.name)] = b.read_text(errors="replace")
            except OSError:
                continue
        if not bodies:
            return out
        recovery_dir = ctx.case_dir / "exports" / "recovery" / "artifact_recovery"
        recovery_dir.mkdir(parents=True, exist_ok=True)
        work = analysis / "vss_work_logs"
        vss_root = Path("/tmp/el-mounts") / f"{ctx.case_id}-artrec-clrlog"

        for offset_sectors, text in bodies.items():
            targets = []
            for suffix in CLEARED_LOG_TARGETS:
                ent = find_log_entry(text, suffix)
                if ent:
                    targets.append((suffix, *ent))   # (suffix, relpath, inode, live_size)
            if not targets:
                continue
            try:
                vol = vss_diff.vss_open(
                    raw_image, work, offset_bytes=offset_sectors * sector_size)
            except vss_diff.VssError as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"Cleared-log recovery unavailable (VSS): {e}")))
                continue
            try:
                if not vol.snapshots:
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                        claim=("Event log(s) were cleared but no Volume Shadow "
                               "Copies survive to recover a pre-clearing copy."))))
                    continue
                try:
                    vss_diff.vshadowmount(vol.device, vss_root, offset_bytes=0,
                                          timeout=60)
                except vss_diff.VssError as e:
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                        claim=f"Cleared-log recovery: vshadowmount failed: {e}")))
                    continue
                for suffix, relpath, live_inode, live_size in targets:
                    out.extend(self._recover_one_cleared_log(
                        ctx, vss_root, vol.snapshots, suffix, relpath,
                        live_inode, live_size, recovery_dir))
            finally:
                vss_diff.fusermount_unmount(vss_root)
                vss_diff.vss_close(vol)
        return out

    def _recover_one_cleared_log(self, ctx, vss_root, snapshots, suffix,
                                 relpath, live_inode, live_size, recovery_dir):
        out: list[Finding] = []
        basename = relpath.replace("\\", "/").rstrip("/").split("/")[-1]
        sizes: list[tuple[int, int]] = []   # (snapshot_number, log_size)
        # The system-file inode is stable across snapshots, so size it via istat
        # on the same inode (fast) — no full fls walk per snapshot.
        for snap in sorted(snapshots, key=lambda s: s.number, reverse=True):
            dev = vss_root / f"vss{snap.number}"
            if not dev.exists():
                continue
            try:
                run = sk.istat(dev, live_inode, recovery_dir.parent,
                               label=f"istat_snap{snap.number}_{basename}")
            except sk.SleuthkitError:
                continue
            rec = wipe_detect.parse_istat(run.stdout_path.read_text(errors="replace"))
            if rec.data_size:
                sizes.append((snap.number, rec.data_size))

        pick = select_pre_clearing(live_size, sizes)
        if pick is None:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"`{relpath}` was cleared (live {live_size} bytes) but no "
                       f"shadow copy holds a substantially larger pre-clearing "
                       f"copy ({len(sizes)} snapshot(s) checked) — clearing "
                       f"predates the shadow set, or the log genuinely grew."))))
            return out

        snap = next(s for s in snapshots if s.number == pick)
        dest = recovery_dir / f"snap{pick}_{basename}"
        try:
            n = sk.icat_extract(vss_root / f"vss{pick}", live_inode, dest)
        except sk.SleuthkitError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Cleared-log recovery: icat failed for `{relpath}`: {e}"))]
        head = dest.read_bytes()[:8] if dest.is_file() else b""
        if head[:7] != b"ElfFile":   # EVTX magic — guards against inode reuse
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"Cleared-log recovery: snapshot #{pick} copy of "
                       f"`{relpath}` failed EVTX header validation.")))]
        sha = hashlib.sha256(dest.read_bytes()).hexdigest()
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"RECOVERED cleared event log `{relpath}` from VSS snapshot "
                   f"#{pick} ({snap.creation_utc}) — pre-clearing copy {n} bytes "
                   f"vs cleared live {live_size} bytes (+{n - live_size}). "
                   f"EVTX-validated; written to {dest}. sha256={sha}. Parse with "
                   f"EvtxECmd to recover the destroyed records."),
            evidence=[wipe_detect.EvidenceItem(
                tool="libvshadow+sleuthkit", version="vss_open+icat",
                command=(f"vss_open | vshadowmount | istat/icat vss{pick} "
                         f"{live_inode}"),
                output_sha256=sha, output_path=str(dest),
                extracted_facts={"snapshot": pick, "snapshot_utc": snap.creation_utc,
                                 "recovered_bytes": n, "cleared_live_bytes": live_size,
                                 "relpath": relpath})],
            hypotheses_supported=["H_ANTI_FORENSICS", "H_LOG_CLEARED"])))
        return out


__all__ = [
    "ArtifactRecoveryAgent",
    "Candidate",
    "parse_bodyfile_targets",
    "expected_magic",
    "header_matches",
    "CLEARED_LOG_TARGETS",
    "find_log_entry",
    "select_pre_clearing",
]
