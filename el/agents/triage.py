"""Triage agent — first-touch artifact classification.

Deterministic. Inspects the input and tries to identify what kind of evidence
this is (memory image vs pcap vs disk image vs log corpus). For memory images,
attempts vol3 OS detection.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import vol3


WINDOWS_ARTIFACT_HINTS = (
    "$MFT", "Amcache.hve", "SYSTEM", "SOFTWARE", "NTUSER.DAT",
    "SRUDB.dat", "Prefetch", "winevt", "*.evtx",
)

VELOCIRAPTOR_HINTS = (
    "Windows.System.Pslist", "Windows.Network.Netstat",
    "Windows.Sysinternals.Autoruns", "Windows.Forensics.Prefetch",
)


MAGIC_HINTS = {
    b"\xd4\xc3\xb2\xa1": "pcap (libpcap)",
    b"\xa1\xb2\xc3\xd4": "pcap (libpcap, big-endian)",
    b"\x0a\x0d\x0d\x0a": "pcapng",
    b"EMiL": "kdmp / windows mini-dump variant",
    b"PAGEDUMP": "windows full crash dump",
    b"PAGE": "windows page-truncated dump",
    b"\x53\x46\x53\x4d": "winmem (older format)",
    b"EVF\x09\x0d\x0a\xff\x00": "EWF (E01)",
    b"LVF\x09\x0d\x0a\xff\x00": "EWF (L01 logical evidence)",
    b"EVF2\r\n\x81\x00": "EWF v2 (Ex01)",
    b"ElfFile\x00": "EVTX (Windows Event Log)",
    b"regf": "Windows Registry hive",
    # VM disk images — dispatched through `el.skills.disk_convert` →
    # qemu-img → raw, then through the normal DiskForensicator raw walk.
    b"vhdxfile": "vhdx",                                 # Microsoft VHDX
    b"KDMV": "vmdk (sparse)",                            # VMware VMDK sparse
    b"COWD": "vmdk (sparse)",                            # VMware COW (older)
    b"# Disk DescriptorFile": "vmdk (descriptor)",       # VMDK text descriptor
}


def _detect_bitlocker(path: Path) -> str | None:
    """BitLocker volume header has `-FVE-FS-` (BitLocker To Go /
    post-Vista BitLocker) at file offset 0x03 — the leading 3
    bytes are the boot-sector JMP instruction so the magic doesn't
    sit at byte 0 where `MAGIC_HINTS.startswith` would catch it.
    Read 11 bytes and check the suffix."""
    try:
        with path.open("rb") as f:
            head = f.read(11)
    except OSError:
        return None
    if head[3:11] == b"-FVE-FS-":
        return "bitlocker"
    return None


def _detect_vhd_footer(path: Path) -> str | None:
    """VHD (Connectix/Microsoft, legacy) has no header magic for fixed
    images — the signature lives in the last 512-byte footer as the
    ASCII 'conectix' cookie. Check for it so we don't miss legacy
    .vhd inputs from Hyper-V / Azure exports.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size < 512:
        return None
    try:
        with path.open("rb") as f:
            f.seek(size - 512)
            footer = f.read(8)
    except OSError:
        return None
    if footer == b"conectix":
        return "vhd"
    return None


def _detect_raw_disk(path: Path) -> str | None:
    """Recognise a raw (dd) disk image by its partition structure.

    Raw disk images carry no container magic at byte 0 (unlike E01 /
    VHDX / VMDK), so the byte-0 MAGIC_HINTS loop misses them and the
    image falls through to "opaque memory candidate" — misrouting the
    single most common forensic disk format to MemoryForensicator.

    Two signatures, cheap to check (reads the first ~520 bytes):

      * GPT: the protective-MBR is at LBA 0 and the GPT header
        ("EFI PART") sits at LBA 1 — offset 512. Unambiguous.
      * MBR: 0x55AA boot signature at offset 510 PLUS at least one
        plausible partition-table entry (a non-zero partition type
        with a non-zero LBA start) in the 446..510 table. The
        partition-entry guard is essential — 0x55AA alone is a weak
        signal (countless unrelated files end in those two bytes),
        so we require real partition geometry before claiming a disk.

    Returns "raw-disk (GPT)" / "raw-disk (MBR)" or None. Both route to
    DiskForensicator via KIND_TO_AGENT["raw-disk …"]; the agent's
    run() falls through to the raw-disk walk (mmls + per-partition
    fls) for any non-EWF/VM/bitlocker kind.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None
    # A real disk image is large; guard against tiny files that
    # happen to end in 0x55AA.
    if size < 1024 * 1024:        # < 1 MiB is not a disk image
        return None
    try:
        with path.open("rb") as f:
            head = f.read(520)
    except OSError:
        return None
    if len(head) < 512:
        return None
    # GPT — "EFI PART" at offset 512 (LBA 1). Strongest signal.
    if head[512:520] == b"EFI PART":
        return "raw-disk (GPT)"
    # MBR — 0x55AA at 510 + a plausible partition entry. The 4 entries
    # are 16 bytes each starting at 446 (0x1BE): byte 4 = type,
    # bytes 8-11 = LBA start (LE u32).
    if head[510:512] == b"\x55\xaa":
        import struct
        for i in range(4):
            entry = head[446 + i * 16: 446 + i * 16 + 16]
            if len(entry) < 16:
                break
            ptype = entry[4]
            lba_start = struct.unpack("<I", entry[8:12])[0]
            if ptype != 0 and lba_start != 0:
                return "raw-disk (MBR)"
    # Damaged/wiped primary GPT — the front of the disk (protective MBR +
    # primary GPT header) is zeroed, so neither signature above fires and the
    # image would misroute to MemoryForensicator. But GPT keeps a backup
    # header in the LAST sector; if "EFI PART" is there while the front is
    # zeroed, this is a wiped-GPT disk (an interrupted disk wipe). Route it to
    # DiskForensicator, where mmls recovers via the backup and the gpt_state
    # detector raises the anti-forensic finding. See CIRCL wiped-disk exercise.
    if head[:512] == b"\x00" * 512:
        for sec in (512, 4096):              # try 512B and 4K sector geometries
            try:
                with path.open("rb") as f:
                    f.seek(size - sec)
                    if f.read(8) == b"EFI PART":
                        return "raw-disk (GPT-damaged)"
            except OSError:
                break
    return None


# File-system-artifact signatures that densely populate UNALLOCATED disk space
# but are not the structure of a memory image. Used to recognise a headerless
# "carve-only" blob (e.g. exported unallocated space) so it routes to the
# carving pipeline instead of misrouting to MemoryForensicator (which would run
# vol3, find no kernel, and never carve). Deliberately disk-specific
# (NTFS/Windows artifacts), not generic MZ/PE which a memory dump also carries.
# Strong, near-unambiguous NTFS/Windows filesystem-artifact signatures that
# densely populate UNALLOCATED disk space but are not the structure of a memory
# image: MFT records ("FILE0"), registry hives ("regf"), EVTX logs
# ("ElfFile\x00"), compressed Win8+ prefetch ("MAM\x04"). Deliberately
# disk-specific — not generic MZ/PE which a memory dump also carries.
_CARVE_STRONG: tuple[bytes, ...] = (b"FILE0", b"regf", b"ElfFile\x00", b"MAM\x04")


def _detect_carvable_blob(path: Path, min_size: int = 256 * 1024 * 1024) -> str | None:
    """Recognise a large, headerless raw blob that is filesystem CONTENT
    (e.g. exported unallocated space) rather than a partitioned disk or a
    memory image — so it routes to the carving pipeline.

    Cheap: samples 1 MiB at a spread of offsets across the file and looks for
    NTFS/Windows filesystem-artifact signatures. Requires either one strong
    signature seen at two or more offsets or two distinct strong signatures, so
    a stray fragment in a memory dump does not trip it. Returns
    "unallocated (carve-only)" or None.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size < min_size:
        return None
    win = 1024 * 1024
    fracs = (0.0, 0.06, 0.12, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.97)
    offsets = [min(int(size * fr), max(0, size - win)) for fr in fracs]
    seen: dict[bytes, int] = {}
    try:
        with path.open("rb") as f:
            for off in offsets:
                f.seek(off)
                chunk = f.read(win)
                for sig in _CARVE_STRONG:
                    if sig in chunk:
                        seen[sig] = seen.get(sig, 0) + 1
    except OSError:
        return None
    distinct = len(seen)
    repeated = any(c >= 2 for c in seen.values())
    if distinct >= 2 or (distinct == 1 and repeated):
        return "unallocated (carve-only)"
    return None


# A Windows memory image caches huge volumes of filesystem metadata — MFT
# records (FILE0), registry hives (regf), event logs (ElfFile) and prefetch
# (MAM) all sit resident in RAM — so a raw memory capture trips
# _detect_carvable_blob() exactly like an exported unallocated-space blob.
# (Measured on the 19 GiB SRL "Rocba" capture: FILE0 present in 9 of 12 sample
# windows.) Signature density therefore cannot separate "memory image" from
# "carve-only blob". The discriminator is the input naming itself a memory
# capture — via a conventional extension/name token, or the bundle device
# label carried in case_id ("<bundle>:<device>"). When that hint fires we let
# Volatility 3 be the authority: kernel found → MemoryForensicator; no kernel
# → fall back to carving (see TriageAgent.run). _EXT_STRONG values are
# unambiguously volatile-memory formats; _EXT_WEAK (.raw/.img/.bin) only count
# as a hint alongside a name/label token, since they are also disk extensions.
_MEM_NAME_TOKENS: tuple[str, ...] = (
    "memory", "memdump", "mem-dump", "mem_dump", "ramdump", "ram-dump",
    "ram_dump", "pmem", "winpmem", "memimage", "physmem", "memcapture",
)
_MEM_LABEL_TOKENS: tuple[str, ...] = ("memory", "mem", "ram") + _MEM_NAME_TOKENS
_MEM_EXT_STRONG: frozenset[str] = frozenset(
    {".lime", ".vmem", ".vmss", ".vmsn", ".pmem", ".dmp", ".dump",
     ".core", ".crash", ".mem"})
_MEM_EXT_WEAK: frozenset[str] = frozenset({".raw", ".img", ".bin"})


def _looks_like_memory_input(path: Path, case_id: str | None) -> bool:
    """True when the input *names itself* a memory capture — so a carve-blob
    false positive can be deferred to a vol3 kernel probe instead of being
    routed straight to carving. Name-only heuristic (no I/O); correctness is
    still decided by Volatility downstream, this only gates whether we bother
    to probe before carving."""
    name = path.name.lower()
    ext = path.suffix.lower()
    # Bundle device label, e.g. case_id "rocba:memory" → "memory".
    label = ""
    if case_id and ":" in case_id:
        label = case_id.rsplit(":", 1)[-1].strip().lower()
    if label and (label in _MEM_LABEL_TOKENS
                  or any(t in label for t in _MEM_NAME_TOKENS)):
        return True
    if any(t in name for t in _MEM_NAME_TOKENS):
        return True
    if ext in _MEM_EXT_STRONG:
        return True
    return False


class TriageAgent(Agent):
    name = "triage"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        # Paired-capture marker (set by investigate-bundle's pair
        # detector when this device's input shares size + name-root
        # with another device in the same bundle). Emit one Finding
        # so the H_PAIRED_CAPTURE_CANDIDATE hypothesis scorer can
        # lift, and the analyst sees the pair surfaced in the
        # case-glance section of the report.
        pw = ctx.shared.get("paired_with")
        if pw:
            sha = hashlib.sha256(
                f"paired:{ctx.case_id}:{pw.get('peer_name','')}".encode()
            ).hexdigest()
            ev = EvidenceItem(
                tool="el.pair_detection", version="0.1.0",
                command=("detect_pairs() over bundle device list — "
                         "size + name-root match"),
                output_sha256=sha, output_path=str(ctx.input_path),
                extracted_facts={
                    "role": pw.get("role"),
                    "peer_name": pw.get("peer_name"),
                    "peer_path": pw.get("peer_path"),
                    "name_root": pw.get("name_root"),
                    "size_bytes": pw.get("size_bytes"),
                    "selection_reason": pw.get("reason"),
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Paired capture detected: this device "
                       f"({pw.get('role','?')}) shares size and "
                       f"name-root with {pw.get('peer_name','?')!r} "
                       f"in the same bundle — selection reason: "
                       f"{pw.get('reason','(none)')}"),
                evidence=[ev],
                hypotheses_supported=["H_PAIRED_CAPTURE_CANDIDATE"],
            )))

        if ctx.input_path.is_dir():
            return out + self._classify_directory(ctx, analysis)

        # File-shape early detections that don't need the magic-byte
        # path: iOS sysdiagnose tarballs (filename signature), Magnet/
        # UFED Android archive bundles (.tar/.zip extension + Android
        # marker file inside).
        name = ctx.input_path.name
        if (name.startswith("sysdiagnose_")
                and (name.endswith(".tar.gz") or name.endswith(".tgz"))):
            ctx.shared["evidence_kind"] = "ios-sysdiagnose"
            sha = hashlib.sha256(name.encode()).hexdigest()
            ev = EvidenceItem(
                tool="el.triage", version="0.1.0",
                command=f"sysdiagnose-shape probe {name}",
                output_sha256=sha, output_path=str(ctx.input_path),
                extracted_facts={"signature": "sysdiagnose_*.tar.gz"},
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="high",
                claim=(f"Input is an iOS sysdiagnose tarball "
                       f"({name}) — routes to IOSForensicator's "
                       f"sysdiagnose triage path."),
                evidence=[ev],
                hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
            return out
        if ctx.input_path.is_file() and ctx.input_path.suffix.lower() == ".zip":
            cylr_target = self._classify_cylr_zip(ctx.input_path)
            if cylr_target is not None:
                # Map classification → evidence_kind. Linux + macOS + the
                # "unknown" fallback all walk through LinuxForensicator
                # (its detectors are mostly nondestructive on
                # heterogeneous trees); Windows routes to
                # WindowsArtifactAgent which already understands
                # drive-letter prefixed paths via its rglob walkers.
                kind_map = {
                    "windows": "cylr-collection-windows",
                    "linux":   "cylr-collection-linux",
                    "macos":   "cylr-collection-macos",
                    "unknown": "cylr-collection-linux",
                }
                route_label = {
                    "windows": "WindowsArtifactAgent",
                    "linux":   "LinuxForensicatorAgent",
                    "macos":   "MacOSForensicatorAgent",
                    "unknown": "LinuxForensicatorAgent (best-effort)",
                }
                ctx.shared["evidence_kind"] = kind_map[cylr_target]
                sha = hashlib.sha256(name.encode()).hexdigest()
                ev = EvidenceItem(
                    tool="el.triage", version="0.1.0",
                    command=f"cylr-zip probe {name}",
                    output_sha256=sha, output_path=str(ctx.input_path),
                    extracted_facts={
                        "target_os": cylr_target,
                        "signature":
                            "CyLR_Collection_Log_*.log marker / "
                            "platform FS-root prefix"},
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="high",
                    claim=(f"Input is a CyLR collection zip ({name}) — "
                           f"target OS: {cylr_target}; routes to "
                           f"{route_label[cylr_target]} via auto-extract."),
                    evidence=[ev],
                    hypotheses_supported=["H_DISK_ARTIFACTS"],
                )))
                return out
        if (ctx.input_path.is_file()
                and ctx.input_path.suffix.lower() == ".zip"
                and self._archive_looks_velociraptor(ctx.input_path)):
            ctx.shared["evidence_kind"] = "velociraptor-collection"
            sha = hashlib.sha256(name.encode()).hexdigest()
            ev = EvidenceItem(
                tool="el.triage", version="0.1.0",
                command=f"velociraptor-zip probe {name}",
                output_sha256=sha, output_path=str(ctx.input_path),
                extracted_facts={
                    "signature":
                        "hunt_info.json / client_info.json / "
                        "collection_context.json"},
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="high",
                claim=(f"Input is a Velociraptor collection zip "
                       f"({name}) — routes to EndpointAnalystAgent."),
                evidence=[ev],
                hypotheses_supported=["H_ENDPOINT_COLLECTION"],
            )))
            return out
        if (ctx.input_path.is_file()
                and ctx.input_path.suffix.lower() in (".tar", ".zip")
                and self._archive_looks_android(ctx.input_path)):
            ctx.shared["evidence_kind"] = "android-archive"
            sha = hashlib.sha256(name.encode()).hexdigest()
            ev = EvidenceItem(
                tool="el.triage", version="0.1.0",
                command=f"android-archive probe {name}",
                output_sha256=sha, output_path=str(ctx.input_path),
                extracted_facts={"signature":
                                  "data/system/packages.xml or data/data/"},
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="high",
                claim=(f"Input is an Android extraction archive "
                       f"({name}) — routes to AndroidForensicator's "
                       f"ALEAPP wrap."),
                evidence=[ev],
                hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
            return out

        with ctx.input_path.open("rb") as f:
            head = f.read(64)
        head_path = analysis / "head.bin"
        head_path.write_bytes(head)
        head_sha = hashlib.sha256(head).hexdigest()

        magic_hint = None
        for sig, label in MAGIC_HINTS.items():
            if head.startswith(sig):
                magic_hint = label
                break
        if not magic_hint:
            # VHD cookies live at end-of-file, not the head — check there
            # before falling through to "treating as memory candidate".
            vhd_kind = _detect_vhd_footer(ctx.input_path)
            if vhd_kind:
                magic_hint = vhd_kind
        if not magic_hint:
            # BitLocker `-FVE-FS-` sits at file offset 0x03 (after the
            # 3-byte JMP). Not picked up by the byte-0 prefix loop above.
            bl_kind = _detect_bitlocker(ctx.input_path)
            if bl_kind:
                magic_hint = bl_kind
        if not magic_hint:
            # Raw dd disk — no container magic at byte 0; recognised
            # by its GPT / MBR partition structure. Must run AFTER the
            # bitlocker check (an encrypted volume isn't a partitioned
            # raw disk) and BEFORE the memory fallback (a partitioned
            # disk is never a memory image).
            rd_kind = _detect_raw_disk(ctx.input_path)
            if rd_kind:
                magic_hint = rd_kind
        deferred_carve: str | None = None
        if not magic_hint:
            # Carve-only blob (e.g. exported UNALLOCATED disk space): a large
            # headerless stream densely populated with NTFS/Windows artifact
            # signatures. Must run LAST in the magic chain (after every
            # container/disk check) and BEFORE the memory fallback, so a real
            # memory image still falls through to MemoryForensicator.
            cb_kind = _detect_carvable_blob(ctx.input_path)
            if cb_kind:
                # A Windows memory image trips this same heuristic (its RAM
                # caches MFT/registry/EVTX/prefetch). If the input names
                # itself a memory capture, don't commit to carve-only — defer
                # to the vol3 kernel probe below and only carve if vol3 finds
                # no kernel.
                if _looks_like_memory_input(ctx.input_path, ctx.case_id):
                    deferred_carve = cb_kind
                else:
                    magic_hint = cb_kind

        evidence = [EvidenceItem(
            tool="el.triage", version="0.1.0",
            command=f"head -c 64 {ctx.input_path}",
            output_sha256=head_sha, output_path=str(head_path),
            extracted_facts={"magic_first16_hex": head[:16].hex(), "matched": magic_hint},
        )]

        if magic_hint:
            ctx.shared["evidence_kind"] = magic_hint
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                claim=f"Input identified as {magic_hint} from magic bytes",
                confidence="high", evidence=evidence,
            )))
        else:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                claim="Input has no recognised magic header — treating as opaque memory candidate",
                confidence="low", evidence=evidence,
            )))

        non_memory = ("pcap", "pcapng", "EWF", "EVTX", "Registry",
                      "vhdx", "vhd", "vmdk", "bitlocker", "raw-disk",
                      "unallocated")
        if magic_hint and any(n in magic_hint for n in non_memory):
            return out
        if head[:1] in (b"{", b"[") or head[:5] in (b"<?xml", b"<html"):
            # Suricata EVE JSON — JSONL of {"event_type":..., ...} rows.
            # Detect by peeking at the first few rows for canonical
            # event-type values. Cheap: 10-line read, no full parse.
            try:
                from el.skills.suricata_eve import is_suricata_eve
                if head[:1] == b"{" and is_suricata_eve(ctx.input_path):
                    ctx.shared["evidence_kind"] = "suricata-eve"
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="high",
                        claim=(f"Input identified as Suricata EVE JSON "
                               f"({ctx.input_path.name}) — routes to "
                               f"NetworkAnalystAgent."),
                        evidence=evidence,
                        hypotheses_supported=["H_NETWORK_ARTIFACTS"],
                    )))
                    return out
            except Exception:
                # Defensive — Suricata detection must never block the
                # structured-text fallback path.
                pass
            ctx.shared["evidence_kind"] = ctx.shared.get("evidence_kind") or "structured-text"
            return out

        out += self._maybe_run_vol3(ctx, analysis)
        if deferred_carve and not ctx.shared.get("mem_os"):
            # The input named itself a memory capture and tripped the
            # carve-blob heuristic, but Volatility found no kernel — it is a
            # headerless blob after all (e.g. an unallocated export with a
            # memory-ish name). Route to the carving pipeline as originally
            # detected rather than dropping it.
            ctx.shared["evidence_kind"] = deferred_carve
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Input named like a memory capture but Volatility "
                       f"found no kernel — reclassifying as {deferred_carve} "
                       f"and routing to the carving pipeline"),
                evidence=evidence,
            )))
        return out

    def _maybe_run_vol3(self, ctx: AgentContext, analysis):
        out: list[Finding] = []
        # Pre-flight host-RAM check: vol3 plugins page-fault through
        # the memory image and Python wrappers retain large per-plugin
        # state. On the SRL-2018 mail capture (18 GB image into 16 GB
        # host) memory_forensicator OOM-killed mid-run with no graceful
        # surface. Emit an insufficient finding now so the operator
        # sees the constraint instead of a silent kill.
        try:
            img_size = ctx.input_path.stat().st_size
        except OSError:
            img_size = 0
        try:
            import os as _os
            page_size = _os.sysconf("SC_PAGE_SIZE")
            phys_pages = _os.sysconf("SC_PHYS_PAGES")
            host_ram_bytes = page_size * phys_pages
        except (ValueError, OSError, AttributeError):
            host_ram_bytes = 0
        if img_size and host_ram_bytes and img_size > host_ram_bytes:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"Memory image size ({img_size // (1024**3)} GiB) "
                       f"exceeds host physical RAM "
                       f"({host_ram_bytes // (1024**3)} GiB) — vol3 "
                       f"is likely to OOM-kill mid-run on plugins that "
                       f"materialise per-process state. Run on a host "
                       f"with ≥ {(img_size * 12 // 10) // (1024**3)} "
                       f"GiB RAM, or pre-trim the image."),
            )))
        try:
            family, run = vol3.detect_os(ctx.input_path, analysis / "vol3-banners")
            ev = run.as_evidence()
            if family:
                ctx.shared["mem_os"] = family
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    claim=f"Volatility 3 banners indicate {family} memory image",
                    confidence="high", evidence=[ev],
                    hypotheses_supported=[f"H_OS_{family.upper()}"],
                )))
            else:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    claim="Volatility 3 ran but did not yield a confident OS family",
                    confidence="low", evidence=[ev],
                )))
        except vol3.Vol3Error as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                claim=f"Cannot determine memory OS family — vol3 failed: {e}",
                confidence="insufficient",
            )))
        return out

    @staticmethod
    def _classify_cylr_zip(path: Path) -> str | None:
        """Two-stage CyLR detection: recognise the zip shape AND
        classify the target OS so dispatch routes to the right
        downstream agent.

        Stage 1 — recognise CyLR shape via either:
          * canonical `CyLR_Collection_Log_<YYYY-MM-DD_HH-MM-SS>.log`
            marker at the zip root (written on every platform), OR
          * a strong FS-root signal (≥5 entries under known
            absolute-path prefixes — `C/Windows/` for Windows,
            `var/log/` for Linux, `private/var/` for macOS).
            Per-OS thresholds keep the structural fallback robust
            even when CyLR was run with --DisableLogging.

        Stage 2 — classify target OS from the prefix pattern:
          * `C/Windows/` or `C/Users/` or `C/$MFT` / `C/$LogFile`
            → "windows"
          * `var/log/` / `etc/` / `home/` / `root/` → "linux"
          * `private/var/` / `System/Library/` / `Users/<u>/Library/`
            → "macos"

        Returns the platform string or None when the zip isn't
        CyLR-shaped. Cheap probe — namelist only, no decompression.
        """
        name = path.name.lower()
        if not name.endswith(".zip"):
            return None
        try:
            import zipfile
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                if len(names) > 2000:
                    names = names[:2000]
                has_marker = any(
                    n.startswith("CyLR_Collection_Log_")
                    and n.endswith(".log")
                    for n in names)
                # Per-OS structural counters
                linux_hits = sum(
                    1 for n in names
                    if n.startswith(("var/log/", "etc/", "home/",
                                       "root/")))
                # Windows: drive-letter prefix (`C/`, `D/`, etc.)
                # carries `Windows/`, `Users/`, or `$MFT` / `$LogFile`
                # underneath. Check just for paths like `C/Windows/`
                # to be conservative.
                windows_hits = sum(
                    1 for n in names
                    if (len(n) > 2 and n[1] == "/"
                        and n[0].isalpha()
                        and n[2:].startswith(
                            ("Windows/", "Users/", "ProgramData/",
                             "$MFT", "$LogFile", "$Recycle.Bin/"))))
                # macOS: `private/var/`, `System/`, `Users/<u>/Library/`
                macos_hits = sum(
                    1 for n in names
                    if n.startswith(("private/var/",
                                     "System/Library/",
                                     "Library/")))
                # Don't fire unless we have either the marker file
                # or a per-OS structural threshold.
                if not has_marker and (
                        linux_hits < 5
                        and windows_hits < 5
                        and macos_hits < 5):
                    return None
                # Stage 2: classify. Highest hit-count wins; marker-
                # only zips with no clear platform shape get "unknown"
                # which the dispatch can degrade gracefully.
                top = max(("linux", linux_hits),
                           ("windows", windows_hits),
                           ("macos", macos_hits),
                           key=lambda kv: kv[1])
                if top[1] >= 5:
                    return top[0]
                # Marker present but no clear platform — return a
                # sentinel so dispatch can still route to the most
                # universal handler (LinuxForensicator is best-effort
                # on a heterogeneous tree).
                return "unknown" if has_marker else None
        except (OSError, Exception):                       # noqa: BLE001
            return None

    # Back-compat alias — earlier code called the boolean form. Keep
    # the old name working as a thin wrapper so any external caller
    # (tests, scripts) doesn't break in one go.
    @staticmethod
    def _archive_looks_cylr(path: Path) -> bool:
        return TriageAgent._classify_cylr_zip(path) is not None

    @staticmethod
    def _archive_looks_velociraptor(path: Path) -> bool:
        """Cheap probe — list the archive without extracting and
        look for Velociraptor canonical markers in the member names.
        Two shapes covered:

          1. Single-host offline collector: zip with
             `Collection-<host>-<ts>/uploads.json` or a top-level
             `client_info.json`.
          2. Hunt download: zip with `hunt_info.json` at root +
             per-client subdirs containing `client_info.json` and
             `collection_context.json`.

        Either marker is sufficient. Files are read by name only —
        no decompression, so this is cheap even on large hunt zips."""
        name = path.name.lower()
        if not name.endswith(".zip"):
            return False
        try:
            import zipfile
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                if len(names) > 2000:
                    names = names[:2000]
                for n in names:
                    nl = n.lower()
                    if (nl.endswith("hunt_info.json")
                            or nl.endswith("client_info.json")
                            or nl.endswith("collection_context.json")
                            or nl.endswith("velociraptor.config.yaml")):
                        return True
        except (OSError, Exception):                       # noqa: BLE001
            return False
        return False

    @staticmethod
    def _archive_looks_android(path: Path) -> bool:
        """Cheap probe — list the archive without extracting and
        look for canonical Android root markers in the member
        names. Avoids a full unpack (Magnet TARs are 25 GB+)."""
        name = path.name.lower()
        try:
            if name.endswith(".tar"):
                import tarfile
                with tarfile.open(path, "r") as tf:
                    for i, m in enumerate(tf):
                        if i > 200:
                            break
                        n = m.name.lower()
                        if ("data/system/packages.xml" in n
                                or "data/data/" in n
                                or "system/build.prop" in n):
                            return True
            elif name.endswith(".zip"):
                import zipfile
                with zipfile.ZipFile(path) as zf:
                    for i, n in enumerate(zf.namelist()):
                        if i > 500:
                            break
                        nl = n.lower()
                        if ("data/system/packages.xml" in nl
                                or "data/data/" in nl
                                or "system/build.prop" in nl):
                            return True
        except (OSError, Exception):                       # noqa: BLE001
            return False
        return False

    @staticmethod
    def _looks_like_log_corpus(d) -> bool:
        """True if *d* has >=2 child subdirs that each contain a recognised
        log source (Windows Event XML / eCAR / Zeek / Cisco ASA / Snort /
        web access / syslog) — the multi-host SOC log-corpus shape."""
        try:
            subdirs = [c for c in d.iterdir() if c.is_dir()]
        except OSError:
            return False
        if len(subdirs) < 2:
            return False
        logset = {"ecar.json", "cisco_asa.log", "snort_alert.log",
                  "syslog.log", "conn.json", "dns.json", "web_access.log",
                  "proxy_access.log"}
        marker_hosts = 0
        for sd in subdirs[:40]:
            try:
                for f in sd.iterdir():
                    n = f.name.lower()
                    if (n in logset or n.startswith("windows_event")
                            or n.endswith("access.log")
                            or n.endswith("_alert.log")):
                        marker_hosts += 1
                        break
            except OSError:
                continue
            if marker_hosts >= 2:
                return True
        return False

    def _classify_directory(self, ctx: AgentContext, analysis) -> list[Finding]:
        """Classify a directory input: Windows artifacts vs Velociraptor collection vs unknown."""
        import hashlib
        out: list[Finding] = []
        d = ctx.input_path

        # Multi-host log corpus — a directory of per-host subdirs each holding
        # mixed-format logs (Windows Event XML / eCAR / Zeek JSON / Cisco ASA /
        # Snort / web access / syslog). Checked early: the root carries no
        # FS-root markers, so the OS-shape probes below would all miss it.
        if self._looks_like_log_corpus(d):
            import hashlib as _hl
            ctx.shared["evidence_kind"] = "log-corpus"
            hosts = sorted(c.name for c in d.iterdir() if c.is_dir())[:50]
            sha = _hl.sha256(("log-corpus:" + ",".join(hosts)).encode()).hexdigest()
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Input directory looks like a multi-host log corpus "
                       f"({len(hosts)} host dir(s)) with recognised log "
                       f"sources (Windows Event XML / eCAR / Zeek JSON / "
                       f"Cisco ASA / Snort / web access / syslog) — routes to "
                       f"LogCorpusAgent."),
                evidence=[EvidenceItem(
                    tool="el.triage", version="0.1.0",
                    command=f"log-corpus shape probe {d.name}",
                    output_sha256=sha, output_path=str(d),
                    extracted_facts={"host_dirs": hosts})],
                hypotheses_supported=["H_DISK_ARTIFACTS"])))
            return out

        # MTD/YAFFS2 bundle — old Android phone dumps (pre-Android-4)
        # arrive as a directory with multiple mtdN.dd raw partition
        # files. AndroidForensicator's YAFFS2 path runs unyaffs on the
        # YAFFS2-shaped partitions, then chains the extracted FS into
        # the standard android-artifacts walker.
        from el.skills import yaffs2 as y_skill
        if y_skill.is_mtd_bundle_dir(d):
            ctx.shared["evidence_kind"] = "android-mtd-bundle"
            mtd_files = sorted(d.glob("mtd*.dd"))
            sha = hashlib.sha256(
                b"".join(f.name.encode() for f in mtd_files)
            ).hexdigest()
            ev = EvidenceItem(
                tool="el.triage", version="0.1.0",
                command=f"mtd-bundle probe {d.name}",
                output_sha256=sha, output_path=str(d),
                extracted_facts={
                    "mtd_partition_count": len(mtd_files),
                    "mtd_files": [f.name for f in mtd_files][:20],
                    "has_sdcard_dump":
                        (d / "sdcard.dd").is_file(),
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="high",
                claim=(f"Input directory looks like an MTD/YAFFS2 "
                       f"phone dump ({len(mtd_files)} mtd*.dd "
                       f"partition file(s); old-Android shape). "
                       f"Routes to AndroidForensicator's YAFFS2 "
                       f"extract path (unyaffs)."),
                evidence=[ev],
                hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
            return out

        # dfTimewolf bundle — directory with a recipe JSON/YAML and / or
        # a dftimewolf.log alongside collected artifacts. Run BEFORE the
        # FS-shape detectors below (an aws_forensics recipe drops a Plaso
        # storage + a CloudTrail JSON which would otherwise look like a
        # generic mixed dir).
        from el.skills import dftimewolf_bundle as dftw
        if dftw.looks_like_dftimewolf_bundle(d):
            try:
                bundle = dftw.parse_bundle(d)
            except dftw.DFTimewolfError:
                bundle = None
            if bundle is not None:
                ctx.shared["evidence_kind"] = "dftimewolf-bundle"
                ctx.shared["dftimewolf_bundle"] = bundle
                ev = bundle.as_evidence()
                recipe_name = (bundle.recipe.name if bundle.recipe
                                else "(recipe not parsed)")
                modules_str = (", ".join(bundle.recipe.module_names[:6])
                                if bundle.recipe else "")
                kinds_str = ", ".join(
                    f"{k}×{v}" for k, v
                    in sorted(bundle.artifact_kinds.items(),
                              key=lambda kv: -kv[1])[:8]
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim=(f"Input directory looks like a dfTimewolf output "
                           f"bundle (recipe='{recipe_name}'"
                           + (f", modules: {modules_str}" if modules_str else "")
                           + f"; {len(bundle.artifact_files)} sub-artifacts"
                           + (f" — {kinds_str}" if kinds_str else "")
                           + ")"),
                    evidence=[ev],
                )))
                return out

        # Disk-image + memory-dump bundle (e.g. the SANS LoneWolf shape:
        # multi-segment .E01 + memdump.mem + pagefile.sys + FTK Imager log
        # in one directory). Top-level glob only — cheap. We treat the
        # disk image as the primary investigator input (route via the
        # existing EWF (E01) kind → DiskForensicator) and hand off the
        # memory image to the coordinator via ctx.shared so it runs the
        # MemoryForensicator pass after disk extraction. Without this
        # detector the directory falls through to "directory-unclassified"
        # and neither agent ever sees the right input.
        # The disk half of the bundle is either E01 segments OR a raw
        # dd image recognised by its GPT/MBR partition structure (the
        # 2019 Narcos corpus ships split-raw GPT disks, reassembled to
        # a single .raw via affuse before staging). Find whichever is
        # present.
        e01_segments = sorted(
            list(d.glob("*.E01")) + list(d.glob("*.e01")))
        raw_disk_file: Path | None = None
        raw_disk_kind: str | None = None
        if not e01_segments:
            for p in sorted(d.iterdir()):
                if not p.is_file() or p.name.lower() == "pagefile.sys":
                    continue
                rk = _detect_raw_disk(p)
                if rk:
                    raw_disk_file = p
                    raw_disk_kind = rk
                    break
        if e01_segments or raw_disk_file:
            # Candidate memory image: top-level file matching a known
            # vol3-compatible extension or canonical name. pagefile.sys
            # is NOT a memory image — it's the swap, picked up separately
            # as a vol3 swap layer when present. The raw DISK file (when
            # the disk is raw) must be EXCLUDED — it shares the .raw
            # extension with a raw memory dump, so we filter it out by
            # identity here.
            #
            # `.img` is included because a `.img` sibling of E01 segments
            # is almost certainly a paired memory dump, not a redundant
            # disk image — the SRL-2018 corpus uses `base-<host>-memory.img`
            # naming for every captured host.
            mem_exts = (".mem", ".vmem", ".raw", ".dmp", ".bin", ".lime",
                         ".img")
            # Stem substrings (not exact match) so `base-dc-memory`,
            # `wkstn05-memdump`, `host-RAM-capture` all qualify.
            mem_names = ("memdump", "memory", "memcap", "ram")
            mem_candidates = [
                p for p in sorted(d.iterdir())
                if p.is_file()
                and p.name.lower() != "pagefile.sys"
                and p != raw_disk_file
                and (p.suffix.lower() in mem_exts
                     or any(n in p.stem.lower() for n in mem_names))
            ]
            if mem_candidates:
                if e01_segments:
                    disk_input = e01_segments[0]
                    disk_kind = "EWF (E01)"
                    disk_desc = f"{len(e01_segments)} .E01 segment(s)"
                else:
                    disk_input = raw_disk_file
                    disk_kind = raw_disk_kind  # "raw-disk (GPT|MBR)"
                    disk_desc = f"{raw_disk_kind} '{disk_input.name}'"
                mem_image = mem_candidates[0]
                pagefile = (d / "pagefile.sys"
                            if (d / "pagefile.sys").is_file() else None)
                ctx.shared["evidence_kind"] = disk_kind
                ctx.shared["paired_memory_image"] = str(mem_image)
                if pagefile is not None:
                    ctx.shared["paired_pagefile"] = str(pagefile)
                # Rewrite input_path to the disk (E01 first segment, or
                # the raw disk file). DiskForensicator handles both.
                ctx.input_path = disk_input
                facts_blob = ":".join(
                    [str(disk_input), str(mem_image),
                     str(pagefile or "")]).encode()
                sha = hashlib.sha256(facts_blob).hexdigest()
                ev = EvidenceItem(
                    tool="el.triage", version="0.1.0",
                    command=f"disk-and-memory-bundle probe {d.name}",
                    output_sha256=sha, output_path=str(d),
                    extracted_facts={
                        "disk_kind": disk_kind,
                        "disk_input": disk_input.name,
                        "e01_segment_count": len(e01_segments),
                        "memory_image": mem_image.name,
                        "memory_image_size_bytes": mem_image.stat().st_size,
                        "pagefile_present": pagefile is not None,
                    },
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim=(f"Input directory looks like a disk+memory "
                           f"evidence bundle ({disk_desc} + memory image "
                           f"'{mem_image.name}'"
                           + (f" + pagefile.sys" if pagefile else "")
                           + f"). Disk routes to DiskForensicator; "
                           f"coordinator chains MemoryForensicator on "
                           f"'{mem_image.name}' after disk extraction."),
                    evidence=[ev],
                    hypotheses_supported=["H_DISK_ARTIFACTS"],
                )))
                return out

        # iTunes / Finder backup directory — Manifest.plist + Manifest.db
        # at the top level. Distinct from a generic iOS FS tree because
        # it's blob-keyed-by-sha1, not a real filesystem.
        if (d / "Manifest.plist").is_file() and \
                (d / "Manifest.db").is_file():
            ctx.shared["evidence_kind"] = "itunes-backup"
            sha = hashlib.sha256(
                (d / "Manifest.plist").read_bytes()).hexdigest()
            ev = EvidenceItem(
                tool="el.triage", version="0.1.0",
                command=f"itunes-backup probe {d.name}",
                output_sha256=sha,
                output_path=str(d / "Manifest.plist"),
                extracted_facts={"manifest_plist": True,
                                  "manifest_db": True},
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="high",
                claim=(f"Input directory looks like an iTunes/Finder "
                       f"backup (Manifest.plist + Manifest.db at top "
                       f"level) — routes to IOSForensicator's "
                       f"backup-parse path."),
                evidence=[ev],
                hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
            return out

        # Cheap path-shape checks FIRST. iOS/Android trees can contain
        # hundreds of thousands of files across app-data subtrees; on a
        # slow FUSE mount (e.g. VMware HGFS) the rglob walk below
        # degrades into minutes of readdir. Mobile shapes can be
        # recognised from a handful of `is_dir()` probes without walking.
        android_signals = (
            (d / "data" / "system" / "packages.xml").is_file(),
            (d / "data" / "app").is_dir(),
            (d / "data" / "data").is_dir(),
            (d / "storage" / "emulated").is_dir(),
        )
        is_android = sum(android_signals) >= 2

        ios_signals = (
            (d / "private" / "var" / "mobile").is_dir(),
            (d / "private" / "var" / "containers" / "Bundle"
                 / "Application").is_dir(),
            (d / "private" / "var" / "installd").is_dir(),
            (d / "Applications" / "MobileSMS.app").is_dir()
              or (d / "Applications" / "AppStore.app").is_dir(),
        )
        is_ios = sum(ios_signals) >= 2

        # bulk_extractor output dir — has report.xml OR ≥3 of the
        # canonical feature files. Decided cheaply via is_dir() probes
        # before any rglob.
        from el.skills.bulk_extractor_features import (
            is_bulk_extractor_output as _be_probe,
        )
        is_bulk_extractor = _be_probe(d)

        # QNAP NAS user-data volume (QTS DataVolN ext4 mount).
        # Distinct shape: `homes/` (singular `home/` is Linux), `.qpkg/`
        # for installed apps, `.@*` private metadata dirs, `.system/`,
        # `.samba/`. Validated against case 21APR_245 (Geneva-airport
        # seizure 2021): one DataVol1 mount produced 5/5 hits.
        qnap_signals = (
            (d / "homes").is_dir(),
            (d / ".qpkg").is_dir(),
            (d / ".system").is_dir(),
            (d / ".samba").is_dir(),
            (d / ".@station_config").is_dir(),
        )
        is_qnap = sum(qnap_signals) >= 3

        # macOS filesystem root (mounted APFS Data volume OR a copied-out
        # tree). Distinct from generic Linux: presence of a /System/
        # directory PLUS Apple-specific markers (private/var/db,
        # .Spotlight-V100, .fseventsd, /Users with apple-shaped subdirs).
        macos_signals = (
            (d / "System").is_dir() and (d / "Library").is_dir(),
            (d / "Users").is_dir(),
            (d / "private" / "var" / "db").is_dir(),
            (d / ".Spotlight-V100").exists(),
            (d / ".fseventsd").exists(),
            (d / "Applications" / "Safari.app").is_dir()
                or (d / "Applications" / "Mail.app").is_dir()
                or (d / "Applications" / "Utilities").is_dir(),
        )
        is_macos = sum(macos_signals) >= 3

        # Generic Linux filesystem root (mounted ext4 / btrfs / xfs).
        # Also matches a chroot or a container-extracted rootfs. Need
        # ≥4 to avoid false-positives on partial extracts that happen
        # to have one or two of these names.
        linux_signals = (
            (d / "etc").is_dir(),
            (d / "var" / "log").is_dir(),
            (d / "home").is_dir(),
            (d / "root").is_dir(),
            (d / "usr").is_dir(),
            (d / "bin").is_dir() or (d / "usr" / "bin").is_dir(),
            (d / "boot").is_dir(),
        )
        is_linux = sum(linux_signals) >= 4

        # KAPE-Triage output preserves the native Windows path layout
        # under a drive-letter subdir (typically `C/`). Distinct from
        # `windows-artifacts-dir` (DiskForensicator's curated flat
        # `mft/`+`registry/`+`evtx/` layout). Cheap probe against the
        # first drive-letter root containing `Windows/`. KAPE captures
        # all drives by default; we accept C/D/E/F as plausible system
        # drives — anything more exotic falls through to the rglob
        # fallback below.
        kape_drive: Path | None = None
        kape_hits = 0
        for _letter in ("C", "D", "E", "F"):
            _drive = d / _letter
            if not _drive.is_dir() or not (_drive / "Windows").is_dir():
                continue
            _hits = sum((
                (_drive / "Windows" / "System32" / "config" / "SYSTEM").is_file(),
                (_drive / "Windows" / "System32" / "config" / "SOFTWARE").is_file(),
                (_drive / "Windows" / "Prefetch").is_dir(),
                (_drive / "$MFT").is_file(),
                (_drive / "Windows" / "System32" / "winevt" / "Logs").is_dir(),
                (_drive / "Windows" / "appcompat" / "Programs" / "Amcache.hve").is_file(),
            ))
            if _hits >= 2:
                kape_drive = _drive
                kape_hits = _hits
                break
        is_kape = kape_drive is not None

        # Only pay for the full rglob when we DIDN'T recognise a shape
        # already — every mobile / QNAP / Linux-rootfs / KAPE case is
        # decided from the cheap is_dir() probes above. Windows-extracted
        # / Velociraptor detection still needs filename scans.
        names: list[str] = []
        if not (is_android or is_ios or is_macos or is_qnap or is_linux
                 or is_bulk_extractor or is_kape):
            # Walk via os.walk so we can pass onerror=None and skip
            # unreadable subtrees gracefully — QNAP DataVol1 mounts
            # have root-only files (.qcodesigning) that crash rglob's
            # implicit stat() with PermissionError. Same pattern used
            # in intake._hash_directory.
            import os as _os
            try:
                for dirpath, dirnames, filenames in _os.walk(
                    str(d), onerror=lambda e: None, followlinks=False,
                ):
                    for fn in filenames:
                        names.append(fn)
                        if len(names) >= 5000:
                            break
                    if len(names) >= 5000:
                        break
            except OSError:
                pass

        velo_hits = sum(1 for n in names if any(n.startswith(h) for h in VELOCIRAPTOR_HINTS))
        artifact_hits = sum(1 for n in names if any(h in n for h in
                            ("$MFT", "Amcache.hve", "SYSTEM", "SOFTWARE", "NTUSER.DAT",
                             "SRUDB.dat")))
        evtx_count = sum(1 for n in names if n.endswith(".evtx"))
        prefetch_dir = (d / "Prefetch").exists() or (d / "prefetch").exists()
        pcap_count = sum(
            1 for n in names
            if n.lower().endswith((".pcap", ".pcapng", ".cap"))
        )

        listing_path = analysis / "directory-listing.txt"
        listing_path.write_text("\n".join(sorted(names))[:200_000])
        sha = hashlib.sha256(listing_path.read_bytes()).hexdigest()
        ev = EvidenceItem(
            tool="el.triage", version="0.1.0",
            command=f"file inventory of {d}",
            output_sha256=sha, output_path=str(listing_path),
            extracted_facts={"file_count": len(names),
                             "velociraptor_hits": velo_hits,
                             "artifact_hits": artifact_hits,
                             "evtx_count": evtx_count,
                             "prefetch_dir": prefetch_dir,
                             "pcap_count": pcap_count},
        )

        if is_android:
            ctx.shared["evidence_kind"] = "android-fs-dir"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Input directory looks like an extracted Android "
                       f"filesystem tree (data/system/packages.xml + "
                       f"data/data/ per-app subtree + /storage/emulated "
                       f"signals matched)"),
                evidence=[ev], hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
        elif is_bulk_extractor:
            ctx.shared["evidence_kind"] = "bulk-extractor-output"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Input directory looks like a bulk_extractor "
                       f"output dir (report.xml or ≥3 canonical feature "
                       f"files present)"),
                evidence=[ev], hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
        elif is_qnap:
            ctx.shared["evidence_kind"] = "qnap-nas-dir"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Input directory looks like a mounted QNAP QTS "
                       f"DataVol root ({sum(qnap_signals)}/5 markers: "
                       f"homes/ + .qpkg/ + .system/ + .samba/ + "
                       f".@station_config/)"),
                evidence=[ev], hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
        elif is_ios:
            ctx.shared["evidence_kind"] = "ios-fs-dir"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Input directory looks like an extracted iOS "
                       f"filesystem tree (/private/var/mobile + "
                       f"/private/var/containers/Bundle/Application + "
                       f"/private/var/installd signals matched)"),
                evidence=[ev], hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
        elif is_macos:
            ctx.shared["evidence_kind"] = "macos-fs-dir"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Input directory looks like a mounted macOS "
                       f"filesystem ({sum(macos_signals)}/6 markers: "
                       f"System+Library, Users/, private/var/db/, "
                       f".Spotlight-V100, .fseventsd, Apple .app "
                       f"presence)"),
                evidence=[ev], hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
        elif is_linux:
            # Linux check is intentionally LAST among FS-shape probes:
            # iOS / macOS / QNAP NAS roots all share /etc + /usr + /bin
            # + /var with vanilla Linux, so a more-specific shape must
            # win first or the iPhone SE AFU dump misroutes to
            # LinuxForensicatorAgent.
            ctx.shared["evidence_kind"] = "linux-fs-dir"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Input directory looks like a mounted Linux "
                       f"filesystem root ({sum(linux_signals)}/7 "
                       f"markers: etc/, var/log/, home/, root/, usr/, "
                       f"bin/, boot/)"),
                evidence=[ev], hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
        elif velo_hits >= 2:
            ctx.shared["evidence_kind"] = "velociraptor-collection"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=f"Input directory looks like a Velociraptor collection "
                      f"({velo_hits} Velociraptor artifact filenames matched)",
                evidence=[ev], hypotheses_supported=["H_ENDPOINT_COLLECTION"],
            )))
        elif is_kape:
            ctx.shared["evidence_kind"] = "kape-triage"
            ctx.shared["kape_drive"] = str(kape_drive)
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Input directory looks like a KAPE triage collection "
                       f"({kape_drive.name}/Windows/ present + "
                       f"{kape_hits}/6 native-layout artifact markers: "
                       f"SYSTEM, SOFTWARE, Prefetch, $MFT, winevt/Logs, "
                       f"Amcache.hve)"),
                evidence=[ev], hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
        elif artifact_hits >= 2 or evtx_count >= 5 or prefetch_dir:
            ctx.shared["evidence_kind"] = "windows-artifacts-dir"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=f"Input directory looks like an extracted Windows artifacts collection "
                      f"(MFT/registry hits={artifact_hits}, evtx={evtx_count}, "
                      f"prefetch_dir={prefetch_dir})",
                evidence=[ev], hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))
        elif pcap_count >= 2:
            # Directory of pcaps — typically a multi-day capture series
            # (e.g. M57's 50 pcaps spanning Nov 13-17 2009). Pre-merge
            # them into one file so NetworkAnalystAgent (which expects a
            # single pcap input) can process the whole series in one
            # pass. Sort by name for determinism — most capture series
            # are ISO-timestamped so name-order ≈ chronological order.
            import subprocess as _sp
            merged_dir = ctx.case_dir / "raw"
            merged_dir.mkdir(parents=True, exist_ok=True)
            merged_path = merged_dir / "merged.pcap"
            pcap_files = sorted(
                str(d / n) for n in names
                if n.lower().endswith((".pcap", ".pcapng", ".cap"))
            )
            mergecap_cmd = ["mergecap", "-w", str(merged_path), *pcap_files]
            try:
                rc = _sp.run(
                    mergecap_cmd, capture_output=True, text=True,
                    timeout=900,
                )
                if rc.returncode != 0 or not merged_path.exists():
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="insufficient",
                        claim=(f"mergecap failed for {pcap_count} pcap "
                                f"file(s) (rc={rc.returncode}): "
                                f"{rc.stderr[:200]}"),
                        evidence=[ev],
                    )))
                    ctx.shared["evidence_kind"] = "directory-unclassified"
                    return out
            except (FileNotFoundError, _sp.TimeoutExpired) as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=f"mergecap unavailable or timed out: {e}",
                    evidence=[ev],
                )))
                ctx.shared["evidence_kind"] = "directory-unclassified"
                return out
            ctx.shared["evidence_kind"] = "pcap-collection"
            ctx.shared["merged_pcap_path"] = str(merged_path)
            ctx.shared["pcap_source_files"] = pcap_files
            # Rewrite input_path so NetworkAnalystAgent + downstream
            # network skills see a single normal pcap instead of a dir.
            ctx.input_path = merged_path
            merged_size = merged_path.stat().st_size
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Input directory looks like a multi-pcap capture "
                        f"series ({pcap_count} pcap file(s) merged via "
                        f"mergecap into {merged_path.name}, "
                        f"{merged_size/1024/1024:.1f} MiB total). "
                        f"Routing to network analyst."),
                evidence=[ev], hypotheses_supported=["H_NETWORK_TRAFFIC"],
            )))
        else:
            ctx.shared["evidence_kind"] = "directory-unclassified"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"Directory input does not match any known shape "
                      f"(files={len(names)}); routing to default agent",
                evidence=[ev],
            )))
        return out
