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


class TriageAgent(Agent):
    name = "triage"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        if ctx.input_path.is_dir():
            return self._classify_directory(ctx, analysis)

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
                      "vhdx", "vhd", "vmdk")
        if magic_hint and any(n in magic_hint for n in non_memory):
            return out
        if head[:1] in (b"{", b"[") or head[:5] in (b"<?xml", b"<html"):
            ctx.shared["evidence_kind"] = ctx.shared.get("evidence_kind") or "structured-text"
            return out

        return out + self._maybe_run_vol3(ctx, analysis)

    def _maybe_run_vol3(self, ctx: AgentContext, analysis):
        out: list[Finding] = []
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

    def _classify_directory(self, ctx: AgentContext, analysis) -> list[Finding]:
        """Classify a directory input: Windows artifacts vs Velociraptor collection vs unknown."""
        import hashlib
        out: list[Finding] = []
        d = ctx.input_path

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

        # Only pay for the full rglob when we DIDN'T recognise a mobile
        # shape — Windows / Velociraptor detection needs filename scans.
        names: list[str] = []
        if not (is_android or is_ios):
            for p in d.rglob("*"):
                if p.is_file():
                    names.append(p.name)
                    if len(names) >= 5000:
                        break

        velo_hits = sum(1 for n in names if any(n.startswith(h) for h in VELOCIRAPTOR_HINTS))
        artifact_hits = sum(1 for n in names if any(h in n for h in
                            ("$MFT", "Amcache.hve", "SYSTEM", "SOFTWARE", "NTUSER.DAT",
                             "SRUDB.dat")))
        evtx_count = sum(1 for n in names if n.endswith(".evtx"))
        prefetch_dir = (d / "Prefetch").exists() or (d / "prefetch").exists()

        listing_path = analysis / "directory-listing.txt"
        listing_path.write_text("\n".join(sorted(names))[:200_000])
        sha = hashlib.sha256(listing_path.read_bytes()).hexdigest()
        from el.schemas.finding import EvidenceItem
        ev = EvidenceItem(
            tool="el.triage", version="0.1.0",
            command=f"file inventory of {d}",
            output_sha256=sha, output_path=str(listing_path),
            extracted_facts={"file_count": len(names),
                             "velociraptor_hits": velo_hits,
                             "artifact_hits": artifact_hits,
                             "evtx_count": evtx_count,
                             "prefetch_dir": prefetch_dir},
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
        elif velo_hits >= 2:
            ctx.shared["evidence_kind"] = "velociraptor-collection"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=f"Input directory looks like a Velociraptor collection "
                      f"({velo_hits} Velociraptor artifact filenames matched)",
                evidence=[ev], hypotheses_supported=["H_ENDPOINT_COLLECTION"],
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
        else:
            ctx.shared["evidence_kind"] = "directory-unclassified"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"Directory input does not match any known shape "
                      f"(files={len(names)}); routing to default agent",
                evidence=[ev],
            )))
        return out
