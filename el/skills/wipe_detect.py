"""Skill: file-level wipe detection from NTFS MFT metadata.

Distinct from ``gpt_state`` (whole-disk GPT/MBR front-wipe) and ``ntfs_vbr``
(front-VBR recovery): this detector finds individual *files* whose content was
destroyed in place while the file stays present in the directory tree — the
fingerprint of a targeted anti-forensic wipe (sdelete, cipher /w over the file,
a zero-overwrite script) rather than a normal delete.

The load-bearing signal is the NTFS ``$DATA`` *initialized size* (a.k.a. valid
data length). NTFS records how many bytes of a non-resident stream were ever
written; reads past that point return zeros without touching disk. So:

    allocated file  +  non-resident $DATA  +  init_size > 0  +  content all-zero
        ⇒ the file ONCE held init_size bytes that are now zeroed = WIPED.

The init_size is a metadata *fossil* of the destroyed data. The crucial
false-positive guard is the *never-written stub*: a freshly-created OST/cache
file Windows preallocated but never populated has ``init_size == 0`` and is NOT
a wipe. classify() separates the two deterministically.

This was validated on the rocba case: ``fred.rocba@outlook.com.ost`` was
allocated, non-resident, ``init_size = 24 973 312``, every cluster zero — an
sdelete-class wipe — while its never-synced cousins had ``init_size == 0``.

Design: parse_istat() + classify() are pure and unit-tested; the icat/istat
plumbing lives in the (gated) artifact-recovery agent, not here.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem

# A wiped stream must have declared at least this many initialized bytes before
# we treat an all-zero read as destruction. Below this, an all-zero tiny stream
# is indistinguishable from filesystem slack / a stub and not worth a finding.
MIN_WIPED_INIT_BYTES = 4096

# High-value artifact paths whose wipe is forensically load-bearing. The
# recovery agent uses these to decide *which* files to istat rather than
# walking the whole MFT. Matched case-insensitively against the relpath.
# Each is an artifact that (a) normally exists on a live Windows host and
# (b) carries user-attributable evidence an insider/intruder would want gone.
HIGH_VALUE_TARGETS: tuple[str, ...] = (
    r"\.ost$", r"\.pst$",                       # Outlook mail caches
    r"NTUSER\.DAT$", r"UsrClass\.dat$",         # per-user registry
    r"[/\\]config[/\\](SYSTEM|SOFTWARE|SECURITY|SAM)$",  # system hives
    r"\.evtx$",                                 # event logs
    r"ConsoleHost_history\.txt$",               # PowerShell history
    r"[/\\]History$", r"places\.sqlite$", r"\.sqlite$",  # browser/app DBs
    r"\$MFT$", r"\$UsnJrnl",                     # filesystem metadata
    r"\.lnk$", r"[/\\]Recent[/\\]",             # shellbag / recent-docs
)


@dataclass
class IstatRecord:
    """The subset of ``istat`` output that wipe classification needs."""
    inode: str = ""
    allocated: bool = True
    non_resident: bool | None = None
    data_size: int | None = None
    init_size: int | None = None
    names: list[str] = field(default_factory=list)


@dataclass
class WipeVerdict:
    """Classification of one file's content-state.

    ``status`` ∈ {wiped_in_place, deleted_recoverable, empty_stub, intact}.
    Only the first two are anti-forensic findings; empty_stub is the explicit
    benign verdict that prevents a never-written cache from looking wiped."""
    relpath: str
    inode: str
    status: str
    confidence: str                       # high | medium | low | insufficient
    reason: str
    init_size: int | None = None
    data_size: int | None = None
    allocated: bool = True
    content_zero: bool | None = None
    hypotheses: list[str] = field(default_factory=list)
    attack_techniques: list[tuple[str, str]] = field(default_factory=list)

    @property
    def is_wipe(self) -> bool:
        return self.status in ("wiped_in_place", "deleted_recoverable")


# ---------------------------------------------------------------------------
# Pure parsing + classification (unit-tested; no subprocess / filesystem)
# ---------------------------------------------------------------------------

_ALLOC_RE = re.compile(r"^(Not\s+)?Allocated File\b", re.M | re.I)
_NAME_RE = re.compile(r"^\s*Name:\s*(.+?)\s*$", re.M)
# $DATA attribute line, e.g.:
#   Type: $DATA (128-4)   Name: N/A   Non-Resident   size: 33497088  init_size: 24973312
_DATA_RE = re.compile(
    r"^Type:\s*\$DATA\b.*?(?P<res>Resident|Non-Resident)"
    r"(?:.*?\bsize:\s*(?P<size>\d+))?"
    r"(?:.*?\binit_size:\s*(?P<init>\d+))?",
    re.M | re.I)


def parse_istat(text: str) -> IstatRecord:
    """Parse Sleuth Kit ``istat`` output into an IstatRecord. Tolerant of
    missing fields — anything absent stays None. Picks the *largest* $DATA
    stream (the unnamed default $DATA dominates ADS in size) so an attached
    Zone.Identifier doesn't shadow the real content stream."""
    rec = IstatRecord()
    alloc_m = _ALLOC_RE.search(text)
    if alloc_m:
        rec.allocated = alloc_m.group(1) is None  # "Not " prefix ⇒ deleted

    best_size = -1
    for m in _DATA_RE.finditer(text):
        size = int(m.group("size")) if m.group("size") else None
        init = int(m.group("init")) if m.group("init") else None
        non_res = m.group("res").lower() == "non-resident"
        rank = size if size is not None else 0
        if rank > best_size:
            best_size = rank
            rec.data_size = size
            rec.init_size = init
            rec.non_resident = non_res

    # De-dupe names while preserving order ($FILE_NAME often lists the short
    # 8.3 name plus the long name for the same entry).
    seen: set[str] = set()
    for nm in _NAME_RE.findall(text):
        if nm not in seen and nm.upper() not in ("N/A",):
            seen.add(nm)
            rec.names.append(nm)
    return rec


def is_high_value(relpath: str) -> bool:
    """True when *relpath* matches one of the HIGH_VALUE_TARGETS patterns."""
    return any(re.search(p, relpath, re.I) for p in HIGH_VALUE_TARGETS)


def target_priority(relpath: str) -> int:
    """Rank a high-value path by its position in HIGH_VALUE_TARGETS (which is
    ordered most-important first: mail caches → registry → logs → … → browser
    DBs / shellbags). Lower = more important; non-matches sort last. Callers
    that cap how many files they metadata-probe sort by this so a wiped OST is
    never crowded out by hundreds of .sqlite / .lnk rows."""
    for i, p in enumerate(HIGH_VALUE_TARGETS):
        if re.search(p, relpath, re.I):
            return i
    return len(HIGH_VALUE_TARGETS)


def classify(rec: IstatRecord, content_zero: bool | None,
             relpath: str = "", inode: str = "") -> WipeVerdict:
    """Deterministically classify a file's content state.

    ``content_zero`` is the result of reading the file's bytes (True = every
    byte read was zero; False = real data present; None = not read / unknown).

    The four outcomes:

    * **wiped_in_place** (high) — allocated, non-resident, init_size ≥
      MIN_WIPED_INIT_BYTES, content all-zero. The file declares it once held
      data; that data is now zero ⇒ targeted overwrite.
    * **deleted_recoverable** (medium) — not allocated but still carries a
      data_size / non-resident runs ⇒ classic delete whose clusters may be
      carvable until reuse.
    * **empty_stub** (insufficient) — content zero but init_size is 0/None ⇒
      never-written preallocation, NOT a wipe (the false-positive guard).
    * **intact** (insufficient) — real data present or nothing actionable.
    """
    inode = inode or rec.inode
    base = dict(relpath=relpath, inode=inode, init_size=rec.init_size,
                data_size=rec.data_size, allocated=rec.allocated,
                content_zero=content_zero)

    wiped_hyps = ["H_ANTI_FORENSICS", "H_INSIDER_DEVICE_DESTRUCTION"]
    wiped_att = [("T1070.004", "Indicator Removal: File Deletion"),
                 ("T1485", "Data Destruction"),
                 ("T1070", "Indicator Removal")]

    if (rec.allocated and rec.non_resident and content_zero is True
            and rec.init_size and rec.init_size >= MIN_WIPED_INIT_BYTES):
        return WipeVerdict(
            status="wiped_in_place", confidence="high",
            reason=(f"allocated non-resident file with init_size="
                    f"{rec.init_size} but all-zero content — content destroyed "
                    f"in place (metadata fossil proves data once existed)"),
            hypotheses=wiped_hyps, attack_techniques=wiped_att, **base)

    if not rec.allocated and (rec.data_size or rec.non_resident):
        return WipeVerdict(
            status="deleted_recoverable", confidence="medium",
            reason=("unallocated file still carrying $DATA runs — deleted; "
                    "clusters may be carvable until overwritten"),
            hypotheses=["H_ANTI_FORENSICS"],
            attack_techniques=[("T1070.004", "Indicator Removal: File Deletion")],
            **base)

    if content_zero is True and not rec.init_size:
        return WipeVerdict(
            status="empty_stub", confidence="insufficient",
            reason=("all-zero content but init_size=0 — never-written "
                    "preallocation / stub, not a wipe"),
            **base)

    return WipeVerdict(
        status="intact", confidence="insufficient",
        reason="content present or nothing actionable", **base)


# ---------------------------------------------------------------------------
# Evidence helper
# ---------------------------------------------------------------------------

def verdict_as_evidence(verdict: WipeVerdict, image: Path,
                        istat_path: Path | None = None) -> EvidenceItem:
    """Build an EvidenceItem for a wipe verdict. ``output_sha256`` is the hash
    of the istat output when supplied (the metadata that grounds the claim),
    else a stable digest of the verdict facts so the contract is satisfiable
    even for pure-metadata findings."""
    if istat_path is not None and Path(istat_path).is_file():
        sha = hashlib.sha256(Path(istat_path).read_bytes()).hexdigest()
        out_path = str(istat_path)
    else:
        payload = f"{verdict.inode}|{verdict.status}|{verdict.init_size}".encode()
        sha = hashlib.sha256(payload).hexdigest()
        out_path = str(image)
    return EvidenceItem(
        tool="el.wipe_detect", version="0.1.0",
        command=f"istat {Path(image).name} {verdict.inode}",
        output_sha256=sha, output_path=out_path,
        extracted_facts={
            "relpath": verdict.relpath,
            "inode": verdict.inode,
            "status": verdict.status,
            "init_size": verdict.init_size,
            "data_size": verdict.data_size,
            "allocated": verdict.allocated,
            "content_zero": verdict.content_zero,
            "reason": verdict.reason,
        },
    )


__all__ = [
    "MIN_WIPED_INIT_BYTES",
    "HIGH_VALUE_TARGETS",
    "IstatRecord",
    "WipeVerdict",
    "parse_istat",
    "is_high_value",
    "target_priority",
    "classify",
    "verdict_as_evidence",
]
