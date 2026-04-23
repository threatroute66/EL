"""Skill: PE structural deep-dive via `pefile`.

Complements capa (which is rule-based ATT&CK matching) with three
structural-analysis outputs that survive packing and obfuscation:

  1. **imphash** — MD5 of (dll, function) pairs in the import table.
     Stable across recompiles + minor modifications; classic
     malware-family attribution IOC.

  2. **Rich Header hash** — fingerprint of the Microsoft linker
     tool-chain that built the PE. Not present on rustc / MinGW /
     packed binaries, so absence is itself a signal.

  3. **Per-section entropy** — Shannon entropy of each section's
     raw data. Values near 8.0 indicate compressed / encrypted
     content — characteristic of UPX-style packers and of encrypted
     payload sections in stagers.

  4. **Sensitive-import groups** — pre-defined API sets whose
     co-occurrence in a PE's import table is high-signal for
     specific ATT&CK techniques (T1003 credential access, T1055
     injection, T1027 obfuscation).

All outputs are deterministic and reproducible — same bytes in, same
result out. Suitable for the knowledge DB's cross-case IOC column
(imphash) and for ATT&CK-technique attribution.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PeSection:
    name: str
    vaddr: int
    raw_size: int
    virt_size: int
    entropy: float
    characteristics: int


@dataclass
class PeAnalysis:
    path: str
    sha256: str
    file_size: int
    machine: str                    # "i386" / "x64" / "arm64" / other
    subsystem: str                  # "gui" / "console" / "native" / other
    imphash: str                    # may be "" when no imports
    rich_header_hash: str           # "" when absent
    sections: list[PeSection] = field(default_factory=list)
    imports: list[tuple[str, str]] = field(default_factory=list)
    # Derived signals
    max_section_entropy: float = 0.0
    suspected_packed: bool = False
    import_groups_matched: list[str] = field(default_factory=list)
    # Raw parser error (when analyze_pe returns None instead, this
    # stays unused; the analyzer uses `analyze_pe_or_none` pattern).
    error: str = ""


# Sensitive-import groups. Each entry is (group_name, [function_sets]).
# A group matches when ANY of its function_sets has ALL members present
# in the PE's import table (function-name match; case-insensitive;
# dll-agnostic because attackers swap dlls via forwarders).
_SENSITIVE_IMPORT_GROUPS: dict[str, list[set[str]]] = {
    "credential_dump": [
        {"OpenProcess", "ReadProcessMemory"},
        {"LsaEnumerateLogonSessions", "LsaGetLogonSessionData"},
        {"MiniDumpWriteDump"},
    ],
    "process_injection": [
        {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
        {"NtUnmapViewOfSection", "WriteProcessMemory"},      # hollowing
        {"NtQueueApcThread"},                                # APC injection
        {"SetWindowsHookEx"},                                # hook injection
    ],
    "shellcode_runtime": [
        {"VirtualAlloc", "VirtualProtect"},
    ],
    "anti_debug": [
        {"IsDebuggerPresent", "CheckRemoteDebuggerPresent"},
        {"NtQueryInformationProcess"},
    ],
    "lateral_movement": [
        {"WNetAddConnection2"},
        {"OpenSCManager", "CreateService"},
        {"DuplicateHandle", "ImpersonateLoggedOnUser"},
    ],
    "persistence_registry": [
        {"RegCreateKeyEx", "RegSetValueEx"},
    ],
}


_IMPORT_GROUP_TO_ATTACK: dict[str, list[tuple[str, str]]] = {
    "credential_dump":    [("T1003", "OS Credential Dumping"),
                            ("T1003.001", "OS Credential Dumping: LSASS Memory")],
    "process_injection":  [("T1055", "Process Injection"),
                            ("T1055.012", "Process Injection: Process Hollowing")],
    "shellcode_runtime":  [("T1055", "Process Injection")],
    "anti_debug":         [("T1622", "Debugger Evasion")],
    "lateral_movement":   [("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
                            ("T1543.003", "Windows Service")],
    "persistence_registry": [("T1547.001", "Registry Run Keys / Startup Folder")],
}


def _machine_name(code: int) -> str:
    return {0x014c: "i386", 0x8664: "x64",
            0xaa64: "arm64", 0x01c0: "arm"}.get(code, f"0x{code:04x}")


def _subsystem_name(code: int) -> str:
    return {1: "native", 2: "gui", 3: "console",
            7: "posix", 9: "wince"}.get(code, f"subsys-{code}")


def _shannon_entropy(data: bytes) -> float:
    """Classic Shannon entropy in bits per byte (0 — 8)."""
    if not data:
        return 0.0
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    n = len(data)
    h = 0.0
    for c in hist:
        if c == 0:
            continue
        p = c / n
        h -= p * math.log2(p)
    return h


def _rich_header_hash(pe) -> str:
    """Return MD5 of the Rich Header clear bytes, or '' when absent."""
    try:
        rich = pe.parse_rich_header()
    except Exception:
        return ""
    if not rich:
        return ""
    raw = rich.get("clear_data") or b""
    if not raw:
        return ""
    return hashlib.md5(raw).hexdigest()


def analyze_pe(path: str | Path) -> PeAnalysis | None:
    """Return a PeAnalysis for a parseable PE, None otherwise. Does
    not raise — callers iterate over bulk output trees where many
    files are random bytes that happen to start with MZ."""
    try:
        import pefile
    except ImportError:
        return None
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError:
        return None
    sha = hashlib.sha256(data).hexdigest()
    size = len(data)
    if size < 64 or not data.startswith(b"MZ"):
        return None
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as e:
        return None
    imphash = ""
    imports: list[tuple[str, str]] = []
    try:
        imphash = pe.get_imphash() or ""
    except Exception:
        pass
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for imp in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = (imp.dll or b"").decode("utf-8", errors="replace")
            except Exception:
                dll_name = ""
            for sym in imp.imports or []:
                fn_name = ""
                if sym.name:
                    try:
                        fn_name = sym.name.decode("utf-8", errors="replace")
                    except Exception:
                        pass
                if fn_name:
                    imports.append((dll_name, fn_name))

    sections: list[PeSection] = []
    max_e = 0.0
    for s in pe.sections:
        try:
            sd = s.get_data()
        except Exception:
            sd = b""
        e = _shannon_entropy(sd)
        if e > max_e:
            max_e = e
        try:
            sname = (s.Name or b"").rstrip(b"\x00").decode(
                "utf-8", errors="replace")
        except Exception:
            sname = ""
        sections.append(PeSection(
            name=sname,
            vaddr=int(getattr(s, "VirtualAddress", 0) or 0),
            raw_size=int(getattr(s, "SizeOfRawData", 0) or 0),
            virt_size=int(getattr(s, "Misc_VirtualSize", 0) or 0),
            entropy=round(e, 3),
            characteristics=int(getattr(s, "Characteristics", 0) or 0),
        ))

    import_fn_set = {fn for _d, fn in imports}
    matched_groups: list[str] = []
    for group, needed_sets in _SENSITIVE_IMPORT_GROUPS.items():
        for needed in needed_sets:
            if needed.issubset(import_fn_set):
                matched_groups.append(group)
                break

    # Packed heuristic: entropy > 7.0 on an executable section (code
    # or data-exec flagged). Pure-data high entropy (resources) is
    # common and not a signal.
    packed = False
    for s in sections:
        if s.entropy < 7.0:
            continue
        # Characteristic 0x20000000 = IMAGE_SCN_MEM_EXECUTE, 0x60000000
        # covers code + exec. Any EXEC + high-entropy → packed.
        if s.characteristics & 0x20000000:
            packed = True
            break

    return PeAnalysis(
        path=str(p), sha256=sha, file_size=size,
        machine=_machine_name(pe.FILE_HEADER.Machine),
        subsystem=_subsystem_name(pe.OPTIONAL_HEADER.Subsystem),
        imphash=imphash,
        rich_header_hash=_rich_header_hash(pe),
        sections=sections,
        imports=imports,
        max_section_entropy=round(max_e, 3),
        suspected_packed=packed,
        import_groups_matched=matched_groups,
    )


def attack_techniques_for_groups(
    groups: list[str],
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for g in groups:
        for tid, name in _IMPORT_GROUP_TO_ATTACK.get(g, []):
            if tid in seen:
                continue
            out.append((tid, name))
            seen.add(tid)
    return out


def iter_pe_candidates(roots: list[Path]) -> list[Path]:
    """Walk analysis-tree roots and return every file that looks
    like it could be a PE (starts with 'MZ'). Single-pass; does not
    descend hidden dirs or huge artifact blobs like EvtxECmd CSVs."""
    out: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            key = str(p.resolve())
            if key in seen:
                continue
            seen.add(key)
            # Skip obvious non-PE + huge files
            suf = p.suffix.lower()
            if suf in (".csv", ".txt", ".json", ".xml", ".log",
                       ".md", ".html", ".htm"):
                continue
            try:
                sz = p.stat().st_size
            except OSError:
                continue
            if sz < 64 or sz > 50 * 1024 * 1024:
                continue
            try:
                with p.open("rb") as f:
                    head = f.read(2)
            except OSError:
                continue
            if head == b"MZ":
                out.append(p)
    return out


__all__ = [
    "PeSection", "PeAnalysis",
    "analyze_pe", "attack_techniques_for_groups",
    "iter_pe_candidates",
]
