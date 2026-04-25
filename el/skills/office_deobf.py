"""Skill: Office document macro + embedded-object deobfuscation.

Wraps `oletools` (pip-installed, pure Python). Three analysis paths:

  olevba(path)      Scan OLE/OOXML for VBA macros → decoded source +
                    suspicious-keyword matches (AutoOpen, Shell,
                    WScript, URLDownloadToFile, etc.). Returns the
                    mraptor verdict when available.

  rtfobj(path)      Scan RTF for embedded OLE objects — CVE-2017-11882
                    Equation Editor exploits, embedded OOXML droppers.

  oleid(path)       Fast classifier — file type, encryption flag,
                    macro presence summary.

Every function is silent on error + returns None for non-Office inputs.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


_OFFICE_SUFFIXES = frozenset({
    ".doc", ".docx", ".docm", ".dot", ".dotm",
    ".xls", ".xlsx", ".xlsm", ".xlsb", ".xlt", ".xltm",
    ".ppt", ".pptx", ".pptm", ".pps", ".ppsm",
    ".rtf", ".vsd", ".vsdm",
    ".mht", ".mhtml", ".odt", ".ods", ".odp",
})


@dataclass
class MacroAnalysis:
    path: str
    file_type: str = ""          # "OLE" / "OOXML" / "RTF" / "unknown"
    has_macros: bool = False
    macro_count: int = 0
    autoexec: list[str] = field(default_factory=list)
    suspicious: list[tuple[str, str]] = field(default_factory=list)
    iocs: list[tuple[str, str]] = field(default_factory=list)
    mraptor_flags: list[str] = field(default_factory=list)
    decoded_macros_sample: str = ""
    error: str = ""


@dataclass
class RtfAnalysis:
    path: str
    object_count: int = 0
    objects: list[dict] = field(default_factory=list)
    error: str = ""


def is_office_candidate(path: str | Path) -> bool:
    p = Path(path)
    return p.is_file() and p.suffix.lower() in _OFFICE_SUFFIXES


def _olevba_bin() -> str | None:
    """Prefer the venv's olevba; fall back to PATH."""
    return (shutil.which("olevba")
            or shutil.which("/opt/EL/.venv/bin/olevba"))


def _rtfobj_bin() -> str | None:
    return (shutil.which("rtfobj")
            or shutil.which("/opt/EL/.venv/bin/rtfobj"))


def analyze_macros(path: str | Path, timeout: int = 60) -> MacroAnalysis | None:
    """Run olevba --json on an Office file. Returns MacroAnalysis or
    None on non-Office / parse failure."""
    p = Path(path)
    if not is_office_candidate(p):
        return None
    exe = _olevba_bin()
    if not exe:
        return None
    try:
        r = subprocess.run(
            [exe, "--json", str(p)],
            capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return MacroAnalysis(path=str(p), error="olevba timeout")
    if r.returncode not in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20):
        # olevba uses non-zero exit codes to encode the verdict
        # (1 = macros, 2 = suspicious, etc.); treat <30 as normal
        # completion. Hard failures (>=30 or signal-kill codes) are
        # errors.
        return MacroAnalysis(
            path=str(p),
            error=f"olevba rc={r.returncode}: "
                   f"{(r.stderr or b'').decode(errors='replace')[:200]}")

    # olevba --json emits a JSON array of dicts (file header, per-VBA-
    # stream entries, analysis results). Parse defensively.
    try:
        payload = json.loads((r.stdout or b"").decode("utf-8",
                                                       errors="replace"))
    except json.JSONDecodeError:
        return MacroAnalysis(path=str(p), error="non-JSON olevba output")

    if not isinstance(payload, list):
        return MacroAnalysis(path=str(p),
                              error="unexpected olevba shape")

    out = MacroAnalysis(path=str(p))
    macro_codes: list[str] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        t = item.get("type")
        if t == "MetaInformation":
            out.file_type = str(item.get("container", ""))
        elif t == "VBA":
            out.has_macros = True
            out.macro_count += 1
            code = item.get("vba_code") or ""
            if code:
                macro_codes.append(code)
        elif t == "analysis":
            # analysis blocks carry `analysis.result` list with (type,
            # keyword, description) triples
            for a in item.get("analysis", []):
                if not isinstance(a, dict):
                    continue
                atype = str(a.get("type", "")).lower()
                kw = str(a.get("keyword", ""))
                desc = str(a.get("description", ""))
                if atype == "autoexec":
                    out.autoexec.append(kw)
                elif atype == "suspicious":
                    out.suspicious.append((kw, desc))
                elif atype == "iocs":
                    out.iocs.append((kw, desc))
        elif t == "MRAPTOR":
            flags = item.get("flags") or ""
            out.mraptor_flags = [f for f in str(flags)
                                  if f not in (" ", "-")]

    if macro_codes:
        out.decoded_macros_sample = ("\n\n---\n\n".join(macro_codes))[:4000]
    return out


def analyze_rtf_objects(path: str | Path,
                         timeout: int = 60) -> RtfAnalysis | None:
    """Run rtfobj on an RTF file. Returns RtfAnalysis or None on
    non-RTF / parse failure."""
    p = Path(path)
    if not p.is_file() or p.suffix.lower() != ".rtf":
        return None
    exe = _rtfobj_bin()
    if not exe:
        return None
    try:
        r = subprocess.run(
            [exe, "--json", str(p)],
            capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return RtfAnalysis(path=str(p), error="rtfobj timeout")

    # rtfobj --json emits a JSON array; when no objects are embedded
    # it exits 0 with just the meta-info entries.
    try:
        payload = json.loads((r.stdout or b"").decode("utf-8",
                                                       errors="replace"))
    except json.JSONDecodeError:
        return RtfAnalysis(path=str(p), error="non-JSON rtfobj output")

    if not isinstance(payload, list):
        return RtfAnalysis(path=str(p), error="unexpected rtfobj shape")

    out = RtfAnalysis(path=str(p))
    for item in payload:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "OLE object":
            out.object_count += 1
            out.objects.append({
                "index": item.get("index"),
                "format_id": item.get("format_id"),
                "class_name": item.get("class_name"),
                "size": item.get("size"),
                "filename": item.get("filename"),
                "is_exploit": item.get("is_exploit", False),
                "is_ole_package": item.get("is_ole_package", False),
                "ole_package_filename": item.get("ole_package_filename"),
            })
    return out


def iter_office_candidates(roots: list[Path],
                            max_files: int = 500) -> list[Path]:
    """Walk directories and return every Office-suffixed file."""
    out: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if len(out) >= max_files:
                break
            if not p.is_file():
                continue
            if p.suffix.lower() not in _OFFICE_SUFFIXES:
                continue
            key = str(p.resolve())
            if key in seen:
                continue
            try:
                sz = p.stat().st_size
            except OSError:
                continue
            if sz < 1024 or sz > 100 * 1024 * 1024:
                continue
            seen.add(key)
            out.append(p)
    return out


@dataclass
class PcodeAnalysis:
    """Output of `pcodedmp`. P-code is the compiled VBA bytecode that
    sits next to the source in an Office doc — attackers sometimes
    leave the source benign while the actual malicious logic lives in
    p-code that survives source-stripping. pcodedmp disassembles it."""
    path: str
    available: bool = False             # pcodedmp installed?
    rc: int = 0
    has_pcode: bool = False
    line_count: int = 0
    raw_path: str = ""
    error: str = ""


@dataclass
class XlmAnalysis:
    """Output of XLMMacroDeobfuscator. Excel 4.0 macros (XLM) predate
    VBA and survive on a parallel attack surface."""
    path: str
    available: bool = False
    rc: int = 0
    has_xlm: bool = False
    decoded_lines: int = 0
    raw_path: str = ""
    error: str = ""


@dataclass
class PdfAnalysis:
    """Output of pdf-parser.py (Didier Stevens). PDF is a container —
    JS, embedded OLE, OpenAction triggers, Launch actions, embedded
    files all live inside indirect objects."""
    path: str
    available: bool = False
    rc: int = 0
    object_count: int = 0
    suspicious_keywords: list[str] = field(default_factory=list)
    raw_path: str = ""
    error: str = ""


def _pcodedmp_bin() -> str | None:
    return (shutil.which("pcodedmp")
            or shutil.which("/opt/EL/.venv/bin/pcodedmp"))


def _xlmdeobf_bin() -> str | None:
    return (shutil.which("xlmdeobfuscator")
            or shutil.which("/opt/EL/.venv/bin/xlmdeobfuscator"))


def _pdfparser_bin() -> str | None:
    """Didier Stevens' `pdf-parser.py`. Various install paths across
    SIFT versions."""
    for name in ("pdf-parser", "pdf-parser.py"):
        p = shutil.which(name)
        if p:
            return p
    for guess in ("/opt/EL/.venv/bin/pdf-parser.py",
                  "/usr/local/bin/pdf-parser.py",
                  "/opt/didierstevens/pdf-parser.py"):
        if Path(guess).is_file():
            return guess
    return None


def analyze_pcode(path: str | Path, *,
                   out_dir: Path | None = None,
                   timeout: int = 60) -> PcodeAnalysis:
    """Disassemble VBA p-code via `pcodedmp <path>`. Returns a
    PcodeAnalysis even on failure / unavailable so callers don't
    have to None-check."""
    p = Path(path)
    exe = _pcodedmp_bin()
    if exe is None:
        return PcodeAnalysis(path=str(p), available=False,
                              error="pcodedmp not on PATH")
    out = PcodeAnalysis(path=str(p), available=True)
    try:
        r = subprocess.run([exe, str(p)], check=False, capture_output=True,
                            text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        out.error = f"pcodedmp timeout after {timeout}s"
        return out
    out.rc = r.returncode
    if out_dir is not None:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out.raw_path = str(out_dir / f"{p.name}.pcode.txt")
        try:
            Path(out.raw_path).write_text(r.stdout or "")
        except OSError:
            pass
    text = r.stdout or ""
    out.line_count = sum(1 for _ in text.splitlines())
    out.has_pcode = out.line_count > 8 and "Line " in text
    if out.rc != 0 and not out.error:
        out.error = (r.stderr or "").strip()[-200:]
    return out


def analyze_xlm(path: str | Path, *,
                 out_dir: Path | None = None,
                 timeout: int = 120) -> XlmAnalysis:
    """Decode Excel-4 (XLM) macros via xlmdeobfuscator."""
    p = Path(path)
    exe = _xlmdeobf_bin()
    if exe is None:
        return XlmAnalysis(path=str(p), available=False,
                            error="xlmdeobfuscator not on PATH")
    out = XlmAnalysis(path=str(p), available=True)
    try:
        r = subprocess.run([exe, "-f", str(p), "--no-indent"],
                            check=False, capture_output=True,
                            text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        out.error = f"xlmdeobfuscator timeout after {timeout}s"
        return out
    out.rc = r.returncode
    if out_dir is not None:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out.raw_path = str(out_dir / f"{p.name}.xlm.txt")
        try:
            Path(out.raw_path).write_text(r.stdout or "")
        except OSError:
            pass
    text = r.stdout or ""
    out.decoded_lines = sum(1 for line in text.splitlines()
                             if line.startswith("CELL:"))
    out.has_xlm = out.decoded_lines > 0
    if out.rc != 0 and not out.error:
        out.error = (r.stderr or "").strip()[-200:]
    return out


_PDF_SUSPECT_KEYWORDS = (
    "/JavaScript", "/JS", "/AA", "/OpenAction", "/Launch",
    "/SubmitForm", "/RichMedia", "/Action", "/EmbeddedFile",
    "/XFA", "/JBIG2Decode",
)


def analyze_pdf(path: str | Path, *,
                 out_dir: Path | None = None,
                 timeout: int = 120) -> PdfAnalysis:
    """Enumerate PDF indirect objects via `pdf-parser.py --stats`.
    Surfaces suspicious-keyword tokens (/JavaScript, /OpenAction,
    /Launch, /EmbeddedFile, …) without trying to dump object
    content — that's a follow-up for the malware_triage chain."""
    p = Path(path)
    exe = _pdfparser_bin()
    if exe is None:
        return PdfAnalysis(path=str(p), available=False,
                            error="pdf-parser not on PATH")
    out = PdfAnalysis(path=str(p), available=True)
    try:
        r = subprocess.run([exe, "--stats", str(p)],
                            check=False, capture_output=True,
                            text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        out.error = f"pdf-parser timeout after {timeout}s"
        return out
    out.rc = r.returncode
    if out_dir is not None:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out.raw_path = str(out_dir / f"{p.name}.pdf-stats.txt")
        try:
            Path(out.raw_path).write_text(r.stdout or "")
        except OSError:
            pass
    text = r.stdout or ""
    out.object_count = text.count("obj ")
    out.suspicious_keywords = sorted({
        kw for kw in _PDF_SUSPECT_KEYWORDS if kw in text})
    if out.rc != 0 and not out.error:
        out.error = (r.stderr or "").strip()[-200:]
    return out


__all__ = [
    "MacroAnalysis", "RtfAnalysis",
    "PcodeAnalysis", "XlmAnalysis", "PdfAnalysis",
    "is_office_candidate", "iter_office_candidates",
    "analyze_macros", "analyze_rtf_objects",
    "analyze_pcode", "analyze_xlm", "analyze_pdf",
]
