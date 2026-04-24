"""Skill: convert VM disk image formats (VMDK, VHD, VHDX) to flat raw.

The rest of EL's disk pipeline (mmls → fls-per-partition → mactime →
extract_windows_artifacts) expects a raw byte stream. VMware, Hyper-V,
and VirtualBox exports aren't raw — they're wrapped in VMDK (optionally
sparse), VHD (dynamic or fixed), or VHDX (with per-sector metadata).
We convert to raw via `qemu-img convert` and run the existing pipeline
against the flat output.

Read-only on the source. Output goes under `<case_dir>/raw/converted.img`.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from el.schemas.finding import EvidenceItem


class DiskConvertError(RuntimeError):
    """Raised on any failure during VM-disk → raw conversion."""


@dataclass
class ConvertResult:
    source: Path
    source_kind: str
    raw_path: Path
    stdout_path: Path
    stderr_path: Path
    qemu_img_version: str

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        import hashlib
        # Hash the stderr log (cheap, stable, not the multi-GB raw image)
        try:
            sha = hashlib.sha256(self.stderr_path.read_bytes()).hexdigest()
        except OSError:
            sha = ""
        extracted = {
            "source_kind": self.source_kind,
            "source_path": str(self.source),
            "raw_path": str(self.raw_path),
            "qemu_img_version": self.qemu_img_version,
        }
        if facts:
            extracted.update(facts)
        return EvidenceItem(
            tool="qemu-img", version=self.qemu_img_version,
            command=f"qemu-img convert -O raw {self.source} {self.raw_path}",
            output_sha256=sha, output_path=str(self.stderr_path),
            extracted_facts=extracted,
        )


def qemu_img_available() -> tuple[bool, str]:
    """Return (available, version_string). Empty string on not-found."""
    path = shutil.which("qemu-img")
    if not path:
        return (False, "")
    try:
        res = subprocess.run(
            [path, "--version"], check=False, capture_output=True,
            text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return (False, "")
    # qemu-img --version first line: "qemu-img version X.Y.Z (qemu-X.Y.Z-*)"
    line = (res.stdout or "").splitlines()[0] if res.stdout else ""
    # Extract just the X.Y.Z token
    version = ""
    for tok in line.split():
        if tok and tok[0].isdigit():
            version = tok
            break
    return (True, version or line)


def convert_to_raw(source: Path, source_kind: str, out_dir: Path,
                   timeout: int = 3600) -> ConvertResult:
    """Run `qemu-img convert -O raw <source> <out_dir>/converted.img`.

    Parameters
    ----------
    source : Path
        VMDK / VHD / VHDX file.
    source_kind : str
        The triage evidence_kind string — goes into the evidence record
        so the analyst can see what the input was identified as.
    out_dir : Path
        Destination directory. Created if missing.

    Raises
    ------
    DiskConvertError
        If qemu-img isn't on PATH, the invocation fails, or the output
        file never materialises.
    """
    available, version = qemu_img_available()
    if not available:
        raise DiskConvertError(
            "qemu-img not available — install qemu-utils to ingest "
            "VMDK / VHD / VHDX images, or pre-convert with: "
            f"qemu-img convert -O raw {source} <out.img>"
        )

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "converted.img"
    stdout_path = out_dir / "qemu-img.stdout"
    stderr_path = out_dir / "qemu-img.stderr"

    cmd = ["qemu-img", "convert", "-O", "raw", str(source), str(raw_path)]
    try:
        res = subprocess.run(
            cmd, check=False, capture_output=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        stderr_path.write_bytes(
            (e.stderr or b"") + b"\n[el] qemu-img timed out"
        )
        raise DiskConvertError(
            f"qemu-img convert timed out after {timeout}s"
        ) from e
    except OSError as e:
        raise DiskConvertError(f"qemu-img invocation failed: {e}") from e

    stdout_path.write_bytes(res.stdout or b"")
    stderr_path.write_bytes(res.stderr or b"")

    if res.returncode != 0 or not raw_path.exists():
        tail = (res.stderr or b"").decode("utf-8", errors="replace").strip()[-400:]
        raise DiskConvertError(
            f"qemu-img convert rc={res.returncode}: {tail or 'no stderr'}"
        )

    return ConvertResult(
        source=Path(source), source_kind=source_kind,
        raw_path=raw_path, stdout_path=stdout_path, stderr_path=stderr_path,
        qemu_img_version=version,
    )


__all__ = [
    "ConvertResult", "DiskConvertError",
    "convert_to_raw", "qemu_img_available",
]
