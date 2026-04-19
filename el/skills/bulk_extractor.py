"""Skill: bulk_extractor — feature carving from disk / unallocated space.

bulk_extractor scans bytes for features (emails, URLs, domains, IPs,
credit-card numbers, BTC addresses, telephone numbers, JSON blobs) and
writes one CSV per feature class to the output dir. Operates on raw
disk images, mounted filesystems, individual files, or unallocated
extracts. Recommended by sleuthkit SKILL: `bulk_extractor -o out/ ewf1`.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from el.schemas.finding import EvidenceItem


class BulkExtractorError(RuntimeError):
    pass


@dataclass
class BulkRun:
    target: Path
    out_dir: Path
    rc: int
    feature_files: list[Path]
    command: list[str]

    def features(self) -> dict[str, int]:
        """Return {feature_class: row_count} for each non-empty CSV."""
        out: dict[str, int] = {}
        for p in self.feature_files:
            if p.suffix != ".txt":
                continue
            name = p.stem  # email, url, domain, ip, etc.
            try:
                # bulk_extractor feature files have 4 header lines + 1 row per hit
                with p.open(errors="ignore") as f:
                    n = sum(1 for line in f if line and not line.startswith("#"))
            except Exception:
                n = 0
            if n:
                out[name] = n
        return out

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        h = hashlib.sha256()
        for p in sorted(self.feature_files):
            try:
                h.update(p.read_bytes()[:1024 * 1024])
            except Exception:
                continue
        merged = {"rc": self.rc, "feature_files": [p.name for p in self.feature_files[:30]],
                  "feature_counts": self.features()}
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool="bulk_extractor", version=_version(),
            command=" ".join(self.command),
            output_sha256=h.hexdigest() or "0" * 64,
            output_path=str(self.out_dir),
            extracted_facts=merged,
        )


def _bin() -> str:
    p = shutil.which("bulk_extractor")
    if not p:
        raise BulkExtractorError("bulk_extractor not on PATH")
    return p


def _version() -> str:
    try:
        r = subprocess.run([_bin(), "-V"], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr).splitlines()[0].strip()
    except Exception:
        return "present"


# Valid bulk_extractor scanner names (from `bulk_extractor -h`). Feature
# categories in output files (url.txt, domain.txt, ip.txt, ccn.txt, …) are
# produced BY scanners — they are NOT scanner names themselves. Passing a
# feature-category string to `-e` makes bulk_extractor exit with
# "Invalid scanner name" before producing any output, so we validate.
VALID_SCANNERS: frozenset[str] = frozenset({
    # default-on
    "accts", "aes", "base64", "elf", "email", "evtx", "exif", "find",
    "gps", "gzip", "hiberfile", "httplogs", "json", "kml", "msxml", "net",
    "ntfsindx", "ntfslogfile", "ntfsmft", "ntfsusn", "pdf", "rar", "sqlite",
    "utmp", "vcard", "windirs", "winlnk", "winpe", "winprefetch", "zip",
    # default-off (must be explicitly enabled)
    "base16", "facebook", "outlook", "sceadan", "wordlist", "xor",
})


def scan(target: Path, out_dir: Path,
         enable_scanners: list[str] | None = None,
         disable_scanners: list[str] | None = None,
         threads: int = 4, timeout: int = 7200) -> BulkRun:
    """Run bulk_extractor against target.

    `enable_scanners` forwards to `-e <name>` (enables a default-off scanner
    or explicitly enables an already-on one). `disable_scanners` forwards to
    `-x <name>`. Names are validated against VALID_SCANNERS — if you want a
    particular feature category (url, domain, ip, ccn), enable the scanner
    that PRODUCES it (email, net, accts) rather than the category name.

    With both args empty, bulk_extractor runs its full default scanner set,
    which already covers the common DFIR haul (email/domain/url, net/ip,
    accts/ccn/pii, httplogs, evtx, winprefetch, winlnk, winpe, exif, pdf,
    json, sqlite, ntfs*, zip/gzip/rar). Default-off scanners worth enabling
    explicitly: `outlook` (PST carving), `base16`/`xor`/`wordlist` (special
    cases).

    The output dir must be empty (bulk_extractor refuses to overwrite).
    """
    target = Path(target)
    if not target.exists():
        raise BulkExtractorError(f"target not found: {target}")
    out_dir = Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise BulkExtractorError(f"output dir not empty: {out_dir} "
                                 "(bulk_extractor refuses to overwrite)")
    out_dir.mkdir(parents=True, exist_ok=True)

    for name in (enable_scanners or []):
        if name not in VALID_SCANNERS:
            raise BulkExtractorError(
                f"invalid bulk_extractor scanner name: {name!r}. "
                f"Valid scanners: {sorted(VALID_SCANNERS)}. "
                "Feature categories like 'url'/'domain'/'ip'/'ccn' are NOT "
                "scanner names — enable the scanner that emits them "
                "(email for url/domain, net for ip, accts for ccn)."
            )
    for name in (disable_scanners or []):
        if name not in VALID_SCANNERS:
            raise BulkExtractorError(
                f"invalid bulk_extractor scanner name: {name!r}"
            )

    cmd = [_bin(), "-o", str(out_dir), "-j", str(threads)]
    for name in (enable_scanners or []):
        cmd += ["-e", name]
    for name in (disable_scanners or []):
        cmd += ["-x", name]
    cmd.append(str(target))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise BulkExtractorError(f"bulk_extractor timeout after {timeout}s") from e

    files = sorted(p for p in out_dir.iterdir() if p.is_file())
    return BulkRun(target=target, out_dir=out_dir, rc=proc.returncode,
                   feature_files=files, command=cmd)
