"""Skill: parse a `bulk_extractor` output directory.

`bulk_extractor` (Garfinkel) is the canonical streaming feature
extractor that EL already runs against memory dumps + raw partition
captures. Its output directory contains:

- Per-feature TSV files (e.g. `domain.txt`, `email.txt`, `url.txt`,
  `ip.txt`, `winpe_carved.txt`) with one line per feature occurrence:
  `<offset>\\t<value>\\t<context>`
- Per-feature histograms (`*_histogram.txt`) summarising the same data
  with one line per unique value: `n=<count>\\t<value>`
- A handful of carved-content subdirs (`evtx_carved/`, `jpeg_carved/`,
  `unzip_carved/`, …) populated when the corresponding scanner finds
  intact records.

This skill streams those files and returns a `BulkExtractorSummary`
that downstream agents/findings can turn into structured claims —
useful when EL has been run against a `bulk_extractor` output dir
itself (e.g. a 2 TB raw-partition carve we don't want to re-extract).
Pure-Python, no dependencies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Canonical feature-file basenames bulk_extractor produces. Used
# by triage to recognise a BE output directory and by the parser
# to enumerate what's worth surfacing.
CANONICAL_FEATURE_FILES = (
    "domain.txt", "email.txt", "url.txt", "ip.txt", "ether.txt",
    "telephone.txt", "ccn.txt", "ccn_track2.txt", "exif.txt",
    "json.txt", "elf.txt", "find.txt", "gps.txt", "httplogs.txt",
    "aes_keys.txt", "alerts.txt",
)

# Histogram counterparts — bulk_extractor only writes these for
# scanners that actually fired, so their existence implies the
# content is non-empty even when the per-feature TSV is also present.
CANONICAL_HISTOGRAM_FILES = tuple(
    n.removesuffix(".txt") + "_histogram.txt"
    for n in CANONICAL_FEATURE_FILES
)

# Carved-content marker files — when bulk_extractor reconstructs
# whole records (EVTX, JPEG, ZIP entries, NTFS metadata) it writes
# both a metadata `.txt` and a sibling subdir of the same root.
CARVED_MARKERS = (
    "evtx_carved.txt", "jpeg_carved.txt", "unzip_carved.txt",
    "winpe_carved.txt", "ntfsindx_carved.txt", "ntfsmft_carved.txt",
    "ntfsusn_carved.txt", "ntfslogfile_carved.txt", "sqlite_carved.txt",
    "unrar_carved.txt", "utmp_carved.txt",
)

_HIST_LINE_RE = re.compile(r"^n=(\d+)\s+(.+)$")


@dataclass
class FeatureSummary:
    name: str                              # e.g. "domain", "email"
    feature_path: Path | None = None       # the TSV (may be empty)
    histogram_path: Path | None = None     # the histogram (may be missing)
    record_count: int = 0                  # TSV non-comment line count
    unique_values: int = 0                 # histogram entry count
    top: list[tuple[int, str]] = field(default_factory=list)
    # Per-feature observations the analyst would want to inspect first.

    @property
    def has_content(self) -> bool:
        return self.record_count > 0 or self.unique_values > 0


@dataclass
class CarvedSummary:
    name: str                              # e.g. "evtx_carved"
    txt_path: Path | None = None
    subdir_path: Path | None = None
    record_count: int = 0                  # TSV line count
    file_count: int = 0                    # files inside subdir

    @property
    def has_content(self) -> bool:
        return self.record_count > 0 or self.file_count > 0


@dataclass
class BulkExtractorSummary:
    output_dir: Path
    features: dict[str, FeatureSummary] = field(default_factory=dict)
    carved: dict[str, CarvedSummary] = field(default_factory=dict)
    report_xml: Path | None = None

    @property
    def populated_features(self) -> list[FeatureSummary]:
        return [f for f in self.features.values() if f.has_content]

    @property
    def populated_carved(self) -> list[CarvedSummary]:
        return [c for c in self.carved.values() if c.has_content]


def _count_tsv_records(path: Path) -> int:
    """Count non-comment, non-empty lines in a bulk_extractor TSV."""
    n = 0
    try:
        with path.open("r", errors="replace") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                n += 1
    except OSError:
        pass
    return n


def parse_histogram(path: Path, top: int = 25) -> tuple[int, list[tuple[int, str]]]:
    """Return (unique_values_count, top_N_descending). Lines beginning
    with `#` are bulk_extractor banner/version headers — skipped."""
    rows: list[tuple[int, str]] = []
    try:
        with path.open("r", errors="replace") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line or line.startswith("#"):
                    continue
                m = _HIST_LINE_RE.match(line)
                if not m:
                    continue
                rows.append((int(m.group(1)), m.group(2)))
    except OSError:
        return (0, [])
    rows.sort(key=lambda r: -r[0])
    return (len(rows), rows[:top])


def is_bulk_extractor_output(path: Path) -> bool:
    """Triage probe: does this directory look like a bulk_extractor
    output dir? Requires either `report.xml` (bulk_extractor's own
    manifest) OR ≥3 of the canonical feature files."""
    p = Path(path)
    if not p.is_dir():
        return False
    if (p / "report.xml").is_file():
        return True
    hits = sum(1 for n in CANONICAL_FEATURE_FILES if (p / n).is_file())
    return hits >= 3


def summarise(out_dir: Path, *, top: int = 25) -> BulkExtractorSummary:
    """Walk a bulk_extractor output dir and return a summary that
    captures every populated feature + carved record bucket. Empty
    feature files (the typical case for ccn/aes_keys/gps on most
    inputs) get a FeatureSummary with `has_content == False` so the
    analyst can SEE that the scanner ran and produced nothing."""
    out_dir = Path(out_dir)
    summary = BulkExtractorSummary(output_dir=out_dir)

    if (out_dir / "report.xml").is_file():
        summary.report_xml = out_dir / "report.xml"

    for fname in CANONICAL_FEATURE_FILES:
        name = fname.removesuffix(".txt")
        feat = FeatureSummary(name=name)
        fp = out_dir / fname
        hp = out_dir / f"{name}_histogram.txt"
        if fp.is_file():
            feat.feature_path = fp
            feat.record_count = _count_tsv_records(fp)
        if hp.is_file():
            feat.histogram_path = hp
            uniq, top_rows = parse_histogram(hp, top=top)
            feat.unique_values = uniq
            feat.top = top_rows
        summary.features[name] = feat

    for marker in CARVED_MARKERS:
        name = marker.removesuffix(".txt")
        carve = CarvedSummary(name=name)
        tp = out_dir / marker
        sp = out_dir / name
        if tp.is_file():
            carve.txt_path = tp
            carve.record_count = _count_tsv_records(tp)
        if sp.is_dir():
            carve.subdir_path = sp
            try:
                carve.file_count = sum(
                    1 for x in sp.rglob("*") if x.is_file()
                )
            except OSError:
                pass
        summary.carved[name] = carve

    return summary


__all__ = [
    "BulkExtractorSummary", "CarvedSummary", "FeatureSummary",
    "CANONICAL_FEATURE_FILES", "CANONICAL_HISTOGRAM_FILES",
    "CARVED_MARKERS",
    "is_bulk_extractor_output", "parse_histogram", "summarise",
]
