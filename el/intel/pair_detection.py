"""A/B paired-capture detection for bundle inputs.

Memory captures of the same host typically share their byte size
exactly (RAM size is fixed at acquisition time), so when an evidence
bundle contains two files of identical size whose device-names share
a root prefix after stripping a known acquisition-suffix, the most
likely explanation is that the two files are *paired captures* of
the same host taken at different points in time. Seeing this at
intake matters because:

* If both inputs are ingested as independent devices, Memory
  Baseliner has nothing to diff against and the analyst loses the
  cross-image differential view entirely.
* If the analyst manually re-runs with ``--baseline``, the diff
  reveals whether the second image is a *clean baseline* (real
  remediation) or a *re-capture of the same compromised state*
  (the persistence layer survived) — a load-bearing distinction.

This module ships v1: **detect + advise**. The bundle CLI calls
:func:`detect_pairs` against its parsed ``[(name, path), …]`` device
list, writes ``pair_candidates.json`` into the bundle dir, prints
an advisory, and stamps ``ctx.shared["paired_with"]`` on each
device's coordinator context. Two new ACH hypotheses
(``H_PAIRED_CAPTURE_CANDIDATE`` and ``H_NOT_CLEAN_BASELINE``)
consume that marker to surface the situation in the report rather
than silently lifting the benign null when the "no non-baseline
items observed" claim fires on a paired (i.e. non-clean) reference.

Heuristic — intentionally conservative to avoid mis-pairing
cookie-cutter VMs that share the same RAM size:

1. **Exact byte-size match.** Both inputs must be regular files
   (directories never form a pair candidate) with identical size > 0.
2. **Different content.** Cheap divergence check: same head-512-byte
   sample = same file = NOT a pair; skip. Anything else proceeds —
   the byte-level differences are confirmed when Memory Baseliner
   actually runs.
3. **Device-name similarity.** Names are normalised by lowercasing
   and stripping a known acquisition-suffix set (``-mem``, ``-memory``,
   ``-pmem``, ``-snap``/``-snapshot``\\d+, ``-a``/``-b``, ``-img``,
   ``-raw``, ``-dump``). The remaining root must match exactly
   between the two candidates.
4. **Authoritative side selection.** If exactly one side has a
   sibling ``*.md5`` file (the dc3dd / FTK Imager hash sidecar
   convention), that side is authoritative; the other becomes
   the baseline. Otherwise the older mtime is authoritative
   (rationale: the earlier capture is presumed to be the live
   incident-era state, and the later capture is the candidate
   for "did anything actually get cleaned up").

The heuristic deliberately rejects cookie-cutter VM siblings
(e.g. ``wkstn-02`` vs ``wkstn-03``) because their roots differ
after suffix-stripping.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path


# Suffix groups stripped during name-root normalisation. Order matters:
# longer / more-specific suffixes must be tried before shorter ones so
# ``-pmem`` and ``-memory`` are stripped to root before ``-mem`` can
# over-match. The trailing ``\d*`` on ``snap`` / ``snapshot`` handles
# ``-snapshot5`` / ``-snap2`` style multi-capture series.
#
# The single-letter capture-iteration suffix (a/b/c) requires an
# actual separator (-_/) so ``dc-mem`` (which strips to ``dc``) is
# not then over-stripped to ``d`` by a trailing-``c`` match. SANS
# lab convention writes paired captures as ``wkstn-01a`` /
# ``wkstn-01b`` with the dash, which still strips correctly here.
_SUFFIX_PATTERNS: tuple[re.Pattern, ...] = (
    # 8 — "known good" qualifiers that prefix the acquisition-mode
    # suffixes. Added after SRL-2015 surfaced two SANS-provided
    # clean baseline memory images (Win7SP1x86-baseline.img,
    # XPSP3x86-baseline.img) whose device-name was, by convention,
    # ``<host>-baseline-mem`` — without this, the live capture
    # ``<host>-mem`` stripped to ``<host>`` while the baseline
    # stripped only the ``-mem`` portion to ``<host>-baseline``,
    # so the two never paired. With ``-baseline`` stripped, both
    # collapse to the same root and the new H_NOT_CLEAN_BASELINE
    # hypothesis can fire on the zero-diff side.
    re.compile(r"[-_]?baseline$"),
    # 7+ characters
    re.compile(r"[-_]?snapshot\d*$"),
    re.compile(r"[-_]?capture$"),
    re.compile(r"[-_]?memory$"),
    # 5
    re.compile(r"[-_]?image$"),
    re.compile(r"[-_]?clean$"),     # operator-named "known good" captures
    # 4
    re.compile(r"[-_]?pmem$"),
    re.compile(r"[-_]?snap\d*$"),
    re.compile(r"[-_]?dump$"),
    # 3
    re.compile(r"[-_]?mem$"),
    re.compile(r"[-_]?img$"),
    re.compile(r"[-_]?raw$"),
    # 1 — separator OR digit required before the trailing letter so
    # common host names ending in a/b/c (dc, lpac, …) don't get
    # over-stripped, while still matching the SANS lab convention
    # of writing paired captures as ``wkstn-01a`` / ``wkstn-01b``
    # (digit immediately before the suffix letter).
    re.compile(r"(?:[-_]|(?<=\d))[abc]$"),
)


def name_root(name: str) -> str:
    """Normalise a device name down to its host/role root.

    Lowercase + iteratively strip the longest matching acquisition
    suffix until the name stabilises. Stable result is the *root*
    used for pair matching.
    """
    n = name.strip().lower()
    while True:
        before = n
        for pat in _SUFFIX_PATTERNS:
            n = pat.sub("", n)
            if n != before:
                break
        if n == before:
            return n


@dataclass
class PairCandidate:
    """One detected pair. ``authoritative`` is the side whose evidence
    is treated as the primary investigation target; ``baseline`` is
    the side the diff runs against. The reason explains *why* the
    detector picked the authoritative side — analyst-facing prose,
    not machine-consumed."""
    authoritative_name: str
    authoritative_path: str
    baseline_name: str
    baseline_path: str
    name_root: str
    size_bytes: int
    reason: str
    # Optional extra evidence the bundle CLI can render in its log
    # without re-deriving — keeps the advisory print self-contained.
    md5_sidecar_present_for: str | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def _head_sample(path: Path, n: int = 512) -> bytes:
    """Read the first n bytes for the cheap divergence check.
    Returns b"" on any IO error so the caller treats the inputs as
    distinct (safer to over-detect a pair than mis-skip one)."""
    try:
        with path.open("rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def _has_md5_sidecar(path: Path) -> bool:
    """Return True when a sibling ``*.md5`` file exists in the same
    directory as ``path``. dc3dd / FTK Imager / Cellebrite all emit
    a sidecar at acquisition time — its presence is the canonical
    chain-of-custody marker."""
    parent = path.parent
    if not parent.exists():
        return False
    # Two common shapes: <stem>.md5 next to <stem>.img, or any *.md5
    # in the same dir (single-file capture dirs). Prefer the stem
    # match when possible.
    stem_match = parent / f"{path.stem}.md5"
    if stem_match.exists():
        return True
    for sibling in parent.glob("*.md5"):
        return True
    return False


def detect_pairs(
    devices: list[tuple[str, str]],
) -> list[PairCandidate]:
    """Scan a parsed ``[(device_name, device_path), …]`` list for
    paired-capture candidates.

    The detector is order-independent and produces at most one
    candidate per *root* — a root with three or more matching files
    is treated as an N-way capture series and the two with the
    closest mtimes are paired (the rest are emitted as ``notes``
    on the chosen pair). This keeps the v1 API simple while still
    surfacing the over-capture case to the analyst.
    """
    # Resolve paths + collect filesystem facts up front so the
    # rest of the function is pure data manipulation (testable
    # without filesystem mocking).
    enriched: list[dict] = []
    for name, raw_path in devices:
        p = Path(raw_path)
        try:
            st = p.stat()
        except OSError:
            continue
        # Directories never pair — we only diff regular files.
        # (Bundle inputs include directories like a Velociraptor
        # JSONL dir or an iOS sysdiagnose tarball — those need
        # their own pairing model.)
        if not p.is_file():
            continue
        if st.st_size <= 0:
            continue
        enriched.append({
            "name": name,
            "path": p,
            "size": st.st_size,
            "mtime": st.st_mtime,
            "root": name_root(name),
            "head": None,  # lazy
            "has_md5_sidecar": _has_md5_sidecar(p),
        })

    # Group by (size, name_root); only groups with ≥ 2 members
    # are pair candidates. Size-alone groups (cookie-cutter VMs)
    # are NOT promoted — root must match too.
    groups: dict[tuple[int, str], list[dict]] = {}
    for e in enriched:
        groups.setdefault((e["size"], e["root"]), []).append(e)

    pairs: list[PairCandidate] = []
    for (size, root), members in groups.items():
        if len(members) < 2:
            continue
        # Cheap divergence check: load the head sample for each
        # member; if any two members share the same head sample
        # they're likely the same file (e.g. hard link / copy).
        # The pair detector should NOT propose a candidate when
        # the two inputs are byte-identical — that's a deduplication
        # opportunity, not a baseline-diff opportunity.
        for m in members:
            if m["head"] is None:
                m["head"] = _head_sample(m["path"])

        # Pick the two members to pair. With exactly 2 → trivial.
        # With ≥ 3 → pick the two whose mtimes are most distant,
        # so the pair spans the largest possible capture window
        # (the rest are recorded as overflow notes). Picking by
        # mtime-extreme is one defensible default; the analyst
        # can always override with `--pair`.
        if len(members) == 2:
            a, b = members[0], members[1]
        else:
            members_sorted = sorted(members, key=lambda m: m["mtime"])
            a, b = members_sorted[0], members_sorted[-1]

        # Divergence check — skip if heads are identical (duplicates
        # rather than paired captures).
        if a["head"] and b["head"] and a["head"] == b["head"]:
            continue

        # Authoritative selection: prefer the side with an md5 sidecar
        # (chain-of-custody marker). If both or neither has one, fall
        # back to older mtime = authoritative.
        if a["has_md5_sidecar"] and not b["has_md5_sidecar"]:
            auth, base = a, b
            reason = (f"{a['name']} has an .md5 acquisition sidecar; "
                      f"{b['name']} does not")
            md5_for = a["name"]
        elif b["has_md5_sidecar"] and not a["has_md5_sidecar"]:
            auth, base = b, a
            reason = (f"{b['name']} has an .md5 acquisition sidecar; "
                      f"{a['name']} does not")
            md5_for = b["name"]
        else:
            # Tie on sidecar — fall back to older mtime as authoritative.
            if a["mtime"] <= b["mtime"]:
                auth, base = a, b
            else:
                auth, base = b, a
            if a["has_md5_sidecar"] and b["has_md5_sidecar"]:
                reason = ("both sides carry .md5 acquisition sidecars; "
                          "older mtime treated as authoritative")
                md5_for = "both"
            else:
                reason = ("neither side carries an .md5 acquisition "
                          "sidecar; older mtime treated as authoritative")
                md5_for = None

        overflow = [m["name"] for m in members
                    if m["name"] not in (auth["name"], base["name"])]
        notes: list[str] = []
        if overflow:
            notes.append(
                f"{len(overflow)} additional same-root capture(s) not "
                f"paired in this run: {sorted(overflow)} — re-run with "
                "explicit --pair to diff a different combination."
            )

        pairs.append(PairCandidate(
            authoritative_name=auth["name"],
            authoritative_path=str(auth["path"]),
            baseline_name=base["name"],
            baseline_path=str(base["path"]),
            name_root=root,
            size_bytes=size,
            reason=reason,
            md5_sidecar_present_for=md5_for,
            notes=notes,
        ))

    # Deterministic ordering for stable bundle output / golden tests.
    pairs.sort(key=lambda p: (p.name_root, p.authoritative_name))
    return pairs


def write_candidates(
    bundle_dir: Path | str,
    pairs: list[PairCandidate],
) -> Path:
    """Persist the detector result to ``<bundle_dir>/pair_candidates.json``.
    Always writes (even when the list is empty) so the artefact is a
    reliable signal that the detector ran — analysts grepping for
    "was pair detection applied to this case" don't have to guess."""
    out = Path(bundle_dir) / "pair_candidates.json"
    payload = {
        "schema_version": 1,
        "candidate_count": len(pairs),
        "candidates": [p.as_dict() for p in pairs],
    }
    out.write_text(json.dumps(payload, indent=2))
    return out


__all__ = [
    "PairCandidate",
    "detect_pairs",
    "name_root",
    "write_candidates",
]
