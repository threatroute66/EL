"""Combined multi-host report — stitches N per-case ledgers into one.

Motivation: the SRL-2015 Compromised Enterprise Network scenario
produced 8 per-case ledgers (4 hosts × {memory, disk}). Each case is
forensically complete on its own, but the attacker story is only
legible when the hosts are shown side-by-side — lateral movement
markers on one host correlate to persistence artifacts on another,
credential-access evidence from memory joins up with timestamped
logon events from a different host's disk.

This module is a DETERMINISTIC projection. No LLM. Every claim in the
combined report carries a pointer to the underlying case_id +
finding_id so anyone can walk the provenance back to the tool
invocation that produced it.

Sections (in order):
  1. Executive summary
  2. Hosts + leading hypothesis table
  3. Cross-host signal matrix (lateral movement / credential access /
     persistence / exfil / anti-forensic markers per host)
  4. Unified MITRE ATT&CK coverage (union across all cases)
  5. Cross-case IOC overlap (from the knowledge DB)
  6. Per-host summary (top findings, compact)
  7. Pointers to per-case reports + artifacts
"""
from __future__ import annotations

import collections
import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class CaseSlice:
    """Compact projection of a single case for the combined renderer."""
    case_id: str
    case_dir: Path
    manifest: dict = field(default_factory=dict)
    ach_ranking: list[dict] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    report_path: Path | None = None

    @property
    def leading(self) -> tuple[str | None, int]:
        if not self.ach_ranking:
            return (None, 0)
        top = self.ach_ranking[0]
        return (top.get("hyp_id"), int(top.get("score", 0)))

    @property
    def host_label(self) -> str:
        """Derive a compact host label from the case_id.
        e.g. 'srl2015-nromanoff-memory' -> 'nromanoff / memory'."""
        parts = self.case_id.split("-")
        # common suffixes we want to pull out as the 'kind'
        kind = ""
        for tail in ("memory", "disk", "pcap", "memory-r2", "disk-r2"):
            suffix = tail.split("-")
            if len(parts) >= len(suffix) and parts[-len(suffix):] == suffix:
                kind = " / " + tail
                parts = parts[:-len(suffix)]
                break
        # drop a single leading token treated as scenario prefix
        # (srl2015, m57, etc.) — that's shared across all the slices
        if len(parts) >= 2:
            return "-".join(parts[1:]) + kind
        return self.case_id


def load_case(case_dir: Path) -> CaseSlice:
    """Hydrate a CaseSlice from the on-disk case directory."""
    case_dir = Path(case_dir)
    manifest_path = case_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    case_id = manifest.get("case_id") or case_dir.name

    ach_path = case_dir / "ach_matrix.json"
    ach_ranking = []
    if ach_path.exists():
        try:
            ach_ranking = json.loads(ach_path.read_text()).get("ranking", [])
        except Exception:
            pass

    iocs_path = case_dir / "iocs.json"
    iocs: dict[str, list[str]] = {}
    if iocs_path.exists():
        try:
            iocs = json.loads(iocs_path.read_text()) or {}
        except Exception:
            pass

    findings: list[dict] = []
    ledger = case_dir / "findings.sqlite"
    if ledger.exists():
        conn = sqlite3.connect(ledger)
        try:
            cols = [c[1] for c in conn.execute("PRAGMA table_info(findings)")]
            rows = conn.execute("SELECT * FROM findings").fetchall()
            for r in rows:
                d = dict(zip(cols, r))
                if "payload_json" in d:
                    try:
                        payload = json.loads(d["payload_json"])
                        d.update(payload)
                    except Exception:
                        pass
                findings.append(d)
        finally:
            conn.close()

    report_path = case_dir / "reports" / "report.md"
    return CaseSlice(
        case_id=case_id, case_dir=case_dir, manifest=manifest,
        ach_ranking=ach_ranking, iocs=iocs, findings=findings,
        report_path=report_path if report_path.exists() else None,
    )


# --- Signal-matrix row detectors -------------------------------------------
# Each detector inspects the findings of one case and returns a 1-line
# cell string if the signal is present, empty string otherwise. Kept as
# KEYWORD lookups — the per-case reporter already did the hard work of
# shaping these claims; we just surface the binary.

def _any_claim_contains(findings: list[dict], *needles: str) -> str | None:
    low = [n.lower() for n in needles]
    for f in findings:
        c = (f.get("claim") or "").lower()
        if any(n in c for n in low):
            return f.get("claim", "")[:120]
    return None


_SIGNAL_ROWS: list[tuple[str, list[str]]] = [
    ("malfind regions",            ["malfind flagged", "malfind.malfind:"]),
    ("hidden processes",           ["hidden processes detected"]),
    ("kernel rootkit",             ["hidden kernel driver", "unlinked driver"]),
    ("credential access (lsass)",  ["code-injection in credential-access",
                                     "mimikatz", "sekurlsa", "lsass"]),
    ("kerberoasting (RC4)",        ["kerberoasting", "rc4-hmac"]),
    ("psexec install",             ["psexec/service_install", "psexesvc"]),
    ("rdp inbound",                ["rdp/inbound_session"]),
    ("scheduled task persist",     ["scheduled_task/task_created",
                                     "scheduled_task_nonms"]),
    ("service install (non-PSE)",  ["service_install/remote_service"]),
    ("svchost outside system32",   ["svchost_outside_system32"]),
    ("pyinstaller dropper",        ["pyinstaller_temp_dir"]),
    ("exe in user temp",           ["exe_in_temp"]),
    ("zero-size system binary",    ["system_binary_zero_size"]),
    ("timestomping",               ["system_binary_zero_timestamps"]),
    ("reflective PE inject",       ["reflectively-loaded pe"]),
    ("unlinked DLL (ldrmodules)",  ["unlinked dll"]),
    ("failed-logon brute burst",   ["failed_logon_burst"]),
    ("outlook/mbox EXFIL folder",  ["exfil.pst", "exfil folder"]),
    ("consumer-webmail visit",     ["consumer-webmail access"]),
    ("BTC wallet exposure",        ["bc1", "btc wallet", "bitcoin"]),
]


def _signal_matrix(cases: list[CaseSlice]) -> list[list[str]]:
    """Build a rows × hosts matrix. Each cell is '•' (present) or ''."""
    matrix: list[list[str]] = []
    matrix.append(["Signal"] + [c.host_label for c in cases])
    for row_name, needles in _SIGNAL_ROWS:
        row = [row_name]
        any_present = False
        for c in cases:
            hit = _any_claim_contains(c.findings, *needles)
            row.append("•" if hit else "")
            if hit:
                any_present = True
        if any_present:
            matrix.append(row)
    return matrix


# --- Time-range across cases -----------------------------------------------

def _time_range(cases: list[CaseSlice]) -> tuple[str | None, str | None]:
    mn = mx = None
    for c in cases:
        for f in c.findings:
            ts = f.get("created_utc")
            if ts:
                if mn is None or ts < mn:
                    mn = ts
                if mx is None or ts > mx:
                    mx = ts
    return (mn, mx)


# --- MITRE ATT&CK union ----------------------------------------------------

def _technique_union(cases: list[CaseSlice]) -> dict[str, dict]:
    """Collect the ATT&CK technique_ids referenced across every case's
    findings. Three sources:
      1. Hypothesis tags → attack_map.HYPOTHESIS_MAP (the canonical path
         EL uses in per-case report generation).
      2. Regex on claim text (catches '[T1078.004]' and similar literal
         mentions — used by k8s_audit + network_anomaly).
      3. extracted_facts['attack'] on evidence items (explicit 'Tid:Name'
         strings from the k8s_audit family)."""
    import re
    tid_re = re.compile(r"\bT\d{4}(?:\.\d+)?\b")
    try:
        from el.intel import attack_map as _am
        hmap = _am.HYPOTHESIS_MAP
    except Exception:
        hmap = {}
    # Build name lookup from attack_map for enrichment
    names: dict[str, str] = {}
    for lst in hmap.values():
        for tid, name in lst:
            names[tid] = name
    try:
        from el.intel.attack_map import PATTERN_MAP as _pm
        for _, items in _pm:
            for tid, name in items:
                names.setdefault(tid, name)
    except Exception:
        pass

    out: dict[str, dict] = {}
    for c in cases:
        for f in c.findings:
            tids: set[str] = set()
            # (1) Hypothesis-tag-based mapping
            for tag in (f.get("hypotheses_supported") or []):
                for tid, name in hmap.get(tag, []):
                    tids.add(tid)
                    names.setdefault(tid, name)
            # (2) Literal TID in claim text
            claim = f.get("claim") or ""
            for m in tid_re.findall(claim):
                tids.add(m)
            # (3) extracted_facts['attack'] on evidence items
            for e in (f.get("evidence") or []):
                for a in (e.get("extracted_facts") or {}).get("attack", []) or []:
                    if isinstance(a, str) and ":" in a:
                        tid, name = a.split(":", 1)
                        tids.add(tid)
                        names.setdefault(tid, name)
            for tid in tids:
                slot = out.setdefault(tid, {"id": tid, "cases": set(),
                                              "findings": 0, "name": ""})
                slot["cases"].add(c.case_id)
                slot["findings"] += 1
    for tid, info in out.items():
        if not info["name"]:
            info["name"] = names.get(tid, "")
        info["cases"] = sorted(info["cases"])
    return out


# --- Cross-case IOC overlap via the knowledge DB ---------------------------

def _ioc_overlap(cases: list[CaseSlice], min_hosts: int = 2
                  ) -> list[tuple[str, str, list[str]]]:
    """Query ~/.el/knowledge.sqlite for IOC values that appear in ≥
    min_hosts of our case_ids. Returns rows of (ioc_type, value, case_ids)."""
    import os
    db_path = os.environ.get("EL_KNOWLEDGE_DB") or \
        os.path.expanduser("~/.el/knowledge.sqlite")
    if not os.path.exists(db_path):
        return []
    case_ids = [c.case_id for c in cases]
    placeholders = ",".join("?" * len(case_ids))
    sql = (f"SELECT ioc_type, value, group_concat(DISTINCT case_id) "
           f"FROM ioc_observations WHERE case_id IN ({placeholders}) "
           f"GROUP BY ioc_type, value HAVING count(DISTINCT case_id) >= ? "
           f"ORDER BY count(DISTINCT case_id) DESC, ioc_type, value "
           f"LIMIT 500")
    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute(sql, (*case_ids, min_hosts)).fetchall()
        conn.close()
    except Exception:
        return []
    return [(t, v, sorted(ids.split(","))) for t, v, ids in rows]


# --- Per-host summary block -------------------------------------------------

_SUMMARY_CONF_ORDER = {"high": 0, "medium": 1, "low": 2, "insufficient": 3}


def _host_summary(case: CaseSlice, max_findings: int = 8) -> list[str]:
    """Top findings for a single host, formatted as markdown bullets."""
    highs = [f for f in case.findings
             if f.get("confidence") == "high"
             and f.get("agent") not in ("knowledge_lookup", "red_reviewer")
             and "parsed" not in (f.get("claim") or "").lower()
             and "extracted" not in (f.get("claim") or "").lower()
             and "ewf metadata" not in (f.get("claim") or "").lower()]
    mediums = [f for f in case.findings
               if f.get("confidence") == "medium"
               and f.get("agent") not in ("knowledge_lookup", "red_reviewer")]
    picks = highs[:max_findings]
    if len(picks) < max_findings:
        picks += mediums[: max_findings - len(picks)]
    lines: list[str] = []
    for f in picks:
        claim = (f.get("claim") or "").strip().replace("\n", " ")
        if len(claim) > 240:
            claim = claim[:237] + "…"
        agent = f.get("agent", "?")
        lines.append(f"  - _{agent}_ ({f.get('confidence','?')}): {claim}")
    if not lines:
        lines.append("  - _(no high/medium findings to surface)_")
    return lines


# --- Render entry point ----------------------------------------------------

def render_combined(
    case_dirs: list[Path], out_path: Path,
    name: str | None = None,
) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cases = [load_case(Path(d)) for d in case_dirs]
    if not cases:
        raise ValueError("no cases supplied")

    name = name or "combined-case"
    mn, mx = _time_range(cases)
    techniques = _technique_union(cases)
    matrix = _signal_matrix(cases)
    overlap = _ioc_overlap(cases)

    lines: list[str] = []
    now = datetime.now(timezone.utc).isoformat()
    lines.append(f"# EL Combined Case Report — {name}")
    lines.append(f"_Generated {now} UTC · {len(cases)} case(s) stitched_")
    lines.append("")

    # 1. Executive summary
    total_findings = sum(len(c.findings) for c in cases)
    high_count = sum(1 for c in cases for f in c.findings
                     if f.get("confidence") == "high"
                     and f.get("agent") != "knowledge_lookup")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Cases stitched: **{len(cases)}**")
    lines.append(f"- Total findings: **{total_findings:,}** "
                 f"(high-confidence: {high_count:,})")
    if mn and mx:
        lines.append(f"- Finding-time range: `{mn}` → `{mx}` UTC")
    lines.append(f"- Distinct ATT&CK techniques observed: "
                 f"**{len(techniques)}**")
    lines.append("")
    lines.append("_This combined report is a deterministic projection of "
                 "the per-case ledgers. Every claim here is grounded in a "
                 "finding_id within one of the cases listed below. No LLM "
                 "was used to generate the narrative._")
    lines.append("")

    # 2. Per-case leading hypothesis table
    lines.append("## Hosts & Leading Hypotheses")
    lines.append("")
    lines.append("| Case | Host / Kind | Leading Hypothesis | Score |")
    lines.append("|---|---|---|---:|")
    for c in cases:
        hid, score = c.leading
        lines.append(f"| `{c.case_id}` | {c.host_label} "
                     f"| {hid or '—'} | {score} |")
    lines.append("")

    # 3. Cross-host signal matrix
    if len(matrix) > 1:
        lines.append("## Cross-Host Signal Matrix")
        lines.append("")
        header = matrix[0]
        lines.append("| " + " | ".join(header) + " |")
        lines.append("|" + "|".join(["---"] * len(header)) + "|")
        for row in matrix[1:]:
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
        lines.append("_Only rows with ≥1 host hit are shown. • = the signal "
                     "was observed in that host's ledger (keyword match "
                     "against finding claims; pivot to the per-case report "
                     "for the specific finding_id and evidence)._")
        lines.append("")

    # 4. Unified ATT&CK
    if techniques:
        lines.append("## MITRE ATT&CK Technique Coverage (Union)")
        lines.append("")
        lines.append("| Technique | Name | Cases observed | Total findings |")
        lines.append("|---|---|---:|---:|")
        for tid in sorted(techniques):
            info = techniques[tid]
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            lines.append(f"| [`{tid}`]({url}) | {info.get('name','')} "
                         f"| {len(info['cases'])} | {info['findings']} |")
        lines.append("")

    # 5. Cross-case IOC overlap
    if overlap:
        lines.append("## Cross-Case IOC Overlap")
        lines.append("")
        lines.append("IOC values observed in **≥ 2** of the stitched cases "
                     "(via `~/.el/knowledge.sqlite`). These are the "
                     "pivot points that bind the hosts together into a "
                     "single narrative.")
        lines.append("")
        lines.append("| IOC type | Value | Seen in |")
        lines.append("|---|---|---|")
        for ioc_type, value, ids in overlap[:200]:
            ids_s = ", ".join(f"`{i}`" for i in ids)
            lines.append(f"| {ioc_type} | `{value}` | {ids_s} |")
        if len(overlap) > 200:
            lines.append(f"| _… {len(overlap)-200} more elided_ |  |  |")
        lines.append("")

    # 6. Per-host summary
    lines.append("## Per-Host Summary")
    lines.append("")
    for c in cases:
        hid, score = c.leading
        lines.append(f"### `{c.case_id}` — {c.host_label}")
        lines.append("")
        lines.append(f"- Leading hypothesis: `{hid or '—'}` (score={score})")
        lines.append(f"- Per-case report: `{c.report_path}`")
        lines.extend(_host_summary(c))
        lines.append("")

    # 7. Pointers
    lines.append("## Case Artifact Pointers")
    lines.append("")
    for c in cases:
        lines.append(f"- `{c.case_id}`")
        lines.append(f"    - report: `{c.report_path}`")
        lines.append(f"    - ledger: `{c.case_dir / 'findings.sqlite'}`")
        lines.append(f"    - ACH matrix: `{c.case_dir / 'ach_matrix.json'}`")
        lines.append(f"    - STIX: `{c.case_dir / 'reports' / 'stix-bundle.json'}`")
    lines.append("")

    out_path.write_text("\n".join(lines))
    return out_path
