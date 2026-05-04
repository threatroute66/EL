"""SIGMA rule export — convert a SIGMA YAML pack to deployable SIEM queries.

The proposal in docs/enhancement_proposals.md Tier 4.1 asked to "expand
sigma_engine.py to run any installed pySigma backend, not just Hayabusa."

Reality check: pySigma backends *convert* SIGMA rules to platform-specific
query strings (SPL, KQL, Lucene, OpenSearch) — they do **not** evaluate
those queries. Evaluation happens in the SIEM. EL cannot replicate the
SIEM in process.

So this skill ships the *useful* half of that proposal: at coordinator
DONE, write per-backend query files under ``reports/sigma_rules/`` so the
analyst can ship them straight to their SIEM. The existing
``sigma_engine.py`` continues to handle in-process EvtxECmd-row matching
(its design value).

Backends wired (all Apache-2.0, all currently installed):
  * ``splunk``        — SPL
  * ``elasticsearch`` — Lucene query syntax
  * ``opensearch``    — OpenSearch Lucene
  * ``kusto``         — KQL (Sentinel / Defender XDR / Log Analytics)
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class SigmaExportError(Exception):
    pass


@dataclass
class SigmaExportRun:
    rules_root: Path
    output_dir: Path
    rule_count: int = 0
    converted_count: int = 0
    skipped_count: int = 0
    backends_run: list[str] = field(default_factory=list)
    output_files: dict[str, Path] = field(default_factory=dict)
    output_sha256: str = ""
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="sigma_export",
            version="0.1.0",
            command=(f"convert_pack({self.rules_root.name}) -> "
                     f"{', '.join(self.backends_run)}"),
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_dir),
            extracted_facts={
                "rule_count": self.rule_count,
                "converted_count": self.converted_count,
                "skipped_count": self.skipped_count,
                "backends": self.backends_run,
                "output_files": {b: str(p) for b, p
                                 in self.output_files.items()},
                "note": self.note,
                **extra,
            },
        )


def _hash_directory(directory: Path, max_files: int = 100) -> str:
    if not directory.is_dir():
        return "0" * 64
    h = hashlib.sha256()
    for p in sorted(directory.rglob("*"))[:max_files]:
        if p.is_file():
            try:
                h.update(p.name.encode())
                with p.open("rb") as f:
                    h.update(f.read(65536))
            except (PermissionError, OSError):
                continue
    return h.hexdigest()


def is_available() -> tuple[bool, str]:
    """Return (ok, reason) — pySigma + at least one backend installed?"""
    try:
        import sigma  # noqa: F401
    except ImportError:
        return False, "pip install pysigma"
    backends = _resolve_backends()
    if not backends:
        return False, ("no pySigma backends installed — try: pip install "
                        "pysigma-backend-splunk pysigma-backend-elasticsearch "
                        "pysigma-backend-kusto pysigma-backend-opensearch")
    return True, ""


def _resolve_backends() -> dict[str, type]:
    """Return {label: BackendClass} for every available pySigma backend."""
    out: dict[str, type] = {}
    try:
        from sigma.backends.splunk import SplunkBackend
        out["splunk"] = SplunkBackend
    except ImportError:
        pass
    try:
        from sigma.backends.elasticsearch import LuceneBackend
        out["elasticsearch"] = LuceneBackend
    except ImportError:
        pass
    try:
        from sigma.backends.opensearch import OpensearchLuceneBackend
        out["opensearch"] = OpensearchLuceneBackend
    except ImportError:
        pass
    try:
        from sigma.backends.kusto import KustoBackend
        out["kusto"] = KustoBackend
    except ImportError:
        pass
    return out


# Each backend gets one output file with one query per line, prefixed with
# the rule title in a comment so the analyst knows which rule a query
# corresponds to. Comment syntax differs per backend.
_COMMENT_PREFIX: dict[str, str] = {
    "splunk":         "# ",
    "elasticsearch":  "// ",
    "opensearch":     "// ",
    "kusto":          "// ",
}

_FILE_EXT: dict[str, str] = {
    "splunk":         "spl",
    "elasticsearch":  "lucene",
    "opensearch":     "lucene",
    "kusto":          "kql",
}


def export_pack(rules_root: Path, output_dir: Path) -> SigmaExportRun:
    """Walk a directory of SIGMA YAML files and convert each to every
    available backend's query language. Writes one file per backend.

    Args:
        rules_root: directory of SIGMA YAML files (recursive walk).
        output_dir: per-case directory; receives one file per backend +
            a manifest.txt summarising what was emitted.
    """
    rules_root = Path(rules_root)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ok, reason = is_available()
    if not ok:
        return SigmaExportRun(
            rules_root=rules_root, output_dir=output_dir,
            note=f"sigma_export skipped: {reason}",
        )

    if not rules_root.is_dir():
        raise SigmaExportError(f"rules_root not a directory: {rules_root}")

    backends = _resolve_backends()
    backend_buckets: dict[str, list[str]] = {b: [] for b in backends}

    rule_count = 0
    skipped_count = 0
    converted_count = 0
    converted_per_backend: dict[str, int] = {b: 0 for b in backends}

    from sigma.collection import SigmaCollection

    yaml_files = sorted(rules_root.rglob("*.yml")) + sorted(
        rules_root.rglob("*.yaml")
    )
    for rule_file in yaml_files:
        rule_count += 1
        try:
            text = rule_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped_count += 1
            continue
        try:
            collection = SigmaCollection.from_yaml(text)
        except Exception:
            skipped_count += 1
            continue
        # Pull the title out of the first rule for comment headers.
        try:
            rule_title = collection.rules[0].title or rule_file.stem
        except (AttributeError, IndexError):
            rule_title = rule_file.stem

        for backend_label, backend_cls in backends.items():
            try:
                queries = backend_cls().convert(collection)
            except Exception:
                # Some rules use SIGMA features a given backend doesn't
                # support. Don't fail the export; skip this backend for
                # this rule and move on.
                continue
            if not queries:
                continue
            comment_pfx = _COMMENT_PREFIX[backend_label]
            for q in queries:
                backend_buckets[backend_label].append(
                    f"{comment_pfx}{rule_title} ({rule_file.name})\n{q}\n"
                )
            converted_per_backend[backend_label] += 1

        if any(converted_per_backend[b] > 0 for b in backends):
            converted_count += 1

    output_files: dict[str, Path] = {}
    for backend_label, queries in backend_buckets.items():
        if not queries:
            continue
        ext = _FILE_EXT[backend_label]
        out_path = output_dir / f"sigma_rules.{backend_label}.{ext}"
        out_path.write_text("\n".join(queries))
        output_files[backend_label] = out_path

    # Per-backend stats manifest.
    manifest_lines = [
        "# SIGMA pack export — pySigma backend conversion stats",
        f"# rules_walked:    {rule_count}",
        f"# rules_converted: {converted_count}",
        f"# rules_skipped:   {skipped_count}",
        "",
    ]
    for backend_label in backends:
        per = converted_per_backend[backend_label]
        manifest_lines.append(
            f"{backend_label}: {per} rule(s) converted "
            f"-> {output_files.get(backend_label, '(none)')}"
        )
    (output_dir / "manifest.txt").write_text("\n".join(manifest_lines) + "\n")

    return SigmaExportRun(
        rules_root=rules_root,
        output_dir=output_dir,
        rule_count=rule_count,
        converted_count=converted_count,
        skipped_count=skipped_count,
        backends_run=list(backends.keys()),
        output_files=output_files,
        output_sha256=_hash_directory(output_dir),
        note=("converted SIGMA rules to multiple SIEM query languages; "
              "each file has one query per line with a rule-title "
              "comment header"),
    )
