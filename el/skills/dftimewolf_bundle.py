"""dfTimewolf bundle ingestion — provenance + sub-artifact routing.

dfTimewolf (Google, log2timeline org) is a recipe-driven DFIR pipeline.
It does NOT produce a single canonical "bundle" format — its outputs are
the standard artifacts its modules collect: Plaso storage files,
GCS-extracted disk images, BigQuery JSON, Turbinia-processed exports, etc.

This skill is therefore deliberately small. It does two useful things:

  1. **Detect** when the case input is a dfTimewolf output directory
     (heuristic: contains a recipe JSON file, a dftimewolf.log file, or
     a ``conf.yaml`` with the dfTimewolf-shape ``modules`` key).
  2. **Surface provenance** — parse the recipe + log to record which
     dfTimewolf modules ran. That metadata is forensic gold for chain-of-
     custody: it tells the analyst *how* the evidence was assembled.

Sub-artifact analysis happens via EL's existing agents (Plaso storage →
TimelineSynthesistAgent, JSON logs → CloudForensicator, etc.). We don't
re-implement those routes — we just point at them.

Project: https://github.com/log2timeline/dftimewolf
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from el.schemas.finding import EvidenceItem


class DFTimewolfError(Exception):
    pass


_RECIPE_FILE_PATTERNS = (
    re.compile(r"^recipe(_[a-z0-9_]+)?\.(json|yaml|yml)$", re.IGNORECASE),
    re.compile(r"^dftimewolf[._-].*\.(json|yaml|yml)$", re.IGNORECASE),
)
_LOG_FILE_PATTERNS = (
    re.compile(r"^dftimewolf\.log$", re.IGNORECASE),
    re.compile(r"^dftimewolf-.*\.log$", re.IGNORECASE),
)


@dataclass
class DFTimewolfRecipe:
    name: str
    description: str = ""
    args: dict = field(default_factory=dict)
    module_names: list[str] = field(default_factory=list)


@dataclass
class DFTimewolfBundle:
    bundle_root: Path
    recipe: DFTimewolfRecipe | None = None
    recipe_path: Path | None = None
    log_path: Path | None = None
    artifact_files: list[Path] = field(default_factory=list)
    artifact_kinds: dict[str, int] = field(default_factory=dict)
    output_sha256: str = ""
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="dftimewolf_bundle",
            version="0.1.0",
            command=f"parse_bundle({self.bundle_root.name})",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.bundle_root),
            extracted_facts={
                "recipe_name": self.recipe.name if self.recipe else "",
                "recipe_modules": self.recipe.module_names if self.recipe else [],
                "recipe_path": str(self.recipe_path) if self.recipe_path else "",
                "log_path": str(self.log_path) if self.log_path else "",
                "artifact_count": len(self.artifact_files),
                "artifact_kinds": self.artifact_kinds,
                "note": self.note,
                **extra,
            },
        )

    def routing_hints(self) -> dict[str, list[Path]]:
        """Map sub-artifacts to the EL agent that should pick them up.

        Returns a dict like:
            {"plaso": [<path>, ...], "cloudtrail": [<path>, ...], ...}
        Empty buckets are omitted. Caller (TriageAgent / coordinator) can
        re-run dispatch on each bucket.
        """
        out: dict[str, list[Path]] = {}
        for f in self.artifact_files:
            kind = _artifact_kind(f)
            if kind:
                out.setdefault(kind, []).append(f)
        return out


def _hash_directory(directory: Path, max_files: int = 1000) -> str:
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


def _is_recipe_filename(name: str) -> bool:
    return any(p.match(name) for p in _RECIPE_FILE_PATTERNS)


def _is_log_filename(name: str) -> bool:
    return any(p.match(name) for p in _LOG_FILE_PATTERNS)


def _looks_like_dftimewolf_recipe(text: str) -> bool:
    """Cheap shape check: real dfTimewolf recipes are JSON or YAML with a
    ``modules`` array containing module dicts that have ``wants`` / ``args``
    / ``name`` keys."""
    text = text.strip()
    if not text:
        return False
    try:
        if text.startswith("{") or text.startswith("["):
            data = json.loads(text)
        else:
            try:
                import yaml  # type: ignore
                data = yaml.safe_load(text)
            except ImportError:
                return False
            except Exception:
                return False
    except json.JSONDecodeError:
        return False
    if not isinstance(data, dict):
        return False
    if not isinstance(data.get("modules"), list):
        return False
    # Either a module has 'wants' (DAG dep) or 'name' + dftimewolf-known keys.
    for m in data["modules"]:
        if isinstance(m, dict) and ("wants" in m or "args" in m):
            return True
    return False


def _parse_recipe(path: Path) -> DFTimewolfRecipe | None:
    """Read *path* (json or yaml) into a :class:`DFTimewolfRecipe`."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    data: dict | None = None
    if text.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
    else:
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(text)
        except (ImportError, Exception):
            return None
    if not isinstance(data, dict):
        return None

    name = str(data.get("name") or path.stem)
    description = str(data.get("description") or "")
    args_field = data.get("args")
    args: dict = {}
    if isinstance(args_field, dict):
        args = {str(k): str(v)[:200] for k, v in args_field.items()}
    elif isinstance(args_field, list):
        args = {f"arg_{i}": str(v)[:200] for i, v in enumerate(args_field)}

    modules_field = data.get("modules")
    module_names: list[str] = []
    if isinstance(modules_field, list):
        for m in modules_field:
            if isinstance(m, dict):
                n = m.get("name")
                if n:
                    module_names.append(str(n))
    return DFTimewolfRecipe(
        name=name, description=description,
        args=args, module_names=module_names,
    )


_KIND_BY_SUFFIX: dict[str, str] = {
    ".plaso":     "plaso",
    ".pcap":      "pcap",
    ".pcapng":    "pcap",
    ".evtx":      "evtx",
    ".csv":       "csv",
    ".raw":       "raw_disk",
    ".dd":        "raw_disk",
    ".e01":       "ewf",
    ".aff4":      "aff4",
    ".vmdk":      "vmdk",
    ".vhdx":      "vhdx",
}


def _artifact_kind(path: Path) -> str:
    """Map an artifact path → an EL evidence-kind string for routing."""
    suffix = path.suffix.lower()
    if suffix in _KIND_BY_SUFFIX:
        return _KIND_BY_SUFFIX[suffix]
    if suffix in (".json", ".jsonl"):
        # Best-effort sniff for cloudtrail/m365/azure shape — but defer
        # the heavy detection to existing skills.
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:4096]
        except OSError:
            return "json"
        if '"eventName"' in head and '"eventSource"' in head:
            return "cloudtrail"
        if '"audit.k8s.io/' in head:
            return "k8s_audit"
        if '"AppDisplayName"' in head and '"UserPrincipalName"' in head:
            return "azure_signin"
        return "json"
    return ""


def _walk_artifacts(root: Path,
                     skip: set[Path] | None = None,
                     max_files: int = 5000) -> Iterator[Path]:
    skip = skip or set()
    seen = 0
    for p in root.rglob("*"):
        if not p.is_file() or p in skip:
            continue
        if _is_log_filename(p.name) or _is_recipe_filename(p.name):
            continue
        yield p
        seen += 1
        if seen >= max_files:
            return


def looks_like_dftimewolf_bundle(path: Path) -> bool:
    """Heuristic shape check for triage routing."""
    if not path.is_dir():
        return False
    try:
        for p in path.iterdir():
            if not p.is_file():
                continue
            if _is_recipe_filename(p.name):
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")[:8192]
                except OSError:
                    continue
                if _looks_like_dftimewolf_recipe(text):
                    return True
            if _is_log_filename(p.name):
                # The presence of a dftimewolf.log alone is suggestive.
                return True
    except (PermissionError, OSError):
        return False
    return False


def parse_bundle(bundle_root: Path) -> DFTimewolfBundle:
    """Parse a directory, returning a :class:`DFTimewolfBundle` summary.

    Args:
        bundle_root: directory dfTimewolf wrote outputs to.
    """
    bundle_root = Path(bundle_root)
    if not bundle_root.is_dir():
        raise DFTimewolfError(f"not a directory: {bundle_root}")

    recipe: DFTimewolfRecipe | None = None
    recipe_path: Path | None = None
    log_path: Path | None = None
    skip_paths: set[Path] = set()

    for p in bundle_root.iterdir():
        if not p.is_file():
            continue
        if _is_recipe_filename(p.name) and recipe_path is None:
            try:
                text = p.read_text(encoding="utf-8", errors="replace")[:8192]
            except OSError:
                continue
            if _looks_like_dftimewolf_recipe(text):
                parsed = _parse_recipe(p)
                if parsed:
                    recipe = parsed
                    recipe_path = p
                    skip_paths.add(p)
        elif _is_log_filename(p.name) and log_path is None:
            log_path = p
            skip_paths.add(p)

    artifacts: list[Path] = list(_walk_artifacts(bundle_root, skip=skip_paths))
    kinds: dict[str, int] = {}
    for f in artifacts:
        k = _artifact_kind(f)
        if k:
            kinds[k] = kinds.get(k, 0) + 1

    return DFTimewolfBundle(
        bundle_root=bundle_root,
        recipe=recipe,
        recipe_path=recipe_path,
        log_path=log_path,
        artifact_files=artifacts,
        artifact_kinds=kinds,
        output_sha256=_hash_directory(bundle_root),
        note=("recipe metadata + sub-artifact inventory; downstream agents "
              "consume the artifacts via existing routes (Plaso storage → "
              "TimelineSynthesist, .json logs → CloudForensicator, etc.)"),
    )
