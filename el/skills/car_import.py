"""MITRE Cyber Analytics Repository (CAR) analytic loader.

CAR (https://car.mitre.org/) is MITRE's hand-curated detection
analytics library — a sibling to SIGMA but governed by MITRE
directly and tagged tightly against ATT&CK. Roughly 100 analytics
as of 2026, many of which ship a ``sigma`` implementation field in
their YAML.

EL's design philosophy is "wrap court-vetted tools, don't reinvent
them" — the existing ``el.skills.sigma_engine`` is the rule
evaluator we already use; nothing CAR-specific has to be built on
the detection side. This skill is the LOAD side: walk a CAR
analytics directory, for each YAML pull out the sigma snippet and
hand the resulting list of SIGMA rules to the existing engine.

CAR YAML shape (abridged)::

    id: CAR-2020-09-001
    title: Webshell-Indicative Process Tree
    description: ...
    coverage:
      - technique: T1190
        coverage: Moderate
    implementations:
      - name: pseudocode
        type: pseudocode
        code: |
          processes = ...
      - name: Webshell-Indicative Process Tree (Sigma)
        type: sigma
        code: |
          title: ...
          detection:
            selection:
              ...
            condition: selection

We only extract the ``type: sigma`` blob. CAR analytics without a
sigma implementation are skipped silently (they have only
pseudocode / EQL / Splunk impls, none of which our evaluator can
execute today; surfacing them as failed rules would just be noise).

CAR analytic IDs ride along on the rule's ``tags`` list as
``car.CAR-YYYY-MM-NNN`` so per-finding provenance stays clear and
the existing tag→hypothesis mapping in sigma_engine still works.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from el.skills.sigma_engine import SigmaRule, load_rules as _load_sigma_rules


@dataclass
class CarAnalytic:
    """Compact projection of a CAR analytic — just the fields we
    actually use downstream. The full YAML is on disk if the
    analyst needs the pseudocode / Splunk / EQL implementations
    too."""
    car_id: str
    title: str
    description: str
    coverage: list[dict]            # [{technique, subtechnique, coverage}]
    sigma_code: str                 # the sigma YAML snippet ("" if absent)
    file_path: Path


def _extract_sigma_snippet(impls: list[dict] | None) -> str:
    """Return the first sigma-typed implementation's code field, or
    empty string when no sigma impl exists for this analytic."""
    for impl in impls or []:
        if not isinstance(impl, dict):
            continue
        if (impl.get("type") or "").lower() == "sigma":
            code = impl.get("code")
            if isinstance(code, str) and code.strip():
                return code
    return ""


def _coverage_to_attack_tags(coverage: list[dict] | None) -> list[str]:
    """Translate the CAR `coverage[]` block into SIGMA-style ATT&CK
    tags. CAR uses `technique: T1190` / `subtechnique: '001'` rather
    than the dotted T1190.001 SIGMA convention; normalise to the
    SIGMA form so the existing tag→hypothesis map applies."""
    tags: list[str] = []
    for entry in coverage or []:
        if not isinstance(entry, dict):
            continue
        tid = (entry.get("technique") or "").strip()
        sub = (entry.get("subtechnique") or "").strip()
        if not tid:
            continue
        full = f"{tid}.{sub}" if sub else tid
        tags.append(f"attack.t{full.lower().lstrip('t')}")
    return tags


def parse_analytic(path: Path) -> CarAnalytic | None:
    """Load one CAR YAML file, return a CarAnalytic. None on parse
    failure or missing required fields. Defensive: malformed YAML
    must not break the rest of the load loop."""
    try:
        with path.open() as f:
            doc = yaml.safe_load(f)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    car_id = str(doc.get("id") or "").strip()
    if not car_id or not car_id.upper().startswith("CAR-"):
        return None
    return CarAnalytic(
        car_id=car_id,
        title=str(doc.get("title") or doc.get("name") or car_id),
        description=str(doc.get("description") or "")[:500],
        coverage=list(doc.get("coverage") or []),
        sigma_code=_extract_sigma_snippet(doc.get("implementations")),
        file_path=path,
    )


def _materialise_sigma_yaml(analytic: CarAnalytic) -> str:
    """Stitch the CAR analytic's sigma snippet with ATT&CK tags +
    CAR provenance tag derived from the analytic's coverage block.
    Sigma snippets in CAR sometimes omit tags entirely; we inject
    them so the rule's ATT&CK coverage survives the sigma_engine
    parse and the rule provenance is visible at finding-time.
    """
    try:
        snippet = yaml.safe_load(analytic.sigma_code)
    except Exception:
        return ""
    if not isinstance(snippet, dict):
        return ""
    # Inject CAR provenance + coverage tags. Preserve any tags the
    # sigma impl already carries — union semantics, no clobber.
    existing_tags = [str(t) for t in (snippet.get("tags") or [])]
    car_tag = f"car.{analytic.car_id}"
    attack_tags = _coverage_to_attack_tags(analytic.coverage)
    merged = list(dict.fromkeys(existing_tags + [car_tag] + attack_tags))
    snippet["tags"] = merged
    # Force a deterministic rule id so duplicate analytics → duplicate
    # rules across runs land on the same finding_id seed downstream.
    snippet.setdefault("id", analytic.car_id)
    snippet.setdefault("title", analytic.title)
    snippet.setdefault("description", analytic.description)
    return yaml.safe_dump(snippet, sort_keys=False)


def load_car_rules(car_root: Path | str) -> list[SigmaRule]:
    """Walk a CAR analytics directory, materialise the sigma
    snippets into a temp directory, parse them with the existing
    SIGMA engine. Returns a list of SigmaRule objects — same shape
    the sigma_engine already produces, so the agent can concatenate
    these with the operator's regular sigma rule pack and run a
    single match pass.

    Empty CAR directory / no sigma snippets / parse failures all
    return an empty list (never raise). CAR analytics without a
    sigma impl are skipped silently — they have only pseudocode /
    Splunk / EQL impls that our evaluator can't run; surfacing them
    as failed rules would inflate the skipped-rule count for no
    forensic gain.
    """
    car_root = Path(car_root)
    if not car_root.exists():
        return []
    paths = ([car_root] if car_root.is_file()
             else sorted(car_root.rglob("*.yaml"))
                  + sorted(car_root.rglob("*.yml")))
    analytics: list[CarAnalytic] = []
    for p in paths:
        a = parse_analytic(p)
        if a is None:
            continue
        if not a.sigma_code.strip():
            continue
        analytics.append(a)
    if not analytics:
        return []
    # Write each analytic's sigma snippet to a temp dir, then load
    # via the existing engine. Using a temp dir (vs a single-file
    # multi-doc YAML) keeps file_path on each rule pointing at the
    # CAR analytic — visible to the operator in error messages /
    # debug logs.
    out: list[SigmaRule] = []
    with tempfile.TemporaryDirectory(prefix="el-car-") as td:
        td_path = Path(td)
        for a in analytics:
            rendered = _materialise_sigma_yaml(a)
            if not rendered:
                continue
            sigma_path = td_path / f"{a.car_id}.yml"
            sigma_path.write_text(rendered)
        out = _load_sigma_rules(td_path)
        # The rule.file_path is now a temp path that will vanish.
        # Rewrite it to the original CAR YAML on disk so a future
        # `el ledger` lookup or operator inspection finds the
        # actual source-of-truth file.
        car_path_by_id = {a.car_id: a.file_path for a in analytics}
        for rule in out:
            mapped = car_path_by_id.get(rule.id)
            if mapped is not None:
                rule.file_path = mapped
    return out


__all__ = ["CarAnalytic", "load_car_rules", "parse_analytic"]
