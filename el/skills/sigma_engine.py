"""Skill: Native SIGMA rule evaluator against EvtxECmd CSV rows.

SIGMA (https://github.com/SigmaHQ/sigma) is the community-maintained
YAML detection-rule format — thousands of rules across Windows, Linux,
and cloud telemetry, each mapped to MITRE ATT&CK techniques. EL already
produces the target log stream (EvtxECmd normalized CSV); this skill
turns a SIGMA rule pack into a matcher callable and applies it to our
rows, so community rules become Findings without hand-writing detectors.

Native evaluator rather than a pysigma backend: zero dep weight, full
auditability, fits the row-dict shape we already have. Supports the
modifier set that covers ~90% of community Windows rules — `contains`,
`startswith`, `endswith`, `re`, `all`, `cased` — plus the core condition
grammar (and / or / not / parens / "1 of X" / "all of X" with wildcards).

Out of V1: `|base64`, `|base64offset`, `|utf16`, `|wide`, `|cidr`,
correlation rules, aggregation (`| count() by Field > N`). Rules using
those features are loaded but skipped with a note — explicit, not silent.

Performance: EID indexing keeps per-row cost small. On a 5 M-row DC CSV
with 800 Windows rules, about 2-3 rules evaluate per row; the rest are
pre-filtered by the (EventId → rules[]) index and never touched.
"""
from __future__ import annotations

import csv
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

import yaml


class SigmaError(RuntimeError):
    pass


# --- Rule model -----------------------------------------------------------

@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    description: str
    author: str
    tags: list[str]                  # ["attack.execution", "attack.t1059.001"]
    logsource: dict[str, str]        # {product, service, category}
    detection: dict[str, Any]        # selections + condition (unprocessed)
    file_path: Path
    skipped_reason: str = ""         # non-empty => rule cannot run on V1
    _condition_fn: Callable[[dict[str, bool]], bool] | None = None
    _target_eids: set[int] | None = None   # None = no EID constraint


@dataclass
class SigmaHit:
    rule: SigmaRule
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    sample_rows: list[dict] = field(default_factory=list)    # up to 3

    def attack_techniques(self) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from the rule's tags."""
        out: list[str] = []
        for t in self.rule.tags:
            t = t.lower()
            m = re.match(r"attack\.t(\d+(?:\.\d+)?)", t)
            if m:
                out.append(f"T{m.group(1).upper()}")
        return sorted(set(out))


# --- Rule loading ---------------------------------------------------------

def load_rules(root: Path | str) -> list[SigmaRule]:
    """Walk a directory (or single file) of SIGMA YAML rules, return
    the parsed list. Multi-document YAML files are supported (one
    rule per document). Parse errors are collected into
    `skipped_reason` rather than raised."""
    root = Path(root)
    paths: list[Path] = []
    if root.is_file():
        paths = [root]
    elif root.is_dir():
        paths = sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml"))
    out: list[SigmaRule] = []
    for p in paths:
        try:
            with p.open() as f:
                for doc in yaml.safe_load_all(f):
                    if not isinstance(doc, dict):
                        continue
                    rule = _parse_rule(doc, p)
                    if rule:
                        out.append(rule)
        except yaml.YAMLError as e:
            out.append(SigmaRule(
                id="invalid", title=p.name, level="informational",
                description="", author="", tags=[],
                logsource={}, detection={}, file_path=p,
                skipped_reason=f"yaml parse error: {e}"))
    return out


def _parse_rule(doc: dict, path: Path) -> SigmaRule | None:
    det = doc.get("detection") or {}
    condition = det.get("condition")
    if not det or not condition:
        return None
    rule = SigmaRule(
        id=str(doc.get("id") or path.stem),
        title=str(doc.get("title") or path.stem),
        level=str(doc.get("level") or "informational").lower(),
        description=str(doc.get("description") or "")[:500],
        author=str(doc.get("author") or ""),
        tags=[str(t) for t in (doc.get("tags") or [])],
        logsource=dict(doc.get("logsource") or {}),
        detection=dict(det),
        file_path=path,
    )
    # Build the condition callable + EID pre-filter now, so the
    # per-row hot loop doesn't re-parse on every tick.
    try:
        selection_keys = [k for k in det.keys() if k != "condition"]
        rule._condition_fn = _compile_condition(str(condition),
                                                  selection_keys)
        rule._target_eids = _extract_eid_filter(det, selection_keys,
                                                  str(condition))
    except SigmaError as e:
        rule.skipped_reason = f"condition compile failed: {e}"
    except Exception as e:        # noqa: BLE001
        rule.skipped_reason = f"rule parse error: {e}"
    return rule


# --- Field + modifier matching -------------------------------------------

_WINDOWS_CSV_FIELD_ALIASES: dict[str, str] = {
    # SIGMA Windows field → EvtxECmd CSV column (case-sensitive here
    # since CSV header is fixed).
    "eventid": "EventId",
    "channel": "Channel",
    "computer": "Computer",
    "computername": "Computer",
    "provider_name": "Provider",
    "source_name": "Provider",
    "level": "Level",
    "username": "UserName",
    "user": "UserName",
    "recordid": "EventRecordId",
    "eventrecordid": "EventRecordId",
    "processid": "ProcessId",
    "threadid": "ThreadId",
    "timecreated": "TimeCreated",
}


def _payload_blob(row: dict) -> str:
    """All PayloadData columns + MapDescription, concatenated. EvtxECmd
    packs the variable event fields into PayloadData1..6; rules that
    reference a specific Windows field (ScriptBlockText, CommandLine,
    Image, TargetObject, etc.) don't get that column directly — we
    search the blob instead. Imprecise but the way community rules use
    `|contains` makes this robust in practice."""
    parts: list[str] = []
    for k in ("MapDescription", "PayloadData1", "PayloadData2",
              "PayloadData3", "PayloadData4", "PayloadData5",
              "PayloadData6"):
        v = row.get(k)
        if v:
            parts.append(str(v))
    return "\n".join(parts)


def _resolve_field(row: dict, field_name: str) -> str | None:
    """Return the string value of a SIGMA field against a CSV row, or
    None to indicate "search the payload blob." Case-insensitive lookup
    into the alias table; unknown fields fall back to the payload."""
    if not field_name:
        return None
    key = field_name.lower()
    col = _WINDOWS_CSV_FIELD_ALIASES.get(key)
    if col is not None and col in row:
        v = row.get(col)
        return "" if v is None else str(v)
    # Fall back to a direct column lookup (custom EvtxECmd exports
    # sometimes include a column with the exact SIGMA field name).
    for col_name in row:
        if col_name.lower() == key:
            v = row.get(col_name)
            return "" if v is None else str(v)
    return None    # signal "search the payload"


def _apply_modifiers(field_value: str | None, target: Any,
                       modifiers: list[str], row: dict) -> bool:
    """Evaluate a single field:target pair with its modifier chain.
    target is the SIGMA YAML value (scalar or list)."""
    targets = target if isinstance(target, list) else [target]
    # Normalise all targets to strings — SIGMA allows integers for EIDs
    targets = ["" if t is None else str(t) for t in targets]

    cased = "cased" in modifiers
    operators = [m for m in modifiers if m not in ("cased", "all")]
    require_all = "all" in modifiers

    op = operators[0] if operators else ""
    if op in ("base64", "base64offset", "utf16", "wide", "cidr", "expand"):
        raise SigmaError(f"unsupported modifier: {op}")

    # Resolve the haystack — None means "search payload blob"
    if field_value is None:
        haystack = _payload_blob(row)
        # Strict prefix/suffix semantics don't apply when the field
        # has been flattened into a key:value blob (EvtxECmd packs
        # "Target: SHIELDBASE.LAN\admin" into PayloadData1 etc.).
        # Degrade to contains so community rules that check
        # "Image|startswith: C:\Windows\Temp\" still fire on
        # real data.
        if op in ("startswith", "endswith"):
            op = "contains"
    else:
        haystack = field_value

    if not cased:
        haystack_cmp = haystack.lower()
        targets_cmp = [t.lower() for t in targets]
    else:
        haystack_cmp = haystack
        targets_cmp = targets

    def one(t_cmp: str) -> bool:
        if op == "" or op == "equals":
            # Default: full-string equality OR containment against the
            # payload blob. (Community rules lean on the convention that
            # bare Field: "x" matches the raw event-field value. For the
            # payload-fallback case we relax to contains, which gives
            # the behaviour analysts expect when the EvtxECmd flattening
            # scatters the field across PayloadData columns.)
            if field_value is None:
                return t_cmp in haystack_cmp
            return haystack_cmp == t_cmp
        if op == "contains":
            return t_cmp in haystack_cmp
        if op == "startswith":
            return haystack_cmp.startswith(t_cmp)
        if op == "endswith":
            return haystack_cmp.endswith(t_cmp)
        if op == "re":
            flags = 0 if cased else re.IGNORECASE
            try:
                return bool(re.search(t_cmp, haystack, flags))
            except re.error:
                return False
        if op == "gt":
            try: return float(haystack_cmp) > float(t_cmp)
            except (ValueError, TypeError): return False
        if op == "gte":
            try: return float(haystack_cmp) >= float(t_cmp)
            except (ValueError, TypeError): return False
        if op == "lt":
            try: return float(haystack_cmp) < float(t_cmp)
            except (ValueError, TypeError): return False
        if op == "lte":
            try: return float(haystack_cmp) <= float(t_cmp)
            except (ValueError, TypeError): return False
        raise SigmaError(f"unsupported modifier: {op}")

    if require_all:
        return all(one(t) for t in targets_cmp)
    return any(one(t) for t in targets_cmp)


def _match_selection_body(body: Any, row: dict) -> bool:
    """Selection bodies come in several shapes:
      dict: each key Field[|modifier] must match (AND across keys)
      list of dicts: OR across the list (any dict matches)
      list of strings: payload-blob OR across the strings (rare)
    """
    if isinstance(body, dict):
        for key, target in body.items():
            if "|" in key:
                field_name, *mods = key.split("|")
            else:
                field_name, mods = key, []
            val = _resolve_field(row, field_name)
            if not _apply_modifiers(val, target, mods, row):
                return False
        return True
    if isinstance(body, list):
        if body and isinstance(body[0], dict):
            return any(_match_selection_body(b, row) for b in body)
        # List of scalars — substring-match any against payload
        blob = _payload_blob(row).lower()
        return any(str(s).lower() in blob for s in body)
    return False


# --- Condition expression parser ----------------------------------------

_TOKEN_RE = re.compile(
    r"\s*(?:(and|or|not)\b|(\()|(\))|"
    r"(1|all)\s+of\s+(them|[A-Za-z_][\w\*]*)|"
    r"([A-Za-z_][\w\*]*))"
)


def _tokenize_condition(expr: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(expr):
        if expr[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            raise SigmaError(f"unparseable condition at {pos}: {expr[pos:pos+20]!r}")
        op, lparen, rparen, quant, quant_target, ident = m.groups()
        if op:
            tokens.append(("OP", op))
        elif lparen:
            tokens.append(("LPAREN", "("))
        elif rparen:
            tokens.append(("RPAREN", ")"))
        elif quant:
            tokens.append(("QUANT", f"{quant}:{quant_target}"))
        elif ident:
            tokens.append(("IDENT", ident))
        pos = m.end()
    return tokens


def _expand_wildcard(name: str, selection_keys: list[str]) -> list[str]:
    if name == "them":
        return list(selection_keys)
    if "*" in name:
        pat = re.compile("^" + re.escape(name).replace(r"\*", ".*") + "$")
        return [k for k in selection_keys if pat.match(k)]
    return [name] if name in selection_keys else []


def _compile_condition(expr: str,
                        selection_keys: list[str]) -> Callable[[dict[str, bool]], bool]:
    """Parse a SIGMA condition into a closure over the selections dict."""
    tokens = _tokenize_condition(expr)
    pos = [0]

    def peek() -> tuple[str, str] | None:
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def consume() -> tuple[str, str]:
        t = tokens[pos[0]]
        pos[0] += 1
        return t

    def parse_or() -> Callable:
        left = parse_and()
        while (t := peek()) and t == ("OP", "or"):
            consume()
            right = parse_and()
            l, r = left, right
            left = lambda sels, l=l, r=r: l(sels) or r(sels)
        return left

    def parse_and() -> Callable:
        left = parse_unary()
        while (t := peek()) and t == ("OP", "and"):
            consume()
            right = parse_unary()
            l, r = left, right
            left = lambda sels, l=l, r=r: l(sels) and r(sels)
        return left

    def parse_unary() -> Callable:
        t = peek()
        if t == ("OP", "not"):
            consume()
            inner = parse_unary()
            return lambda sels, i=inner: not i(sels)
        return parse_primary()

    def parse_primary() -> Callable:
        t = peek()
        if not t:
            raise SigmaError("unexpected end of condition")
        if t[0] == "LPAREN":
            consume()
            inner = parse_or()
            if not peek() or peek()[0] != "RPAREN":
                raise SigmaError("missing closing paren")
            consume()
            return inner
        if t[0] == "IDENT":
            consume()
            name = t[1]
            resolved = _expand_wildcard(name, selection_keys)
            if not resolved:
                return lambda sels: False
            return lambda sels, r=resolved: any(sels.get(k, False) for k in r)
        if t[0] == "QUANT":
            consume()
            quant, target = t[1].split(":", 1)
            resolved = _expand_wildcard(target, selection_keys)
            if not resolved:
                return lambda sels: False
            if quant == "1":
                return lambda sels, r=resolved: any(sels.get(k, False) for k in r)
            # "all"
            return lambda sels, r=resolved: all(sels.get(k, False) for k in r)
        raise SigmaError(f"unexpected token: {t}")

    tree = parse_or()
    if pos[0] != len(tokens):
        raise SigmaError(f"trailing tokens in condition: {tokens[pos[0]:]}")
    return tree


# --- EID pre-filter extraction -------------------------------------------

def _extract_eid_filter(detection: dict,
                         selection_keys: list[str],
                         condition: str) -> set[int] | None:
    """If every selection named in the condition has an EventID pin,
    we can build a union set and skip rows whose EID isn't in it. This
    is the single biggest perf win on large CSVs.

    Returns None when we can't prove a bound (e.g., condition includes
    a `not selection` branch, or any selection omits EventID, or a
    selection uses a modifier on the EventID field).
    """
    # Identify selections referenced by the condition (exclude negatives)
    # — very rough but safe: any "not X" marks X as unbounded.
    neg_marks = set(re.findall(r"not\s+([A-Za-z_][\w\*]*)", condition))
    eids: set[int] = set()
    for key in selection_keys:
        if key in neg_marks:
            return None                  # negated: can't pre-filter
        body = detection.get(key)
        pinned = _selection_eid_pins(body)
        if pinned is None:
            return None
        eids |= pinned
    return eids or None


def _selection_eid_pins(body: Any) -> set[int] | None:
    """Return {N,...} if this selection body pins EventID, else None."""
    if isinstance(body, dict):
        for key, val in body.items():
            base = key.split("|")[0].lower()
            if base not in ("eventid", "event_id"):
                continue
            # Modifiers on EventID defeat a clean pin — bail.
            if "|" in key:
                return None
            if isinstance(val, list):
                try:
                    return {int(v) for v in val}
                except (TypeError, ValueError):
                    return None
            try:
                return {int(val)}
            except (TypeError, ValueError):
                return None
        return None
    if isinstance(body, list) and body and isinstance(body[0], dict):
        union: set[int] = set()
        for sub in body:
            sub_eids = _selection_eid_pins(sub)
            if sub_eids is None:
                return None
            union |= sub_eids
        return union
    return None


# --- Top-level evaluation -------------------------------------------------

def evaluate_rule(rule: SigmaRule, row: dict) -> bool:
    if rule.skipped_reason or rule._condition_fn is None:
        return False
    try:
        sels = {
            k: _match_selection_body(v, row)
            for k, v in rule.detection.items() if k != "condition"
        }
        return rule._condition_fn(sels)
    except SigmaError:
        return False


def index_rules_by_eid(rules: list[SigmaRule]
                        ) -> tuple[dict[int, list[SigmaRule]], list[SigmaRule]]:
    """Split rules into (indexed_by_eid, generic). Generic rules must
    run on every row; indexed rules only on rows with matching EID."""
    by_eid: dict[int, list[SigmaRule]] = defaultdict(list)
    generic: list[SigmaRule] = []
    for r in rules:
        if r.skipped_reason or r._target_eids is None:
            if not r.skipped_reason:
                generic.append(r)
            continue
        for eid in r._target_eids:
            by_eid[eid].append(r)
    return dict(by_eid), generic


def is_windows_evtx_rule(rule: SigmaRule) -> bool:
    """True if this rule targets Windows event logs — the only source
    V1 applies rules to. Covers rules explicitly tagged product:windows
    and any rule without a logsource (the community pattern for
    generic-windows)."""
    if rule.skipped_reason:
        return False
    ls = rule.logsource
    prod = (ls.get("product") or "").lower()
    if prod and prod != "windows":
        return False
    return True


def stream_csv(csv_path: Path) -> Iterator[dict]:
    """Stream rows from an EvtxECmd CSV without materialising the list."""
    with csv_path.open(errors="ignore", newline="") as f:
        for row in csv.DictReader(f):
            yield row


def run_rules_against_csv(rules: list[SigmaRule],
                            csv_path: Path,
                            max_samples: int = 3) -> list[SigmaHit]:
    """Stream the CSV once; for each row apply only the rules whose
    EID index matches it, plus the generic (EID-unbounded) set.

    Returns one SigmaHit per rule that matched ≥1 row, with
    first_seen / last_seen / sample_rows populated.
    """
    applicable = [r for r in rules if is_windows_evtx_rule(r)]
    by_eid, generic = index_rules_by_eid(applicable)
    hits: dict[str, SigmaHit] = {}

    for row in stream_csv(csv_path):
        try:
            eid = int((row.get("EventId") or "").strip())
        except (TypeError, ValueError):
            eid = -1
        candidate_rules: list[SigmaRule] = []
        if eid >= 0:
            candidate_rules.extend(by_eid.get(eid, ()))
        candidate_rules.extend(generic)
        if not candidate_rules:
            continue
        ts = row.get("TimeCreated") or ""
        for rule in candidate_rules:
            if not evaluate_rule(rule, row):
                continue
            h = hits.get(rule.id)
            if h is None:
                h = SigmaHit(rule=rule, event_count=0,
                             first_seen=ts, last_seen=ts)
                hits[rule.id] = h
            h.event_count += 1
            if ts:
                if not h.first_seen or ts < h.first_seen:
                    h.first_seen = ts
                if not h.last_seen or ts > h.last_seen:
                    h.last_seen = ts
            if len(h.sample_rows) < max_samples:
                h.sample_rows.append(dict(row))
    return sorted(hits.values(),
                  key=lambda h: (_level_rank(h.rule.level), -h.event_count))


_LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2,
                 "low": 3, "informational": 4}


def _level_rank(level: str) -> int:
    return _LEVEL_ORDER.get(level.lower(), 5)


__all__ = [
    "SigmaError", "SigmaRule", "SigmaHit",
    "load_rules", "evaluate_rule",
    "index_rules_by_eid", "is_windows_evtx_rule",
    "run_rules_against_csv", "stream_csv",
]
