"""Generate provenance-stamped lexicon data modules for el.narcotic_lexicon.

Two authoritative sources, two registers:

  * INCB Yellow List (64th ed.) — controlled-substance INNs (Schedules
    I/II/IV of the 1961 Single Convention). Emits Tier-B substance names,
    split by false-positive risk:
        SPECIFIC_INN — designer fentanyl/nitazene analogues + obscure NPS;
                       near-zero benign-text incidence → standalone-strong.
        COMMON_INN   — classic opiates + all other scheduled INNs;
                       appear in medical/news text → co-occurrence gated.
    Erring toward COMMON is the conservative (low-FP) choice.

  * NIST OSAC Lexicon — forensic-science terminology. NOT a positive
    narcotic signal (it is the analyst's microscope/QA vocabulary).
    Emits STOP_TERMS: single-word lab jargon used as a build-time guard
    so FP-prone words (tablets, grains, nuggets, habit, …) can never be
    added to the positive slang/INN vocabulary. ALLOW carries the handful
    of real substance names OSAC also defines (e.g. cocaine).

Reproducible: re-run against the two source files; the sha256s in each
emitted module's header pin the exact inputs used.
"""
from __future__ import annotations

import csv
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

YL_TXT = Path("/opt/EL/analysis/yl64.txt")          # pdftotext -layout of YL_64th_E.pdf
YL_PDF = Path("/media/sansforensics/images/YL_64th_E.pdf")
OSAC = Path("/media/sansforensics/images/osac_lexicon_export_1779907216.csv")
OUT = Path("/opt/EL/el/skills")


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


# --------------------------------------------------------------------------
# Yellow List INN extraction
# --------------------------------------------------------------------------
IDS_RX = re.compile(r"^\s*N[A-Z]{1,2}\s?\d{3}\b")
CAS_RX = re.compile(r"\b\d{2,7}-\d{2}-\d\b")
RANGES = [(107, 540), (552, 567), (574, 600)]  # Schedule I / II / IV tables


def _is_name_token(tok: str) -> bool:
    letters = [c for c in tok if c.isalpha()]
    return bool(letters) and all(c.isupper() for c in letters)


def _name_phrase(rest: str) -> str:
    out = []
    for t in rest.split():
        if _is_name_token(t):
            out.append(t)
        else:
            break
    return " ".join(out).strip(" ,")


def extract_inns() -> list[str]:
    lines = YL_TXT.read_text(encoding="utf-8", errors="replace").splitlines()
    cand: list[str] = []
    for a, b in RANGES:
        prev = None
        for ln in lines[a - 1 : b - 1]:
            if not ln.strip() or "NARCOTIC DRUG" in ln or "IDS CODE" in ln:
                continue
            has_ids = bool(IDS_RX.search(ln))
            cas = CAS_RX.search(ln)
            if has_ids or cas:
                rest = CAS_RX.sub("", ln)
                rest = IDS_RX.sub("", rest, count=1)
                nm = _name_phrase(rest.strip())
                if nm:
                    cand.append(nm)
                    prev = len(cand) - 1
            else:
                frag = _name_phrase(ln.strip())
                if frag and prev is not None and frag == ln.strip().strip(" ,"):
                    if cand[prev].endswith("-"):
                        cand[prev] = cand[prev] + frag
                    else:
                        cand[prev] = cand[prev] + " " + frag
    return cand


# parse-artifact cleanup → canonical names (documented, deterministic)
DROP_EXACT = {
    "BETA-HYDROXY-3-", "CONCENTRATE OF POPPY STRAW", "MORAMIDE INTERMEDIATE",
    "METHADONE INTERMEDIATE", "PETHIDINE INTERMEDIATE A",
    "PETHIDINE INTERMEDIATE B", "PETHIDINE INTERMEDIATE C",
}
REMAP = {
    "N/A N-PYRROLIDINO METONITAZENE": ["N-PYRROLIDINO METONITAZENE"],
    "NC-092 CROTONYLFENTANYL": ["CROTONYLFENTANYL"],
    "NM MORPHINE METHOBROMIDE AND OTHER PENTAVALENT NITROGEN MORPHINE":
        ["MORPHINE METHOBROMIDE"],
    "ACETYLMETHADOL (ACRYLFENTANYL)": ["ACETYLMETHADOL", "ACRYLOYLFENTANYL"],
    "RACEMORPHAN4": ["RACEMORPHAN"],
    "CANNABIS RESIN, EXTRACTS": ["CANNABIS RESIN"],
}


def clean(cands: list[str]) -> set[str]:
    out: set[str] = set()
    for c in cands:
        c = re.sub(r"\s+", " ", c).strip().strip(" ,")
        if "+" in c or c.startswith("CPS ") or c in DROP_EXACT or len(c) < 3:
            continue
        if c in REMAP:
            out.update(REMAP[c])
            continue
        out.add(c)
    return {x.lower() for x in out}


# Tier classification --------------------------------------------------------
# Medical fentanils that DO appear in benign clinical text → keep COMMON.
_MEDICAL_FENTANILS = {"fentanyl", "sufentanil", "alfentanil", "remifentanil"}
# Obscure NPS that are not -fentanil/-nitazene by name but are designer-only.
_OTHER_SPECIFIC = {
    "brorphine", "ah-7921", "mt-45", "u-47700", "2-methyl-ap-237",
    "mppp", "pepap", "etazene", "n-desethyl isotonitazene",
    "n-pyrrolidino protonitazene", "n-pyrrolidino metonitazene",
}


def is_specific(name: str) -> bool:
    if name in _MEDICAL_FENTANILS:
        return False
    if name.endswith(("fentanyl", "fentanil")):
        return True
    if "nitazene" in name or name.endswith(("nitazepyne", "nitazepipne")):
        return True
    return name in _OTHER_SPECIFIC


def emit_yellow_list() -> None:
    inns = clean(extract_inns())
    specific = sorted(n for n in inns if is_specific(n))
    common = sorted(n for n in inns if not is_specific(n))
    hdr = (
        '"""GENERATED — do not edit by hand. Regenerate with '
        "scripts/gen_lexicon_data.py.\n\n"
        "Controlled-substance INNs from the INCB Yellow List, 64th edition\n"
        "(List of Narcotic Drugs under International Control, 1961 Single\n"
        "Convention Schedules I/II/IV). The authoritative substance-name\n"
        "register for el.narcotic_lexicon Tier B.\n\n"
        f"  source_pdf      : {YL_PDF}\n"
        f"  source_pdf_sha  : {sha256(YL_PDF)}\n"
        f"  pdftotext_sha   : {sha256(YL_TXT)}\n"
        f"  generated_utc   : {datetime.now(timezone.utc).isoformat()}\n\n"
        "SPECIFIC_INN: designer fentanyl/nitazene analogues + obscure NPS —\n"
        "  near-zero benign-text incidence, treated as standalone-strong.\n"
        "COMMON_INN: classic opiates + all other scheduled INNs — appear in\n"
        "  medical/news text, so co-occurrence gated (never fire alone).\n"
        '"""\n'
    )
    body = (
        "from __future__ import annotations\n\n"
        "SPECIFIC_INN: tuple[str, ...] = (\n"
        + "".join(f"    {n!r},\n" for n in specific)
        + ")\n\n"
        "COMMON_INN: tuple[str, ...] = (\n"
        + "".join(f"    {n!r},\n" for n in common)
        + ")\n"
    )
    (OUT / "_yellow_list_inn.py").write_text(hdr + body, encoding="utf-8")
    print(f"_yellow_list_inn.py: {len(specific)} specific, {len(common)} common")


# --------------------------------------------------------------------------
# OSAC stop-list
# --------------------------------------------------------------------------
def emit_osac_stoplist() -> None:
    terms: set[str] = set()
    with OSAC.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if not row:
                continue
            t = row[0].strip().strip('"').lower()
            if re.fullmatch(r"[a-z]{3,}", t):
                terms.add(t)
    stop = sorted(terms)
    # real substances OSAC also defines — must stay matchable as signal
    allow = ("cocaine",)
    hdr = (
        '"""GENERATED — do not edit by hand. Regenerate with '
        "scripts/gen_lexicon_data.py.\n\n"
        "Single-word NIST OSAC Lexicon terms (forensic-science / lab QA\n"
        "vocabulary). NOT positive narcotic signal — used as a build-time\n"
        "guard so FP-prone lab jargon (tablets, grains, nuggets, habit, …)\n"
        "can never be added to the positive slang/INN vocabulary. ALLOW\n"
        "lists substance names OSAC also defines that ARE legitimate signal.\n\n"
        f"  source_csv  : {OSAC}\n"
        f"  source_sha  : {sha256(OSAC)}\n"
        f"  generated_utc : {datetime.now(timezone.utc).isoformat()}\n"
        '"""\n'
    )
    body = (
        "from __future__ import annotations\n\n"
        "ALLOW: frozenset[str] = frozenset({\n"
        + "".join(f"    {a!r},\n" for a in allow)
        + "})\n\n"
        "STOP_TERMS: frozenset[str] = frozenset({\n"
        + "".join(f"    {t!r},\n" for t in stop)
        + "})\n"
    )
    (OUT / "_osac_stoplist.py").write_text(hdr + body, encoding="utf-8")
    print(f"_osac_stoplist.py: {len(stop)} stop terms, {len(allow)} allow")


if __name__ == "__main__":
    emit_yellow_list()
    emit_osac_stoplist()
