"""Skill: scan text/files for narcotic-trade lexicon markers.

Surfaces the vocabulary that identifies a user-side drug-sale operation
(strain names, slang for cocaine/meth/mdma, unit/weight markers, emoji
ciphers). Deliberately narrow — this is NOT an attempt to enumerate all
drug-related language, only the tokens that are genuinely uncommon in
legitimate DFIR text and repeat across multiple casework scenarios.

Motivation: BelkaCTF Kidnapper — Ivan's `.mynote/` directory, Firefox
history (x-tux-0.web.app vendor panel), and Thunderbird attachments held
strain names and gram/oz weight markers that never surfaced to the
investigator because no detector looked for them.

Three registers, distinct sources:

  Tier A — slang / strain names (curated from open-source narcotics-market
    ground-truth corpora: DarkNetMarkets listings, AlphaBay / Hansa
    indictment exhibits; register matches DEA DIR-020-17 "Slang Terms and
    Code Words"). The "how a dealer writes" vocabulary.
  Tier B — controlled-substance INNs from the INCB Yellow List, 64th ed.
    (1961 Single Convention Schedules I/II/IV). SPECIFIC designer analogues
    (fentanyl/nitazene NPS) are standalone-strong; COMMON classic opiates
    appear in medical/news text and only count with co-occurrence. See
    el/skills/_yellow_list_inn.py (generated, sha256-pinned to the source).
  Stop-list — NIST OSAC Lexicon forensic-science terminology is NOT positive
    signal (it is the analyst's microscope/QA vocabulary). It guards, at
    build time, against FP-prone lab jargon (tablets, grains, nuggets, …)
    leaking into the positive vocabulary. See el/skills/_osac_stoplist.py.

It is not meant to flag every drug mention in user text, only to raise the
probability that a concentrated cluster IS a dealing operation.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem
from el.skills._osac_stoplist import ALLOW as _OSAC_ALLOW
from el.skills._osac_stoplist import STOP_TERMS as _OSAC_STOP
from el.skills._yellow_list_inn import COMMON_INN as _INN_COMMON
from el.skills._yellow_list_inn import SPECIFIC_INN as _INN_SPECIFIC


# Strain / product names — popular cannabis strains + stimulant/
# entheogen street names. Whole-word match (\b) to avoid substring
# false positives (e.g., "bliss" inside "oblivious").
_STRAIN_WORDS = (
    # Cannabis strains
    "acapulco gold", "alaskan thunder", "ak-47",
    "blue dream", "bubba kush", "chemdawg", "cookies",
    "durban poison", "girl scout cookies", "gorilla glue",
    "granddaddy purple", "green crack", "haze",
    "jack herer", "kush", "lemon haze",
    "mexican sativa", "northern lights", "og kush", "pineapple express",
    "purple haze", "sour diesel", "tangie", "trainwreck",
    "white widow", "zkittlez",
    # Stimulants / entheogens street names
    "molly", "mdma", "ecstasy", "x-pills",
    "addy", "adderall", "ritalin",
    "tina", "crystal meth", "ice meth",
    "snow", "blow", "coke rock", "yayo",
    # Opioids
    "blues", "percs", "oxy", "oxys", "oxycontin",
    "fenty", "fent", "china white",
)

# Unit / weight markers commonly used in sales listings — these are the
# "math of dealing" tokens. Must appear inside a price/quantity context.
_UNIT_RX = re.compile(
    r"\b(?:"
    r"\d+(?:\.\d+)?\s?(?:g|gr|gm|grams?|oz|ounces?|qp|hp|lb|lbs|pounds?|kilo|kg|ki)\b"
    r"|"
    r"(?:\beighth|quarter|half[- ]?oz|qp|hp)\b"
    r")",
    re.IGNORECASE,
)

# Price+unit co-occurrence (e.g., "$80/g", "50 per gram", "200 an oz")
_PRICE_PER_UNIT_RX = re.compile(
    r"\$?\s?\d{1,4}\s?(?:/|per|an?)\s?"
    r"(?:g\b|gm\b|gr\b|gram[s]?\b|oz\b|ounce[s]?\b|eighth\b|qp\b|hp\b)",
    re.IGNORECASE,
)

# Emoji / icon cipher markers common on darknet vendor pages.
_EMOJI_CODES = ("❄", "🍁", "💊", "🌿", "💎", "🔥", "🍫")


# Tier B — controlled-substance INNs from the INCB Yellow List (64th ed.).
# SPECIFIC = designer fentanyl/nitazene analogues + obscure NPS (near-zero
# benign incidence, standalone-strong); COMMON = classic opiates + all other
# scheduled INNs (medical/news text → co-occurrence gated). Match as phrases
# with word boundaries that tolerate the hyphens/spaces in INN names.
def _inn_regex(names: tuple[str, ...]) -> re.Pattern[str]:
    alts = sorted((re.escape(n).replace(r"\ ", r"\s+") for n in names),
                  key=len, reverse=True)
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(alts) + r")(?![a-z0-9])",
                      re.IGNORECASE)


_INN_SPECIFIC_RX = _inn_regex(_INN_SPECIFIC)
_INN_COMMON_RX = _inn_regex(_INN_COMMON)

# OSAC stop-list guard (build-time): the positive slang/strain vocabulary must
# never collide with NIST OSAC forensic-lab jargon (tablets, grains, nuggets,
# habit, …), minus the substances OSAC also defines (cocaine). Catches FP-prone
# additions before they ship. See el/skills/_osac_stoplist.py for provenance.
_OSAC_GUARD = _OSAC_STOP - _OSAC_ALLOW
_strain_single = {w for w in _STRAIN_WORDS if " " not in w}
assert not (_strain_single & _OSAC_GUARD), (
    "narcotic strain vocabulary collides with OSAC forensic-lab jargon: "
    f"{sorted(_strain_single & _OSAC_GUARD)} — these are ambiguous lab terms, "
    "not dealing signal; remove or qualify with co-occurrence."
)


@dataclass
class NarcoticMatch:
    path: Path
    strain_hits: list[str] = field(default_factory=list)
    unit_hits: list[str] = field(default_factory=list)
    price_hits: list[str] = field(default_factory=list)
    emoji_hits: list[str] = field(default_factory=list)
    # Tier-B controlled-substance INN hits (Yellow List). specific = designer
    # analogues (standalone-strong); common = gated classic opiates.
    substance_hits: list[str] = field(default_factory=list)

    @property
    def total_hits(self) -> int:
        return (len(self.strain_hits) + len(self.unit_hits)
                + len(self.price_hits) + len(self.emoji_hits)
                + len(self.substance_hits))

    @property
    def signal_strength(self) -> str:
        """high if ≥2 categories co-occur with ≥3 strain hits OR ≥2 price
        hits OR any designer-analogue (specific) INN; medium otherwise."""
        cats = sum(1 for x in (self.strain_hits, self.unit_hits,
                                self.price_hits, self.emoji_hits,
                                self.substance_hits) if x)
        has_specific = any(s in _INN_SPECIFIC for s in self.substance_hits)
        if cats >= 2 and (len(self.strain_hits) >= 3
                          or len(self.price_hits) >= 2 or has_specific):
            return "high"
        return "medium"

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        seed = (str(self.path) + "|"
                + "|".join(sorted(self.strain_hits + self.unit_hits
                                    + self.price_hits + self.emoji_hits
                                    + self.substance_hits))
                ).encode()
        sha = hashlib.sha256(seed).hexdigest()
        f = {"path": str(self.path), "total_hits": self.total_hits,
             "strain_hits": self.strain_hits[:10],
             "unit_hits": self.unit_hits[:10],
             "price_hits": self.price_hits[:10],
             "emoji_hits": self.emoji_hits[:10],
             "substance_hits": self.substance_hits[:10]}
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="el.narcotic_lexicon", version="0.1.0",
            command=f"scan({self.path.name})",
            output_sha256=sha, output_path=str(self.path),
            extracted_facts=f,
        )


def scan_text(text: str, source: Path | None = None) -> NarcoticMatch | None:
    """Scan *text*. Return a match ONLY when at least one category fires AND
    the total-hits count is ≥ 2 (a single 'kush' reference on its own is
    not evidence of dealing)."""
    if not text:
        return None
    lower = text.lower()
    strain_hits = [w for w in _STRAIN_WORDS
                   if re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", lower)]
    unit_hits = _UNIT_RX.findall(text)[:20]
    price_hits = _PRICE_PER_UNIT_RX.findall(text)[:20]
    emoji_hits = [e for e in _EMOJI_CODES if e in text]

    # Tier B — Yellow List controlled-substance INNs.
    specific = sorted({h.lower() for h in _INN_SPECIFIC_RX.findall(lower)})
    # COMMON INNs (cocaine, morphine, fentanyl, …) appear in medical/news
    # text, so they only count when another narcotic register is already
    # present — they corroborate, they don't fire alone.
    has_other = bool(strain_hits or unit_hits or price_hits
                     or emoji_hits or specific)
    common = (sorted({h.lower() for h in _INN_COMMON_RX.findall(lower)})
              if has_other else [])
    substance_hits = specific + common

    m = NarcoticMatch(
        path=source or Path("<text>"),
        strain_hits=strain_hits, unit_hits=unit_hits,
        price_hits=price_hits, emoji_hits=emoji_hits,
        substance_hits=substance_hits[:20],
    )
    if m.total_hits < 2:
        return None
    return m


_TEXT_EXTS = frozenset({
    ".txt", ".md", ".rtf", ".log", ".csv", ".tsv",
    ".json", ".yaml", ".yml", ".ini", ".conf",
    ".html", ".htm", ".xml",
    ".odt", ".eml",   # odt/eml are zipped/structured but contain plaintext blobs
})


def walk_files(root: Path, max_bytes_per_file: int = 1_000_000,
               max_files: int = 2000) -> list[NarcoticMatch]:
    """Walk *root* and scan every plausible text file (by extension).

    Files larger than *max_bytes_per_file* are read in a single slice of
    that size (header-only scan — narcotics markers usually cluster near
    the top of notes/orders files).
    """
    hits: list[NarcoticMatch] = []
    scanned = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in _TEXT_EXTS:
            continue
        scanned += 1
        if scanned > max_files:
            break
        try:
            data = p.read_bytes()[:max_bytes_per_file]
            text = data.decode("utf-8", errors="replace")
        except OSError:
            continue
        m = scan_text(text, source=p)
        if m is not None:
            hits.append(m)
    return hits
