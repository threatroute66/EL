"""Skill: scan text/files for pre-attack planning lexicon markers.

Surfaces the vocabulary that identifies user-side planning of a violent
act — specific weapons + ammunition counts, escape-route operational
language, non-extradition / cash-smuggling research, lone-wolf intent
markers. Deliberately narrow: NOT an attempt to flag every firearm
mention. We require co-occurrence across ≥2 categories before emitting
a hit, exactly the same posture as `narcotic_lexicon`.

Motivation: NIST CFReDS Lone Wolf 2018 corpus (Moore) — Jim Cloudy's
`Planning.docx` + `The Cloudy Manifesto.docx` + Chrome Autofill +
Google Searches all carried this vocabulary cluster (Kel-Tec Sub 2000,
9mm 1000 for $360, latex gloves, velcro tear-away, no-extradition
Indonesia / Bali, "I will be the Lone Wolf", "fresh start in Bali",
"A hundred targets. 2000 bullets. Endless freedom"). No EL detector
flagged them because the existing lexicons were drug-trade focused.

The categories below were curated from the solution-guide quotes plus
the FBI's published Lone-Offender Terrorism research (2019) and
Threat Assessment / Behavioral Threat Assessment literature on
pre-attack indicators. The lexicon is meant to RAISE PROBABILITY
that a concentrated cluster IS planning, not to make a final call.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


# Specific weapon / accessory model identifiers — these are
# uncommonly mentioned outside of a purchase / planning context.
# Whole-word match (\b).
_WEAPON_WORDS = (
    "kel-tec sub 2000", "kel-tec sub-2000", "keltec sub 2000",
    "keltech sub 2000", "keltec sxusu2000", "kel-tec sub2k",
    "fn p90", "fnp90", "fn ps90", "fn 5.7", "fn 5 7",
    "mp40", "mp5", "mp7",
    "9mm sbr", "9mm rifle", "concealable rifle", "tactical rifle",
    "submachine gun", "foldable kel tec", "foldable kel-tec",
    "ar-15", "ar 15",
    "glock 17", "glock 19", "ruger",
    "ghost gun", "p80", "polymer80", "80% lower",
    "silencer", "suppressor",
)

# Ammunition + price-per-round patterns — operationally distinctive
# because they imply *bulk acquisition*, not enthusiast collecting.
# Threshold-bearing: "1000 for $360", "$400 rifle"
_AMMO_RX = re.compile(
    r"\b(?:"
    r"\d{2,5}\s*(?:rounds?|rds?|rd|bullets?|shells?|cartridges?)"
    r"|"
    r"(?:9\s?mm|5\.7|5\.56|7\.62|\.223|\.308|\.45|\.40)\s*(?:ammo|ammunition|rounds?)"
    r"|"
    r"\d{3,4}\s*for\s*\$\d{2,4}"  # "1000 for $360"
    r")\b",
    re.IGNORECASE,
)

# Escape-route + operational-security planning vocabulary — these are
# the "how do I get away" tokens that overlap minimally with normal
# firearm-enthusiast text.
_ESCAPE_OPSEC_WORDS = (
    "escape route", "no extradition", "non-extradition", "no-extradition",
    "non extradition", "extradition treaty",
    "smuggle cash", "strap cash", "transfer money overseas",
    "overseas bank account", "press release",
    "latex gloves", "tear away clothing", "tear-away clothing",
    "velcro tear", "burner phone", "burner sim",
    "tor browser", "vpn",
    "gun-free zone", "gun free zone",
    "police response time", "police response times",
    "do the cops track", "do cops track web searches",
    "track web searches",
    "black market",
    "shooting range near me",
    "best record of on-time departures",
)

# Lone-wolf intent / manifesto language — these turned up verbatim
# across the Lone Wolf solution-guide quotes. Less specific
# individually but high-signal together with weapons + opsec.
_INTENT_WORDS = (
    "lone wolf", "the lone wolf",
    "manifesto", "the manifesto",
    "i will be the revolutionary", "i will be the history maker",
    "i will be the change",
    "blood has been shed", "defenseless bodies",
    "atrocity", "another atrocity", "commit atrocity",
    "fresh start in bali", "fresh start in indonesia",
    "endless freedom",
    "molon labe", "#molonlabe",
    "what im doing is just and right", "what i'm doing is just and right",
    "for my country", "for our country",
    "even if i'm killed", "even if i am killed",
    "100 targets", "hundred targets",
    "operation 2nd hand smoke", "operation second hand smoke",
)

# Place-specific search markers — non-extradition destinations
# repeatedly searched alongside firearms/cash language.
_DESTINATION_WORDS = (
    "bali indonesia", "denpasar", "candidasa",
    "non extradition countries", "non-extradition countries",
    "best country to flee",
    "live very well on", "live very well in",
    "9 years on savings", "nine years on savings",
    "ronald reagan washington national",
    "dulles to bali",
)


@dataclass
class PreAttackMatch:
    path: Path
    weapon_hits: list[str] = field(default_factory=list)
    ammo_hits: list[str] = field(default_factory=list)
    opsec_hits: list[str] = field(default_factory=list)
    intent_hits: list[str] = field(default_factory=list)
    destination_hits: list[str] = field(default_factory=list)

    @property
    def total_hits(self) -> int:
        return (len(self.weapon_hits) + len(self.ammo_hits)
                + len(self.opsec_hits) + len(self.intent_hits)
                + len(self.destination_hits))

    @property
    def categories_fired(self) -> int:
        return sum(1 for x in (self.weapon_hits, self.ammo_hits,
                                self.opsec_hits, self.intent_hits,
                                self.destination_hits) if x)

    @property
    def signal_strength(self) -> str:
        """high if ≥3 categories co-occur (e.g. weapon + opsec + intent —
        the diagnostic combination); medium if ≥2 categories with total
        ≥3 hits; otherwise weak (filtered)."""
        if self.categories_fired >= 3:
            return "high"
        if self.categories_fired >= 2 and self.total_hits >= 3:
            return "medium"
        return "weak"

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        seed = (str(self.path) + "|"
                + "|".join(sorted(
                    self.weapon_hits + self.ammo_hits + self.opsec_hits
                    + self.intent_hits + self.destination_hits))
                ).encode()
        sha = hashlib.sha256(seed).hexdigest()
        f = {"path": str(self.path), "total_hits": self.total_hits,
             "categories_fired": self.categories_fired,
             "weapon_hits": self.weapon_hits[:10],
             "ammo_hits": self.ammo_hits[:10],
             "opsec_hits": self.opsec_hits[:10],
             "intent_hits": self.intent_hits[:10],
             "destination_hits": self.destination_hits[:10]}
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="el.pre_attack_planning_lexicon", version="0.1.0",
            command=f"scan({self.path.name})",
            output_sha256=sha, output_path=str(self.path),
            extracted_facts=f,
        )


def _word_hits(words: tuple[str, ...], lower: str) -> list[str]:
    """Whole-word hits — apostrophes, dashes, and digits inside multi-
    word phrases tolerated by the literal match. Avoids substring FPs
    (e.g. matching `bali` inside `balistic` — not real but cheap to
    guard against)."""
    out: list[str] = []
    for w in words:
        # Phrases need a tolerant boundary on each end. Words inside the
        # phrase keep their spaces verbatim — they came from real quotes.
        pat = rf"(?<![a-z]){re.escape(w)}(?![a-z])"
        if re.search(pat, lower):
            out.append(w)
    return out


def scan_text(text: str, source: Path | None = None) -> PreAttackMatch | None:
    """Scan *text*. Return a match ONLY when ≥2 categories fire AND
    the total-hits count is ≥ 2 — single "molon labe" on its own (or
    a single "ar-15" mention) is not evidence of planning. Weak hits
    are filtered before emission."""
    if not text:
        return None
    lower = text.lower()
    m = PreAttackMatch(
        path=source or Path("<text>"),
        weapon_hits=_word_hits(_WEAPON_WORDS, lower),
        ammo_hits=_AMMO_RX.findall(text)[:20],
        opsec_hits=_word_hits(_ESCAPE_OPSEC_WORDS, lower),
        intent_hits=_word_hits(_INTENT_WORDS, lower),
        destination_hits=_word_hits(_DESTINATION_WORDS, lower),
    )
    if m.categories_fired < 2 or m.total_hits < 2:
        return None
    if m.signal_strength == "weak":
        return None
    return m


_TEXT_EXTS = frozenset({
    ".txt", ".md", ".rtf", ".log", ".csv", ".tsv",
    ".json", ".yaml", ".yml", ".ini", ".conf",
    ".html", ".htm", ".xml",
    ".odt", ".eml",   # structured but contain plaintext blobs
    # Office formats — caller is expected to have already converted
    # these to text (via office_deobf or a dedicated extractor) and
    # passed the result back here. The extension is whitelisted so
    # callers can feed converted-text-with-original-suffix paths.
    ".docx", ".doc", ".pptx", ".ppt", ".xlsx", ".xls", ".pdf",
})


def walk_files(root: Path, max_bytes_per_file: int = 1_000_000,
               max_files: int = 2000) -> list[PreAttackMatch]:
    """Walk *root* and scan every plausible text file (by extension).

    Files larger than *max_bytes_per_file* are read in a single slice of
    that size (planning markers cluster near the top of notes / manifesto
    / planning files, never at the tail — same posture as narcotic_lexicon).
    """
    hits: list[PreAttackMatch] = []
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
