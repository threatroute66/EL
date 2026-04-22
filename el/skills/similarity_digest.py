"""Similarity-digest skill — fuzzy hashing + perceptual hashing.

Motivated by Roussev & Quates 2012 "Content triage with similarity
digests: The M57 case study" (Digital Investigation 9, S60–S68).
Cryptographic hashes (sha256) match byte-exact; they miss modified
variants, fragments of a known-bad file embedded in RAM, and
steganography carriers (visually identical images with differing
pixel-level perturbations).

Two algorithms:

  * ssdeep (context-triggered piecewise hash, CTPH) via the
    pure-Python `ppdeep` implementation — returns a `3:AAAA:BBBB`
    digest and a 0-100 resemblance score between two digests.
    Roussev's interpretation scale: 21-100 strong, 11-20 marginal,
    1-10 weak, 0 uncorrelated.

  * Perceptual image hash (`pHash`) via `imagehash.phash` over PIL —
    returns a 64-bit bit-vector; Hamming distance ≤ 8 is a strong
    visual match even if the cryptographic hashes differ (the
    paper's Case-3 stego-carrier signature).

Pure functions; silent on bad inputs (`None` return) so callers can
iterate over a tree without bailing on corrupt files.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# ssdeep / CTPH fuzzy digest
# ---------------------------------------------------------------------------

def ssdeep_digest(path: str | Path) -> str | None:
    """Compute an ssdeep digest of `path`. None on I/O error, non-file,
    or if the file is below ssdeep's minimum (<4 KB)."""
    try:
        import ppdeep
    except ImportError:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = p.read_bytes()
    except OSError:
        return None
    if len(data) < 4096:
        return None
    try:
        return ppdeep.hash(data)
    except Exception:
        return None


def ssdeep_compare(digest_a: str, digest_b: str) -> int:
    """Compare two ssdeep digests. Returns 0-100 score, or -1 on
    malformed input. Score scale (Roussev 2011b / 2012):
      21-100 strong · 11-20 marginal · 1-10 weak · 0 uncorrelated."""
    try:
        import ppdeep
    except ImportError:
        return -1
    if not digest_a or not digest_b:
        return -1
    try:
        return int(ppdeep.compare(digest_a, digest_b))
    except Exception:
        return -1


def ssdeep_score_band(score: int) -> str:
    """Human-readable band for an ssdeep score."""
    if score < 0:   return "invalid"
    if score == 0:  return "uncorrelated"
    if score <= 10: return "weak"
    if score <= 20: return "marginal"
    return "strong"


# ---------------------------------------------------------------------------
# Perceptual image hash (pHash) for stego-carrier detection
# ---------------------------------------------------------------------------

_IMAGE_SUFFIXES = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
    ".webp", ".heic",
})


def phash(path: str | Path) -> str | None:
    """64-bit perceptual hash of an image as a lowercase hex string.
    None on non-image / I/O error / unsupported format."""
    p = Path(path)
    if p.suffix.lower() not in _IMAGE_SUFFIXES or not p.is_file():
        return None
    try:
        import imagehash
        from PIL import Image
    except ImportError:
        return None
    try:
        with Image.open(p) as img:
            h = imagehash.phash(img)
        return str(h)
    except Exception:
        return None


def phash_distance(a: str, b: str) -> int:
    """Hamming distance between two pHash hex strings. Returns 64 (max)
    on invalid input or length mismatch."""
    if not a or not b or len(a) != len(b):
        return 64
    try:
        ia = int(a, 16); ib = int(b, 16)
    except ValueError:
        return 64
    return bin(ia ^ ib).count("1")


# ---------------------------------------------------------------------------
# Stego-carrier detection (Tier 2 — paper's Case 3)
# ---------------------------------------------------------------------------

@dataclass
class StegoCarrierPair:
    """Two image files whose pixel content is near-identical (pHash
    Hamming ≤ threshold) but whose cryptographic hashes differ — the
    classic stego-carrier signature from M57 Case 3 (microscope.jpg +
    microscope1.jpg / astronaut.jpg + astronaut1.jpg, pairs that
    looked identical but carried different steganographic payloads)."""
    path_a: str
    path_b: str
    phash_a: str
    phash_b: str
    hamming: int
    sha256_a: str
    sha256_b: str


def detect_stego_carrier_pairs(
    images_dir: str | Path,
    hamming_threshold: int = 8,
    max_files: int = 5000,
) -> list[StegoCarrierPair]:
    """Walk `images_dir` looking for pairs of images with low pHash
    Hamming distance and differing sha256 — stego-carrier candidates.

    Args:
        images_dir: root directory to scan recursively for images.
        hamming_threshold: max pHash Hamming distance to consider a
            pair "visually identical". Default 8 (of 64 bits) matches
            the imagehash library's widely-cited strong-match threshold.
        max_files: cap on number of images hashed per call; protects
            against million-image trees (iOS photo libraries).

    Returns a list of StegoCarrierPair records, one per flagged pair.
    Empty list when the directory doesn't exist or no pairs cross the
    threshold.
    """
    root = Path(images_dir)
    if not root.is_dir():
        return []
    import hashlib
    records: list[tuple[str, str, str]] = []  # (path, phash, sha256)
    for i, p in enumerate(root.rglob("*")):
        if i >= max_files:
            break
        if not (p.is_file() and p.suffix.lower() in _IMAGE_SUFFIXES):
            continue
        ph = phash(p)
        if not ph:
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        sha = hashlib.sha256(data).hexdigest()
        records.append((str(p), ph, sha))

    pairs: list[StegoCarrierPair] = []
    for i in range(len(records)):
        pa, pha, sha_a = records[i]
        for j in range(i + 1, len(records)):
            pb, phb, sha_b = records[j]
            if sha_a == sha_b:
                continue      # byte-identical, not a stego pair
            d = phash_distance(pha, phb)
            if d <= hamming_threshold:
                pairs.append(StegoCarrierPair(
                    path_a=pa, path_b=pb, phash_a=pha, phash_b=phb,
                    hamming=d, sha256_a=sha_a, sha256_b=sha_b,
                ))
    return pairs


# ---------------------------------------------------------------------------
# Ssdeep cross-target query (file-in-target, paper's File-vs-HDD query)
# ---------------------------------------------------------------------------

@dataclass
class SsdeepHit:
    reference_label: str
    target_path: str
    score: int
    band: str


def ssdeep_query_set(
    reference_digests: dict[str, str],
    target_paths: list[str | Path],
    threshold: int = 20,
) -> list[SsdeepHit]:
    """Roussev-style content-triage query: given a bag of labelled
    reference digests (sha256 / name → ssdeep) and a set of target
    files, return every (reference, target) pair that exceeds
    `threshold`. Default 20 = lower bound of "marginal"."""
    hits: list[SsdeepHit] = []
    if not reference_digests:
        return hits
    for tp in target_paths:
        tp = Path(tp)
        td = ssdeep_digest(tp)
        if not td:
            continue
        for label, rd in reference_digests.items():
            s = ssdeep_compare(rd, td)
            if s >= threshold:
                hits.append(SsdeepHit(
                    reference_label=label,
                    target_path=str(tp),
                    score=s,
                    band=ssdeep_score_band(s),
                ))
    return hits


__all__ = [
    "ssdeep_digest", "ssdeep_compare", "ssdeep_score_band",
    "phash", "phash_distance",
    "StegoCarrierPair", "detect_stego_carrier_pairs",
    "SsdeepHit", "ssdeep_query_set",
]
