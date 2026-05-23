"""Skill: detect the same file content mirrored across multiple cloud-
sync local directories.

The Lone Wolf 2018 corpus made one operationally distinctive choice
explicit: every planning document (Manifesto.docx, Planning.docx,
Operation 2nd Hand Smoke.pptx, AIRPORT INFORMATION.docx, Cloudy
Thoughts.docx) was deliberately mirrored to Box Sync + Dropbox +
OneDrive + Google Drive + Amazon S3, so the content would survive
the user's intent to dispose of the laptop. From Cloudy Thoughts:

    "I am saving everything to the cloud on several accounts."
    "The only record will remain in the cloud and Paul will have
     the only other keys."

This isn't normal sync behaviour — most users pick ONE cloud and use
it. Five cloud-sync directories containing the same SHA-256 file is a
strong "evidence-preservation strategy" signal. We surface it as a
distinct finding so the analyst doesn't have to eyeball five Desktop /
Box Sync / Dropbox / OneDrive / Google Drive trees side-by-side.

Cross-platform aware:
  Windows  — Users/<user>/{Box Sync,Dropbox,OneDrive,Google Drive,Desktop}/
  macOS    — Users/<user>/{Box Sync,Dropbox,OneDrive,Google Drive,Desktop}/
  Linux    — home/<user>/{...same...}/ (less common; Dropbox + Drive only)

The detector hashes files in each candidate cloud-sync root and
clusters by SHA-256. A cluster spanning ≥3 distinct cloud providers
on the same host is the threshold (3 catches the case shape; 2
would FP on Box Sync defaulting to mirror the OneDrive folder, etc.).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


# Canonical cloud-sync directory names. Each one represents ONE cloud
# provider — even if Box's local mount happens to be inside the user
# profile, it still counts as Box-the-provider. Lower-cased for the
# case-insensitive match (Win+macOS preserve casing, Linux doesn't).
_CLOUD_DIR_PROVIDERS: dict[str, str] = {
    "box sync":         "Box",
    "boxsync":          "Box",
    "dropbox":          "Dropbox",
    "onedrive":         "OneDrive",
    "onedrive - personal": "OneDrive",
    "google drive":     "Google Drive",
    "google drive file stream": "Google Drive",
    "googledrive":      "Google Drive",
    "drive":            "Google Drive",  # post-2021 Backup-and-Sync rename
    "icloud drive":     "iCloud",
    "icloud":           "iCloud",
    "mega":             "MEGA",
    "amazon drive":     "Amazon",
}

# How many distinct providers must mirror the same SHA-256 before we
# emit a finding. 3 is the conservative threshold; the Lone Wolf
# corpus hits 5 (Box + Dropbox + OneDrive + Google Drive + S3).
DEFAULT_MIN_PROVIDERS = 3

# Skip files smaller than this — the Box/Dropbox/Google Drive `.tmp`
# state files + lnk shortcuts are tiny and shared by construction
# (`Box Sync.lnk` for instance lives in every Desktop). They drown
# real signal otherwise.
DEFAULT_MIN_BYTES = 1024

# Skip noise filenames — sync clients drop these everywhere
_NOISE_FILENAMES = frozenset({
    "desktop.ini", ".ds_store", "thumbs.db",
    "box sync.lnk", "dropbox.lnk", "google drive.lnk",
    "onedrive.lnk", ".tmp.drivedownload",
})


@dataclass
class MirroredFile:
    sha256: str
    size: int
    name: str                        # display basename (from first occurrence)
    providers: dict[str, list[Path]] = field(default_factory=dict)

    @property
    def provider_count(self) -> int:
        return len(self.providers)

    @property
    def total_copies(self) -> int:
        return sum(len(paths) for paths in self.providers.values())


@dataclass
class CrossCloudResult:
    root: Path
    user_profile: Path
    cloud_roots: dict[str, Path] = field(default_factory=dict)
    mirrored: list[MirroredFile] = field(default_factory=list)
    files_hashed: int = 0
    bytes_hashed: int = 0

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        # Deterministic hash of the result so the finding is reproducible
        seed = "|".join(sorted(
            f"{m.sha256}:{m.provider_count}:{m.name}" for m in self.mirrored
        )).encode()
        sha = hashlib.sha256(seed).hexdigest()
        f = {
            "user_profile": str(self.user_profile),
            "cloud_roots": {k: str(v) for k, v in self.cloud_roots.items()},
            "mirrored_count": len(self.mirrored),
            "files_hashed": self.files_hashed,
            "bytes_hashed": self.bytes_hashed,
            "top_mirrored": [
                {"name": m.name, "sha256": m.sha256, "size": m.size,
                 "providers": sorted(m.providers.keys()),
                 "total_copies": m.total_copies}
                for m in self.mirrored[:20]
            ],
        }
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="el.cross_cloud_mirror", version="0.1.0",
            command=f"scan({self.user_profile.name})",
            output_sha256=sha, output_path=str(self.user_profile),
            extracted_facts=f,
        )


def _discover_cloud_roots(user_profile: Path) -> dict[str, Path]:
    """Return {provider_name: directory_path} for every cloud-sync
    directory we recognise under *user_profile*. Case-insensitive
    match against `_CLOUD_DIR_PROVIDERS`."""
    out: dict[str, Path] = {}
    if not user_profile.is_dir():
        return out
    for child in user_profile.iterdir():
        if not child.is_dir():
            continue
        provider = _CLOUD_DIR_PROVIDERS.get(child.name.lower())
        if provider is None:
            continue
        # Prefer the deepest specific match — if Box and "Box Sync"
        # both fire, keep the first (Box Sync). Don't clobber.
        out.setdefault(provider, child)
    return out


def _hash_file(path: Path, max_bytes: int) -> tuple[str, int] | None:
    """Hash *path* up to *max_bytes* — for typical user-doc / image
    sizes (<5 MB) this is the whole file. Returns (sha256, size_read)
    or None on read error."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size < DEFAULT_MIN_BYTES:
        return None
    if path.name.lower() in _NOISE_FILENAMES:
        return None
    h = hashlib.sha256()
    read = 0
    try:
        with path.open("rb") as f:
            while read < max_bytes:
                chunk = f.read(min(65536, max_bytes - read))
                if not chunk:
                    break
                h.update(chunk)
                read += len(chunk)
    except OSError:
        return None
    return h.hexdigest(), read


def scan(user_profile: Path, *, min_providers: int = DEFAULT_MIN_PROVIDERS,
         max_bytes_per_file: int = 8 * 1024 * 1024,
         max_files_per_root: int = 5000) -> CrossCloudResult:
    """Walk every recognised cloud-sync root under *user_profile*, hash
    each file, and cluster by SHA-256. Emit one MirroredFile per cluster
    whose provider-count meets the threshold.
    """
    user_profile = Path(user_profile)
    result = CrossCloudResult(root=user_profile.parent,
                              user_profile=user_profile)
    result.cloud_roots = _discover_cloud_roots(user_profile)
    if len(result.cloud_roots) < min_providers:
        return result   # not enough providers present to even meet threshold

    # sha256 → MirroredFile aggregator
    clusters: dict[str, MirroredFile] = {}

    for provider, root in result.cloud_roots.items():
        scanned = 0
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            scanned += 1
            if scanned > max_files_per_root:
                break
            hashed = _hash_file(p, max_bytes_per_file)
            if hashed is None:
                continue
            sha, size = hashed
            result.files_hashed += 1
            result.bytes_hashed += size
            cluster = clusters.get(sha)
            if cluster is None:
                cluster = MirroredFile(sha256=sha, size=size, name=p.name)
                clusters[sha] = cluster
            cluster.providers.setdefault(provider, []).append(p)

    # Keep only clusters spanning ≥ min_providers distinct cloud providers
    result.mirrored = sorted(
        (m for m in clusters.values() if m.provider_count >= min_providers),
        key=lambda m: (-m.provider_count, -m.size, m.name),
    )
    return result


def find_user_profiles(extracted_root: Path) -> list[Path]:
    """Locate user-profile candidates under an extracted filesystem root.

    Windows: `Users/<user>/`
    macOS:   `Users/<user>/`
    Linux:   `home/<user>/`

    Skips the system profiles (Public, Default, All Users, Shared)
    which never carry cloud-sync state.
    """
    skip_users = frozenset({
        "public", "default", "default user", "all users",
        "defaultappdata", "shared", "guest",
    })
    candidates: list[Path] = []
    for base in ("Users", "home"):
        base_dir = extracted_root / base
        if not base_dir.is_dir():
            continue
        for u in base_dir.iterdir():
            if u.is_dir() and u.name.lower() not in skip_users:
                candidates.append(u)
    return candidates
