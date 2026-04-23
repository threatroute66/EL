"""Skill: surface Linux dotfile directories being used for concealment.

Unix dotfiles (`.config`, `.ssh`, `.cache`) are expected to contain small
config / cache / credential files. When a user parks binaries, archives,
PDFs, audio/video, or office documents inside a dotfile directory, that's
an intentional concealment signal — not an accident of tool defaults.

Seen on BelkaCTF Kidnapper: `.custom/`, `.secs/`, `.mynote/`, `.db/` held
the dealer's drug-shop database, client notes, PDFs with mangled
extensions, and WAV files used for steganography.

The detector walks `/home/*/` and `/root/` of an extracted Linux image
tree. For each dotfile directory found, it classifies its contents by
extension and flags the directory when ≥ 1 non-config file is present.
Well-known benign dotfile dirs (`.cache`, `.local/share/Trash`, …) and
common file types for them (e.g. sqlite DBs inside `.mozilla`) are
allow-listed to keep FP noise down.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


# Dotfile directories whose purpose is to hold binaries / archives / media
# — listing one of these is not suspicious on its own.
_BENIGN_DOTDIRS = frozenset({
    ".cache", ".local", ".mozilla", ".thunderbird", ".config",
    ".gnupg", ".ssh", ".vim", ".vscode", ".vscode-server",
    ".npm", ".yarn", ".cargo", ".rustup", ".m2", ".gradle",
    ".docker", ".kube", ".aws", ".azure", ".gcloud",
    ".mc", ".minikube", ".terraform", ".ansible",
    ".pki", ".dbus", ".pulse", ".java", ".jdks",
    ".steam", ".wine", ".dotnet", ".nuget",
    ".git",  # bare/embedded git repos are normal project content
})

# File extensions that raise the concealment signal when found in ANY
# dotfile directory not on the benign list.
_SUSPICIOUS_EXTS = frozenset({
    # Archives (user-controllable data containers)
    ".zip", ".rar", ".7z", ".tar", ".tgz", ".gz", ".bz2", ".xz",
    # Documents / office
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".rtf",
    # Media (steganography candidates)
    ".wav", ".mp3", ".flac", ".ogg",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
    ".mp4", ".avi", ".mov", ".mkv", ".webm",
    # Binaries
    ".exe", ".dll", ".so", ".dylib", ".elf", ".bin",
    # Packet captures
    ".pcap", ".pcapng", ".cap",
})


@dataclass
class DotfileAnomalyHit:
    dotfile_dir: Path
    user: str
    total_files: int
    suspicious_files: list[Path] = field(default_factory=list)
    ext_counts: dict[str, int] = field(default_factory=dict)

    @property
    def suspicious_count(self) -> int:
        return len(self.suspicious_files)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        # Hash the dirpath + sorted filenames so the evidence is reproducible.
        names = sorted(p.name for p in self.suspicious_files)
        seed = (str(self.dotfile_dir) + "\n" + "\n".join(names)).encode()
        sha = hashlib.sha256(seed).hexdigest()
        f = {"dotfile_dir": str(self.dotfile_dir),
             "user": self.user,
             "total_files": self.total_files,
             "suspicious_count": self.suspicious_count,
             "suspicious_sample": [p.name for p in self.suspicious_files[:5]],
             "ext_counts": self.ext_counts}
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="el.dotfile_anomaly", version="0.1.0",
            command=f"walk({self.dotfile_dir.name})",
            output_sha256=sha, output_path=str(self.dotfile_dir),
            extracted_facts=f,
        )


def _scan_user_home(home: Path) -> list[DotfileAnomalyHit]:
    """Check every dotfile-directory child of *home* for suspicious content."""
    hits: list[DotfileAnomalyHit] = []
    if not home.is_dir():
        return hits
    user = home.name if home.name != "root" else "root"
    for child in home.iterdir():
        if not child.is_dir() or not child.name.startswith("."):
            continue
        if child.name in _BENIGN_DOTDIRS:
            continue
        total = 0
        suspicious: list[Path] = []
        ext_counts: dict[str, int] = {}
        for p in child.rglob("*"):
            if not p.is_file():
                continue
            total += 1
            ext = p.suffix.lower()
            if ext in _SUSPICIOUS_EXTS:
                suspicious.append(p)
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
        if suspicious:
            hits.append(DotfileAnomalyHit(
                dotfile_dir=child, user=user,
                total_files=total, suspicious_files=suspicious,
                ext_counts=ext_counts,
            ))
    return hits


def walk(root: Path) -> list[DotfileAnomalyHit]:
    """Scan an extracted Linux filesystem root for dotfile-concealment."""
    hits: list[DotfileAnomalyHit] = []
    home = root / "home"
    if home.is_dir():
        for udir in home.iterdir():
            hits.extend(_scan_user_home(udir))
    rootdir = root / "root"
    if rootdir.is_dir():
        hits.extend(_scan_user_home(rootdir))
    return hits
