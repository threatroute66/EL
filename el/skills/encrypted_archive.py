"""Skill: detect ZIP archives containing encrypted members.

ZIP local-file-header flag_bits & 0x01 == 1 indicates a password-protected
entry. Seen on BelkaCTF Kidnapper — the dealer packed his monthly sales
database and client notes into password-locked ZIPs (Monthly_DB.zip,
mycon.zip) before attaching them to outgoing mail. Finding an encrypted
archive on a user's desktop is a strong anti-forensic signal: ordinary
document workflows almost never produce them.

Pure stdlib — uses zipfile.ZipFile().infolist() so no external deps.
Non-ZIP or truncated files fail soft and are skipped.
"""
from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


@dataclass
class EncryptedArchiveHit:
    archive_path: Path
    total_members: int
    encrypted_members: list[str] = field(default_factory=list)

    @property
    def encrypted_count(self) -> int:
        return len(self.encrypted_members)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        f = {"archive": str(self.archive_path),
             "total_members": self.total_members,
             "encrypted_count": self.encrypted_count,
             "encrypted_member_sample": self.encrypted_members[:5]}
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="el.encrypted_archive", version="0.1.0",
            command=f"scan({self.archive_path.name})",
            output_sha256="0" * 64,
            output_path=str(self.archive_path),
            extracted_facts=f,
        )


def scan_archive(path: Path) -> EncryptedArchiveHit | None:
    """Return a hit if *any* member is encrypted; None otherwise."""
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, OSError):
        return None
    total = len(infos)
    encrypted = [i.filename for i in infos if (i.flag_bits & 0x01)]
    if not encrypted:
        return None
    return EncryptedArchiveHit(
        archive_path=path,
        total_members=total,
        encrypted_members=encrypted,
    )


def walk(root: Path, max_archives: int = 200) -> list[EncryptedArchiveHit]:
    """Walk *root* for .zip / .jar / .ipa / .apk and return hits.

    Only archives of type ZIP are probed — rar/7z encryption detection
    requires third-party libs and is deferred.
    """
    hits: list[EncryptedArchiveHit] = []
    seen = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in {".zip", ".jar", ".ipa", ".apk"}:
            continue
        seen += 1
        if seen > max_archives:
            break
        h = scan_archive(p)
        if h is not None:
            hits.append(h)
    return hits
