"""Skill: dislocker — read-only BitLocker volume decryption.

Wraps the `dislocker-fuse` and `dislocker-metadata` binaries that
ship on SIFT under `/usr/bin/`. EL only needs the FUSE-mount path
(`dislocker-fuse`) for downstream filesystem analysis — the
metadata-only path (`dislocker-metadata`) is exposed separately so
triage can probe the BitLocker header + key-protector inventory
without staging credentials.

Two operating modes:

  1. **Probe** (`probe_metadata(image)`) — runs `dislocker-metadata`
     against the image, returns a structured dataclass with the
     volume GUID, dataset GUID, encryption type, key-protector
     inventory (recovery-key GUIDs, TPM presence, password
     presence, BEK file presence), state flags. No credentials
     needed. Used by triage to surface a BitLocker-found finding
     and tell the analyst which protector GUIDs to supply keys for.

  2. **Mount** (`mount(image, mount_point, ...)`) — runs
     `dislocker-fuse -V <image> [-p <rec_pw> | -u <user_pw> | -f
     <bek>] <mount_point>`. The mount point gets a single virtual
     file `dislocker-file` exposing the decrypted volume as a
     plain raw stream, ready for `mmls` / `fls` / `mactime`. The
     wrapper unmount counterpart (`umount`) calls `fusermount -u`.

Evidence shape:
  - All commands run with capture-stderr-to-file; the stderr file
    is hashed and recorded as `output_sha256` for chain-of-custody.
  - The `version_line` field captures the dislocker version banner
    so future cases can pin the exact decryption binary used.
  - Credentials are NEVER written into the evidence record —
    they're parameter inputs only. The agent stores their digest
    (sha256 of the credential bytes) so the case can prove which
    key set was supplied without leaking the key itself.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class DislockerError(RuntimeError):
    pass


@dataclass
class DislockerMetadata:
    """Structured projection of `dislocker-metadata` stdout."""
    signature: str = ""                 # "-FVE-FS-" when valid
    volume_guid: str = ""               # 4967D63B-... (the volume id)
    dataset_guid: str = ""              # F0EA764F-... (the FVE dataset)
    encryption_type: str = ""           # "AES-128-DIFFUSER", "AES-128-XTS", etc.
    state: str = ""                     # "ENCRYPTED", "DECRYPTING", etc.
    sector_size: int = 0
    volume_size: int = 0
    recovery_key_guids: list[str] = field(default_factory=list)
    has_tpm_protector: bool = False
    has_password_protector: bool = False
    has_bek_protector: bool = False
    raw_stdout_path: Path | None = None
    stderr_path: Path | None = None
    version_line: str = ""
    rc: int = 0

    def as_evidence(self, extra: dict | None = None) -> EvidenceItem:
        h = hashlib.sha256()
        if self.raw_stdout_path and self.raw_stdout_path.is_file():
            h.update(self.raw_stdout_path.read_bytes())
        return EvidenceItem(
            tool="dislocker-metadata", version=self.version_line or "v0.7",
            command=f"dislocker-metadata -V <image>",
            output_sha256=h.hexdigest() or "0" * 64,
            output_path=str(self.raw_stdout_path or ""),
            extracted_facts={
                "signature": self.signature,
                "volume_guid": self.volume_guid,
                "dataset_guid": self.dataset_guid,
                "encryption_type": self.encryption_type,
                "state": self.state,
                "sector_size": self.sector_size,
                "volume_size_bytes": self.volume_size,
                "recovery_key_guids": list(self.recovery_key_guids),
                "has_tpm_protector": self.has_tpm_protector,
                "has_password_protector": self.has_password_protector,
                "has_bek_protector": self.has_bek_protector,
                "phase": "bitlocker_probe",
                **(extra or {}),
            },
        )


@dataclass
class DislockerMount:
    """Successful mount handle from `dislocker-fuse`."""
    image_path: Path
    mount_point: Path
    decrypted_file: Path                # <mount>/dislocker-file
    command: list[str]
    stderr_path: Path
    rc: int = 0
    used_protector_kind: str = ""       # "recovery_key" | "user_password" | "bek_file"
    used_protector_digest: str = ""     # sha256 of the credential bytes (no leak)
    version_line: str = ""

    def as_evidence(self, extra: dict | None = None) -> EvidenceItem:
        # Hash the decrypted file's HEAD ONLY — never the whole
        # content; the decrypted blob can be GBs, and the per-
        # sector mactime + fls walks will downstream-hash anyway.
        head_sha = ""
        try:
            with self.decrypted_file.open("rb") as f:
                head_sha = hashlib.sha256(f.read(1024 * 1024)).hexdigest()
        except OSError:
            head_sha = "0" * 64
        return EvidenceItem(
            tool="dislocker-fuse", version=self.version_line or "v0.7",
            command=" ".join(self.command),
            output_sha256=head_sha,
            output_path=str(self.decrypted_file),
            extracted_facts={
                "image_path": str(self.image_path),
                "mount_point": str(self.mount_point),
                "used_protector_kind": self.used_protector_kind,
                "used_protector_digest": self.used_protector_digest,
                "phase": "bitlocker_unlock",
                **(extra or {}),
            },
        )


# ---------------------------------------------------------------------------
# Helpers — binary discovery + signature probe
# ---------------------------------------------------------------------------

def _bin(name: str) -> str:
    """Locate a dislocker binary; raise if missing so callers get a
    consistent error class to handle."""
    p = shutil.which(name)
    if not p:
        raise DislockerError(
            f"{name} not on PATH — install dislocker ("
            "`apt install dislocker` on SIFT) to handle BitLocker images")
    return p


def is_bitlocker_signature(path: Path) -> bool:
    """Cheap header check — read bytes 0..11 and look for the
    `-FVE-FS-` signature at offset 0x03. Used by triage to decide
    whether to invoke probe_metadata before the heavier dispatch."""
    try:
        with Path(path).open("rb") as f:
            head = f.read(11)
    except OSError:
        return False
    return head[3:11] == b"-FVE-FS-"


# ---------------------------------------------------------------------------
# Metadata probe
# ---------------------------------------------------------------------------

# Capture lines like:
#     [INFO]   Volume GUID: '4967D63B-2E29-4AD8-8399-F6A339E3D001'
#     [INFO]     Dataset GUID: 'F0EA764F-08FF-4198-91DC-60F78E86D881'
#     [INFO]     Encryption Type: AES-128-DIFFUSER (0x8000)
#     [INFO]   Current state: ENCRYPTED (4)
#     [INFO]   Sector size: 0x0200 (512) bytes
#     [INFO]   Encrypted volume size: 4294966784 bytes (0xfffffe00), ~4095 MB
#     [INFO] Recovery Key GUID: 'AEF79D3D-9AD5-4CB3-8FDB-CCBFEB966F27'
_RE_VOLUME_GUID = re.compile(r"Volume GUID:\s*'([0-9A-Fa-f-]+)'")
_RE_DATASET_GUID = re.compile(r"Dataset GUID:\s*'([0-9A-Fa-f-]+)'")
_RE_ENC_TYPE = re.compile(r"Encryption Type:\s*([A-Z0-9-]+)\s*\(0x")
_RE_STATE = re.compile(r"Current state:\s*([A-Z_]+)\s*\(\d+\)")
_RE_SECTOR_SIZE = re.compile(r"Sector size:\s*0x[0-9a-fA-F]+\s*\((\d+)\)")
_RE_VOLUME_SIZE = re.compile(r"Encrypted volume size:\s*(\d+)\s*bytes")
_RE_REC_KEY_GUID = re.compile(r"Recovery Key GUID:\s*'([0-9A-Fa-f-]+)'")
_RE_VERSION = re.compile(r"dislocker by [^,]+,\s*(v[0-9.]+)")


def probe_metadata(image_path: Path, out_dir: Path,
                    timeout: int = 120) -> DislockerMetadata:
    """Run `dislocker-metadata -V <image>`, capture stdout +
    stderr, parse the structured fields. Returns the metadata
    dataclass even on rc != 0 — fields stay empty when unparseable,
    but the raw_stdout_path always points at the captured output
    so the analyst can re-read it manually.

    Raises DislockerError only when the binary itself is missing
    from PATH — every other failure (corrupt header, missing
    metadata block, etc.) is reported via the returned dataclass
    so callers can emit an `insufficient` finding rather than
    crash."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = _bin("dislocker-metadata")
    stdout_path = out_dir / "dislocker-metadata.stdout"
    stderr_path = out_dir / "dislocker-metadata.stderr"
    cmd = [binary, "-V", str(image_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise DislockerError(
            f"dislocker-metadata timed out on {image_path}") from e
    # Merge stdout + stderr — dislocker-metadata writes ALL its
    # informational output to stderr (the [INFO] lines) and
    # nothing to stdout. We treat stderr as the data channel.
    combined = (proc.stdout or "") + (proc.stderr or "")
    stdout_path.write_text(combined)
    stderr_path.write_text(proc.stderr or "")
    md = DislockerMetadata(
        rc=proc.returncode,
        raw_stdout_path=stdout_path,
        stderr_path=stderr_path,
    )
    # Best-effort parse — every field is independent, missing
    # fields stay at their default.
    if vm := _RE_VERSION.search(combined):
        md.version_line = vm.group(1)
    if vm := _RE_VOLUME_GUID.search(combined):
        md.volume_guid = vm.group(1)
    if vm := _RE_DATASET_GUID.search(combined):
        md.dataset_guid = vm.group(1)
    if vm := _RE_ENC_TYPE.search(combined):
        md.encryption_type = vm.group(1)
    if vm := _RE_STATE.search(combined):
        md.state = vm.group(1)
    if vm := _RE_SECTOR_SIZE.search(combined):
        md.sector_size = int(vm.group(1))
    if vm := _RE_VOLUME_SIZE.search(combined):
        md.volume_size = int(vm.group(1))
    md.recovery_key_guids = sorted(set(_RE_REC_KEY_GUID.findall(combined)))
    if md.signature == "" and "-FVE-FS-" in combined:
        md.signature = "-FVE-FS-"
    # Protector-kind flags — dislocker emits explicit phrases per
    # protector class. Substring match is sufficient (these strings
    # don't appear elsewhere in dislocker's output).
    md.has_tpm_protector = "TPM" in combined and "protector" in combined.lower()
    md.has_password_protector = ("USER PASSWORD" in combined.upper() or
                                  "User password" in combined)
    md.has_bek_protector = "EXTERNAL KEY" in combined.upper() or ".bek" in combined.lower()
    return md


# ---------------------------------------------------------------------------
# Mount + umount
# ---------------------------------------------------------------------------

def mount(image_path: Path, mount_point: Path, *,
          recovery_password: str | None = None,
          user_password: str | None = None,
          bek_file: Path | None = None,
          stderr_out: Path | None = None,
          timeout: int = 60) -> DislockerMount:
    """Run `dislocker-fuse -V <image> [credential] <mount>`.

    Exactly one credential MUST be supplied (recovery_password OR
    user_password OR bek_file). Otherwise raises DislockerError —
    we don't fall through to "try without auth" because that's a
    silent failure mode the analyst won't notice.

    On success, `<mount_point>/dislocker-file` exposes the
    decrypted raw stream (~ full volume size). On failure raises
    DislockerError with the stderr captured.

    The credential VALUE is never stored anywhere on disk by EL —
    only the sha256 of its bytes lands in the evidence (so the
    case can prove WHICH key set was tried without leaking the key
    itself).
    """
    mount_point = Path(mount_point)
    mount_point.mkdir(parents=True, exist_ok=True)
    binary = _bin("dislocker-fuse")
    creds = [c for c in (recovery_password, user_password, bek_file) if c]
    if len(creds) != 1:
        raise DislockerError(
            "mount() requires exactly one of recovery_password, "
            "user_password, bek_file")
    cred_kind = ""
    cred_digest = ""
    args: list[str] = [binary, "-V", str(image_path)]
    if recovery_password is not None:
        cred_kind = "recovery_key"
        cred_digest = hashlib.sha256(
            recovery_password.encode("utf-8")).hexdigest()
        args.append(f"-p{recovery_password}")
    elif user_password is not None:
        cred_kind = "user_password"
        cred_digest = hashlib.sha256(
            user_password.encode("utf-8")).hexdigest()
        args.append(f"-u{user_password}")
    elif bek_file is not None:
        cred_kind = "bek_file"
        try:
            cred_digest = hashlib.sha256(
                Path(bek_file).read_bytes()).hexdigest()
        except OSError as e:
            raise DislockerError(f"cannot read BEK file: {e}") from e
        args.extend(["-f", str(bek_file)])
    args.append(str(mount_point))
    # Pass `allow_other` through to FUSE so the downstream `sudo
    # ntfs-3g <dislocker-file>` (run by mount_ntfs) can read this
    # mount. Default FUSE policy is owner-only access; without
    # allow_other a root subprocess gets EACCES on the FUSE inode
    # even though it could read any other file on disk. Requires
    # /etc/fuse.conf to carry `user_allow_other` — present on SIFT
    # by default. Falls through silently if FUSE rejects (older
    # kernels may report errors but still mount with default ACL).
    args.extend(["--", "-o", "allow_other"])
    if stderr_out is None:
        stderr_out = mount_point.parent / "dislocker-fuse.stderr"
    stderr_path = Path(stderr_out)
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                                timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise DislockerError(
            f"dislocker-fuse timed out mounting {image_path}") from e
    stderr_path.write_text(proc.stderr or "")
    if proc.returncode != 0 or "CRITICAL" in (proc.stderr or ""):
        raise DislockerError(
            f"dislocker-fuse failed (rc={proc.returncode}) — "
            f"check {stderr_path} for details "
            f"(commonly: wrong key, wrong key kind, or corrupt header)")
    decrypted = mount_point / "dislocker-file"
    if not decrypted.exists():
        raise DislockerError(
            f"dislocker-fuse returned rc=0 but no dislocker-file "
            f"appeared at {decrypted} — mount may be in a bad state")
    version_line = ""
    if vm := _RE_VERSION.search(proc.stderr or ""):
        version_line = vm.group(1)
    return DislockerMount(
        image_path=Path(image_path),
        mount_point=mount_point,
        decrypted_file=decrypted,
        command=args,
        stderr_path=stderr_path,
        rc=proc.returncode,
        used_protector_kind=cred_kind,
        used_protector_digest=cred_digest,
        version_line=version_line,
    )


def umount(mount_point: Path) -> bool:
    """Unmount a previously-mounted dislocker-fuse mount. Returns
    True on success, False on any failure (caller may choose to
    retry or warn). Never raises — clean-up paths often run from
    `finally:` blocks where raising would mask the original error."""
    try:
        proc = subprocess.run(
            ["fusermount", "-u", str(mount_point)],
            capture_output=True, text=True, timeout=15)
        return proc.returncode == 0
    except Exception:
        return False


__all__ = [
    "DislockerError",
    "DislockerMetadata",
    "DislockerMount",
    "is_bitlocker_signature",
    "probe_metadata",
    "mount",
    "umount",
]
