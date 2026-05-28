"""Skill: LUKS encrypted-volume detection + (optional, keyed) read-only open.

A recovered partition whose filesystem is LUKS-encrypted dead-ends in the
Sleuth Kit path as "Cannot determine file system type". This skill identifies
it as a LUKS container and reports it as encrypted — the correct, honest
forensic outcome when no key material is present in the evidence.

Detection is a PURE read-only header parse (LUKS header layout is stable:
magic "LUKS\\xba\\xbe" @0, version @6 big-endian, UUID @168 for both LUKS1 and
LUKS2; LUKS1 also carries cipher/mode/hash in the binary header). This works
without root or loop devices.

When a key IS supplied (operator-provided, never from evidence), `open_readonly`
wraps the court-vetted `cryptsetup` (SIFT default): losetup -r at the partition
offset, then `cryptsetup open --readonly`, exposing a /dev/mapper node the normal
filesystem pipeline can walk. Always paired with `close()` in a finally block.
"""
from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from el.schemas.finding import EvidenceItem

_LUKS_MAGIC = b"LUKS\xba\xbe"


class LuksError(RuntimeError):
    pass


@dataclass
class LuksInfo:
    image: Path
    offset_bytes: int
    version: int
    uuid: str
    cipher: str            # "<name>-<mode>" for LUKS1; "" if unknown (LUKS2 JSON)
    hash_spec: str

    def as_evidence(self, out_dir: Path, facts: dict | None = None) -> EvidenceItem:
        seed = f"{self.image}|{self.offset_bytes}|{self.uuid}|{self.version}".encode()
        sha = hashlib.sha256(seed).hexdigest()
        f = {
            "luks_version": self.version,
            "uuid": self.uuid,
            "cipher": self.cipher,
            "hash_spec": self.hash_spec,
            "offset_bytes": self.offset_bytes,
            "decryptable": False,
            "reason": "no key material present in evidence",
        }
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="el.luks", version="0.1.0",
            command=f"luks.detect({Path(self.image).name}@{self.offset_bytes})",
            output_sha256=sha, output_path=str(self.image),
            extracted_facts=f,
        )


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()


def detect(image: Path, offset_bytes: int) -> LuksInfo | None:
    """Return a LuksInfo when a LUKS header sits at *offset_bytes*, else None.
    Pure read-only header parse."""
    image = Path(image)
    try:
        with image.open("rb") as f:
            f.seek(offset_bytes)
            hdr = f.read(512)
    except OSError:
        return None
    if len(hdr) < 208 or hdr[0:6] != _LUKS_MAGIC:
        return None
    version = struct.unpack_from(">H", hdr, 6)[0]
    uuid = _cstr(hdr[168:208])
    cipher = ""
    hash_spec = ""
    if version == 1:
        # LUKS1 binary header carries cipher/mode/hash in cleartext.
        name = _cstr(hdr[8:40])
        mode = _cstr(hdr[40:72])
        hash_spec = _cstr(hdr[72:104])
        cipher = f"{name}-{mode}".strip("-")
    return LuksInfo(image=image, offset_bytes=offset_bytes, version=version,
                    uuid=uuid, cipher=cipher, hash_spec=hash_spec)


def _which(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        raise LuksError(f"{tool} not on PATH")
    return p


def open_readonly(image: Path, offset_bytes: int, key: bytes,
                  mapper_name: str, timeout: int = 60) -> str:
    """Operator-keyed read-only unlock. Sets up a read-only loop device at the
    partition offset, then `cryptsetup open --readonly`. Returns the
    /dev/mapper/<mapper_name> path. Caller MUST pair with close().

    *key* is operator-supplied passphrase bytes — NEVER sourced from evidence.
    """
    losetup = _which("losetup")
    cryptsetup = _which("cryptsetup")
    # read-only loop at the partition offset
    lo = subprocess.run(
        ["sudo", losetup, "-r", "-o", str(offset_bytes), "--show", "-f", str(image)],
        capture_output=True, text=True, timeout=timeout,
    )
    if lo.returncode != 0:
        raise LuksError(f"losetup failed: {lo.stderr.strip()}")
    loop_dev = lo.stdout.strip()
    try:
        op = subprocess.run(
            ["sudo", cryptsetup, "open", "--readonly", "--key-file=-",
             loop_dev, mapper_name],
            input=key, capture_output=True, timeout=timeout,
        )
        if op.returncode != 0:
            raise LuksError(
                f"cryptsetup open failed (rc={op.returncode}): "
                f"{op.stderr.decode('utf-8', 'replace').strip()}")
    except Exception:
        subprocess.run(["sudo", losetup, "-d", loop_dev],
                       capture_output=True, timeout=timeout)
        raise
    # stash the loop dev so close() can tear it down
    _OPEN_LOOPS[mapper_name] = loop_dev
    return f"/dev/mapper/{mapper_name}"


_OPEN_LOOPS: dict[str, str] = {}


def close(mapper_name: str, timeout: int = 60) -> None:
    """Tear down a mapping opened by open_readonly (cryptsetup close + losetup -d)."""
    cryptsetup = shutil.which("cryptsetup")
    losetup = shutil.which("losetup")
    if cryptsetup:
        subprocess.run(["sudo", cryptsetup, "close", mapper_name],
                       capture_output=True, timeout=timeout)
    loop_dev = _OPEN_LOOPS.pop(mapper_name, None)
    if loop_dev and losetup:
        subprocess.run(["sudo", losetup, "-d", loop_dev],
                       capture_output=True, timeout=timeout)
