"""Browser saved-credential recovery — Firefox NSS login vault.

Productises the Layer-2 analyst step: decrypt a Firefox profile's
``logins.json`` (saved usernames/passwords) using the profile's
``key4.db`` NSS key store. When no Primary (master) password is set the
vault decrypts to cleartext with the empty password — no cracking.

Design note — crash safety: NSS is driven via ``libnss3`` (the
court-vetted Mozilla library, present on SIFT). A malformed/foreign
key4.db can make libnss *segfault*, which would be uncatchable in-process
and would take the whole investigation down. So decryption runs in an
isolated SUBPROCESS (``python -m el.skills.browser_credentials <profile>``);
a crash there is contained as a non-zero exit and surfaces as a graceful
"decryption unavailable" result. The parent never loads libnss.

The analysis helpers (password reuse, alternate-identity detection) are
pure-Python and deterministic — they are what turn recovered logins into
the high-signal findings (credential exposure, reused password, a covert
account identity that doesn't match the profile owner).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class BrowserCredentialsError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# NSS worker — only ever executed in a child process (see decrypt_firefox).
# Kept dependency-free (ctypes + stdlib) so the subprocess is cheap.
# ---------------------------------------------------------------------------

def _nss_decrypt_profile(profile_dir: str) -> dict:
    """Decrypt logins.json in *profile_dir* via libnss3. Returns a plain
    dict (JSON-serialisable). NEVER call this in the parent process — a
    bad key4.db can segfault libnss. Use decrypt_firefox()."""
    import base64
    import ctypes as ct

    prof = Path(profile_dir)
    lf = prof / "logins.json"
    if not lf.is_file():
        return {"ok": False, "error": "no logins.json in profile"}
    try:
        entries = json.loads(lf.read_text()).get("logins", [])
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"logins.json parse: {e}"}

    try:
        nss = ct.CDLL("libnss3.so")
    except OSError as e:
        return {"ok": False, "error": f"libnss3 unavailable: {e}"}

    class SECItem(ct.Structure):
        _fields_ = [("type", ct.c_uint), ("data", ct.c_char_p), ("len", ct.c_uint)]

    nss.NSS_Init.argtypes = [ct.c_char_p]
    nss.NSS_Init.restype = ct.c_int
    nss.PK11_GetInternalKeySlot.restype = ct.c_void_p
    nss.PK11_CheckUserPassword.argtypes = [ct.c_void_p, ct.c_char_p]
    nss.PK11_CheckUserPassword.restype = ct.c_int
    nss.PK11SDR_Decrypt.argtypes = [ct.POINTER(SECItem), ct.POINTER(SECItem), ct.c_void_p]
    nss.PK11SDR_Decrypt.restype = ct.c_int

    if nss.NSS_Init(b"sql:" + str(prof).encode()) != 0:
        return {"ok": False, "error": "NSS_Init failed (no/invalid key4.db?)"}
    slot = nss.PK11_GetInternalKeySlot()
    if not slot:
        return {"ok": False, "error": "no internal key slot"}
    # Empty primary password accepted -> rc 0; rejected -> a primary
    # password IS set and the vault is not offline-recoverable here.
    primary_set = nss.PK11_CheckUserPassword(slot, b"") != 0

    def _dec(b64: str):
        if not b64:
            return None
        try:
            raw = base64.b64decode(b64)
            i = SECItem(0, raw, len(raw))
            o = SECItem(0, None, 0)
            if nss.PK11SDR_Decrypt(ct.byref(i), ct.byref(o), None) != 0:
                return None
            return ct.string_at(o.data, o.len).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return None

    logins = []
    if not primary_set:
        for L in entries:
            logins.append({
                "origin": L.get("hostname") or L.get("origin"),
                "username": _dec(L.get("encryptedUsername", "")),
                "password": _dec(L.get("encryptedPassword", "")),
                "timeCreated": L.get("timeCreated"),
                "timeLastUsed": L.get("timeLastUsed"),
                "timePasswordChanged": L.get("timePasswordChanged"),
            })
    return {"ok": True, "primary_password_set": primary_set,
            "saved_count": len(entries), "logins": logins}


# ---------------------------------------------------------------------------
# Result + parent-side API
# ---------------------------------------------------------------------------

@dataclass
class FirefoxLogin:
    origin: str
    username: str | None
    password: str | None
    time_created: int | None = None
    time_last_used: int | None = None


@dataclass
class FirefoxCredsResult:
    profile_dir: Path
    ok: bool
    primary_password_set: bool
    saved_count: int
    logins: list[FirefoxLogin] = field(default_factory=list)
    error: str | None = None
    command: list[str] = field(default_factory=list)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        f = {
            "saved_logins": self.saved_count,
            "primary_password_set": self.primary_password_set,
            "decrypted": sum(1 for L in self.logins if L.password is not None),
        }
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="libnss3 (Firefox NSS vault)", version="PK11SDR_Decrypt",
            command=" ".join(self.command) or f"nss decrypt {self.profile_dir}",
            output_sha256="0" * 64,  # decryption is in-memory; logins.json hash carries provenance
            output_path=str(self.profile_dir / "logins.json"),
            extracted_facts=f, source_reliability="A", info_credibility="1",
        )


def is_firefox_profile(d: Path) -> bool:
    d = Path(d)
    return (d / "logins.json").is_file() and (d / "key4.db").is_file()


def decrypt_firefox(profile_dir: str | Path, timeout: int = 60) -> FirefoxCredsResult:
    """Decrypt a Firefox login vault in an isolated subprocess (crash-safe).
    Returns ok=False (never raises) when the profile is incomplete, a
    primary password is set, libnss is missing, or the worker crashes."""
    profile_dir = Path(profile_dir)
    cmd = [sys.executable, "-m", "el.skills.browser_credentials", str(profile_dir)]
    if not is_firefox_profile(profile_dir):
        return FirefoxCredsResult(profile_dir, ok=False, primary_password_set=False,
                                  saved_count=0, error="no logins.json + key4.db",
                                  command=cmd)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return FirefoxCredsResult(profile_dir, ok=False, primary_password_set=False,
                                  saved_count=0, error="decrypt subprocess timeout",
                                  command=cmd)
    if proc.returncode != 0 or not proc.stdout.strip():
        # non-zero = libnss segfault/abort isolated to the child
        return FirefoxCredsResult(profile_dir, ok=False, primary_password_set=False,
                                  saved_count=0,
                                  error=f"decrypt worker rc={proc.returncode} "
                                        f"{(proc.stderr or '').strip()[:120]}",
                                  command=cmd)
    try:
        d = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return FirefoxCredsResult(profile_dir, ok=False, primary_password_set=False,
                                  saved_count=0, error=f"worker output: {e}", command=cmd)
    return FirefoxCredsResult(
        profile_dir=profile_dir, ok=bool(d.get("ok")),
        primary_password_set=bool(d.get("primary_password_set")),
        saved_count=int(d.get("saved_count", 0)),
        logins=[FirefoxLogin(
            origin=L.get("origin") or "", username=L.get("username"),
            password=L.get("password"), time_created=L.get("timeCreated"),
            time_last_used=L.get("timeLastUsed")) for L in d.get("logins", [])],
        error=d.get("error"), command=cmd)


# ---------------------------------------------------------------------------
# Pure-Python analysis helpers (deterministic; drive the findings)
# ---------------------------------------------------------------------------

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def password_reuse(logins: list[FirefoxLogin]) -> dict[str, list[str]]:
    """password -> [origins] for passwords reused across >=2 distinct
    origins (case-sensitive; a single typo'd-case variant still counts as
    its own bucket, which is itself worth surfacing)."""
    by_pw: dict[str, list[str]] = {}
    for L in logins:
        if L.password:
            by_pw.setdefault(L.password, []).append(L.origin)
    return {pw: sorted(set(o)) for pw, o in by_pw.items() if len(set(o)) >= 2}


def _local_part_tokens(email: str) -> set[str]:
    local = email.split("@", 1)[0].lower()
    return {t for t in re.split(r"[._\-+0-9]+", local) if len(t) >= 3}


def find_alternate_identities(logins: list[FirefoxLogin]) -> list[str]:
    """Email usernames whose local-part shares NO token with the dominant
    (most-common) owner local-part. Surfaces a covert/alternate identity
    (e.g. 'redguard.cobra@gmail.com' among a 'fred.rocba' majority)
    without needing an external owner hint."""
    emails = sorted({L.username for L in logins
                     if L.username and _EMAIL.match(L.username)})
    if len(emails) < 2:
        return []
    # Dominant owner = the local-part token-set seen on the most accounts.
    tok_counts: Counter = Counter()
    for e in emails:
        for t in _local_part_tokens(e):
            tok_counts[t] += 1
    if not tok_counts:
        return []
    owner_tokens = {t for t, c in tok_counts.items() if c == max(tok_counts.values())}
    alt = [e for e in emails if not (_local_part_tokens(e) & owner_tokens)]
    return alt


def _main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(json.dumps({"ok": False, "error": "usage: <profile_dir>"}))
        return 2
    print(json.dumps(_nss_decrypt_profile(argv[1])))
    return 0


if __name__ == "__main__":  # subprocess worker entrypoint
    raise SystemExit(_main(sys.argv))
