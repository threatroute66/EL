"""Skill: parse Linux utmp / wtmp / btmp binary login records.

These files are the canonical Linux auth-forensics surface:

  /var/run/utmp       currently-active sessions
  /var/log/wtmp       historical successful logins / logouts / boots
  /var/log/btmp       **failed** auth attempts — brute-force signal

The on-disk format is a fixed-width C struct `utmpx` — 384 bytes per
record on glibc x86_64 (Linux). Pure-Python parse; no external deps.

Layout (glibc 2.x utmpx, x86_64):

    short    ut_type       2  bytes   (+ 2 bytes padding)
    pid_t    ut_pid        4
    char     ut_line[32]  32          tty line ("tty1", "pts/0")
    char     ut_id[4]      4
    char     ut_user[32]  32          username
    char     ut_host[256]256           remote hostname / IP
    struct   ut_exit       8          { e_termination, e_exit }
    int32    ut_session    4
    struct   ut_tv         8          { tv_sec, tv_usec }
    int32    ut_addr_v6[4]16           IPv4 in [0]; IPv6 fills all four
    char     __unused[20] 20
                        --------
                         384  bytes
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


_RECORD_SIZE = 384
_STRUCT_FMT = "<hxx i 32s 4s 32s 256s hhi ii 16s 20s"


_TYPE_NAMES: dict[int, str] = {
    0: "EMPTY",
    1: "RUN_LVL",
    2: "BOOT_TIME",
    3: "NEW_TIME",
    4: "OLD_TIME",
    5: "INIT_PROCESS",
    6: "LOGIN_PROCESS",
    7: "USER_PROCESS",
    8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}


@dataclass
class UtmpRecord:
    type_id: int
    type_name: str
    pid: int
    tty: str
    user: str
    host: str
    session: int
    ts_utc: str              # ISO-8601 string
    addr: str                # "" when zeroed / IPv4 0.0.0.0
    source_file: str = ""
    offset: int = 0


def _cstr(b: bytes) -> str:
    """Null-terminated C string → Python str. Trailing \\x00 pad
    stripped. Decode best-effort (utf-8 → latin-1 fallback for legacy
    locales)."""
    end = b.find(b"\x00")
    raw = b[:end] if end >= 0 else b
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace").strip()


def _addr_from_ut_addr_v6(buf: bytes) -> str:
    """ut_addr_v6 is 16 bytes: IPv4 in the first 4, IPv6 fills all 16.
    Detect which by looking at whether bytes 4..16 are zero."""
    if buf[4:] == b"\x00" * 12:
        # IPv4 in first 4 bytes (little-endian per kernel)
        ip4 = buf[:4]
        if ip4 == b"\x00\x00\x00\x00":
            return ""
        try:
            return socket.inet_ntop(socket.AF_INET, ip4)
        except OSError:
            return ""
    try:
        return socket.inet_ntop(socket.AF_INET6, buf)
    except OSError:
        return ""


def parse_file(path: str | Path) -> list[UtmpRecord]:
    """Parse a utmp/wtmp/btmp file. Records whose ut_type is
    EMPTY / RUN_LVL / unknown are skipped — we only surface the
    auth-meaningful types (BOOT_TIME, INIT_PROCESS, LOGIN_PROCESS,
    USER_PROCESS, DEAD_PROCESS). Silent on I/O + struct errors
    because wtmp files are sometimes truncated."""
    p = Path(path)
    out: list[UtmpRecord] = []
    if not p.is_file():
        return out
    try:
        data = p.read_bytes()
    except OSError:
        return out
    n_records = len(data) // _RECORD_SIZE
    for i in range(n_records):
        off = i * _RECORD_SIZE
        chunk = data[off:off + _RECORD_SIZE]
        try:
            (ut_type, pid, ut_line, ut_id, ut_user, ut_host,
             _eterm, _eexit, session,
             tv_sec, tv_usec, ut_addr_v6, _unused) = struct.unpack(
                _STRUCT_FMT, chunk)
        except struct.error:
            continue
        # Skip empty / non-auth records
        if ut_type in (0, 1):
            continue
        ts = ""
        if tv_sec > 0:
            try:
                ts = datetime.fromtimestamp(
                    tv_sec, tz=timezone.utc).isoformat(
                    timespec="seconds").replace("+00:00", "Z")
            except (OSError, OverflowError, ValueError):
                ts = ""
        out.append(UtmpRecord(
            type_id=int(ut_type),
            type_name=_TYPE_NAMES.get(int(ut_type), f"TYPE_{int(ut_type)}"),
            pid=int(pid), tty=_cstr(ut_line),
            user=_cstr(ut_user), host=_cstr(ut_host),
            session=int(session), ts_utc=ts,
            addr=_addr_from_ut_addr_v6(ut_addr_v6),
            source_file=str(p), offset=off,
        ))
    return out


# ---------------------------------------------------------------------------
# Aggregators used by the agent
# ---------------------------------------------------------------------------

@dataclass
class BruteForceBurst:
    user: str
    source_host: str
    count: int
    first_ts_utc: str
    last_ts_utc: str
    sample_ttys: list[str]


def failed_auth_bursts(records: list[UtmpRecord],
                       threshold: int = 5) -> list[BruteForceBurst]:
    """Group btmp (failed-auth) records by (user, source_host) and
    return groups with count >= threshold. That's the brute-force /
    password-spray signal — many failures against one account (brute)
    or one source hitting many accounts (spray)."""
    groups: dict[tuple[str, str], list[UtmpRecord]] = {}
    for r in records:
        if r.type_name != "LOGIN_PROCESS" and r.type_name != "USER_PROCESS":
            # btmp writes DEAD_PROCESS on failed auth attempts typically.
            # The real selector is: record came from a btmp file —
            # caller should pre-filter. But include DEAD too.
            pass
        key = (r.user or "(unknown)", r.host or r.addr or "(local)")
        groups.setdefault(key, []).append(r)
    bursts: list[BruteForceBurst] = []
    for (user, src), recs in groups.items():
        if len(recs) < threshold:
            continue
        recs.sort(key=lambda x: x.ts_utc)
        bursts.append(BruteForceBurst(
            user=user, source_host=src, count=len(recs),
            first_ts_utc=recs[0].ts_utc, last_ts_utc=recs[-1].ts_utc,
            sample_ttys=sorted({r.tty for r in recs[:5] if r.tty})))
    return bursts


def root_direct_logins(records: list[UtmpRecord]) -> list[UtmpRecord]:
    """Return wtmp records that look like a direct root login — the
    `/etc/securetty` anti-pattern. Any USER_PROCESS where user=='root'
    and host/addr is non-local (remote) is suspect on hardened hosts."""
    out: list[UtmpRecord] = []
    for r in records:
        if r.type_name != "USER_PROCESS":
            continue
        if r.user.lower() != "root":
            continue
        if not (r.host or r.addr):
            continue
        if r.host in ("localhost", "") and not r.addr:
            continue
        out.append(r)
    return out


def source_diversity(records: list[UtmpRecord]) -> dict[str, set[str]]:
    """For each user, return the set of unique source hosts/addrs
    logged in from. A user with 10+ unique sources on the same day
    is a credential-stuffing signal."""
    out: dict[str, set[str]] = {}
    for r in records:
        if r.type_name != "USER_PROCESS" or not r.user:
            continue
        src = r.host or r.addr
        if not src:
            continue
        out.setdefault(r.user, set()).add(src)
    return out


__all__ = [
    "UtmpRecord", "BruteForceBurst",
    "parse_file", "failed_auth_bursts",
    "root_direct_logins", "source_diversity",
]
