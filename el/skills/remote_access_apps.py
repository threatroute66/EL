"""Skill: Remote-access application log parsers.

TeamViewer + AnyDesk are the two remote-access tools attackers reach
for most often — legitimate on many user machines, but any unexpected
**inbound** session is high-signal. Both keep plain-text logs that
list peer identifiers, timestamps, and connection directionality.

TeamViewer:
  - `connections_incoming.txt`  (tab-separated, system-wide)
      Columns: TV-id, displayName, startTime, endTime, localUser, type, guid
  - `TeamViewer<major>_Logfile.log` (timestamped log lines)

AnyDesk:
  - `connection_trace.txt` (per-user)
      Tab-separated: incoming/outgoing flag, ts, peer-id, profile
  - `ad_svc.trace` / `ad.trace` (verbose debug log; we skim for peer
    IDs of established sessions)

Pure functions. No subprocess. Parsers are tolerant of version drift
(column count varies by TV release).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RemoteAccessSession:
    app: str                      # "teamviewer" or "anydesk"
    direction: str                # "inbound" or "outbound"
    peer_id: str = ""             # TV ID or AnyDesk ID
    peer_display: str = ""        # friendly name if present
    start_ts: str = ""
    end_ts: str = ""
    local_user: str = ""          # when captured
    source_file: str = ""


@dataclass
class RemoteAccessHit:
    app: str
    technique: str                # "inbound_session" / "outbound_session"
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    sessions: list[RemoteAccessSession] = field(default_factory=list)
    top_peers: list[tuple[str, int]] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


# --- TeamViewer ----------------------------------------------------------

def parse_teamviewer_incoming(path: Path) -> list[RemoteAccessSession]:
    """Parse TeamViewer's connections_incoming.txt. Each row is one
    inbound session. Column layout has drifted slightly over the years;
    we anchor on TV-id being the first whitespace/tab-separated field
    and fall back gracefully on partial rows."""
    sessions: list[RemoteAccessSession] = []
    p = Path(path)
    if not p.is_file():
        return sessions
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return sessions

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # TeamViewer uses whitespace-padded columns; tab-separated is
        # the modern default but older versions emit multiple spaces.
        parts = re.split(r"\t|\s{2,}", line)
        if not parts or not parts[0]:
            continue
        tv_id = parts[0].strip()
        if not re.match(r"^\d{9,12}$", tv_id):
            # Not a TeamViewer ID → header line / malformed row
            continue
        sess = RemoteAccessSession(
            app="teamviewer",
            direction="inbound",
            peer_id=tv_id,
            peer_display=parts[1].strip() if len(parts) > 1 else "",
            start_ts=parts[2].strip() if len(parts) > 2 else "",
            end_ts=parts[3].strip() if len(parts) > 3 else "",
            local_user=parts[4].strip() if len(parts) > 4 else "",
            source_file=str(p),
        )
        sessions.append(sess)
    return sessions


def detect_teamviewer_inbound_sessions(
    incoming_files: list[Path],
) -> list[RemoteAccessHit]:
    sessions: list[RemoteAccessSession] = []
    for f in incoming_files:
        sessions.extend(parse_teamviewer_incoming(f))
    if not sessions:
        return []
    peers: dict[str, int] = {}
    for s in sessions:
        peers[s.peer_id] = peers.get(s.peer_id, 0) + 1
    top = sorted(peers.items(), key=lambda kv: -kv[1])
    ts = sorted(s.start_ts for s in sessions if s.start_ts)
    return [RemoteAccessHit(
        app="teamviewer",
        technique="inbound_session",
        event_count=len(sessions),
        first_seen=ts[0] if ts else "",
        last_seen=ts[-1] if ts else "",
        sessions=sessions[:10],
        top_peers=top[:10],
        attack=[("T1219", "Remote Access Software")],
    )]


# --- AnyDesk --------------------------------------------------------------

_ANYDESK_LINE_RE = re.compile(
    r"^(?P<direction>\w+)\s+"                 # Incoming / Outgoing
    r"(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<peer>\d{9,12})"                     # peer ID
    r"(?:\s+(?P<profile>.+))?$"
)


def parse_anydesk_connection_trace(path: Path) -> list[RemoteAccessSession]:
    """Parse AnyDesk's connection_trace.txt. One line per session:
      Incoming 2024-06-01 09:41:22 123456789 workprofile
    Older formats omit the profile. Direction is the first column."""
    sessions: list[RemoteAccessSession] = []
    p = Path(path)
    if not p.is_file():
        return sessions
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return sessions
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _ANYDESK_LINE_RE.match(line)
        if not m:
            continue
        direction = m.group("direction").lower()
        if direction not in ("incoming", "outgoing"):
            continue
        sessions.append(RemoteAccessSession(
            app="anydesk",
            direction="inbound" if direction == "incoming" else "outbound",
            peer_id=m.group("peer"),
            peer_display=m.group("profile") or "",
            start_ts=m.group("ts"),
            source_file=str(p),
        ))
    return sessions


def detect_anydesk_sessions(
    trace_files: list[Path],
) -> list[RemoteAccessHit]:
    all_sessions: list[RemoteAccessSession] = []
    for f in trace_files:
        all_sessions.extend(parse_anydesk_connection_trace(f))
    if not all_sessions:
        return []

    hits: list[RemoteAccessHit] = []
    for direction in ("inbound", "outbound"):
        sess = [s for s in all_sessions if s.direction == direction]
        if not sess:
            continue
        peers: dict[str, int] = {}
        for s in sess:
            peers[s.peer_id] = peers.get(s.peer_id, 0) + 1
        top = sorted(peers.items(), key=lambda kv: -kv[1])
        ts = sorted(s.start_ts for s in sess if s.start_ts)
        hits.append(RemoteAccessHit(
            app="anydesk",
            technique=f"{direction}_session",
            event_count=len(sess),
            first_seen=ts[0] if ts else "",
            last_seen=ts[-1] if ts else "",
            sessions=sess[:10],
            top_peers=top[:10],
            attack=[("T1219", "Remote Access Software")],
        ))
    return hits


def run_all(export_dir: Path) -> list[RemoteAccessHit]:
    """Walk an extracted artifacts tree and run every detector.
    Expects the directory layout produced by extract_windows_artifacts'
    remote-access extension (see _extract_remote_access helper).
    """
    root = Path(export_dir)
    if not root.is_dir():
        return []
    tv_incoming = sorted(root.rglob("connections_incoming.txt"))
    anydesk_traces = sorted(root.rglob("connection_trace.txt"))
    hits: list[RemoteAccessHit] = []
    hits.extend(detect_teamviewer_inbound_sessions(tv_incoming))
    hits.extend(detect_anydesk_sessions(anydesk_traces))
    return hits


__all__ = [
    "RemoteAccessSession", "RemoteAccessHit",
    "parse_teamviewer_incoming",
    "parse_anydesk_connection_trace",
    "detect_teamviewer_inbound_sessions",
    "detect_anydesk_sessions",
    "run_all",
]
