"""Apple Mail (.emlx) parser — message metadata + body + Mail.app flags.

macOS Mail stores each message as an ``.emlx`` file under
``~/Library/Mail/V*/<account>/<mailbox>.mbox/<uuid>/Data/Messages/<n>.emlx``
(``.partial.emlx`` for partially-downloaded ones). An emlx is three parts:

    <byte-count>\\n
    <RFC-822 message>            (exactly <byte-count> bytes)
    <Apple plist>               (Mail.app's own metadata)

The RFC-822 half is parsed with Python's vetted ``email`` package (the
court-defensible RFC parser); the trailing plist carries Mail.app state that
is nowhere in the message itself — the ``flags`` bitfield (read / flagged /
answered / deleted), the ``color`` tag, ``date-last-viewed``, the
conversation id, and Gmail label ids. No SIFT-bundled CLI structures emlx, so
this is a native parser in the spirit of the utmp / W3C-log parsers.

Read-only: evidence files are only ever opened for reading.
"""
from __future__ import annotations

import hashlib
import html
import json
import plistlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import message_from_bytes, policy
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path

from el.schemas.finding import EvidenceItem


class AppleMailError(Exception):
    pass


# emlx ``flags`` is an integer bitfield; the low bits are Mail.app message
# state (higher bits carry Gmail/label data we ignore). Well-agreed bits:
_FLAG_BITS = {0: "read", 1: "deleted", 2: "answered", 4: "flagged"}

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_EPOCH_MIN = 946_684_800        # 2000-01-01
_EPOCH_MAX = 4_102_444_800      # 2100-01-01


def _epoch_to_utc(value) -> str:
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return ""
    if not (_EPOCH_MIN <= ts <= _EPOCH_MAX):
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")


def _decode_flags(flags) -> list[str]:
    if not isinstance(flags, int):
        return []
    return [name for bit, name in sorted(_FLAG_BITS.items())
            if flags & (1 << bit)]


def _clean_body(text: str, subtype: str) -> str:
    if not isinstance(text, str):
        return ""
    if subtype == "html":
        text = _TAG_RE.sub(" ", text)
        text = html.unescape(text)
    return _WS_RE.sub(" ", text).strip()[:500]


@dataclass
class MailMessage:
    path: str = ""
    message_id: str = ""
    date_utc: str = ""
    from_name: str = ""
    from_addr: str = ""
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    subject: str = ""
    body_snippet: str = ""
    is_partial: bool = False
    # Mail.app trailing-plist state:
    mail_flags: list[str] = field(default_factory=list)
    color: str = ""
    date_last_viewed_utc: str = ""
    conversation_id: int | None = None
    gmail_label_ids: list[int] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "message_id": self.message_id,
            "date_utc": self.date_utc,
            "from_name": self.from_name,
            "from_addr": self.from_addr,
            "to": self.to,
            "cc": self.cc,
            "subject": self.subject,
            "body_snippet": self.body_snippet,
            "is_partial": self.is_partial,
            "mail_flags": self.mail_flags,
            "color": self.color,
            "date_last_viewed_utc": self.date_last_viewed_utc,
            "conversation_id": self.conversation_id,
            "gmail_label_ids": self.gmail_label_ids,
        }


@dataclass
class AppleMailRun:
    mail_root: Path
    messages: list[MailMessage] = field(default_factory=list)
    parsed_count: int = 0
    error_count: int = 0
    output_path: Path | None = None
    output_sha256: str = ""
    note: str = ""

    @property
    def total(self) -> int:
        return len(self.messages)

    def top_correspondents(self, n: int = 10) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for m in self.messages:
            if m.from_addr:
                counts[m.from_addr] = counts.get(m.from_addr, 0) + 1
        return sorted(counts.items(), key=lambda kv: -kv[1])[:n]

    def search(self, term: str) -> list[MailMessage]:
        t = term.lower()
        return [m for m in self.messages
                if t in m.subject.lower() or t in m.body_snippet.lower()]

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="el.apple_mail", version="0.1.0",
            command=f"parse .emlx tree -- {self.mail_root}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.mail_root),
            extracted_facts={
                "mail_root": str(self.mail_root),
                "message_count": self.total,
                "parsed_count": self.parsed_count,
                "error_count": self.error_count,
                "top_correspondents": dict(self.top_correspondents(10)),
                "note": self.note,
                **extra,
            },
        )


def find_mail_root(macos_root: Path) -> Path | None:
    """Locate a ``Library/Mail`` dir (per-user or system) under an extracted
    macOS filesystem. Returns the first one that contains a ``V*`` store."""
    macos_root = Path(macos_root)
    candidates: list[Path] = []
    users = macos_root / "Users"
    if users.is_dir():
        for u in users.iterdir():
            if u.is_dir():
                candidates.append(u / "Library" / "Mail")
    candidates.append(macos_root / "Library" / "Mail")
    # macos_root may itself be a Mail dir.
    candidates.append(macos_root)
    for c in candidates:
        if c.is_dir() and any(c.glob("V*")):
            return c
    return None


def parse_emlx(path: Path) -> MailMessage | None:
    """Parse one ``.emlx`` / ``.partial.emlx`` into a :class:`MailMessage`.
    Returns ``None`` if the file can't be read at all."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError:
        return None

    # Split: first line is the RFC-822 byte count; the plist follows.
    nl = raw.find(b"\n")
    msg_bytes = raw
    tail = b""
    if nl != -1 and raw[:nl].strip().isdigit():
        length = int(raw[:nl].strip())
        msg_bytes = raw[nl + 1: nl + 1 + length]
        tail = raw[nl + 1 + length:]

    try:
        msg = message_from_bytes(msg_bytes, policy=policy.default)
    except Exception:
        return None

    out = MailMessage(path=str(path),
                      is_partial=path.name.endswith(".partial.emlx"))

    try:
        out.subject = str(msg["subject"] or "")[:500]
    except Exception:
        out.subject = ""
    try:
        out.message_id = str(msg["message-id"] or "")[:256]
    except Exception:
        out.message_id = ""
    try:
        out.from_name, out.from_addr = parseaddr(str(msg["from"] or ""))
    except Exception:
        out.from_name = out.from_addr = ""
    for hdr, dest in (("to", out.to), ("cc", out.cc)):
        try:
            dest.extend(a for _n, a in getaddresses(msg.get_all(hdr, [])) if a)
        except Exception:
            pass
    try:
        dt = parsedate_to_datetime(str(msg["date"] or ""))
        if dt is not None:
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc)
            out.date_utc = dt.strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        out.date_utc = ""

    out.body_snippet = _extract_body(msg)

    # Mail.app trailing plist.
    i = tail.find(b"<?xml")
    if i != -1:
        try:
            meta = plistlib.loads(tail[i:])
        except Exception:
            meta = None
        if isinstance(meta, dict):
            out.mail_flags = _decode_flags(meta.get("flags"))
            out.color = str(meta.get("color") or "")
            out.date_last_viewed_utc = _epoch_to_utc(
                meta.get("date-last-viewed"))
            cid = meta.get("conversation-id")
            out.conversation_id = cid if isinstance(cid, int) else None
            labels = meta.get("gmail-label-ids")
            if isinstance(labels, list):
                out.gmail_label_ids = [x for x in labels if isinstance(x, int)]
    return out


def _extract_body(msg) -> str:
    try:
        body = msg.get_body(preferencelist=("plain", "html"))
    except Exception:
        body = None
    if body is None:
        try:
            if not msg.is_multipart():
                return _clean_body(msg.get_content(),
                                   msg.get_content_subtype())
        except Exception:
            return ""
        return ""
    try:
        return _clean_body(body.get_content(), body.get_content_subtype())
    except Exception:
        return ""


def iter_emlx(mail_root: Path):
    """Yield every .emlx / .partial.emlx path under *mail_root*, sorted for
    deterministic order."""
    mail_root = Path(mail_root)
    yield from sorted(
        p for p in mail_root.rglob("*.emlx") if p.is_file())


def parse(mail_root: Path, output_dir: Path | None = None,
          *, max_messages: int = 20_000) -> AppleMailRun:
    """Walk *mail_root* and parse up to *max_messages* emlx files. Writes a
    JSONL dump under *output_dir* when given."""
    mail_root = Path(mail_root)
    if not mail_root.is_dir():
        raise AppleMailError(f"mail root not found: {mail_root}")

    run = AppleMailRun(mail_root=mail_root)
    for path in iter_emlx(mail_root):
        if run.total >= max_messages:
            run.note = f"capped at {max_messages} messages"
            break
        msg = parse_emlx(path)
        if msg is None:
            run.error_count += 1
            continue
        run.parsed_count += 1
        run.messages.append(msg)

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "apple_mail_messages.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for m in run.messages:
                f.write(json.dumps(m.as_dict(), sort_keys=True) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run
