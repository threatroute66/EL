"""iOS Messages (sms.db) parser — iMessage / SMS with attributedBody decode.

``/private/var/mobile/Library/SMS/sms.db`` holds the device's iMessage + SMS
history. On iOS 14+ the ``message.text`` column is frequently NULL and the
text lives only in the ``attributedBody`` typedstream blob — so a naive read
returns empty messages. This composes the evidence-safe SQLite reader
(:mod:`el.skills._sqlite`, WAL-applied, read-only copy) with the typedstream
decoder (:func:`el.skills.apple_archive.imessage_text`) to recover the real
text, joined to handles (the other party) and chats.

No SIFT-bundled CLI does this join+decode, so it's a native parser built on
EL's own primitives. Read-only throughout.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from el.schemas.finding import EvidenceItem
from el.skills._sqlite import EvidenceDBError, open_evidence_db
from el.skills.apple_archive import imessage_text

_MAC_EPOCH_OFFSET = 978307200          # 2001-01-01 -> 1970-01-01 seconds


class IOSMessagesError(Exception):
    pass


def _date_to_utc(value) -> str:
    """sms.db dates are seconds (old) or nanoseconds (iOS 11+) since
    2001-01-01. Normalise to 'YYYY-MM-DD HH:MM:SS' UTC."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return ""
    if v == 0:
        return ""
    secs = v / 1_000_000_000 if v > 1_000_000_000_000 else float(v)
    try:
        return (datetime(2001, 1, 1, tzinfo=timezone.utc)
                + timedelta(seconds=secs)).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class IMessage:
    rowid: int = 0
    date_utc: str = ""
    is_from_me: bool = False
    contact: str = ""            # handle id (phone / email) of the other party
    service: str = ""           # iMessage / SMS
    text: str = ""
    chat: str = ""

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class MessagesRun:
    db_path: Path
    messages: list[IMessage] = field(default_factory=list)
    output_path: Path | None = None
    output_sha256: str = ""

    @property
    def total(self) -> int:
        return len(self.messages)

    @property
    def sent(self) -> int:
        return sum(1 for m in self.messages if m.is_from_me)

    @property
    def received(self) -> int:
        return self.total - self.sent

    def contacts(self) -> list[str]:
        return sorted({m.contact for m in self.messages if m.contact})

    def top_contacts(self, n: int = 10) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for m in self.messages:
            if m.contact:
                counts[m.contact] = counts.get(m.contact, 0) + 1
        return sorted(counts.items(), key=lambda kv: -kv[1])[:n]

    def find(self, needle: str, *, sent_only: bool = False) -> list[IMessage]:
        t = needle.lower()
        return [m for m in self.messages
                if t in m.text.lower() and (m.is_from_me or not sent_only)]

    def date_range(self) -> tuple[str, str]:
        ds = [m.date_utc for m in self.messages if m.date_utc]
        return (min(ds), max(ds)) if ds else ("", "")

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        lo, hi = self.date_range()
        return EvidenceItem(
            tool="el.ios_messages", version="0.1.0",
            command=f"parse sms.db (attributedBody-decoded) -- {self.db_path}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.db_path),
            extracted_facts={
                "db_path": str(self.db_path),
                "message_count": self.total,
                "sent": self.sent,
                "received": self.received,
                "distinct_contacts": len(self.contacts()),
                "first_message_utc": lo,
                "last_message_utc": hi,
                "top_contacts": dict(self.top_contacts(10)),
                **extra,
            },
        )


def find_sms_db(fs_root: Path) -> Path | None:
    fs_root = Path(fs_root)
    for rel in (("private", "var", "mobile", "Library", "SMS", "sms.db"),
                ("var", "mobile", "Library", "SMS", "sms.db")):
        p = fs_root.joinpath(*rel)
        if p.is_file():
            return p
    if fs_root.name == "sms.db" and fs_root.is_file():
        return fs_root
    direct = fs_root / "sms.db"
    return direct if direct.is_file() else None


def parse(sms_db: Path, output_dir: Path | None = None,
          *, max_messages: int = 500_000) -> MessagesRun:
    """Parse sms.db into decoded :class:`IMessage` records (text recovered
    from ``attributedBody`` when the ``text`` column is empty). Writes a
    JSONL dump under *output_dir* when given."""
    sms_db = Path(sms_db)
    if not sms_db.is_file():
        raise IOSMessagesError(f"sms.db not found: {sms_db}")

    run = MessagesRun(db_path=sms_db)
    workdir = Path(output_dir) / "_dbcopy" if output_dir else None
    try:
        with open_evidence_db(sms_db, workdir=workdir,
                              row_factory=sqlite3.Row) as conn:
            try:
                cur = conn.execute("""
                    SELECT m.ROWID AS rid, m.date AS date, m.is_from_me AS fromme,
                           m.text AS text, m.attributedBody AS ab,
                           m.service AS service, h.id AS handle,
                           c.chat_identifier AS chatid
                    FROM message m
                    LEFT JOIN handle h ON m.handle_id = h.ROWID
                    LEFT JOIN chat_message_join cmj ON cmj.message_id = m.ROWID
                    LEFT JOIN chat c ON c.ROWID = cmj.chat_id
                    ORDER BY m.date
                """)
            except sqlite3.Error as e:
                raise IOSMessagesError(f"sms.db schema unexpected: {e}") from e
            for r in cur:
                if run.total >= max_messages:
                    break
                text = r["text"] or ""
                if not text and r["ab"] is not None:
                    text = imessage_text(r["ab"])
                run.messages.append(IMessage(
                    rowid=r["rid"] or 0,
                    date_utc=_date_to_utc(r["date"]),
                    is_from_me=bool(r["fromme"]),
                    contact=str(r["handle"] or ""),
                    service=str(r["service"] or ""),
                    text=text or "",
                    chat=str(r["chatid"] or ""),
                ))
    except EvidenceDBError as e:
        raise IOSMessagesError(str(e)) from e

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "ios_messages.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for m in run.messages:
                f.write(json.dumps(m.as_dict(), ensure_ascii=False) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run
