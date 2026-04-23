"""Skill: walk a Thunderbird profile's mbox files and surface messages
with attachments or suspicious content.

Thunderbird stores mail as mbox files under
`~/.thunderbird/<profile>/Mail/<server>/` and
`~/.thunderbird/<profile>/ImapMail/<server>/`. Each folder file is a
concatenation of RFC 822 messages separated by `From ` lines — stdlib
`mailbox.mbox` parses them directly, no external deps.

The parallel to `outlook_pst.py` is deliberate: same dataclass surface
(Message / Attachment / Recipient), same evidence hashing, so the two
skills feed similar Finding shapes into ACH / the knowledge DB.

BelkaCTF Kidnapper: Ivan's Thunderbird attachments held the
10-million-password-list wordlist and several password-locked archives
— evidence that never reached the investigator because no skill walked
mbox.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import mailbox
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from el.schemas.finding import EvidenceItem


@dataclass
class Recipient:
    display_name: str
    email: str
    recipient_type: str     # "To" / "Cc" / "Bcc"


@dataclass
class Attachment:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


@dataclass
class Message:
    mbox_path: Path
    folder: str             # mbox filename stem ("Inbox", "Sent")
    subject: str
    sender_name: str
    sender_email: str
    recipients: list[Recipient]
    date_utc: datetime | None
    message_id: str
    size_bytes: int
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def has_attachments(self) -> bool:
        return bool(self.attachments)


@dataclass
class MboxRun:
    root: Path
    messages: list[Message]
    mbox_paths: list[Path]

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        seed = "\n".join(sorted(str(p) for p in self.mbox_paths)).encode()
        sha = hashlib.sha256(seed).hexdigest()
        f = {"message_count": len(self.messages),
             "mbox_count": len(self.mbox_paths),
             "mbox_paths": [str(p) for p in self.mbox_paths]}
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="stdlib.mailbox", version="mailbox-py",
            command=f"walk({self.root})",
            output_sha256=sha, output_path=str(self.root),
            extracted_facts=f,
        )


def _split_addr(raw: str | None) -> tuple[str, str]:
    if not raw:
        return ("", "")
    addr = email.utils.parseaddr(raw)
    return (addr[0] or "", addr[1] or "")


def _recipients(msg: email.message.Message) -> list[Recipient]:
    out: list[Recipient] = []
    for field_name, type_label in (("To", "To"), ("Cc", "Cc"), ("Bcc", "Bcc")):
        raw = msg.get(field_name)
        if not raw:
            continue
        for disp, addr in email.utils.getaddresses([raw]):
            if addr:
                out.append(Recipient(
                    display_name=disp, email=addr,
                    recipient_type=type_label,
                ))
    return out


def _date_utc(msg: email.message.Message) -> datetime | None:
    raw = msg.get("Date")
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _attachments(msg: email.message.Message) -> list[Attachment]:
    out: list[Attachment] = []
    if not msg.is_multipart():
        return out
    for part in msg.walk():
        disp = (part.get("Content-Disposition") or "").lower()
        filename = part.get_filename()
        if not filename or "attachment" not in disp and "inline" not in disp:
            continue
        if not filename:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        out.append(Attachment(
            filename=filename,
            content_type=part.get_content_type() or "application/octet-stream",
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        ))
    return out


def _parse_mbox_file(path: Path) -> list[Message]:
    msgs: list[Message] = []
    try:
        mb = mailbox.mbox(str(path), create=False)
    except Exception:
        return msgs
    folder = path.stem
    for key, raw in mb.iteritems():
        try:
            msg = email.message_from_bytes(
                raw.as_bytes(), policy=email.policy.compat32
            )
        except Exception:
            continue
        sender_name, sender_email = _split_addr(msg.get("From"))
        msgs.append(Message(
            mbox_path=path, folder=folder,
            subject=msg.get("Subject", "") or "",
            sender_name=sender_name, sender_email=sender_email,
            recipients=_recipients(msg),
            date_utc=_date_utc(msg),
            message_id=msg.get("Message-ID", "") or "",
            size_bytes=len(raw.as_bytes()),
            attachments=_attachments(msg),
        ))
    return msgs


def _find_mbox_files(root: Path) -> list[Path]:
    """Walk any Thunderbird-profile-shaped root for mbox files.

    Matches both Mozilla/Thunderbird profile layouts:
      <profile>/Mail/<server>/<folder>
      <profile>/ImapMail/<server>/<folder>
    Folders lack an extension. Also allows arbitrary trees
    (mail/ subdir) so callers can pass any root.
    """
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in {".msf", ".dat", ".sbd", ".ini"}:
            continue
        try:
            with p.open("rb") as fh:
                head = fh.read(8)
        except OSError:
            continue
        if head.startswith(b"From "):
            out.append(p)
    return out


def walk(root: Path) -> MboxRun:
    """Parse every mbox under *root* and return an aggregated MboxRun."""
    mbox_paths = _find_mbox_files(root)
    messages: list[Message] = []
    for mbp in mbox_paths:
        messages.extend(_parse_mbox_file(mbp))
    return MboxRun(root=root, messages=messages, mbox_paths=mbox_paths)
