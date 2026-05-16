"""Skill: Outlook PST/OST parsing via libpff.

Wraps the `pffinfo` (metadata) and `pffexport` (message extraction) tools
from libpff/libyal — preinstalled on SIFT. We prefer libpff over libpst's
`readpst` because the per-message directory layout (InternetHeaders.txt +
OutlookHeaders.txt + Recipients.txt + Attachments/) preserves the
structured fields an analyst needs (display-name vs. SMTP-address
mismatches, per-recipient types, exact timestamps) without forcing a
mail-format round-trip.

Each exported message becomes a `Message` dataclass with:
  folder, subject, sender_name, sender_email, recipients (list of
  (display_name, email, recipient_type)), date_submit_utc, flags,
  attachments (list of filenames, sha256-hashed in-place).

Conservative by design — all timestamps in UTC, all hashes SHA-256 of
raw bytes. Parser is tolerant of missing fields (some exported messages
don't have InternetHeaders.txt; some OutlookHeaders.txt lack a Sender
when the sender is unresolved).
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from el.schemas.finding import EvidenceItem


class OutlookPstError(RuntimeError):
    pass


@dataclass
class Recipient:
    display_name: str
    email: str
    recipient_type: str   # "To" / "CC" / "BCC"


@dataclass
class Attachment:
    filename: str
    path: Path
    sha256: str
    size_bytes: int


@dataclass
class Message:
    folder: str                     # "Inbox", "Sent Items", etc.
    message_dir: Path
    subject: str
    sender_name: str
    sender_email: str
    recipients: list[Recipient]
    date_submit_utc: datetime | None
    flags: str                      # raw "Flags:" value, includes "Has attachments"
    size_bytes: int
    attachments: list[Attachment] = field(default_factory=list)
    # Parsed InternetHeaders.txt — populated by _parse_message when the
    # pffexport-emitted headers file is present. None when the headers
    # file is missing (some PST messages predate Outlook's header
    # preservation, or libpff couldn't decode them). Detectors read
    # `header_chain.originator_ip` / `.return_path` to surface the
    # real sender infrastructure underneath any display-name spoof.
    header_chain: "object | None" = None     # el.skills.email_headers.HeaderChain

    @property
    def has_attachments(self) -> bool:
        return bool(self.attachments) or "has attachments" in self.flags.lower()


@dataclass
class PstRun:
    pst_path: Path
    out_dir: Path                   # the ".export" directory pffexport created
    rc: int
    folders: list[str]              # folder names seen in pffinfo output
    command: list[str]
    messages: list[Message]

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        h = hashlib.sha256(self.pst_path.read_bytes())
        merged = {"message_count": len(self.messages),
                  "folders": self.folders,
                  "out_dir": str(self.out_dir)}
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool="libpff/pffexport", version=_version("pffexport"),
            command=" ".join(self.command),
            output_sha256=h.hexdigest(),
            output_path=str(self.pst_path),
            extracted_facts=merged,
        )


def _which(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        raise OutlookPstError(f"{tool} not on PATH (install libpff-tools)")
    return p


def _version(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        return "unknown"
    try:
        r = subprocess.run([p, "-V"], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr).splitlines()[0].strip() if (r.stdout or r.stderr) else "present"
    except Exception:
        return "present"


# -- pffinfo ---------------------------------------------------------------

_FOLDERS_LINE = re.compile(r"^\s*Folders:\s*(.+)$", re.M)


def info(pst_path: Path, timeout: int = 60) -> dict:
    """Run pffinfo; return {file_size, encryption, folders: [names]}."""
    pst_path = Path(pst_path)
    if not pst_path.is_file():
        raise OutlookPstError(f"PST not found: {pst_path}")
    cmd = [_which("pffinfo"), str(pst_path)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise OutlookPstError(f"pffinfo timeout after {timeout}s") from e
    if r.returncode != 0:
        raise OutlookPstError(f"pffinfo failed rc={r.returncode}: {r.stderr.strip()}")
    out = {"stdout": r.stdout, "folders": []}
    m = _FOLDERS_LINE.search(r.stdout)
    if m:
        out["folders"] = [f.strip() for f in m.group(1).split(",") if f.strip()]
    return out


# -- pffexport + message parsing ------------------------------------------

def export(pst_path: Path, out_dir: Path, timeout: int = 1800) -> PstRun:
    """pffexport the PST into out_dir (creates `<out_dir>.export/`).

    Returns a PstRun with parsed Message objects. Use this as the entry
    point — the caller doesn't have to touch the pffexport directory
    layout directly.
    """
    pst_path = Path(pst_path)
    out_dir = Path(out_dir)
    if not pst_path.is_file():
        raise OutlookPstError(f"PST not found: {pst_path}")

    # pffexport creates `<target>.export/` next to <target>; let the caller
    # choose a clean target path.
    export_root = out_dir.with_suffix(out_dir.suffix + ".export") \
        if out_dir.suffix else Path(str(out_dir) + ".export")
    if export_root.exists():
        # pffexport refuses to overwrite — tolerate prior runs by cleaning.
        shutil.rmtree(export_root)

    out_dir.parent.mkdir(parents=True, exist_ok=True)

    cmd = [_which("pffexport"), "-q", "-t", str(out_dir), str(pst_path)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise OutlookPstError(f"pffexport timeout after {timeout}s") from e
    if r.returncode != 0:
        raise OutlookPstError(f"pffexport failed rc={r.returncode}: {r.stderr.strip()[:400]}")

    if not export_root.is_dir():
        raise OutlookPstError(f"pffexport completed but {export_root} missing")

    folders = _list_folder_names(export_root)
    messages = list(_iter_messages(export_root))
    return PstRun(pst_path=pst_path, out_dir=export_root, rc=r.returncode,
                  folders=folders, command=cmd, messages=messages)


def _list_folder_names(export_root: Path) -> list[str]:
    """Top-of-Personal-Folders → its children are the real mail folders."""
    top = None
    for entry in export_root.iterdir():
        if entry.is_dir() and "personal folders" in entry.name.lower():
            top = entry
            break
    if top is None:
        # No "Top of Personal Folders" wrapper — treat immediate children as folders
        top = export_root
    return sorted(d.name for d in top.iterdir() if d.is_dir())


def _iter_messages(export_root: Path):
    """Walk each message directory: <root>/<TopOfPersonal>/<Folder>/<MessageNNNN>/*"""
    for msg_dir in export_root.rglob("Message*"):
        if not msg_dir.is_dir():
            continue
        if not re.fullmatch(r"Message\d+", msg_dir.name):
            continue
        yield _parse_message(msg_dir)


# --- message field parsing ---

_OUTLOOK_FIELDS = (
    "Subject",
    "Sender name",
    "Sender email address",
    "Client submit time",
    "Delivery time",
    "Flags",
    "Size",
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _kv_field(text: str, name: str) -> str:
    pat = re.compile(rf"^\s*{re.escape(name)}\s*:\s*(.*)$", re.M)
    m = pat.search(text)
    return m.group(1).strip() if m else ""


def _parse_date_utc(s: str) -> datetime | None:
    """Parse pffexport's date format: 'Jul 20, 2008 01:28:47.828125000 UTC'."""
    if not s:
        return None
    try:
        # Strip sub-second precision beyond microseconds (Python stdlib limit)
        m = re.match(r"(\w+ \d+, \d+ \d+:\d+:\d+)(\.\d+)? UTC", s)
        if not m:
            return None
        base = m.group(1)
        frac = m.group(2) or ".0"
        # Truncate fractional to 6 digits
        frac = frac[:7]  # ".123456"
        dt = datetime.strptime(base + frac, "%b %d, %Y %H:%M:%S.%f")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _parse_recipients(text: str) -> list[Recipient]:
    """Recipients.txt is a series of blocks:
        Display name:    <name>
        Email address:   <addr>
        Address type:    SMTP/EX
        Recipient type:  To/CC/BCC
    Blocks separated by blank lines (sometimes).
    """
    out: list[Recipient] = []
    cur: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                out.append(Recipient(
                    display_name=cur.get("display name", ""),
                    email=cur.get("email address", ""),
                    recipient_type=cur.get("recipient type", ""),
                ))
                cur = {}
            continue
        m = re.match(r"\s*([A-Za-z ]+):\s*(.*)$", line)
        if m:
            key = m.group(1).strip().lower()
            cur[key] = m.group(2).strip()
    if cur:
        out.append(Recipient(
            display_name=cur.get("display name", ""),
            email=cur.get("email address", ""),
            recipient_type=cur.get("recipient type", ""),
        ))
    return out


def _collect_attachments(msg_dir: Path) -> list[Attachment]:
    """Attachments/ subdirectory, when present. pffexport names files
    `<N>_<original>` when there are multiple; we keep the display name."""
    attdir = msg_dir / "Attachments"
    if not attdir.is_dir():
        return []
    out: list[Attachment] = []
    for f in sorted(attdir.iterdir()):
        if not f.is_file():
            continue
        data = f.read_bytes()
        out.append(Attachment(
            filename=f.name,
            path=f,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
        ))
    return out


def _parse_message(msg_dir: Path) -> Message:
    outlook = _read(msg_dir / "OutlookHeaders.txt")
    recips = _read(msg_dir / "Recipients.txt")
    size_s = _kv_field(outlook, "Size")
    size_b = 0
    if size_s.isdigit():
        size_b = int(size_s)
    # Folder name is the message_dir's parent's name (folder/Message0001)
    folder = msg_dir.parent.name if msg_dir.parent else ""

    # Parse the raw SMTP envelope + Received chain from
    # InternetHeaders.txt. Inbound mail in pffexport's output
    # carries the full RFC 5322 header block; outbound mail
    # composed in Outlook usually lacks it (the headers aren't
    # written until the SMTP submission happens, which is the
    # mail server's job, not the client's). header_chain stays
    # None when the file is missing or empty — detectors should
    # treat that as a soft signal, not a parse failure.
    header_chain = None
    raw_headers = _read(msg_dir / "InternetHeaders.txt")
    if raw_headers:
        try:
            from el.skills.email_headers import parse as _parse_hdrs
            header_chain = _parse_hdrs(raw_headers)
        except Exception:
            header_chain = None

    return Message(
        folder=folder,
        message_dir=msg_dir,
        subject=_kv_field(outlook, "Subject"),
        sender_name=_kv_field(outlook, "Sender name"),
        sender_email=_kv_field(outlook, "Sender email address"),
        recipients=_parse_recipients(recips),
        date_submit_utc=_parse_date_utc(_kv_field(outlook, "Client submit time")),
        flags=_kv_field(outlook, "Flags"),
        size_bytes=size_b,
        attachments=_collect_attachments(msg_dir),
        header_chain=header_chain,
    )
