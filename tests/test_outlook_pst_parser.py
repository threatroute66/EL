"""Parser-level tests for el.skills.outlook_pst.

We don't carry real PST binaries in the repo. Instead, we build a
pre-exported directory structure programmatically — the exact layout
pffexport produces — and exercise the parse helpers (_parse_message,
_parse_recipients, _list_folder_names, _parse_date_utc). This locks
the parser's understanding of libpff's output format.
"""
from datetime import datetime, timezone
from pathlib import Path

import pytest

from el.skills import outlook_pst as pst


# ---------------------------------------------------------------------------
# _parse_date_utc: pffexport's "Jul 20, 2008 01:28:47.828125000 UTC"
# ---------------------------------------------------------------------------

def test_parse_date_basic():
    dt = pst._parse_date_utc("Jul 20, 2008 01:28:47.828125000 UTC")
    assert dt == datetime(2008, 7, 20, 1, 28, 47, 828125, tzinfo=timezone.utc)


def test_parse_date_no_fractional():
    dt = pst._parse_date_utc("Jan 01, 2020 00:00:00 UTC")
    assert dt == datetime(2020, 1, 1, tzinfo=timezone.utc)


def test_parse_date_invalid_returns_none():
    assert pst._parse_date_utc("") is None
    assert pst._parse_date_utc("N/A") is None


# ---------------------------------------------------------------------------
# _parse_recipients: Display/Email/Address type/Recipient type blocks
# ---------------------------------------------------------------------------

def test_parse_recipients_single_block():
    text = (
        "Display name:\t\talison@m57.biz\n"
        "Recipient display name:\talison@m57.biz\n"
        "Email address:\t\ttuckgorge@gmail.com\n"
        "Address type:\t\tSMTP\n"
        "Recipient type:\t\tTo\n"
    )
    r = pst._parse_recipients(text)
    assert len(r) == 1
    assert r[0].display_name == "alison@m57.biz"
    assert r[0].email == "tuckgorge@gmail.com"
    assert r[0].recipient_type == "To"


def test_parse_recipients_multi_blocks():
    text = (
        "Display name:\tPrimary\n"
        "Email address:\tprimary@corp.example\n"
        "Recipient type:\tTo\n"
        "\n"
        "Display name:\tCC Target\n"
        "Email address:\tcc@corp.example\n"
        "Recipient type:\tCC\n"
    )
    r = pst._parse_recipients(text)
    assert len(r) == 2
    assert r[0].email == "primary@corp.example"
    assert r[1].recipient_type == "CC"


# ---------------------------------------------------------------------------
# _parse_message against a built-from-tmp message directory
# ---------------------------------------------------------------------------

def _build_exported_message(folder_dir: Path, *, subject: str,
                             sender_name: str, sender_email: str,
                             recipients: list[tuple[str, str, str]],
                             date_str: str,
                             flags: str = "0x00000001 (Read)",
                             size: int = 1234,
                             attachments: dict[str, bytes] | None = None) -> Path:
    msg_dir = folder_dir / f"Message{len(list(folder_dir.glob('Message*'))) + 1:04d}"
    msg_dir.mkdir(parents=True, exist_ok=True)

    # OutlookHeaders.txt
    outlook = (
        "Message:\n"
        f"Client submit time:\t\t\t{date_str}\n"
        f"Delivery time:\t\t\t\t{date_str}\n"
        f"Size:\t\t\t\t\t{size}\n"
        f"Flags:\t\t\t\t\t{flags}\n"
        f"Subject:\t\t\t\t{subject}\n"
        f"Sender name:\t\t\t\t{sender_name}\n"
        f"Sender email address:\t\t\t{sender_email}\n"
    )
    (msg_dir / "OutlookHeaders.txt").write_text(outlook)

    # Recipients.txt
    rcpt_text = ""
    for disp, email, rtype in recipients:
        rcpt_text += (
            f"Display name:\t\t{disp}\n"
            f"Email address:\t\t{email}\n"
            f"Address type:\t\tSMTP\n"
            f"Recipient type:\t\t{rtype}\n"
            "\n"
        )
    (msg_dir / "Recipients.txt").write_text(rcpt_text)

    # Attachments
    if attachments:
        att_dir = msg_dir / "Attachments"
        att_dir.mkdir()
        for n, (name, data) in enumerate(attachments.items(), 1):
            (att_dir / f"{n}_{name}").write_bytes(data)

    return msg_dir


def test_parse_message_full_round_trip(tmp_path):
    folder = tmp_path / "Sent Items"
    folder.mkdir()
    msg_dir = _build_exported_message(
        folder,
        subject="RE: Please send me the information now",
        sender_name="Jean User",
        sender_email="jean@m57.biz",
        recipients=[("alison@m57.biz", "tuckgorge@gmail.com", "To")],
        date_str="Jul 20, 2008 01:28:47.828125000 UTC",
        flags="0x00000011 (Read, Has attachments)",
        size=297082,
        attachments={"m57biz.xls": b"A" * 1024},
    )
    m = pst._parse_message(msg_dir)
    assert m.folder == "Sent Items"
    assert m.subject == "RE: Please send me the information now"
    assert m.sender_email == "jean@m57.biz"
    assert m.sender_name == "Jean User"
    assert m.date_submit_utc == datetime(2008, 7, 20, 1, 28, 47, 828125,
                                          tzinfo=timezone.utc)
    assert len(m.recipients) == 1
    r = m.recipients[0]
    assert r.display_name == "alison@m57.biz"
    assert r.email == "tuckgorge@gmail.com"
    assert r.recipient_type == "To"
    assert m.has_attachments
    assert len(m.attachments) == 1
    assert m.attachments[0].filename == "1_m57biz.xls"
    assert m.attachments[0].size_bytes == 1024
    assert len(m.attachments[0].sha256) == 64  # sha256 hex


def test_list_folder_names_with_top_wrapper(tmp_path):
    top = tmp_path / "Top of Personal Folders"
    (top / "Inbox").mkdir(parents=True)
    (top / "Sent Items").mkdir()
    (top / "Contacts").mkdir()
    names = pst._list_folder_names(tmp_path)
    assert names == ["Contacts", "Inbox", "Sent Items"]


def test_list_folder_names_without_top_wrapper(tmp_path):
    """Some exports don't have the Top wrapper — fall back to immediate dirs."""
    (tmp_path / "Inbox").mkdir()
    (tmp_path / "Sent Items").mkdir()
    names = pst._list_folder_names(tmp_path)
    assert "Inbox" in names and "Sent Items" in names
