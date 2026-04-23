"""Tests for the Thunderbird mbox walker."""
from __future__ import annotations

import email
import email.mime.multipart
import email.mime.text
import email.mime.base
from email import encoders
from pathlib import Path

from el.skills import thunderbird_mbox as tb


def _write_mbox(mbox_path: Path, messages: list[bytes]) -> None:
    """Concatenate RFC-822 messages separated by `From ` envelopes."""
    mbox_path.parent.mkdir(parents=True, exist_ok=True)
    with mbox_path.open("wb") as fh:
        for raw in messages:
            fh.write(b"From - Thu Jan 01 00:00:00 2026\n")
            fh.write(raw)
            if not raw.endswith(b"\n"):
                fh.write(b"\n")
            fh.write(b"\n")


def _build_simple(subject: str, sender: str, recipient: str,
                   body: str = "hello") -> bytes:
    msg = email.mime.multipart.MIMEMultipart()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Date"] = "Mon, 02 Feb 2026 14:00:00 +0000"
    msg["Message-ID"] = f"<{subject.replace(' ','')}@test>"
    msg.attach(email.mime.text.MIMEText(body, "plain"))
    return msg.as_bytes()


def _build_with_attachment(subject: str, filename: str,
                            content: bytes) -> bytes:
    msg = email.mime.multipart.MIMEMultipart()
    msg["From"] = "ivan@example.com"
    msg["To"] = "client@example.com"
    msg["Subject"] = subject
    msg["Date"] = "Mon, 02 Feb 2026 14:00:00 +0000"
    msg["Message-ID"] = f"<{subject.replace(' ','')}@test>"
    msg.attach(email.mime.text.MIMEText("body", "plain"))
    part = email.mime.base.MIMEBase("application", "octet-stream")
    part.set_payload(content)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
    msg.attach(part)
    return msg.as_bytes()


def test_parse_single_mbox(tmp_path):
    inbox = tmp_path / "profile" / "Mail" / "local" / "Inbox"
    _write_mbox(inbox, [_build_simple("hi", "a@x.com", "b@y.com")])
    run = tb.walk(tmp_path)
    assert len(run.messages) == 1
    m = run.messages[0]
    assert m.subject == "hi"
    assert m.sender_email == "a@x.com"
    assert m.recipients and m.recipients[0].email == "b@y.com"
    assert m.date_utc is not None


def test_attachments_are_hashed(tmp_path):
    """Attachment.sha256 MUST be content-derived so the evidence item can
    be verified later. BelkaCTF Kidnapper had 10-million-password-list
    attached — we need the hash to assert lineage."""
    sent = tmp_path / "profile" / "Mail" / "local" / "Sent"
    _write_mbox(sent, [_build_with_attachment(
        "order q1", "wordlist.txt", b"hello-world-payload",
    )])
    run = tb.walk(tmp_path)
    assert len(run.messages) == 1
    m = run.messages[0]
    assert len(m.attachments) == 1
    a = m.attachments[0]
    assert a.filename == "wordlist.txt"
    assert a.size_bytes == len(b"hello-world-payload")
    assert len(a.sha256) == 64


def test_non_mbox_files_skipped(tmp_path):
    """Thunderbird profiles carry .msf index files — must be ignored."""
    prof = tmp_path / "profile" / "Mail" / "local"
    prof.mkdir(parents=True)
    (prof / "Inbox.msf").write_bytes(b"// mork dump - not mbox")
    (prof / "prefs.js").write_bytes(b"user_pref(...)")
    run = tb.walk(tmp_path)
    assert run.messages == []
    assert run.mbox_paths == []


def test_walk_returns_evidence_hashable(tmp_path):
    inbox = tmp_path / "profile" / "Mail" / "local" / "Inbox"
    _write_mbox(inbox, [_build_simple("hi", "a@x.com", "b@y.com")])
    run = tb.walk(tmp_path)
    ev = run.as_evidence()
    assert len(ev.output_sha256) == 64
