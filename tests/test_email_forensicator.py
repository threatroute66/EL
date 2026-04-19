"""Agent-level tests for EmailForensicatorAgent.

We bypass the PST binary by monkeypatching `pst.export` to return a
handcrafted PstRun with handcrafted Message objects. This locks the
DETECTION rules:
  - display-name / SMTP-address mismatch → high-confidence Finding with
    spoofing hypotheses
  - sensitive attachment → consumer webmail → high-confidence Finding
    with H_INSIDER_DATA_EXFIL
  - sensitive attachment → non-webmail external → medium-confidence
  - external bulk attachment without sensitive keyword → low (info)
"""
from datetime import datetime, timezone
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.email_forensicator import EmailForensicatorAgent
from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger
from el.schemas.finding import EvidenceItem
from el.skills import outlook_pst as pst


def _ctx(tmp_path, monkeypatch, case_id="t-email"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"
    src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


def _msg(folder, subject, sender, recipients, *,
         attachments=None, date=None, flags="0x00000001 (Read)") -> pst.Message:
    return pst.Message(
        folder=folder,
        message_dir=Path("/tmp/fake-msg"),
        subject=subject,
        sender_name=sender.split("@")[0],
        sender_email=sender,
        recipients=[
            pst.Recipient(display_name=d, email=e, recipient_type=rt)
            for d, e, rt in recipients
        ],
        date_submit_utc=date or datetime(2008, 7, 20, tzinfo=timezone.utc),
        flags=flags,
        size_bytes=1234,
        attachments=attachments or [],
    )


def _att(name, data=b"A" * 1024) -> pst.Attachment:
    import hashlib
    return pst.Attachment(
        filename=name, path=Path("/tmp/fake") / name,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def _fake_run(messages: list[pst.Message], pst_path: Path) -> pst.PstRun:
    return pst.PstRun(
        pst_path=pst_path, out_dir=pst_path.with_suffix(".export"),
        rc=0, folders=sorted({m.folder for m in messages}),
        command=["pffexport"], messages=messages,
    )


def _seed_mail_dir(tmp_path: Path, pst_name: str = "jean.pst") -> Path:
    mail = tmp_path / "mail"
    mail.mkdir(parents=True, exist_ok=True)
    (mail / pst_name).write_bytes(b"FAKE_PST")  # agent only needs a file here
    return mail


# ---------------------------------------------------------------------------
# The M57-Jean signature: display-name/SMTP mismatch
# ---------------------------------------------------------------------------

def test_display_name_smtp_mismatch_fires_high_confidence(tmp_path, monkeypatch):
    """jean@m57.biz sends with display-name `alison@m57.biz` but actual
    SMTP is `tuckgorge@gmail.com`. Classic pretexting — must surface as
    a high-confidence Finding with H_BEC_ACCOUNT_TAKEOVER."""
    ctx = _ctx(tmp_path, monkeypatch, "t-spoof")
    mail = _seed_mail_dir(tmp_path)
    messages = [
        _msg("Sent Items", "RE: Please send me the information now",
             "jean@m57.biz",
             [("alison@m57.biz", "tuckgorge@gmail.com", "To")],
             attachments=[_att("m57biz.xls", b"B" * 50_000)]),
    ]

    def _fake_export(pst_path, out_dir, timeout=1800):
        return _fake_run(messages, pst_path)
    monkeypatch.setattr(pst, "export", _fake_export)

    ctx.input_path = mail
    findings = EmailForensicatorAgent().run(ctx)

    spoof = [f for f in findings if "display-name/SMTP mismatch" in f.claim]
    assert spoof, "expected a display-name/SMTP mismatch finding"
    f = spoof[0]
    assert f.confidence == "high"
    assert "tuckgorge@gmail.com" in f.claim
    assert "alison@m57.biz" in f.claim
    assert "H_BEC_ACCOUNT_TAKEOVER" in f.hypotheses_supported


def test_aligned_display_and_email_does_not_fire(tmp_path, monkeypatch):
    """If display == email, no mismatch — regular addressing."""
    ctx = _ctx(tmp_path, monkeypatch, "t-clean")
    mail = _seed_mail_dir(tmp_path)
    messages = [
        _msg("Inbox", "Team update",
             "bob@corp.example",
             [("Alice Smith", "alice@corp.example", "To")]),
    ]

    def _fake_export(pst_path, out_dir, timeout=1800):
        return _fake_run(messages, pst_path)
    monkeypatch.setattr(pst, "export", _fake_export)

    ctx.input_path = mail
    findings = EmailForensicatorAgent().run(ctx)
    assert not any("display-name/SMTP mismatch" in f.claim for f in findings)


# ---------------------------------------------------------------------------
# Sensitive attachment → external (consumer webmail vs corporate)
# ---------------------------------------------------------------------------

def test_sensitive_attachment_to_consumer_webmail_high(tmp_path, monkeypatch):
    """m57plan.xlsx sent from jean@m57.biz to a gmail address — high."""
    ctx = _ctx(tmp_path, monkeypatch, "t-webmail")
    mail = _seed_mail_dir(tmp_path)
    # Multiple sends in the mailbox so local_domain infers m57.biz
    messages = [
        _msg("Sent Items", "Q2 budget",
             "jean@m57.biz",
             [("CFO", "cfo@m57.biz", "To")]),
        _msg("Sent Items", "RE: info",
             "jean@m57.biz",
             [("alison@m57.biz", "tuckgorge@gmail.com", "To")],
             attachments=[_att("m57plan.xlsx", b"X" * 200_000)]),
    ]

    def _fake_export(pst_path, out_dir, timeout=1800):
        return _fake_run(messages, pst_path)
    monkeypatch.setattr(pst, "export", _fake_export)

    ctx.input_path = mail
    findings = EmailForensicatorAgent().run(ctx)
    sens = [f for f in findings if "Sensitive attachment" in f.claim]
    assert sens, "expected sensitive-attachment-exfil finding"
    f = sens[0]
    assert f.confidence == "high"
    assert "H_INSIDER_DATA_EXFIL" in f.hypotheses_supported
    assert "tuckgorge@gmail.com" in f.claim
    assert "m57plan.xlsx" in f.claim


def test_sensitive_attachment_to_corporate_external_medium(tmp_path, monkeypatch):
    """To an external non-webmail domain (partner.example) — medium, not high."""
    ctx = _ctx(tmp_path, monkeypatch, "t-extcorp")
    mail = _seed_mail_dir(tmp_path)
    messages = [
        _msg("Sent Items", "Weekly",
             "jean@m57.biz",
             [("Alice", "alice@m57.biz", "To")]),
        _msg("Sent Items", "pricing",
             "jean@m57.biz",
             [("Contact", "contact@partner.example", "To")],
             attachments=[_att("pricing-strategy.xlsx")]),
    ]
    monkeypatch.setattr(pst, "export",
                        lambda p, o, timeout=1800: _fake_run(messages, p))

    ctx.input_path = mail
    findings = EmailForensicatorAgent().run(ctx)
    sens = [f for f in findings if "Sensitive attachment" in f.claim]
    assert sens, "external partner attachment should still surface"
    assert sens[0].confidence == "medium"


def test_bulk_attachment_without_sensitive_keyword_low(tmp_path, monkeypatch):
    """A big .zip to external without sensitive-keyword in filename →
    low-confidence informational only."""
    ctx = _ctx(tmp_path, monkeypatch, "t-bulk")
    mail = _seed_mail_dir(tmp_path)
    messages = [
        _msg("Sent Items", "photos",
             "jean@m57.biz",
             [("party", "fun@gmail.com", "To")],
             attachments=[_att("holiday-photos.zip", b"Y" * 500_000)]),
    ]
    monkeypatch.setattr(pst, "export",
                        lambda p, o, timeout=1800: _fake_run(messages, p))

    ctx.input_path = mail
    findings = EmailForensicatorAgent().run(ctx)
    bulk = [f for f in findings if "External-recipient bulk attachment" in f.claim]
    assert bulk
    assert bulk[0].confidence == "low"
    # Informational — does NOT lift insider-exfil hypothesis
    assert bulk[0].hypotheses_supported == []


def test_internal_only_recipients_no_exfil_finding(tmp_path, monkeypatch):
    """All recipients on the local domain — no exfil finding even with
    a sensitive-keyword attachment."""
    ctx = _ctx(tmp_path, monkeypatch, "t-internal")
    mail = _seed_mail_dir(tmp_path)
    messages = [
        _msg("Sent Items", "budget",
             "jean@m57.biz",
             [("Alison", "alison@m57.biz", "To")],
             attachments=[_att("q2-budget-confidential.xlsx")]),
    ]
    monkeypatch.setattr(pst, "export",
                        lambda p, o, timeout=1800: _fake_run(messages, p))

    ctx.input_path = mail
    findings = EmailForensicatorAgent().run(ctx)
    assert not any("Sensitive attachment" in f.claim for f in findings)


# ---------------------------------------------------------------------------
# Agent scaffolding
# ---------------------------------------------------------------------------

def test_emits_insufficient_when_no_pst_present(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, "t-empty")
    mail = tmp_path / "mail"
    mail.mkdir()

    ctx.input_path = mail
    findings = EmailForensicatorAgent().run(ctx)
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"
    assert "No .pst/.ost files" in findings[0].claim


def test_skill_export_failure_gracefully_degrades(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, "t-fail")
    mail = _seed_mail_dir(tmp_path)

    def _raise(pst_path, out_dir, timeout=1800):
        raise pst.OutlookPstError("pffexport not installed")
    monkeypatch.setattr(pst, "export", _raise)

    ctx.input_path = mail
    findings = EmailForensicatorAgent().run(ctx)
    # One insufficient finding per PST
    assert any(f.confidence == "insufficient" and "pffexport failed" in f.claim
               for f in findings)
