"""Gap-closure tests: inbound-phishing reply-chain + graph population
on the email forensicator (M57-Jean fidelity work).
"""
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from el.agents.email_forensicator import (
    EmailForensicatorAgent, _normalise_subject, _reply_stem,
)
from el.skills.outlook_pst import Attachment, Message, PstRun, Recipient


# ---------------------------------------------------------------------------
# Subject normalisation
# ---------------------------------------------------------------------------

def test_reply_stem_strips_one_prefix():
    assert _reply_stem("RE: Please send me the info") == \
        "please send me the info"
    assert _reply_stem("Fwd: Q3 plan") == "q3 plan"
    assert _reply_stem("plain subject") == ""


def test_reply_stem_handles_language_variants():
    assert _reply_stem("Sv: Viktigt").lower() == "viktigt"   # Swedish
    assert _reply_stem("AW: Wichtig").lower() == "wichtig"   # German
    assert _reply_stem("TR: urgent").lower() == "urgent"     # French


def test_normalise_subject_strips_chains_of_prefixes():
    assert _normalise_subject("RE: FW: RE: Q3 plan") == "q3 plan"


# ---------------------------------------------------------------------------
# Inbound-phishing reply-chain detection
# ---------------------------------------------------------------------------

def _mk_msg(folder, subject, sender_email, sender_name="",
             recipients=None, attachments=None, message_dir_name="m1"):
    return Message(
        folder=folder, message_dir=Path(f"/tmp/{message_dir_name}"),
        subject=subject, sender_name=sender_name,
        sender_email=sender_email,
        recipients=recipients or [],
        date_submit_utc=datetime(2008, 7, 19, 14, 0, tzinfo=timezone.utc),
        flags="", size_bytes=1024,
        attachments=attachments or [],
    )


def _mk_recip(email, display=None, rtype="To"):
    return Recipient(
        email=email, display_name=display or email, recipient_type=rtype)


def _mk_run(tmp_path, pst_name, messages):
    (tmp_path / pst_name).write_bytes(b"fake pst")
    run = PstRun(
        pst_path=tmp_path / pst_name,
        out_dir=tmp_path / "out", rc=0,
        folders=["Inbox", "Sent Items"],
        command=["pffexport"],
        messages=messages,
    )
    (tmp_path / "out").mkdir(exist_ok=True)
    return run


def test_inbound_precursor_to_flagged_reply_fires(tmp_path, monkeypatch):
    """M57-Jean reproduction: 'Alison' sends an inbound pretext, Jean
    replies with RE: carrying a display-name/SMTP mismatch recipient.
    The inbound should be flagged as H_INITIAL_ACCESS_PHISHING."""
    inbound = _mk_msg("Inbox", "Please send me the information now",
                       "attacker@notalison.test",
                       sender_name="Alison Smith",
                       message_dir_name="inbound")
    # Outbound RE: with display/SMTP mismatch on recipient
    outbound = _mk_msg("Sent Items",
                        "RE: Please send me the information now",
                        "jean@m57.biz", sender_name="Jean Jones",
                        recipients=[
                            _mk_recip("tuckgorge@gmail.com",
                                       display="alison@m57.biz")],
                        attachments=[Attachment(
                            filename="1_m57biz.xls",
                            path=Path("/tmp/att.xls"),
                            sha256="0"*64,
                            size_bytes=291840)],
                        message_dir_name="outbound")
    run = _mk_run(tmp_path, "jean.pst", [inbound, outbound])

    # Build a minimal AgentContext + stub the pst.export + ledger writes
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod, ledger as ledger_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "maildir"
    src.mkdir()
    (src / "jean.pst").write_bytes(b"fake pst")
    m = intake_mod.intake(src, case_id="t-inbound-phish")
    with ledger_mod.open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-inbound-phish",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={})

    # Stub pst.export → return our pre-built run
    from el.skills import outlook_pst as pst
    monkeypatch.setattr(pst, "export", lambda *a, **kw: run)

    findings = EmailForensicatorAgent()._triage_pst(
        ctx, tmp_path / "jean.pst", tmp_path / "analysis")

    # Must emit at least one H_INITIAL_ACCESS_PHISHING finding
    phish = [f for f in findings
              if "H_INITIAL_ACCESS_PHISHING" in f.hypotheses_supported]
    assert phish, "inbound precursor detector did not fire"
    claim = phish[0].claim
    assert "Inbound precursor" in claim
    assert "Please send me the information now" in claim
    assert "attacker@notalison.test" in claim


def test_inbound_from_display_mismatch_alone_fires(tmp_path, monkeypatch):
    """Direct phishing: inbound From display name looks like
    alison@m57.biz but actual From-SMTP is attacker@badco.test."""
    inbound = _mk_msg("Inbox", "Urgent question",
                       "attacker@badco.test",
                       sender_name="alison@m57.biz")
    run = _mk_run(tmp_path, "jean.pst", [inbound])
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod, ledger as ledger_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "maildir"; src.mkdir()
    (src / "jean.pst").write_bytes(b"fake pst")
    m = intake_mod.intake(src, case_id="t-direct-phish")
    with ledger_mod.open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-direct-phish",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__, shared={})
    from el.skills import outlook_pst as pst
    monkeypatch.setattr(pst, "export", lambda *a, **kw: run)

    findings = EmailForensicatorAgent()._triage_pst(
        ctx, tmp_path / "jean.pst", tmp_path / "analysis")
    phish = [f for f in findings if "Inbound phishing" in f.claim]
    assert phish, findings
    assert "alison@m57.biz" in phish[0].claim
    assert "attacker@badco.test" in phish[0].claim


def test_no_phishing_finding_when_legit_thread(tmp_path, monkeypatch):
    """Control: purely internal thread, no display/SMTP mismatch, no
    external recipients — phishing detector MUST stay silent."""
    inbound = _mk_msg("Inbox", "Q3 forecast",
                       "alison@m57.biz",
                       sender_name="Alison Smith",
                       message_dir_name="inbound")
    outbound = _mk_msg("Sent Items", "RE: Q3 forecast",
                        "jean@m57.biz", sender_name="Jean Jones",
                        recipients=[_mk_recip("alison@m57.biz")],
                        message_dir_name="outbound")
    run = _mk_run(tmp_path, "jean.pst", [inbound, outbound])
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod, ledger as ledger_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "maildir"; src.mkdir()
    (src / "jean.pst").write_bytes(b"fake pst")
    m = intake_mod.intake(src, case_id="t-clean-thread")
    with ledger_mod.open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-clean-thread",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__, shared={})
    from el.skills import outlook_pst as pst
    monkeypatch.setattr(pst, "export", lambda *a, **kw: run)
    findings = EmailForensicatorAgent()._triage_pst(
        ctx, tmp_path / "jean.pst", tmp_path / "analysis")
    for f in findings:
        assert "H_INITIAL_ACCESS_PHISHING" not in f.hypotheses_supported


# ---------------------------------------------------------------------------
# Graph population
# ---------------------------------------------------------------------------

def test_graph_populated_from_pst(tmp_path, monkeypatch):
    """Email / User / Domain / File nodes + SENT_FROM / SENT_TO /
    HAS_ATTACHMENT / EMAILS_ON_DOMAIN edges materialise so the
    case.html graph pane isn't empty on email-only cases."""
    outbound = _mk_msg("Sent Items",
                        "RE: Please send me the information now",
                        "jean@m57.biz", sender_name="Jean Jones",
                        recipients=[
                            _mk_recip("tuckgorge@gmail.com",
                                       display="alison@m57.biz")],
                        attachments=[Attachment(
                            filename="1_m57biz.xls",
                            path=Path("/tmp/att.xls"),
                            sha256="0"*64,
                            size_bytes=291840)],
                        message_dir_name="outbound")
    run = _mk_run(tmp_path, "jean.pst", [outbound])
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod, ledger as ledger_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "maildir"; src.mkdir()
    (src / "jean.pst").write_bytes(b"fake pst")
    m = intake_mod.intake(src, case_id="t-graph-email")
    with ledger_mod.open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-graph-email",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__, shared={})
    from el.skills import outlook_pst as pst
    monkeypatch.setattr(pst, "export", lambda *a, **kw: run)
    EmailForensicatorAgent()._triage_pst(
        ctx, tmp_path / "jean.pst", tmp_path / "analysis")

    # Inspect the graph via the same exporter the HTML report uses
    from el.reporting.graph_export import export_graph
    out = export_graph(Path(m.case_dir))
    by_type: dict[str, list] = {}
    for n in out["nodes"]:
        by_type.setdefault(n["type"], []).append(n)
    assert "Email" in by_type, out
    assert "User" in by_type
    assert "Domain" in by_type
    assert "File" in by_type
    # Specific expected nodes
    user_sids = {n["attrs"].get("name"): n for n in by_type["User"]}
    assert any("jean@m57.biz" in sid or "jean@m57.biz" == sid
               for n in by_type["User"] for sid in [n["id"]])
    assert any("tuckgorge@gmail.com" in n["id"] for n in by_type["User"])
    doms = {n["id"] for n in by_type["Domain"]}
    assert any("m57.biz" in d for d in doms)
    assert any("gmail.com" in d for d in doms)
    # Edges — at least one SENT_FROM + SENT_TO + HAS_ATTACHMENT
    edge_types = {e["type"] for e in out["edges"]}
    assert "SENT_FROM" in edge_types
    assert "SENT_TO" in edge_types
    assert "HAS_ATTACHMENT" in edge_types
    assert "EMAILS_ON_DOMAIN" in edge_types
