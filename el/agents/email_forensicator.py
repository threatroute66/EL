"""Email Forensicator — triage Outlook PST/OST mailboxes for exfil signals.

Consumes a directory of extracted .pst/.ost files (disk_forensicator
copies these to case/exports/windows-artifacts/mail/). For each mailbox,
exports via libpff and emits Findings on three shape-independent
signals:

  1. DISPLAY_NAME_SMTP_MISMATCH — recipient display name does not match
     the actual SMTP email address (classic impersonation / spoofing
     pattern; the M57-Jean case-answering signal: display `alison@m57.biz`,
     actual `tuckgorge@gmail.com`).
  2. SENSITIVE_ATTACHMENT_TO_EXTERNAL — a mail with an Office/archive/pdf
     attachment whose filename contains sensitive-document keywords
     AND is addressed to a recipient outside the local mail domain.
  3. EXTERNAL_BULK_ATTACHMENT — any message with a ≥100 KB attachment
     sent to an external recipient (lower-confidence, informational).

Detection is deterministic — no LLM. All evidence carries sha256 of
the raw PST + the attachment for chain of custody.
"""
from __future__ import annotations

import re
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import outlook_pst as pst


# Attachment filename keywords that often indicate a sensitive document.
_SENSITIVE_KEYWORDS = (
    "plan", "roadmap", "confidential", "secret", "salary", "salaries",
    "ssn", "payroll", "employees", "customers", "acquisition", "merger",
    "strategy", "budget", "forecast", "q1", "q2", "q3", "q4",
    "client", "clients", "pricing", "contract",
)
_SENSITIVE_EXTENSIONS = (".xls", ".xlsx", ".xlsm", ".doc", ".docx",
                          ".pdf", ".csv", ".zip", ".7z", ".rar")

# Consumer webmail domains — external recipients from a corporate mailbox
# are a strong exfil channel signal regardless of attachment contents.
_CONSUMER_WEBMAIL = {
    "gmail.com", "yahoo.com", "hotmail.com", "live.com", "outlook.com",
    "protonmail.com", "proton.me", "aol.com", "icloud.com", "mail.com",
    "gmx.com", "zoho.com", "yandex.com", "tutanota.com",
}


def _smtp_domain(address: str) -> str:
    """Lowercase the address and return the domain, or '' if malformed."""
    a = address.strip().lower()
    if "@" not in a:
        return ""
    return a.rsplit("@", 1)[-1]


def _display_is_email(display: str) -> bool:
    """Does the display name itself look like an email address?"""
    return bool(re.fullmatch(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", display.strip()))


def _local_domains(msgs: list[pst.Message]) -> set[str]:
    """Infer the mailbox's local mail domain(s) from sender addresses —
    the domain(s) of the accounts the owner is sending FROM."""
    doms: dict[str, int] = {}
    for m in msgs:
        d = _smtp_domain(m.sender_email)
        if d:
            doms[d] = doms.get(d, 0) + 1
    # Most-sent-from domain wins; include near-tiers.
    if not doms:
        return set()
    top = max(doms.values())
    return {d for d, n in doms.items() if n >= max(1, top // 3)}


class EmailForensicatorAgent(Agent):
    name = "email_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        mail_dir = Path(ctx.input_path)
        if not mail_dir.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"EmailForensicator expects a directory input; got {mail_dir}",
            ))]

        psts = sorted(p for p in mail_dir.iterdir()
                      if p.is_file() and p.suffix.lower() in (".pst", ".ost"))
        if not psts:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"No .pst/.ost files in {mail_dir}",
            ))]

        for p in psts:
            out.extend(self._triage_pst(ctx, p, analysis))
        return out

    def _triage_pst(self, ctx: AgentContext, pst_path: Path,
                    analysis: Path) -> list[Finding]:
        out: list[Finding] = []
        out_target = analysis / pst_path.stem
        try:
            run = pst.export(pst_path, out_target)
        except pst.OutlookPstError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"pffexport failed on {pst_path.name}: {e}",
            ))]

        msgs = run.messages
        local_doms = _local_domains(msgs)

        # Volume finding — high confidence, establishes the PST was parsed
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"PST parsed ({pst_path.name}): {len(msgs)} message(s) "
                   f"across {len(run.folders)} folder(s) "
                   f"({', '.join(run.folders[:5])}"
                   f"{'…' if len(run.folders) > 5 else ''}). "
                   f"Inferred local domain(s): "
                   f"{', '.join(sorted(local_doms)) or 'unknown'}"),
            evidence=[run.as_evidence()],
            hypotheses_supported=["H_MAILBOX_PARSED"],
        )))

        # Per-message triage
        for m in msgs:
            out.extend(self._check_display_name_mismatch(ctx, pst_path, run, m))
            out.extend(self._check_sensitive_exfil(
                ctx, pst_path, run, m, local_doms))
        return out

    # ---------- detection 1: display-name / SMTP-address mismatch ----------

    def _check_display_name_mismatch(self, ctx: AgentContext,
                                      pst_path: Path, run: pst.PstRun,
                                      m: pst.Message) -> list[Finding]:
        out: list[Finding] = []
        for r in m.recipients:
            if not _display_is_email(r.display_name):
                continue
            # Both the display name AND the email address are email shapes;
            # a mismatch at the domain level is strong spoofing signal.
            if not r.email or r.email.lower() == r.display_name.lower():
                continue
            disp_dom = _smtp_domain(r.display_name)
            real_dom = _smtp_domain(r.email)
            if not disp_dom or not real_dom or disp_dom == real_dom:
                continue
            ev = run.as_evidence(facts={
                "folder": m.folder,
                "subject": m.subject,
                "sender": m.sender_email,
                "display_name": r.display_name,
                "actual_recipient": r.email,
                "recipient_type": r.recipient_type,
                "date_utc": m.date_submit_utc.isoformat() if m.date_submit_utc else None,
                "attachments": [a.filename for a in m.attachments],
                "message_dir": str(m.message_dir),
            })
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Email display-name/SMTP mismatch in {pst_path.name} "
                       f"({m.folder}): sender={m.sender_email} subject="
                       f"{m.subject!r}; recipient DISPLAYED as "
                       f"{r.display_name!r} but ACTUALLY sent to {r.email!r} "
                       f"(display domain {disp_dom} ≠ actual {real_dom}). "
                       f"{'Has ' + str(len(m.attachments)) + ' attachment(s). ' if m.attachments else ''}"
                       f"Classic impersonation / pretexting pattern."),
                evidence=[ev],
                hypotheses_supported=[
                    # Display-name/SMTP mismatch is the forensic fingerprint
                    # of both insider exfil (impersonator inside the company)
                    # and classic BEC (external attacker with spoofed header).
                    "H_INSIDER_EMAIL_EXFIL",
                    "H_BEC_ACCOUNT_TAKEOVER",
                ],
            )))
        return out

    # ---------- detection 2: sensitive attachment → external recipient ----

    def _check_sensitive_exfil(self, ctx: AgentContext, pst_path: Path,
                                run: pst.PstRun, m: pst.Message,
                                local_doms: set[str]) -> list[Finding]:
        out: list[Finding] = []
        if not m.attachments:
            return out
        ext_recips = []
        for r in m.recipients:
            d = _smtp_domain(r.email)
            if d and d not in local_doms:
                ext_recips.append(r)
        if not ext_recips:
            return out

        sensitive_attachments = []
        bulk_attachments = []
        for a in m.attachments:
            name = a.filename.lower()
            matches_kw = any(k in name for k in _SENSITIVE_KEYWORDS)
            matches_ext = any(name.endswith(e) for e in _SENSITIVE_EXTENSIONS)
            if matches_kw and matches_ext:
                sensitive_attachments.append(a)
            elif a.size_bytes >= 100 * 1024 and matches_ext:
                bulk_attachments.append(a)

        if sensitive_attachments:
            ext_list = ", ".join(
                f"{r.email} ({r.recipient_type or 'To'})" for r in ext_recips[:3])
            att_list = ", ".join(f"{a.filename} ({a.size_bytes}B)"
                                  for a in sensitive_attachments[:3])
            ev = run.as_evidence(facts={
                "folder": m.folder, "subject": m.subject,
                "sender": m.sender_email,
                "external_recipients": [r.email for r in ext_recips],
                "sensitive_attachments": [
                    {"filename": a.filename, "sha256": a.sha256,
                     "size_bytes": a.size_bytes}
                    for a in sensitive_attachments
                ],
                "date_utc": m.date_submit_utc.isoformat() if m.date_submit_utc else None,
                "message_dir": str(m.message_dir),
            })
            is_webmail = any(_smtp_domain(r.email) in _CONSUMER_WEBMAIL
                             for r in ext_recips)
            conf = "high" if is_webmail else "medium"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=conf,
                claim=(f"Sensitive attachment → external recipient in "
                       f"{pst_path.name} ({m.folder}): "
                       f"sender={m.sender_email} subject={m.subject!r} "
                       f"to {ext_list}; attachment(s): {att_list}. "
                       f"{'Consumer webmail destination. ' if is_webmail else ''}"
                       f"Attachment-filename keyword + external domain → "
                       f"data-exfil-via-email candidate."),
                evidence=[ev],
                hypotheses_supported=["H_INSIDER_EMAIL_EXFIL"],
            )))
        elif bulk_attachments:
            # Bulk attachment to external without the sensitive-keyword
            # signal — lower confidence, informational only.
            ext_list = ", ".join(r.email for r in ext_recips[:3])
            att_list = ", ".join(f"{a.filename} ({a.size_bytes}B)"
                                  for a in bulk_attachments[:3])
            ev = run.as_evidence(facts={
                "folder": m.folder, "subject": m.subject,
                "sender": m.sender_email,
                "external_recipients": [r.email for r in ext_recips],
                "attachments": [
                    {"filename": a.filename, "sha256": a.sha256,
                     "size_bytes": a.size_bytes}
                    for a in bulk_attachments
                ],
                "date_utc": m.date_submit_utc.isoformat() if m.date_submit_utc else None,
            })
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=(f"External-recipient bulk attachment in "
                       f"{pst_path.name} ({m.folder}): "
                       f"sender={m.sender_email} subject={m.subject!r} "
                       f"to {ext_list}; attachment(s): {att_list}. "
                       f"Informational — common in normal business mail."),
                evidence=[ev],
            )))
        return out
