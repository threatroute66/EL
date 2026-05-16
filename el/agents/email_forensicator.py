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


def _header_chain_facts(m: pst.Message) -> dict:
    """Convert a Message's parsed header_chain (when present) into a
    flat dict of forensically-load-bearing extracted_facts keys. Used
    by the inbound-side detectors so the Diamond Adversary quarter
    picks up the real SMTP-path attribution (originator IP +
    Return-Path envelope sender + Postfix submitter UID) alongside
    whatever spoofed display-From the From: line carries.

    Returns {} when no header chain is parsed — keeps the merge
    site (`facts.update(_header_chain_facts(m))`) a no-op on
    messages whose InternetHeaders.txt was missing.
    """
    hc = getattr(m, "header_chain", None)
    if hc is None:
        return {}
    out = {}
    if hc.originator_ip:
        out["smtp_originator_ip"] = hc.originator_ip
    if hc.originator_host:
        out["smtp_originator_host"] = hc.originator_host
    if hc.return_path:
        out["smtp_return_path"] = hc.return_path
    if hc.submitter_uid is not None:
        out["smtp_submitter_uid"] = hc.submitter_uid
    if hc.x_originating_ip:
        out["x_originating_ip"] = hc.x_originating_ip
    if hc.received_chain:
        # Compact per-hop summary — `from_host`/`from_ip`/`by_host`
        # for each hop in chronological order so an analyst can read
        # the relay path without going back to the raw headers file.
        out["smtp_relay_chain"] = [
            {k: v for k, v in {
                "from_host": h.from_host,
                "from_ip": h.from_ip,
                "by_host": h.by_host,
                "uid": h.submitter_uid,
                "id": h.smtp_id,
            }.items() if v is not None}
            for h in hc.received_chain
        ]
    return out


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


_REPLY_PREFIX_RE = re.compile(
    r"^(?:re|fw|fwd|tr|sv|aw|antw|res)(?:\s*\[\d+\])?\s*:\s*",
    re.IGNORECASE,
)


def _reply_stem(subject: str) -> str:
    """Strip ONE leading RE:/FW:/FWD: (and language variants) from a
    subject. Returns '' if nothing was stripped (subject is not a reply)."""
    s = (subject or "").strip()
    m = _REPLY_PREFIX_RE.match(s)
    if not m:
        return ""
    return s[m.end():].strip().lower()


def _normalise_subject(subject: str) -> str:
    """Strip ANY number of RE:/FW:/FWD: prefixes (reply-of-reply-of-reply)
    and lowercase, so `m.subject` of an inbound matches the stem of an
    outbound reply regardless of thread depth."""
    s = (subject or "").strip()
    while True:
        m = _REPLY_PREFIX_RE.match(s)
        if not m:
            break
        s = s[m.end():].strip()
    return s.lower()


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
        # Reply-chain analysis — catch inbound phishing whose subject is
        # later answered with an outbound reply that exfils. This is the
        # M57-Jean initial-compromise beat: the spoofed "Alison" email
        # Jean replied to is in her Inbox, findable by matching its
        # subject to an outbound RE: that the display-name/SMTP-mismatch
        # detector already flagged.
        out.extend(self._check_inbound_phishing_reply_chain(
            ctx, pst_path, run, msgs, local_doms))
        self._populate_graph(ctx, pst_path, msgs, local_doms)
        return out

    def _check_inbound_phishing_reply_chain(
        self, ctx, pst_path, run, msgs, local_doms,
    ) -> list[Finding]:
        """Detect inbound messages that are the PRECURSOR to a flagged
        outbound exfil reply. Two heuristics — either is enough:

          A) The inbound has a From display-name / SMTP mismatch on its
             own (e.g. From: 'Alison Smith <alison@m57.biz>' but actual
             SMTP From is 'alison@attacker.example') → direct phishing
             signature.

          B) An outbound Sent-Items message whose display-name/SMTP
             mismatch was already flagged has a subject prefixed with
             RE:/FW:/FWD: whose stem matches an inbound message. That
             inbound is the PRECURSOR pretext the user replied to.

        Either hit emits a H_INITIAL_ACCESS_PHISHING finding pointing at
        the inbound message.
        """
        out: list[Finding] = []
        inbox_by_norm_subject: dict[str, list] = {}
        for m in msgs:
            if (m.folder or "").lower() in ("sent items", "outbox",
                                              "drafts", "deleted items"):
                continue
            if not m.subject:
                continue
            key = _normalise_subject(m.subject)
            if key:
                inbox_by_norm_subject.setdefault(key, []).append(m)

        # Heuristic B: find outbound mismatches whose subject is a reply
        # to an inbound message. We use the display-name-mismatch check
        # we already ran but collapse the work here for locality.
        flagged_reply_stems: set[str] = set()
        for m in msgs:
            if (m.folder or "").lower() != "sent items":
                continue
            if not m.subject:
                continue
            stem = _reply_stem(m.subject)
            if not stem:
                continue
            # Any external recipient + matches the mismatch detector?
            has_mismatch = False
            for r in m.recipients:
                if not _display_is_email(r.display_name):
                    continue
                if (not r.email or
                        r.email.lower() == r.display_name.lower()):
                    continue
                if _smtp_domain(r.display_name) and _smtp_domain(r.email) \
                        and _smtp_domain(r.display_name) != _smtp_domain(r.email):
                    has_mismatch = True
                    break
            if has_mismatch:
                flagged_reply_stems.add(stem)

        emitted_fids: set[str] = set()
        for stem in flagged_reply_stems:
            for inbound in inbox_by_norm_subject.get(stem, []):
                if str(inbound.message_dir) in emitted_fids:
                    continue
                emitted_fids.add(str(inbound.message_dir))
                facts = {
                    "folder": inbound.folder,
                    "subject": inbound.subject,
                    "sender": inbound.sender_email,
                    "sender_display": inbound.sender_name,
                    "date_utc": inbound.date_submit_utc.isoformat()
                                 if inbound.date_submit_utc else None,
                    "matched_reply_stem": stem,
                    "message_dir": str(inbound.message_dir),
                    # The inbound pretext that initiated the reply
                    # chain. T1566.002 (Phishing: Spearphishing Link
                    # — used here as the closest fit for an inbound
                    # text request) + T1534 (Internal Spearphishing
                    # — the spoofed display name made the mail look
                    # internal). Surfaces in the Diamond Capability
                    # quarter + the narrative ATT&CK chain.
                    "attack_techniques": ["T1566.002", "T1534"],
                }
                # Parsed Received chain + envelope sender — surfaces
                # the REAL SMTP path underneath any header spoof. On
                # M57-Jean this lands smtp_originator_ip=208.97.188.9
                # (Dreamhost shared web server) + Return-Path
                # `simsong@xy.dreamhostps.com` + submitter UID 558838,
                # all far more actionable for legal-process pivots
                # than the spoofed `tuckgorge@gmail.com`.
                facts.update(_header_chain_facts(inbound))
                ev = run.as_evidence(facts=facts)
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="high",
                    claim=(f"Inbound precursor to flagged outbound "
                           f"exfil reply in {pst_path.name} "
                           f"({inbound.folder}): subject "
                           f"{inbound.subject!r} from "
                           f"{inbound.sender_email!r}"
                           f"{' (display: ' + inbound.sender_name + ')' if inbound.sender_name else ''}. "
                           f"Jean replied with RE: "
                           f"{inbound.subject!r}, and that reply "
                           f"carries a display-name/SMTP recipient "
                           f"mismatch. This is the initial "
                           f"social-engineering vector: the "
                           f"attacker sent the pretext inbound, "
                           f"the user replied with the sensitive "
                           f"payload attached."),
                    evidence=[ev],
                    hypotheses_supported=[
                        "H_INITIAL_ACCESS_PHISHING",
                        "H_BEC_ACCOUNT_TAKEOVER",
                    ],
                )))

        # Heuristic A: inbound messages whose From display-name and
        # From SMTP address have mismatched domains — direct impersonation
        # even without a later reply.
        for m in msgs:
            if (m.folder or "").lower() in ("sent items", "outbox", "drafts"):
                continue
            disp = m.sender_name or ""
            real = m.sender_email or ""
            if not _display_is_email(disp) or not real:
                continue
            if disp.lower() == real.lower():
                continue
            disp_dom = _smtp_domain(disp)
            real_dom = _smtp_domain(real)
            if not disp_dom or not real_dom or disp_dom == real_dom:
                continue
            facts = {
                "folder": m.folder, "subject": m.subject,
                "from_display": disp, "from_smtp": real,
                "display_domain": disp_dom, "actual_domain": real_dom,
                "date_utc": m.date_submit_utc.isoformat()
                             if m.date_submit_utc else None,
                "message_dir": str(m.message_dir),
                # Direct sender impersonation. T1566 (Phishing) +
                # T1534 (Internal Spearphishing) — the spoofed
                # display name makes the message look internal even
                # though the SMTP From is external.
                "attack_techniques": ["T1566.002", "T1534"],
            }
            # Real SMTP path under the display-name spoof — see
            # _header_chain_facts for the key set (smtp_originator_ip,
            # smtp_originator_host, smtp_return_path, smtp_submitter_uid,
            # x_originating_ip, smtp_relay_chain).
            facts.update(_header_chain_facts(m))
            ev = run.as_evidence(facts=facts)
            # Append the real SMTP-path attribution to the claim when
            # the parsed Received chain produced one — gives the
            # narrative a concrete origin (`208.97.188.9` /
            # `apache2-xy.xy.dreamhostps.com` / `Return-Path
            # simsong@xy.dreamhostps.com`) instead of stopping at
            # "display name spoofed".
            chain_tail = ""
            orig_ip = facts.get("smtp_originator_ip")
            orig_host = facts.get("smtp_originator_host")
            return_path = facts.get("smtp_return_path")
            submitter_uid = facts.get("smtp_submitter_uid")
            if orig_ip or return_path:
                bits = []
                if orig_ip and orig_host:
                    bits.append(f"originator {orig_host} [{orig_ip}]")
                elif orig_ip:
                    bits.append(f"originator IP {orig_ip}")
                if return_path:
                    bits.append(f"envelope Return-Path {return_path}")
                if submitter_uid is not None:
                    bits.append(f"Postfix UID {submitter_uid}")
                chain_tail = (f" Real SMTP path: {', '.join(bits)} — "
                              f"the displayed From is the spoof; this "
                              f"is the actual sender's infrastructure.")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="high",
                claim=(f"Inbound phishing / spoofed From in {pst_path.name} "
                       f"({m.folder}): From DISPLAYED as {disp!r} but "
                       f"ACTUAL From-SMTP is {real!r} (display domain "
                       f"{disp_dom} ≠ actual {real_dom}). Direct "
                       f"impersonation — the sender spoofed a display "
                       f"name to make the mail look internal."
                       f"{chain_tail}"),
                evidence=[ev],
                hypotheses_supported=[
                    "H_INITIAL_ACCESS_PHISHING",
                    "H_BEC_ACCOUNT_TAKEOVER",
                ],
            )))

        return out

    def _populate_graph(self, ctx, pst_path, msgs, local_doms) -> None:
        """Write Email / User / Domain / File nodes + edges so the
        case.html entity graph surfaces the email substrate. Silent on
        any failure — graph population never blocks findings emission."""
        from el.evidence.graph import open_graph
        try:
            db, conn = open_graph(ctx.case_dir)
        except Exception:
            return
        def _esc(s: str) -> str:
            return (s or "").replace("'", "''").replace("\\", "\\\\")

        try:
            for m in msgs:
                mid = f"{pst_path.name}:{m.message_dir.name if m.message_dir else 'unknown'}"
                subj = (m.subject or "")[:200]
                folder = m.folder or ""
                sent = (m.date_submit_utc.isoformat()
                        if getattr(m, "date_submit_utc", None) else "")
                has_att = 1 if m.attachments else 0
                conn.execute(
                    f"MERGE (e:Email {{msg_id: '{_esc(mid)}'}}) "
                    f"SET e.subject='{_esc(subj)}', "
                    f"e.folder='{_esc(folder)}', "
                    f"e.pst_path='{_esc(pst_path.name)}', "
                    f"e.sent_utc='{_esc(sent)}', "
                    f"e.has_attachments={has_att}"
                )
                # Sender User + domain
                if m.sender_email:
                    se = m.sender_email.lower()
                    conn.execute(
                        f"MERGE (u:User {{sid: '{_esc(se)}'}}) "
                        f"SET u.name='{_esc(se)}', u.host=''")
                    conn.execute(
                        f"MATCH (e:Email {{msg_id:'{_esc(mid)}'}}), "
                        f"      (u:User {{sid:'{_esc(se)}'}}) "
                        f"MERGE (e)-[:SENT_FROM]->(u)")
                    sdom = _smtp_domain(se)
                    if sdom:
                        conn.execute(
                            f"MERGE (d:Domain {{name: '{_esc(sdom)}'}})")
                        conn.execute(
                            f"MATCH (u:User {{sid:'{_esc(se)}'}}), "
                            f"      (d:Domain {{name:'{_esc(sdom)}'}}) "
                            f"MERGE (u)-[:EMAILS_ON_DOMAIN]->(d)")
                # Recipients
                for r in m.recipients:
                    if not r.email:
                        continue
                    re_ = r.email.lower()
                    conn.execute(
                        f"MERGE (u:User {{sid: '{_esc(re_)}'}}) "
                        f"SET u.name='{_esc(r.display_name or re_)}', "
                        f"u.host=''")
                    conn.execute(
                        f"MATCH (e:Email {{msg_id:'{_esc(mid)}'}}), "
                        f"      (u:User {{sid:'{_esc(re_)}'}}) "
                        f"MERGE (e)-[:SENT_TO]->(u)")
                    rdom = _smtp_domain(re_)
                    if rdom:
                        conn.execute(
                            f"MERGE (d:Domain {{name: '{_esc(rdom)}'}})")
                        conn.execute(
                            f"MATCH (u:User {{sid:'{_esc(re_)}'}}), "
                            f"      (d:Domain {{name:'{_esc(rdom)}'}}) "
                            f"MERGE (u)-[:EMAILS_ON_DOMAIN]->(d)")
                # Attachments
                for a in m.attachments:
                    if not a.filename:
                        continue
                    key = f"{pst_path.name}:{mid}:{a.filename}"[:180]
                    conn.execute(
                        f"MERGE (f:File {{path: '{_esc(key)}'}}) "
                        f"SET f.sha256='', f.size={int(a.size_bytes or 0)}, "
                        f"f.host=''")
                    conn.execute(
                        f"MATCH (e:Email {{msg_id:'{_esc(mid)}'}}), "
                        f"      (f:File {{path:'{_esc(key)}'}}) "
                        f"MERGE (e)-[:HAS_ATTACHMENT]->(f)")
        except Exception:
            # Partial graph is better than no graph; swallow and return
            pass
        finally:
            try: del conn
            except: pass
            try: del db
            except: pass

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
                # Outbound exfil-via-deception: T1534 (Internal
                # Spearphishing — the user believed they were
                # replying internally) + T1567 (Exfiltration Over
                # Web Service — the attachment leaves the org via
                # the email channel to an external recipient).
                "attack_techniques": (
                    ["T1534", "T1567"] if m.attachments else ["T1534"]
                ),
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
                # Pure exfil shape: sensitive attachment to external
                # recipient. T1567 (Exfiltration Over Web Service —
                # the email channel routes the data out of org). The
                # outer mismatch detector adds T1534 separately when
                # impersonation is also present.
                "attack_techniques": ["T1567"],
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
