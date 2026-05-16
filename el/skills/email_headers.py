"""Parse SMTP Received chain + envelope headers from raw RFC 5322 text.

The forensic value of an email's `InternetHeaders.txt` (preserved by
the PST exporter at one file per message) lives in the headers the
mail client never shows the user. For the M57-Jean case specifically:

* The visible `From:` line says `tuckgorge@gmail.com (alison@m57.biz)`
  — pure header spoof.
* The actual SMTP path is `xy.dreamhostps.com` (`apache2-xy`, IP
  `208.97.188.9`) → `smarty.dreamhost.com` → `spunkymail-mx2.g.
  dreamhost.com`. The mail never transited Gmail.
* `Return-Path:` carries `simsong@xy.dreamhostps.com` — the real
  envelope sender. (Simson Garfinkel — the scenario author, playing
  the attacker. In a real-world case, the analogous value would be
  the actual attacker's hosting-provider account.)
* `Received: by xy.dreamhostps.com (Postfix, from userid 558838)`
  — the local Unix UID that submitted the mail via PHP / sendmail.
  Combined with Dreamhost's billing records this would name the
  paying customer.

This module turns those raw headers into structured fields the
email_forensicator agent surfaces as `extracted_facts` on its
inbound-phishing findings, which the Diamond Adversary quarter
then picks up alongside the spoofed `tuckgorge@gmail.com`.

Pure-Python, regex only. No external deps. Robust to:
  - missing headers (return None / empty)
  - folded headers (lines starting with whitespace continue the
    previous header — RFC 5322 §2.2.3 header folding / unfolding)
  - IPv6 addresses (`[2001:db8::1]`)
  - multi-hop Received chains (returns chronological order with
    the originator hop first)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ReceivedHop:
    """One Received: header parsed into structured fields.

    Not every hop has every field — local submissions
    (`Received: by host (Postfix, from userid N)`) lack a `from`
    clause; some MTAs omit the bracketed IP.
    """
    raw: str                            # full unfolded header line
    from_host: str | None = None        # the HELO name + rDNS part
    from_ip: str | None = None          # bracketed IPv4 / IPv6 if present
    by_host: str | None = None          # receiving host
    submitter_uid: int | None = None    # Postfix "from userid N" local submission
    smtp_id: str | None = None          # the receiving MTA's queue ID


@dataclass
class HeaderChain:
    """Structured projection of an email's envelope + Received chain.

    `received_chain` is in **chronological order** — index 0 is the
    originator hop (the bottommost Received: header in the raw file,
    since Received headers are PREPENDED at each relay). `originator_ip`
    and `originator_host` are convenience aliases for the first hop
    that carries a `from … [IP]` clause.
    """
    return_path: str | None = None      # SMTP envelope sender (MAIL FROM)
    x_originating_ip: str | None = None # Gmail/Yahoo classic header (pre-2012)
    received_chain: list[ReceivedHop] = field(default_factory=list)

    @property
    def originator_ip(self) -> str | None:
        """First-hop sender IP. X-Originating-IP wins when present
        (Gmail/Yahoo populated it from the user's browser IP); otherwise
        the lowest Received hop that carries a bracketed IP."""
        if self.x_originating_ip:
            return self.x_originating_ip
        for hop in self.received_chain:
            if hop.from_ip:
                return hop.from_ip
        return None

    @property
    def originator_host(self) -> str | None:
        for hop in self.received_chain:
            if hop.from_host:
                return hop.from_host
        return None

    @property
    def submitter_uid(self) -> int | None:
        """The local Unix UID that submitted the mail via Postfix's
        sendmail interface — only present on local-submission hops.
        Strong identifier on shared-hosting providers where each UID
        maps to a paying customer's account."""
        for hop in self.received_chain:
            if hop.submitter_uid is not None:
                return hop.submitter_uid
        return None


# ---------------------------------------------------------------------------
# Regex bestiary — kept module-level so the compile happens once at import
# ---------------------------------------------------------------------------

# Header unfolding: RFC 5322 §2.2.3 — any line beginning with whitespace
# is a continuation of the previous header. Replace `\n[\t ]+` with a
# single space so each header sits on one line for downstream parsing.
_HEADER_FOLD = re.compile(r"\r?\n[ \t]+")

# Return-Path: <addr>  (envelope sender — strip optional angle brackets)
_RETURN_PATH = re.compile(
    r"^Return-Path:\s*<?\s*([^>\r\n\s]+)\s*>?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# X-Originating-IP: [a.b.c.d]  or  X-Originating-IP: a.b.c.d
# (Gmail/Yahoo populated this with the user's browser IP at compose
# time. Deprecated by Gmail in 2012; pre-2012 cases still carry it.)
_X_ORIG_IP = re.compile(
    r"^X-Originating-IP:\s*\[?([0-9A-Fa-f:.]+)\]?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# Received: from <host> (<rDNS> [<IP>]) by <by_host> ...
# Pieces individually rather than one mega-regex so partial matches
# still extract what's present.
_RECEIVED_HEADER = re.compile(
    r"^Received:\s*(.+?)$",
    re.IGNORECASE | re.MULTILINE,
)
_FROM_CLAUSE = re.compile(
    r"\bfrom\s+(\S+)(?:\s+\(([^)]+)\))?",
    re.IGNORECASE,
)
_BRACKETED_IP = re.compile(r"\[([0-9A-Fa-f:.]+)\]")
_BY_CLAUSE = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_POSTFIX_UID = re.compile(
    r"Postfix,\s*from\s+userid\s+(\d+)", re.IGNORECASE,
)
_SMTP_QUEUE_ID = re.compile(
    r"\b(?:ESMTP|SMTP|LMTP)(?:S|A)?\s+id\s+(\S+)", re.IGNORECASE,
)


def _unfold(text: str) -> str:
    return _HEADER_FOLD.sub(" ", text)


def _parse_received_line(raw: str) -> ReceivedHop:
    """Parse a single (unfolded) `Received:` header value."""
    hop = ReceivedHop(raw=raw.strip())
    m = _FROM_CLAUSE.search(raw)
    if m:
        from_host = m.group(1)
        from_paren = m.group(2) or ""
        # Reject Postfix local-submission false positives:
        # `Received: by host (Postfix, from userid N)` makes the
        # regex match `from userid` and grab `userid` as a hostname.
        # Real SMTP `from` clauses are FQDN-like (contain a dot) OR
        # are immediately followed by a parenthetical with the rDNS
        # / IP. Local submissions have neither, so the gate filters
        # them out without affecting any real `Received: from`.
        is_fqdn_like = ("." in from_host) or bool(from_paren)
        if is_fqdn_like:
            hop.from_host = from_host
            # The bracketed IP can live in the from_host clause OR
            # in the parenthetical immediately after. Check both.
            ip_match = (_BRACKETED_IP.search(from_paren)
                         or _BRACKETED_IP.search(raw))
            if ip_match:
                hop.from_ip = ip_match.group(1)
            # Some MTAs emit `from host (rDNS [IP])` — pull the
            # rDNS as the more informative `from_host` value.
            if from_paren and not _BRACKETED_IP.search(from_host or ""):
                rdns_token = from_paren.split()[0].strip()
                if rdns_token and "[" not in rdns_token:
                    hop.from_host = rdns_token
    by_match = _BY_CLAUSE.search(raw)
    if by_match:
        hop.by_host = by_match.group(1)
    uid_match = _POSTFIX_UID.search(raw)
    if uid_match:
        try:
            hop.submitter_uid = int(uid_match.group(1))
        except ValueError:
            pass
    id_match = _SMTP_QUEUE_ID.search(raw)
    if id_match:
        hop.smtp_id = id_match.group(1)
    return hop


def parse(headers_text: str) -> HeaderChain:
    """Parse an RFC 5322 header block. Returns a HeaderChain whose
    fields are None / empty when the corresponding headers are absent.
    Robust to folded headers, missing pieces, IPv6, multi-hop chains.
    """
    if not headers_text:
        return HeaderChain()
    unfolded = _unfold(headers_text)

    # Envelope sender
    rp = None
    rp_match = _RETURN_PATH.search(unfolded)
    if rp_match:
        rp = rp_match.group(1).strip().lower() or None

    # X-Originating-IP (when present)
    xoip = None
    xoip_match = _X_ORIG_IP.search(unfolded)
    if xoip_match:
        xoip = xoip_match.group(1).strip()

    # Received chain. Received headers are PREPENDED at each relay,
    # so the FIRST Received line in the file is the LAST hop (closest
    # to recipient) and the LAST is the FIRST hop (closest to sender).
    # Reverse the regex matches so the returned list is in chronological
    # order — index 0 = originator hop.
    received_raw_lines = [m.group(1) for m in _RECEIVED_HEADER.finditer(unfolded)]
    received_hops = [_parse_received_line(line) for line in received_raw_lines]
    received_hops.reverse()

    return HeaderChain(
        return_path=rp,
        x_originating_ip=xoip,
        received_chain=received_hops,
    )


__all__ = ["HeaderChain", "ReceivedHop", "parse"]
