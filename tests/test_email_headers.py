"""Tests for el.skills.email_headers — Received chain + envelope parser.

The M57-Jean pretext mail header is the canonical drive-by example:
spoofed `From: tuckgorge@gmail.com (alison@m57.biz)` over an actual
SMTP path of Dreamhost shared web server `apache2-xy.xy.dreamhostps.com`
[208.97.188.9] → `smarty.dreamhost.com` [208.97.132.66] →
`spunkymail-mx2.g.dreamhost.com`, Return-Path
`simsong@xy.dreamhostps.com`, Postfix submission by Unix UID 558838.
Every relevant field is pinned below.
"""
from __future__ import annotations

import pytest

from el.skills.email_headers import HeaderChain, ReceivedHop, parse


# ---------------------------------------------------------------------------
# M57-Jean canonical sample
# ---------------------------------------------------------------------------

M57_PRETEXT_HEADERS = """\
Return-Path: <simsong@xy.dreamhostps.com>
X-Original-To: jean@m57.biz
Delivered-To: x2789967@spunkymail-mx2.g.dreamhost.com
Received: from smarty.dreamhost.com (sd-green-bigip-66.dreamhost.com [208.97.132.66])
\tby spunkymail-mx2.g.dreamhost.com (Postfix) with ESMTP id 2D1DC7278E
\tfor <jean@m57.biz>; Sat, 19 Jul 2008 18:22:45 -0700 (PDT)
Received: from xy.dreamhostps.com (apache2-xy.xy.dreamhostps.com [208.97.188.9])
\tby smarty.dreamhost.com (Postfix) with ESMTP id 138E5EE221
\tfor <jean@m57.biz>; Sat, 19 Jul 2008 18:22:45 -0700 (PDT)
Received: by xy.dreamhostps.com (Postfix, from userid 558838)
\tid 177343B1DA8; Sat, 19 Jul 2008 18:22:45 -0700 (PDT)
To: jean@m57.biz
From: tuckgorge@gmail.com (alison@m57.biz)
subject: Please send me the information now
Message-Id: <20080720012245.177343B1DA8@xy.dreamhostps.com>
Date: Sat, 19 Jul 2008 18:22:45 -0700 (PDT)
"""


def test_m57_pretext_return_path():
    """The real SMTP envelope sender — `simsong@xy.dreamhostps.com`
    in M57-Jean. Forensically more actionable than the displayed
    From because it survives any header spoof (Return-Path is set
    by the receiving MTA from the MAIL FROM)."""
    hc = parse(M57_PRETEXT_HEADERS)
    assert hc.return_path == "simsong@xy.dreamhostps.com"


def test_m57_pretext_originator_ip():
    """First non-local Received hop — `[208.97.188.9]` in M57-Jean
    (apache2-xy.xy.dreamhostps.com, the Dreamhost shared web server
    where the attacker ran their script). The IP that needs to land
    in the Diamond Adversary quarter."""
    hc = parse(M57_PRETEXT_HEADERS)
    assert hc.originator_ip == "208.97.188.9"


def test_m57_pretext_originator_host():
    """rDNS of the originator IP — `apache2-xy.xy.dreamhostps.com`.
    Cosmetic but useful in narratives ('originator host: apache2-xy.
    xy.dreamhostps.com [208.97.188.9]')."""
    hc = parse(M57_PRETEXT_HEADERS)
    assert hc.originator_host == "apache2-xy.xy.dreamhostps.com"


def test_m57_pretext_submitter_uid():
    """The local Unix UID that submitted the mail via Postfix's
    sendmail interface — `558838` in M57-Jean. On a shared-hosting
    provider this maps directly to a paying customer's account via
    the provider's billing records."""
    hc = parse(M57_PRETEXT_HEADERS)
    assert hc.submitter_uid == 558838


def test_m57_pretext_full_chain():
    """Full 3-hop chain in chronological order. Hop 0 (originator)
    is the Postfix local submission; hop 1 is xy.dreamhostps.com →
    smarty.dreamhost.com; hop 2 is smarty → spunkymail-mx2 (final
    delivery). Verifying the chain ordering pins the
    Received-headers-are-prepended convention; if a future MTA
    reverses this convention the chain ordering would flip and
    `originator_ip` would silently shift."""
    hc = parse(M57_PRETEXT_HEADERS)
    assert len(hc.received_chain) == 3
    # Hop 0: Postfix local submission (no from_host/from_ip)
    assert hc.received_chain[0].from_host is None
    assert hc.received_chain[0].from_ip is None
    assert hc.received_chain[0].submitter_uid == 558838
    assert hc.received_chain[0].by_host == "xy.dreamhostps.com"
    # Hop 1: xy.dreamhostps.com (originator) → smarty.dreamhost.com
    assert hc.received_chain[1].from_host == "apache2-xy.xy.dreamhostps.com"
    assert hc.received_chain[1].from_ip == "208.97.188.9"
    assert hc.received_chain[1].by_host == "smarty.dreamhost.com"
    assert hc.received_chain[1].smtp_id == "138E5EE221"
    # Hop 2: smarty.dreamhost.com → spunkymail-mx2.g.dreamhost.com
    assert hc.received_chain[2].from_host == "sd-green-bigip-66.dreamhost.com"
    assert hc.received_chain[2].from_ip == "208.97.132.66"
    assert hc.received_chain[2].by_host == "spunkymail-mx2.g.dreamhost.com"


def test_postfix_local_submission_not_treated_as_from_host():
    """Regression for the parser bug where `Received: by host
    (Postfix, from userid 558838)` made the `from` regex grab
    `userid` as the from_host. The from-clause gate now requires
    an FQDN-like token (dot in name OR followed by parens) so the
    Postfix submission line correctly produces no from_host."""
    sample = (
        "Received: by xy.dreamhostps.com (Postfix, from userid 558838)\n"
        "\tid 177343B1DA8; Sat, 19 Jul 2008 18:22:45 -0700 (PDT)\n"
    )
    hc = parse(sample)
    assert len(hc.received_chain) == 1
    assert hc.received_chain[0].from_host is None
    assert hc.received_chain[0].submitter_uid == 558838


# ---------------------------------------------------------------------------
# X-Originating-IP precedence
# ---------------------------------------------------------------------------

def test_x_originating_ip_wins_over_received_chain():
    """Gmail/Yahoo's `X-Originating-IP` was populated with the user's
    browser IP at compose time. When present it's a stronger signal
    than the first-hop Received IP (which would just be the webmail
    provider's outbound MTA). M57-Jean predates the Gmail deprecation
    but doesn't itself use Gmail compose, so the M57 sample doesn't
    have this header — but the precedence logic must work for cases
    that do."""
    sample = (
        "X-Originating-IP: [203.0.113.42]\n"
        "Received: from mx.gmail.com (mx.gmail.com [74.125.20.27])\n"
        "\tby mx.example.com (Postfix) with ESMTP id ABCDEF\n"
        "\tfor <user@example.com>; ...\n"
    )
    hc = parse(sample)
    assert hc.x_originating_ip == "203.0.113.42"
    assert hc.originator_ip == "203.0.113.42"   # X-Originating-IP wins


def test_x_originating_ip_optional_brackets():
    """The header is sometimes emitted with brackets, sometimes
    without. Both shapes parse the same IP."""
    with_brackets = parse("X-Originating-IP: [192.0.2.1]\n")
    without_brackets = parse("X-Originating-IP: 192.0.2.1\n")
    assert with_brackets.x_originating_ip == "192.0.2.1"
    assert without_brackets.x_originating_ip == "192.0.2.1"


# ---------------------------------------------------------------------------
# Robustness — missing headers, folded headers, IPv6, junk input
# ---------------------------------------------------------------------------

def test_empty_input_returns_empty_chain():
    hc = parse("")
    assert hc.return_path is None
    assert hc.originator_ip is None
    assert hc.received_chain == []


def test_no_received_headers_returns_empty_chain():
    sample = "From: alice@example.com\nTo: bob@example.com\n"
    hc = parse(sample)
    assert hc.received_chain == []
    assert hc.originator_ip is None


def test_folded_received_header_is_unfolded_before_parsing():
    """RFC 5322 §2.2.3 — header continuation lines start with
    whitespace. Parser must unfold so the Received pieces (from/by/
    id) on continuation lines are visible to the field regexes."""
    sample = (
        "Received: from mx.example.com (mx.example.com\n"
        "\t[198.51.100.5])\n"
        "\tby relay.example.org (Postfix) with ESMTP id AAAAAA\n"
    )
    hc = parse(sample)
    assert len(hc.received_chain) == 1
    assert hc.received_chain[0].from_ip == "198.51.100.5"
    assert hc.received_chain[0].by_host == "relay.example.org"


def test_ipv6_bracketed_ip_extracted():
    """RFC 5321 IPv6 literal must come bracketed. Test that the
    parser handles `[2001:db8::1]` the same way it handles IPv4."""
    sample = (
        "Received: from sender.example (sender.example [2001:db8::1])\n"
        "\tby mx.example.com (Postfix) with ESMTP id BBBBBB\n"
    )
    hc = parse(sample)
    assert hc.received_chain[0].from_ip == "2001:db8::1"
    assert hc.originator_ip == "2001:db8::1"


def test_return_path_optional_angle_brackets():
    """RFC 5321 specifies <addr> but many MTAs omit the brackets."""
    with_brackets = parse("Return-Path: <admin@example.com>\n")
    without_brackets = parse("Return-Path: admin@example.com\n")
    assert with_brackets.return_path == "admin@example.com"
    assert without_brackets.return_path == "admin@example.com"


def test_garbage_input_does_not_raise():
    """Defensive: parser must not throw on malformed input — the
    PST exporter occasionally outputs partial / truncated header
    blocks for messages whose headers were stored fragmentarily."""
    for garbage in (
        "\x00\x01\x02 binary garbage",
        "no headers just text",
        "Received:\n",  # truncated
        "Received: from\n",  # no IP, no by
    ):
        hc = parse(garbage)
        # No assertion on content — just that it doesn't crash
        assert isinstance(hc, HeaderChain)


def test_multiple_envelope_senders_takes_first_only():
    """If two `Return-Path:` headers are present (some MTAs add a
    new one on each relay), the parser picks the first match. This
    is defensible but worth pinning so a regex tweak doesn't
    silently swap to the last match."""
    sample = (
        "Return-Path: <first@example.com>\n"
        "Return-Path: <second@example.com>\n"
    )
    hc = parse(sample)
    assert hc.return_path == "first@example.com"


# ---------------------------------------------------------------------------
# Integration with outlook_pst._parse_message
# ---------------------------------------------------------------------------

def test_outlook_pst_message_populates_header_chain(tmp_path):
    """The _parse_message helper must read InternetHeaders.txt and
    populate Message.header_chain when the file is present."""
    from el.skills.outlook_pst import _parse_message
    msg_dir = tmp_path / "Inbox" / "Message00001"
    msg_dir.mkdir(parents=True)
    (msg_dir / "OutlookHeaders.txt").write_text(
        "Subject: test\nSender name: A\nSender email address: a@x.com\n"
    )
    (msg_dir / "Recipients.txt").write_text("")
    (msg_dir / "InternetHeaders.txt").write_text(M57_PRETEXT_HEADERS)
    msg = _parse_message(msg_dir)
    assert msg.header_chain is not None
    assert msg.header_chain.return_path == "simsong@xy.dreamhostps.com"
    assert msg.header_chain.originator_ip == "208.97.188.9"


def test_outlook_pst_message_handles_missing_internet_headers(tmp_path):
    """Outbound messages composed in Outlook usually have no
    InternetHeaders.txt — the SMTP relay path is set by the mail
    server after submission. header_chain must be None, NOT raise."""
    from el.skills.outlook_pst import _parse_message
    msg_dir = tmp_path / "Sent Items" / "Message00001"
    msg_dir.mkdir(parents=True)
    (msg_dir / "OutlookHeaders.txt").write_text(
        "Subject: test\nSender name: A\nSender email address: a@x.com\n"
    )
    (msg_dir / "Recipients.txt").write_text("")
    # No InternetHeaders.txt
    msg = _parse_message(msg_dir)
    assert msg.header_chain is None
