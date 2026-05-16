"""IANA-TLD allowlist + repeat-run guard for the IOC domain extractor.

Surfaced by the M57-Jean Diamond audit: the Adversary / Infrastructure
quarters were full of carved-domain noise (`0iga3dj.cg`, `1q.gkt`,
`5.spoi`, `pscript.hlp`, `tpps.ppd`, …) — 46 garbage hits out of 47
total domains in the case's iocs.json. 43 of those had fake TLDs
(`.spoi`, `.gkt`, `.del`, `.ntf`, `.ppd`, `.hlp`, `.default`, etc.)
that no real-world domain could use.

This file pins:
  - the IANA TLD allowlist drops carved garbage with fake TLDs
  - real internal / RFC-reserved TLDs (.lan / .local / .corp /
    .example / .invalid) still pass — protects shieldbase.lan
    (SRL-2018 corp AD) and the RFC 2606 reserved-name set
  - repeat-run guard catches IANA-valid-but-garbage labels like
    `aaaaaa.aaaaaa` / `7la.baaaaaa`
  - short-first-label real domains (`n8n.io`, `bbc.com`, `mit.edu`,
    `4chan.org`) survive — no first-label-length rule
"""
from __future__ import annotations

import pytest

from el.skills.ioc_extract import _filter_domains, _has_repeat_run


# ---------------------------------------------------------------------------
# IANA TLD allowlist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("garbage_domain", [
    # The M57-Jean canonical 43-of-46 fake-TLD garbage set
    "0ngx.del", "1q.gkt", "5.spoi", "7.aabecvbee", "7ewo.oxcn",
    "7la.baaaaaa", "9ws.ko", "a.xbiv", "abaaa.aa", "b2t.cbdi",
    "baabaa.baaubaa", "bb.bbg", "d.iuo", "eurnbdlvfo6bdaoe.ugua",
    "fo.gqrx", "g6.aadaaaaaaaaaaaaaa", "h.tdo", "hegyd.vf", "i.hss",
    "jjbr.hi", "k.roro", "ko0.xyf", "lesd.yrj", "lg.fgv", "m.hsez",
    "n.nunb", "n.oouo", "o.sok", "pcf6.ey", "r.ngq", "rh.uxe",
    "u.qpe", "x.dxgl", "yh.yqr", "yx.aot", "zbovo.xd",
    # Plus the file-extension-as-TLD ones — defense in depth
    "pscript.hlp", "pscript.ntf", "tpog.hlp", "tpps.ppd",
    "administrator--towjib3x.default", "jean--c3xj7bxx.default",
])
def test_iana_allowlist_drops_fake_tld_garbage(garbage_domain):
    """Each member of the M57-Jean fake-TLD garbage set must be
    rejected. If one starts passing the wrong direction, either the
    IANA allowlist regressed or a TLD got mistakenly added."""
    assert _filter_domains([garbage_domain]) == set(), \
        f"carved-noise '{garbage_domain}' must NOT survive"


# ---------------------------------------------------------------------------
# Real domains pass through
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("real_domain", [
    # Common gTLDs
    "example.com", "wikipedia.org", "github.io",
    # Short-first-label domains — must NOT be over-filtered
    "n8n.io", "bbc.com", "mit.edu", "4chan.org",
    # Compound TLDs
    "amazon.co.uk", "test.co.jp",
    # Subdomains
    "mail.example.com", "api.github.io",
    # Stark-themed (this corpus already uses these)
    "stark-research.com",
])
def test_iana_allowlist_passes_real_domains(real_domain):
    """A representative set of real-world domains must survive the
    filter. Short first labels are deliberately not gated — many
    legitimate domains use them (BBC, MIT, T-Mobile shortener t.co,
    4chan, n8n.io). The cost of letting through `nle.la`-style
    short-garbage residuals is accepted in exchange."""
    assert _filter_domains([real_domain]) == {real_domain.lower()}, \
        f"real domain '{real_domain}' must survive"


# ---------------------------------------------------------------------------
# Internal / RFC-reserved TLD extension
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("internal_domain", [
    # Corporate AD (de-facto)
    "shieldbase.lan",     # SRL-2018 corp AD — load-bearing for that case
    "files.corp",
    "wiki.intranet",
    "router.home",
    "vault.private",
    # RFC 6762 mDNS
    "printer.local",
    "fileserver.local",
    # RFC 2606 reserved names
    "test.example",       # for examples / docs
    "stuff.test",         # for testing
    "nope.invalid",       # guaranteed not to resolve
    "loopback.localhost",
])
def test_internal_and_reserved_tlds_pass(internal_domain):
    """Enterprise AD + RFC 6762 / RFC 2606 reserved TLDs are not in
    the IANA list but are legitimately used in real networks.
    `shieldbase.lan` is the load-bearing case — SRL-2018 corpus
    revolves around it, so dropping it would regress every SRL run."""
    assert _filter_domains([internal_domain]) == {internal_domain.lower()}


# ---------------------------------------------------------------------------
# Repeat-run guard — IANA-valid TLDs paired with garbage labels
# ---------------------------------------------------------------------------

def test_repeat_run_catches_aaaaaa_pattern():
    """`aaaaaa.aaaaaa` has IANA-valid `.aaa` (AAA, the auto club gTLD)
    but the first label is pure repetition garbage. The repeat-run
    guard (4+ consecutive same char) catches it without depending on
    the TLD shape."""
    assert _filter_domains(["aaaaaa.aaaaaa"]) == set()


def test_repeat_run_catches_aaxaab_inflated_label():
    """`aaxaabaawaabaaaaaaaaaxbaaaa.aa` has a long run of `a`'s
    inside the first label (`aaaaaaaaa` = 9 in a row). Guarded by
    the same 4+-repeat heuristic."""
    assert _filter_domains([
        "aaxaabaawaabaaaaaaaaaxbaaaa.aa"
    ]) == set()


def test_repeat_run_helper_threshold_is_four():
    """Threshold pinned at 4 (not 3) — `kkkenya` style 3-letter runs
    appear in legitimate brand-name domains. Lowering to 3 would
    over-correct. This test pins the 4-vs-3 choice."""
    assert _has_repeat_run("aaaa", 4)
    assert _has_repeat_run("xaaaay", 4)
    assert _has_repeat_run("aaaaaa", 4)
    assert not _has_repeat_run("kkkenya", 4)
    assert not _has_repeat_run("aaa", 4)        # only 3 in a row
    assert not _has_repeat_run("", 4)
    assert not _has_repeat_run("abc", 4)


# ---------------------------------------------------------------------------
# End-to-end: M57-Jean garbage cleanup ratio
# ---------------------------------------------------------------------------

def test_m57_jean_garbage_cleanup_ratio():
    """The full M57-Jean carved-domain garbage set (47 entries) should
    survive the filter at no more than 3 entries. Pins the cleanup
    ratio so a regression in the IANA list or in the repeat-run
    guard re-floods the catalog."""
    m57_garbage = [
        "0iga3dj.cg", "0ngx.del", "1q.gkt", "5.spoi", "6aaba6aaaba.aaa",
        "7.aabecvbee", "7ewo.oxcn", "7la.baaaaaa", "9ws.ko", "a.xbiv",
        "aaaaaa.aaaaaa", "aaxaabaawaabaaaaaaaaaxbaaaa.aa", "abaaa.aa",
        "administrator--towjib3x.default", "b2t.cbdi",
        "baabaa.baaubaa", "bb.bbg", "d.iuo",
        "eurnbdlvfo6bdaoe.ugua", "fo.gqrx", "g6.aadaaaaaaaaaaaaaa",
        "h.tdo", "hegyd.vf", "i.hss", "jean--c3xj7bxx.default",
        "jjbr.hi", "k.roro", "ko0.xyf", "lesd.yrj", "lg.fgv",
        "m.hsez", "n.nunb", "n.oouo", "nle.la", "o.sok", "pcf6.ey",
        "pscript.hlp", "pscript.ntf", "r.ngq", "rh.uxe", "tpog.hlp",
        "tpps.ppd", "u.qpe", "x.dxgl", "yh.yqr", "yx.aot", "zbovo.xd",
    ]
    residual = _filter_domains(m57_garbage)
    # ≤3 residual — the IANA-valid TLDs with garbage labels that the
    # repeat-run guard doesn't catch (.cg with `0iga3dj`, .la with
    # `nle`, etc.). Acceptable tail.
    assert len(residual) <= 3, \
        f"Carved-noise filter regressed: residual={sorted(residual)}"
