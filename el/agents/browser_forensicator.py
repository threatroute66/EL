"""Browser Forensicator — triage browser history for exfil + pretexting
destinations.

Consumes a directory of extracted browser profiles (disk_forensicator
copies Firefox profiles into exports/windows-artifacts/browser/firefox/
<profile>/places.sqlite). Parses each places.sqlite and emits findings
on destination shapes that matter for DFIR:

  1. POST-SHAPE forum/board destination  (/viewtopic.php?, /post/,
     /submit, /upload)  → often used for anonymous data drops
  2. File-upload / pastebin / anonymous-share services  (pastebin,
     file.io, transfer.sh, anonfiles, mega.nz, etc.)
  3. Consumer webmail  (gmail.com, mail.yahoo, outlook.com, protonmail)

All three are suggestive — a visit alone is not proof — but they
narrow investigator focus materially on insider-exfil-shaped cases.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import browser, hindsight as hs


# URL shapes that are exfil-adjacent in casework. We match against the
# URL path+query, not the domain — a generic domain with these shapes
# is still a signal (forum boards and paste sites use many domains).
_FORUM_UPLOAD_PATH = re.compile(
    r"/(?:viewtopic|showthread|thread|post|upload|submit|newpost|newtopic|"
    r"forum|attachment|file/upload)\b",
    re.IGNORECASE,
)
_ANON_SHARE_HOSTS = {
    "pastebin.com", "paste.ee", "ghostbin.co", "hastebin.com",
    "file.io", "transfer.sh", "wetransfer.com", "we.tl",
    "anonfiles.com", "bayfiles.com", "mega.nz", "mega.co.nz",
    "mediafire.com", "sendspace.com", "zippyshare.com",
    "dropfiles.net", "uploadfiles.io", "filebin.net",
    "0x0.st", "catbox.moe", "files.catbox.moe",
}
_CONSUMER_WEBMAIL_HOSTS = {
    "mail.google.com", "gmail.com",
    "mail.yahoo.com", "login.yahoo.com",
    "outlook.live.com", "mail.live.com", "hotmail.com",
    "mail.proton.me", "mail.protonmail.com", "protonmail.com",
    "mail.aol.com", "mail.gmx.com", "mail.tutanota.com",
    "icloud.com",
}


def _host(url: str) -> str:
    try:
        return urlparse(url).hostname.lower() if urlparse(url).hostname else ""
    except Exception:
        return ""


class BrowserForensicatorAgent(Agent):
    name = "browser_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        root = Path(ctx.input_path)
        if not root.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"BrowserForensicator expects a directory input; got {root}",
            ))]

        # Firefox profiles: any places.sqlite anywhere under root.
        places = sorted(p for p in root.rglob("places.sqlite") if p.is_file())
        for p in places:
            out.extend(self._triage_places(ctx, p))

        # Chromium-family profiles: dirs containing both 'History' and 'Cookies'.
        # Run Hindsight against each, emit a JSONL inventory finding plus
        # url-shape exfil triage on the parsed history rows.
        chromium_profiles = hs.find_profiles(root)
        for prof in chromium_profiles:
            out.extend(self._triage_chromium(ctx, prof, analysis))

        if not places and not chromium_profiles:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"No Firefox places.sqlite or Chromium profile dirs "
                       f"(History+Cookies) found under {root}"),
            ))]

        return out

    def _triage_chromium(self, ctx: AgentContext, profile_dir: Path,
                          analysis: Path) -> list[Finding]:
        """Run Hindsight against a Chromium profile and emit findings."""
        out: list[Finding] = []
        out_dir = analysis / "hindsight" / profile_dir.name
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            run = hs.run(profile_dir, out_dir)
        except hs.HindsightError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Hindsight unavailable for {profile_dir.name}: {e}",
            )))
            return out

        if run.rc != 0 or run.output_jsonl is None:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"Hindsight failed for {profile_dir.name}: "
                       f"rc={run.rc}, note={run.note or '-'}"),
            )))
            return out

        ev = run.as_evidence()
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Chromium profile parsed: {run.record_count:,} record(s) "
                   f"across {len(run.distinct_event_types)} event type(s) "
                   f"({profile_dir.name})"),
            evidence=[ev],
        )))

        # URL-shape exfil triage over Hindsight history rows.
        forum_hits: list[dict] = []
        anon_hits: list[dict] = []
        webmail_hits: list[dict] = []
        for rec in run.iter_records(max_rows=20000):
            url = (rec.get("url") or rec.get("URL")
                   or rec.get("web_address") or "")
            if not url or not url.startswith(("http://", "https://")):
                continue
            host = _host(url)
            if _FORUM_UPLOAD_PATH.search(url):
                forum_hits.append({"url": url[:200], "host": host})
            if host in _ANON_SHARE_HOSTS:
                anon_hits.append({"url": url[:200], "host": host})
            if host in _CONSUMER_WEBMAIL_HOSTS:
                webmail_hits.append({"url": url[:200], "host": host})

        if forum_hits:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Chromium history: {len(forum_hits)} forum/upload-shape "
                       f"URL(s) ({profile_dir.name}) — exfil-adjacent paths"),
                evidence=[ev],
                hypotheses_supported=["H_INSIDER_DATA_EXFIL"],
            )))
        if anon_hits:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Chromium history: {len(anon_hits)} visit(s) to "
                       f"anon-share/pastebin host(s) "
                       f"({sorted(set(h['host'] for h in anon_hits))[:5]}) "
                       f"({profile_dir.name})"),
                evidence=[ev],
                hypotheses_supported=["H_INSIDER_DATA_EXFIL",
                                       "H_BEC_ACCOUNT_TAKEOVER"],
            )))
        if webmail_hits:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=(f"Chromium history: {len(webmail_hits)} consumer-webmail "
                       f"visit(s) ({profile_dir.name}) — relevant to BEC / "
                       f"insider-email-exfil scenarios"),
                evidence=[ev],
                hypotheses_supported=["H_INSIDER_DATA_EXFIL"],
            )))

        return out

    def _triage_places(self, ctx: AgentContext, places_sqlite: Path) -> list[Finding]:
        out: list[Finding] = []
        try:
            run = browser.firefox_places(places_sqlite)
        except browser.BrowserError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"firefox_places failed on {places_sqlite}: {e}",
            ))]
        if run.error:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Firefox history schema read error on {places_sqlite}: {run.error}",
            ))]

        # Volume finding
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Firefox history parsed ({places_sqlite.name}): "
                   f"{len(run.visits)} URL(s) in places.sqlite"),
            evidence=[run.as_evidence()],
            hypotheses_supported=["H_BROWSER_HISTORY_PARSED"],
        )))

        # Bucket by category
        forum_hits: list[browser.Visit] = []
        share_hits: list[browser.Visit] = []
        webmail_hits: list[browser.Visit] = []
        for v in run.visits:
            host = _host(v.url)
            if not host:
                continue
            if host in _ANON_SHARE_HOSTS or any(
                    host.endswith("." + h) for h in _ANON_SHARE_HOSTS):
                share_hits.append(v)
            elif host in _CONSUMER_WEBMAIL_HOSTS or any(
                    host.endswith("." + h) for h in _CONSUMER_WEBMAIL_HOSTS):
                webmail_hits.append(v)
            elif _FORUM_UPLOAD_PATH.search(urlparse(v.url).path or ""):
                forum_hits.append(v)

        if share_hits:
            sample = [v.url for v in share_hits[:5]]
            ev = run.as_evidence(facts={"category": "anon_share",
                                        "url_count": len(share_hits),
                                        "sample_urls": sample})
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Browser history → anonymous file-share / pastebin "
                       f"destination(s) ({places_sqlite.name}): "
                       f"{len(share_hits)} visit(s). Hosts: "
                       f"{', '.join(sorted({_host(v.url) for v in share_hits}))[:200]}. "
                       f"Upload-capable external destination."),
                evidence=[ev],
                hypotheses_supported=["H_INSIDER_DATA_EXFIL"],
            )))

        if forum_hits:
            hosts = sorted({_host(v.url) for v in forum_hits})
            sample = [v.url for v in forum_hits[:5]]
            ev = run.as_evidence(facts={"category": "forum_upload",
                                        "url_count": len(forum_hits),
                                        "sample_urls": sample})
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Browser history → forum / board post-shape URL(s) "
                       f"({places_sqlite.name}): {len(forum_hits)} visit(s). "
                       f"Hosts: {', '.join(hosts)[:200]}. Post/upload-capable "
                       f"external destination — pivot via URL list."),
                evidence=[ev],
                hypotheses_supported=["H_INSIDER_DATA_EXFIL"],
            )))

        if webmail_hits:
            hosts = sorted({_host(v.url) for v in webmail_hits})
            sample = [v.url for v in webmail_hits[:5]]
            ev = run.as_evidence(facts={"category": "consumer_webmail",
                                        "url_count": len(webmail_hits),
                                        "sample_urls": sample})
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=(f"Browser history → consumer-webmail access "
                       f"({places_sqlite.name}): {len(webmail_hits)} visit(s) "
                       f"across {len(hosts)} host(s) ({', '.join(hosts)[:200]}). "
                       f"Informational — confirms a personal-mail channel "
                       f"was available on the device."),
                evidence=[ev],
            )))

        # Narcotic-lexicon + BTC cross-reference over URL + page title.
        # Surfaces vendor-panel / order-tracking / wallet-copy pages that
        # the category buckets above don't catch.
        from el.skills import narcotic_lexicon as nl
        from el.skills import ioc_extract as iex
        narco_visits: list[browser.Visit] = []
        narco_subs: set[str] = set()
        btc_visits: list[tuple[browser.Visit, set[str]]] = []
        for v in run.visits:
            text = f"{v.url} {v.title or ''}"
            m = nl.scan_text(text)
            if m is not None:
                narco_visits.append(v)
                narco_subs.update(m.substance_hits)
            btcs = iex.extract(text).get("btc", set())
            if btcs:
                btc_visits.append((v, btcs))
        if narco_visits:
            ev = run.as_evidence(facts={"category": "narcotic_lexicon",
                                        "url_count": len(narco_visits),
                                        "substance_hits": sorted(narco_subs)[:10],
                                        "sample_urls": [v.url for v in narco_visits[:5]]})
            sub_note = (f" Controlled-substance names [INCB Yellow List]: "
                        f"{sorted(narco_subs)[:5]}." if narco_subs else "")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Browser history → narcotic-lexicon match(es) "
                       f"({places_sqlite.name}): {len(narco_visits)} "
                       f"URL(s) with strain/unit/price markers.{sub_note} "
                       f"Pivot against firefox downloads + mbox for "
                       f"corroboration."),
                evidence=[ev],
                # Drug-trade browsing is illicit-enterprise evidence,
                # not insider-exfil or commodity-malware — H_ILLICIT_
                # ENTERPRISE is the motive that fits a subject-operated
                # device. (Was mis-tagged H_INSIDER_DATA_EXFIL +
                # H_OPPORTUNISTIC_COMMODITY before that hypothesis existed.)
                hypotheses_supported=["H_ILLICIT_ENTERPRISE"],
            )))
        if btc_visits:
            btc_set = {b for _, bs in btc_visits for b in bs}
            ev = run.as_evidence(facts={"category": "btc_wallet",
                                        "url_count": len(btc_visits),
                                        "btc_addresses": sorted(btc_set)[:10],
                                        "sample_urls": [v.url for v, _ in btc_visits[:5]]})
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Browser history → BTC wallet address(es) "
                       f"({places_sqlite.name}): {len(btc_visits)} URL(s) "
                       f"carry {len(btc_set)} distinct wallet(s). "
                       f"Sample: {sorted(btc_set)[:3]}."),
                evidence=[ev],
                # Cryptocurrency in user browsing corroborates an
                # illicit-enterprise motive (graded +1 — weaker than a
                # narcotic-lexicon hit, since crypto alone is dual-use).
                hypotheses_supported=["H_ILLICIT_ENTERPRISE"],
            )))
        return out
