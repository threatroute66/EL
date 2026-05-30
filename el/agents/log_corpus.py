"""LogCorpusAgent — fan a multi-host SOC/IR log corpus out per format.

Input shape: a directory whose children are per-host subdirectories, each
holding one or more log files in mixed formats (Windows Event XML, eCAR EDR
telemetry, Zeek JSON, Cisco ASA syslog, Snort fast-alerts, web access logs,
RFC 5424 syslog). This agent dispatches each source to the matching native
parser and emits one grounded Finding per parsed source plus a corpus
summary — turning a heterogeneous log dump into structured, ACH-feedable
evidence in a single ``el investigate`` pass.

Routing is by filename + a cheap content sniff, so it is robust to naming
drift. Each parser is read-only and lenient; an unparseable source is noted,
never fatal.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding

_ZEEK_MIN = 2                     # min recognised Zeek logs to treat a dir as Zeek
_SNIFF = 4096
# Conservative thresholds for lifting an intrusion hypothesis from a count.
_FAILED_LOGON_MIN = 10            # Windows 4625 burst -> brute force
_ASA_DENY_MIN = 50                # blocked inbound probing -> recon/scan


def _head(path: Path) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(_SNIFF)
    except OSError:
        return b""


class LogCorpusAgent(Agent):
    name = "log_corpus"

    def run(self, ctx: AgentContext) -> list[Finding]:
        root = Path(ctx.input_path)
        if not root.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"LogCorpusAgent expects a directory; got {root}"))]

        analysis = ctx.case_dir / "analysis" / self.name
        host_dirs = [d for d in sorted(root.iterdir()) if d.is_dir()] or [root]
        out: list[Finding] = []
        sources = 0
        total_events = 0
        hosts_seen: set[str] = set()
        signals: list[dict] = []      # (host, stage, ips) for graph population

        for host in host_dirs:
            host_out, n_src, n_evt = self._run_host(
                ctx, host, analysis, signals)
            out.extend(host_out)
            if n_src:
                hosts_seen.add(host.name)
                sources += n_src
                total_events += n_evt

        # Feed per-host attack-stage signals into the Kùzu graph so the
        # Correlator can tie the recon -> web-shell -> injection chain across
        # hosts (Host + Event[stage] + IPAddress / OBSERVED_ON / SOURCE_IP).
        self._populate_graph(ctx, signals)

        if sources == 0:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=(f"LogCorpusAgent walked {root.name} but recognised no "
                       f"parseable log sources (Windows Event XML, eCAR, Zeek "
                       f"JSON, Cisco ASA, Snort, web access, syslog)."),
            ))]

        sha = hashlib.sha256(
            f"{root}:{sorted(hosts_seen)}:{sources}".encode()).hexdigest()
        out.insert(0, self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Log corpus parsed: {sources} source(s) across "
                   f"{len(hosts_seen)} host(s), {total_events:,} total "
                   f"record(s). Hosts: {', '.join(sorted(hosts_seen))}."),
            evidence=[EvidenceItem(
                tool="el.log_corpus", version="0.1.0",
                command=f"fan-out parse {root}",
                output_sha256=sha, output_path=str(analysis),
                extracted_facts={"hosts": sorted(hosts_seen),
                                 "sources": sources,
                                 "total_records": total_events})],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))
        return out

    def _run_host(self, ctx: AgentContext, host: Path,
                  analysis: Path, signals: list) -> tuple[list[Finding], int, int]:
        out: list[Finding] = []
        sources = 0
        events = 0
        outdir = analysis / host.name
        files = [f for f in sorted(host.rglob("*")) if f.is_file()]
        handled: set[Path] = set()

        # 1) Zeek — handled at dir level (a host's Zeek logs live together).
        from el.skills import zeek_json as zj
        zlogs = zj.find_zeek_logs(host)
        if len(zlogs) >= _ZEEK_MIN:
            try:
                run = zj.parse_dir(host, output_dir=outdir / "zeek")
                if run.total:
                    sources += 1
                    events += run.total
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name, confidence="medium",
                        claim=(f"[{host.name}] Zeek JSON: {run.total:,} record(s) "
                               f"across {len(run.counts())} log type(s) "
                               f"{list(run.counts())}."),
                        evidence=[run.as_evidence()],
                        hypotheses_supported=["H_DISK_ARTIFACTS"])))
                handled.update(zlogs.values())
            except Exception:
                pass

        for f in files:
            if f in handled:
                continue
            fins, n = self._route_file(ctx, f, host.name, outdir, signals)
            if fins:
                for fin in fins:
                    out.append(self.emit(ctx, fin))
                sources += 1
                events += n
        return out, sources, events

    def _signal(self, ctx: AgentContext, host: str, claim: str,
                tags: list[str], evidence) -> Finding:
        """A targeted threat finding that lifts a specific intrusion
        hypothesis (kept separate from the H_DISK_ARTIFACTS inventory)."""
        return Finding(
            case_id=ctx.case_id, agent=self.name, confidence="medium",
            claim=f"[{host}] {claim}", evidence=[evidence],
            hypotheses_supported=tags)

    @staticmethod
    def _external_ips(ips, *, cap: int = 200) -> list[str]:
        """Distinct routable (non-RFC1918 / loopback / link-local) IPv4s."""
        out: set[str] = set()
        for ip in ips:
            ip = (ip or "").strip()
            if not ip or ":" in ip:
                continue
            parts = ip.split(".")
            if len(parts) != 4 or not all(p.isdigit() for p in parts):
                continue
            a, b = int(parts[0]), int(parts[1])
            if (a == 10 or a == 127 or (a == 192 and b == 168)
                    or (a == 172 and 16 <= b <= 31) or (a == 169 and b == 254)
                    or a == 0 or a >= 224):
                continue
            out.add(ip)
            if len(out) >= cap:
                break
        return sorted(out)

    def _populate_graph(self, ctx: AgentContext, signals: list) -> None:
        """Write per-host attack-stage signals into the Kùzu graph as
        Host + Event(channel=stage) nodes (OBSERVED_ON), plus external
        attacker IPs (SOURCE_IP). The Correlator then ties the multi-host
        chain together. Best-effort: graph failures never break the agent."""
        if not signals:
            return
        from el.evidence.graph import open_graph
        try:
            db, conn = open_graph(ctx.case_dir)
        except Exception:
            return

        def esc(s: str) -> str:
            return (s or "").replace("'", "''").replace("\\", "\\\\")

        for sig in signals:
            host = sig.get("host", "")
            stage = sig.get("stage", "")
            if not host or not stage:
                continue
            try:
                conn.execute(
                    f"MERGE (h:Host {{name: '{esc(host)}'}})")
                eid = f"{host}:log_corpus:{stage}"[:180]
                conn.execute(
                    f"MERGE (e:Event {{event_id: '{esc(eid)}'}}) "
                    f"SET e.source='log_corpus', e.channel='{esc(stage)}', "
                    f"e.eid=0, e.host='{esc(host)}'")
                conn.execute(
                    f"MATCH (e:Event {{event_id: '{esc(eid)}'}}), "
                    f"      (h:Host {{name: '{esc(host)}'}}) "
                    f"MERGE (e)-[:OBSERVED_ON]->(h)")
                for ip in sig.get("ips", []):
                    conn.execute(
                        f"MERGE (:IPAddress {{addr: '{esc(ip)}', version: 4}})")
                    conn.execute(
                        f"MATCH (e:Event {{event_id: '{esc(eid)}'}}), "
                        f"      (i:IPAddress {{addr: '{esc(ip)}'}}) "
                        f"MERGE (e)-[:SOURCE_IP]->(i)")
            except Exception:
                continue

    def _route_file(self, ctx: AgentContext, f: Path, host: str,
                    outdir: Path, signals: list):
        """Dispatch one file to its parser. Returns (list[Finding], count):
        an H_DISK_ARTIFACTS inventory finding, plus any targeted threat
        findings whose high-signal counts cross a conservative threshold."""
        name = f.name.lower()
        head = _head(f)

        # Windows Event XML export
        if f.suffix.lower() == ".xml" and (
                b"<Events" in head or b"win/2004/08/events" in head
                or name.startswith("windows_event")):
            from el.skills import evtx_xml as ex
            try:
                r = ex.parse(f, output_dir=outdir / "evtx")
            except ex.EvtxXmlError:
                return [], 0
            fail = len(r.with_id("4625"))
            fins = [Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"[{host}] Windows Event XML ({f.name}): {r.total:,} "
                       f"event(s); {len(r.logons())} logon, {fail} failed-logon "
                       f"(4625), {len(r.process_creations())} process event(s)."),
                evidence=[r.as_evidence()],
                hypotheses_supported=["H_DISK_ARTIFACTS"])]
            if fail >= _FAILED_LOGON_MIN:
                fins.append(self._signal(
                    ctx, host,
                    f"{fail} failed logons (Event 4625) on {host} — "
                    f"failed-authentication burst consistent with brute-force "
                    f"/ password-spray.",
                    ["H_BRUTE_FORCE"],
                    r.as_evidence(facts={"failed_logon_4625": fail})))
                signals.append({"host": host, "stage": "brute_force",
                                "ips": self._external_ips(
                                    e.data.get("IpAddress", "")
                                    for e in r.with_id("4625"))})
            return fins, r.total

        # eCAR EDR telemetry
        if name.endswith(".json") and b'"object"' in head and b'"action"' in head:
            from el.skills import ecar
            try:
                r = ecar.parse(f, output_dir=outdir / "ecar")
            except ecar.ECARError:
                return [], 0
            inj = r.remote_thread_creations()
            fins = [Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"[{host}] eCAR EDR: {r.total:,} event(s); "
                       f"{len(r.processes())} process-create, "
                       f"{len(r.network_flows())} net-flow, {len(inj)} "
                       f"remote-thread injection(s)."),
                evidence=[r.as_evidence()],
                hypotheses_supported=["H_DISK_ARTIFACTS"])]
            if inj:
                tgt = sorted({str(e.target_pid) for e in inj if e.target_pid})
                fins.append(self._signal(
                    ctx, host,
                    f"{len(inj)} cross-process remote-thread creation(s) on "
                    f"{host} (target pid(s): {', '.join(tgt) or '?'}) — "
                    f"high-fidelity process-injection telemetry.",
                    ["H_PROCESS_INJECTION"],
                    r.as_evidence(facts={"remote_thread_creations": len(inj)})))
                signals.append({"host": host, "stage": "process_injection",
                                "ips": []})
            return fins, r.total

        # Cisco ASA syslog
        if name.endswith(".log") and (b"%ASA-" in head or "asa" in name):
            from el.skills import cisco_asa
            try:
                r = cisco_asa.parse(f, output_dir=outdir / "asa")
            except cisco_asa.CiscoASAError:
                return [], 0
            if not r.total:
                return [], 0
            fins = [Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"[{host}] Cisco ASA: {r.total:,} event(s); "
                       f"{len(r.connections())} connection(s), "
                       f"{len(r.denies())} ACL deny(ies)."),
                evidence=[r.as_evidence()],
                hypotheses_supported=["H_DISK_ARTIFACTS"])]
            if len(r.denies()) >= _ASA_DENY_MIN:
                fins.append(self._signal(
                    ctx, host,
                    f"{len(r.denies())} ASA ACL denies — sustained blocked "
                    f"inbound probing consistent with scanning / recon.",
                    ["H_SCAN_RECON"],
                    r.as_evidence(facts={"acl_denies": len(r.denies())})))
                signals.append({"host": host, "stage": "scan_recon",
                                "ips": self._external_ips(
                                    e.src_ip for e in r.denies())})
            return fins, r.total

        # Snort / ET fast-alert
        if name.endswith(".log") and (b"[**]" in head or "snort" in name):
            from el.skills import snort_alert as sn
            try:
                r = sn.parse(f, output_dir=outdir / "snort")
            except sn.SnortAlertError:
                return [], 0
            if not r.total:
                return [], 0
            fins = [Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"[{host}] Snort IDS: {r.total:,} alert(s); "
                       f"{len(r.high_priority())} priority-1; "
                       f"top: {[s for s, _ in r.top_signatures(3)]}."),
                evidence=[r.as_evidence()],
                hypotheses_supported=["H_DISK_ARTIFACTS"])]
            recon = [a for a in r.alerts
                     if "recon" in a.classification.lower()
                     or "scan" in a.classification.lower()
                     or "scan" in a.msg.lower()]
            if recon:
                fins.append(self._signal(
                    ctx, host,
                    f"{len(recon)} Snort recon/scan alert(s) (e.g. "
                    f"{recon[0].msg!r}) — network scanning / reconnaissance.",
                    ["H_SCAN_RECON"],
                    r.as_evidence(facts={"recon_alerts": len(recon)})))
                signals.append({"host": host, "stage": "scan_recon",
                                "ips": self._external_ips(
                                    a.src_ip for a in recon)})
            return fins, r.total

        # Web / proxy access — Apache/nginx Common-Combined OR W3C extended
        # (e.g. a secure-web-gateway proxy log). Sniff the W3C header and
        # route to iis_w3c; otherwise the Combined-Log parser.
        if name.endswith((".log", ".log.gz")) and "access" in name:
            is_w3c = (b"#Fields:" in head or b"#Software:" in head
                      or head.startswith(b"#Version"))
            try:
                if is_w3c:
                    from el.skills import iis_w3c as _wa
                    fmt, tool = "W3C", "el.iis_w3c"
                else:
                    from el.skills import webserver_access as _wa
                    fmt, tool = "Apache/nginx", "el.webserver_access"
                res = _wa.scan_path(f)
            except Exception:
                return [], 0
            sha = hashlib.sha256(str(f).encode()).hexdigest()
            ev = EvidenceItem(
                tool=tool, version="0.1.0", command=f"scan_path({f.name})",
                output_sha256=sha, output_path=str(f),
                extracted_facts={"format": fmt, "parsed_rows": res.parsed_rows,
                                 "hits": len(res.hits)})
            fins = [Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"[{host}] Web/proxy access ({fmt}, {f.name}): "
                       f"{res.parsed_rows:,} request(s) parsed, "
                       f"{len(res.hits)} anomaly hit(s)."),
                evidence=[ev], hypotheses_supported=["H_DISK_ARTIFACTS"])]
            hyp = sorted({h for hit in res.hits
                          for h in (getattr(hit, "hypotheses", []) or [])})
            if hyp:
                desc = getattr(res.hits[0], "description", "")
                fins.append(self._signal(
                    ctx, host,
                    f"{len(res.hits)} web/proxy-access anomaly hit(s) in "
                    f"{f.name} (e.g. {desc[:80]}).",
                    hyp, ev))
                stage = ("web_shell" if any("WEB_SHELL" in h for h in hyp)
                         else "scan_recon")
                signals.append({"host": host, "stage": stage, "ips": []})
            return fins, res.parsed_rows

        # RFC5424 syslog
        if name.endswith(".log") and (b">1 " in head[:64] or name == "syslog.log"):
            from el.skills import syslog_rfc5424 as sl
            try:
                r = sl.parse(f, output_dir=outdir / "syslog")
            except sl.SyslogError:
                return [], 0
            if not r.total:
                return [], 0
            return [Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"[{host}] syslog ({f.name}): {r.total:,} event(s) "
                       f"from {len(r.by_app())} app(s); "
                       f"{len(r.high_severity())} at severity<=err."),
                evidence=[r.as_evidence()],
                hypotheses_supported=["H_DISK_ARTIFACTS"])], r.total

        return [], 0
