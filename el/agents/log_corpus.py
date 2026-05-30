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

        for host in host_dirs:
            host_out, n_src, n_evt = self._run_host(ctx, host, analysis)
            out.extend(host_out)
            if n_src:
                hosts_seen.add(host.name)
                sources += n_src
                total_events += n_evt

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
                  analysis: Path) -> tuple[list[Finding], int, int]:
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
            fin, n = self._route_file(ctx, f, host.name, outdir)
            if fin is not None:
                out.append(self.emit(ctx, fin))
                sources += 1
                events += n
        return out, sources, events

    def _route_file(self, ctx: AgentContext, f: Path, host: str,
                    outdir: Path):
        """Dispatch one file to its parser; return (Finding|None, record_count)."""
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
                return None, 0
            fail = len(r.with_id("4625"))
            return Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"[{host}] Windows Event XML ({f.name}): {r.total:,} "
                       f"event(s); {len(r.logons())} logon, {fail} failed-logon "
                       f"(4625), {len(r.process_creations())} process event(s)."),
                evidence=[r.as_evidence()],
                hypotheses_supported=["H_DISK_ARTIFACTS"]), r.total

        # eCAR EDR telemetry
        if name.endswith(".json") and b'"object"' in head and b'"action"' in head:
            from el.skills import ecar
            try:
                r = ecar.parse(f, output_dir=outdir / "ecar")
            except ecar.ECARError:
                return None, 0
            inj = len(r.remote_thread_creations())
            return Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"[{host}] eCAR EDR: {r.total:,} event(s); "
                       f"{len(r.processes())} process-create, "
                       f"{len(r.network_flows())} net-flow, {inj} remote-thread "
                       f"injection(s)."),
                evidence=[r.as_evidence()],
                hypotheses_supported=["H_DISK_ARTIFACTS"]), r.total

        # Cisco ASA syslog
        if name.endswith(".log") and (b"%ASA-" in head or "asa" in name):
            from el.skills import cisco_asa
            try:
                r = cisco_asa.parse(f, output_dir=outdir / "asa")
            except cisco_asa.CiscoASAError:
                return None, 0
            if r.total:
                return Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="medium",
                    claim=(f"[{host}] Cisco ASA: {r.total:,} event(s); "
                           f"{len(r.connections())} connection(s), "
                           f"{len(r.denies())} ACL deny(ies)."),
                    evidence=[r.as_evidence()],
                    hypotheses_supported=["H_DISK_ARTIFACTS"]), r.total

        # Snort / ET fast-alert
        if name.endswith(".log") and (b"[**]" in head or "snort" in name):
            from el.skills import snort_alert as sn
            try:
                r = sn.parse(f, output_dir=outdir / "snort")
            except sn.SnortAlertError:
                return None, 0
            if r.total:
                return Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="medium",
                    claim=(f"[{host}] Snort IDS: {r.total:,} alert(s); "
                           f"{len(r.high_priority())} priority-1; "
                           f"top: {[s for s, _ in r.top_signatures(3)]}."),
                    evidence=[r.as_evidence()],
                    hypotheses_supported=["H_DISK_ARTIFACTS"]), r.total

        # Web access (Apache/nginx/proxy)
        if name.endswith((".log", ".log.gz")) and "access" in name:
            from el.skills import webserver_access as wa
            try:
                res = wa.scan_path(f)
            except Exception:
                return None, 0
            sha = hashlib.sha256(str(f).encode()).hexdigest()
            return Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"[{host}] Web access ({f.name}): {res.parsed_rows:,} "
                       f"request(s) parsed, {len(res.hits)} anomaly hit(s)."),
                evidence=[EvidenceItem(
                    tool="el.webserver_access", version="0.1.0",
                    command=f"scan_path({f.name})", output_sha256=sha,
                    output_path=str(f),
                    extracted_facts={"parsed_rows": res.parsed_rows,
                                     "hits": len(res.hits)})],
                hypotheses_supported=["H_DISK_ARTIFACTS"]), res.parsed_rows

        # RFC5424 syslog
        if name.endswith(".log") and (b">1 " in head[:64] or name == "syslog.log"):
            from el.skills import syslog_rfc5424 as sl
            try:
                r = sl.parse(f, output_dir=outdir / "syslog")
            except sl.SyslogError:
                return None, 0
            if r.total:
                return Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="medium",
                    claim=(f"[{host}] syslog ({f.name}): {r.total:,} event(s) "
                           f"from {len(r.by_app())} app(s); "
                           f"{len(r.high_severity())} at severity<=err."),
                    evidence=[r.as_evidence()],
                    hypotheses_supported=["H_DISK_ARTIFACTS"]), r.total

        return None, 0
