"""Network Analyst — pcap triage via scapy.

Pure Python; no system tools required. Populates the case graph with
NetworkFlow / IPAddress / Domain nodes so cross-agent correlation works.
"""
from __future__ import annotations

import hashlib

from el.agents.base import Agent, AgentContext
from el.evidence.graph import open_graph
from el.schemas.finding import Finding
from el.skills import network_extra as nx, scapy_pcap, zeek as zeek_skill


def _esc(s: str) -> str:
    return s.replace("'", "''")


class NetworkAnalystAgent(Agent):
    name = "network_analyst"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        kind = ctx.shared.get("evidence_kind") or ""
        # Suricata EVE JSON — standalone (operator brings the eve log
        # without the source pcap). Single parser pass + per-cluster
        # findings; no pcap-replay path needed.
        if kind == "suricata-eve":
            return self._handle_eve_json(ctx, analysis)
        if "pcap" not in kind:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Network agent does not apply: evidence_kind='{kind}'",
            ))]

        try:
            s = scapy_pcap.summarize(ctx.input_path, analysis)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"pcap parse failed: {e}",
            ))]

        ev = s.as_evidence()
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"Parsed {s.packet_count} packets across {len(s.flows)} unique flows; "
                  f"{len(set(s.dns_queries))} DNS query name(s), "
                  f"{len(set(s.http_hosts))} HTTP Host header(s), "
                  f"{len(set(s.tls_sni))} TLS SNI(s)",
            evidence=[ev], hypotheses_supported=["H_NETWORK_TRAFFIC_OBSERVED"],
        )))

        if s.suspicious_dports:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=f"Connections observed to suspicious destination ports: "
                      f"{dict(s.suspicious_dports)}",
                evidence=[ev], hypotheses_supported=["H_C2_OR_REVERSE_SHELL"],
            )))

        try:
            db, conn = open_graph(ctx.case_dir)
            for ip in {f[0] for f in s.flows} | {f[1] for f in s.flows}:
                conn.execute(f"MERGE (:IPAddress {{addr: '{_esc(ip)}', version: {6 if ':' in ip else 4}}})")
            for q in set(s.dns_queries):
                conn.execute(f"MERGE (:Domain {{name: '{_esc(q.lower())}'}})")
            for sni in set(s.tls_sni):
                conn.execute(f"MERGE (:Domain {{name: '{_esc(sni.lower())}'}})")
            for (src, dst, sport, dport, proto), packets in s.flows.items():
                fid = hashlib.sha256(f"{src}|{dst}|{sport}|{dport}|{proto}".encode()).hexdigest()[:16]
                conn.execute(
                    f"MERGE (f:NetworkFlow {{flow_id: '{fid}'}}) "
                    f"SET f.src='{_esc(src)}', f.dst='{_esc(dst)}', "
                    f"f.sport={sport}, f.dport={dport}, f.proto='{proto}', f.bytes={packets}"
                )
                conn.execute(f"MATCH (f:NetworkFlow {{flow_id:'{fid}'}}), (i:IPAddress {{addr:'{_esc(src)}'}}) MERGE (f)-[:FLOW_SRC]->(i)")
                conn.execute(f"MATCH (f:NetworkFlow {{flow_id:'{fid}'}}), (i:IPAddress {{addr:'{_esc(dst)}'}}) MERGE (f)-[:FLOW_DST]->(i)")
        except Exception as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"Graph population partially failed: {e}", evidence=[ev],
            )))

        # Suricata IDS: replay the pcap with the system ruleset and surface
        # named alerts. Falls back silently if Suricata isn't installed.
        out.extend(self._run_suricata(ctx, analysis))
        # Zeek: behavioural per-protocol logs (conn/http/dns/ssl/x509/notice).
        # Cross-checks scapy_pcap's protocol parse and surfaces things scapy
        # misses (full HTTP URI, x509 cert chains, weird/notice records).
        out.extend(self._run_zeek(ctx, analysis))
        # tshark: deeper HTTP+TLS extraction (full URIs, cert subjects).
        out.extend(self._run_tshark(ctx, analysis))
        # JA4+ family fingerprinting (FoxIO). Supplements JA3 — JA3 was
        # deprecated by FoxIO in 2024 but many TI feeds still index by it,
        # so both run side-by-side during the migration window.
        out.extend(self._run_ja4(ctx, analysis))
        # Statistical beaconing detection over Zeek conn.log
        # (RITA-algorithm implementation; strengthens H_C2_BEACONING).
        out.extend(self._run_beaconing(ctx, analysis))
        return out

    def _handle_eve_json(self, ctx: AgentContext,
                          analysis: Path) -> list[Finding]:
        """Parse a standalone Suricata `eve.json` and emit findings.
        Same logic the pcap path uses for its post-suricata processing,
        but here the operator skipped pcap and brought the eve log
        directly. The skill caps at 200k events; truncation is
        recorded but not failure."""
        from el.skills import suricata_eve as se
        out: list[Finding] = []
        try:
            summary = se.parse_eve_json(ctx.input_path, analysis)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"Suricata EVE parse failed: {e}",
            ))]
        ev = summary.as_evidence()
        # Top-level summary finding
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Suricata EVE parsed: {summary.total_events:,} event(s); "
                   f"{summary.alert_count} alert(s) across "
                   f"{summary.unique_signatures} unique signature(s); "
                   f"types={summary.by_event_type}"),
            evidence=[ev],
            hypotheses_supported=["H_NETWORK_TRAFFIC_OBSERVED"],
        )))
        # Per-cluster alert findings (top 10 by count). Severity 1 = high
        # in Suricata's convention; 2 = medium; 3+ = low. Cluster severity
        # maps directly to finding confidence.
        sev_to_conf = {1: "high", 2: "medium", 3: "low"}
        for c in summary.alert_clusters[:10]:
            conf = sev_to_conf.get(c.severity, "low")
            dst_clause = (", → ".join(c.dest_ips[:3])
                          if c.dest_ips else "(no dst)")
            port_clause = (f" ports={c.dest_ports[:5]}"
                           if c.dest_ports else "")
            techniques_clause = (f" ATT&CK={','.join(c.attack_techniques)}"
                                 if c.attack_techniques else "")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=conf,
                claim=(f"Suricata alert cluster: SID {c.signature_id} "
                       f"`{c.signature[:120]}` × {c.count} hit(s) — "
                       f"{c.first_seen[:19]} → {c.last_seen[:19]}, "
                       f"dst {dst_clause}{port_clause}{techniques_clause}"),
                evidence=[ev],
                hypotheses_supported=["H_NETWORK_TRAFFIC_OBSERVED"],
            )))
        # Extracted files (fileinfo events with sha256) — high-value
        # IOCs. Each one gets its own finding so the cross-case
        # knowledge store + malware-triage tier can pivot on them.
        for f in summary.fileinfo[:20]:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Suricata extracted file: "
                       f"sha256={f['sha256'][:16]}…, "
                       f"name={f.get('filename', '?')!r}, "
                       f"magic={f.get('magic', '?')!r}, "
                       f"src={f.get('src_ip')} → dst={f.get('dest_ip')}"),
                evidence=[ev],
                hypotheses_supported=["H_IOC_CORROBORATED"],
            )))
        # Anomaly events (protocol-decode weirdness) — under-rated
        # signal that doesn't depend on rule coverage.
        if summary.anomaly_types:
            top_anom = sorted(summary.anomaly_types.items(),
                               key=lambda kv: -kv[1])[:5]
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=(f"Suricata decode anomalies: "
                       + "; ".join(f"{n}={k}" for n, k in top_anom)),
                evidence=[ev],
            )))
        if summary.truncated:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("Suricata EVE parse stopped at the 200k-event cap "
                       "— summary reflects partial data. Re-invoke "
                       "`suricata_eve.parse_eve_json` with a higher "
                       "max_events for full coverage."),
            )))
        return out

    def _run_beaconing(self, ctx: AgentContext, analysis) -> list[Finding]:
        """Score Zeek's conn.log for beacon-shaped traffic patterns."""
        from el.skills import network_beaconing as bcn
        out: list[Finding] = []
        zeek_dir = analysis / "zeek"
        if not zeek_dir.is_dir():
            return out  # zeek didn't run — nothing to score

        # Find conn.log (Zeek emits conn.log in the case-runtime dir).
        candidates: list[Path] = []
        for name in ("conn.log", "conn.log.gz"):
            candidates.extend(p for p in zeek_dir.rglob(name) if p.is_file())
        if not candidates:
            return out

        for conn_log in candidates[:3]:  # cap; one is the norm
            try:
                result = bcn.score_conn_log(conn_log)
            except (bcn.BeaconingError, OSError, TypeError, ValueError) as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=f"Beaconing scan skipped for {conn_log.name}: {e}",
                )))
                continue

            ev = result.as_evidence()
            if not result.hits:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="low",
                    claim=(f"Beaconing scan: {result.candidate_pairs} "
                           f"flow-pair(s) had >=10 connections; none scored "
                           f"≥{result.threshold} (no statistical beacon "
                           f"shape detected). Algorithmic check from "
                           f"{conn_log.name}."),
                    evidence=[ev],
                )))
                continue

            # Headline finding for the top-scoring beacon.
            top = result.hits[0]
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Statistical beaconing: {len(result.hits)} flow-pair(s) "
                       f"score ≥{result.threshold}. Top: "
                       f"{top.src} → {top.dst}:{top.dport}/{top.proto} "
                       f"score={top.score:.3f} "
                       f"({top.connection_count} conns over "
                       f"{top.duration_seconds:.0f}s, mean interval "
                       f"{top.mean_interval_seconds:.1f}s ± "
                       f"{top.interval_stdev_seconds:.1f}s)"),
                evidence=[ev],
                hypotheses_supported=["H_C2_BEACONING"],
                hypotheses_refuted=["H_BENIGN_NO_INCIDENT"],
            )))

            # Per-hit findings for the next 4 (cap), so each ranks individually
            # in the report rather than only the top one.
            for hit in result.hits[1:5]:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="medium",
                    claim=(f"Beaconing candidate: {hit.src} → {hit.dst}:"
                           f"{hit.dport}/{hit.proto} score={hit.score:.3f} "
                           f"({hit.connection_count} conns, mean interval "
                           f"{hit.mean_interval_seconds:.1f}s)"),
                    evidence=[ev],
                    hypotheses_supported=["H_C2_BEACONING"],
                )))
        return out

    def _run_ja4(self, ctx: AgentContext, analysis) -> list[Finding]:
        """FoxIO JA4+ family fingerprinting on the pcap."""
        from el.skills import ja4 as ja4_skill
        out: list[Finding] = []
        ja4_dir = analysis / "ja4"
        ja4_dir.mkdir(parents=True, exist_ok=True)
        try:
            r = ja4_skill.scan_pcap(ctx.input_path, ja4_dir)
        except (ja4_skill.JA4Error, OSError, TypeError, ValueError) as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"JA4 fingerprinting skipped: {e}",
            )))
            return out

        ev = r.as_evidence()
        if r.flow_count == 0:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=("JA4: extraction completed with 0 flows — pcap may "
                       "lack TLS/HTTP/SSH or tshark version is older than "
                       "4.0.6 (the JA4 minimum)"),
                evidence=[ev],
            )))
            return out

        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"JA4 family fingerprints extracted: {r.flow_count} "
                   f"flow(s) — {len(r.distinct_ja4)} JA4, "
                   f"{len(r.distinct_ja4s)} JA4S, "
                   f"{len(r.distinct_ja4h)} JA4H, "
                   f"{len(r.distinct_ja4x)} JA4X, "
                   f"{len(r.distinct_ja4ssh)} JA4SSH"),
            evidence=[ev],
        )))

        # Curated bad-JA4 lookup. Mirror of the JA3 reputation flow but on
        # the FoxIO-canonical fingerprint format. Empty table by default;
        # populated only when an operator stages JA4 IOC entries.
        bad_hits: list[tuple[str, str, str]] = []
        for fp in r.all_distinct_fingerprints():
            match = ja4_skill.lookup_ja4(fp)
            if match:
                family, source = match
                bad_hits.append((fp, family, source))

        for fp, family, source in bad_hits:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"JA4 fingerprint {fp} matches known-bad family "
                       f"'{family}' (source: {source})"),
                evidence=[ev],
                hypotheses_supported=["H_C2_BEACONING", "H_APT_ESPIONAGE"],
            )))

        return out

    def _run_suricata(self, ctx: AgentContext, analysis) -> list[Finding]:
        out: list[Finding] = []
        try:
            r = nx.replay_pcap(ctx.input_path, analysis / "suricata", timeout=1800)
        except nx.SuricataError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Suricata unavailable or failed: {e}",
            )))
            return out
        if r.alert_count == 0:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim="Suricata replay: 0 alerts — neither corroborates nor refutes "
                      "(rules may not cover the traffic, or capture has no malicious flows)",
                evidence=[r.as_evidence()],
            )))
            return out
        # Pick out malware-family signatures and classify
        tags: list[str] = []
        for sig, _ in r.sig_hits.items():
            sl = sig.lower()
            if any(fam in sl for fam in ("trojan", "trickbot", "qakbot", "emotet",
                                          "hancitor", "icedid", "bazarloader",
                                          "remcos", "njrat", "ransomware",
                                          "cobalt strike", "meterpreter", "metasploit")):
                tags.append("H_C2_OR_REVERSE_SHELL")
                tags.append("H_OPPORTUNISTIC_COMMODITY")
            if "exploit" in sl or "et exploit" in sl:
                tags.append("H_C2_OR_REVERSE_SHELL")
            if "scan" in sl or "policy" in sl:
                pass  # don't lift on policy / scan noise
        tags = sorted(set(tags))
        top = ", ".join(s for s, _ in
                        sorted(r.sig_hits.items(), key=lambda kv: -kv[1])[:3])
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Suricata IDS: {r.alert_count} alert(s) across "
                   f"{len(r.sig_hits)} unique signature(s). Top: {top}"),
            evidence=[r.as_evidence()],
            hypotheses_supported=tags,
        )))
        # Hand the freshly-written eve.json to the standalone EVE
        # parser to surface per-cluster + fileinfo + anomaly findings
        # the rc-summary above doesn't expose. Defensive — any failure
        # here must not block the existing pcap path.
        if r.eve_path.is_file():
            try:
                from el.skills import suricata_eve as se
                eve_summary = se.parse_eve_json(r.eve_path, analysis)
                ev = eve_summary.as_evidence({"source": "pcap_replay"})
                sev_to_conf = {1: "high", 2: "medium", 3: "low"}
                for c in eve_summary.alert_clusters[:10]:
                    conf = sev_to_conf.get(c.severity, "low")
                    dst_clause = (", → ".join(c.dest_ips[:3])
                                  if c.dest_ips else "(no dst)")
                    port_clause = (f" ports={c.dest_ports[:5]}"
                                   if c.dest_ports else "")
                    tech = (f" ATT&CK={','.join(c.attack_techniques)}"
                            if c.attack_techniques else "")
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence=conf,
                        claim=(f"Suricata alert cluster: SID "
                               f"{c.signature_id} `{c.signature[:120]}` "
                               f"× {c.count} hit(s) — "
                               f"{c.first_seen[:19]} → "
                               f"{c.last_seen[:19]}, dst {dst_clause}"
                               f"{port_clause}{tech}"),
                        evidence=[ev],
                        hypotheses_supported=tags,
                    )))
                for f in eve_summary.fileinfo[:20]:
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="medium",
                        claim=(f"Suricata extracted file: "
                               f"sha256={f['sha256'][:16]}…, "
                               f"name={f.get('filename', '?')!r}, "
                               f"magic={f.get('magic', '?')!r}, "
                               f"src={f.get('src_ip')} → "
                               f"dst={f.get('dest_ip')}"),
                        evidence=[ev],
                        hypotheses_supported=["H_IOC_CORROBORATED"],
                    )))
                if eve_summary.anomaly_types:
                    top_anom = sorted(eve_summary.anomaly_types.items(),
                                       key=lambda kv: -kv[1])[:5]
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="low",
                        claim=("Suricata decode anomalies: "
                               + "; ".join(f"{n}={k}"
                                            for n, k in top_anom)),
                        evidence=[ev],
                    )))
            except Exception as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="low",
                    claim=(f"Suricata EVE post-parse skipped: {e}. "
                           "Per-cluster + fileinfo findings unavailable; "
                           "the rc-count summary above still stands."),
                )))
        return out

    # ----- Zeek -----

    _ZEEK_C2_FAMILIES = (
        "trickbot", "qakbot", "emotet", "hancitor", "icedid",
        "bazarloader", "remcos", "njrat", "agent tesla", "agent_tesla",
        "cobaltstrike", "cobalt strike", "meterpreter", "metasploit",
        "sliver", "empire",
    )

    def _run_zeek(self, ctx: AgentContext, analysis) -> list[Finding]:
        out: list[Finding] = []
        try:
            r = zeek_skill.replay_pcap(ctx.input_path, analysis / "zeek",
                                        timeout=1800)
        except zeek_skill.ZeekError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Zeek unavailable or failed: {e}",
            )))
            return out

        rows = r.summary or {}
        if not rows:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim="Zeek produced no logs — pcap may be empty or unreadable",
                evidence=[r.as_evidence()],
            )))
            return out

        breakdown = ", ".join(f"{k}={v}" for k, v in
                               sorted(rows.items(), key=lambda kv: -kv[1])[:8] if v)
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"Zeek replay: {len(rows)} log type(s) emitted. {breakdown}",
            evidence=[r.as_evidence()],
            hypotheses_supported=["H_NETWORK_TRAFFIC_OBSERVED"],
        )))

        # Notice.log captures Zeek's behavioural anomaly notes (scan,
        # SSL::Invalid_Server_Cert, Weird::*). Surface them as a separate
        # finding so the rule-challenger can scrutinise them.
        notices = r.notable.get("notices") or []
        if notices:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=f"Zeek notices: {', '.join(notices[:5])}"
                      f"{' …' if len(notices) > 5 else ''}",
                evidence=[r.as_evidence()],
            )))

        # JA3 fingerprints: reputation-check each hash against the
        # curated known-bad / benign-common tables, then layer
        # cross-case rarity on top. One finding per KNOWN-BAD match
        # at high confidence; one rollup finding summarising the rest.
        ja3 = r.notable.get("ja3") or []
        if ja3:
            out.extend(self._triage_ja3_hashes(ctx, r, ja3))

        # Family-name heuristic across HTTP user-agents + cert subjects +
        # DNS queries. If a known C2 family name leaks into any of these,
        # corroborates suricata + scapy heuristics.
        haystack = " ".join((r.notable.get("http_user_agents") or []) +
                            (r.notable.get("cert_subjects") or []) +
                            (r.notable.get("dns_queries") or [])).lower()
        for fam in self._ZEEK_C2_FAMILIES:
            if fam in haystack:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim=f"Zeek surfaced known C2-family marker '{fam}' in "
                          "HTTP UA / TLS cert subject / DNS query",
                    evidence=[r.as_evidence()],
                    hypotheses_supported=["H_C2_OR_REVERSE_SHELL",
                                           "H_OPPORTUNISTIC_COMMODITY"],
                )))
                break

        # PR-L: network traffic anomaly detectors over Zeek http.log +
        # dns.log. Each detector computes one poster-shaped anomaly
        # (HTTP POST skew, error-rate, scripted UA, DNS short TTL,
        # DNS domain skew) and returns hit summaries we promote to
        # Findings with their own hypothesis lift.
        out.extend(self._run_network_anomaly(ctx, analysis / "zeek",
                                              r.as_evidence()))

        # Kerberos wire-level detectors over Zeek kerberos.log. Mirror
        # of the EVTX-based credential_analyst (PR-E) at the network
        # layer — fires even when Windows auditing is disabled or
        # cleared. One Finding per hit; hypotheses route into
        # H_CREDENTIAL_ACCESS / H_BRUTE_FORCE.
        out.extend(self._run_kerberos_triage(ctx, analysis / "zeek",
                                              r.as_evidence()))

        # PR-M: surface the specific Zeek log classes the SANS poster
        # calls out — weird (protocol anomalies), signatures (Zeek's
        # own sig hits), software (UA/Server/MIME fingerprints), known_
        # services + file SHA256s. Each gets its own Finding so the
        # analyst can pivot without re-opening the raw logs.
        weird_names = r.notable.get("weird_names") or []
        # Zeek fires 'above_hole_data_without_any_acks', 'inappropriate_FIN'
        # and similar on every noisy capture. Require ≥10 distinct names
        # (not just rows) before surfacing as a dedicated finding.
        if len(weird_names) >= 10:
            sample = ", ".join(weird_names[:5])
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Zeek weird.log: {len(weird_names)} distinct "
                       f"protocol-violation name(s). Samples: {sample}"
                       f"{' …' if len(weird_names) > 5 else ''}. "
                       f"Protocol anomalies frequently accompany evasion "
                       f"(malformed HTTP headers, TLS fragmentation, "
                       f"unknown command codes)."),
                evidence=[r.as_evidence()],
                hypotheses_supported=["H_C2_OR_REVERSE_SHELL"],
            )))
        sig_ids = r.notable.get("signature_ids") or []
        if sig_ids:
            sample = ", ".join(sig_ids[:5])
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Zeek signatures.log matched {len(sig_ids)} "
                       f"signature(s). Samples: {sample}"
                       f"{' …' if len(sig_ids) > 5 else ''}. "
                       f"Zeek's native signature engine fired — verify "
                       f"the rule IDs against the loaded signature set."),
                evidence=[r.as_evidence()],
                hypotheses_supported=["H_C2_OR_REVERSE_SHELL",
                                       "H_OPPORTUNISTIC_COMMODITY"],
            )))
        software_names = r.notable.get("software_names") or []
        if software_names:
            # Informational — helps the analyst know what's on the wire
            sample = ", ".join(software_names[:8])
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=(f"Zeek software.log identified "
                       f"{len(software_names)} unique software "
                       f"fingerprint(s) on the wire. Samples: {sample}"
                       f"{' …' if len(software_names) > 8 else ''}."),
                evidence=[r.as_evidence()],
            )))
        file_sha = r.notable.get("file_sha256") or []
        if file_sha:
            # Raise a low-confidence finding so the hashes land in the
            # IOC catalog; cross-case knowledge lookup might connect
            # them to prior cases.
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=(f"Zeek files.log captured {len(file_sha)} "
                       f"unique SHA-256 file hash(es) from the wire. "
                       f"These are pivot points for cross-case lookup."),
                evidence=[r.as_evidence()],
            )))
        return out

    def _triage_ja3_hashes(self, ctx: AgentContext, zeek_run,
                            ja3_hashes: list[str]) -> list[Finding]:
        """Classify every Zeek-captured JA3 hash against the curated
        known-bad / benign-common tables; layer cross-case rarity via
        the knowledge store. Emits:

        - one HIGH-confidence finding per known-bad match (tagged
          H_C2_BEACONING with the attribution source)
        - one LOW-confidence rollup counting everything else, with a
          rarity breakdown (novel / common) drawn from the knowledge DB
        """
        from el.skills import ja3_reputation
        from el import knowledge as kb

        out: list[Finding] = []
        unique = sorted({h.lower().strip()
                         for h in ja3_hashes
                         if isinstance(h, str) and h.strip()})
        if not unique:
            return out

        known_bad: list[tuple[str, ja3_reputation.JA3Reputation]] = []
        benign: list[str] = []
        unknown: list[str] = []
        for h in unique:
            rep = ja3_reputation.classify(h)
            if rep.classification == "known_bad":
                known_bad.append((h, rep))
            elif rep.classification == "benign_common":
                benign.append(h)
            else:
                unknown.append(h)

        # Cross-case rarity for the unknowns — a JA3 seen in ≥3 prior
        # cases is probably a local stable client; a JA3 seen in 0 is
        # novel to this corpus. Surfaced in the rollup claim.
        novel_count = 0
        repeat_count = 0
        try:
            prior = kb.lookup_iocs(unknown, current_case_id=ctx.case_id) \
                if unknown else {}
        except Exception:
            prior = {}
        for h in unknown:
            observations = prior.get(h, [])
            distinct_cases = len({o["case_id"] for o in observations})
            if distinct_cases >= 3:
                repeat_count += 1
            else:
                novel_count += 1

        # Record the JA3s we just saw so future cases see this one in
        # the cross-case overlap.
        try:
            kb.record_iocs(ctx.case_id, self.name, {"ja3": set(unique)})
        except Exception:
            pass

        for h, rep in known_bad:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"JA3 fingerprint {h} matches known-bad "
                       f"'{rep.label}' (source: {rep.source}). "
                       "JA3 collisions with legitimate traffic are "
                       "possible — pair with destination IP + pcap "
                       "session review before acting."),
                evidence=[zeek_run.as_evidence({"ja3_hash": h,
                                                 "label": rep.label,
                                                 "source": rep.source})],
                hypotheses_supported=["H_C2_BEACONING", "H_APT_ESPIONAGE"],
            )))

        # Rollup for the rest — low confidence, but surfacing the
        # novel count is the analyst's cue to pivot on those hashes.
        unlabeled = len(unknown) + len(benign)
        if unlabeled:
            parts = [f"{unlabeled} unique JA3 client fingerprint(s) "
                     f"with no known-bad match"]
            if novel_count:
                parts.append(f"{novel_count} novel to the cross-case "
                             "knowledge store")
            if repeat_count:
                parts.append(f"{repeat_count} seen in ≥3 prior cases "
                             "(likely stable client)")
            if benign:
                parts.append(f"{len(benign)} match benign-common "
                             "(curl / wget / browser)")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim="; ".join(parts) + ".",
                evidence=[zeek_run.as_evidence({
                    "ja3_unknown_sample": unknown[:10],
                    "novel_count": novel_count,
                    "repeat_count": repeat_count,
                })],
            )))
        return out

    def _run_network_anomaly(self, ctx: AgentContext, zeek_dir,
                              zeek_evidence) -> list[Finding]:
        from el.skills import network_anomaly as na
        out: list[Finding] = []
        try:
            hits = na.run_all(zeek_dir)
        except Exception as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Network-anomaly detector failure: {e}",
            )))
            return out
        for h in hits:
            # confidence from the detector itself is the floor; in some
            # detectors the summary text already carries the reason —
            # we never escalate here, only copy.
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence=h.confidence,
                claim=f"Network anomaly [{h.anomaly_id}]: {h.summary}",
                evidence=[zeek_evidence],
                hypotheses_supported=h.hypotheses,
            )))
        return out

    def _run_kerberos_triage(self, ctx: AgentContext, zeek_dir,
                              zeek_evidence) -> list[Finding]:
        """Wire-layer Kerberos detectors: RC4-HMAC TGS (Kerberoasting),
        AS-REQ failure bursts, krbtgt/ TGS (golden-ticket smell).
        Mirrors `credential_analyst` at the network layer."""
        from pathlib import Path

        from el.skills import kerberos_triage as kt
        out: list[Finding] = []
        log_path = Path(zeek_dir) / "kerberos.log"
        if not log_path.is_file():
            return out
        try:
            hits = kt.run_all(log_path)
        except Exception as e:       # noqa: BLE001
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"Kerberos-triage failure parsing {log_path.name}: {e}",
            )))
            return out
        # Technique → hypothesis tags. Mirror the EVTX credential_analyst
        # map so ACH sees the cross-layer reinforcement.
        tech_to_hyps = {
            "kerberoasting":  ["H_CREDENTIAL_ACCESS", "H_APT_ESPIONAGE"],
            "kerberos_brute": ["H_BRUTE_FORCE", "H_CREDENTIAL_ACCESS"],
            "kerberos_spray": ["H_BRUTE_FORCE", "H_CREDENTIAL_ACCESS"],
            "krbtgt_tgs":     ["H_CREDENTIAL_ACCESS", "H_APT_ESPIONAGE"],
        }
        for h in hits:
            # Kerberoasting + golden-ticket are unambiguous → high;
            # brute / spray follow the same ≥3-entity tiering as the
            # EVTX credential analyst.
            if h.technique in ("kerberoasting", "krbtgt_tgs"):
                confidence = "high"
            elif (len(h.top_targets) >= 3 or len(h.top_sources) >= 3
                  or h.event_count >= 50):
                confidence = "high"
            else:
                confidence = "medium"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"Kerberos wire [{h.technique}/{h.subtechnique}] — "
                       f"{h.description}"),
                evidence=[zeek_evidence],
                hypotheses_supported=tech_to_hyps.get(
                    h.technique, ["H_CREDENTIAL_ACCESS"]),
            )))
        return out

    # ----- tshark -----

    def _run_tshark(self, ctx: AgentContext, analysis) -> list[Finding]:
        out: list[Finding] = []
        try:
            r = nx.extract_http_tls(ctx.input_path, analysis / "tshark",
                                     timeout=600)
        except nx.TsharkError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"tshark unavailable or failed: {e}",
            )))
            return out

        counts = {k: len(v) for k, v in r.fields.items() if v}
        if not counts:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim="tshark extracted no HTTP/TLS fields — pcap may be "
                      "fully encrypted or non-web",
                evidence=[r.as_evidence()],
            )))
            return out

        breakdown = ", ".join(f"{k.split('.')[-1]}={v}"
                               for k, v in sorted(counts.items(),
                                                   key=lambda kv: -kv[1]))
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"tshark HTTP/TLS sweep: {breakdown}",
            evidence=[r.as_evidence()],
            hypotheses_supported=["H_NETWORK_TRAFFIC_OBSERVED"],
        )))

        # Behavioural triage over the hosts + SNIs we just extracted.
        # Shape-agnostic — fires on characteristics that don't depend on
        # a specific malware family's URL regex (PR-E).
        out.extend(self._url_triage(ctx, r, analysis))
        return out

    # ----- behavioural URL triage -----

    def _url_triage(self, ctx: AgentContext, tshark_run, analysis) -> list[Finding]:
        """Apply url_triage detectors to the HTTP hosts + TLS SNIs extracted
        by tshark. Two detectors:
          - suspicious_tld: per-host classification by TLD risk bucket
            (abuse / newgen / ddns / mixed)
          - disposable_subdomain_cluster: parents serving ≥3 high-entropy
            random-looking subdomains (classic EK landing pattern)
        """
        from collections import Counter as _Counter
        from el.skills import url_triage as ut
        out: list[Finding] = []

        hosts = set()
        for key in ("http.host", "tls.handshake.extensions_server_name"):
            for v in tshark_run.fields.get(key, []) or []:
                v = v.strip()
                if v:
                    hosts.add(v)
        if not hosts:
            return out

        # --- Suspicious TLDs ---
        by_cat: dict[str, list[tuple[str, str]]] = {}
        for h in sorted(hosts):
            is_sus, info = ut.suspicious_tld(h)
            if is_sus and info is not None:
                cat, hit = info
                by_cat.setdefault(cat, []).append((h, hit))

        if by_cat:
            # One finding per risk category so ACH scoring isn't dominated
            # by "newgen" when an actual "abuse" or "ddns" is also present.
            for cat in ("abuse", "ddns", "newgen", "mixed"):
                if cat not in by_cat:
                    continue
                entries = by_cat[cat]
                sample = ", ".join(h for h, _ in entries[:5])
                more = f" (+{len(entries)-5} more)" if len(entries) > 5 else ""
                conf, hyps = {
                    "abuse":  ("medium", ["H_C2_OR_REVERSE_SHELL",
                                          "H_OPPORTUNISTIC_COMMODITY"]),
                    "ddns":   ("medium", ["H_C2_OR_REVERSE_SHELL",
                                          "H_OPPORTUNISTIC_COMMODITY"]),
                    "newgen": ("low",    []),
                    "mixed":  ("low",    []),
                }[cat]
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence=conf,
                    claim=(f"Suspicious-TLD traffic ({cat}): "
                           f"{len(entries)} host(s) under risky TLDs/parents. "
                           f"Sample: {sample}{more}. "
                           f"Bucket rationale: {ut.__doc__.splitlines()[8].strip() if cat == 'abuse' else cat}"),
                    evidence=[tshark_run.as_evidence(facts={
                        "tld_category": cat,
                        "host_count": len(entries),
                        "sample_hosts": [h for h, _ in entries[:20]],
                    })],
                    hypotheses_supported=hyps,
                )))

        # --- Disposable-subdomain clusters ---
        clusters = ut.disposable_subdomain_cluster(sorted(hosts))
        if clusters:
            # One finding covering all clusters; the extracted_facts
            # field carries the full parent→hosts mapping for the
            # analyst to pivot on.
            parents = sorted(clusters.keys())
            total_hosts = sum(len(v) for v in clusters.values())
            sample_lines = []
            for p in parents[:3]:
                samples = clusters[p][:3]
                sample_lines.append(f"{p} → {', '.join(samples)}"
                                    + (" …" if len(clusters[p]) > 3 else ""))
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Disposable-subdomain cluster(s): {len(parents)} "
                       f"parent(s) each serving ≥3 high-entropy random "
                       f"subdomains ({total_hosts} total). "
                       f"Classic EK/landing-page evasion pattern. "
                       f"Sample: {' | '.join(sample_lines)}"),
                evidence=[tshark_run.as_evidence(facts={
                    "disposable_clusters": {
                        p: clusters[p][:20] for p in parents
                    },
                    "cluster_count": len(parents),
                    "total_hosts": total_hosts,
                })],
                hypotheses_supported=["H_C2_OR_REVERSE_SHELL",
                                       "H_OPPORTUNISTIC_COMMODITY"],
            )))
        return out
