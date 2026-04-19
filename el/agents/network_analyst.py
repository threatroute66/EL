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

        # x509 cert subjects + JA3 fingerprints can flag malware-family C2
        # by known-bad fingerprints in the future. For now just surface
        # the count.
        ja3 = r.notable.get("ja3") or []
        if ja3:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"Zeek captured {len(ja3)} unique JA3 client fingerprint(s) "
                      "(blocklist-comparable)",
                evidence=[r.as_evidence()],
            )))

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
