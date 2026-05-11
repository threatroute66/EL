"""Inbound RDP brute-force agent — chained after MemoryForensicator.

Reads the netscan JSONL the memory forensicator already produced
(``analysis/memory_forensicator/windows_netscan_NetScan.jsonl``)
and emits Findings tagged ``H_BRUTE_FORCE`` for external sources
hitting the host's RDP server. Any cluster with a successful TCP
handshake (ESTABLISHED state) gets a separate "breach" Finding so
the analyst can see the difference between *attempted* and
*authenticated* attack edges at a glance.

This agent is a separate signal from ``lateral_movement_analyst``,
which scores RDP that crosses *internal* hosts (RFC1918 → RFC1918).
The two are deliberately disjoint: lateral movement is the inside
story, this is the outside story.
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import rdp_brute_force as rdp


_NETSCAN_FILE = "windows_netscan_NetScan.jsonl"
_TOP_PRETTY = 5    # max source IPs to include in a single claim line


class RDPBruteForceAnalyst(Agent):
    """Inbound RDP brute-force / external-compromise detector."""

    name = "rdp_brute_force"

    def run(self, ctx: AgentContext) -> list[Finding]:
        if ctx.shared.get("mem_os") != "windows":
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=("RDPBruteForceAnalyst only runs on Windows memory "
                       f"images; current OS family = {ctx.shared.get('mem_os')!r}."),
            ))]

        netscan_path = (
            ctx.case_dir / "analysis" / "memory_forensicator" / _NETSCAN_FILE
        )
        if not netscan_path.is_file():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=("MemoryForensicator did not emit a netscan JSONL "
                       f"at {netscan_path}; nothing to analyse for inbound "
                       "RDP brute-force activity."),
            ))]

        report = rdp.analyze_netscan(netscan_path)

        if not report.external_clusters and not report.other_external:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=(f"No external inbound TCP/{rdp.RDP_PORT} connections "
                       "observed in netscan — RDP server-side activity is "
                       "internal-only or absent."),
                evidence=[report.as_evidence()],
            ))]

        out: list[Finding] = []

        if report.external_clusters:
            pretty = "; ".join(
                f"{c.foreign_ip} ×{c.total_connections} "
                f"(CLOSED={c.closed_count}, SYN_RCVD={c.syn_rcvd_count}, "
                f"ESTABLISHED={c.established_count})"
                for c in report.external_clusters[:_TOP_PRETTY]
            )
            extra = ("" if len(report.external_clusters) <= _TOP_PRETTY
                     else f" (+{len(report.external_clusters) - _TOP_PRETTY} more)")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                # Claim text intentionally includes "brute-force" + "RDP"
                # + "external" so existing keyword scorers treat it as
                # a brute-force lift on top of the explicit tag below.
                claim=(f"Inbound RDP brute-force pattern: "
                       f"{len(report.external_clusters)} external "
                       f"source(s) with ≥{rdp.MIN_CLUSTER_CONNECTIONS} "
                       f"connection(s) each to local TCP/{rdp.RDP_PORT}. "
                       f"{pretty}{extra}"),
                confidence="high", evidence=[report.as_evidence()],
                hypotheses_supported=["H_BRUTE_FORCE"],
            )))

        if report.breach_clusters:
            # Separate Finding so the analyst can see *who got in* without
            # rescanning the brute-force claim text. Tag the same hypothesis
            # plus a confidence bump on the claim.
            pretty = "; ".join(
                f"{c.foreign_ip} (ESTABLISHED ×{c.established_count} "
                f"of {c.total_connections}; first {c.earliest_created_utc}, "
                f"last {c.latest_created_utc})"
                for c in report.breach_clusters[:_TOP_PRETTY]
            )
            extra = ("" if len(report.breach_clusters) <= _TOP_PRETTY
                     else f" (+{len(report.breach_clusters) - _TOP_PRETTY} more)")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                claim=(f"Inbound RDP authenticated session(s) from external "
                       f"source(s) — {len(report.breach_clusters)} brute-force "
                       f"cluster(s) reached ESTABLISHED state on local "
                       f"TCP/{rdp.RDP_PORT}. {pretty}{extra}"),
                confidence="high",
                evidence=[report.as_evidence(facts={
                    "established_total": sum(
                        c.established_count for c in report.breach_clusters
                    ),
                })],
                hypotheses_supported=["H_BRUTE_FORCE"],
            )))

        if report.other_external and not report.external_clusters:
            # Sub-threshold external probe activity. Surface as low so the
            # analyst sees the lead without it scoring brute force.
            top = report.other_external[:_TOP_PRETTY]
            pretty = "; ".join(
                f"{c.foreign_ip} ×{c.total_connections}"
                for c in top
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                claim=(f"External inbound TCP/{rdp.RDP_PORT} probes below "
                       f"brute-force threshold: {len(report.other_external)} "
                       f"source(s), each <{rdp.MIN_CLUSTER_CONNECTIONS} "
                       f"connection(s). {pretty}"),
                confidence="low", evidence=[report.as_evidence()],
            )))

        return out


__all__ = ["RDPBruteForceAnalyst"]
