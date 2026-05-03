"""Live Response Collector Agent

Agent for live response collection using UAC on live Unix/Linux systems.
Runs before traditional forensic agents to gather volatile artifacts in proper
order of volatility. Only activates when evidence path represents a live system.
"""
from __future__ import annotations

import os
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills.uac import collect_ir_triage, collect_full_forensics, UACError


class LiveResponseCollector(Agent):
    """
    Agent for live response collection using UAC.

    Detects live systems and performs comprehensive artifact collection
    following forensic order of volatility. Updates shared context for
    downstream agents to consume UAC artifacts.
    """

    name = "live_response_collector"

    def run(self, ctx: AgentContext) -> list[Finding]:
        findings = []

        # Only run on live systems
        if not self._is_live_system(ctx.input_path):
            findings.append(self.emit(ctx, Finding(
                agent=self.name,
                claim="Skipping live response collection — input is not a live system",
                confidence="insufficient",
                evidence=[],
                hypotheses_supported=[],
                hypotheses_refuted=[]
            )))
            return findings

        # Prepare UAC output directory
        uac_output_dir = ctx.case_dir / "raw" / "uac_collection"
        hostname = self._get_hostname(ctx.input_path)

        try:
            # Determine collection profile based on system type and resources
            if self._should_use_full_collection(ctx.input_path):
                collection = collect_full_forensics(
                    target_dir=ctx.input_path,
                    output_dir=uac_output_dir,
                    hostname=hostname
                )
            else:
                collection = collect_ir_triage(
                    target_dir=ctx.input_path,
                    output_dir=uac_output_dir,
                    hostname=hostname
                )

            # Emit successful collection finding
            findings.append(self.emit(ctx, Finding(
                agent=self.name,
                claim=f"Live response collection completed: {collection.artifacts_collected} artifacts "
                     f"collected in {collection.duration_seconds:.1f}s using {collection.collection_profile} profile",
                confidence="high",
                evidence=[collection.as_evidence({
                    "collection_type": "live_response",
                    "target_system": hostname,
                    "live_response_dir": str(collection.live_response_dir) if collection.live_response_dir else None,
                    "bodyfile_path": str(collection.bodyfile_path) if collection.bodyfile_path else None
                })],
                hypotheses_supported=[],
                hypotheses_refuted=["H_BENIGN_NO_INCIDENT"]  # Active collection suggests investigation warranted
            )))

            # Update shared context for downstream agents
            ctx.shared['uac_collection'] = collection
            ctx.shared['live_response_available'] = True
            ctx.shared['evidence_kind'] = 'uac-collection'

            # Emit specific findings for key UAC artifacts
            if collection.live_response_dir and collection.live_response_dir.exists():
                findings.extend(self._analyze_live_response_artifacts(ctx, collection))

            if collection.bodyfile_path and collection.bodyfile_path.exists():
                findings.append(self._analyze_bodyfile_artifact(ctx, collection))

        except UACError as e:
            findings.append(self.emit(ctx, Finding(
                agent=self.name,
                claim=f"Live response collection failed: {e}",
                confidence="insufficient",
                evidence=[],
                hypotheses_supported=[],
                hypotheses_refuted=[]
            )))

        return findings

    def _is_live_system(self, path: Path) -> bool:
        """
        Determine if path represents a live system vs forensic image.

        Checks for live system indicators:
        - /proc filesystem present and mounted
        - /sys filesystem present
        - Root path (/)
        - Current working processes
        """
        if not path.exists() or not path.is_dir():
            return False

        # Check if this is root filesystem
        if str(path) == "/":
            return True

        # Check for live system indicators
        proc_dir = path / "proc"
        sys_dir = path / "sys"

        # /proc must exist and have active content for live system
        if proc_dir.exists() and proc_dir.is_dir():
            # Check if /proc has live process directories (numeric PIDs)
            pid_dirs = [d for d in proc_dir.iterdir() if d.is_dir() and d.name.isdigit()]
            if len(pid_dirs) > 10:  # Arbitrary threshold for "live" system
                return True

            # Also check if /proc/self exists (indicates mounted proc)
            if (proc_dir / "self").exists():
                return True

        return False

    def _get_hostname(self, system_path: Path) -> str:
        """Get hostname from live system or generate identifier."""
        try:
            # Try to read hostname from live system
            hostname_file = system_path / "etc" / "hostname"
            if hostname_file.exists():
                hostname = hostname_file.read_text().strip()
                if hostname:
                    return hostname

            # Try /proc/sys/kernel/hostname for live systems
            if system_path == Path("/"):
                proc_hostname = Path("/proc/sys/kernel/hostname")
                if proc_hostname.exists():
                    hostname = proc_hostname.read_text().strip()
                    if hostname:
                        return hostname

            # Fallback to system hostname command for live systems
            if system_path == Path("/"):
                import subprocess
                result = subprocess.run(['hostname'], capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.strip()

        except (OSError, IOError, subprocess.SubprocessError):
            pass

        # Generate identifier based on path
        return f"target-{abs(hash(str(system_path))) % 10000:04d}"

    def _should_use_full_collection(self, system_path: Path) -> bool:
        """
        Determine whether to use full forensic collection vs IR triage.

        Full collection for:
        - Systems with evidence of compromise
        - High-value targets
        - When time/storage permits

        IR triage for:
        - Initial rapid assessment
        - Resource-constrained environments
        - Time-sensitive investigations
        """
        # For now, default to IR triage for speed
        # This could be enhanced to detect compromise indicators
        # and automatically escalate to full collection
        return False

    def _analyze_live_response_artifacts(self, ctx: AgentContext, collection) -> list[Finding]:
        """Analyze key artifacts from UAC live response collection."""
        findings = []

        live_response_dir = collection.live_response_dir

        # Check for process artifacts
        process_dir = live_response_dir / "process"
        if process_dir.exists():
            process_files = list(process_dir.glob("ps_*.txt"))
            if process_files:
                findings.append(self.emit(ctx, Finding(
                    agent=self.name,
                    claim=f"Live process data collected: {len(process_files)} process snapshots",
                    confidence="high",
                    evidence=[{
                        "tool": "uac",
                        "description": f"Process artifacts in {process_dir}",
                        "path": str(process_dir),
                        "file_count": len(process_files)
                    }],
                    hypotheses_supported=[],
                    hypotheses_refuted=[]
                )))

        # Check for network artifacts
        network_dir = live_response_dir / "network"
        if network_dir.exists():
            network_files = list(network_dir.glob("*.txt"))
            if network_files:
                findings.append(self.emit(ctx, Finding(
                    agent=self.name,
                    claim=f"Live network data collected: {len(network_files)} network snapshots",
                    confidence="high",
                    evidence=[{
                        "tool": "uac",
                        "description": f"Network artifacts in {network_dir}",
                        "path": str(network_dir),
                        "file_count": len(network_files)
                    }],
                    hypotheses_supported=[],
                    hypotheses_refuted=[]
                )))

        # Check for system artifacts
        system_dir = live_response_dir / "system"
        if system_dir.exists():
            system_files = list(system_dir.glob("*.txt"))
            if system_files:
                findings.append(self.emit(ctx, Finding(
                    agent=self.name,
                    claim=f"Live system data collected: {len(system_files)} system snapshots",
                    confidence="high",
                    evidence=[{
                        "tool": "uac",
                        "description": f"System artifacts in {system_dir}",
                        "path": str(system_dir),
                        "file_count": len(system_files)
                    }],
                    hypotheses_supported=[],
                    hypotheses_refuted=[]
                )))

        return findings

    def _analyze_bodyfile_artifact(self, ctx: AgentContext, collection) -> Finding:
        """Analyze UAC-generated bodyfile for timeline data."""
        bodyfile_path = collection.bodyfile_path

        try:
            # Get basic stats on bodyfile
            file_size = bodyfile_path.stat().st_size
            line_count = 0
            with open(bodyfile_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = sum(1 for _ in f)

            return self.emit(ctx, Finding(
                agent=self.name,
                claim=f"Filesystem timeline data collected: {line_count:,} entries in bodyfile "
                     f"({file_size:,} bytes)",
                confidence="high",
                evidence=[{
                    "tool": "uac",
                    "description": f"Bodyfile timeline at {bodyfile_path}",
                    "path": str(bodyfile_path),
                    "size_bytes": file_size,
                    "entry_count": line_count
                }],
                hypotheses_supported=[],
                hypotheses_refuted=[]
            ))

        except (OSError, IOError) as e:
            return self.emit(ctx, Finding(
                agent=self.name,
                claim=f"Bodyfile present but unreadable: {e}",
                confidence="insufficient",
                evidence=[],
                hypotheses_supported=[],
                hypotheses_refuted=[]
            ))