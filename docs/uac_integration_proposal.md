# UAC Integration Proposal for EL Framework

**Date**: 2026-05-03  
**Status**: PROPOSAL  
**Priority**: HIGH  

## Executive Summary

UAC (Unix Artifact Collector) is an ideal candidate for integration into the EL DFIR orchestrator framework. It would significantly enhance our Linux/Unix forensic capabilities by providing standardized, comprehensive artifact collection with minimal overhead.

## Key Benefits for EL Integration

### 1. **Complements Existing Architecture**
- **Pre-Analysis Collection**: UAC runs before EL agents to gather comprehensive artifacts
- **Structured Output**: Produces organized directories that EL agents can consume
- **Evidence Integrity**: Built-in hashing and forensic validation
- **No Tool Conflicts**: Pure shell implementation, no SIFT tool interference

### 2. **Direct EL Workflow Enhancement**
```
Current: Manual evidence → EL agents → Analysis
Proposed: Live system → UAC collection → EL agents → Analysis
```

### 3. **Artifact Coverage Expansion**
| UAC Capability | EL Agent Benefit |
|----------------|------------------|
| Live response process data | Enhanced memory forensics correlation |
| Comprehensive logs | Better timeline synthesis |
| Network state capture | Improved network analysis |
| File system bodyfile | Enhanced disk forensics |
| Container/VM detection | New endpoint analysis capabilities |

## Technical Integration Strategy

### Phase 1: Tool Installation & Basic Integration

**1. Add UAC to SIFT Environment**
```bash
# Download and install UAC
cd /opt
sudo wget https://github.com/tclahr/uac/releases/latest/download/uac.tar.gz
sudo tar -xf uac.tar.gz
sudo mv uac* uac
sudo ln -s /opt/uac/uac /usr/local/bin/uac
```

**2. Tool Probe Integration**
```python
# el/tooling.py
def probe_uac() -> ToolStatus:
    """Probe Unix Artifact Collector availability."""
    uac_paths = [
        Path("/opt/uac/uac"),
        Path("/usr/local/bin/uac"),
        which("uac")
    ]
    
    for path in uac_paths:
        if path and path.exists():
            return ToolStatus.available(str(path))
    
    return ToolStatus.missing("UAC not found - install from https://github.com/tclahr/uac")
```

### Phase 2: UAC Skill Wrapper

```python
# el/skills/uac.py
from __future__ import annotations
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

class UACError(Exception):
    pass

@dataclass
class UACCollection:
    """Results from UAC collection run."""
    output_dir: Path
    collection_profile: str
    artifacts_collected: int
    duration_seconds: float
    bodyfile_path: Optional[Path] = None
    live_response_dir: Optional[Path] = None
    memory_dump_path: Optional[Path] = None
    
    def as_evidence(self, facts: dict | None = None) -> dict:
        """Convert to EvidenceItem format."""
        facts = facts or {}
        
        return {
            "tool": "uac",
            "description": f"UAC {self.collection_profile} collection: {self.artifacts_collected} artifacts",
            "path": str(self.output_dir),
            "sha256": _hash_directory(self.output_dir),
            **facts
        }

def collect_ir_triage(target_system: str, output_dir: Path) -> UACCollection:
    """
    Run UAC incident response triage collection.
    
    Args:
        target_system: Target system identifier or path
        output_dir: Output directory for collected artifacts
    """
    uac_path = _which("uac")
    
    cmd = [
        str(uac_path),
        "-p", "ir_triage",  # Fast IR collection profile
        "-o", str(output_dir),
        target_system
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise UACError(f"UAC collection failed: {result.stderr}")
    
    # Parse UAC output structure
    collection_dir = output_dir / f"uac-{target_system}-*"  # UAC naming pattern
    
    return UACCollection(
        output_dir=collection_dir,
        collection_profile="ir_triage",
        artifacts_collected=_count_artifacts(collection_dir),
        duration_seconds=_parse_duration(result.stdout),
        bodyfile_path=collection_dir / "bodyfile" / "bodyfile.txt",
        live_response_dir=collection_dir / "live_response",
        memory_dump_path=collection_dir / "memory_dump"
    )

def collect_full_forensics(target_system: str, output_dir: Path) -> UACCollection:
    """Run comprehensive UAC forensic collection."""
    # Similar implementation with 'full' profile
    pass

def _count_artifacts(uac_dir: Path) -> int:
    """Count collected artifact files."""
    if not uac_dir.exists():
        return 0
    return len([f for f in uac_dir.rglob("*") if f.is_file()])
```

### Phase 3: Live Response Agent

```python
# el/agents/live_response_collector.py
class LiveResponseCollector(Agent):
    """
    Agent for live response collection using UAC.
    Runs on live systems before traditional forensic agents.
    """
    name = "live_response_collector"
    
    def run(self, ctx: AgentContext) -> list[Finding]:
        findings = []
        
        # Determine if this is a live system vs forensic image
        if self._is_live_system(ctx.input_path):
            
            # Run UAC IR triage collection
            collection = collect_ir_triage(
                target_system=str(ctx.input_path),
                output_dir=ctx.case_dir / "raw" / "uac_collection"
            )
            
            # Emit finding about collection
            findings.append(self.emit(ctx, Finding(
                agent=self.name,
                claim=f"Live response collection completed: {collection.artifacts_collected} artifacts",
                confidence="high",
                evidence=[collection.as_evidence({"collection_type": "live_ir_triage"})],
                hypotheses_supported=[],
                hypotheses_refuted=[]
            )))
            
            # Update shared context for other agents
            ctx.shared['uac_collection'] = collection
            ctx.shared['live_response_available'] = True
            
        return findings
    
    def _is_live_system(self, path: Path) -> bool:
        """Determine if path represents a live system vs forensic image."""
        return path.exists() and path.is_dir() and (path / "proc").exists()
```

### Phase 4: Enhanced Evidence Routing

```python
# Update el/orchestrator/coordinator.py
KIND_TO_AGENT = {
    "live-linux-system": ["live_response_collector", "linux_forensicator"],
    "linux-fs-dir": ["disk_forensicator", "linux_forensicator"],  # Existing
    "uac-collection": ["timeline_synthesist", "correlator"],  # New
    # ... existing mappings
}
```

### Phase 5: UAC Output Integration

**Existing agents enhanced to consume UAC artifacts:**

```python
# Enhanced Linux Forensicator
class LinuxForensicatorAgent(Agent):
    def _analyze_uac_artifacts(self, ctx: AgentContext) -> list[Finding]:
        """Analyze artifacts from UAC collection."""
        findings = []
        
        if 'uac_collection' in ctx.shared:
            uac = ctx.shared['uac_collection']
            
            # Process bodyfile for timeline
            if uac.bodyfile_path and uac.bodyfile_path.exists():
                timeline_finding = self._analyze_bodyfile_timeline(uac.bodyfile_path)
                findings.append(timeline_finding)
            
            # Process live response data
            if uac.live_response_dir:
                process_findings = self._analyze_uac_processes(uac.live_response_dir / "process")
                network_findings = self._analyze_uac_network(uac.live_response_dir / "network")
                findings.extend(process_findings + network_findings)
                
        return findings
```

## UAC Collection Profiles for EL

### Custom EL-Optimized Profile
```yaml
# /opt/uac/artifacts/live_response/el_optimized.yaml
version: 4.1
description: "EL Framework optimized collection"
artifacts:
  - description: "Process memory strings for Father rootkit detection"
    supported_os: [linux]
    collector: command
    command: "for pid in $(ps -eo pid --no-headers); do strings /proc/$pid/maps 2>/dev/null | grep -E '(libymv|7823|48411)'; done"
    output_file: father_rootkit_strings.txt
    
  - description: "LD_PRELOAD configuration"
    supported_os: [linux] 
    collector: file
    path: /etc/ld.so.preload
    output_file: ld_so_preload.txt
    
  - description: "Father rootkit credential harvest log"
    supported_os: [linux]
    collector: file
    path: /tmp/silly.txt
    output_file: father_silly_log.txt
```

## Evidence Structure Compatibility

**UAC Output Structure** (already compatible with enhanced Father rootkit detection):
```
uac_collection/
├── bodyfile/
├── live_response/
│   ├── process/          # ps outputs, process lists
│   ├── network/          # netstat, ss outputs  
│   ├── system/           # system configuration
│   └── storage/          # mount info, disk info
└── memory_dump/          # AVML memory images
```

**Current EL Structure** (seamless integration):
```
cases/case_id/
├── analysis/             # Agent outputs
├── raw/uac_collection/   # UAC artifacts (new)
├── exports/              # Extracted evidence
└── reports/              # Final reports
```

## Implementation Benefits

### 1. **Forensic Value**
- **Order of Volatility**: UAC follows forensic best practices automatically
- **Evidence Integrity**: Built-in hashing and chain of custody
- **Comprehensive Coverage**: Reduces missed artifacts from manual collection

### 2. **Operational Efficiency**
- **Standardized Collection**: Repeatable, documented procedures
- **Reduced Manual Effort**: Automated artifact gathering
- **Cross-Platform**: Extends EL to AIX, FreeBSD, macOS, Solaris

### 3. **Integration Synergies**
- **Enhanced Father Rootkit Detection**: UAC + enhanced detection = comprehensive coverage
- **Memory Correlation**: UAC process data + Volatility analysis
- **Timeline Fusion**: UAC bodyfile + Plaso supertimeline

## Real-World Validation

**Note**: The hackathon challenge evidence was actually collected using UAC + AVML, demonstrating proven compatibility with our existing analysis workflows.

## Resource Requirements

- **Storage**: ~3MB for UAC installation
- **Runtime**: Minimal overhead (pure shell)
- **Dependencies**: None (optional: osquery, chkrootkit for enhanced capabilities)
- **Training**: Minimal - integrates transparently with existing EL workflows

## Recommendation

**APPROVE for immediate integration** - UAC provides significant value with minimal risk:

1. **Phase 1 (Immediate)**: Install UAC and add tool probe
2. **Phase 2 (Week 1)**: Implement UAC skill wrapper  
3. **Phase 3 (Week 2)**: Add live response collector agent
4. **Phase 4 (Week 3)**: Enhance existing agents for UAC artifact consumption
5. **Phase 5 (Week 4)**: Deploy custom EL-optimized UAC profiles

This integration would position EL as a comprehensive DFIR platform capable of both live response collection and forensic analysis, significantly expanding our investigative capabilities.