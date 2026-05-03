"""Father Rootkit Detection Skill

Specialized detection for the Father userland rootkit family.
Based on analysis from https://github.com/mav8557/Father

The Father rootkit uses LD_PRELOAD to hook system calls and provides:
- Root shell backdoor via specific source port (default 48411)
- File/process hiding via magic GID
- Network connection hiding via /proc/net/tcp manipulation
- Password hooking via PAM (logs to /tmp/silly.txt)
- GnuPG signature verification bypass
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

class FatherRootkitError(Exception):
    pass


def _build_evidence_search_paths(evidence_root: Path) -> dict:
    """
    Build comprehensive search paths for Father rootkit artifacts based on evidence structure.

    Handles three evidence patterns:
    1. Live response collection (chkrootkit/, live_response/, [root]/, etc.)
    2. Direct filesystem root (etc/, var/, home/, etc.)
    3. Mixed structure with both live response and filesystem data
    """
    evidence_root = Path(evidence_root)

    # Detect evidence structure type
    has_live_response = (evidence_root / "live_response").exists()
    has_chkrootkit = (evidence_root / "chkrootkit").exists()
    has_root_dir = (evidence_root / "[root]").exists()
    has_direct_etc = (evidence_root / "etc").exists()

    search_paths = {
        "preload_files": [],
        "rootkit_libraries": [],
        "silly_txt_paths": [],
        "log_paths": [],
        "proc_files": [],
        "net_files": [],
        "evidence_type": "unknown"
    }

    if has_live_response or has_chkrootkit:
        # Live response collection structure
        search_paths["evidence_type"] = "live_response_collection"

        # LD_PRELOAD files from chkrootkit or system scans
        search_paths["preload_files"].extend([
            evidence_root / "chkrootkit" / "etc_ld_so_preload.txt",
            evidence_root / "system" / "etc_ld_so_preload.txt",
            evidence_root / "live_response" / "system" / "etc_ld_so_preload.txt",
        ])

        # Process lists from live response
        if has_live_response:
            lr_proc = evidence_root / "live_response" / "process"
            search_paths["proc_files"].extend([
                lr_proc / "ps_-ef.txt",
                lr_proc / "ps_auxwww.txt",
                lr_proc / "ps_-axo_pid_user_lstart_args.txt",
            ])

            # Network connections from live response
            lr_net = evidence_root / "live_response" / "network"
            search_paths["net_files"].extend([
                lr_net / "ss_-tanp.txt",
                lr_net / "ss_-ap.txt",
                lr_net / "netstat.txt",
                lr_net / "netstat_-anp.txt",
            ])

        # If [root] directory exists, also check filesystem artifacts
        if has_root_dir:
            root_dir = evidence_root / "[root]"
            search_paths["preload_files"].append(root_dir / "etc" / "ld.so.preload")
            search_paths["rootkit_libraries"].extend([
                root_dir / "usr" / "lib" / "x86_64-linux-gnu" / "libymv.so.3",
                root_dir / "lib" / "x86_64-linux-gnu" / "libymv.so.3",
            ])
            search_paths["silly_txt_paths"].append(root_dir / "tmp" / "silly.txt")
            search_paths["log_paths"].extend([
                root_dir / "var" / "log" / "boot.log",
                root_dir / "var" / "log" / "syslog",
                root_dir / "var" / "log" / "dmesg",
            ])

        # Add live response system files to logs for error detection
        if has_live_response:
            lr_system = evidence_root / "live_response" / "system"
            search_paths["log_paths"].extend([
                lr_system / "dmesg.txt",
                lr_system / "boot_log.txt",
                lr_system / "syslog.txt",
            ])

        # Add chkrootkit and system directory scans
        if has_chkrootkit:
            chk_dir = evidence_root / "chkrootkit"
            search_paths["log_paths"].extend([
                chk_dir / "dmesg.txt",
                chk_dir / "boot_log.txt",
            ])
            search_paths["proc_files"].extend([
                chk_dir / "ps_-ef.txt",
                chk_dir / "ps_auxwww.txt",
            ])

        # Add system directory scans
        system_dir = evidence_root / "system"
        if system_dir.exists():
            search_paths["log_paths"].extend([
                system_dir / "dmesg.txt",
                system_dir / "boot_log.txt",
            ])
            search_paths["proc_files"].extend([
                system_dir / "ps_-ef.txt",
                system_dir / "ps_auxwww.txt",
            ])

    elif has_direct_etc:
        # Direct filesystem root structure
        search_paths["evidence_type"] = "filesystem_root"

        search_paths["preload_files"].append(evidence_root / "etc" / "ld.so.preload")
        search_paths["rootkit_libraries"].extend([
            evidence_root / "usr" / "lib" / "x86_64-linux-gnu" / "libymv.so.3",
            evidence_root / "lib" / "x86_64-linux-gnu" / "libymv.so.3",
        ])
        search_paths["silly_txt_paths"].append(evidence_root / "tmp" / "silly.txt")
        search_paths["log_paths"].extend([
            evidence_root / "var" / "log" / "boot.log",
            evidence_root / "var" / "log" / "syslog",
        ])

    else:
        # Unknown structure - try common paths
        search_paths["evidence_type"] = "unknown_structure"
        search_paths["preload_files"].extend([
            evidence_root / "etc" / "ld.so.preload",
            evidence_root / "chkrootkit" / "etc_ld_so_preload.txt",
        ])

    return search_paths


@dataclass
class FatherRootkitEvidence:
    """Evidence of Father rootkit presence."""

    preload_path: Optional[str] = None
    rootkit_path: Optional[str] = None
    rootkit_md5: Optional[str] = None
    config_gid: Optional[int] = None
    source_port: Optional[int] = None
    shell_pass: Optional[str] = None
    env_var: Optional[str] = None
    hidden_port: Optional[int] = None
    silly_txt_present: bool = False
    preload_errors: list[str] = None

    def as_evidence(self, facts: dict | None = None) -> dict:
        """Convert to EvidenceItem format."""
        facts = facts or {}

        # Build evidence description
        desc_parts = []
        if self.rootkit_path:
            desc_parts.append(f"Father rootkit at {self.rootkit_path}")
        if self.config_gid:
            desc_parts.append(f"Magic GID {self.config_gid}")
        if self.source_port:
            desc_parts.append(f"Backdoor port {self.source_port}")
        if self.shell_pass:
            desc_parts.append(f"Shell password '{self.shell_pass}'")

        return {
            "tool": "father_rootkit_detection",
            "description": "; ".join(desc_parts) if desc_parts else "Father rootkit indicators",
            "sha256": hashlib.sha256(str(self).encode()).hexdigest()[:16] + "...",
            "path": self.preload_path or self.rootkit_path or "/etc/ld.so.preload",
            **facts
        }


def detect_father_rootkit(evidence_root: Path) -> FatherRootkitEvidence:
    """
    Detect Father rootkit artifacts in evidence.

    Enhanced to handle multiple evidence structures:
    - Live response data (chkrootkit/, live_response/, system/)
    - Mounted filesystem ([root]/ directory)
    - Direct filesystem root (etc/, var/, home/, etc.)

    Father rootkit detection signatures:
    1. LD_PRELOAD entry pointing to suspicious .so file
    2. Magic GID 7823 (default) in processes/files
    3. Source port 48411 (default) in network connections
    4. Password log file /tmp/silly.txt
    5. Boot errors about missing preload library
    6. Specific environment variable (default 'ymv')
    """
    evidence_root = Path(evidence_root)
    result = FatherRootkitEvidence()
    result.preload_errors = []

    # Detect evidence structure type and build search paths
    search_paths = _build_evidence_search_paths(evidence_root)

    # Check LD_PRELOAD configuration across all possible locations
    preload_files = search_paths["preload_files"]

    for preload_file in preload_files:
        if not preload_file.exists():
            continue

        try:
            content = preload_file.read_text().strip()
            if content and not content.startswith("#"):
                result.preload_path = str(preload_file)

                # Extract library path
                if "/libymv.so" in content:
                    result.rootkit_path = content

                    # Father default config extraction
                    if "libymv.so.3" in content:
                        result.config_gid = 7823  # Default Father GID
                        result.source_port = 48411  # Default Father source port
                        result.env_var = "ymv"  # Default Father env var
                        result.shell_pass = "ymv"  # Default Father shell password
                        result.hidden_port = 0xD431  # Default Father hidden port (54321)

        except Exception as e:
            result.preload_errors.append(f"Error reading {preload_file}: {e}")

    # Look for Father rootkit library file using enhanced search paths
    rootkit_libraries = search_paths["rootkit_libraries"]
    for lib_path in rootkit_libraries:
        if lib_path.exists():
            result.rootkit_path = str(lib_path)
            # Calculate MD5 hash
            with open(lib_path, "rb") as f:
                result.rootkit_md5 = hashlib.md5(f.read()).hexdigest()
            break

    # Check for password log file (Father hooks PAM passwords here)
    silly_txt_paths = search_paths["silly_txt_paths"]
    for silly_path in silly_txt_paths:
        if silly_path.exists():
            result.silly_txt_present = True
            break

    # Look for Father rootkit errors in system logs
    log_paths = search_paths["log_paths"]

    father_error_patterns = [
        r"object '/.*libymv\.so.*' from /etc/ld\.so\.preload cannot be preloaded",
        r"file too short.*libymv\.so",
        r"ERROR.*ld\.so.*libymv\.so",
    ]

    for log_path in log_paths:
        if not log_path.exists():
            continue

        try:
            content = log_path.read_text()
            for pattern in father_error_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                result.preload_errors.extend(matches)
        except Exception as e:
            continue

    # Look for magic GID 7823 in process lists or file ownership
    proc_files = search_paths["proc_files"]

    for proc_file in proc_files:
        if not proc_file.exists():
            continue

        try:
            content = proc_file.read_text()
            if "7823" in content:
                result.config_gid = 7823
        except Exception:
            continue

    # Look for source port 48411 in network connections
    net_files = search_paths["net_files"]

    for net_file in net_files:
        if not net_file.exists():
            continue

        try:
            content = net_file.read_text()
            if "48411" in content:
                result.source_port = 48411
        except Exception:
            continue

    return result


def analyze_father_config(rootkit_path: Path) -> dict:
    """
    Analyze Father rootkit configuration if binary is available.

    Father configuration constants:
    - GID: Magic group ID for hiding files/processes
    - SOURCEPORT: Port number for backdoor activation
    - ENV: Environment variable name
    - SHELL_PASS: Password for root shell
    - PRELOAD: Path to rootkit library
    - HIDDENPORT: Port to hide from netstat
    """
    if not rootkit_path.exists():
        return {}

    try:
        content = rootkit_path.read_bytes()

        # Look for Father configuration strings
        config = {}

        # Common Father strings
        father_strings = [
            b"SOURCEPORT",
            b"SHELL_PASS",
            b"HIDDENPORT",
            b"libymv.so",
            b"/tmp/silly.txt",
            b"direct-tcpip",
            b"gid=7823",
        ]

        for string in father_strings:
            if string in content:
                config[string.decode()] = True

        return config

    except Exception as e:
        return {"error": str(e)}


# Father rootkit YARA rule for threat hunting
FATHER_YARA_RULES = '''
rule Father_Rootkit_Strings {
    meta:
        description = "Father userland rootkit detection"
        author = "EL DFIR Framework"
        reference = "https://github.com/mav8557/Father"

    strings:
        $s1 = "SOURCEPORT" ascii
        $s2 = "SHELL_PASS" ascii
        $s3 = "HIDDENPORT" ascii
        $s4 = "libymv.so" ascii
        $s5 = "/tmp/silly.txt" ascii
        $s6 = "direct-tcpip" ascii
        $s7 = "ld.so.preload" ascii
        $s8 = "gid=7823" ascii

    condition:
        3 of them
}

rule Father_Rootkit_Behavior {
    meta:
        description = "Father rootkit behavioral indicators"

    strings:
        $preload = "/etc/ld.so.preload" ascii
        $ymv = "ymv" ascii
        $port = "48411" ascii
        $gid = "7823" ascii
        $silly = "silly.txt" ascii

    condition:
        $preload and ($ymv or $port or $gid or $silly)
}
'''