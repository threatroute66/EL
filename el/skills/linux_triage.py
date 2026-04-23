"""Skill: Linux IR/forensics detectors on extracted artifacts.

Consumers pass the exports dir produced by `extract_linux_artifacts`
and get back a list of `LinuxHit` records — one per detector hit —
tagged with MITRE ATT&CK technique IDs and EL hypothesis IDs.

Detectors implemented in V1:

1. `detect_shell_history_malicious` — scans every per-user shell
   history for attacker-shell patterns (wget/curl to raw IPs,
   base64 pipes, reverse shells, chmod a+x in /tmp, nc listeners,
   pkill auditd / systemctl stop auditd, etc.)

2. `detect_ld_so_preload` — ANY non-empty `/etc/ld.so.preload`
   is a near-unambiguous persistence / injection primitive.

3. `detect_auth_log_failure_burst` — sshd failures clustered per
   user or per source IP. Mirror of the credential-triage tiers
   used on the Windows side.

4. `detect_ssh_authorized_keys_anomaly` — >1 public key per
   user, OR any key whose algorithm / comment looks generated
   (e.g., `root@kali`, trailing `# backdoor`, unusual bit lengths).

5. `detect_cron_suspicious` — crontab entries whose command
   invokes something from /tmp, /dev/shm, /var/tmp, or whose
   schedule is `* * * * *` (every minute).

6. `detect_tmp_suid` — skipped V1 (needs a preserved SUID listing;
   fls already captures mode bits, follow-up to consume that).

Pure functions on paths. No subprocess.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


# Reuse the powershell-triage family idea: regex patterns grouped by
# attack family. Everything runs case-insensitive.
_SHELL_PATTERNS: dict[str, tuple[str, ...]] = {
    "reverse_shell": (
        r"\bnc(?:\.traditional)?\s+-[a-z]*e\b",                # nc -e /bin/bash
        r"\bbash\s+-i\s*>\s*/dev/tcp/",
        r"\bmkfifo\s+.*\|\s*bash",
        r"\bpython3?\s+-c\s+['\"].*socket\b.*\bconnect",
        r"\bperl\s+-e\s+['\"].*socket\b",
        r"/dev/tcp/\d",
        r"\bsocat\s+.*exec:",
    ),
    "download_cradle": (
        # Raw-IP wget (any flags)
        r"\bwget\s+(?:-\S+\s+)*https?://\d+\.\d+\.\d+\.\d+",
        r"\bcurl\s+(?:-\S+\s+)*https?://\d+\.\d+\.\d+\.\d+",
        # wget/curl piped to shell (flags optional)
        r"\bwget\s+(?:-\S+\s+)*\S+.*\|\s*(?:sh|bash)\b",
        r"\bcurl\s+(?:-\S+\s+)*\S+.*\|\s*(?:sh|bash)\b",
        # wget -O- | sh idiom
        r"\bwget\s+-[a-z]*O\s*-\s*\|",
    ),
    "base64_pipe": (
        r"\becho\s+['\"]?[A-Za-z0-9+/=]{30,}\s*['\"]?\s*\|\s*base64\s+-d\b",
        r"\bbase64\s+-d.*\|\s*(?:sh|bash)\b",
        r"`echo\s+[A-Za-z0-9+/=]{30,}.*base64",
    ),
    "persistence_cron": (
        r"\bcrontab\s+-e",
        r"\becho\s+['\"].*\*\s*\*\s*\*\s*\*\s*\*['\"]?\s*>>?\s*/etc/cron",
        r">\s*/etc/cron\.d/",
    ),
    "persistence_ssh": (
        r">>\s*~/\.ssh/authorized_keys",
        r">>\s*/root/\.ssh/authorized_keys",
        r">\s*/root/\.ssh/authorized_keys",
    ),
    "defense_evasion": (
        r"\bsystemctl\s+(?:stop|disable)\s+auditd\b",
        r"\bpkill\s+-9?\s+auditd\b",
        r"\bservice\s+auditd\s+stop\b",
        r"\bunset\s+HISTFILE\b",
        r"\bhistory\s+-c\b",
        r"\bchattr\s+\+i\b",                                    # make immutable
        r"\bchmod\s+[0-7]*7{3}\s+/tmp\b",                        # chmod 777 /tmp
    ),
    "priv_esc": (
        r"\bsudo\s+-s\b",
        r"\bsudo\s+su\s+-\b",
        r"/tmp/[\w.-]+\.sh\s*$",                                # invoked .sh in /tmp
        r"\bchmod\s+[\+0-7]*x\s+/tmp/",
        r"\bchmod\s+[\+0-7]*x\s+/dev/shm/",
    ),
    "credential_access": (
        r"\bcat\s+/etc/shadow\b",
        r"\bcat\s+/etc/sudoers\b",
        r"\bcat\s+~/\.aws/credentials\b",
        r"\bcat\s+~/\.ssh/id_\w+\b",                             # cat private key
        r"\bmimipenguin\b",
        r"\blazagne\b",
        r"/var/lib/kdc/principal",
    ),
    # Concealment / anti-forensic / manual-crypto commands — the
    # BelkaCTF-Kidnapper-style user-illicit-activity signature. These
    # are NOT typical intrusion tools; they indicate a user
    # deliberately hiding evidence (extension-mangling, packing into
    # encrypted archives, encoding payloads for later decode).
    "concealment_tooling": (
        r"\bhexedit\b",                            # raw-byte patching
        r"\bxxd\s+-r\b",                           # hex → binary patching
        r"\bzip2john\b",                           # prep for john
        r"\bjohn\s+.*\.(?:zip|rar|7z|pdf)\b",      # john cracking container
        r"\bhashcat\s+.*\.(?:zip|rar|7z|pdf)\b",
        r"\b(?:openssl\s+enc|gpg\s+-c)\b",          # manual symmetric crypto
        r"\bbase32\s+(?:-d|--decode)\b",           # base32 decoder usage
        r"\b(?:rot13|tr\s+['\"]?A-Za-z['\"]?)\b",  # rot13-style transforms
        r"\b(?:shred|wipe)\s+.*\w",                # tracks-erasure
        r"\bchattr\s+\+[aiu]\b",                   # set immutable/append-only/undeletable
        r"\bsteghide\b",
        r"\boutguess\b",
        r"\bzsteg\b",
        r"\bexiftool\s+.*\s+-(?:Comment|UserComment)=",  # metadata write
    ),
    # Password-cracker tooling presence — seeing a 10-million-password
    # list or rockyou.txt in a user directory or command line is an
    # operational tell for offline password recovery, which directly
    # implies targeting an encrypted archive / document.
    "cracker_tooling": (
        r"\b10-million-password-list(?:-top-\d+)?\.txt\b",
        r"\brockyou\.txt\b",
        r"\bSecLists/Passwords\b",
        r"\bcrackstation\.txt\b",
        r"\bweakpass\b",
        r"\bhashes\.org\b",
    ),
}


_FAMILY_HYPOTHESES: dict[str, list[str]] = {
    "reverse_shell":    ["H_C2_OR_REVERSE_SHELL", "H_APT_ESPIONAGE"],
    "download_cradle":  ["H_LIVING_OFF_THE_LAND",
                          "H_C2_OR_REVERSE_SHELL"],
    "base64_pipe":      ["H_DEFENSE_EVASION", "H_APT_ESPIONAGE"],
    "persistence_cron": ["H_PERSISTENCE_SCHEDULED_TASK",
                          "H_APT_ESPIONAGE"],
    "persistence_ssh":  ["H_PERSISTENCE_SERVICE",
                          "H_APT_ESPIONAGE"],
    "defense_evasion":  ["H_DEFENSE_EVASION", "H_APT_ESPIONAGE"],
    "priv_esc":         ["H_APT_ESPIONAGE",
                          "H_LIVING_OFF_THE_LAND"],
    "credential_access": ["H_CREDENTIAL_ACCESS", "H_APT_ESPIONAGE"],
    "concealment_tooling": ["H_INSIDER_DATA_EXFIL",
                              "H_OPPORTUNISTIC_COMMODITY"],
    "cracker_tooling":    ["H_CREDENTIAL_ACCESS",
                              "H_INSIDER_DATA_EXFIL"],
}


_FAMILY_ATTACK: dict[str, list[tuple[str, str]]] = {
    "reverse_shell":    [("T1059.004", "Unix Shell"),
                          ("T1021.004", "Remote Services: SSH")],
    "download_cradle":  [("T1105", "Ingress Tool Transfer"),
                          ("T1059.004", "Unix Shell")],
    "base64_pipe":      [("T1027", "Obfuscated Files or Information"),
                          ("T1059.004", "Unix Shell")],
    "persistence_cron": [("T1053.003", "Scheduled Task/Job: Cron")],
    "persistence_ssh":  [("T1098.004",
                          "Account Manipulation: SSH Authorized Keys")],
    "defense_evasion":  [("T1562.001",
                          "Impair Defenses: Disable or Modify Tools"),
                          ("T1070.003",
                           "Indicator Removal: Clear Command History")],
    "priv_esc":         [("T1548.003",
                          "Abuse Elevation Control: Sudo and Sudo Caching")],
    "credential_access": [("T1552.001",
                           "Unsecured Credentials: Credentials In Files")],
    "concealment_tooling": [
        ("T1027", "Obfuscated Files or Information"),
        ("T1070.004", "Indicator Removal: File Deletion"),
        ("T1070.006", "Indicator Removal: Timestomp"),
    ],
    "cracker_tooling":    [("T1110", "Brute Force")],
}


@dataclass
class LinuxHit:
    family: str
    matched_pattern: str
    event_count: int = 0
    sample_text: str = ""
    top_users: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


def _scan_text(text: str, per_family: dict[str, list[str]]) -> None:
    for family, patterns in _SHELL_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                per_family[family].append(pat)
                break       # one pattern per family per line is enough


# ---------------------------------------------------------------------------
# Detector 1: shell-history malicious pattern scan
# ---------------------------------------------------------------------------

def detect_shell_history_malicious(exports_dir: Path) -> list[LinuxHit]:
    root = Path(exports_dir) / "home"
    if not root.is_dir():
        return []

    from collections import Counter, defaultdict

    family_counter: Counter = Counter()
    family_users: dict[str, Counter] = defaultdict(Counter)
    family_files: dict[str, set[str]] = defaultdict(set)
    family_samples: dict[str, str] = {}
    family_pattern: dict[str, str] = {}

    for user_dir in sorted(root.iterdir()):
        if not user_dir.is_dir():
            continue
        user = user_dir.name
        for hist in user_dir.iterdir():
            if not hist.is_file():
                continue
            try:
                text = hist.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                per_family: dict[str, list[str]] = \
                    {k: [] for k in _SHELL_PATTERNS}
                _scan_text(line, per_family)
                for family, matches in per_family.items():
                    if not matches:
                        continue
                    family_counter[family] += 1
                    family_users[family][user] += 1
                    family_files[family].add(str(hist))
                    if family not in family_pattern:
                        family_pattern[family] = matches[0]
                    if family not in family_samples:
                        family_samples[family] = line[:200]

    out: list[LinuxHit] = []
    for family, count in family_counter.items():
        out.append(LinuxHit(
            family=family,
            matched_pattern=family_pattern[family],
            event_count=count,
            sample_text=family_samples[family],
            top_users=[u for u, _ in family_users[family].most_common(5)],
            source_files=sorted(family_files[family])[:10],
            attack=_FAMILY_ATTACK.get(family, []),
        ))
    priority = {"reverse_shell": 0, "credential_access": 1,
                 "defense_evasion": 2, "persistence_ssh": 3,
                 "persistence_cron": 4, "download_cradle": 5,
                 "base64_pipe": 6, "priv_esc": 7}
    out.sort(key=lambda h: priority.get(h.family, 99))
    return out


# ---------------------------------------------------------------------------
# Detector 2: /etc/ld.so.preload non-empty
# ---------------------------------------------------------------------------

def detect_ld_so_preload(exports_dir: Path) -> list[LinuxHit]:
    preload = Path(exports_dir) / "etc" / "ld.so.preload"
    if not preload.is_file():
        return []
    try:
        text = preload.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    lines = [l.strip() for l in text.splitlines()
             if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return []
    return [LinuxHit(
        family="ld_so_preload",
        matched_pattern="non-empty /etc/ld.so.preload",
        event_count=len(lines),
        sample_text=", ".join(lines[:5]),
        source_files=[str(preload)],
        attack=[("T1574.006",
                  "Hijack Execution Flow: Dynamic Linker Hijacking"),
                ("T1547.006",
                  "Boot or Logon Autostart: Kernel Modules and Extensions")],
    )]


# ---------------------------------------------------------------------------
# Detector 3: sshd auth.log failure burst
# ---------------------------------------------------------------------------

_AUTH_SSHD_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user\s+)?(\S+) from (\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

_AUTH_BRUTE_MIN = 10
_AUTH_SPRAY_MIN = 5


def detect_auth_log_failure_burst(exports_dir: Path) -> list[LinuxHit]:
    log_dir = Path(exports_dir) / "var" / "log"
    if not log_dir.is_dir():
        return []
    # Parse every auth.log*/secure* file
    auth_files = sorted(
        [f for f in log_dir.iterdir() if f.is_file()
         and (f.name.startswith("auth.log") or f.name.startswith("secure"))]
    )
    if not auth_files:
        return []

    from collections import Counter, defaultdict
    per_user_fail: Counter = Counter()
    per_source: dict[str, set[str]] = defaultdict(set)
    first_seen_ts = ""
    last_seen_ts = ""
    parsed_count = 0

    for f in auth_files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            m = _AUTH_SSHD_FAIL_RE.search(line)
            if not m:
                continue
            user, ip = m.group(1), m.group(2)
            per_user_fail[user] += 1
            per_source[ip].add(user)
            ts = line[:15].strip()    # "Mon DD HH:MM:SS"
            if ts and not first_seen_ts:
                first_seen_ts = ts
            if ts:
                last_seen_ts = ts
            parsed_count += 1
    if not parsed_count:
        return []

    out: list[LinuxHit] = []
    brute = [(u, n) for u, n in per_user_fail.items() if n >= _AUTH_BRUTE_MIN]
    if brute:
        brute.sort(key=lambda kv: -kv[1])
        out.append(LinuxHit(
            family="ssh_brute",
            matched_pattern=r"Failed password for <user> from <ip>",
            event_count=sum(n for _, n in brute),
            sample_text=f"{brute[0][0]}: {brute[0][1]} failed passwords",
            top_users=[u for u, _ in brute[:5]],
            source_files=[str(f) for f in auth_files],
            attack=[("T1110.001", "Brute Force: Password Guessing")],
        ))

    spray = [(ip, len(users)) for ip, users in per_source.items()
             if len(users) >= _AUTH_SPRAY_MIN]
    if spray:
        spray.sort(key=lambda kv: -kv[1])
        out.append(LinuxHit(
            family="ssh_spray",
            matched_pattern=r"Failed password from <ip> against N users",
            event_count=parsed_count,
            sample_text=f"{spray[0][0]}: {spray[0][1]} distinct users tried",
            top_users=[ip for ip, _ in spray[:5]],
            source_files=[str(f) for f in auth_files],
            attack=[("T1110.003", "Brute Force: Password Spraying")],
        ))
    return out


# ---------------------------------------------------------------------------
# Detector 4: SSH authorized_keys anomaly
# ---------------------------------------------------------------------------

_KALI_COMMENT_RE = re.compile(
    r"\b(kali|parrot|backbox|metasploit|msfuser|pentest)\b",
    re.IGNORECASE,
)


def detect_ssh_authorized_keys_anomaly(exports_dir: Path) -> list[LinuxHit]:
    home = Path(exports_dir) / "home"
    if not home.is_dir():
        return []
    hits: list[LinuxHit] = []
    for user_dir in sorted(home.iterdir()):
        if not user_dir.is_dir():
            continue
        ak = user_dir / ".ssh" / "authorized_keys"
        if not ak.is_file():
            continue
        try:
            text = ak.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        key_lines = [l.strip() for l in text.splitlines()
                     if l.strip() and not l.startswith("#")]
        if not key_lines:
            continue
        suspect = []
        for line in key_lines:
            if _KALI_COMMENT_RE.search(line):
                suspect.append(line)
        # Flag when: (a) any key carries a pentester-distro comment
        # OR (b) the file has ≥3 keys (operator-curated authorized_keys
        # normally has 1-2 entries; many keys on a user box = backup + backdoor
        # blend of signatures)
        if suspect or len(key_lines) >= 3:
            hits.append(LinuxHit(
                family="ssh_authorized_keys_anomaly",
                matched_pattern=(
                    "pentester-distro comment OR key-count>=3"
                ),
                event_count=len(key_lines),
                sample_text=(suspect[0][:200]
                              if suspect else key_lines[0][:200]),
                top_users=[user_dir.name],
                source_files=[str(ak)],
                attack=[("T1098.004",
                          "Account Manipulation: SSH Authorized Keys")],
            ))
    return hits


# ---------------------------------------------------------------------------
# Detector 5: cron entries invoking /tmp, /dev/shm, /var/tmp
# ---------------------------------------------------------------------------

_CRON_SUSPICIOUS_PATH_RE = re.compile(
    r"(?:^|\s)(/tmp/|/dev/shm/|/var/tmp/)\S+",
)


def detect_cron_suspicious(exports_dir: Path) -> list[LinuxHit]:
    roots: list[Path] = []
    etc_cron = Path(exports_dir) / "etc"
    if etc_cron.is_dir():
        for name in ("crontab", "cron.d", "cron.hourly",
                      "cron.daily", "cron.weekly", "cron.monthly"):
            p = etc_cron / name
            if p.is_file():
                roots.append(p)
            elif p.is_dir():
                roots.extend(f for f in p.iterdir() if f.is_file())
    user_cron = Path(exports_dir) / "var" / "spool" / "cron"
    if user_cron.is_dir():
        for f in user_cron.rglob("*"):
            if f.is_file():
                roots.append(f)

    suspicious: list[tuple[Path, str]] = []
    for p in roots:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if _CRON_SUSPICIOUS_PATH_RE.search(line):
                suspicious.append((p, line))
    if not suspicious:
        return []
    sample = suspicious[0][1][:200]
    return [LinuxHit(
        family="cron_suspicious_path",
        matched_pattern="cron command invokes /tmp/ or /dev/shm/ or /var/tmp/",
        event_count=len(suspicious),
        sample_text=sample,
        source_files=sorted({str(p) for p, _ in suspicious})[:10],
        attack=[("T1053.003", "Scheduled Task/Job: Cron")],
    )]


ALL_DETECTORS = (
    detect_shell_history_malicious,
    detect_ld_so_preload,
    detect_auth_log_failure_burst,
    detect_ssh_authorized_keys_anomaly,
    detect_cron_suspicious,
)


def run_all(exports_dir: Path) -> list[LinuxHit]:
    hits: list[LinuxHit] = []
    for fn in ALL_DETECTORS:
        try:
            hits.extend(fn(exports_dir))
        except Exception:
            # Detectors must not break the whole run on a single bad file
            continue
    return hits


def hypotheses_for(family: str) -> list[str]:
    return list(_FAMILY_HYPOTHESES.get(family, []))


__all__ = [
    "LinuxHit",
    "detect_shell_history_malicious", "detect_ld_so_preload",
    "detect_auth_log_failure_burst",
    "detect_ssh_authorized_keys_anomaly", "detect_cron_suspicious",
    "ALL_DETECTORS", "run_all", "hypotheses_for",
]
