"""Skill: Linux disk-artifact extraction + triage.

Parallel to `sleuthkit.extract_windows_artifacts` — takes a mounted
Linux filesystem, copies the high-signal IR/forensic files into an
exports dir, and returns a count dict the caller can summarise.

Coverage:
  /etc/                      passwd, shadow, group, hostname, hosts,
                             ld.so.preload, sudoers[.d/*], rc.local
  /etc/cron.*                crontab + cron.hourly/daily/weekly/monthly
                             + cron.d/*
  /var/spool/cron/           per-user crontabs
  /var/log/                  auth.log*, syslog*, messages*, wtmp, btmp,
                             dpkg.log*, apt/history.log*, audit/audit.log*
  ~/.ssh/                    authorized_keys, known_hosts, config
                             (per user AND root)
  ~/.bash_history etc.       per-user shell + tool histories
  /etc/systemd/system/*.service + /usr/lib/systemd/system/*.service
                             (system unit files)

Everything is copied via `sudo cp` because the FUSE ext4 mount is
root-owned when the operator ran `sudo mount -o ro,loop`. We chown
back to the current user so downstream parsers can read without
escalation.

Pure function. No parsing here — that lives in `linux_triage`.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _child_ci(parent: Path, name: str) -> Path | None:
    """Case-insensitive child lookup. Linux filesystems ARE
    case-sensitive in theory but well-known forensic paths follow
    the canonical case. This mirrors the Windows helper so parent
    code paths can stay parallel."""
    if not parent or not parent.is_dir():
        return None
    target = name.lower()
    try:
        for entry in parent.iterdir():
            if entry.name.lower() == target:
                return entry
    except (PermissionError, OSError):
        return None
    return None


def _resolve(root: Path, *segments: str) -> Path | None:
    cur = root
    for seg in segments:
        cur = _child_ci(cur, seg)
        if cur is None:
            return None
    return cur


def _sudo_ls(d: Path) -> list[str]:
    """Fallback directory listing when the operator's UID can't read
    a root:root 700 dir (e.g. /var/spool/cron/crontabs). Uses
    `sudo ls -1` to get names without elevating our process."""
    try:
        r = subprocess.run(["sudo", "ls", "-1", str(d)],
                            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return []
        return [n.strip() for n in (r.stdout or "").splitlines()
                if n.strip()]
    except Exception:
        return []


def _sudo_is_file(p: Path) -> bool:
    try:
        r = subprocess.run(["sudo", "test", "-f", str(p)],
                            capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _sudo_cp(src: Path, dst: Path) -> bool:
    """Copy src to dst with sudo + chown back to caller. Silent on
    failure; caller decides whether to surface the miss."""
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        r1 = subprocess.run(["sudo", "cp", "--preserve=timestamps",
                              str(src), str(dst)],
                             capture_output=True, text=True, timeout=120)
        if r1.returncode != 0:
            return False
        subprocess.run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}",
                         str(dst)],
                        capture_output=True, text=True, timeout=30)
        return True
    except Exception:
        return False


def _cp_glob(src_dir: Path, dst_dir: Path, pattern: str) -> int:
    """Copy every file matching pattern from src_dir into dst_dir."""
    if not src_dir.is_dir():
        return 0
    n = 0
    try:
        for entry in src_dir.iterdir():
            if not entry.is_file():
                continue
            # Accept simple endswith-style patterns: "*", "*.log", "auth.log*"
            if pattern == "*" or _matches_glob(entry.name, pattern):
                if _sudo_cp(entry, dst_dir / entry.name):
                    n += 1
    except (PermissionError, OSError):
        pass
    return n


def _matches_glob(name: str, pattern: str) -> bool:
    import fnmatch
    return fnmatch.fnmatch(name, pattern)


# ---------------------------------------------------------------------------
# Top-level extractor
# ---------------------------------------------------------------------------

_USER_HISTORY_FILES = (
    ".bash_history", ".zsh_history", ".ash_history",
    ".python_history", ".mysql_history", ".psql_history",
    ".lesshst", ".viminfo", ".sqlite_history", ".rediscli_history",
)

_USER_SSH_FILES = ("authorized_keys", "known_hosts", "config",
                    "id_rsa", "id_ed25519", "id_ecdsa")     # public + private


def extract_linux_artifacts(mount_point: Path,
                              exports_dir: Path) -> dict:
    """Walk a mounted Linux filesystem root, copy high-value
    forensic artifacts into `exports_dir`. Returns an artifact-
    class → count dict the caller summarises into a Finding."""
    out: dict[str, int] = {}
    exports_dir = Path(exports_dir)

    # /etc/ core system config
    etc = _child_ci(mount_point, "etc")
    if etc and etc.is_dir():
        etc_out = exports_dir / "etc"
        for fname in ("passwd", "shadow", "group", "hostname", "hosts",
                       "ld.so.preload", "rc.local", "crontab",
                       "resolv.conf", "fstab", "issue", "os-release",
                       "shells", "sudoers"):
            src = _child_ci(etc, fname)
            if src and src.is_file():
                if _sudo_cp(src, etc_out / fname):
                    out["etc_core_files"] = out.get("etc_core_files", 0) + 1

        # /etc/cron.* directories + /etc/cron.d/*
        for cron_name in ("cron.d", "cron.hourly", "cron.daily",
                           "cron.weekly", "cron.monthly"):
            cron_dir = _child_ci(etc, cron_name)
            if cron_dir and cron_dir.is_dir():
                n = _cp_glob(cron_dir, exports_dir / "etc" / cron_name, "*")
                if n:
                    out["cron_files"] = out.get("cron_files", 0) + n

        # /etc/sudoers.d/*
        sudoers_d = _child_ci(etc, "sudoers.d")
        if sudoers_d and sudoers_d.is_dir():
            n = _cp_glob(sudoers_d, exports_dir / "etc" / "sudoers.d", "*")
            if n:
                out["sudoers_d_files"] = n

        # /etc/systemd/system/*.service (admin-managed unit files)
        sysd_sys = _resolve(etc, "systemd", "system")
        if sysd_sys and sysd_sys.is_dir():
            n = _cp_glob(sysd_sys,
                         exports_dir / "etc" / "systemd" / "system",
                         "*.service")
            if n:
                out["systemd_service_files"] = n

    # /usr/lib/systemd/system/*.service  (vendor unit files —
    # still worth grabbing because attackers sometimes drop
    # camouflaged vendor-named units here)
    usr_sysd = _resolve(mount_point, "usr", "lib", "systemd", "system")
    if usr_sysd and usr_sysd.is_dir():
        n = _cp_glob(usr_sysd,
                     exports_dir / "usr" / "lib" / "systemd" / "system",
                     "*.service")
        if n:
            out["systemd_service_files"] = (
                out.get("systemd_service_files", 0) + n)

    # /var/spool/cron/crontabs/<user> and /var/spool/cron/<user>
    # Note: on some distros this whole subtree is root:root 700, so
    # iterdir raises PermissionError — use `sudo ls` to enumerate.
    var_cron = _resolve(mount_point, "var", "spool", "cron")
    if var_cron and var_cron.is_dir():
        cron_out = exports_dir / "var" / "spool" / "cron"
        for entry_name in _sudo_ls(var_cron):
            entry = var_cron / entry_name
            if entry.is_file() or _sudo_is_file(entry):
                if _sudo_cp(entry, cron_out / entry_name):
                    out["user_crontab_files"] = (
                        out.get("user_crontab_files", 0) + 1)
            elif entry_name == "crontabs":
                for sub_name in _sudo_ls(entry):
                    sub = entry / sub_name
                    if _sudo_cp(sub, cron_out / "crontabs" / sub_name):
                        out["user_crontab_files"] = (
                            out.get("user_crontab_files", 0) + 1)

    # /var/log/ — auth + syslog + package + wtmp/btmp/audit
    var_log = _resolve(mount_point, "var", "log")
    if var_log and var_log.is_dir():
        log_out = exports_dir / "var" / "log"
        for pattern in ("auth.log*", "secure*", "syslog*", "messages*",
                         "kern.log*", "boot.log*", "wtmp", "btmp",
                         "lastlog", "dpkg.log*", "yum.log*",
                         "ufw.log*", "firewalld*"):
            n = _cp_glob(var_log, log_out, pattern)
            if n:
                out["system_log_files"] = (
                    out.get("system_log_files", 0) + n)
        # /var/log/apt/history.log*
        apt = _child_ci(var_log, "apt")
        if apt and apt.is_dir():
            n = _cp_glob(apt, log_out / "apt", "history.log*")
            if n:
                out["apt_history_files"] = n
        # /var/log/audit/audit.log*
        audit = _child_ci(var_log, "audit")
        if audit and audit.is_dir():
            n = _cp_glob(audit, log_out / "audit", "audit.log*")
            if n:
                out["auditd_log_files"] = n
        # /var/log/nginx/access.log + error.log
        for web in ("nginx", "apache2", "httpd"):
            w = _child_ci(var_log, web)
            if w and w.is_dir():
                n = _cp_glob(w, log_out / web, "access.log*") \
                    + _cp_glob(w, log_out / web, "error.log*")
                if n:
                    out["webserver_log_files"] = (
                        out.get("webserver_log_files", 0) + n)
        # /var/log/journal/<machine-id>/*.journal — systemd binary
        # journal. Pull all .journal files so journalctl --file can
        # replay them in the analysis host.
        journal = _child_ci(var_log, "journal")
        if journal and journal.is_dir():
            for machine_dir in journal.iterdir():
                if not machine_dir.is_dir():
                    continue
                n = _cp_glob(machine_dir,
                             log_out / "journal" / machine_dir.name,
                             "*.journal")
                if n:
                    out["systemd_journal_files"] = (
                        out.get("systemd_journal_files", 0) + n)

    # /var/run/utmp — currently-active sessions (may be stale on an
    # acquired image; copy anyway, cheap)
    var_run_utmp = _resolve(mount_point, "var", "run", "utmp")
    if var_run_utmp and var_run_utmp.is_file():
        dst = exports_dir / "var" / "run" / "utmp"
        if _sudo_cp(var_run_utmp, dst):
            out["utmp_file"] = 1

    # Per-user artifacts — shell histories + SSH dir
    # Roots: /home/<user> AND /root
    user_dirs: list[Path] = []
    home = _child_ci(mount_point, "home")
    if home and home.is_dir():
        user_dirs.extend(d for d in home.iterdir() if d.is_dir())
    root = _child_ci(mount_point, "root")
    if root and root.is_dir():
        user_dirs.append(root)

    for user_dir in user_dirs:
        user_out = exports_dir / "home" / user_dir.name
        for hist_name in _USER_HISTORY_FILES:
            src = _child_ci(user_dir, hist_name)
            if src and src.is_file():
                if _sudo_cp(src, user_out / hist_name):
                    out["user_history_files"] = (
                        out.get("user_history_files", 0) + 1)
        ssh_dir = _child_ci(user_dir, ".ssh")
        if ssh_dir and ssh_dir.is_dir():
            for fname in _USER_SSH_FILES:
                src = _child_ci(ssh_dir, fname)
                if src and src.is_file():
                    if _sudo_cp(src, user_out / ".ssh" / fname):
                        out["user_ssh_files"] = (
                            out.get("user_ssh_files", 0) + 1)

    return out


__all__ = ["extract_linux_artifacts"]
