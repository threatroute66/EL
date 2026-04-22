"""Skill: macOS disk-artifact extraction.

Parallel to `linux_artifacts` and `sleuthkit.extract_windows_artifacts`.
Walks a mounted APFS Data volume (Big Sur splits system into a signed
read-only System volume + Data volume; user data + most forensic
artifacts live in the Data volume) and sudo-cp's the IR-relevant
files into `exports_dir`.

Coverage (V1, Big Sur / Monterey / Ventura baseline):

  /private/etc/               passwd, master.passwd, sudoers[.d],
                              hosts, resolv.conf, shells, ssh/
                              sshd_config
  /Library/LaunchAgents/*     system-wide user-session agents
  /Library/LaunchDaemons/*    system-wide root daemons
  /Library/StartupItems/      legacy startup persistence
  /Users/<user>/Library/
    LaunchAgents/*            per-user persistence (most common
                              attacker primitive)
    Safari/History.db         browser history
    Safari/Downloads.plist    recent downloads
    Application Support/
      Knowledge/knowledgeC.db app usage + focus events (CTF gold)
    Preferences/
      com.apple.loginitems.plist          login-time items
      com.apple.LaunchServices.QuarantineEventsV2  download provenance
  /Users/<user>/.bash_history
  /Users/<user>/.zsh_history
  /Users/<user>/.ssh/authorized_keys + known_hosts + config
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _child_ci(parent: Path, name: str) -> Path | None:
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
    try:
        r = subprocess.run(["sudo", "ls", "-1", str(d)],
                            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return []
        return [n.strip() for n in (r.stdout or "").splitlines()
                if n.strip()]
    except Exception:
        return []


def _sudo_cp(src: Path, dst: Path) -> bool:
    """Copy src→dst. Plain shutil first; sudo only when src is not
    readable as the current user. Saves ~500ms/file on HGFS."""
    import shutil
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        if os.access(src, os.R_OK):
            try:
                shutil.copy2(str(src), str(dst))
                return True
            except (PermissionError, OSError):
                pass
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
    if not src_dir.is_dir():
        return 0
    import fnmatch
    n = 0
    try:
        for entry in src_dir.iterdir():
            if not entry.is_file():
                continue
            if pattern == "*" or fnmatch.fnmatch(entry.name, pattern):
                if _sudo_cp(entry, dst_dir / entry.name):
                    n += 1
    except (PermissionError, OSError):
        pass
    return n


_USER_HISTORY_FILES = (
    ".bash_history", ".zsh_history", ".python_history",
    ".mysql_history", ".psql_history", ".lesshst", ".viminfo",
)

_USER_SSH_FILES = ("authorized_keys", "known_hosts", "config",
                    "id_rsa", "id_ed25519", "id_ecdsa")


def extract_macos_artifacts(mount_point: Path,
                              exports_dir: Path) -> dict:
    """Walk a mounted macOS Data volume, copy IR artifacts. Returns
    artifact-class → count dict."""
    out: dict[str, int] = {}
    exports_dir = Path(exports_dir)

    # /private/etc/ — passwd / sudoers / hosts / ssh server config
    private_etc = _resolve(mount_point, "private", "etc")
    if private_etc and private_etc.is_dir():
        etc_out = exports_dir / "private" / "etc"
        for fname in ("passwd", "master.passwd", "hosts", "resolv.conf",
                       "shells", "sudoers", "crontab", "ttys",
                       "launchd.conf", "security/audit_control",
                       "security/audit_user"):
            src_parts = fname.split("/")
            src = private_etc
            for part in src_parts:
                src = _child_ci(src, part) if src else None
                if src is None:
                    break
            if src and src.is_file():
                dst = etc_out / fname
                if _sudo_cp(src, dst):
                    out["etc_core_files"] = out.get("etc_core_files", 0) + 1
        # /private/etc/sudoers.d/
        sudoers_d = _child_ci(private_etc, "sudoers.d")
        if sudoers_d and sudoers_d.is_dir():
            n = _cp_glob(sudoers_d, etc_out / "sudoers.d", "*")
            if n:
                out["sudoers_d_files"] = n
        # /private/etc/ssh/*
        ssh_etc = _child_ci(private_etc, "ssh")
        if ssh_etc and ssh_etc.is_dir():
            n = _cp_glob(ssh_etc, etc_out / "ssh", "*")
            if n:
                out["etc_ssh_files"] = n

    # /Library/LaunchAgents + /Library/LaunchDaemons (system-wide persistence)
    lib = _child_ci(mount_point, "Library")
    if lib and lib.is_dir():
        for la_name in ("LaunchAgents", "LaunchDaemons", "StartupItems"):
            la = _child_ci(lib, la_name)
            if la and la.is_dir():
                n = _cp_glob(la, exports_dir / "Library" / la_name, "*.plist")
                if n:
                    out["system_launch_plists"] = (
                        out.get("system_launch_plists", 0) + n)
                if la_name == "StartupItems":
                    # StartupItems are directories, not plists. List names.
                    for entry in _sudo_ls(la):
                        dst = (exports_dir / "Library" / la_name /
                               entry / ".keep")
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        dst.write_text(f"StartupItem: {entry}\n")

    # Per-user artifacts under /Users/<user>/
    users_root = _child_ci(mount_point, "Users")
    if users_root and users_root.is_dir():
        for user_dir in users_root.iterdir():
            if not user_dir.is_dir():
                continue
            if user_dir.name.lower() in ("shared", "guest", ".localized"):
                continue
            user_out = exports_dir / "Users" / user_dir.name
            # Shell + tool histories
            for hist_name in _USER_HISTORY_FILES:
                src = _child_ci(user_dir, hist_name)
                if src and src.is_file():
                    if _sudo_cp(src, user_out / hist_name):
                        out["user_history_files"] = (
                            out.get("user_history_files", 0) + 1)
            # SSH dir
            ssh_dir = _child_ci(user_dir, ".ssh")
            if ssh_dir and ssh_dir.is_dir():
                for fname in _USER_SSH_FILES:
                    src = _child_ci(ssh_dir, fname)
                    if src and src.is_file():
                        if _sudo_cp(src, user_out / ".ssh" / fname):
                            out["user_ssh_files"] = (
                                out.get("user_ssh_files", 0) + 1)
            # ~/Library/LaunchAgents/*.plist
            u_lib = _child_ci(user_dir, "Library")
            if u_lib and u_lib.is_dir():
                u_la = _child_ci(u_lib, "LaunchAgents")
                if u_la and u_la.is_dir():
                    n = _cp_glob(u_la, user_out / "Library" / "LaunchAgents",
                                 "*.plist")
                    if n:
                        out["user_launch_plists"] = (
                            out.get("user_launch_plists", 0) + n)
                # Safari / History.db + Downloads.plist
                safari = _child_ci(u_lib, "Safari")
                if safari and safari.is_dir():
                    for fname in ("History.db", "Downloads.plist",
                                   "Bookmarks.plist",
                                   "TopSites.plist"):
                        src = _child_ci(safari, fname)
                        if src and src.is_file():
                            if _sudo_cp(src, user_out / "Library" /
                                        "Safari" / fname):
                                out["safari_files"] = (
                                    out.get("safari_files", 0) + 1)
                # KnowledgeC DB
                kc = _resolve(u_lib, "Application Support", "Knowledge",
                               "knowledgeC.db")
                if kc and kc.is_file():
                    if _sudo_cp(kc, user_out / "Library" /
                                "Application Support" / "Knowledge" /
                                "knowledgeC.db"):
                        out["knowledgec_files"] = (
                            out.get("knowledgec_files", 0) + 1)
                # Quarantine events
                qe = _resolve(u_lib, "Preferences",
                               "com.apple.LaunchServices.QuarantineEventsV2")
                if qe and qe.is_file():
                    if _sudo_cp(qe, user_out / "Library" / "Preferences" /
                                qe.name):
                        out["quarantine_files"] = (
                            out.get("quarantine_files", 0) + 1)
                # Login items plist
                li = _resolve(u_lib, "Preferences",
                               "com.apple.loginitems.plist")
                if li and li.is_file():
                    if _sudo_cp(li, user_out / "Library" / "Preferences" /
                                li.name):
                        out["loginitems_files"] = (
                            out.get("loginitems_files", 0) + 1)

    # /var/log/ (accessible system + install logs; Unified Log is
    # binary-only and skipped in V1 — needs log(1) on a mac host).
    var_log = _resolve(mount_point, "private", "var", "log")
    if var_log and var_log.is_dir():
        log_out = exports_dir / "var" / "log"
        for pattern in ("system.log*", "install.log*", "wifi.log*",
                         "appstore.log*", "ftp.log*", "authd.log*"):
            n = _cp_glob(var_log, log_out, pattern)
            if n:
                out["system_log_files"] = (
                    out.get("system_log_files", 0) + n)
        # /var/log/secure.log (Big Sur+; auth + sudo)
        secure = _child_ci(var_log, "secure.log")
        if secure and secure.is_file():
            if _sudo_cp(secure, log_out / "secure.log"):
                out["system_log_files"] = (
                    out.get("system_log_files", 0) + 1)

    return out


__all__ = ["extract_macos_artifacts"]
