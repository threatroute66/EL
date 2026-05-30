"""macOS install.log parser — software-install timeline.

``/private/var/log/install.log`` is the system installer's append-only audit
trail: every ``installd`` / ``Installer`` / ``softwareupdated`` action lands
here with a local timestamp + tz offset + hostname. Structured, it yields:

  * **Installed applications** — name + version + UTC time
    (``Installed "DaftCloud" (4.1.8)``).
  * **Install durations** — the Installer ``-total-  10.32 seconds`` summary
    and PackageKit ``Ns elapsed install time`` lines.
  * **Timezone changes** — the per-line offset (``-08`` → ``-05``) reveals the
    device moving across zones, useful for normalising every other artifact.
  * **Hostname changes** — successive host fields (a rename / re-provision).

No SIFT-bundled CLI structures install.log into a timeline (it is free text),
so this is a native parser in the same spirit as the utmp / W3C log parsers.
Read-only: the evidence file is only ever opened for reading.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path


class MacOSInstallLogError(Exception):
    pass


# 2025-12-09 16:44:52-05 MacBookPro-1659 installd[609]: PackageKit: ...
_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"(?P<off>[+-]\d{2}(?::?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^\[\]:]+?)(?:\[(?P<pid>\d+)\])?:\s"
    r"(?P<msg>.*)$"
)

_INSTALLED_RE = re.compile(r'Installed "([^"]+)" \(([^)]*)\)')
_TOTAL_SECONDS_RE = re.compile(r"-total-\s+([\d.]+)\s+seconds")
_ELAPSED_RE = re.compile(r"([\d.]+)s elapsed install time")


def _to_utc(local_str: str, offset_str: str) -> str:
    """Convert ``YYYY-MM-DD HH:MM:SS`` + ``-08`` / ``-0800`` / ``-05:00`` to a
    UTC ``YYYY-MM-DD HH:MM:SS`` string. Returns '' on malformed input."""
    try:
        dt = datetime.strptime(local_str, "%Y-%m-%d %H:%M:%S")
        sign = -1 if offset_str[0] == "-" else 1
        digits = offset_str[1:].replace(":", "")
        hh = int(digits[:2])
        mm = int(digits[2:4]) if len(digits) >= 4 else 0
        delta = sign * timedelta(hours=hh, minutes=mm)
        return (dt - delta).strftime("%Y-%m-%d %H:%M:%S")  # utc = local - off
    except (ValueError, IndexError):
        return ""


@dataclass
class InstalledApp:
    name: str
    version: str
    timestamp_utc: str
    tz_offset: str
    host: str = ""

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class InstallDuration:
    seconds: float
    kind: str            # "installer_total" | "packagekit_elapsed"
    timestamp_utc: str
    raw: str

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class InstallLogRun:
    log_path: Path
    installed_apps: list[InstalledApp] = field(default_factory=list)
    durations: list[InstallDuration] = field(default_factory=list)
    tz_offsets: list[tuple[str, str]] = field(default_factory=list)
    hosts: list[tuple[str, str]] = field(default_factory=list)
    line_count: int = 0
    parsed_count: int = 0
    output_path: Path | None = None
    output_sha256: str = ""

    @property
    def tz_changed(self) -> bool:
        return len({o for o, _ in self.tz_offsets}) > 1

    @property
    def host_changed(self) -> bool:
        return len({h for h, _ in self.hosts}) > 1

    def as_evidence(self, *, facts: dict | None = None):
        from el.schemas.finding import EvidenceItem
        extra = facts or {}
        return EvidenceItem(
            tool="el.macos_install_log", version="0.1.0",
            command=f"parse install.log -- {self.log_path}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.log_path),
            extracted_facts={
                "log_path": str(self.log_path),
                "line_count": self.line_count,
                "parsed_count": self.parsed_count,
                "installed_app_count": len(self.installed_apps),
                "duration_event_count": len(self.durations),
                "tz_offsets": [o for o, _ in self.tz_offsets],
                "tz_changed": self.tz_changed,
                "hosts": [h for h, _ in self.hosts],
                "host_changed": self.host_changed,
                **extra,
            },
        )


def find_install_logs(macos_root: Path) -> list[Path]:
    """Return install.log plus any rotated siblings (install.log.0[.gz] …)
    under an extracted macOS filesystem, newest-canonical first."""
    macos_root = Path(macos_root)
    logdir = None
    for rel in (("private", "var", "log"), ("var", "log")):
        d = macos_root.joinpath(*rel)
        if d.is_dir():
            logdir = d
            break
    if logdir is None:
        # macos_root may itself be the log dir or the file.
        if (macos_root / "install.log").is_file():
            logdir = macos_root
        elif macos_root.name.startswith("install.log") and macos_root.is_file():
            return [macos_root]
        else:
            return []
    out = []
    if (logdir / "install.log").is_file():
        out.append(logdir / "install.log")
    out.extend(sorted(p for p in logdir.glob("install.log.*") if p.is_file()))
    return out


def _open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def parse(log_path: Path, output_dir: Path | None = None) -> InstallLogRun:
    """Parse a single install.log (gzip-aware) into an :class:`InstallLogRun`.

    Writes a JSONL dump of installed apps + durations under *output_dir* when
    given. Raises :class:`MacOSInstallLogError` if the file is unreadable.
    """
    log_path = Path(log_path)
    if not log_path.is_file():
        raise MacOSInstallLogError(f"install.log not found: {log_path}")

    run = InstallLogRun(log_path=log_path)
    seen_offsets: set[str] = set()
    seen_hosts: set[str] = set()

    try:
        with _open_text(log_path) as f:
            for line in f:
                run.line_count += 1
                m = _LINE_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                run.parsed_count += 1
                off = m.group("off")
                host = m.group("host")
                ts_utc = _to_utc(m.group("ts"), off)
                msg = m.group("msg")

                if off not in seen_offsets:
                    seen_offsets.add(off)
                    run.tz_offsets.append((off, ts_utc))
                if host not in seen_hosts:
                    seen_hosts.add(host)
                    run.hosts.append((host, ts_utc))

                im = _INSTALLED_RE.search(msg)
                if im:
                    run.installed_apps.append(InstalledApp(
                        name=im.group(1), version=im.group(2),
                        timestamp_utc=ts_utc, tz_offset=off, host=host))
                    continue

                tm = _TOTAL_SECONDS_RE.search(msg)
                if tm:
                    run.durations.append(InstallDuration(
                        seconds=float(tm.group(1)), kind="installer_total",
                        timestamp_utc=ts_utc, raw=msg.strip()[:200]))
                    continue
                em = _ELAPSED_RE.search(msg)
                if em:
                    run.durations.append(InstallDuration(
                        seconds=float(em.group(1)), kind="packagekit_elapsed",
                        timestamp_utc=ts_utc, raw=msg.strip()[:200]))
    except OSError as e:
        raise MacOSInstallLogError(f"cannot read {log_path}: {e}") from e

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "install_log_timeline.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for a in run.installed_apps:
                f.write(json.dumps({"type": "installed_app", **a.as_dict()},
                                   sort_keys=True) + "\n")
            for d in run.durations:
                f.write(json.dumps({"type": "duration", **d.as_dict()},
                                   sort_keys=True) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run
