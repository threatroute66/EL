"""Parse the acquirer-vs-target clock skew out of `ewfinfo` stdout.

EnCase / EWF (E01) images record two timestamps in their header:

  Acquisition date:  Mon Jan 31 21:38:29 2011   (examiner's wall clock)
  System date:       Mon Jan 31 21:38:29 2011   (target machine's RTC)

Both are written by libewf in *the acquirer's local timezone* with no
TZ tag, so neither value is independently anchored to UTC. The DELTA
between them, however, IS timezone-independent — if both are "5pm"
the target was 0s skewed; if Acquisition is "5pm" and System is
"4pm", the target's clock was 1 hour behind the examiner's reference
regardless of where the examiner was sitting.

That delta is the first calibration point analysts need — for FAT /
EXIF / Office-metadata values that get stored in local time with no
TZ record, the System date tells you the target's *configured* time
at acquisition; the delta tells you whether that configured time was
trustworthy.

This parser is read-only on the stdout text. The dates are parsed in
naive form (no TZ assumed) — only the delta in seconds is returned
as a forensically meaningful quantity. We deliberately do NOT try to
infer the acquirer's TZ.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


# libewf prints `%a %b %e %H:%M:%S %Y` — same as asctime(3).
_DATE_FMT = "%a %b %d %H:%M:%S %Y"


@dataclass
class EwfSkew:
    acquisition_date_raw: str       # exact stdout substring (no TZ tag)
    system_date_raw: str
    acquisition_dt: datetime | None  # naive
    system_dt: datetime | None       # naive
    skew_seconds: int | None         # acq - sys (positive = target behind)

    @property
    def have_skew(self) -> bool:
        return self.skew_seconds is not None


_FIELD_RE = re.compile(
    r"^\s*(Acquisition date|System date)\s*:\s*(.+?)\s*$",
    re.MULTILINE,
)


def _parse_date(raw: str) -> datetime | None:
    """libewf double-pads single-digit day-of-month with a space — strptime
    chokes on `Jan  1`. Collapse to single space and let asctime parse it."""
    cleaned = re.sub(r"\s+", " ", raw).strip()
    try:
        return datetime.strptime(cleaned, _DATE_FMT)
    except ValueError:
        return None


def parse(stdout_text: str) -> EwfSkew:
    """Walk `ewfinfo` stdout, extract the two header dates, compute the
    delta in seconds. Returns an EwfSkew with None timestamps + None
    skew when either date is missing or unparseable — caller decides
    how to surface that (probably a `confidence='insufficient'`
    finding noting the acquirer image had no acquisition-time header)."""
    fields: dict[str, str] = {}
    for m in _FIELD_RE.finditer(stdout_text):
        # First occurrence wins — libewf only emits each once per file
        fields.setdefault(m.group(1), m.group(2))
    acq_raw = fields.get("Acquisition date", "")
    sys_raw = fields.get("System date", "")
    acq_dt = _parse_date(acq_raw) if acq_raw else None
    sys_dt = _parse_date(sys_raw) if sys_raw else None
    skew: int | None = None
    if acq_dt is not None and sys_dt is not None:
        skew = int((acq_dt - sys_dt).total_seconds())
    return EwfSkew(
        acquisition_date_raw=acq_raw,
        system_date_raw=sys_raw,
        acquisition_dt=acq_dt,
        system_dt=sys_dt,
        skew_seconds=skew,
    )


def parse_file(stdout_path: Path) -> EwfSkew:
    """Convenience wrapper — read stdout file written by sk.ewfinfo()."""
    try:
        text = stdout_path.read_text(errors="ignore")
    except OSError:
        return EwfSkew("", "", None, None, None)
    return parse(text)


__all__ = ["EwfSkew", "parse", "parse_file"]
