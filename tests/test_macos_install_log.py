"""macOS install.log parser tests — synthetic log mirroring real lines."""
import gzip
from pathlib import Path

import pytest

from el.skills import macos_install_log as il


_SAMPLE = """\
2025-11-20 09:29:24-08 MacBook-Pro installd[1593]: PackageKit: Extracting com.obrhoff.daftcloud.pkg
2025-11-20 09:29:25-08 MacBook-Pro installd[1593]: Installed "DaftCloud" (4.1.8)
2025-12-09 16:44:52-05 MacBookPro-1659 installd[609]: PackageKit: 7.8s elapsed install time
2025-12-09 16:44:54-05 MacBookPro-1659 Installer[1254]:     -total-      10.32 seconds
2025-12-09 16:44:54-05 MacBookPro-1659 Installer[1254]: Installed "Google Drive" ()
this line has no timestamp and must be skipped
2025-12-14 09:54:24-05 Alexs-MacBook-Pro installd[275]: Installed "Google Docs" (1.0)
"""


def _write(tmp_path: Path) -> Path:
    p = tmp_path / "install.log"
    p.write_text(_SAMPLE)
    return p


def test_installed_apps_and_utc(tmp_path):
    run = il.parse(_write(tmp_path))
    names = {a.name: a for a in run.installed_apps}
    assert set(names) == {"DaftCloud", "Google Drive", "Google Docs"}
    assert names["DaftCloud"].version == "4.1.8"
    # 2025-11-20 09:29:25-08  ->  UTC = +8h = 17:29:25
    assert names["DaftCloud"].timestamp_utc == "2025-11-20 17:29:25"
    # 2025-12-09 16:44:54-05  ->  UTC = +5h = 21:44:54
    assert names["Google Drive"].timestamp_utc == "2025-12-09 21:44:54"


def test_durations_captures_installer_total(tmp_path):
    run = il.parse(_write(tmp_path))
    totals = [d for d in run.durations if d.kind == "installer_total"]
    elapsed = [d for d in run.durations if d.kind == "packagekit_elapsed"]
    assert any(abs(d.seconds - 10.32) < 1e-9 for d in totals)
    assert any(abs(d.seconds - 7.8) < 1e-9 for d in elapsed)


def test_tz_and_host_changes_detected(tmp_path):
    run = il.parse(_write(tmp_path))
    assert run.tz_changed                       # -08 then -05
    assert {o for o, _ in run.tz_offsets} == {"-08", "-05"}
    assert run.host_changed                     # 3 distinct hostnames
    assert {h for h, _ in run.hosts} == {
        "MacBook-Pro", "MacBookPro-1659", "Alexs-MacBook-Pro"}


def test_non_matching_line_skipped(tmp_path):
    run = il.parse(_write(tmp_path))
    assert run.line_count == 7
    assert run.parsed_count == 6                # the no-timestamp line skipped


def test_output_jsonl_and_evidence(tmp_path):
    run = il.parse(_write(tmp_path), output_dir=tmp_path / "out")
    assert run.output_path.is_file()
    assert run.output_sha256 and run.output_sha256 != "0" * 64
    ev = run.as_evidence()
    assert ev.extracted_facts["installed_app_count"] == 3
    assert ev.extracted_facts["tz_changed"] is True
    assert ev.tool == "el.macos_install_log"


def test_gzip_rotated_log(tmp_path):
    p = tmp_path / "install.log.0.gz"
    with gzip.open(p, "wt", encoding="utf-8") as f:
        f.write(_SAMPLE)
    run = il.parse(p)
    assert len(run.installed_apps) == 3


def test_find_install_logs(tmp_path):
    root = tmp_path / "fs"
    logdir = root / "private" / "var" / "log"
    logdir.mkdir(parents=True)
    (logdir / "install.log").write_text(_SAMPLE)
    (logdir / "install.log.0.gz").write_bytes(b"\x1f\x8b")
    found = il.find_install_logs(root)
    assert (logdir / "install.log") in found
    assert (logdir / "install.log.0.gz") in found
    # canonical install.log comes first
    assert found[0] == logdir / "install.log"


def test_missing_log_raises(tmp_path):
    with pytest.raises(il.MacOSInstallLogError):
        il.parse(tmp_path / "nope.log")
