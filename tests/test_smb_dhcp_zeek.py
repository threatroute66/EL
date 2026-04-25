"""SMB2 write detector + DHCP option-55 fingerprint over Zeek logs.

Closes gap-doc Network-depth bullets:
- "SMB2 write-operation detection" (line 149)
- "DHCP option 55 fingerprinting" (line 150)
"""
from pathlib import Path

import pytest

from el.skills import smb_dhcp_zeek as sd


def _write_zeek_tsv(path: Path, fields: list[str], rows: list[list[str]]):
    """Materialise a Zeek-shape TSV: `#fields <tabbed names>` then
    one row per line, tab-delimited."""
    lines = ["#separator \\x09",
             "#fields\t" + "\t".join(fields)]
    lines.extend("\t".join(r) for r in rows)
    path.write_text("\n".join(lines) + "\n")


# --- SMB writes ---------------------------------------------------------

def test_smb_write_action_filter(tmp_path):
    _write_zeek_tsv(
        tmp_path / "smb_files.log",
        ["ts", "uid", "id.orig_h", "id.resp_h", "action", "path",
         "size", "user"],
        [
            ["1.0", "C1", "10.0.0.5", "10.0.0.10", "SMB::FILE_OPEN",
             "ADMIN$\\foo", "0", "DOMAIN\\admin"],
            ["2.0", "C2", "10.0.0.5", "10.0.0.10", "SMB::FILE_WRITE",
             "ADMIN$\\evil.exe", "1024", "DOMAIN\\admin"],
            ["3.0", "C3", "10.0.0.5", "10.0.0.10", "SMB::FILE_RENAME",
             "ADMIN$\\evil.exe", "1024", "DOMAIN\\admin"],
            ["4.0", "C4", "10.0.0.42", "10.0.0.10", "SMB::FILE_DELETE",
             "C$\\Logs\\trail.log", "0", "DOMAIN\\bob"],
        ],
    )
    hits = sd.detect_smb_writes(tmp_path)
    assert len(hits) == 3   # FILE_OPEN dropped
    actions = sorted(h.action for h in hits)
    assert actions == ["SMB::FILE_DELETE", "SMB::FILE_RENAME",
                        "SMB::FILE_WRITE"]
    by_path = {h.path: h for h in hits}
    assert by_path["ADMIN$\\evil.exe"].size == 1024
    assert by_path["C$\\Logs\\trail.log"].user == "DOMAIN\\bob"


def test_smb_writes_min_count(tmp_path):
    _write_zeek_tsv(
        tmp_path / "smb_files.log",
        ["id.orig_h", "id.resp_h", "action", "path", "size", "user"],
        [
            # One write from 10.0.0.5 — below min_count
            ["10.0.0.5", "10.0.0.10", "SMB::FILE_WRITE", "x", "1", ""],
            # Three writes from 10.0.0.42 — passes
            ["10.0.0.42", "10.0.0.10", "SMB::FILE_WRITE", "a", "1", ""],
            ["10.0.0.42", "10.0.0.10", "SMB::FILE_WRITE", "b", "1", ""],
            ["10.0.0.42", "10.0.0.10", "SMB::FILE_WRITE", "c", "1", ""],
        ],
    )
    hits = sd.detect_smb_writes(tmp_path, min_count=3)
    assert all(h.src == "10.0.0.42" for h in hits)
    assert len(hits) == 3


def test_smb_no_log_file_returns_empty(tmp_path):
    assert sd.detect_smb_writes(tmp_path) == []


# --- DHCP option-55 fingerprint -----------------------------------------

def test_dhcp_fingerprint_known_signature(tmp_path):
    _write_zeek_tsv(
        tmp_path / "dhcp.log",
        ["mac", "requested_addr", "client_fqdn", "params_list"],
        [
            ["aa:bb:cc:dd:ee:ff", "10.0.0.50", "DESKTOP-X",
             "1,15,3,6,44,46,47,31,33,121,249,43"],
            ["11:22:33:44:55:66", "10.0.0.51", "iPhone",
             "1,33,3,6,15,28,51,58,59,119,121"],
        ],
    )
    fps = sd.fingerprint_dhcp(tmp_path)
    assert any(f.likely_os == "Windows 10 / 11" for f in fps)
    assert any(f.likely_os == "iOS" for f in fps)


def test_dhcp_fingerprint_unknown_pattern(tmp_path):
    _write_zeek_tsv(
        tmp_path / "dhcp.log",
        ["mac", "requested_addr", "client_fqdn", "params_list"],
        [["aa:bb", "10.0.0.99", "weird", "99,98,97"]],
    )
    fps = sd.fingerprint_dhcp(tmp_path)
    # Still surfaces — empty likely_os just means no fingerprint match
    assert len(fps) == 1
    assert fps[0].params_list == "99,98,97"
    assert fps[0].likely_os == ""


def test_dhcp_dedup_repeat_dhcp_renewals(tmp_path):
    """Hourly DHCP renewals from the same client emit identical
    entries; the deduper keys on (mac, ip, params) so we don't flood
    the ledger."""
    _write_zeek_tsv(
        tmp_path / "dhcp.log",
        ["mac", "requested_addr", "client_fqdn", "params_list"],
        [["aa:bb", "10.0.0.50", "X", "1,15,3,6,44,46,47,31,33,121,249,43"]] * 5,
    )
    fps = sd.fingerprint_dhcp(tmp_path)
    assert len(fps) == 1


def test_dhcp_no_log_file_returns_empty(tmp_path):
    assert sd.fingerprint_dhcp(tmp_path) == []
