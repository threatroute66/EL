"""IIS W3C log parser + detector unit tests.

Every detector must fire on a realistic-shape log fixture and stay
silent on benign traffic. Fixtures are crafted minimally but use real
IIS 10 field ordering.
"""
from pathlib import Path

from el.skills.iis_w3c import scan_path, scan_tree


# Representative IIS 10 header that 90% of Windows-Server logs use.
_HEADER = (
    "#Software: Microsoft Internet Information Services 10.0\n"
    "#Version: 1.0\n"
    "#Date: 2025-01-01 00:00:00\n"
    "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query "
    "s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status "
    "sc-substatus sc-win32-status time-taken\n"
)


def _write_log(tmp: Path, rows: list[str]) -> Path:
    p = tmp / "u_ex250101.log"
    p.write_text(_HEADER + "\n".join(rows) + "\n")
    return p


# --- webshell URI shape ----------------------------------------------------

def test_webshell_basename_flagged(tmp_path):
    log = _write_log(tmp_path, [
        "2025-01-01 00:00:01 10.0.0.1 POST /uploads/shell.aspx - 443 "
        "- 203.0.113.10 curl/7.86 - 200 0 0 120",
    ])
    result = scan_path(log)
    ids = [h.pattern_id for h in result.hits]
    assert "W3C_WEBSHELL_URI_SHAPE" in ids
    hit = next(h for h in result.hits
               if h.pattern_id == "W3C_WEBSHELL_URI_SHAPE")
    assert "shell.aspx" in hit.matches[0]
    assert "T1505.003" in [t for t, _ in hit.attack_techniques]


def test_webshell_query_string_flagged(tmp_path):
    log = _write_log(tmp_path, [
        "2025-01-01 00:00:01 10.0.0.1 GET /api/run.aspx cmd=whoami "
        "443 - 203.0.113.10 Mozilla/5.0 - 200 0 0 120",
    ])
    result = scan_path(log)
    assert any(h.pattern_id == "W3C_WEBSHELL_URI_SHAPE"
               for h in result.hits)


def test_path_traversal_query_flagged(tmp_path):
    log = _write_log(tmp_path, [
        "2025-01-01 00:00:01 10.0.0.1 GET /index.php "
        "file=../../etc/passwd 443 - 203.0.113.10 curl/7.86 - 200 0 0 1",
    ])
    result = scan_path(log)
    assert any(h.pattern_id == "W3C_WEBSHELL_URI_SHAPE"
               for h in result.hits)


# --- scripted client ------------------------------------------------------

def test_offensive_ua_always_flagged(tmp_path):
    log = _write_log(tmp_path, [
        # sqlmap — strong UA, always flag.
        "2025-01-01 00:00:01 10.0.0.1 GET /index.aspx - 443 - "
        "203.0.113.10 sqlmap/1.7 - 404 0 0 1",
    ])
    result = scan_path(log)
    assert any(h.pattern_id == "W3C_SCRIPTED_CLIENT_OFFENSIVE"
               for h in result.hits)


def test_generic_scripted_ua_only_when_200(tmp_path):
    log = _write_log(tmp_path, [
        # curl → 200: flagged
        "2025-01-01 00:00:01 10.0.0.1 GET /index.aspx - 443 - "
        "203.0.113.10 curl/7.86.0 - 200 0 0 1",
        # go-http-client → 404: NOT flagged (one-off 404 isn't signal)
        "2025-01-01 00:00:02 10.0.0.1 GET /admin - 443 - "
        "203.0.113.11 go-http-client/1.1 - 404 0 0 1",
    ])
    result = scan_path(log)
    hit = next(h for h in result.hits
               if h.pattern_id == "W3C_SCRIPTED_CLIENT_GENERIC")
    assert "curl" in hit.matches[0].lower()
    assert all("404" not in m for m in hit.matches)


# --- admin URI hit --------------------------------------------------------

def test_admin_path_from_public_ip_flagged(tmp_path):
    log = _write_log(tmp_path, [
        "2025-01-01 00:00:01 10.0.0.1 GET /wp-admin/ - 443 - "
        "203.0.113.10 Mozilla/5.0 - 200 0 0 1",
    ])
    result = scan_path(log)
    assert any(h.pattern_id == "W3C_ADMIN_URI_HIT"
               for h in result.hits)


def test_admin_path_from_private_ip_not_flagged(tmp_path):
    # Internal admin access is expected; don't alert.
    log = _write_log(tmp_path, [
        "2025-01-01 00:00:01 10.0.0.1 GET /wp-admin/ - 443 - "
        "10.0.0.50 Mozilla/5.0 - 200 0 0 1",
    ])
    result = scan_path(log)
    assert not any(h.pattern_id == "W3C_ADMIN_URI_HIT"
                   for h in result.hits)


def test_admin_path_404_not_flagged(tmp_path):
    # 404 means the guard is on; not interesting.
    log = _write_log(tmp_path, [
        "2025-01-01 00:00:01 10.0.0.1 GET /wp-admin/ - 443 - "
        "203.0.113.10 Mozilla/5.0 - 404 0 0 1",
    ])
    result = scan_path(log)
    assert not any(h.pattern_id == "W3C_ADMIN_URI_HIT"
                   for h in result.hits)


# --- upload POST burst ----------------------------------------------------

def test_upload_burst_fires_on_3_plus_posts_with_2xx(tmp_path):
    rows = [
        (f"2025-01-01 00:00:0{i} 10.0.0.1 POST /upload.aspx - 443 - "
         f"203.0.113.10 curl/7.86 - {200 if i < 5 else 302} 0 0 1")
        for i in range(1, 6)
    ]
    result = _write_log(tmp_path, rows)
    r = scan_path(result)
    assert any(h.pattern_id == "W3C_UPLOAD_POST_BURST"
               for h in r.hits)


def test_upload_burst_not_fired_if_no_2xx(tmp_path):
    # Five POSTs, all 403 — upload attempt failed every time, not a
    # successful web-shell interaction.
    rows = [
        f"2025-01-01 00:00:0{i} 10.0.0.1 POST /upload.aspx - 443 - "
        f"203.0.113.10 curl/7.86 - 403 0 0 1"
        for i in range(1, 6)
    ]
    log = _write_log(tmp_path, rows)
    r = scan_path(log)
    assert not any(h.pattern_id == "W3C_UPLOAD_POST_BURST"
                   for h in r.hits)


# --- verb tunnel ---------------------------------------------------------

def test_verb_tunnel_fires_on_heavy_volume(tmp_path):
    rows = [
        f"2025-01-01 00:00:{i:02d} 10.0.0.1 PROPFIND /dav/file{i} - "
        f"443 - 203.0.113.10 Microsoft-WebDAV-MiniRedir - 207 0 0 1"
        for i in range(60)
    ]
    log = _write_log(tmp_path, rows)
    r = scan_path(log)
    assert any(h.pattern_id == "W3C_VERB_TUNNEL" for h in r.hits)


def test_verb_tunnel_not_fired_on_low_volume(tmp_path):
    rows = [
        f"2025-01-01 00:00:{i:02d} 10.0.0.1 OPTIONS / - "
        f"443 - 203.0.113.10 curl/7.86 - 200 0 0 1"
        for i in range(5)
    ]
    log = _write_log(tmp_path, rows)
    r = scan_path(log)
    assert not any(h.pattern_id == "W3C_VERB_TUNNEL" for h in r.hits)


# --- header robustness ---------------------------------------------------

def test_fields_header_re_read_midfile(tmp_path):
    """IIS restarts re-emit #Fields: mid-file. Parser must pick up the
    new field order so column lookups don't misalign."""
    p = tmp_path / "u_ex.log"
    p.write_text(
        _HEADER
        + "2025-01-01 00:00:01 10.0.0.1 GET /a.aspx - 443 - "
          "203.0.113.10 sqlmap/1.7 - 200 0 0 1\n"
        # Restart — different field order, still valid W3C.
        "#Fields: date time c-ip cs-method cs-uri-stem cs(User-Agent) "
        "sc-status\n"
        "2025-01-01 00:01:01 203.0.113.11 POST /cmd.aspx nikto - 200\n"
    )
    r = scan_path(p)
    # Both rows must have been parsed correctly under their own header.
    assert r.parsed_rows == 2
    # Both should fire on offensive UA (sqlmap + nikto)
    hit = next((h for h in r.hits
                if h.pattern_id == "W3C_SCRIPTED_CLIENT_OFFENSIVE"),
               None)
    assert hit is not None
    assert len(hit.matches) == 2


def test_malformed_rows_skipped_without_crash(tmp_path):
    p = tmp_path / "u_ex.log"
    p.write_text(
        _HEADER
        + "not a valid row\n"
        + "\n"
        + "2025-01-01 00:00:01 10.0.0.1 GET /a.aspx\n"   # short row
        + "2025-01-01 00:00:02 10.0.0.1 GET /c99.php - 443 - "
          "203.0.113.10 curl/7 - 200 0 0 1\n"
    )
    r = scan_path(p)
    # Only the full row should be parsed
    assert r.parsed_rows == 1
    # But the webshell should still fire
    assert any(h.pattern_id == "W3C_WEBSHELL_URI_SHAPE" for h in r.hits)


# --- scan_tree ------------------------------------------------------------

def test_scan_tree_walks_site_dirs(tmp_path):
    site1 = tmp_path / "W3SVC1"
    site2 = tmp_path / "W3SVC2"
    site1.mkdir()
    site2.mkdir()
    _write_log(site1, [
        "2025-01-01 00:00:01 10.0.0.1 POST /shell.aspx - 443 - "
        "203.0.113.10 curl/7 - 200 0 0 1",
    ])
    # rename the file fixture wrote to match u_ex*.log pattern
    (site2 / "u_ex250101.log").write_text(
        _HEADER
        + "2025-01-01 00:00:01 10.0.0.1 GET /admin/ - 443 - "
          "203.0.113.10 Mozilla - 200 0 0 1\n"
    )
    results = scan_tree(tmp_path)
    assert len(results) == 2
    # At least one Hit across all results
    assert any(r.hits for r in results)


# --- no-op: benign traffic doesn't trip any detector ---------------------

def test_benign_traffic_produces_no_hits(tmp_path):
    rows = [
        "2025-01-01 00:00:01 10.0.0.1 GET /index.html - 443 - "
        "10.0.0.50 Mozilla/5.0 - 200 0 0 1",
        "2025-01-01 00:00:02 10.0.0.1 GET /favicon.ico - 443 - "
        "10.0.0.50 Mozilla/5.0 - 200 0 0 1",
    ]
    log = _write_log(tmp_path, rows)
    r = scan_path(log)
    assert r.parsed_rows == 2
    assert r.hits == []
