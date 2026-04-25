"""nginx / Apache access-log anomaly detector.

Closes gap-doc Linux-depth bullet "Webserver access-log anomaly
detector (nginx/Apache)". Companion to test_iis_w3c.py — same Hit
taxonomy, Combined / Common Log Format input.
"""
import gzip
from pathlib import Path

from el.skills import webserver_access as wa


def _line(host: str, method: str, uri: str, status: str,
          ua: str = "Mozilla/5.0", ref: str = "-",
          size: int = 1024,
          ts: str = "01/Jan/2025:00:00:00 +0000") -> str:
    return (f'{host} - - [{ts}] "{method} {uri} HTTP/1.1" '
            f'{status} {size} "{ref}" "{ua}"\n')


def test_combined_log_format_basic_parse(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(_line("203.0.113.5", "GET", "/index.html", "200"))
    r = wa.scan_path(p)
    assert r.parsed_rows == 1
    assert r.total_lines == 1
    assert r.hits == []                     # benign request, no detector fires


def test_common_log_format_no_ua_parses(tmp_path):
    p = tmp_path / "access.log"
    p.write_text('1.2.3.4 - - [01/Jan/2025:00:00:00 +0000] '
                 '"GET / HTTP/1.0" 200 1024\n')
    r = wa.scan_path(p)
    assert r.parsed_rows == 1


def test_webshell_uri_basename_flagged(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(_line("203.0.113.7", "GET", "/uploads/c99.php", "200"))
    r = wa.scan_path(p)
    pids = [h.pattern_id for h in r.hits]
    assert "WEB_WEBSHELL_URI_SHAPE" in pids


def test_webshell_query_token_flagged(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(_line("203.0.113.7", "GET",
                        "/index.php?cmd=id;uname%20-a", "200"))
    r = wa.scan_path(p)
    pids = [h.pattern_id for h in r.hits]
    assert "WEB_WEBSHELL_URI_SHAPE" in pids


def test_lfi_traversal_query_flagged(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(_line("203.0.113.7", "GET",
                        "/page.php?file=../../etc/passwd", "200"))
    r = wa.scan_path(p)
    assert "WEB_WEBSHELL_URI_SHAPE" in [h.pattern_id for h in r.hits]


def test_offensive_ua_flagged(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(_line("203.0.113.9", "GET", "/", "200",
                        ua="sqlmap/1.7.2#stable (https://sqlmap.org)"))
    r = wa.scan_path(p)
    assert "WEB_SCRIPTED_CLIENT_OFFENSIVE" in [h.pattern_id for h in r.hits]


def test_generic_ua_only_flagged_on_2xx(tmp_path):
    p = tmp_path / "access.log"
    # 200 with curl → fires
    p.write_text(_line("203.0.113.9", "GET", "/api", "200",
                        ua="curl/7.85.0"))
    r = wa.scan_path(p)
    assert "WEB_SCRIPTED_CLIENT_GENERIC" in [h.pattern_id for h in r.hits]
    # 404 with curl → does NOT fire
    p.write_text(_line("203.0.113.9", "GET", "/api", "404",
                        ua="curl/7.85.0"))
    r = wa.scan_path(p)
    assert "WEB_SCRIPTED_CLIENT_GENERIC" not in [h.pattern_id for h in r.hits]


def test_admin_path_hit_only_from_public_ip(tmp_path):
    p = tmp_path / "access.log"
    # private IP — should NOT fire
    p.write_text(_line("10.0.0.5", "GET", "/wp-admin/", "200"))
    r = wa.scan_path(p)
    assert "WEB_ADMIN_URI_HIT" not in [h.pattern_id for h in r.hits]
    # public IP — fires
    p.write_text(_line("203.0.113.50", "GET", "/wp-admin/", "200"))
    r = wa.scan_path(p)
    assert "WEB_ADMIN_URI_HIT" in [h.pattern_id for h in r.hits]


def test_admin_path_dotenv_dotgit(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(
        _line("203.0.113.50", "GET", "/.env", "200")
        + _line("203.0.113.50", "GET", "/.git/config", "200")
    )
    r = wa.scan_path(p)
    h = next(h for h in r.hits if h.pattern_id == "WEB_ADMIN_URI_HIT")
    assert h.count == 2


def test_upload_post_burst(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(
        _line("203.0.113.7", "POST", "/upload.php", "200")
        + _line("203.0.113.7", "POST", "/upload.php", "200")
        + _line("203.0.113.7", "POST", "/upload.php", "302")
    )
    r = wa.scan_path(p)
    assert "WEB_UPLOAD_POST_BURST" in [h.pattern_id for h in r.hits]


def test_upload_post_burst_below_threshold(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(
        _line("203.0.113.7", "POST", "/upload.php", "200")
        + _line("203.0.113.7", "POST", "/upload.php", "200")
    )
    r = wa.scan_path(p)
    assert "WEB_UPLOAD_POST_BURST" not in [h.pattern_id for h in r.hits]


def test_upload_post_requires_2xx(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(
        _line("203.0.113.7", "POST", "/upload.php", "403")
        + _line("203.0.113.7", "POST", "/upload.php", "403")
        + _line("203.0.113.7", "POST", "/upload.php", "403")
    )
    r = wa.scan_path(p)
    assert "WEB_UPLOAD_POST_BURST" not in [h.pattern_id for h in r.hits]


def test_4xx_recon_burst_fires(tmp_path):
    p = tmp_path / "access.log"
    lines = []
    for i in range(40):
        lines.append(_line("203.0.113.99", "GET", f"/scan/path-{i}", "404"))
    p.write_text("".join(lines))
    r = wa.scan_path(p)
    assert "WEB_4XX_RECON_BURST" in [h.pattern_id for h in r.hits]


def test_4xx_recon_below_threshold(tmp_path):
    p = tmp_path / "access.log"
    lines = []
    for i in range(15):                     # below default min=30
        lines.append(_line("203.0.113.99", "GET", f"/scan/path-{i}", "404"))
    p.write_text("".join(lines))
    r = wa.scan_path(p)
    assert "WEB_4XX_RECON_BURST" not in [h.pattern_id for h in r.hits]


def test_4xx_recon_distinct_uris_required(tmp_path):
    """40 4xx hits to the SAME URI — repeat probing of one path,
    not directory busting. Should NOT fire."""
    p = tmp_path / "access.log"
    lines = [_line("203.0.113.99", "GET", "/admin", "404")
             for _ in range(40)]
    p.write_text("".join(lines))
    r = wa.scan_path(p)
    assert "WEB_4XX_RECON_BURST" not in [h.pattern_id for h in r.hits]


def test_4xx_recon_private_ip_ignored(tmp_path):
    p = tmp_path / "access.log"
    lines = [_line("10.0.0.5", "GET", f"/scan/path-{i}", "404")
             for i in range(40)]
    p.write_text("".join(lines))
    r = wa.scan_path(p)
    assert "WEB_4XX_RECON_BURST" not in [h.pattern_id for h in r.hits]


def test_verb_tunnel_threshold(tmp_path):
    p = tmp_path / "access.log"
    lines = [_line("203.0.113.50", "PROPFIND", "/", "207")
             for _ in range(60)]
    p.write_text("".join(lines))
    r = wa.scan_path(p)
    assert "WEB_VERB_TUNNEL" in [h.pattern_id for h in r.hits]


def test_gzip_log_supported(tmp_path):
    """nginx logrotate gzips on rotation — wrapper must read .gz."""
    p = tmp_path / "access.log.1.gz"
    body = (_line("203.0.113.9", "GET", "/", "200",
                   ua="sqlmap/1.7.2"))
    with gzip.open(p, "wt") as fh:
        fh.write(body)
    r = wa.scan_path(p)
    assert "WEB_SCRIPTED_CLIENT_OFFENSIVE" in [h.pattern_id for h in r.hits]


def test_missing_file_returns_empty(tmp_path):
    r = wa.scan_path(tmp_path / "nope.log")
    assert r.parsed_rows == 0
    assert r.hits == []


def test_malformed_lines_skipped(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(
        "this is not a log line\n"
        + _line("203.0.113.50", "GET", "/wp-admin/", "200")
    )
    r = wa.scan_path(p)
    assert r.total_lines == 2
    assert r.parsed_rows == 1


def test_max_rows_cap(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(_line("1.2.3.4", "GET", "/", "200") * 1000)
    r = wa.scan_path(p, max_rows=10)
    assert r.parsed_rows == 10


def test_scan_tree_walks_nginx_apache_subdirs(tmp_path):
    (tmp_path / "nginx").mkdir()
    (tmp_path / "apache2").mkdir()
    (tmp_path / "nginx" / "access.log").write_text(
        _line("203.0.113.9", "GET", "/", "200", ua="sqlmap/1.7.2"))
    (tmp_path / "apache2" / "access.log").write_text(
        _line("203.0.113.7", "GET", "/uploads/c99.php", "200"))
    results = wa.scan_tree(tmp_path)
    assert len(results) == 2
    pids = {h.pattern_id for r in results for h in r.hits}
    assert "WEB_SCRIPTED_CLIENT_OFFENSIVE" in pids
    assert "WEB_WEBSHELL_URI_SHAPE" in pids


def test_scan_tree_direct_dir_with_access_logs(tmp_path):
    """Caller passed the log dir directly (no subdir)."""
    (tmp_path / "access.log").write_text(
        _line("203.0.113.9", "GET", "/", "200", ua="nuclei/2.9"))
    results = wa.scan_tree(tmp_path)
    assert len(results) == 1
    assert "WEB_SCRIPTED_CLIENT_OFFENSIVE" in [
        h.pattern_id for h in results[0].hits]
