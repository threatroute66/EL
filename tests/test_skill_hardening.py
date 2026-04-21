"""Lock in the SKILL-derived defaults — these are the operator-tier choices
documented in Protocol SIFT skill files. Regressions here mean we've drifted
from operator best practice."""
from el.agents.memory_forensicator import WIN_PLUGINS


def test_memory_plugin_set_includes_psscan_for_hidden_processes():
    assert "windows.psscan.PsScan" in WIN_PLUGINS, \
        "memory-analysis SKILL: psscan finds hidden + exited processes (pool-tag scan); pslist alone misses them"


def test_memory_plugin_set_includes_both_netstat_and_netscan():
    assert "windows.netstat.NetStat" in WIN_PLUGINS
    assert "windows.netscan.NetScan" in WIN_PLUGINS, \
        "memory-analysis SKILL: netstat = current state, netscan = historical pool-tag scan"


def test_memory_plugin_set_includes_svcscan():
    assert "windows.svcscan.SvcScan" in WIN_PLUGINS, \
        "memory-analysis SKILL: svcscan surfaces hidden services and persistent service installations"


def test_plaso_log2timeline_defaults_to_win10_utc(tmp_path):
    from unittest.mock import patch
    from el.skills import plaso

    captured = {}

    def fake_run(cmd, capture_output, text=None, timeout=None):
        captured["cmd"] = cmd
        class P: returncode = 0; stdout = ""; stderr = ""
        return P()

    with patch("el.skills.plaso.subprocess.run", side_effect=fake_run), \
         patch("el.skills.plaso._which", return_value="/fake/log2timeline.py"):
        plaso.log2timeline(tmp_path / "img", tmp_path)
    cmd = captured["cmd"]
    assert "--parsers" in cmd and "win10" in cmd, \
        "plaso-timeline SKILL: --parsers win10 is the preferred default"
    assert "--hashers" in cmd and "md5,sha256" in cmd
    assert "--timezone" in cmd and "UTC" in cmd, \
        "plaso-timeline SKILL: always pass --timezone UTC"


def test_plaso_log2timeline_vss_opt_in_for_intrusion(tmp_path):
    from unittest.mock import patch
    from el.skills import plaso

    captured = {}

    def fake_run(cmd, capture_output, text=None, timeout=None):
        captured["cmd"] = cmd
        class P: returncode = 0; stdout = ""; stderr = ""
        return P()

    with patch("el.skills.plaso.subprocess.run", side_effect=fake_run), \
         patch("el.skills.plaso._which", return_value="/fake/log2timeline.py"):
        plaso.log2timeline(tmp_path / "img", tmp_path, vss=True)
    assert "--vss-stores" in captured["cmd"] and "all" in captured["cmd"]


def test_mactime_uses_utc_default(tmp_path):
    from unittest.mock import patch
    from el.skills import sleuthkit as sk

    captured = {}
    body = tmp_path / "body.txt"
    body.write_text("")

    def fake_run(cmd, capture_output, text=None, timeout=None):
        captured["cmd"] = cmd
        class P:
            returncode = 0
            stdout = b""
            stderr = b""
        return P()

    with patch("el.skills.sleuthkit.subprocess.run", side_effect=fake_run), \
         patch("el.skills.sleuthkit._which", return_value="/fake/mactime"):
        sk.mactime(body, tmp_path)
    cmd = captured["cmd"]
    assert "-z" in cmd and "UTC" in cmd, \
        "sleuthkit SKILL: always pass -z UTC; default local-tz corrupts cross-tz analysis"
