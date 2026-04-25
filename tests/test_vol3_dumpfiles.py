"""vol3 windows.dumpfiles per-PID file carving — skill + agent.

Closes the doc gap "vol3 dumpfiles + yarascan (need per-pid /
per-rules args)" — the yarascan half landed in commit 811764c; this
covers the dumpfiles half.

Tests monkeypatch vol3.run_plugin so they don't require a real
memory image. The intent is to verify:

- the skill places `-o <dir>` correctly as a GLOBAL arg (before the
  plugin name) — vol3 rejects it as an unknown plugin option if
  passed positionally
- multiple `--pid` flags are appended when a list is supplied
- with_output_dir=True triggers the global -o injection in run_plugin
  even without --dump in extra_args
"""
from pathlib import Path

import pytest

from el.skills import vol3


def _captured_run_plugin(monkeypatch, tmp_path):
    """Helper: replaces vol3.run_plugin with a sentinel that records
    args + returns a minimal valid PluginRun."""
    captured = {}

    def fake_run(*, image, plugin, out_dir, extra_args=None,
                  timeout=600, offline=False, with_output_dir=False):
        captured["plugin"] = plugin
        captured["out_dir"] = str(out_dir)
        captured["extra_args"] = list(extra_args or [])
        captured["with_output_dir"] = with_output_dir
        sout = tmp_path / "o.json"; sout.write_text("[]")
        serr = tmp_path / "o.err"; serr.write_text("")
        return vol3.PluginRun(
            plugin=plugin, image=image, rc=0,
            stdout_path=sout, stderr_path=serr,
            rows=[], command=["vol", plugin], version="2.27.0",
        )
    monkeypatch.setattr(vol3, "run_plugin", fake_run)
    return captured


# --- skill: dumpfiles signature -----------------------------------------

def test_dumpfiles_uses_with_output_dir(tmp_path, monkeypatch):
    captured = _captured_run_plugin(monkeypatch, tmp_path)
    img = tmp_path / "mem.img"; img.touch()
    out = tmp_path / "carve"
    vol3.dumpfiles(img, out)
    assert captured["plugin"] == "windows.dumpfiles.DumpFiles"
    assert captured["with_output_dir"] is True
    # Without pids, no --pid flags
    assert not any(a == "--pid" for a in captured["extra_args"])


def test_dumpfiles_appends_pid_per_target(tmp_path, monkeypatch):
    captured = _captured_run_plugin(monkeypatch, tmp_path)
    img = tmp_path / "mem.img"; img.touch()
    out = tmp_path / "carve"
    vol3.dumpfiles(img, out, pids=[100, 200, 300])
    args = captured["extra_args"]
    # Three --pid <N> pairs
    pid_idxs = [i for i, a in enumerate(args) if a == "--pid"]
    assert len(pid_idxs) == 3
    assert [args[i + 1] for i in pid_idxs] == ["100", "200", "300"]


def test_dumpfiles_creates_out_dir(tmp_path, monkeypatch):
    _captured_run_plugin(monkeypatch, tmp_path)
    img = tmp_path / "mem.img"; img.touch()
    out = tmp_path / "deep" / "nested" / "carve"
    vol3.dumpfiles(img, out)
    assert out.is_dir()


# --- run_plugin: with_output_dir global -o injection --------------------

def test_run_plugin_injects_global_output_dir(tmp_path, monkeypatch):
    """`with_output_dir=True` must place `-o <dir>` BEFORE the plugin
    name in the assembled cmd, otherwise vol3 treats it as a
    plugin-level option and errors with 'unrecognized arguments'."""
    captured_cmd = []

    class _Result:
        returncode = 0; stdout = "[]"; stderr = ""

    def fake_run(cmd, *, capture_output, text, timeout):
        captured_cmd.extend(cmd)
        return _Result()

    monkeypatch.setattr(vol3.subprocess, "run", fake_run)
    img = tmp_path / "mem.img"; img.touch()
    out = tmp_path / "carve"; out.mkdir()
    vol3.run_plugin(image=img, plugin="windows.dumpfiles.DumpFiles",
                     out_dir=out, with_output_dir=True)
    # Find positions of `-o` and the plugin name in the assembled cmd
    o_pos = captured_cmd.index("-o")
    plugin_pos = captured_cmd.index("windows.dumpfiles.DumpFiles")
    assert o_pos < plugin_pos, (
        "global -o must appear BEFORE the plugin name; got "
        f"{captured_cmd}")
    assert captured_cmd[o_pos + 1] == str(out)
