"""T3-3 tests: TeamViewer + AnyDesk inbound/outbound parsers + agent wiring."""
from pathlib import Path

import pytest

from el.skills import remote_access_apps as raa


# ---------------------------------------------------------------------------
# TeamViewer connections_incoming.txt
# ---------------------------------------------------------------------------

def test_teamviewer_incoming_parses_tab_separated(tmp_path):
    p = tmp_path / "connections_incoming.txt"
    p.write_text(
        "123456789\tJohn Doe's Mac\t15-06-2024 09:41:22\t15-06-2024 10:02:00\t"
        "alice\tRemoteControl\t{guid}\n"
        "987654321\tUnknown\t16-06-2024 22:17:05\t16-06-2024 22:19:40\t"
        "alice\tRemoteControl\t{guid2}\n"
    )
    sessions = raa.parse_teamviewer_incoming(p)
    assert len(sessions) == 2
    assert sessions[0].peer_id == "123456789"
    assert sessions[0].peer_display == "John Doe's Mac"
    assert sessions[0].local_user == "alice"
    assert sessions[0].direction == "inbound"


def test_teamviewer_incoming_tolerates_whitespace_padding(tmp_path):
    """Older TV versions space-pad columns instead of tab-separating."""
    p = tmp_path / "connections_incoming.txt"
    p.write_text(
        "123456789  AttackerPC  15-06-2024 09:41:22  "
        "15-06-2024 10:02:00  bob  RemoteControl  {guid}\n"
    )
    sessions = raa.parse_teamviewer_incoming(p)
    assert sessions
    assert sessions[0].peer_id == "123456789"


def test_teamviewer_incoming_ignores_non_tv_id_lines(tmp_path):
    p = tmp_path / "connections_incoming.txt"
    p.write_text(
        "# header comment\n"
        "PARTNER_ID  PARTNER_DISPLAY_NAME  START  END  USER  TYPE  GUID\n"
        "123456789\tAttacker\t15-06-2024 09:41:22\t\t\t\t\n"
    )
    sessions = raa.parse_teamviewer_incoming(p)
    # Only the real TV-id line survives
    assert len(sessions) == 1
    assert sessions[0].peer_id == "123456789"


def test_teamviewer_missing_file_returns_empty(tmp_path):
    assert raa.parse_teamviewer_incoming(tmp_path / "nope.txt") == []


def test_detect_teamviewer_builds_top_peers(tmp_path):
    p = tmp_path / "connections_incoming.txt"
    p.write_text(
        "123456789\tRepeat\t15-06-2024 09:00:00\t15-06-2024 09:01:00\tu\tX\tG\n"
        "123456789\tRepeat\t15-06-2024 10:00:00\t15-06-2024 10:05:00\tu\tX\tG\n"
        "987654321\tOnce\t16-06-2024 22:00:00\t16-06-2024 22:10:00\tu\tX\tG\n"
    )
    hits = raa.detect_teamviewer_inbound_sessions([p])
    assert len(hits) == 1
    assert hits[0].event_count == 3
    assert hits[0].top_peers[0] == ("123456789", 2)


# ---------------------------------------------------------------------------
# AnyDesk connection_trace.txt
# ---------------------------------------------------------------------------

def test_anydesk_parses_incoming_and_outgoing(tmp_path):
    p = tmp_path / "connection_trace.txt"
    p.write_text(
        "Incoming 2024-06-01 09:41:22 123456789 workprofile\n"
        "Outgoing 2024-06-01 10:00:00 987654321\n"
        "Incoming 2024-06-02 11:00:00 111222333\n"
    )
    sessions = raa.parse_anydesk_connection_trace(p)
    assert len(sessions) == 3
    dirs = [s.direction for s in sessions]
    assert dirs == ["inbound", "outbound", "inbound"]
    assert sessions[0].peer_id == "123456789"


def test_anydesk_ignores_unparseable_lines(tmp_path):
    p = tmp_path / "connection_trace.txt"
    p.write_text(
        "# comment\n"
        "Garbage line\n"
        "Incoming 2024-06-01 09:41:22 123456789\n"
    )
    sessions = raa.parse_anydesk_connection_trace(p)
    assert len(sessions) == 1


def test_detect_anydesk_splits_by_direction(tmp_path):
    p = tmp_path / "connection_trace.txt"
    p.write_text(
        "Incoming 2024-06-01 09:41:22 123456789\n"
        "Incoming 2024-06-01 10:00:00 987654321\n"
        "Outgoing 2024-06-01 11:00:00 555666777\n"
    )
    hits = raa.detect_anydesk_sessions([p])
    techniques = {h.technique for h in hits}
    assert "inbound_session" in techniques
    assert "outbound_session" in techniques
    inbound = [h for h in hits if h.technique == "inbound_session"][0]
    assert inbound.event_count == 2


# ---------------------------------------------------------------------------
# run_all against a fake export tree
# ---------------------------------------------------------------------------

def test_run_all_walks_both_apps(tmp_path):
    (tmp_path / "teamviewer").mkdir()
    (tmp_path / "teamviewer" / "connections_incoming.txt").write_text(
        "123456789\tpeer\t15-06-2024 09:41:22\t\t\t\t\n"
    )
    (tmp_path / "anydesk").mkdir()
    (tmp_path / "anydesk" / "connection_trace.txt").write_text(
        "Incoming 2024-06-01 09:41:22 123456789\n"
    )
    hits = raa.run_all(tmp_path)
    apps = {h.app for h in hits}
    assert "teamviewer" in apps
    assert "anydesk" in apps


def test_run_all_empty_dir_returns_empty(tmp_path):
    assert raa.run_all(tmp_path / "nonexistent") == []


# ---------------------------------------------------------------------------
# Agent wiring
# ---------------------------------------------------------------------------

def test_agent_emits_inbound_session_findings(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.windows_artifact import WindowsArtifactAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    input_dir = tmp_path / "artifacts"
    (input_dir / "remote_access" / "teamviewer").mkdir(parents=True)
    (input_dir / "remote_access" / "teamviewer"
        / "connections_incoming.txt").write_text(
        "987654321\tUnknownPeer\t01-06-2024 09:41:22\t"
        "01-06-2024 10:05:00\talice\tRemoteControl\t{guid}\n"
    )

    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-remote-access")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-remote-access",
                       case_dir=Path(m.case_dir),
                       input_path=input_dir, manifest=m.__dict__)
    findings = WindowsArtifactAgent()._remote_access(ctx, input_dir,
                                                       input_dir / "analysis")
    assert findings
    inbound = [f for f in findings
               if "teamviewer inbound_session" in f.claim.lower()]
    assert inbound
    assert inbound[0].confidence == "high"
    assert "H_APT_ESPIONAGE" in inbound[0].hypotheses_supported


def test_agent_silent_when_no_remote_access_dir(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.windows_artifact import WindowsArtifactAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    input_dir = tmp_path / "artifacts-minimal"
    input_dir.mkdir()
    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-ra-silent")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-ra-silent",
                       case_dir=Path(m.case_dir),
                       input_path=input_dir, manifest=m.__dict__)
    assert WindowsArtifactAgent()._remote_access(ctx, input_dir,
                                                   tmp_path / "analysis") == []
