"""Shared pytest fixtures.

An autouse fixture redirects EL_KNOWLEDGE_DB to a per-test tmp path so that
tests never touch the real ~/.el/knowledge.sqlite. Without this, tests that
run the Coordinator (test_network_endtoend, test_cloudtrail,
test_windows_artifact_dir, …) read whatever IOCs live cases have accumulated
in the global knowledge store, and runtime scales with its row count —
observed: 17k rows → full suite hangs at ~50%.

Individual tests can still opt in to a specific knowledge DB by setting the
env var again; monkeypatch's env override is LIFO.
"""
import pytest


@pytest.fixture(autouse=True)
def _isolate_global_knowledge_db(tmp_path_factory, monkeypatch):
    kb = tmp_path_factory.mktemp("el-kb") / "knowledge.sqlite"
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(kb))
    yield
