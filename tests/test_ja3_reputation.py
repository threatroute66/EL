"""JA3 reputation classification + network_analyst integration.

Baseline: network_analyst previously emitted a single low-confidence
"captured N JA3 fingerprints (blocklist-comparable)" rollup — no
per-hash reputation, no known-bad surfacing, no cross-case rarity.
"""
from el.skills import ja3_reputation
from el.skills.ja3_reputation import (
    BENIGN_COMMON_JA3, KNOWN_BAD_JA3, classify,
)


# --- classify() ------------------------------------------------------------

def test_known_bad_hashes_classified():
    for h, (label, source) in KNOWN_BAD_JA3.items():
        rep = classify(h)
        assert rep.classification == "known_bad", h
        assert rep.label == label
        assert rep.source == source


def test_benign_common_hashes_classified():
    for h in BENIGN_COMMON_JA3:
        rep = classify(h)
        assert rep.classification == "benign_common"
        assert rep.label  # must have a label


def test_unknown_hash_classified_unknown():
    # Random valid-shape md5 not in either table
    rep = classify("deadbeefdeadbeefdeadbeefdeadbeef")
    assert rep.classification == "unknown"
    assert rep.label is None


def test_malformed_input_returns_unknown():
    for bad in ("", "nothex", "a" * 31, "a" * 33, None, 1234):
        rep = classify(bad)  # type: ignore[arg-type]
        assert rep.classification == "unknown"


def test_case_insensitive_match():
    h = next(iter(KNOWN_BAD_JA3))
    assert classify(h.upper()).classification == "known_bad"
    assert classify(h.lower()).classification == "known_bad"


# --- minimum content of curated tables ------------------------------------

def test_known_bad_has_cobalt_strike_entry():
    labels = [lbl.lower() for lbl, _ in KNOWN_BAD_JA3.values()]
    assert any("cobalt strike" in l for l in labels), (
        "known-bad list must include at least the Cobalt Strike default"
    )


def test_every_known_bad_has_source_attribution():
    for h, (label, source) in KNOWN_BAD_JA3.items():
        assert source, f"{h} missing source — drop or document"
        assert source.startswith("http"), f"{h} source must be a URL"


def test_every_known_bad_is_valid_md5_shape():
    for h in KNOWN_BAD_JA3:
        assert len(h) == 32 and all(c in "0123456789abcdef" for c in h), h


# --- network_analyst integration ------------------------------------------

def test_triage_ja3_emits_high_confidence_for_known_bad(monkeypatch):
    """A known-bad JA3 in the Zeek output must produce a high-confidence
    per-hash finding — not get buried in the rollup."""
    from el.agents.base import AgentContext
    from el.agents.network_analyst import NetworkAnalystAgent

    known_bad_hash = next(iter(KNOWN_BAD_JA3))
    agent = NetworkAnalystAgent()
    ctx = AgentContext(case_id="t", case_dir=_DummyCaseDir(),
                       input_path=None, manifest={})

    # Zeek run stand-in — only needs an as_evidence() method.
    class _FakeRun:
        def as_evidence(self, facts=None):
            from el.schemas.finding import EvidenceItem
            return EvidenceItem(
                tool="zeek", version="test",
                command="zeek", output_sha256="0" * 64,
                output_path="/tmp/zeek", extracted_facts=facts or {},
            )

    # Stub the knowledge DB calls so the test doesn't write to ~/.el/.
    import el.knowledge as kb
    monkeypatch.setattr(kb, "lookup_iocs", lambda *a, **k: {})
    monkeypatch.setattr(kb, "record_iocs", lambda *a, **k: 0)

    # Stub emit to just return the Finding (don't write ledger).
    monkeypatch.setattr(agent, "emit", lambda ctx, f: f)

    findings = agent._triage_ja3_hashes(
        ctx, _FakeRun(),
        [known_bad_hash, "deadbeefdeadbeefdeadbeefdeadbeef"],
    )
    high = [f for f in findings if f.confidence == "high"]
    low = [f for f in findings if f.confidence == "low"]
    assert len(high) == 1, f"expected 1 high-confidence finding, got {len(high)}"
    assert known_bad_hash in high[0].claim
    assert high[0].hypotheses_supported  # tagged


def test_triage_ja3_novel_counts_reflect_knowledge(monkeypatch):
    """When lookup_iocs reports N+ prior cases for a hash, it gets
    counted as 'repeat', not 'novel'."""
    from el.agents.base import AgentContext
    from el.agents.network_analyst import NetworkAnalystAgent

    agent = NetworkAnalystAgent()
    ctx = AgentContext(case_id="t", case_dir=_DummyCaseDir(),
                       input_path=None, manifest={})

    h_novel = "11111111111111111111111111111111"
    h_repeat = "22222222222222222222222222222222"

    class _FakeRun:
        def as_evidence(self, facts=None):
            from el.schemas.finding import EvidenceItem
            return EvidenceItem(tool="zeek", version="t", command="z",
                                output_sha256="0" * 64, output_path="/x",
                                extracted_facts=facts or {})

    import el.knowledge as kb

    def fake_lookup(values, current_case_id):
        return {h_repeat: [
            {"case_id": f"prior-{i}", "ioc_type": "ja3",
             "observed_utc": "2026-01-01T00:00:00Z", "agent": "t"}
            for i in range(5)
        ]}
    monkeypatch.setattr(kb, "lookup_iocs", fake_lookup)
    monkeypatch.setattr(kb, "record_iocs", lambda *a, **k: 0)
    monkeypatch.setattr(agent, "emit", lambda ctx, f: f)

    findings = agent._triage_ja3_hashes(ctx, _FakeRun(), [h_novel, h_repeat])
    claims = [f.claim for f in findings if f.confidence == "low"]
    assert len(claims) == 1
    claim = claims[0]
    assert "1 novel" in claim
    assert "1 seen in ≥3 prior cases" in claim


# --- helpers --------------------------------------------------------------

class _DummyCaseDir:
    """Stand-in for ctx.case_dir — never actually written to in these
    tests (emit is stubbed)."""
    name = "dummy"
    def __truediv__(self, other):
        return self
    def mkdir(self, *a, **kw):
        pass
    def __fspath__(self):
        return "/tmp/el-test-dummy"
