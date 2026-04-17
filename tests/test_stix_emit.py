import json

from el.reporting.stix import emit_bundle
from el.schemas.finding import EvidenceItem, Finding


def _ev():
    return EvidenceItem(tool="t", version="0", command="x",
                        output_sha256="0" * 64, output_path="/tmp/x")


def test_bundle_contains_indicators_and_attack_patterns(tmp_path):
    findings = [
        Finding(case_id="c", agent="memory", confidence="high",
                claim="malfind flagged a region in chrome.exe", evidence=[_ev()],
                hypotheses_supported=["H_PROCESS_INJECTION"]),
    ]
    iocs = {
        "ipv4": {"203.0.113.7"},
        "domain": {"evil.example.com"},
        "sha256": {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    }
    out = tmp_path / "stix.json"
    emit_bundle("c1", findings, iocs, out)
    bundle = json.loads(out.read_text())
    types = [obj["type"] for obj in bundle["objects"]]
    assert "indicator" in types
    assert "attack-pattern" in types
    assert "report" in types
    assert "identity" in types

    indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
    patterns = " ".join(i["pattern"] for i in indicators)
    assert "203.0.113.7" in patterns
    assert "evil.example.com" in patterns
    assert "SHA-256" in patterns
