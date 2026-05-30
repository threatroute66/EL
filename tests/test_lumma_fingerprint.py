"""Lumma Stealer family fingerprint + curated YARA rule."""
import tempfile
from pathlib import Path

from el.intel.malware_families import detect
from el.skills import yara_hunt

# The real C2 bot-registration seen in the 2026-01-31 traffic exercise.
_C2 = ("GET http://whitepepper.su/api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C"
       "&token=842e2802df0f0a06b4ed51f12f4387e761523b&description=&agent=Chrome&act=log")


def test_lumma_detected_from_c2_registration():
    hits = detect([_C2], context="network")
    fams = {h.family for h in hits}
    assert "lumma_stealer" in fams
    h = next(h for h in hits if h.family == "lumma_stealer")
    assert "H_C2_OR_REVERSE_SHELL" in h.hypotheses
    assert "H_CREDENTIAL_ACCESS" in h.hypotheses
    assert any(t == "T1071.001" for t, _ in h.attack_techniques)


def test_lumma_detected_from_canonical_markers():
    assert "lumma_stealer" in {
        h.family for h in detect(["User-Agent: TeslaBrowser/5.5"], context="network")}
    assert "lumma_stealer" in {
        h.family for h in detect(["build string LummaC2 v4"], context="memory")}
    assert "lumma_stealer" in {
        h.family for h in detect(["POST /c2 act=receive_message"], context="network")}


def test_lumma_no_false_positive_on_benign():
    benign = ["GET /api/agents?token=abc HTTP/1.1",   # no set_agent endpoint
              "user logged in via Chrome"]
    assert "lumma_stealer" not in {
        h.family for h in detect(benign, context="network")}


def test_curated_lumma_yara_rule_emitted():
    p = Path(tempfile.mkdtemp()) / "rules.yar"
    yara_hunt.generate_ioc_rules({}, p, case_id="t")
    text = p.read_text()
    assert "rule EL_Lumma_Stealer" in text
    assert "TeslaBrowser/5.5" in text
    assert "/api/set_agent" in text
