"""Lumma Stealer family fingerprint + curated YARA rule."""
import tempfile
from pathlib import Path

import pytest

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


# --- self-match false-positive regression (the phantom Lumma hit on the
# case's own case_iocs.yar) -------------------------------------------------

def test_drop_rule_file_hits_strips_yar_self_match():
    """The guard must drop hits whose target is a .yar/.yara rule file (and
    their trailing match-detail lines), while keeping real-evidence hits."""
    raw = ("EL_Lumma_Stealer /case/analysis/threat_hunter/case_iocs.yar\n"
           "0x380ba:7:$name: LummaC2\n"
           "EL_Lumma_Stealer /evidence/sample.dmp\n"
           "0x1000:5:$ua: TeslaBrowser/5.5\n")
    out = yara_hunt._drop_rule_file_hits(raw, Path("case_iocs.yar"))
    assert "case_iocs.yar" not in out          # self-match dropped
    assert "$name: LummaC2" not in out         # its detail line dropped too
    assert "/evidence/sample.dmp" in out       # real hit kept
    assert "$ua: TeslaBrowser/5.5" in out


def _have_yara():
    try:
        yara_hunt._yara_bin()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _have_yara(), reason="no yara/yr binary")
def test_yara_scan_does_not_self_match_rule_file():
    """End-to-end: scanning a directory that CONTAINS the rules file must
    not report the rules file as a hit, even though it holds every rule's
    string literals verbatim."""
    d = Path(tempfile.mkdtemp())
    rules = d / "case_iocs.yar"
    rules.write_text(yara_hunt._CURATED_RULES)
    res = yara_hunt.scan_paths(rules, d, d / "out", recursive=True)
    matched = {f for fs in res.rule_to_files.values() for f in fs}
    assert not any(f.endswith((".yar", ".yara")) for f in matched)


@pytest.mark.skipif(not _have_yara(), reason="no yara/yr binary")
def test_tightened_lumma_rule_no_fp_on_intel_mention():
    """A benign single mention of the build string 'LummaC2' must NOT fire
    the curated rule; real C2 / UA indicators still must."""
    d = Path(tempfile.mkdtemp())
    rules = d / "rules.yar"
    rules.write_text(yara_hunt._CURATED_RULES)
    (d / "intel.txt").write_text("Report: the LummaC2 stealer targets browsers.")
    (d / "c2.txt").write_text("GET /api/set_agent?id=AA&token=BB&act=log HTTP/1.1")
    (d / "ua.txt").write_text("User-Agent: TeslaBrowser/5.5")
    res = yara_hunt.scan_paths(rules, d, d / "out", recursive=True)
    hit_names = {f.split("/")[-1] for fs in res.rule_to_files.values() for f in fs}
    assert "intel.txt" not in hit_names        # was the old false positive
    assert "c2.txt" in hit_names
    assert "ua.txt" in hit_names
