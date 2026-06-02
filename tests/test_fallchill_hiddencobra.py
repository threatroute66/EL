"""US-CERT HIDDEN COBRA / FALLCHILL detector — the vendored authoritative
YARA pack (byte-accurate, behind the .yar self-match guard) + the
string-level Lazarus fingerprint for the memory-dump path."""
from pathlib import Path

import pytest

from el.intel.malware_families import detect
from el.skills import yara_hunt


def _have_yara():
    try:
        yara_hunt._yara_bin()
        return True
    except Exception:
        return False


def test_vendored_rules_present_with_provenance():
    rd = Path(yara_hunt._RULES_DIR)
    fc = rd / "MALW_FALLCHILL.yar"
    hc = rd / "hiddencobra_uscert.yar"
    assert fc.is_file() and hc.is_file()
    fct = fc.read_text()
    assert "rc4_stack_key_fallchill" in fct
    assert "TA17-318A" in fct          # CISA FALLCHILL provenance
    assert "US-CERT" in hc.read_text()


def test_generated_case_rules_include_fallchill_and_hiddencobra(tmp_path):
    rules = tmp_path / "case_iocs.yar"
    yara_hunt.generate_ioc_rules({}, rules, case_id="t")
    t = rules.read_text()
    for r in ("rc4_stack_key_fallchill", "success_fail_codes_fallchill",
              "Unauthorized_Proxy_Server_RAT", "NK_SSL_PROXY",
              "apt_hiddencobra_binaries"):
        assert r in t, f"vendored rule {r} missing from generated rule set"


@pytest.mark.skipif(not _have_yara(), reason="no yara/yr binary")
def test_assembled_rules_compile_detect_and_no_self_match(tmp_path):
    rules = tmp_path / "case_iocs.yar"
    yara_hunt.generate_ioc_rules({"ipv4": ["8.8.8.8"]}, rules, case_id="t")
    # a sample carrying the real NK_SSL_PROXY (MAR-10135536-G) auth strings
    (tmp_path / "sample.bin").write_text(
        "junk ghfghjuyufgdgftr .. q45tyu6hgvhi7^%$sdf .. m*^&^ghfge4wer junk")
    res = yara_hunt.scan_paths(rules, tmp_path, tmp_path / "out", recursive=True)
    hits = {(r, Path(f).name)
            for r, fs in res.rule_to_files.items() for f in fs}
    assert ("NK_SSL_PROXY", "sample.bin") in hits        # real markers detect
    # the rule file itself contains every string literal — must NOT self-match
    assert not any(f.endswith((".yar", ".yara")) for _, f in hits)


def test_fingerprint_detects_hiddencobra_markers():
    hits = detect({"blob q45tyu6hgvhi7^%$sdf blob", "ghfghjuyufgdgftr"},
                  context="memory")
    fams = {h.family for h in hits}
    assert "hiddencobra_lazarus" in fams
    h = next(h for h in hits if h.family == "hiddencobra_lazarus")
    assert "H_APT_ESPIONAGE" in h.hypotheses
    assert any(t == "T1071.001" for t, _ in h.attack_techniques)


def test_fingerprint_no_false_positive_on_benign():
    benign = {"user login succeeded", "normal application log line",
              "C:\\Windows\\System32\\svchost.exe"}
    assert "hiddencobra_lazarus" not in {
        h.family for h in detect(benign, context="memory")}
