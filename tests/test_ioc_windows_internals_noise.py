"""Regression: Windows filename extensions leaked into the cross-host
IOC overlap of the SRL-2015 and SRL-2018 combined reports as fake
"domains" (e.g. roman.fon, 6.1.1.0.mum, cabundle.cer, netlogon.ftl,
datastore.edb, sysmain.sdb, stdole2.tlb, vscan.bof, *.pf). These are
Windows internals, not domains — they must never land in the domain
bucket."""
from el.skills.ioc_extract import extract


# Every string here is a real entry that appeared in at least one of the
# combined-report cross-case IOC tables under type=domain. Each must be
# filtered out; the single real domain must survive.
_OBSERVED_FALSE_POSITIVES = [
    # Fonts
    "roman.fon", "script.fon", "modern.fon", "coure.fon", "smalle.fon",
    "serife.fon", "sserife.fon", "vgafix.fon", "vgaoem.fon", "vgasys.fon",
    "dosapp.fon", "cga40woa.fon", "cga80woa.fon", "ega40woa.fon",
    "ega80woa.fon", "batang.ttc",
    # Windows Update manifests (KB package names look like ".mum" TLDs)
    "6.1.1.0.mum", "6.1.1.1.mum", "8.0.7600.16385.mum",
    "8.0.7601.17514.mum", "9.4.1.0.mum", "9.4.1.2.mum", "9.4.8112.16421.mum",
    "6.1.7600.16385.cat",
    # ESENT / registry / shim / catalog / type library
    "datastore.edb", "edb.chk", "index.btr", "netlogon.ftl",
    "sysmain.sdb", "locale.nls", "stdole2.tlb",
    # Certs / signatures
    "cabundle.cer", "cryptocme2.sig",
    # Cobalt-Strike style .bof
    "vscan.bof",
    # Other observed junk
    "windowsshell.manifest", "objects.data",
]


def test_observed_windows_filenames_not_domains():
    blob = " ".join(_OBSERVED_FALSE_POSITIVES) + " real.example.com"
    out = extract(blob)
    domains = out["domain"]
    leaked = [x for x in _OBSERVED_FALSE_POSITIVES if x in domains]
    assert leaked == [], (
        f"Windows filename extensions leaked into the domain bucket: {leaked}"
    )
    assert "real.example.com" in domains, (
        "filter must not drop real domains"
    )


def test_prefetch_basenames_not_domains():
    # Prefetch was the single largest noise contributor in SRL-2018
    # (127 entries in the cross-host table as domain=foo.pf)
    sample = "CHROME.EXE-12345678.PF notepad.exe-ABCDEF01.pf rundll32.exe-DEADBEEF.pf"
    out = extract(sample)
    for d in out["domain"]:
        assert not d.endswith(".pf"), f"prefetch leaked as domain: {d}"
