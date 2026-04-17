"""Windows Artifact Agent — process an extracted-artifacts directory.

Expected input layout (any subset is OK; missing pieces become 'insufficient'
findings, not failures):

  <artifacts_dir>/
    mft/$MFT
    mft/$J                       (or $UsnJrnl/$J)
    registry/SYSTEM
    registry/SOFTWARE
    registry/SECURITY
    registry/SAM
    registry/Amcache.hve
    registry/<USER>/NTUSER.DAT   (and UsrClass.dat)
    Prefetch/  (or  prefetch/)
    winevt/Logs/  (or  evtx/)
    srum/SRUDB.dat
    recyclebin/
    jumplists/
    lnk/
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import ezt


def _findfirst(root: Path, *patterns: str) -> Path | None:
    for pat in patterns:
        for p in root.rglob(pat):
            if p.is_file():
                return p
    return None


def _finddir(root: Path, *names: str) -> Path | None:
    for n in names:
        for p in root.rglob(n):
            if p.is_dir():
                return p
    return None


class WindowsArtifactAgent(Agent):
    name = "windows_artifact"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        if not ctx.input_path.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="Windows Artifact Agent expects a directory input",
            ))]

        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)
        root = ctx.input_path

        out.extend(self._mft(ctx, root, analysis))
        out.extend(self._usnjrnl(ctx, root, analysis))
        out.extend(self._registry_batch(ctx, root, analysis))
        out.extend(self._amcache(ctx, root, analysis))
        out.extend(self._appcompat(ctx, root, analysis))
        out.extend(self._prefetch(ctx, root, analysis))
        out.extend(self._evtx(ctx, root, analysis))
        out.extend(self._srum(ctx, root, analysis))
        out.extend(self._shellbags(ctx, root, analysis))
        out.extend(self._jumplists(ctx, root, analysis))
        out.extend(self._lnk(ctx, root, analysis))
        out.extend(self._recyclebin(ctx, root, analysis))

        if all(f.confidence == "insufficient" for f in out):
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"No recognised Windows artifacts found under {root.name}",
            )))
        return out

    def _try(self, ctx: AgentContext, label: str, fn) -> list[Finding]:
        try:
            run = fn()
        except ezt.EztError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"{label}: {e}",
            ))]
        if run.rc != 0:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"{label}: rc={run.rc} (see {run.stderr_path.name})",
            ))]
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"{label}: parsed successfully",
            evidence=[run.as_evidence()],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))]

    def _mft(self, ctx, root, analysis):
        p = _findfirst(root, "$MFT", "MFT")
        if not p:
            return []
        return self._try(ctx, f"MFTECmd $MFT ({p.name})",
                         lambda: ezt.run_mftecmd(p, analysis / "mft"))

    def _usnjrnl(self, ctx, root, analysis):
        p = _findfirst(root, "$J", "$UsnJrnl_$J", "UsnJrnl_J")
        if not p:
            return []
        return self._try(ctx, f"MFTECmd $UsnJrnl/$J ({p.name})",
                         lambda: ezt.run_usnjrnl(p, analysis / "usnjrnl"))

    def _registry_batch(self, ctx, root, analysis):
        d = _finddir(root, "registry", "Registry")
        if not d:
            return []
        return self._try(ctx, f"RECmd batch ({d.name})",
                         lambda: ezt.run_recmd(d, analysis / "registry"))

    def _amcache(self, ctx, root, analysis):
        p = _findfirst(root, "Amcache.hve", "amcache.hve")
        if not p:
            return []
        return self._try(ctx, f"AmcacheParser ({p.name})",
                         lambda: ezt.run_amcache(p, analysis / "amcache"))

    def _appcompat(self, ctx, root, analysis):
        p = _findfirst(root, "SYSTEM")
        if not p:
            return []
        return self._try(ctx, f"AppCompatCacheParser shimcache ({p.name})",
                         lambda: ezt.run_appcompat(p, analysis / "shimcache"))

    def _prefetch(self, ctx, root, analysis):
        d = _finddir(root, "Prefetch", "prefetch")
        if not d:
            return []
        return self._try(ctx, f"PECmd Prefetch ({d.name})",
                         lambda: ezt.run_pecmd(d, analysis / "prefetch"))

    def _evtx(self, ctx, root, analysis):
        d = _finddir(root, "evtx", "Logs", "winevt")
        if not d:
            d = root if any(p.suffix.lower() == ".evtx" for p in root.rglob("*.evtx")) else None
        if not d:
            return []
        return self._try(ctx, f"EvtxECmd ({d.name})",
                         lambda: ezt.run_evtxecmd(d, analysis / "evtx"))

    def _srum(self, ctx, root, analysis):
        p = _findfirst(root, "SRUDB.dat")
        if not p:
            return []
        software = _findfirst(root, "SOFTWARE")
        return self._try(ctx, f"SrumECmd ({p.name})",
                         lambda: ezt.run_srumecmd(p, analysis / "srum",
                                                   software_hive=software))

    def _shellbags(self, ctx, root, analysis):
        d = _finddir(root, "registry", "Registry")
        if not d:
            return []
        return self._try(ctx, f"SBECmd shellbags ({d.name})",
                         lambda: ezt.run_sbecmd(d, analysis / "shellbags"))

    def _jumplists(self, ctx, root, analysis):
        d = _finddir(root, "jumplists", "JumpLists",
                     "AutomaticDestinations", "CustomDestinations")
        if not d:
            return []
        return self._try(ctx, f"JLECmd ({d.name})",
                         lambda: ezt.run_jlecmd(d, analysis / "jumplists"))

    def _lnk(self, ctx, root, analysis):
        d = _finddir(root, "lnk", "Recent")
        if not d:
            return []
        return self._try(ctx, f"LECmd ({d.name})",
                         lambda: ezt.run_lecmd(d, analysis / "lnk"))

    def _recyclebin(self, ctx, root, analysis):
        d = _finddir(root, "recyclebin", "$Recycle.Bin")
        if not d:
            return []
        return self._try(ctx, f"RBCmd ({d.name})",
                         lambda: ezt.run_rbcmd(d, analysis / "recyclebin"))
