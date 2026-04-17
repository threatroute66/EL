from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from el.evidence.ledger import insert as ledger_insert
from el.schemas.finding import Finding


@dataclass
class AgentContext:
    case_id: str
    case_dir: Path
    input_path: Path
    manifest: dict
    shared: dict = field(default_factory=dict)


class Agent(ABC):
    name: str = "agent"

    @abstractmethod
    def run(self, ctx: AgentContext) -> list[Finding]:
        """Execute the agent's procedure. MUST emit Findings — never prose."""

    def emit(self, ctx: AgentContext, finding: Finding) -> Finding:
        ledger_insert(ctx.case_dir, finding)
        return finding
