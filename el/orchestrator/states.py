from __future__ import annotations

from enum import Enum


class State(str, Enum):
    INTAKE = "intake"
    TRIAGE = "triage"
    HYPOTHESIS_GEN = "hypothesis_gen"
    PARALLEL_INVESTIGATE = "parallel_investigate"
    CORRELATE = "correlate"
    ADVERSARIAL_REVIEW = "adversarial_review"
    SYNTHESIZE = "synthesize"
    REPORT = "report"
    DONE = "done"
    BLOCKED = "blocked"


TRANSITIONS: dict[State, set[State]] = {
    State.INTAKE: {State.TRIAGE, State.BLOCKED},
    State.TRIAGE: {State.HYPOTHESIS_GEN, State.BLOCKED},
    State.HYPOTHESIS_GEN: {State.PARALLEL_INVESTIGATE, State.BLOCKED},
    State.PARALLEL_INVESTIGATE: {State.CORRELATE, State.BLOCKED},
    State.CORRELATE: {State.ADVERSARIAL_REVIEW, State.PARALLEL_INVESTIGATE, State.BLOCKED},
    State.ADVERSARIAL_REVIEW: {State.SYNTHESIZE, State.PARALLEL_INVESTIGATE, State.BLOCKED},
    State.SYNTHESIZE: {State.REPORT, State.BLOCKED},
    State.REPORT: {State.DONE, State.BLOCKED},
    State.DONE: set(),
    State.BLOCKED: set(),
}


def can_transition(src: State, dst: State) -> bool:
    return dst in TRANSITIONS.get(src, set())
