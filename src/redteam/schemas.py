"""Typed contracts for the campaign. A Finding is a reproducible bug report: the
exact input, the response, the detector that fired, and its OWASP mapping.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class AttackCase(BaseModel):
    id: str
    category: str
    owasp: str                       # e.g. "LLM01"
    prompt: str                      # the attack input (possibly multi-turn: see turns)
    turns: list[str] = Field(default_factory=list)  # for multi-turn escalation
    seed_id: str | None = None
    mutation: str | None = None      # which mutator produced this, if any


class AttackResult(BaseModel):
    case: AttackCase
    response: str
    succeeded: bool                  # did the attack achieve its goal?
    detector: str                    # which oracle decided success
    detail: dict = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    category: str
    owasp: str
    severity: Severity
    title: str
    attack_prompt: str
    response_excerpt: str
    detector: str
    remediation: str
    reproduction: dict = Field(default_factory=dict)


class CampaignReport(BaseModel):
    name: str
    total_attacks: int
    findings: list[Finding]
    coverage: dict[str, dict]        # per-category: attacks run, successes, rate
