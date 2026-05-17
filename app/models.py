from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
DecisionState = Literal['open', 'false_positive', 'accepted_fix', 'risk_accepted']
Priority = Literal['P0', 'P1', 'P2', 'P3', 'P4']


class Location(BaseModel):
    path: str
    line: int = 1
    column: int = 1
    end_line: int | None = None


class FixSuggestion(BaseModel):
    summary: str
    guidance: list[str] = Field(default_factory=list)
    patch: str | None = None


class RiskFactor(BaseModel):
    name: str
    label: str
    points: int
    detail: str


class RiskScore(BaseModel):
    score: int = 0
    tier: Severity = 'INFO'
    priority: Priority = 'P4'
    recommended_action: str = 'Review and triage.'
    factors: list[RiskFactor] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    source: str
    rule_id: str
    title: str
    severity: Severity
    confidence: str = 'MEDIUM'
    location: Location
    message: str
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    explanation: str
    fix: FixSuggestion
    fingerprint: str
    risk: RiskScore = Field(default_factory=RiskScore)
    decision: DecisionState = 'open'
    decision_reason: str | None = None


class ScanSummary(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    files_scanned: int = 0
    languages: dict[str, int] = Field(default_factory=dict)
    tools: dict[str, str] = Field(default_factory=dict)
    max_risk_score: int = 0
    avg_risk_score: float = 0
    risk_tiers: dict[str, int] = Field(default_factory=dict)
    priorities: dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    scan_id: str
    project_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target_path: str
    summary: ScanSummary
    findings: list[Finding] = Field(default_factory=list)
    new_findings: list[str] = Field(default_factory=list)
    resolved_findings: list[str] = Field(default_factory=list)
    unchanged_findings: list[str] = Field(default_factory=list)


class DecisionRequest(BaseModel):
    finding_id: str
    state: DecisionState
    reason: str | None = None


class BaselineComparison(BaseModel):
    scan_id: str
    baseline_id: str | None = None
    new_findings: list[str] = Field(default_factory=list)
    resolved_findings: list[str] = Field(default_factory=list)
    unchanged_findings: list[str] = Field(default_factory=list)


class KnowledgeChunk(BaseModel):
    id: str
    title: str
    source: str
    text: str
    tags: list[str] = Field(default_factory=list)
    score: float = 0


class LLMRequest(BaseModel):
    prompt: str
    provider: str = 'offline'
    model: str | None = None
    system: str | None = None
    context: list[KnowledgeChunk] = Field(default_factory=list)


class LLMResponse(BaseModel):
    provider: str
    model: str
    text: str
    used_fallback: bool = False
    error: str | None = None


class FixProposal(BaseModel):
    finding_id: str
    scan_id: str
    title: str
    summary: str
    patch: str
    safety_notes: list[str] = Field(default_factory=list)
    requires_human_approval: bool = True


class Role(BaseModel):
    name: str
    permissions: list[str] = Field(default_factory=list)


class UserAccount(BaseModel):
    username: str
    display_name: str
    roles: list[str] = Field(default_factory=list)
    active: bool = True


class AuditEvent(BaseModel):
    event_id: str
    actor: str
    action: str
    resource: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, str] = Field(default_factory=dict)
