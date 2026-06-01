from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
DecisionState = Literal['open', 'false_positive', 'accepted_fix', 'risk_accepted', 'suppressed']
Priority = Literal['P0', 'P1', 'P2', 'P3', 'P4']
ValidationStatus = Literal['passed', 'warning', 'blocked', 'manual']
FindingScope = Literal['production', 'test', 'docs', 'example', 'config', 'dependency', 'generated', 'vendor', 'unknown']


class Location(BaseModel):
    path: str
    line: int = 1
    column: int = 1
    end_line: int | None = None


class FindingDataflow(BaseModel):
    has_dataflow: bool = False
    source: Location | None = None
    sink: Location | None = None
    steps: int | None = None
    tool_precision: Literal['very-high', 'high', 'medium', 'low'] | None = None


class ExecutionEvidence(BaseModel):
    state: Literal['executed', 'not_executed', 'unknown'] = 'unknown'
    source: str | None = None
    hits: int | None = None


class FindingPriorityContext(BaseModel):
    path_class: FindingScope = 'unknown'
    in_pr_diff: bool | None = None
    last_modified_days: int | None = None
    execution: Literal['executed', 'not_executed', 'unknown'] = 'unknown'
    execution_source: str | None = None
    execution_hits: int | None = None
    corroborating_tools: list[str] = Field(default_factory=list)


class PriorityDecisionFactor(BaseModel):
    name: str
    delta: float
    reason: str


class FindingPriority(BaseModel):
    tier: Literal['P0', 'P1', 'P2', 'P3'] | None = None
    score: float | None = None
    factors: list[PriorityDecisionFactor] = Field(default_factory=list)


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
    scanner_metadata: dict[str, str] = Field(default_factory=dict)
    exploitability: str = 'unknown'
    reachability: str = 'unknown'
    dataflow: FindingDataflow = Field(default_factory=FindingDataflow)
    priority_context: FindingPriorityContext = Field(default_factory=FindingPriorityContext)
    priority: FindingPriority | None = None
    cluster_id: str | None = None
    policy_impact: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    scope: FindingScope = 'production'
    risk: RiskScore = Field(default_factory=RiskScore)
    decision: DecisionState = 'open'
    decision_reason: str | None = None


class ConsolidatedFindingEvidence(BaseModel):
    finding_id: str
    source: str
    rule_id: str
    title: str
    severity: Severity
    confidence: str
    path: str
    line: int = 1
    end_line: int | None = None
    cwe: list[str] = Field(default_factory=list)
    sink: str = ''
    message: str = ''
    decision: DecisionState = 'open'


class ConsolidatedFinding(BaseModel):
    cluster_id: str
    title: str
    path: str
    line_start: int = 1
    line_end: int = 1
    semantic_key: str
    cwe: list[str] = Field(default_factory=list)
    sink: str = ''
    severity: Severity
    confidence: str = 'MEDIUM'
    priority_score: int = 0
    priority: Priority = 'P4'
    risk_tier: Severity = 'INFO'
    recommended_action: str = 'Review and triage.'
    agreement_count: int = 1
    tool_agreement_score: int = 40
    raw_count: int = 1
    sources: list[str] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    representative_finding_id: str
    evidence: list[ConsolidatedFindingEvidence] = Field(default_factory=list)
    factors: list[RiskFactor] = Field(default_factory=list)


class SuppressionRecord(BaseModel):
    finding_id: str
    fingerprint: str
    rule_id: str
    source: str
    path: str
    line: int = 1
    annotation_line: int = 1
    reason: str
    annotation: str
    matched_rule: str
    scope: FindingScope = 'unknown'


class InvalidSuppressionAnnotation(BaseModel):
    path: str
    line: int = 1
    annotation: str
    reason: str


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
    scope_counts: dict[str, int] = Field(default_factory=dict)
    production_findings: int = 0
    hygiene_findings: int = 0
    all_max_risk_score: int = 0
    all_avg_risk_score: float = 0
    all_risk_tiers: dict[str, int] = Field(default_factory=dict)
    all_priorities: dict[str, int] = Field(default_factory=dict)
    consolidated_findings: int = 0
    cross_tool_clusters: int = 0
    consolidated_priorities: dict[str, int] = Field(default_factory=dict)
    top_consolidated_priority_score: int = 0
    suppressed_findings: int = 0
    invalid_suppression_annotations: int = 0
    reachability_counts: dict[str, int] = Field(default_factory=dict)
    exploitability_counts: dict[str, int] = Field(default_factory=dict)
    changed_file_findings: int = 0
    request_handler_findings: int = 0
    finding_priority_counts: dict[str, int] = Field(default_factory=dict)
    top_finding_priority_score: float = 0
    active_prioritized_findings: int = 0
    suppressed_prioritized_findings: int = 0


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
    consolidated_findings: list[ConsolidatedFinding] = Field(default_factory=list)
    suppressions: list[SuppressionRecord] = Field(default_factory=list)
    invalid_suppressions: list[InvalidSuppressionAnnotation] = Field(default_factory=list)


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
    section: str | None = None
    chunk_index: int = 0
    metadata: dict[str, str] = Field(default_factory=dict)


class RagQueryResponse(BaseModel):
    query: str
    total_indexed: int
    results: list[KnowledgeChunk] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


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


class ValidationCheck(BaseModel):
    name: str
    status: ValidationStatus = 'manual'
    detail: str


class FixProposal(BaseModel):
    finding_id: str
    scan_id: str
    title: str
    summary: str
    patch: str
    safety_notes: list[str] = Field(default_factory=list)
    requires_human_approval: bool = True
    priority: Priority = 'P4'
    risk_score: int = 0
    effort: str = 'manual-review'
    confidence: str = 'manual'
    validation_checks: list[ValidationCheck] = Field(default_factory=list)
    validation_commands: list[str] = Field(default_factory=list)
    context_summary: dict[str, str] = Field(default_factory=dict)


class RemediationStep(BaseModel):
    finding_id: str
    title: str
    priority: Priority
    risk_score: int
    path: str
    line: int
    rule_id: str
    summary: str
    effort: str
    proposal_endpoint: str
    validation_commands: list[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    scan_id: str
    project_name: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_steps: int = 0
    p0_steps: int = 0
    p1_steps: int = 0
    estimated_effort: str = 'manual-review'
    guardrails: list[str] = Field(default_factory=list)
    validation_commands: list[str] = Field(default_factory=list)
    steps: list[RemediationStep] = Field(default_factory=list)


class FixApplyRequest(BaseModel):
    finding_ids: list[str] = Field(default_factory=list)
    limit: int = 10
    provider: str = 'offline'
    model: str | None = None
    dry_run: bool = True
    approved: bool = False
    allow_placeholders: bool = False
    create_backups: bool = True


class VerifiedAutofixRequest(BaseModel):
    finding_ids: list[str] = Field(default_factory=list)
    limit: int = 5
    provider: str = 'offline'
    model: str | None = None
    dry_run: bool = True
    approved: bool = False
    allow_placeholders: bool = False
    branch_name: str | None = None
    base_branch: str | None = None
    remote: str = 'origin'
    test_commands: list[str] = Field(default_factory=list)
    test_timeout_seconds: int = 900
    allow_auto_detect_tests: bool = True
    push_branch: bool = False
    publish_pr: bool = False
    pr_title: str | None = None
    pr_body: str | None = None
    commit_message: str | None = None


class InsideOutAutofixLoopRequest(BaseModel):
    finding_ids: list[str] = Field(default_factory=list)
    issue_ids: list[str] = Field(default_factory=list)
    limit: int = 5
    max_iterations: int = 1
    provider: str = 'offline'
    model: str | None = None
    dry_run: bool = True
    approved: bool = False
    allow_placeholders: bool = False
    safe_autofix_only: bool = True
    branch_name: str | None = None
    base_branch: str | None = None
    remote: str = 'origin'
    test_commands: list[str] = Field(default_factory=list)
    test_timeout_seconds: int = 900
    allow_auto_detect_tests: bool = True
    push_branch: bool = False
    publish_pr: bool = False
    pr_title: str | None = None
    pr_body: str | None = None
    commit_message: str | None = None
    rescan_after_apply: bool = True


class IssuePlanRequest(BaseModel):
    provider: Literal['all', 'jira', 'linear'] = 'all'
    publish: bool = False
    limit: int = 25
    min_priority: Priority = 'P2'


class ChatNotificationRequest(BaseModel):
    provider: Literal['all', 'slack', 'teams'] = 'all'
    publish: bool = False
    include_findings: int = 10


class GatewaySendRequest(BaseModel):
    channels: list[str] = Field(default_factory=lambda: ['all'])
    title: str = 'Secure Review update'
    message: str = ''
    severity: Literal['info', 'warning', 'critical'] = 'info'
    scan_id: str | None = None
    publish: bool = False
    include_findings: int = 10
    source: str = 'api'
    metadata: dict[str, object] = Field(default_factory=dict)


class CodeHostReviewRequest(BaseModel):
    provider: Literal['all', 'gitlab', 'azure-devops', 'bitbucket'] = 'all'
    publish: bool = False
    publish_status: bool | None = None
    include_findings: int = 25


class QuarantineEntryRequest(BaseModel):
    repository: str
    status: Literal['clear', 'watch', 'quarantined', 'blocked'] = 'quarantined'
    reason: str = ''
    source: str = 'user'
    severity: str | None = None
    tags: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    controls: dict[str, bool] | None = None


class QuarantineLookupRequest(BaseModel):
    repository: str
    project_name: str | None = None


class DisposableVmScanRequest(BaseModel):
    repository_path: str
    repository_url: str | None = None
    project_name: str | None = None
    sonar_project_key: str | None = None
    sonar_branch_name: str | None = None
    output_root: str | None = None
    reports_dir: str | None = None
    run_id: str | None = None
    provider: Literal['windows-sandbox', 'manual'] = 'windows-sandbox'
    network_policy: Literal['offline', 'scanner-only', 'full'] = 'scanner-only'
    approved_quarantine: bool = False
    copy_git_history: bool = True
    job_name: str | None = None


class ReportLakeReindexRequest(BaseModel):
    limit: int = 100
    include_quarantined: bool = True


class RagMemoryReindexRequest(BaseModel):
    limit: int = 100
    include_ineligible: bool = False


class MemoryRollbackRequest(BaseModel):
    reason: str = ''


class HermesRunRequest(BaseModel):
    scan_id: str
    goal: Literal['secure-review-triage', 'release-readiness', 'supply-chain-review', 'scanner-improvement-planning'] = 'secure-review-triage'
    limit: int = 100
    allowed_agents: list[str] = Field(default_factory=list)
    include_ineligible: bool = False


class HermesReviewRequest(BaseModel):
    decision: Literal['acknowledged', 'confirmed_true_positive', 'accepted_risk', 'false_positive', 'needs_fix', 'needs_more_evidence']
    reviewer: str | None = None
    note: str = ''
    review_item_ids: list[str] = Field(default_factory=list)


class TeachingLoopSessionRequest(BaseModel):
    scan_id: str
    limit: int = 50
    max_attempts: int = 3
    pass_score: int = 7
    rebuild_memory: bool = True


class BenchmarkLessonRequest(BaseModel):
    recommendation_id: str | None = None
    lesson_id: str | None = None
    language: str
    category: str
    title: str
    source: str | None = None
    rule_id: str | None = None
    proposed_change: str = ''
    evidence: dict[str, object] = Field(default_factory=dict)
    delegated_actor: str | None = None


class BenchmarkTransitionRequest(BaseModel):
    target_state: Literal['reviewed', 'benchmarked', 'approved', 'active']
    note: str = ''
    benchmark_evidence: dict[str, object] = Field(default_factory=dict)
    delegated_actor: str | None = None


class TeamCampaignRequest(BaseModel):
    title: str
    focus_area: str
    owner: str | None = None
    due_date: str | None = None
    description: str | None = None
    status: Literal['planned', 'active', 'paused', 'completed'] = 'planned'
    scan_id: str | None = None
    rule_ids: list[str] = Field(default_factory=list)
    repository_keys: list[str] = Field(default_factory=list)
    target_reduction_percent: int = 80


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


class GitHubPrReviewRequest(BaseModel):
    repository: str | None = None
    pr_number: int | None = None
    commit_sha: str | None = None
    diff_text: str | None = None
    publish: bool = False
    publish_status: bool | None = None
    event: str | None = None
    max_inline_comments: int | None = None
    min_inline_risk: int | None = None
