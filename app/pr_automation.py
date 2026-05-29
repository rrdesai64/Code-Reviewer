from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from .paths import data_dir

SCHEMA_VERSION = 1
TicketProvider = Literal['jira', 'linear', 'github', 'azure-devops', 'unknown']
PullRequestProvider = Literal['github', 'gitlab', 'azure-devops', 'bitbucket', 'unknown']
FileChangeStatus = Literal['added', 'modified', 'deleted', 'renamed', 'copied', 'unknown']
AgentFindingCategory = Literal['security', 'dependency', 'invariant', 'logic', 'impact-radius', 'scanner-reliability', 'unknown']
ImpactRiskLevel = Literal['none', 'low', 'medium', 'high', 'critical']
PolicyCheckStatus = Literal['passed', 'warning', 'violation', 'not_applicable']
PolicyDecision = Literal['passed', 'review_required', 'blocked']
FeedbackPublicationState = Literal['ready', 'requires_review', 'blocked']
PublisherStatus = Literal['dry_run', 'published', 'partial', 'blocked', 'failed', 'not_configured']
GovernanceEvidenceStatus = Literal['completed', 'partial', 'attention_required']


class PullRequestRepository(BaseModel):
    provider: PullRequestProvider = 'unknown'
    full_name: str
    clone_url: str | None = None
    default_branch: str | None = None
    visibility: str = 'unknown'


class PullRequestIdentity(BaseModel):
    provider: PullRequestProvider = 'unknown'
    repository: str
    number: int
    url: str | None = None
    author: str = ''
    title: str = ''
    description_excerpt: str = ''
    base_branch: str = ''
    head_branch: str = ''
    base_sha: str = ''
    head_sha: str = ''
    state: str = 'open'


class PullRequestFileChange(BaseModel):
    path: str
    previous_path: str | None = None
    status: FileChangeStatus = 'modified'
    additions: int = 0
    deletions: int = 0
    changes: int = 0
    patch_sha256: str = ''
    patch_excerpt: str = ''
    language: str = 'unknown'


class PullRequestDiffSummary(BaseModel):
    raw_diff_included: bool = False
    raw_diff_sha256: str = ''
    raw_diff_excerpt: str = ''
    files_changed: int = 0
    additions: int = 0
    deletions: int = 0
    generated_files: list[str] = Field(default_factory=list)
    manifest: list[PullRequestFileChange] = Field(default_factory=list)


class PullRequestTicketReference(BaseModel):
    key: str
    provider: TicketProvider = 'unknown'
    url: str | None = None
    title: str = ''
    status: str = ''
    source: str = 'extracted'
    description_excerpt: str = ''
    assignee: str = ''
    labels: list[str] = Field(default_factory=list)
    issue_type: str = ''
    priority: str = ''
    updated_at: str | None = None
    hydrated: bool = False
    hydration_status: str = 'pending'
    metadata: dict[str, str] = Field(default_factory=dict)


class PullRequestIntent(BaseModel):
    summary: str = ''
    source: str = 'title-description'
    ticket_keys: list[str] = Field(default_factory=list)
    risk_keywords: list[str] = Field(default_factory=list)
    review_focus: list[str] = Field(default_factory=list)
    business_context: str = ''
    hydrated_from_tickets: bool = False
    confidence: str = 'low'


class PullRequestEvidencePointer(BaseModel):
    kind: str
    id: str
    description: str = ''
    uri: str | None = None
    raw_content_included: bool = False


class PullRequestAgentFinding(BaseModel):
    category: AgentFindingCategory = 'unknown'
    title: str
    severity: str = 'INFO'
    file_path: str | None = None
    line: int | None = None
    evidence: dict[str, str] = Field(default_factory=dict)
    recommendation: str = ''


class PullRequestFeedbackItem(BaseModel):
    title: str
    body: str
    file_path: str | None = None
    line: int | None = None
    suggestion: str | None = None
    requires_human_review: bool = True
    source_finding_ids: list[str] = Field(default_factory=list)
    severity: str = 'INFO'
    category: str = 'general'
    source: str = 'feedback-composer'


class PullRequestImpactModule(BaseModel):
    name: str
    path_prefix: str = ''
    files_changed: int = 0
    additions: int = 0
    deletions: int = 0
    languages: list[str] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: ImpactRiskLevel = 'low'
    reasons: list[str] = Field(default_factory=list)
    review_focus: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)


class PullRequestImpactRadiusReport(BaseModel):
    status: str = 'pending'
    computed_at: datetime | None = None
    overall_risk: ImpactRiskLevel = 'none'
    risk_score: int = 0
    blast_radius: str = 'unknown'
    modules: list[PullRequestImpactModule] = Field(default_factory=list)
    critical_files: list[str] = Field(default_factory=list)
    generated_files: list[str] = Field(default_factory=list)
    cross_cutting_concerns: list[str] = Field(default_factory=list)
    test_recommendations: list[str] = Field(default_factory=list)
    recommended_agents: list[str] = Field(default_factory=list)
    raw_code_included: bool = False
    guardrails: list[str] = Field(default_factory=list)


class PullRequestPolicyCheck(BaseModel):
    check_id: str
    category: str
    title: str
    status: PolicyCheckStatus = 'passed'
    severity: str = 'INFO'
    evidence: dict[str, str] = Field(default_factory=dict)
    recommendation: str = ''
    required_actions: list[str] = Field(default_factory=list)
    related_files: list[str] = Field(default_factory=list)
    related_modules: list[str] = Field(default_factory=list)


class PullRequestPolicyAgentReport(BaseModel):
    status: str = 'pending'
    decision: PolicyDecision = 'passed'
    computed_at: datetime | None = None
    checks: list[PullRequestPolicyCheck] = Field(default_factory=list)
    violations: int = 0
    warnings: int = 0
    passed: int = 0
    required_actions: list[str] = Field(default_factory=list)
    required_agents: list[str] = Field(default_factory=list)
    blocked_by_policy: bool = False
    raw_code_included: bool = False
    guardrails: list[str] = Field(default_factory=list)


class PullRequestFeedbackReport(BaseModel):
    status: str = 'pending'
    publication_state: FeedbackPublicationState = 'requires_review'
    composed_at: datetime | None = None
    summary_markdown: str = ''
    overview_bullets: list[str] = Field(default_factory=list)
    required_actions: list[str] = Field(default_factory=list)
    test_recommendations: list[str] = Field(default_factory=list)
    recommended_agents: list[str] = Field(default_factory=list)
    general_comments: list[PullRequestFeedbackItem] = Field(default_factory=list)
    file_comments: list[PullRequestFeedbackItem] = Field(default_factory=list)
    comment_count: int = 0
    raw_code_included: bool = False
    guardrails: list[str] = Field(default_factory=list)


class PullRequestPublisherProviderResult(BaseModel):
    provider: PullRequestProvider = 'unknown'
    configured: bool = False
    active: bool = False
    dry_run: bool = True
    publish_attempted: bool = False
    published: bool = False
    inline_comment_count: int = 0
    summary_comment_count: int = 0
    suggestion_count: int = 0
    payload: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None


class PullRequestPublisherReport(BaseModel):
    status: PublisherStatus = 'dry_run'
    generated_at: datetime | None = None
    provider: str = 'auto'
    publish_requested: bool = False
    force: bool = False
    allow_suggestions: bool = False
    publication_state: FeedbackPublicationState = 'requires_review'
    blocked_reason: str = ''
    providers: dict[str, PullRequestPublisherProviderResult] = Field(default_factory=dict)
    summary: dict[str, int] = Field(default_factory=dict)
    raw_code_included: bool = False
    guardrails: list[str] = Field(default_factory=list)


class PullRequestGovernanceActionEvidence(BaseModel):
    action: str
    status: str = 'pending'
    completed: bool = False
    evidence_kinds: list[str] = Field(default_factory=list)
    event_count: int = 0
    latest_event_at: str | None = None
    safety: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    missing_evidence: list[str] = Field(default_factory=list)


class PullRequestGovernanceEvidenceReport(BaseModel):
    status: GovernanceEvidenceStatus = 'partial'
    generated_at: datetime | None = None
    state_id: str = ''
    repository: str = ''
    pull_request: int = 0
    action_count: int = 0
    completed_actions: list[str] = Field(default_factory=list)
    missing_actions: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    actions: dict[str, PullRequestGovernanceActionEvidence] = Field(default_factory=dict)
    state_lineage: dict[str, Any] = Field(default_factory=dict)
    safety: dict[str, Any] = Field(default_factory=dict)
    compliance_export: dict[str, Any] = Field(default_factory=dict)
    raw_code_included: bool = False
    guardrails: list[str] = Field(default_factory=list)


class PullRequestAutomationState(BaseModel):
    schema_version: int = SCHEMA_VERSION
    state_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    repository: PullRequestRepository
    pull_request: PullRequestIdentity
    diff: PullRequestDiffSummary
    tickets: list[PullRequestTicketReference] = Field(default_factory=list)
    intent: PullRequestIntent = Field(default_factory=PullRequestIntent)
    evidence: list[PullRequestEvidencePointer] = Field(default_factory=list)
    impact_radius_modules: list[str] = Field(default_factory=list)
    impact_radius: PullRequestImpactRadiusReport = Field(default_factory=PullRequestImpactRadiusReport)
    policy_report: PullRequestPolicyAgentReport = Field(default_factory=PullRequestPolicyAgentReport)
    feedback_report: PullRequestFeedbackReport = Field(default_factory=PullRequestFeedbackReport)
    publisher_report: PullRequestPublisherReport = Field(default_factory=PullRequestPublisherReport)
    governance_evidence: PullRequestGovernanceEvidenceReport = Field(default_factory=PullRequestGovernanceEvidenceReport)
    security_vulnerabilities: list[PullRequestAgentFinding] = Field(default_factory=list)
    invariant_violations: list[PullRequestAgentFinding] = Field(default_factory=list)
    logic_gaps: list[PullRequestAgentFinding] = Field(default_factory=list)
    compiled_feedback: list[PullRequestFeedbackItem] = Field(default_factory=list)
    agent_status: dict[str, str] = Field(default_factory=dict)
    guardrails: list[str] = Field(default_factory=lambda: pr_state_guardrails())


class PullRequestIngressError(RuntimeError):
    pass


class PullRequestTicketHydrationError(RuntimeError):
    pass


class PullRequestImpactRadiusError(RuntimeError):
    pass


class PullRequestPolicyAgentError(RuntimeError):
    pass


class PullRequestFeedbackComposerError(RuntimeError):
    pass


class PullRequestPublisherError(RuntimeError):
    pass


class PullRequestGovernanceEvidenceError(RuntimeError):
    pass


def pr_automation_schema_report() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': 'ready',
        'feature': 'pr-automation-ingress',
        'providers': ['github', 'gitlab', 'azure-devops', 'bitbucket'],
        'state_model': PullRequestAutomationState.model_json_schema(),
        'ingress_model': {
            'github_webhook_builder': 'build_pr_state_from_github_webhook',
            'gitlab_webhook_builder': 'build_pr_state_from_gitlab_webhook',
            'azure_devops_webhook_builder': 'build_pr_state_from_azure_devops_webhook',
            'bitbucket_webhook_builder': 'build_pr_state_from_bitbucket_webhook',
            'generic_builder': 'build_pr_state',
            'unified_ingress': 'ingest_pr_webhook',
            'ticket_intent_hydration': 'hydrate_pr_state',
            'impact_radius_analyzer': 'analyze_pr_impact_radius',
            'invariant_policy_agent': 'run_pr_policy_agent',
            'feedback_composer': 'compose_pr_feedback',
            'inline_comment_publisher': 'publish_pr_feedback',
            'governance_evidence': 'pr_governance_evidence',
        },
        'hydration_model': pr_ticket_hydration_status(),
        'impact_radius_model': pr_impact_radius_status(),
        'policy_agent_model': pr_policy_agent_status(),
        'feedback_composer_model': pr_feedback_composer_status(),
        'publisher_model': pr_feedback_publisher_status(),
        'governance_evidence_model': pr_governance_evidence_status(),
        'guardrails': pr_state_guardrails(),
        'next_steps': [
            'agent fan-out',
        ],
    }


def pr_automation_ingress_status() -> dict[str, Any]:
    states = list_pr_states(limit=1000)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': 'ready',
        'providers': ['github', 'gitlab', 'azure-devops', 'bitbucket'],
        'stored_state_count': len(states),
        'state_dir': str(pr_states_dir()),
        'webhook_endpoint': '/api/pr-automation/webhook/{provider}',
        'signature_policy': {
            'github': 'X-Hub-Signature-256 with GITHUB_WEBHOOK_SECRET or PR_AUTOMATION_GITHUB_WEBHOOK_SECRET',
            'gitlab': 'X-Gitlab-Token with GITLAB_WEBHOOK_SECRET or PR_AUTOMATION_GITLAB_WEBHOOK_SECRET',
            'azure-devops': 'shared secret header x-secure-review-pr-secret or x-azure-devops-webhook-secret',
            'bitbucket': 'X-Hub-Signature-256/X-Hub-Signature or shared secret header',
        },
        'allow_unsigned_default': False,
        'guardrails': pr_state_guardrails(),
    }


def pr_ticket_hydration_status() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': 'ready',
        'endpoint': '/api/pr-automation/states/{state_id}/hydrate',
        'providers': ticket_provider_configuration(),
        'provider_order': hydration_provider_order(),
        'stored_state_count': len(list_pr_states(limit=1000)),
        'guardrails': [
            'Ticket hydration stores bounded, redacted metadata only; raw issue descriptions are not persisted.',
            'Hydration is optional: missing provider credentials produce a not_configured result instead of failing PR ingress.',
            'Hydrated intent can steer review focus, but it cannot publish comments, mutate repositories, or alter scanner rules.',
        ],
    }


def pr_impact_radius_status() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': 'ready',
        'endpoint': '/api/pr-automation/states/{state_id}/impact-radius',
        'inputs': [
            'PullRequestAutomationState.diff.manifest',
            'PullRequestAutomationState.intent',
            'PullRequestAutomationState.tickets',
            'PullRequestAutomationState.diff.generated_files',
        ],
        'stored_state_count': len(list_pr_states(limit=1000)),
        'module_strategy': 'path-prefix and semantic concern heuristics over the bounded PR state',
        'guardrails': impact_radius_guardrails(),
    }


def pr_policy_agent_status() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': 'ready',
        'endpoint': '/api/pr-automation/states/{state_id}/policy',
        'agent': 'invariant-policy-agent',
        'inputs': [
            'PullRequestAutomationState.diff.manifest',
            'PullRequestAutomationState.intent',
            'PullRequestAutomationState.tickets',
            'PullRequestAutomationState.impact_radius',
        ],
        'stored_state_count': len(list_pr_states(limit=1000)),
        'policy_checks': [
            'raw-code-state-invariant',
            'high-impact-review-gate',
            'security-sensitive-test-evidence',
            'dependency-supply-chain-review',
            'ci-iac-least-privilege-review',
            'database-migration-safety',
            'generated-artifact-review',
            'ticket-hydration-context',
            'broad-radius-integration-coverage',
            'sensitive-delete-or-rename',
        ],
        'guardrails': policy_agent_guardrails(),
    }


def pr_feedback_composer_status() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': 'ready',
        'endpoint': '/api/pr-automation/states/{state_id}/feedback',
        'composer': 'pr-feedback-composer',
        'inputs': [
            'PullRequestAutomationState.intent',
            'PullRequestAutomationState.impact_radius',
            'PullRequestAutomationState.policy_report',
            'PullRequestAutomationState.invariant_violations',
        ],
        'stored_state_count': len(list_pr_states(limit=1000)),
        'outputs': [
            'summary_markdown',
            'overview_bullets',
            'required_actions',
            'test_recommendations',
            'general_comments',
            'file_comments',
            'publication_state',
        ],
        'guardrails': feedback_composer_guardrails(),
    }


def pr_feedback_publisher_status() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': 'ready',
        'endpoint': '/api/pr-automation/states/{state_id}/publish',
        'publisher': 'pr-inline-comment-suggestion-publisher',
        'providers': publisher_provider_configuration(),
        'stored_state_count': len(list_pr_states(limit=1000)),
        'dry_run_default': parse_bool(os.getenv('PR_AUTOMATION_PUBLISHER_DRY_RUN'), True),
        'guardrails': feedback_publisher_guardrails(),
    }


def pr_governance_evidence_status() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': 'ready',
        'endpoint': '/api/pr-automation/states/{state_id}/governance-evidence',
        'evidence_store': str(pr_governance_evidence_dir()),
        'stored_state_count': len(list_pr_states(limit=1000)),
        'required_actions': list(pr_governance_action_definitions().keys()),
        'inputs': [
            'PullRequestAutomationState',
            'PullRequestAutomationState.evidence',
            'governance events where category=pr-automation and resource/evidence_refs.state_id matches the PR state',
        ],
        'outputs': [
            'per-action evidence checklist',
            'chronological governance timeline',
            'state lineage and evidence pointer hash',
            'raw-code safety assertions',
            'exportable compliance JSON artifact',
        ],
        'guardrails': governance_evidence_guardrails(),
    }


def pr_governance_evidence(
    state_id: str | None = None,
    *,
    state: PullRequestAutomationState | None = None,
    persist: bool = True,
    limit: int = 200,
) -> dict[str, Any]:
    if state is None:
        if not state_id:
            raise PullRequestGovernanceEvidenceError('state_id is required when state is not supplied')
        state = load_pr_state(state_id)

    report = build_pr_governance_evidence(state, limit=limit)
    artifact_path = pr_governance_evidence_path(state.state_id)
    if persist:
        report.compliance_export['artifact_path'] = str(artifact_path)
    report_id = sha256_text(json.dumps(report.model_dump(mode='json'), sort_keys=True))[:16]
    add_or_replace_evidence(
        state,
        PullRequestEvidencePointer(
            kind='pr-governance-evidence',
            id=report_id,
            description='Exportable PR action governance evidence report; raw source code and raw diff hunks are not included.',
            uri=str(artifact_path) if persist else None,
            raw_content_included=False,
        ),
    )
    state.governance_evidence = report
    state.updated_at = datetime.now(timezone.utc)
    state.agent_status['governance_evidence'] = report.status

    state_path = None
    if persist:
        pr_governance_evidence_dir().mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(report.model_dump_json(indent=2), encoding='utf-8')
        state_path = save_pr_state(state)
        record_pr_governance_evidence_event(state, report, report_id, artifact_path)

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'state_id': state.state_id,
        'status': report.status,
        'persisted': bool(persist),
        'state_path': str(state_path) if state_path else None,
        'artifact_path': str(artifact_path) if persist else None,
        'summary': {
            'action_count': report.action_count,
            'completed_actions': len(report.completed_actions),
            'missing_actions': len(report.missing_actions),
            'timeline_events': len(report.timeline),
            'raw_code_included': report.raw_code_included,
        },
        'governance_evidence': report.model_dump(mode='json'),
        'guardrails': report.guardrails,
    }


def publish_pr_feedback(
    state_id: str | None = None,
    *,
    state: PullRequestAutomationState | None = None,
    provider: str = 'auto',
    publish: bool = False,
    allow_suggestions: bool = False,
    force: bool = False,
    max_inline_comments: int = 25,
    persist: bool = True,
    request_fn: Any | None = None,
) -> dict[str, Any]:
    if state is None:
        if not state_id:
            raise PullRequestPublisherError('state_id is required when state is not supplied')
        state = load_pr_state(state_id)

    if state.feedback_report.status in {'pending', ''}:
        compose_pr_feedback(state=state, persist=False)

    selected = normalize_publish_providers(provider, state)
    blocked_reason = publisher_blocked_reason(state, publish=publish, force=force)
    provider_config = publisher_provider_configuration(state)
    report = build_publisher_report(
        state,
        selected,
        provider_config,
        publish=publish,
        allow_suggestions=allow_suggestions,
        force=force,
        max_inline_comments=max_inline_comments,
        blocked_reason=blocked_reason,
        request_fn=request_fn,
    )
    state.publisher_report = report
    state.updated_at = datetime.now(timezone.utc)
    state.agent_status['publisher'] = report.status
    add_or_replace_evidence(
        state,
        PullRequestEvidencePointer(
            kind='pr-publisher',
            id=sha256_text(json.dumps(report.model_dump(mode='json'), sort_keys=True))[:16],
            description='Governed PR feedback publisher payload/result; raw source code and raw diff hunks are not included.',
            raw_content_included=False,
        ),
    )

    state_path = None
    if persist:
        state_path = save_pr_state(state)
        record_pr_publisher_governance(state, report)

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'state_id': state.state_id,
        'status': report.status,
        'publish_requested': publish,
        'publication_state': report.publication_state,
        'persisted': bool(persist),
        'state_path': str(state_path) if state_path else None,
        'summary': report.summary,
        'publisher_report': report.model_dump(mode='json'),
        'guardrails': report.guardrails,
    }


def compose_pr_feedback(
    state_id: str | None = None,
    *,
    state: PullRequestAutomationState | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    if state is None:
        if not state_id:
            raise PullRequestFeedbackComposerError('state_id is required when state is not supplied')
        state = load_pr_state(state_id)

    if state.impact_radius.status in {'pending', ''}:
        state.impact_radius = build_impact_radius_report(state)
        state.impact_radius_modules = [module.name for module in state.impact_radius.modules]
        state.agent_status['impact_radius'] = state.impact_radius.status
    if state.policy_report.status in {'pending', ''}:
        state.policy_report = build_policy_agent_report(state)
        state.invariant_violations = merge_policy_agent_findings(state.invariant_violations, state.policy_report)
        state.agent_status['invariant_policy'] = state.policy_report.decision

    report = build_feedback_report(state)
    state.feedback_report = report
    state.compiled_feedback = report.general_comments + report.file_comments
    state.updated_at = datetime.now(timezone.utc)
    state.agent_status['feedback_composition'] = report.publication_state
    add_or_replace_evidence(
        state,
        PullRequestEvidencePointer(
            kind='pr-feedback',
            id=sha256_text(json.dumps(report.model_dump(mode='json'), sort_keys=True))[:16],
            description='Draft PR feedback composed from bounded PR state, impact radius, and policy findings; not published.',
            raw_content_included=False,
        ),
    )

    state_path = None
    if persist:
        state_path = save_pr_state(state)
        record_pr_feedback_governance(state, report)

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'state_id': state.state_id,
        'status': report.status,
        'publication_state': report.publication_state,
        'persisted': bool(persist),
        'state_path': str(state_path) if state_path else None,
        'summary': {
            'publication_state': report.publication_state,
            'comment_count': report.comment_count,
            'required_actions': len(report.required_actions),
            'test_recommendations': len(report.test_recommendations),
            'recommended_agents': len(report.recommended_agents),
        },
        'feedback_report': report.model_dump(mode='json'),
        'compiled_feedback': [item.model_dump(mode='json') for item in state.compiled_feedback],
        'guardrails': report.guardrails,
    }


def run_pr_policy_agent(
    state_id: str | None = None,
    *,
    state: PullRequestAutomationState | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    if state is None:
        if not state_id:
            raise PullRequestPolicyAgentError('state_id is required when state is not supplied')
        state = load_pr_state(state_id)

    if state.impact_radius.status in {'pending', ''}:
        state.impact_radius = build_impact_radius_report(state)
        state.impact_radius_modules = [module.name for module in state.impact_radius.modules]
        state.agent_status['impact_radius'] = state.impact_radius.status

    report = build_policy_agent_report(state)
    state.policy_report = report
    state.invariant_violations = merge_policy_agent_findings(state.invariant_violations, report)
    state.updated_at = datetime.now(timezone.utc)
    state.agent_status['invariant_policy'] = report.decision
    add_or_replace_evidence(
        state,
        PullRequestEvidencePointer(
            kind='invariant-policy',
            id=sha256_text(json.dumps(report.model_dump(mode='json'), sort_keys=True))[:16],
            description='Invariant and policy agent result computed from bounded PR state and impact radius metadata.',
            raw_content_included=False,
        ),
    )

    state_path = None
    if persist:
        state_path = save_pr_state(state)
        record_pr_policy_governance(state, report)

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'state_id': state.state_id,
        'status': report.status,
        'decision': report.decision,
        'persisted': bool(persist),
        'state_path': str(state_path) if state_path else None,
        'summary': {
            'decision': report.decision,
            'violations': report.violations,
            'warnings': report.warnings,
            'passed': report.passed,
            'required_actions': len(report.required_actions),
            'required_agents': len(report.required_agents),
            'blocked_by_policy': report.blocked_by_policy,
        },
        'policy_report': report.model_dump(mode='json'),
        'guardrails': report.guardrails,
    }


def analyze_pr_impact_radius(
    state_id: str | None = None,
    *,
    state: PullRequestAutomationState | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    if state is None:
        if not state_id:
            raise PullRequestImpactRadiusError('state_id is required when state is not supplied')
        state = load_pr_state(state_id)

    report = build_impact_radius_report(state)
    state.impact_radius = report
    state.impact_radius_modules = [module.name for module in report.modules]
    state.updated_at = datetime.now(timezone.utc)
    state.agent_status['impact_radius'] = report.status
    add_or_replace_evidence(
        state,
        PullRequestEvidencePointer(
            kind='impact-radius',
            id=sha256_text(json.dumps(report.model_dump(mode='json'), sort_keys=True))[:16],
            description='Impact radius computed from PR file manifest, bounded intent, and ticket metadata; raw code is not stored.',
            raw_content_included=False,
        ),
    )

    state_path = None
    if persist:
        state_path = save_pr_state(state)
        record_pr_impact_governance(state, report)

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'state_id': state.state_id,
        'status': report.status,
        'persisted': bool(persist),
        'state_path': str(state_path) if state_path else None,
        'summary': {
            'overall_risk': report.overall_risk,
            'risk_score': report.risk_score,
            'blast_radius': report.blast_radius,
            'modules': len(report.modules),
            'critical_files': len(report.critical_files),
            'cross_cutting_concerns': len(report.cross_cutting_concerns),
        },
        'impact_radius': report.model_dump(mode='json'),
        'guardrails': report.guardrails,
    }


def hydrate_pr_state(
    state_id: str | None = None,
    *,
    state: PullRequestAutomationState | None = None,
    persist: bool = True,
    providers: str = 'auto',
    ticket_fetcher: Any | None = None,
) -> dict[str, Any]:
    if state is None:
        if not state_id:
            raise PullRequestTicketHydrationError('state_id is required when state is not supplied')
        state = load_pr_state(state_id)
    selected_providers = normalize_hydration_providers(providers)
    provider_config = ticket_provider_configuration()
    summary = {'total': len(state.tickets), 'hydrated': 0, 'not_configured': 0, 'failed': 0, 'skipped': 0}
    outcomes: list[dict[str, Any]] = []
    hydrated_tickets: list[PullRequestTicketReference] = []

    for ticket in state.tickets:
        hydrated, outcome = hydrate_ticket_reference(ticket, state, selected_providers, provider_config, ticket_fetcher)
        hydrated_tickets.append(hydrated)
        status = outcome.get('status') or 'skipped'
        if status == 'hydrated':
            summary['hydrated'] += 1
        elif status == 'not_configured':
            summary['not_configured'] += 1
        elif status == 'failed':
            summary['failed'] += 1
        else:
            summary['skipped'] += 1
        outcomes.append(outcome)

    state.tickets = hydrated_tickets
    state.intent = summarize_hydrated_intent(state)
    state.updated_at = datetime.now(timezone.utc)
    state.agent_status['ticket_hydration'] = hydration_status_from_summary(summary)
    add_or_replace_evidence(
        state,
        PullRequestEvidencePointer(
            kind='ticket-hydration',
            id=sha256_text(json.dumps({'tickets': [ticket.model_dump(mode='json') for ticket in state.tickets], 'summary': summary}, sort_keys=True))[:16],
            description='Bounded ticket metadata and PR intent hydration result; raw ticket content is not stored.',
            raw_content_included=False,
        ),
    )

    state_path = None
    if persist:
        state_path = save_pr_state(state)
        record_pr_hydration_governance(state, summary, selected_providers)

    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'state_id': state.state_id,
        'status': state.agent_status['ticket_hydration'],
        'persisted': bool(persist),
        'state_path': str(state_path) if state_path else None,
        'providers': selected_providers,
        'provider_configuration': provider_config,
        'summary': summary,
        'outcomes': outcomes,
        'intent': state.intent.model_dump(mode='json'),
        'tickets': [ticket.model_dump(mode='json') for ticket in state.tickets],
        'guardrails': pr_ticket_hydration_status()['guardrails'],
    }


def ingest_pr_webhook(
    provider: str,
    event: str,
    payload: dict[str, Any],
    raw_body: bytes = b'',
    headers: dict[str, str] | None = None,
    persist: bool = True,
    diff_text: str = '',
) -> dict[str, Any]:
    normalized_provider = normalize_provider(provider)
    normalized_headers = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    verification = verify_pr_webhook(normalized_provider, raw_body, normalized_headers)
    if not verification['valid']:
        raise PullRequestIngressError(verification['reason'])

    action = webhook_action(normalized_provider, event, payload)
    accepted, reason = webhook_accepted(normalized_provider, event, action, payload)
    result: dict[str, Any] = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'provider': normalized_provider,
        'event': event,
        'action': action,
        'accepted': accepted,
        'reason': reason,
        'verification': verification,
        'persisted': False,
        'state_id': None,
        'state_path': None,
        'state': None,
        'guardrails': pr_state_guardrails(),
    }
    if not accepted:
        return result

    state = build_pr_state_from_webhook(normalized_provider, payload, diff_text=diff_text)
    result['state_id'] = state.state_id
    result['state'] = state.model_dump(mode='json')
    if persist:
        path = save_pr_state(state)
        result['persisted'] = True
        result['state_path'] = str(path)
        record_pr_ingress_governance(result)
    return result


def build_pr_state_from_webhook(provider: PullRequestProvider, payload: dict[str, Any], diff_text: str = '') -> PullRequestAutomationState:
    if provider == 'github':
        return build_pr_state_from_github_webhook(payload, diff_text=diff_text)
    if provider == 'gitlab':
        return build_pr_state_from_gitlab_webhook(payload, diff_text=diff_text)
    if provider == 'azure-devops':
        return build_pr_state_from_azure_devops_webhook(payload, diff_text=diff_text)
    if provider == 'bitbucket':
        return build_pr_state_from_bitbucket_webhook(payload, diff_text=diff_text)
    raise PullRequestIngressError(f'Unsupported PR automation provider: {provider}')


def build_pr_state_from_github_webhook(payload: dict[str, Any], diff_text: str = '', tickets: list[dict[str, Any]] | None = None) -> PullRequestAutomationState:
    pr = payload.get('pull_request') if isinstance(payload.get('pull_request'), dict) else {}
    repo = payload.get('repository') if isinstance(payload.get('repository'), dict) else {}
    head = pr.get('head') if isinstance(pr.get('head'), dict) else {}
    base = pr.get('base') if isinstance(pr.get('base'), dict) else {}
    author = pr.get('user') if isinstance(pr.get('user'), dict) else {}
    return build_pr_state(
        provider='github',
        repository=repo.get('full_name') or '',
        repository_url=repo.get('html_url') or repo.get('clone_url'),
        pr_number=int(pr.get('number') or payload.get('number') or 0),
        pr_url=pr.get('html_url'),
        author=author.get('login') or '',
        title=pr.get('title') or '',
        description=pr.get('body') or '',
        base_branch=base.get('ref') or '',
        head_branch=head.get('ref') or '',
        base_sha=base.get('sha') or '',
        head_sha=head.get('sha') or '',
        state=pr.get('state') or 'open',
        default_branch=repo.get('default_branch'),
        visibility=repo.get('visibility') or ('private' if repo.get('private') else 'public' if 'private' in repo else 'unknown'),
        diff_text=diff_text,
        tickets=tickets,
    )


def build_pr_state_from_gitlab_webhook(payload: dict[str, Any], diff_text: str = '', tickets: list[dict[str, Any]] | None = None) -> PullRequestAutomationState:
    attrs = payload.get('object_attributes') if isinstance(payload.get('object_attributes'), dict) else {}
    project = payload.get('project') if isinstance(payload.get('project'), dict) else {}
    repository_payload = payload.get('repository') if isinstance(payload.get('repository'), dict) else {}
    user = payload.get('user') if isinstance(payload.get('user'), dict) else {}
    last_commit = attrs.get('last_commit') if isinstance(attrs.get('last_commit'), dict) else {}
    return build_pr_state(
        provider='gitlab',
        repository=project.get('path_with_namespace') or repository_payload.get('name') or project.get('name') or '',
        repository_url=project.get('web_url') or project.get('git_http_url'),
        pr_number=int(attrs.get('iid') or attrs.get('id') or 0),
        pr_url=attrs.get('url'),
        author=user.get('username') or user.get('name') or '',
        title=attrs.get('title') or '',
        description=attrs.get('description') or '',
        base_branch=attrs.get('target_branch') or '',
        head_branch=attrs.get('source_branch') or '',
        base_sha=attrs.get('oldrev') or '',
        head_sha=last_commit.get('id') or '',
        state=attrs.get('state') or attrs.get('action') or 'open',
        default_branch=project.get('default_branch'),
        visibility=project.get('visibility') or 'unknown',
        diff_text=diff_text,
        tickets=tickets,
    )


def build_pr_state_from_azure_devops_webhook(payload: dict[str, Any], diff_text: str = '', tickets: list[dict[str, Any]] | None = None) -> PullRequestAutomationState:
    resource = payload.get('resource') if isinstance(payload.get('resource'), dict) else {}
    repo = resource.get('repository') if isinstance(resource.get('repository'), dict) else {}
    project = repo.get('project') if isinstance(repo.get('project'), dict) else {}
    created_by = resource.get('createdBy') if isinstance(resource.get('createdBy'), dict) else {}
    source_commit = resource.get('lastMergeSourceCommit') if isinstance(resource.get('lastMergeSourceCommit'), dict) else {}
    target_commit = resource.get('lastMergeTargetCommit') if isinstance(resource.get('lastMergeTargetCommit'), dict) else {}
    containers = payload.get('resourceContainers') if isinstance(payload.get('resourceContainers'), dict) else {}
    project_container = containers.get('project') if isinstance(containers.get('project'), dict) else {}
    repository = repo.get('name') or repo.get('id') or ''
    if project.get('name') and repository:
        repository = f'{project["name"]}/{repository}'
    return build_pr_state(
        provider='azure-devops',
        repository=repository,
        repository_url=repo.get('remoteUrl') or repo.get('webUrl'),
        pr_number=int(resource.get('pullRequestId') or resource.get('codeReviewId') or 0),
        pr_url=resource.get('url') or project_container.get('baseUrl'),
        author=created_by.get('uniqueName') or created_by.get('displayName') or '',
        title=resource.get('title') or '',
        description=resource.get('description') or '',
        base_branch=strip_ref(resource.get('targetRefName') or ''),
        head_branch=strip_ref(resource.get('sourceRefName') or ''),
        base_sha=target_commit.get('commitId') or '',
        head_sha=source_commit.get('commitId') or '',
        state=resource.get('status') or 'open',
        default_branch=strip_ref(repo.get('defaultBranch') or ''),
        visibility=project.get('visibility') or 'unknown',
        diff_text=diff_text,
        tickets=tickets,
    )


def build_pr_state_from_bitbucket_webhook(payload: dict[str, Any], diff_text: str = '', tickets: list[dict[str, Any]] | None = None) -> PullRequestAutomationState:
    pr = payload.get('pullrequest') if isinstance(payload.get('pullrequest'), dict) else payload.get('pull_request') if isinstance(payload.get('pull_request'), dict) else {}
    repo = payload.get('repository') if isinstance(payload.get('repository'), dict) else {}
    actor = payload.get('actor') if isinstance(payload.get('actor'), dict) else {}
    source = pr.get('source') if isinstance(pr.get('source'), dict) else {}
    destination = pr.get('destination') if isinstance(pr.get('destination'), dict) else {}
    source_branch = source.get('branch') if isinstance(source.get('branch'), dict) else {}
    dest_branch = destination.get('branch') if isinstance(destination.get('branch'), dict) else {}
    source_commit = source.get('commit') if isinstance(source.get('commit'), dict) else {}
    dest_commit = destination.get('commit') if isinstance(destination.get('commit'), dict) else {}
    links = pr.get('links') if isinstance(pr.get('links'), dict) else {}
    html = links.get('html') if isinstance(links.get('html'), dict) else {}
    repo_links = repo.get('links') if isinstance(repo.get('links'), dict) else {}
    repo_html = repo_links.get('html') if isinstance(repo_links.get('html'), dict) else {}
    return build_pr_state(
        provider='bitbucket',
        repository=repo.get('full_name') or repo.get('slug') or repo.get('name') or '',
        repository_url=repo_html.get('href') or repo.get('website'),
        pr_number=int(pr.get('id') or 0),
        pr_url=html.get('href'),
        author=actor.get('username') or actor.get('display_name') or '',
        title=pr.get('title') or '',
        description=pr.get('description') or '',
        base_branch=dest_branch.get('name') or '',
        head_branch=source_branch.get('name') or '',
        base_sha=dest_commit.get('hash') or '',
        head_sha=source_commit.get('hash') or '',
        state=pr.get('state') or 'open',
        default_branch=(repo.get('mainbranch') or {}).get('name') if isinstance(repo.get('mainbranch'), dict) else None,
        visibility='private' if repo.get('is_private') else 'public' if 'is_private' in repo else 'unknown',
        diff_text=diff_text,
        tickets=tickets,
    )


def build_pr_state(
    provider: PullRequestProvider,
    repository: str,
    pr_number: int,
    repository_url: str | None = None,
    pr_url: str | None = None,
    author: str = '',
    title: str = '',
    description: str = '',
    base_branch: str = '',
    head_branch: str = '',
    base_sha: str = '',
    head_sha: str = '',
    state: str = 'open',
    default_branch: str | None = None,
    visibility: str = 'unknown',
    diff_text: str = '',
    file_changes: list[dict[str, Any]] | None = None,
    tickets: list[dict[str, Any]] | None = None,
    include_diff_excerpt: bool = False,
) -> PullRequestAutomationState:
    manifest = parse_unified_diff_manifest(diff_text) if diff_text else []
    if file_changes:
        manifest.extend(normalize_file_change(item) for item in file_changes)
    diff = PullRequestDiffSummary(
        raw_diff_included=False,
        raw_diff_sha256=sha256_text(diff_text) if diff_text else '',
        raw_diff_excerpt=safe_text(diff_text, 1000) if include_diff_excerpt else '',
        files_changed=len(manifest),
        additions=sum(item.additions for item in manifest),
        deletions=sum(item.deletions for item in manifest),
        generated_files=[item.path for item in manifest if looks_generated(item.path)],
        manifest=manifest,
    )
    hash_ticket_provider: TicketProvider = 'azure-devops' if provider == 'azure-devops' else 'github'
    ticket_refs = normalize_tickets(tickets or []) + extract_ticket_refs(title, description, head_branch, hash_provider=hash_ticket_provider)
    ticket_refs = dedupe_tickets(ticket_refs)
    intent = summarize_intent(title, description, ticket_refs)
    repo = PullRequestRepository(provider=provider, full_name=repository, clone_url=repository_url, default_branch=default_branch, visibility=visibility or 'unknown')
    identity = PullRequestIdentity(
        provider=provider,
        repository=repository,
        number=pr_number,
        url=pr_url,
        author=author,
        title=safe_text(title, 300),
        description_excerpt=safe_text(description, 1000),
        base_branch=base_branch,
        head_branch=head_branch,
        base_sha=base_sha,
        head_sha=head_sha,
        state=state or 'open',
    )
    return PullRequestAutomationState(
        state_id=pr_state_id(provider, repository, pr_number, head_sha),
        repository=repo,
        pull_request=identity,
        diff=diff,
        tickets=ticket_refs,
        intent=intent,
        evidence=[
            PullRequestEvidencePointer(kind='diff-digest', id=diff.raw_diff_sha256 or 'no-diff', description='SHA-256 digest of the PR diff; raw diff is not stored in state.', raw_content_included=False),
        ],
        agent_status={
            'ticket_hydration': 'pending',
            'impact_radius': 'pending',
            'invariant_policy': 'pending',
            'agent_fanout': 'pending',
            'feedback_composition': 'pending',
            'publisher': 'pending',
        },
    )


def verify_pr_webhook(provider: PullRequestProvider, raw_body: bytes, headers: dict[str, str]) -> dict[str, Any]:
    allow_unsigned = parse_bool(os.getenv('PR_AUTOMATION_WEBHOOK_ALLOW_UNSIGNED'), False) or parse_bool(os.getenv(f'PR_AUTOMATION_{provider_env(provider)}_WEBHOOK_ALLOW_UNSIGNED'), False)
    if provider == 'github':
        return verify_hmac_signature(
            raw_body,
            headers.get('x-hub-signature-256'),
            env_first('PR_AUTOMATION_GITHUB_WEBHOOK_SECRET', 'GITHUB_WEBHOOK_SECRET'),
            allow_unsigned=allow_unsigned or parse_bool(os.getenv('GITHUB_WEBHOOK_ALLOW_UNSIGNED'), False),
            algorithm='sha256',
            provider=provider,
        )
    if provider == 'gitlab':
        expected = env_first('PR_AUTOMATION_GITLAB_WEBHOOK_SECRET', 'GITLAB_WEBHOOK_SECRET', 'GITLAB_WEBHOOK_TOKEN')
        provided = headers.get('x-gitlab-token')
        return verify_plain_secret(provider, expected, provided, allow_unsigned or parse_bool(os.getenv('GITLAB_WEBHOOK_ALLOW_UNSIGNED'), False), 'X-Gitlab-Token')
    if provider == 'azure-devops':
        expected = env_first('PR_AUTOMATION_AZURE_DEVOPS_WEBHOOK_SECRET', 'AZURE_DEVOPS_WEBHOOK_SECRET')
        provided = headers.get('x-secure-review-pr-secret') or headers.get('x-azure-devops-webhook-secret')
        return verify_plain_secret(provider, expected, provided, allow_unsigned or parse_bool(os.getenv('AZURE_DEVOPS_WEBHOOK_ALLOW_UNSIGNED'), False), 'shared secret header')
    if provider == 'bitbucket':
        expected = env_first('PR_AUTOMATION_BITBUCKET_WEBHOOK_SECRET', 'BITBUCKET_WEBHOOK_SECRET')
        signature = headers.get('x-hub-signature-256') or headers.get('x-hub-signature')
        if signature:
            algorithm = 'sha256' if signature.startswith('sha256=') else 'sha1'
            return verify_hmac_signature(raw_body, signature, expected, allow_unsigned=allow_unsigned or parse_bool(os.getenv('BITBUCKET_WEBHOOK_ALLOW_UNSIGNED'), False), algorithm=algorithm, provider=provider)
        provided = headers.get('x-secure-review-pr-secret') or headers.get('x-bitbucket-webhook-secret')
        return verify_plain_secret(provider, expected, provided, allow_unsigned or parse_bool(os.getenv('BITBUCKET_WEBHOOK_ALLOW_UNSIGNED'), False), 'shared secret header')
    return {'valid': False, 'configured': False, 'reason': f'Unsupported provider: {provider}'}


def verify_hmac_signature(raw_body: bytes, signature: str | None, secret: str | None, allow_unsigned: bool, algorithm: str, provider: str) -> dict[str, Any]:
    if not secret:
        return {'valid': allow_unsigned, 'configured': False, 'reason': 'unsigned webhook allowed' if allow_unsigned else f'{provider} webhook secret is not configured'}
    prefix = f'{algorithm}='
    if not signature or not signature.startswith(prefix):
        return {'valid': False, 'configured': True, 'reason': f'missing or unsupported {provider} signature header'}
    digestmod = hashlib.sha256 if algorithm == 'sha256' else hashlib.sha1
    digest = hmac.new(secret.encode('utf-8'), raw_body, digestmod).hexdigest()
    expected = f'{prefix}{digest}'
    valid = hmac.compare_digest(expected, signature)
    return {'valid': valid, 'configured': True, 'reason': 'signature verified' if valid else 'signature mismatch'}


def verify_plain_secret(provider: str, expected: str | None, provided: str | None, allow_unsigned: bool, header_name: str) -> dict[str, Any]:
    if not expected:
        return {'valid': allow_unsigned, 'configured': False, 'reason': 'unsigned webhook allowed' if allow_unsigned else f'{provider} webhook secret is not configured'}
    if not provided:
        return {'valid': False, 'configured': True, 'reason': f'missing {header_name}'}
    valid = hmac.compare_digest(str(expected), str(provided))
    return {'valid': valid, 'configured': True, 'reason': 'secret verified' if valid else 'secret mismatch'}


def webhook_action(provider: PullRequestProvider, event: str, payload: dict[str, Any]) -> str:
    if provider == 'github':
        return safe_text(payload.get('action'), 80)
    if provider == 'gitlab':
        attrs = payload.get('object_attributes') if isinstance(payload.get('object_attributes'), dict) else {}
        return safe_text(attrs.get('action') or attrs.get('state'), 80)
    if provider == 'azure-devops':
        return safe_text(payload.get('eventType') or event, 120)
    if provider == 'bitbucket':
        return safe_text(event or payload.get('eventKey'), 120)
    return ''


def webhook_accepted(provider: PullRequestProvider, event: str, action: str, payload: dict[str, Any]) -> tuple[bool, str]:
    if provider == 'github':
        if event == 'pull_request' and action in {'opened', 'reopened', 'synchronize', 'ready_for_review', 'edited'} and payload.get('pull_request'):
            return True, 'GitHub pull request event accepted'
        return False, 'GitHub event ignored'
    if provider == 'gitlab':
        kind = str(payload.get('object_kind') or event).lower()
        if kind in {'merge_request', 'merge request hook'} and action in {'open', 'opened', 'reopen', 'reopened', 'update', 'updated'}:
            return True, 'GitLab merge request event accepted'
        return False, 'GitLab event ignored'
    if provider == 'azure-devops':
        event_type = str(payload.get('eventType') or event).lower()
        if 'pullrequest' in event_type and any(token in event_type for token in {'created', 'updated', 'merged'}):
            return True, 'Azure DevOps pull request event accepted'
        return False, 'Azure DevOps event ignored'
    if provider == 'bitbucket':
        event_key = str(event or payload.get('eventKey') or '').lower()
        if event_key in {'pullrequest:created', 'pullrequest:updated', 'pullrequest:rejected', 'pullrequest:fulfilled'}:
            return True, 'Bitbucket pull request event accepted'
        return False, 'Bitbucket event ignored'
    return False, 'Unsupported provider'


def save_pr_state(state: PullRequestAutomationState) -> Path:
    pr_states_dir().mkdir(parents=True, exist_ok=True)
    path = pr_state_path(state.state_id)
    path.write_text(state.model_dump_json(indent=2), encoding='utf-8')
    return path


def load_pr_state(state_id: str) -> PullRequestAutomationState:
    path = pr_state_path(state_id)
    if not path.exists():
        raise FileNotFoundError(state_id)
    return PullRequestAutomationState.model_validate_json(path.read_text(encoding='utf-8'))


def list_pr_states(limit: int = 100) -> list[dict[str, Any]]:
    directory = pr_states_dir()
    if not directory.exists():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob('*.json'), key=lambda item: item.stat().st_mtime, reverse=True)[: max(1, min(limit, 1000))]:
        try:
            state = PullRequestAutomationState.model_validate_json(path.read_text(encoding='utf-8'))
        except Exception:
            continue
        records.append({
            'state_id': state.state_id,
            'provider': state.pull_request.provider,
            'repository': state.pull_request.repository,
            'pull_request': state.pull_request.number,
            'head_sha': state.pull_request.head_sha,
            'created_at': state.created_at.isoformat(),
            'updated_at': state.updated_at.isoformat(),
            'files_changed': state.diff.files_changed,
            'ticket_count': len(state.tickets),
            'path': str(path),
        })
    return records


def record_pr_ingress_governance(result: dict[str, Any]) -> None:
    try:
        from .governance import record_governance_event

        state = result.get('state') or {}
        pr = state.get('pull_request') if isinstance(state.get('pull_request'), dict) else {}
        record_governance_event(
            category='pr-automation',
            action='pr_ingress.state_created',
            actor=f"{result.get('provider')}-webhook",
            resource=result.get('state_id') or 'pr-automation',
            scan_id=None,
            metadata={
                'provider': safe_text(result.get('provider'), 80),
                'event': safe_text(result.get('event'), 120),
                'action': safe_text(result.get('action'), 120),
                'repository': safe_text(pr.get('repository'), 200),
                'pull_request': safe_text(pr.get('number'), 40),
            },
        )
    except Exception:
        pass


def build_impact_radius_report(state: PullRequestAutomationState) -> PullRequestImpactRadiusReport:
    manifest = state.diff.manifest
    computed_at = datetime.now(timezone.utc)
    if not manifest:
        return PullRequestImpactRadiusReport(
            status='no_files',
            computed_at=computed_at,
            overall_risk='none',
            risk_score=0,
            blast_radius='unknown',
            guardrails=impact_radius_guardrails(),
        )

    intent_text = impact_intent_text(state)
    intent_keywords = risk_keywords_for_text(intent_text)
    grouped: dict[str, dict[str, Any]] = {}
    cross_cutting: set[str] = set()
    critical_files: list[str] = []
    generated_files: list[str] = []
    recommended_agents: set[str] = set()

    for change in manifest:
        classification = classify_file_impact(change, intent_keywords)
        name = classification['module']
        module = grouped.setdefault(name, {
            'name': name,
            'path_prefix': classification['path_prefix'],
            'files_changed': 0,
            'additions': 0,
            'deletions': 0,
            'languages': set(),
            'risk_score': 0,
            'reasons': set(),
            'review_focus': set(),
            'files': [],
        })
        module['files_changed'] += 1
        module['additions'] += max(0, change.additions)
        module['deletions'] += max(0, change.deletions)
        if change.language != 'unknown':
            module['languages'].add(change.language)
        module['risk_score'] += classification['risk_score']
        module['reasons'].update(classification['reasons'])
        module['review_focus'].update(classification['review_focus'])
        module['files'].append(change.path)
        cross_cutting.update(classification['concerns'])
        recommended_agents.update(classification['agents'])
        if classification['critical']:
            critical_files.append(change.path)
        if change.path in state.diff.generated_files or looks_generated(change.path):
            generated_files.append(change.path)

    modules: list[PullRequestImpactModule] = []
    for item in grouped.values():
        score = min(100, int(item['risk_score']) + module_size_score(item['files_changed'], item['additions'], item['deletions']))
        modules.append(PullRequestImpactModule(
            name=item['name'],
            path_prefix=item['path_prefix'],
            files_changed=item['files_changed'],
            additions=item['additions'],
            deletions=item['deletions'],
            languages=sorted(item['languages']),
            risk_score=score,
            risk_level=risk_level(score),
            reasons=sorted(item['reasons'])[:12],
            review_focus=sorted(item['review_focus'])[:10],
            files=sorted(item['files'])[:50],
        ))
    modules.sort(key=lambda module: (module.risk_score, module.files_changed), reverse=True)

    overall_score = overall_impact_score(modules, len(manifest), cross_cutting, critical_files)
    concerns = sorted(cross_cutting)
    return PullRequestImpactRadiusReport(
        status='completed',
        computed_at=computed_at,
        overall_risk=risk_level(overall_score),
        risk_score=overall_score,
        blast_radius=blast_radius_for(modules, len(manifest), concerns),
        modules=modules,
        critical_files=sorted(set(critical_files))[:50],
        generated_files=sorted(set(generated_files))[:50],
        cross_cutting_concerns=concerns,
        test_recommendations=impact_test_recommendations(modules, concerns, state),
        recommended_agents=sorted(recommended_agents)[:12],
        raw_code_included=False,
        guardrails=impact_radius_guardrails(),
    )


def classify_file_impact(change: PullRequestFileChange, intent_keywords: list[str]) -> dict[str, Any]:
    path = normalize_path(change.path)
    lowered = path.lower()
    concerns: set[str] = set()
    reasons: set[str] = set()
    review_focus: set[str] = set()
    agents: set[str] = set()
    score = 8
    critical = False

    module, path_prefix = impact_module_for_path(path)
    if change.status in {'deleted', 'renamed'}:
        score += 6
        reasons.add(f'{change.status} file')
    if change.changes >= 500:
        score += 20
        reasons.add('large change volume')
    elif change.changes >= 100:
        score += 12
        reasons.add('moderate change volume')
    elif change.changes >= 25:
        score += 6
        reasons.add('non-trivial change volume')

    if change.language != 'unknown':
        agents.add(agent_for_language(change.language))
        review_focus.add(f'{change.language} change review')

    if is_dependency_file(lowered):
        module, path_prefix = 'dependencies', 'dependency manifests'
        score += 24
        concerns.add('dependency-supply-chain')
        reasons.add('dependency manifest or lockfile changed')
        review_focus.add('dependency and SBOM impact')
        agents.add('dependency-sbom-agent')
        critical = True
    if is_ci_file(lowered):
        module, path_prefix = 'ci-cd', 'pipeline configuration'
        score += 22
        concerns.add('ci-cd')
        reasons.add('CI/CD workflow changed')
        review_focus.add('pipeline trust boundary')
        agents.add('iac-devops-agent')
        critical = True
    if is_iac_file(lowered):
        module, path_prefix = 'infrastructure', 'infrastructure as code'
        score += 20
        concerns.add('infrastructure')
        reasons.add('infrastructure/deployment file changed')
        review_focus.add('deployment and cloud permissions')
        agents.add('iac-devops-agent')
        critical = True
    if is_database_file(lowered):
        score += 18
        concerns.add('database-schema')
        reasons.add('database schema or migration changed')
        review_focus.add('schema and migration safety')
    if is_security_sensitive_path(lowered):
        score += 26
        concerns.add('security-sensitive')
        reasons.add('security-sensitive path changed')
        review_focus.add('authentication and authorization boundaries')
        agents.add('secrets-malware-quarantine-agent')
        critical = True
    if is_config_file(lowered):
        score += 14
        concerns.add('runtime-configuration')
        reasons.add('runtime or build configuration changed')
        review_focus.add('configuration safety')
    if looks_generated(lowered):
        score += 4
        reasons.add('generated or vendored artifact changed')
        review_focus.add('generated artifact review')
        agents.add('scanner-reliability-agent')
    if is_test_file(lowered):
        score = max(6, score - 10)
        concerns.add('test-coverage')
        reasons.add('test file changed')
        review_focus.add('test coverage review')
    if is_docs_file(lowered):
        score = max(4, score - 12)
        concerns.add('documentation')
        reasons.add('documentation changed')

    for keyword in intent_keywords:
        focus = intent_keyword_focus(keyword)
        if focus:
            score += 3
            review_focus.add(focus)
            if keyword in {'auth', 'secret', 'token', 'permission', 'crypto', 'webhook'}:
                concerns.add('security-sensitive')

    return {
        'module': module,
        'path_prefix': path_prefix,
        'risk_score': min(100, score),
        'reasons': reasons or {'file changed'},
        'review_focus': review_focus,
        'concerns': concerns,
        'agents': {agent for agent in agents if agent},
        'critical': critical,
    }


def impact_module_for_path(path: str) -> tuple[str, str]:
    parts = [part for part in normalize_path(path).split('/') if part]
    if not parts:
        return 'root', ''
    first = parts[0]
    if first in {'.github', '.gitlab', '.circleci', 'azure-pipelines.yml'}:
        return 'ci-cd', first
    if first in {'terraform', 'infra', 'infrastructure', 'deploy', 'deployment', 'k8s', 'charts'}:
        return 'infrastructure', first
    if first in {'tests', 'test', 'spec', 'docs', 'doc'}:
        return first, first
    if first in {'services', 'apps', 'packages'} and len(parts) >= 2:
        return f'{first}/{parts[1]}', f'{first}/{parts[1]}'
    if first in {'src', 'app', 'lib', 'pkg', 'cmd', 'internal'}:
        return first, first
    if len(parts) == 1:
        return 'root', ''
    return first, first


def overall_impact_score(modules: list[PullRequestImpactModule], file_count: int, concerns: set[str], critical_files: list[str]) -> int:
    if not modules:
        return 0
    score = max(module.risk_score for module in modules)
    if len(modules) >= 5:
        score += 18
    elif len(modules) >= 3:
        score += 10
    if file_count >= 30:
        score += 16
    elif file_count >= 10:
        score += 8
    if len(concerns) >= 4:
        score += 10
    if critical_files:
        score += 8
    return min(100, score)


def module_size_score(files_changed: int, additions: int, deletions: int) -> int:
    changed_lines = additions + deletions
    score = 0
    if files_changed >= 10:
        score += 14
    elif files_changed >= 4:
        score += 8
    if changed_lines >= 1000:
        score += 18
    elif changed_lines >= 300:
        score += 12
    elif changed_lines >= 75:
        score += 6
    return score


def risk_level(score: int) -> ImpactRiskLevel:
    if score <= 0:
        return 'none'
    if score >= 85:
        return 'critical'
    if score >= 65:
        return 'high'
    if score >= 35:
        return 'medium'
    return 'low'


def blast_radius_for(modules: list[PullRequestImpactModule], file_count: int, concerns: list[str]) -> str:
    if not modules:
        return 'unknown'
    if len(modules) == 1 and file_count <= 3 and not {'dependency-supply-chain', 'ci-cd', 'infrastructure'} & set(concerns):
        return 'localized'
    if len(modules) <= 3 and file_count <= 12:
        return 'contained'
    if len(modules) <= 6:
        return 'broad'
    return 'cross-cutting'


def impact_test_recommendations(modules: list[PullRequestImpactModule], concerns: list[str], state: PullRequestAutomationState) -> list[str]:
    recommendations: list[str] = []
    concern_set = set(concerns)
    languages = {language for module in modules for language in module.languages}
    if 'security-sensitive' in concern_set:
        recommendations.append('Run authentication, authorization, token, and secret-handling regression tests.')
    if 'dependency-supply-chain' in concern_set:
        recommendations.append('Run dependency audit, SBOM generation, and lockfile integrity checks.')
    if 'ci-cd' in concern_set:
        recommendations.append('Run CI/CD workflow validation with least-privilege permission review.')
    if 'infrastructure' in concern_set:
        recommendations.append('Run IaC validation and deployment plan review before merge.')
    if 'database-schema' in concern_set:
        recommendations.append('Run migration, rollback, and data-compatibility tests.')
    if 'python' in languages:
        recommendations.append('Run Python unit tests and focused static analysis for changed Python modules.')
    if {'javascript', 'typescript'} & languages:
        recommendations.append('Run JavaScript/TypeScript tests, type checks, and package audit.')
    if 'go' in languages:
        recommendations.append('Run Go tests, go vet, and govulncheck for changed packages.')
    if not recommendations:
        recommendations.append('Run targeted unit tests for the changed modules and one integration smoke test.')
    if state.diff.files_changed >= 10:
        recommendations.append('Run broader integration tests because the PR touches many files.')
    return dedupe_strings(recommendations)[:10]


def record_pr_impact_governance(state: PullRequestAutomationState, report: PullRequestImpactRadiusReport) -> None:
    try:
        from .governance import record_governance_event

        record_governance_event(
            category='pr-automation',
            action='pr_impact_radius.completed',
            actor='pr-automation',
            resource=state.state_id,
            scan_id=None,
            reason='PR impact radius was computed from bounded PR state and file manifest metadata.',
            metadata={
                'repository': safe_text(state.pull_request.repository, 200),
                'pull_request': str(state.pull_request.number),
                'status': report.status,
                'overall_risk': report.overall_risk,
                'risk_score': str(report.risk_score),
                'blast_radius': report.blast_radius,
                'modules': str(len(report.modules)),
                'critical_files': str(len(report.critical_files)),
            },
            evidence_refs={
                'state_id': state.state_id,
                'modules': [module.name for module in report.modules],
                'cross_cutting_concerns': report.cross_cutting_concerns,
            },
        )
    except Exception:
        pass


def build_policy_agent_report(state: PullRequestAutomationState) -> PullRequestPolicyAgentReport:
    checks = [
        policy_check_raw_code_invariant(state),
        policy_check_high_impact_review(state),
        policy_check_security_tests(state),
        policy_check_dependency_review(state),
        policy_check_ci_iac_review(state),
        policy_check_database_migration(state),
        policy_check_generated_artifacts(state),
        policy_check_ticket_hydration(state),
        policy_check_broad_radius_tests(state),
        policy_check_sensitive_delete_or_rename(state),
    ]
    violations = sum(1 for check in checks if check.status == 'violation')
    warnings = sum(1 for check in checks if check.status == 'warning')
    passed = sum(1 for check in checks if check.status == 'passed')
    blocked_by_policy = any(check.status == 'violation' and severity_rank(check.severity) >= severity_rank('CRITICAL') for check in checks)
    decision: PolicyDecision = 'blocked' if blocked_by_policy else 'review_required' if violations or warnings else 'passed'
    required_actions = dedupe_strings([action for check in checks for action in check.required_actions])
    required_agents = policy_required_agents(state, checks)
    return PullRequestPolicyAgentReport(
        status='completed',
        decision=decision,
        computed_at=datetime.now(timezone.utc),
        checks=checks,
        violations=violations,
        warnings=warnings,
        passed=passed,
        required_actions=required_actions,
        required_agents=required_agents,
        blocked_by_policy=blocked_by_policy,
        raw_code_included=False,
        guardrails=policy_agent_guardrails(),
    )


def policy_check_raw_code_invariant(state: PullRequestAutomationState) -> PullRequestPolicyCheck:
    raw_evidence = [item.kind for item in state.evidence if item.raw_content_included]
    raw_included = state.diff.raw_diff_included or state.impact_radius.raw_code_included or state.policy_report.raw_code_included or bool(raw_evidence)
    if raw_included:
        return PullRequestPolicyCheck(
            check_id='SR-PR-POLICY-001',
            category='state-safety',
            title='PR state must not persist raw code or raw diff evidence',
            status='violation',
            severity='CRITICAL',
            evidence={
                'raw_diff_included': str(state.diff.raw_diff_included),
                'raw_evidence_kinds': ','.join(raw_evidence),
            },
            recommendation='Remove raw code/diff payloads from durable PR automation state and keep only digests, paths, stats, and bounded summaries.',
            required_actions=['Strip raw code/diff payloads from PR automation state before continuing automated review.'],
        )
    return PullRequestPolicyCheck(
        check_id='SR-PR-POLICY-001',
        category='state-safety',
        title='PR state must not persist raw code or raw diff evidence',
        status='passed',
        severity='INFO',
        evidence={'raw_diff_included': 'False', 'raw_content_evidence': '0'},
    )


def policy_check_high_impact_review(state: PullRequestAutomationState) -> PullRequestPolicyCheck:
    risk = state.impact_radius.overall_risk
    if risk in {'high', 'critical'}:
        return PullRequestPolicyCheck(
            check_id='SR-PR-POLICY-010',
            category='review-gate',
            title='High-impact PR requires policy-gated human review',
            status='warning',
            severity='HIGH' if risk == 'high' else 'CRITICAL',
            evidence={
                'overall_risk': risk,
                'risk_score': str(state.impact_radius.risk_score),
                'blast_radius': state.impact_radius.blast_radius,
            },
            recommendation='Route the PR through security/owner review and keep publication disabled until required checks are satisfied.',
            required_actions=['Require explicit reviewer approval for high or critical impact radius before publication.'],
            related_modules=[module.name for module in state.impact_radius.modules[:8]],
        )
    return PullRequestPolicyCheck(
        check_id='SR-PR-POLICY-010',
        category='review-gate',
        title='High-impact PR requires policy-gated human review',
        status='passed' if state.impact_radius.status == 'completed' else 'not_applicable',
        severity='INFO',
        evidence={'overall_risk': risk, 'impact_status': state.impact_radius.status},
    )


def policy_check_security_tests(state: PullRequestAutomationState) -> PullRequestPolicyCheck:
    concerns = set(state.impact_radius.cross_cutting_concerns)
    sensitive_files = state.impact_radius.critical_files
    test_files = changed_test_files(state)
    if 'security-sensitive' in concerns and not test_files:
        return PullRequestPolicyCheck(
            check_id='SR-PR-POLICY-020',
            category='security-invariant',
            title='Security-sensitive changes need focused test evidence',
            status='violation',
            severity='HIGH',
            evidence={
                'security_sensitive': 'True',
                'changed_test_files': '0',
                'critical_files': ','.join(sensitive_files[:10]),
            },
            recommendation='Add or reference focused tests for authentication, authorization, token, secret, or webhook behavior touched by this PR.',
            required_actions=['Provide focused security regression tests or attach an approved test exception.'],
            related_files=sensitive_files[:20],
            related_modules=[module.name for module in state.impact_radius.modules if 'security-sensitive path changed' in module.reasons],
        )
    return PullRequestPolicyCheck(
        check_id='SR-PR-POLICY-020',
        category='security-invariant',
        title='Security-sensitive changes need focused test evidence',
        status='passed' if 'security-sensitive' in concerns else 'not_applicable',
        severity='INFO',
        evidence={'security_sensitive': str('security-sensitive' in concerns), 'changed_test_files': str(len(test_files))},
        related_files=test_files[:20],
    )


def policy_check_dependency_review(state: PullRequestAutomationState) -> PullRequestPolicyCheck:
    concerns = set(state.impact_radius.cross_cutting_concerns)
    files = [change.path for change in state.diff.manifest if is_dependency_file(normalize_path(change.path).lower())]
    if 'dependency-supply-chain' in concerns or files:
        return PullRequestPolicyCheck(
            check_id='SR-PR-POLICY-030',
            category='supply-chain',
            title='Dependency changes require SBOM and vulnerability review',
            status='warning',
            severity='HIGH',
            evidence={'dependency_files': ','.join(files[:20]), 'file_count': str(len(files))},
            recommendation='Run dependency review, SBOM generation, vulnerable package checks, and lockfile integrity validation before merge.',
            required_actions=['Run dependency/SBOM review and attach the resulting evidence to the PR decision.'],
            related_files=files[:20],
            related_modules=['dependencies'] if files else [],
        )
    return PullRequestPolicyCheck(
        check_id='SR-PR-POLICY-030',
        category='supply-chain',
        title='Dependency changes require SBOM and vulnerability review',
        status='not_applicable',
        severity='INFO',
        evidence={'dependency_files': '0'},
    )


def policy_check_ci_iac_review(state: PullRequestAutomationState) -> PullRequestPolicyCheck:
    concerns = set(state.impact_radius.cross_cutting_concerns)
    files = [change.path for change in state.diff.manifest if is_ci_file(normalize_path(change.path).lower()) or is_iac_file(normalize_path(change.path).lower())]
    if {'ci-cd', 'infrastructure'} & concerns or files:
        return PullRequestPolicyCheck(
            check_id='SR-PR-POLICY-040',
            category='deployment-policy',
            title='CI/CD and IaC changes require least-privilege review',
            status='warning',
            severity='HIGH',
            evidence={'deployment_files': ','.join(files[:20]), 'concerns': ','.join(sorted({'ci-cd', 'infrastructure'} & concerns))},
            recommendation='Review workflow permissions, secret exposure, cloud/IaC plan output, and deployment blast radius before merge.',
            required_actions=['Complete CI/CD or IaC least-privilege review before publication.'],
            related_files=files[:20],
            related_modules=[module.name for module in state.impact_radius.modules if module.name in {'ci-cd', 'infrastructure'}],
        )
    return PullRequestPolicyCheck(
        check_id='SR-PR-POLICY-040',
        category='deployment-policy',
        title='CI/CD and IaC changes require least-privilege review',
        status='not_applicable',
        severity='INFO',
        evidence={'deployment_files': '0'},
    )


def policy_check_database_migration(state: PullRequestAutomationState) -> PullRequestPolicyCheck:
    concerns = set(state.impact_radius.cross_cutting_concerns)
    files = [change.path for change in state.diff.manifest if is_database_file(normalize_path(change.path).lower())]
    if 'database-schema' in concerns or files:
        return PullRequestPolicyCheck(
            check_id='SR-PR-POLICY-050',
            category='data-safety',
            title='Database schema changes require migration and rollback evidence',
            status='warning',
            severity='MEDIUM',
            evidence={'database_files': ','.join(files[:20]), 'file_count': str(len(files))},
            recommendation='Require migration, rollback, and backward-compatibility evidence before merge.',
            required_actions=['Attach migration, rollback, and data compatibility validation evidence.'],
            related_files=files[:20],
        )
    return PullRequestPolicyCheck(
        check_id='SR-PR-POLICY-050',
        category='data-safety',
        title='Database schema changes require migration and rollback evidence',
        status='not_applicable',
        severity='INFO',
        evidence={'database_files': '0'},
    )


def policy_check_generated_artifacts(state: PullRequestAutomationState) -> PullRequestPolicyCheck:
    files = state.impact_radius.generated_files or state.diff.generated_files
    if files:
        return PullRequestPolicyCheck(
            check_id='SR-PR-POLICY-060',
            category='review-integrity',
            title='Generated or vendored artifact changes require source-of-truth review',
            status='warning',
            severity='MEDIUM',
            evidence={'generated_files': ','.join(files[:20]), 'file_count': str(len(files))},
            recommendation='Confirm generated/vendor changes came from an approved source-of-truth update and do not hide security-relevant behavior.',
            required_actions=['Confirm generated or vendored artifacts match an approved source-of-truth change.'],
            related_files=files[:20],
        )
    return PullRequestPolicyCheck(
        check_id='SR-PR-POLICY-060',
        category='review-integrity',
        title='Generated or vendored artifact changes require source-of-truth review',
        status='not_applicable',
        severity='INFO',
        evidence={'generated_files': '0'},
    )


def policy_check_ticket_hydration(state: PullRequestAutomationState) -> PullRequestPolicyCheck:
    if not state.tickets:
        return PullRequestPolicyCheck(
            check_id='SR-PR-POLICY-070',
            category='context-quality',
            title='Ticketed PRs should include hydrated intent context',
            status='not_applicable',
            severity='INFO',
            evidence={'ticket_count': '0'},
        )
    hydrated = [ticket.key for ticket in state.tickets if ticket.hydrated]
    if not hydrated:
        return PullRequestPolicyCheck(
            check_id='SR-PR-POLICY-070',
            category='context-quality',
            title='Ticketed PRs should include hydrated intent context',
            status='warning',
            severity='LOW',
            evidence={'ticket_count': str(len(state.tickets)), 'hydrated_count': '0', 'ticket_hydration_status': state.agent_status.get('ticket_hydration', '')},
            recommendation='Hydrate ticket metadata when provider credentials are available, or record why ticket context was unavailable.',
            required_actions=['Hydrate ticket context or record a ticket-context exception before relying on intent routing.'],
        )
    return PullRequestPolicyCheck(
        check_id='SR-PR-POLICY-070',
        category='context-quality',
        title='Ticketed PRs should include hydrated intent context',
        status='passed',
        severity='INFO',
        evidence={'ticket_count': str(len(state.tickets)), 'hydrated_count': str(len(hydrated))},
    )


def policy_check_broad_radius_tests(state: PullRequestAutomationState) -> PullRequestPolicyCheck:
    if state.impact_radius.blast_radius in {'broad', 'cross-cutting'}:
        return PullRequestPolicyCheck(
            check_id='SR-PR-POLICY-080',
            category='test-policy',
            title='Broad impact radius requires integration coverage',
            status='warning',
            severity='MEDIUM',
            evidence={'blast_radius': state.impact_radius.blast_radius, 'files_changed': str(state.diff.files_changed), 'modules': ','.join(state.impact_radius_modules[:12])},
            recommendation='Run broader integration or smoke coverage and route the PR through the relevant specialist agents.',
            required_actions=['Run integration/smoke coverage for the impacted modules before publication.'],
            related_modules=state.impact_radius_modules[:12],
        )
    return PullRequestPolicyCheck(
        check_id='SR-PR-POLICY-080',
        category='test-policy',
        title='Broad impact radius requires integration coverage',
        status='passed' if state.impact_radius.status == 'completed' else 'not_applicable',
        severity='INFO',
        evidence={'blast_radius': state.impact_radius.blast_radius},
    )


def policy_check_sensitive_delete_or_rename(state: PullRequestAutomationState) -> PullRequestPolicyCheck:
    files = [
        change.path
        for change in state.diff.manifest
        if change.status in {'deleted', 'renamed'} and is_security_sensitive_path(normalize_path(change.path).lower())
    ]
    if files:
        return PullRequestPolicyCheck(
            check_id='SR-PR-POLICY-090',
            category='security-invariant',
            title='Deleting or renaming security-sensitive files requires blocker review',
            status='violation',
            severity='CRITICAL',
            evidence={'sensitive_deleted_or_renamed': ','.join(files[:20]), 'file_count': str(len(files))},
            recommendation='Block automated publication until an owner confirms the security-sensitive delete/rename is intentional and tested.',
            required_actions=['Obtain explicit owner/security approval for security-sensitive delete or rename.'],
            related_files=files[:20],
        )
    return PullRequestPolicyCheck(
        check_id='SR-PR-POLICY-090',
        category='security-invariant',
        title='Deleting or renaming security-sensitive files requires blocker review',
        status='not_applicable',
        severity='INFO',
        evidence={'sensitive_deleted_or_renamed': '0'},
    )


def merge_policy_agent_findings(existing: list[PullRequestAgentFinding], report: PullRequestPolicyAgentReport) -> list[PullRequestAgentFinding]:
    retained = [finding for finding in existing if finding.evidence.get('agent') != 'invariant-policy-agent']
    policy_findings = []
    for check in report.checks:
        if check.status not in {'violation', 'warning'}:
            continue
        policy_findings.append(PullRequestAgentFinding(
            category='invariant',
            title=check.title,
            severity=check.severity,
            file_path=check.related_files[0] if check.related_files else None,
            evidence={
                'agent': 'invariant-policy-agent',
                'check_id': check.check_id,
                'status': check.status,
                **check.evidence,
            },
            recommendation=check.recommendation or '; '.join(check.required_actions),
        ))
    return retained + policy_findings


def policy_required_agents(state: PullRequestAutomationState, checks: list[PullRequestPolicyCheck]) -> list[str]:
    agents = list(state.impact_radius.recommended_agents)
    for check in checks:
        if check.status not in {'violation', 'warning'}:
            continue
        if check.category in {'security-invariant', 'state-safety'}:
            agents.append('secrets-malware-quarantine-agent')
        if check.category == 'supply-chain':
            agents.append('dependency-sbom-agent')
        if check.category == 'deployment-policy':
            agents.append('iac-devops-agent')
        if check.category == 'review-integrity':
            agents.append('scanner-reliability-agent')
    return dedupe_strings([agent for agent in agents if agent])[:12]


def record_pr_policy_governance(state: PullRequestAutomationState, report: PullRequestPolicyAgentReport) -> None:
    try:
        from .governance import record_governance_event

        record_governance_event(
            category='pr-automation',
            action='pr_policy_agent.completed',
            actor='pr-automation',
            resource=state.state_id,
            scan_id=None,
            reason='Invariant and policy agent evaluated bounded PR state before agent fan-out.',
            metadata={
                'repository': safe_text(state.pull_request.repository, 200),
                'pull_request': str(state.pull_request.number),
                'decision': report.decision,
                'violations': str(report.violations),
                'warnings': str(report.warnings),
                'blocked_by_policy': str(report.blocked_by_policy),
            },
            evidence_refs={
                'state_id': state.state_id,
                'checks': [check.check_id for check in report.checks if check.status in {'warning', 'violation'}],
                'required_agents': report.required_agents,
            },
        )
    except Exception:
        pass


def build_feedback_report(state: PullRequestAutomationState) -> PullRequestFeedbackReport:
    publication_state = feedback_publication_state(state.policy_report)
    overview = feedback_overview_bullets(state)
    required_actions = dedupe_strings(state.policy_report.required_actions)
    test_recommendations = dedupe_strings(state.impact_radius.test_recommendations)
    recommended_agents = dedupe_strings(state.policy_report.required_agents or state.impact_radius.recommended_agents)
    general_comments = build_general_feedback_comments(state, publication_state)
    file_comments = build_file_feedback_comments(state)
    comment_count = len(general_comments) + len(file_comments)
    summary = build_feedback_summary_markdown(
        state,
        publication_state,
        overview,
        required_actions,
        test_recommendations,
        recommended_agents,
        file_comments,
    )
    return PullRequestFeedbackReport(
        status='completed',
        publication_state=publication_state,
        composed_at=datetime.now(timezone.utc),
        summary_markdown=summary,
        overview_bullets=overview,
        required_actions=required_actions,
        test_recommendations=test_recommendations,
        recommended_agents=recommended_agents,
        general_comments=general_comments,
        file_comments=file_comments,
        comment_count=comment_count,
        raw_code_included=False,
        guardrails=feedback_composer_guardrails(),
    )


def feedback_publication_state(policy_report: PullRequestPolicyAgentReport) -> FeedbackPublicationState:
    if policy_report.decision == 'blocked' or policy_report.blocked_by_policy:
        return 'blocked'
    if policy_report.decision == 'review_required' or policy_report.violations or policy_report.warnings:
        return 'requires_review'
    return 'ready'


def feedback_overview_bullets(state: PullRequestAutomationState) -> list[str]:
    bullets = [
        f'Intent: {safe_text(state.intent.summary or state.pull_request.title or "No intent summary supplied.", 220)}',
        f'Impact: {state.impact_radius.overall_risk} risk, {state.impact_radius.blast_radius} blast radius, {len(state.impact_radius.modules)} impacted modules.',
        f'Policy: {state.policy_report.decision} with {state.policy_report.violations} violation(s) and {state.policy_report.warnings} warning(s).',
    ]
    if state.intent.ticket_keys:
        bullets.append(f'Tickets: {", ".join(state.intent.ticket_keys[:8])}.')
    if state.impact_radius.cross_cutting_concerns:
        bullets.append(f'Concerns: {", ".join(state.impact_radius.cross_cutting_concerns[:8])}.')
    return dedupe_strings(bullets)


def build_general_feedback_comments(state: PullRequestAutomationState, publication_state: FeedbackPublicationState) -> list[PullRequestFeedbackItem]:
    comments = [
        PullRequestFeedbackItem(
            title='Secure Review PR Summary',
            body=build_general_summary_body(state, publication_state),
            requires_human_review=publication_state != 'ready',
            severity='HIGH' if publication_state == 'blocked' else 'MEDIUM' if publication_state == 'requires_review' else 'INFO',
            category='summary',
            source='pr-feedback-composer',
        )
    ]
    if state.policy_report.required_actions:
        comments.append(PullRequestFeedbackItem(
            title='Required Actions Before Publication',
            body=bullet_lines(state.policy_report.required_actions),
            requires_human_review=True,
            severity='HIGH' if publication_state == 'blocked' else 'MEDIUM',
            category='policy',
            source='pr-feedback-composer',
        ))
    if state.impact_radius.test_recommendations:
        comments.append(PullRequestFeedbackItem(
            title='Recommended Validation',
            body=bullet_lines(state.impact_radius.test_recommendations),
            requires_human_review=True,
            severity='MEDIUM',
            category='validation',
            source='pr-feedback-composer',
        ))
    if state.policy_report.required_agents:
        comments.append(PullRequestFeedbackItem(
            title='Recommended Specialist Routing',
            body=bullet_lines([agent_label(agent) for agent in state.policy_report.required_agents]),
            requires_human_review=True,
            severity='INFO',
            category='routing',
            source='pr-feedback-composer',
        ))
    return comments


def build_file_feedback_comments(state: PullRequestAutomationState) -> list[PullRequestFeedbackItem]:
    comments: list[PullRequestFeedbackItem] = []
    for check in state.policy_report.checks:
        if check.status not in {'violation', 'warning'}:
            continue
        files = check.related_files or files_for_policy_check(state, check)
        for file_path in files[:5]:
            comments.append(PullRequestFeedbackItem(
                title=check.title,
                body=policy_file_comment_body(check),
                file_path=file_path,
                requires_human_review=True,
                severity=check.severity,
                category=check.category,
                source='invariant-policy-agent',
                source_finding_ids=[check.check_id],
            ))
    for module in state.impact_radius.modules[:5]:
        if module.risk_level not in {'high', 'critical'}:
            continue
        for file_path in module.files[:3]:
            comments.append(PullRequestFeedbackItem(
                title=f'High-impact module: {module.name}',
                body=impact_file_comment_body(module),
                file_path=file_path,
                requires_human_review=True,
                severity='HIGH' if module.risk_level == 'high' else 'CRITICAL',
                category='impact-radius',
                source='impact-radius-analyzer',
            ))
    return dedupe_feedback_items(comments)[:30]


def build_feedback_summary_markdown(
    state: PullRequestAutomationState,
    publication_state: FeedbackPublicationState,
    overview: list[str],
    required_actions: list[str],
    test_recommendations: list[str],
    recommended_agents: list[str],
    file_comments: list[PullRequestFeedbackItem],
) -> str:
    lines = [
        '## Secure Review Draft',
        '',
        f'Publication state: **{publication_state}**',
        '',
        '### Overview',
        *[f'- {item}' for item in overview],
    ]
    if required_actions:
        lines.extend(['', '### Required Actions', *[f'- {item}' for item in required_actions[:10]]])
    if test_recommendations:
        lines.extend(['', '### Validation', *[f'- {item}' for item in test_recommendations[:10]]])
    if recommended_agents:
        lines.extend(['', '### Recommended Routing', *[f'- {agent_label(agent)}' for agent in recommended_agents[:10]]])
    if file_comments:
        lines.extend(['', '### File-Scoped Draft Comments', *[f'- `{item.file_path}`: {item.title}' for item in file_comments[:12] if item.file_path]])
    lines.extend([
        '',
        'Guardrail: this is a draft review artifact only. It has not been published to the code host.',
    ])
    return safe_text('\n'.join(lines), 6000)


def build_general_summary_body(state: PullRequestAutomationState, publication_state: FeedbackPublicationState) -> str:
    lines = [
        f'Publication state: {publication_state}.',
        f'Intent confidence: {state.intent.confidence}.',
        f'Impact radius: {state.impact_radius.overall_risk} risk across {len(state.impact_radius.modules)} module(s).',
        f'Policy decision: {state.policy_report.decision}.',
    ]
    if state.impact_radius.cross_cutting_concerns:
        lines.append(f'Cross-cutting concerns: {", ".join(state.impact_radius.cross_cutting_concerns[:8])}.')
    return '\n'.join(lines)


def policy_file_comment_body(check: PullRequestPolicyCheck) -> str:
    parts = []
    if check.recommendation:
        parts.append(check.recommendation)
    if check.required_actions:
        parts.append('Required: ' + '; '.join(check.required_actions[:3]))
    if not parts:
        parts.append('Review this file against the policy check before publication.')
    return safe_text('\n'.join(parts), 1200)


def impact_file_comment_body(module: PullRequestImpactModule) -> str:
    lines = [
        f'This file is part of `{module.name}`, which is currently rated {module.risk_level} impact.',
    ]
    if module.reasons:
        lines.append('Reasons: ' + '; '.join(module.reasons[:5]))
    if module.review_focus:
        lines.append('Review focus: ' + '; '.join(module.review_focus[:5]))
    return safe_text('\n'.join(lines), 1200)


def files_for_policy_check(state: PullRequestAutomationState, check: PullRequestPolicyCheck) -> list[str]:
    if check.category == 'supply-chain':
        return [change.path for change in state.diff.manifest if is_dependency_file(normalize_path(change.path).lower())]
    if check.category == 'deployment-policy':
        return [change.path for change in state.diff.manifest if is_ci_file(normalize_path(change.path).lower()) or is_iac_file(normalize_path(change.path).lower())]
    if check.category == 'security-invariant':
        return state.impact_radius.critical_files
    if check.category == 'review-integrity':
        return state.impact_radius.generated_files or state.diff.generated_files
    return []


def bullet_lines(values: list[str]) -> str:
    return '\n'.join(f'- {safe_text(value, 400)}' for value in values[:12])


def agent_label(agent: str) -> str:
    labels = {
        'python-specialist-review': 'Python specialist agent',
        'javascript-typescript-agent': 'JavaScript/TypeScript agent',
        'go-agent': 'Go agent',
        'rust-agent': 'Rust agent',
        'php-agent': 'PHP agent',
        'java-kotlin-agent': 'Java/Kotlin agent',
        'dotnet-csharp-agent': '.NET/C# agent',
        'ruby-agent': 'Ruby agent',
        'iac-devops-agent': 'IaC/DevOps agent',
        'dependency-sbom-agent': 'Dependency/SBOM agent',
        'secrets-malware-quarantine-agent': 'Secrets/malware/quarantine agent',
        'scanner-reliability-agent': 'Scanner reliability agent',
    }
    return labels.get(agent, safe_text(agent, 120))


def dedupe_feedback_items(items: list[PullRequestFeedbackItem]) -> list[PullRequestFeedbackItem]:
    seen: set[tuple[str, str | None, str]] = set()
    result: list[PullRequestFeedbackItem] = []
    for item in items:
        key = (item.title, item.file_path, item.body)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def record_pr_feedback_governance(state: PullRequestAutomationState, report: PullRequestFeedbackReport) -> None:
    try:
        from .governance import record_governance_event

        record_governance_event(
            category='pr-automation',
            action='pr_feedback_composed',
            actor='pr-automation',
            resource=state.state_id,
            scan_id=None,
            reason='Draft PR feedback was composed from bounded PR automation state; no code-host publication occurred.',
            metadata={
                'repository': safe_text(state.pull_request.repository, 200),
                'pull_request': str(state.pull_request.number),
                'publication_state': report.publication_state,
                'comment_count': str(report.comment_count),
                'required_actions': str(len(report.required_actions)),
                'recommended_agents': str(len(report.recommended_agents)),
            },
            evidence_refs={
                'state_id': state.state_id,
                'policy_decision': state.policy_report.decision,
                'impact_risk': state.impact_radius.overall_risk,
            },
        )
    except Exception:
        pass


def build_publisher_report(
    state: PullRequestAutomationState,
    selected: list[PullRequestProvider],
    provider_config: dict[str, dict[str, Any]],
    *,
    publish: bool,
    allow_suggestions: bool,
    force: bool,
    max_inline_comments: int,
    blocked_reason: str,
    request_fn: Any | None,
) -> PullRequestPublisherReport:
    providers: dict[str, PullRequestPublisherProviderResult] = {}
    summary = {'providers': len(selected), 'attempted': 0, 'published': 0, 'dry_run': 0, 'skipped': 0, 'failed': 0, 'inline_comments': 0, 'suggestions': 0}
    for item in selected:
        cfg = provider_config.get(item, {})
        artifact = build_provider_publish_artifact(
            state,
            item,
            cfg,
            publish=publish,
            allow_suggestions=allow_suggestions,
            force=force,
            max_inline_comments=max_inline_comments,
            blocked_reason=blocked_reason,
        )
        if blocked_reason:
            artifact.error = blocked_reason
            summary['skipped'] += 1
        elif not artifact.configured or not artifact.active:
            artifact.error = 'provider credentials or repository settings are incomplete'
            summary['skipped'] += 1
        elif artifact.dry_run:
            artifact.result = {'dry_run': True, 'message': 'publisher dry-run is enabled'}
            summary['dry_run'] += 1
        else:
            artifact.publish_attempted = True
            summary['attempted'] += 1
            try:
                artifact.result = publish_provider_feedback(item, artifact.payload, cfg, request_fn=request_fn)
                artifact.published = True
                summary['published'] += 1
            except PullRequestPublisherError as exc:
                artifact.error = str(exc)
                summary['failed'] += 1
        summary['inline_comments'] += artifact.inline_comment_count
        summary['suggestions'] += artifact.suggestion_count
        providers[item] = artifact

    status = publisher_status(publish, blocked_reason, summary)
    return PullRequestPublisherReport(
        status=status,
        generated_at=datetime.now(timezone.utc),
        provider=','.join(selected),
        publish_requested=publish,
        force=force,
        allow_suggestions=allow_suggestions,
        publication_state=state.feedback_report.publication_state,
        blocked_reason=blocked_reason,
        providers=providers,
        summary=summary,
        raw_code_included=False,
        guardrails=feedback_publisher_guardrails(),
    )


def build_provider_publish_artifact(
    state: PullRequestAutomationState,
    provider: PullRequestProvider,
    cfg: dict[str, Any],
    *,
    publish: bool,
    allow_suggestions: bool,
    force: bool,
    max_inline_comments: int,
    blocked_reason: str,
) -> PullRequestPublisherProviderResult:
    del force
    dry_run = not publish or bool(cfg.get('dry_run', True)) or bool(blocked_reason)
    payload = provider_publish_payload(state, provider, cfg, allow_suggestions=allow_suggestions, max_inline_comments=max_inline_comments)
    return PullRequestPublisherProviderResult(
        provider=provider,
        configured=bool(cfg.get('configured')),
        active=bool(cfg.get('active')),
        dry_run=dry_run,
        inline_comment_count=len(payload.get('inline_comments') or []),
        summary_comment_count=1 if payload.get('summary') else 0,
        suggestion_count=sum(1 for item in payload.get('inline_comments') or [] if item.get('suggestion_included')),
        payload=payload,
    )


def provider_publish_payload(state: PullRequestAutomationState, provider: PullRequestProvider, cfg: dict[str, Any], *, allow_suggestions: bool, max_inline_comments: int) -> dict[str, Any]:
    summary = state.feedback_report.summary_markdown or build_feedback_summary_markdown(
        state,
        state.feedback_report.publication_state,
        state.feedback_report.overview_bullets,
        state.feedback_report.required_actions,
        state.feedback_report.test_recommendations,
        state.feedback_report.recommended_agents,
        state.feedback_report.file_comments,
    )
    inline = publishable_inline_comments(state, provider, allow_suggestions=allow_suggestions, max_inline_comments=max_inline_comments)
    if provider == 'github':
        return {
            'provider': provider,
            'summary': summary,
            'review': {
                'method': 'POST',
                'path': f'/repos/{cfg.get("repository") or state.pull_request.repository}/pulls/{cfg.get("pull_request") or state.pull_request.number}/reviews',
                'body': {
                    'body': summary,
                    'event': 'COMMENT',
                    'comments': [item['github'] for item in inline],
                },
            },
            'inline_comments': inline,
        }
    if provider == 'gitlab':
        project = url_quote(cfg.get('project_id') or state.pull_request.repository)
        mr = cfg.get('merge_request_iid') or state.pull_request.number
        return {
            'provider': provider,
            'summary': summary,
            'note': {
                'method': 'POST',
                'path': f'/projects/{project}/merge_requests/{mr}/notes',
                'body': {'body': summary_with_file_comments(summary, state)},
            },
            'inline_comments': inline,
        }
    if provider == 'azure-devops':
        return {
            'provider': provider,
            'summary': summary,
            'thread': {
                'method': 'POST',
                'path': '',
                'body': {
                    'comments': [{'parentCommentId': 0, 'content': summary_with_file_comments(summary, state), 'commentType': 'text'}],
                    'status': 'active',
                },
            },
            'inline_comments': inline,
        }
    if provider == 'bitbucket':
        return {
            'provider': provider,
            'summary': summary,
            'comment': {
                'method': 'POST',
                'path': '',
                'body': {'content': {'raw': summary_with_file_comments(summary, state)}},
            },
            'inline_comments': inline,
        }
    return {'provider': provider, 'summary': summary, 'inline_comments': inline}


def publishable_inline_comments(state: PullRequestAutomationState, provider: PullRequestProvider, *, allow_suggestions: bool, max_inline_comments: int) -> list[dict[str, Any]]:
    inline: list[dict[str, Any]] = []
    limit = max(0, min(max_inline_comments, 100))
    if limit == 0:
        return inline
    for item in state.compiled_feedback:
        if len(inline) >= limit:
            break
        if not item.file_path or not item.line:
            continue
        body = item.body
        suggestion_included = False
        if allow_suggestions and item.suggestion:
            body = f'{body}\n\n```suggestion\n{safe_text(item.suggestion, 2000)}\n```'
            suggestion_included = True
        base = {
            'path': normalize_path(item.file_path),
            'line': int(item.line),
            'body': safe_text(body, 4000),
            'title': item.title,
            'severity': item.severity,
            'category': item.category,
            'suggestion_included': suggestion_included,
        }
        if provider == 'github':
            base['github'] = {'path': base['path'], 'line': base['line'], 'side': 'RIGHT', 'body': base['body']}
        inline.append(base)
    return inline


def summary_with_file_comments(summary: str, state: PullRequestAutomationState) -> str:
    file_items = [item for item in state.compiled_feedback if item.file_path]
    if not file_items:
        return summary
    lines = [summary.rstrip(), '', '### File-Scoped Draft Comments']
    for item in file_items[:20]:
        lines.append(f'- `{item.file_path}`: **{item.title}** - {safe_text(item.body, 300)}')
    return safe_text('\n'.join(lines), 12000)


def publish_provider_feedback(provider: PullRequestProvider, payload: dict[str, Any], cfg: dict[str, Any], request_fn: Any | None = None) -> dict[str, Any]:
    request = request_fn or http_publish_request
    if provider == 'github':
        review = payload['review']
        return {'review': publish_response_summary(request(f'{cfg["api_url"]}{review["path"]}', review['method'], review['body'], github_publish_headers(cfg)))}
    if provider == 'gitlab':
        note = payload['note']
        return {'note': publish_response_summary(request(f'{cfg["api_url"]}{note["path"]}', note['method'], note['body'], {'PRIVATE-TOKEN': cfg.get('token') or ''}))}
    if provider == 'azure-devops':
        thread = payload['thread']
        path = azure_pr_thread_path(cfg)
        return {'thread': publish_response_summary(request(f'{cfg["api_url"]}{path}', thread['method'], thread['body'], azure_publish_headers(cfg)))}
    if provider == 'bitbucket':
        comment = payload['comment']
        path = bitbucket_pr_comment_path(cfg)
        return {'comment': publish_response_summary(request(f'{cfg["api_url"]}{path}', comment['method'], comment['body'], bitbucket_publish_headers(cfg)))}
    raise PullRequestPublisherError(f'Unsupported publisher provider: {provider}')


def http_publish_request(url: str, method: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        method=method,
        headers={'Accept': 'application/json', 'Content-Type': 'application/json', 'User-Agent': 'secure-code-review-assistant', **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read().decode('utf-8', errors='replace')
            return {'status_code': response.status, 'body': json.loads(body) if body.strip() else {}}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode('utf-8', errors='replace')
        raise PullRequestPublisherError(f'{method} {url} failed with {exc.code}: {safe_text(body, 500)}') from exc
    except urllib.error.URLError as exc:
        raise PullRequestPublisherError(f'{method} {url} failed: {exc}') from exc


def publish_response_summary(response: dict[str, Any]) -> dict[str, Any]:
    body = response.get('body') if isinstance(response.get('body'), dict) else {}
    return {
        'status_code': response.get('status_code'),
        'id': body.get('id') or body.get('key') or body.get('threadId'),
        'url': body.get('html_url') or body.get('web_url') or body.get('url'),
    }


def publisher_provider_configuration(state: PullRequestAutomationState | None = None) -> dict[str, dict[str, Any]]:
    github_repo = (state.pull_request.repository if state else None) or os.getenv('GITHUB_REPOSITORY') or ''
    github_pr = (state.pull_request.number if state else None) or int_or_none(os.getenv('GITHUB_PR_NUMBER'))
    gitlab_project = (state.pull_request.repository if state and state.pull_request.provider == 'gitlab' else None) or os.getenv('GITLAB_PROJECT_ID') or ''
    gitlab_mr = (state.pull_request.number if state and state.pull_request.provider == 'gitlab' else None) or int_or_none(os.getenv('GITLAB_MR_IID'))
    azure_repo = os.getenv('AZURE_DEVOPS_REPOSITORY_ID') or os.getenv('AZURE_DEVOPS_REPO_ID') or ''
    azure_pr = (state.pull_request.number if state and state.pull_request.provider == 'azure-devops' else None) or int_or_none(os.getenv('AZURE_DEVOPS_PR_ID'))
    bitbucket_repo = bitbucket_repo_parts(state)
    dry_run = parse_bool(os.getenv('PR_AUTOMATION_PUBLISHER_DRY_RUN'), True)
    return {
        'github': {
            'configured': bool(github_repo and github_pr and publisher_env_first('PR_AUTOMATION_GITHUB_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN')),
            'active': True,
            'dry_run': parse_bool(os.getenv('GITHUB_DRY_RUN'), dry_run),
            'api_url': os.getenv('GITHUB_API_URL', 'https://api.github.com').rstrip('/'),
            'api_version': os.getenv('GITHUB_API_VERSION', '2026-03-10'),
            'repository': github_repo,
            'pull_request': github_pr,
            'token': publisher_env_first('PR_AUTOMATION_GITHUB_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN'),
        },
        'gitlab': {
            'configured': bool(gitlab_project and gitlab_mr and os.getenv('GITLAB_TOKEN')),
            'active': os.getenv('GITLAB_ENABLED', 'auto').lower() in {'auto', 'true'},
            'dry_run': parse_bool(os.getenv('GITLAB_DRY_RUN'), dry_run),
            'api_url': os.getenv('GITLAB_API_URL', 'https://gitlab.com/api/v4').rstrip('/'),
            'project_id': gitlab_project,
            'merge_request_iid': gitlab_mr,
            'token': os.getenv('GITLAB_TOKEN') or '',
        },
        'azure-devops': {
            'configured': bool(os.getenv('AZURE_DEVOPS_ORG') and os.getenv('AZURE_DEVOPS_PROJECT') and azure_repo and azure_pr and os.getenv('AZURE_DEVOPS_PAT')),
            'active': os.getenv('AZURE_DEVOPS_ENABLED', 'auto').lower() in {'auto', 'true'},
            'dry_run': parse_bool(os.getenv('AZURE_DEVOPS_DRY_RUN'), dry_run),
            'api_url': os.getenv('AZURE_DEVOPS_API_URL', 'https://dev.azure.com').rstrip('/'),
            'organization': os.getenv('AZURE_DEVOPS_ORG') or os.getenv('AZURE_DEVOPS_ORGANIZATION') or '',
            'project': os.getenv('AZURE_DEVOPS_PROJECT') or '',
            'repository_id': azure_repo,
            'pull_request_id': azure_pr,
            'pat': os.getenv('AZURE_DEVOPS_PAT') or '',
            'api_version': os.getenv('AZURE_DEVOPS_API_VERSION', '7.1'),
        },
        'bitbucket': {
            'configured': bool(bitbucket_repo['workspace'] and bitbucket_repo['repo_slug'] and bitbucket_repo['pull_request_id'] and (os.getenv('BITBUCKET_TOKEN') or (os.getenv('BITBUCKET_USERNAME') and os.getenv('BITBUCKET_APP_PASSWORD')))),
            'active': os.getenv('BITBUCKET_ENABLED', 'auto').lower() in {'auto', 'true'},
            'dry_run': parse_bool(os.getenv('BITBUCKET_DRY_RUN'), dry_run),
            'api_url': os.getenv('BITBUCKET_API_URL', 'https://api.bitbucket.org/2.0').rstrip('/'),
            'workspace': bitbucket_repo['workspace'],
            'repo_slug': bitbucket_repo['repo_slug'],
            'pull_request_id': bitbucket_repo['pull_request_id'],
            'token': os.getenv('BITBUCKET_TOKEN') or '',
            'username': os.getenv('BITBUCKET_USERNAME') or '',
            'app_password': os.getenv('BITBUCKET_APP_PASSWORD') or '',
        },
    }


def normalize_publish_providers(provider: str, state: PullRequestAutomationState) -> list[PullRequestProvider]:
    value = (provider or 'auto').strip().lower()
    if value == 'auto':
        return [state.pull_request.provider if state.pull_request.provider != 'unknown' else 'github']
    if value in {'all', '*'}:
        return ['github', 'gitlab', 'azure-devops', 'bitbucket']
    selected: list[PullRequestProvider] = []
    for item in re.split(r'[;,]', value):
        try:
            normalized = normalize_provider(item.strip())
        except PullRequestIngressError as exc:
            raise PullRequestPublisherError(str(exc)) from exc
        if normalized not in selected:
            selected.append(normalized)
    return selected


def publisher_blocked_reason(state: PullRequestAutomationState, *, publish: bool, force: bool) -> str:
    if not publish:
        return ''
    if state.feedback_report.publication_state == 'blocked' and not force:
        return 'feedback is blocked by policy; publish requires force=true after governance approval'
    if state.feedback_report.publication_state == 'requires_review' and not force:
        return 'feedback requires review; publish requires force=true after approval'
    return ''


def publisher_status(publish: bool, blocked_reason: str, summary: dict[str, int]) -> PublisherStatus:
    if blocked_reason:
        return 'blocked'
    if not publish or summary.get('dry_run', 0):
        return 'dry_run'
    if summary.get('failed', 0) and summary.get('published', 0):
        return 'partial'
    if summary.get('failed', 0):
        return 'failed'
    if summary.get('published', 0):
        return 'published'
    return 'not_configured'


def github_publish_headers(cfg: dict[str, Any]) -> dict[str, str]:
    return {
        'Authorization': f'Bearer {cfg.get("token") or ""}',
        'X-GitHub-Api-Version': cfg.get('api_version') or '2026-03-10',
    }


def azure_publish_headers(cfg: dict[str, Any]) -> dict[str, str]:
    auth = b64encode(f':{cfg.get("pat") or ""}'.encode('utf-8')).decode('ascii')
    return {'Authorization': f'Basic {auth}'}


def bitbucket_publish_headers(cfg: dict[str, Any]) -> dict[str, str]:
    if cfg.get('token'):
        return {'Authorization': f'Bearer {cfg.get("token")}'}
    raw = f'{cfg.get("username") or ""}:{cfg.get("app_password") or ""}'
    return {'Authorization': 'Basic ' + b64encode(raw.encode('utf-8')).decode('ascii')}


def azure_pr_thread_path(cfg: dict[str, Any]) -> str:
    org = url_quote(cfg.get('organization') or 'organization')
    project = url_quote(cfg.get('project') or 'project')
    repo = url_quote(cfg.get('repository_id') or 'repository')
    pr_id = cfg.get('pull_request_id') or 0
    version = cfg.get('api_version') or '7.1'
    return f'/{org}/{project}/_apis/git/repositories/{repo}/pullRequests/{pr_id}/threads?api-version={version}'


def bitbucket_pr_comment_path(cfg: dict[str, Any]) -> str:
    workspace = url_quote(cfg.get('workspace') or 'workspace')
    repo = url_quote(cfg.get('repo_slug') or 'repo')
    pr_id = cfg.get('pull_request_id') or 0
    return f'/repositories/{workspace}/{repo}/pullrequests/{pr_id}/comments'


def bitbucket_repo_parts(state: PullRequestAutomationState | None) -> dict[str, Any]:
    workspace = os.getenv('BITBUCKET_WORKSPACE') or ''
    repo_slug = os.getenv('BITBUCKET_REPO_SLUG') or ''
    if state and state.pull_request.provider == 'bitbucket' and '/' in state.pull_request.repository:
        workspace, repo_slug = state.pull_request.repository.split('/', 1)
    return {
        'workspace': workspace,
        'repo_slug': repo_slug,
        'pull_request_id': (state.pull_request.number if state and state.pull_request.provider == 'bitbucket' else None) or int_or_none(os.getenv('BITBUCKET_PR_ID')),
    }


def publisher_env_first(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def record_pr_publisher_governance(state: PullRequestAutomationState, report: PullRequestPublisherReport) -> None:
    try:
        from .governance import record_governance_event

        record_governance_event(
            category='pr-automation',
            action='pr_publisher.completed',
            actor='pr-automation',
            resource=state.state_id,
            scan_id=None,
            reason='Governed PR feedback publisher prepared or published code-host review comments.',
            metadata={
                'repository': safe_text(state.pull_request.repository, 200),
                'pull_request': str(state.pull_request.number),
                'status': report.status,
                'publish_requested': str(report.publish_requested),
                'force': str(report.force),
                'publication_state': report.publication_state,
                'blocked_reason': report.blocked_reason,
                'published': str(report.summary.get('published', 0)),
                'inline_comments': str(report.summary.get('inline_comments', 0)),
            },
            evidence_refs={
                'state_id': state.state_id,
                'providers': list(report.providers.keys()),
                'feedback_evidence': [item.id for item in state.evidence if item.kind == 'pr-feedback'],
            },
        )
    except Exception:
        pass


def build_pr_governance_evidence(state: PullRequestAutomationState, limit: int = 200) -> PullRequestGovernanceEvidenceReport:
    event_limit = max(1, min(max(limit, 50), 1000))
    events = pr_governance_events_for_state(state.state_id, limit=event_limit)
    timeline = pr_governance_timeline(events, limit=limit)
    safety = pr_governance_safety_summary(state, events)
    actions: dict[str, PullRequestGovernanceActionEvidence] = {}
    for action, definition in pr_governance_action_definitions().items():
        actions[action] = build_pr_governance_action_evidence(state, action, definition, events)
    completed_actions = [action for action, evidence in actions.items() if evidence.completed]
    missing_actions = [action for action, evidence in actions.items() if evidence.missing_evidence]
    status: GovernanceEvidenceStatus = 'completed'
    if not safety.get('passed', False):
        status = 'attention_required'
    elif missing_actions:
        status = 'partial'
    return PullRequestGovernanceEvidenceReport(
        status=status,
        generated_at=datetime.now(timezone.utc),
        state_id=state.state_id,
        repository=state.pull_request.repository or state.repository.full_name,
        pull_request=state.pull_request.number,
        action_count=len(actions),
        completed_actions=completed_actions,
        missing_actions=missing_actions,
        timeline=timeline,
        actions=actions,
        state_lineage=pr_governance_state_lineage(state, events),
        safety=safety,
        compliance_export=pr_governance_compliance_export(state),
        raw_code_included=bool(safety.get('raw_code_included', False)),
        guardrails=governance_evidence_guardrails(),
    )


def build_pr_governance_action_evidence(
    state: PullRequestAutomationState,
    action: str,
    definition: dict[str, Any],
    events: list[dict[str, Any]],
) -> PullRequestGovernanceActionEvidence:
    event_name = str(definition.get('event') or '')
    action_events = [event for event in events if event.get('action') == event_name]
    status = pr_governance_action_status(state, action)
    terminal = pr_governance_action_terminal(action, status)
    evidence_kinds = pr_governance_action_evidence_kinds(state, action, definition)
    missing: list[str] = []
    if not terminal:
        missing.append('action has not completed')
    if event_name and not action_events:
        missing.append(f'missing governance event: {event_name}')
    required_evidence = [str(kind) for kind in definition.get('evidence_kinds', []) if kind]
    if required_evidence and not set(required_evidence).intersection(evidence_kinds):
        missing.append('missing evidence pointer: ' + ', '.join(required_evidence))
    latest_event = max((str(event.get('created_at') or '') for event in action_events), default='') or None
    return PullRequestGovernanceActionEvidence(
        action=action,
        status=status,
        completed=terminal and not missing,
        evidence_kinds=evidence_kinds,
        event_count=len(action_events),
        latest_event_at=latest_event,
        safety=pr_governance_action_safety(action_events),
        metadata=pr_governance_action_metadata(state, action, definition),
        missing_evidence=missing,
    )


def pr_governance_action_definitions() -> dict[str, dict[str, Any]]:
    return {
        'ingress': {
            'event': 'pr_ingress.state_created',
            'evidence_kinds': [],
            'description': 'Webhook or offline PR state creation with diff digest and file manifest.',
        },
        'ticket_hydration': {
            'event': 'pr_hydration.completed',
            'evidence_kinds': ['ticket-hydration'],
            'description': 'Ticket metadata and intent hydration using bounded, redacted summaries.',
        },
        'impact_radius': {
            'event': 'pr_impact_radius.completed',
            'evidence_kinds': ['impact-radius'],
            'description': 'Impact radius analysis over PR manifest, intent, and ticket metadata.',
        },
        'invariant_policy': {
            'event': 'pr_policy_agent.completed',
            'evidence_kinds': ['invariant-policy'],
            'description': 'Invariant and policy gate decision before feedback or publishing.',
        },
        'feedback_composition': {
            'event': 'pr_feedback_composed',
            'evidence_kinds': ['pr-feedback'],
            'description': 'Draft PR feedback composition from sanitized PR state evidence.',
        },
        'publisher': {
            'event': 'pr_publisher.completed',
            'evidence_kinds': ['pr-publisher'],
            'description': 'Governed dry-run or real code-host publication payload/result.',
        },
    }


def pr_governance_action_status(state: PullRequestAutomationState, action: str) -> str:
    if action == 'ingress':
        return 'completed' if state.state_id else 'pending'
    if action == 'ticket_hydration':
        return state.agent_status.get('ticket_hydration') or 'pending'
    if action == 'impact_radius':
        return state.agent_status.get('impact_radius') or state.impact_radius.status or 'pending'
    if action == 'invariant_policy':
        if state.agent_status.get('invariant_policy'):
            return state.agent_status['invariant_policy']
        return state.policy_report.decision if state.policy_report.status == 'completed' else 'pending'
    if action == 'feedback_composition':
        if state.agent_status.get('feedback_composition'):
            return state.agent_status['feedback_composition']
        return state.feedback_report.publication_state if state.feedback_report.status == 'completed' else 'pending'
    if action == 'publisher':
        if state.agent_status.get('publisher'):
            return state.agent_status['publisher']
        return state.publisher_report.status if state.publisher_report.generated_at else 'pending'
    return 'pending'


def pr_governance_action_terminal(action: str, status: str) -> bool:
    if action == 'ingress':
        return status == 'completed'
    return bool(status and status != 'pending')


def pr_governance_action_evidence_kinds(state: PullRequestAutomationState, action: str, definition: dict[str, Any]) -> list[str]:
    if action == 'ingress':
        kinds = ['pr-state']
        if state.diff.raw_diff_sha256:
            kinds.append('diff-digest')
        if state.diff.manifest:
            kinds.append('file-manifest')
        return kinds
    available = {item.kind for item in state.evidence if not item.raw_content_included}
    required = [str(kind) for kind in definition.get('evidence_kinds', []) if kind]
    return [kind for kind in required if kind in available]


def pr_governance_action_metadata(state: PullRequestAutomationState, action: str, definition: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        'description': definition.get('description', ''),
        'repository': state.pull_request.repository or state.repository.full_name,
        'pull_request': state.pull_request.number,
        'head_sha': state.pull_request.head_sha,
    }
    if action == 'ticket_hydration':
        metadata.update({'ticket_count': len(state.tickets), 'intent_confidence': state.intent.confidence})
    elif action == 'impact_radius':
        metadata.update({'overall_risk': state.impact_radius.overall_risk, 'module_count': len(state.impact_radius.modules)})
    elif action == 'invariant_policy':
        metadata.update({'decision': state.policy_report.decision, 'violations': state.policy_report.violations, 'warnings': state.policy_report.warnings})
    elif action == 'feedback_composition':
        metadata.update({'publication_state': state.feedback_report.publication_state, 'comment_count': state.feedback_report.comment_count})
    elif action == 'publisher':
        metadata.update({'publisher_status': state.publisher_report.status, 'publish_requested': state.publisher_report.publish_requested, 'provider': state.publisher_report.provider})
    return sanitize_evidence_metadata(metadata)


def pr_governance_events_for_state(state_id: str, limit: int = 500) -> list[dict[str, Any]]:
    try:
        from .governance import governance_events_path
    except Exception:
        return []
    matched: list[dict[str, Any]] = []
    path = governance_events_path()
    if not path.exists():
        return matched
    for line in reversed(path.read_text(encoding='utf-8').splitlines()):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get('category') != 'pr-automation':
            continue
        refs = event.get('evidence_refs') if isinstance(event.get('evidence_refs'), dict) else {}
        metadata = event.get('metadata') if isinstance(event.get('metadata'), dict) else {}
        if event.get('resource') == state_id or refs.get('state_id') == state_id or metadata.get('state_id') == state_id:
            matched.append(event)
            if len(matched) >= max(1, min(limit, 5000)):
                break
    return matched


def pr_governance_timeline(events: list[dict[str, Any]], limit: int = 200) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in sorted(events, key=lambda item: str(item.get('created_at') or ''))[-max(1, min(limit, 500)):]:
        rows.append({
            'event_id': event.get('event_id'),
            'created_at': event.get('created_at'),
            'actor': event.get('actor'),
            'action': event.get('action'),
            'resource': event.get('resource'),
            'reason': safe_text(event.get('reason'), 500),
            'metadata': sanitize_evidence_metadata(event.get('metadata') if isinstance(event.get('metadata'), dict) else {}),
            'evidence_refs': sanitize_json_refs(event.get('evidence_refs') if isinstance(event.get('evidence_refs'), dict) else {}),
            'safety': event.get('safety') if isinstance(event.get('safety'), dict) else {},
        })
    return rows


def pr_governance_safety_summary(state: PullRequestAutomationState, events: list[dict[str, Any]]) -> dict[str, Any]:
    event_raw = 0
    event_repo_mutated = 0
    event_rule_mutated = 0
    for event in events:
        safety = event.get('safety') if isinstance(event.get('safety'), dict) else {}
        if safety.get('raw_code_included') or safety.get('raw_report_included'):
            event_raw += 1
        if safety.get('repository_mutated'):
            event_repo_mutated += 1
        if safety.get('scanner_rule_mutated'):
            event_rule_mutated += 1
    flags = {
        'raw_diff_included': bool(state.diff.raw_diff_included),
        'raw_evidence_included': any(item.raw_content_included for item in state.evidence),
        'impact_radius_raw_code_included': bool(state.impact_radius.raw_code_included),
        'policy_report_raw_code_included': bool(state.policy_report.raw_code_included),
        'feedback_report_raw_code_included': bool(state.feedback_report.raw_code_included),
        'publisher_report_raw_code_included': bool(state.publisher_report.raw_code_included),
        'event_raw_content_count': event_raw,
        'event_repository_mutation_count': event_repo_mutated,
        'event_scanner_rule_mutation_count': event_rule_mutated,
    }
    raw_code_included = any(bool(value) for key, value in flags.items() if 'raw' in key and key.endswith(('included', 'count')))
    repository_mutated = event_repo_mutated > 0
    scanner_rule_mutated = event_rule_mutated > 0
    return {
        **flags,
        'raw_code_included': raw_code_included,
        'repository_mutated': repository_mutated,
        'scanner_rule_mutated': scanner_rule_mutated,
        'passed': not raw_code_included and not repository_mutated and not scanner_rule_mutated,
    }


def pr_governance_action_safety(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        'raw_code_included': any(bool((event.get('safety') or {}).get('raw_code_included')) for event in events if isinstance(event.get('safety'), dict)),
        'raw_report_included': any(bool((event.get('safety') or {}).get('raw_report_included')) for event in events if isinstance(event.get('safety'), dict)),
        'repository_mutated': any(bool((event.get('safety') or {}).get('repository_mutated')) for event in events if isinstance(event.get('safety'), dict)),
        'scanner_rule_mutated': any(bool((event.get('safety') or {}).get('scanner_rule_mutated')) for event in events if isinstance(event.get('safety'), dict)),
    }


def pr_governance_state_lineage(state: PullRequestAutomationState, events: list[dict[str, Any]]) -> dict[str, Any]:
    evidence = [
        {
            'kind': item.kind,
            'id': item.id,
            'uri': item.uri,
            'raw_content_included': item.raw_content_included,
        }
        for item in state.evidence
    ]
    lineage = {
        'state_id': state.state_id,
        'schema_version': state.schema_version,
        'created_at': state.created_at.isoformat(),
        'updated_at': state.updated_at.isoformat(),
        'repository': {
            'provider': state.repository.provider,
            'full_name': state.repository.full_name,
            'visibility': state.repository.visibility,
        },
        'pull_request': {
            'provider': state.pull_request.provider,
            'number': state.pull_request.number,
            'url': state.pull_request.url,
            'base_branch': state.pull_request.base_branch,
            'head_branch': state.pull_request.head_branch,
            'base_sha': state.pull_request.base_sha,
            'head_sha': state.pull_request.head_sha,
        },
        'diff': {
            'raw_diff_sha256': state.diff.raw_diff_sha256,
            'files_changed': state.diff.files_changed,
            'additions': state.diff.additions,
            'deletions': state.diff.deletions,
            'raw_diff_included': state.diff.raw_diff_included,
        },
        'agent_status': dict(sorted(state.agent_status.items())),
        'evidence': evidence,
        'event_ids': [event.get('event_id') for event in events if event.get('event_id')],
    }
    lineage['lineage_hash'] = sha256_text(json.dumps(lineage, sort_keys=True, default=str))[:16]
    return lineage


def pr_governance_compliance_export(state: PullRequestAutomationState) -> dict[str, Any]:
    artifact_name = f'pr-governance-evidence-{safe_filename(state.state_id)}.json'
    return {
        'exportable': True,
        'format': 'json',
        'artifact_name': artifact_name,
        'artifact_path': None,
        'retention_scope': 'SECURE_REVIEW_DATA_DIR/pr-automation/governance-evidence',
        'redaction': 'Raw source code, raw diff hunks, raw ticket descriptions, and provider secrets are excluded.',
        'resource': state.state_id,
    }


def pr_governance_evidence_dir() -> Path:
    return data_dir() / 'pr-automation' / 'governance-evidence'


def pr_governance_evidence_path(state_id: str) -> Path:
    return pr_governance_evidence_dir() / f'pr-governance-evidence-{safe_filename(state_id)}.json'


def record_pr_governance_evidence_event(
    state: PullRequestAutomationState,
    report: PullRequestGovernanceEvidenceReport,
    report_id: str,
    artifact_path: Path,
) -> None:
    try:
        from .governance import record_governance_event

        record_governance_event(
            category='pr-automation',
            action='pr_governance_evidence.generated',
            actor='pr-automation',
            resource=state.state_id,
            scan_id=None,
            reason='Exportable governance evidence was generated for PR automation actions.',
            metadata={
                'repository': safe_text(state.pull_request.repository, 200),
                'pull_request': str(state.pull_request.number),
                'status': report.status,
                'completed_actions': str(len(report.completed_actions)),
                'missing_actions': str(len(report.missing_actions)),
                'raw_code_included': str(report.raw_code_included),
            },
            evidence_refs={
                'state_id': state.state_id,
                'report_id': report_id,
                'artifact_path': str(artifact_path),
                'actions': list(report.actions.keys()),
            },
        )
    except Exception:
        pass


def hydrate_ticket_reference(
    ticket: PullRequestTicketReference,
    state: PullRequestAutomationState,
    selected_providers: list[TicketProvider],
    provider_config: dict[str, dict[str, Any]],
    ticket_fetcher: Any | None = None,
) -> tuple[PullRequestTicketReference, dict[str, Any]]:
    hydrated = ticket.model_copy(deep=True)
    candidates = ticket_provider_candidates(hydrated, state, selected_providers)
    outcome: dict[str, Any] = {
        'key': hydrated.key,
        'provider': hydrated.provider,
        'candidate_providers': candidates,
        'status': 'skipped',
        'reason': '',
    }
    if not candidates:
        hydrated.hydration_status = 'skipped'
        outcome['reason'] = 'no matching hydration provider selected'
        return hydrated, outcome

    attempted = False
    errors: list[str] = []
    for provider in candidates:
        configured = bool(provider_config.get(provider, {}).get('configured'))
        if not ticket_fetcher and not configured:
            continue
        attempted = True
        try:
            data = ticket_fetcher(hydrated, state, provider) if ticket_fetcher else fetch_ticket_metadata(hydrated, state, provider)
        except PullRequestTicketHydrationError as exc:
            errors.append(f'{provider}: {safe_text(str(exc), 240)}')
            continue
        if not data:
            errors.append(f'{provider}: no ticket metadata returned')
            continue
        apply_ticket_metadata(hydrated, provider, data)
        outcome.update({
            'provider': provider,
            'status': 'hydrated',
            'reason': 'ticket metadata hydrated',
            'title': hydrated.title,
            'ticket_status': hydrated.status,
        })
        return hydrated, outcome

    if not attempted:
        hydrated.hydration_status = 'not_configured'
        hydrated.metadata['candidate_providers'] = ','.join(candidates)
        outcome['status'] = 'not_configured'
        outcome['reason'] = 'no selected ticket provider is configured'
        return hydrated, outcome

    hydrated.hydration_status = 'failed'
    hydrated.metadata['hydration_errors'] = '; '.join(errors)[:500]
    outcome['status'] = 'failed'
    outcome['reason'] = '; '.join(errors)[:500] or 'ticket hydration failed'
    return hydrated, outcome


def fetch_ticket_metadata(ticket: PullRequestTicketReference, state: PullRequestAutomationState, provider: TicketProvider) -> dict[str, Any]:
    if provider == 'jira':
        return fetch_jira_ticket(ticket)
    if provider == 'linear':
        return fetch_linear_ticket(ticket)
    if provider == 'github':
        return fetch_github_issue(ticket, state)
    if provider == 'azure-devops':
        return fetch_azure_work_item(ticket, state)
    raise PullRequestTicketHydrationError(f'unsupported ticket provider: {provider}')


def fetch_jira_ticket(ticket: PullRequestTicketReference) -> dict[str, Any]:
    base_url = (os.getenv('JIRA_BASE_URL') or '').rstrip('/')
    email = os.getenv('JIRA_EMAIL') or ''
    token = os.getenv('JIRA_API_TOKEN') or os.getenv('JIRA_TOKEN') or ''
    if not (base_url and email and token):
        raise PullRequestTicketHydrationError('Jira credentials are incomplete')
    auth = b64encode(f'{email}:{token}'.encode('utf-8')).decode('ascii')
    fields = 'summary,status,description,assignee,labels,updated,issuetype,priority'
    response = http_json_request(
        f'{base_url}/rest/api/3/issue/{urllib.parse.quote(ticket.key)}?fields={fields}',
        headers={'Authorization': f'Basic {auth}', 'Accept': 'application/json'},
    )
    body = response.get('body') if isinstance(response.get('body'), dict) else {}
    fields_body = body.get('fields') if isinstance(body.get('fields'), dict) else {}
    status = fields_body.get('status') if isinstance(fields_body.get('status'), dict) else {}
    assignee = fields_body.get('assignee') if isinstance(fields_body.get('assignee'), dict) else {}
    issue_type = fields_body.get('issuetype') if isinstance(fields_body.get('issuetype'), dict) else {}
    priority = fields_body.get('priority') if isinstance(fields_body.get('priority'), dict) else {}
    description = jira_document_text(fields_body.get('description'))
    return {
        'key': body.get('key') or ticket.key,
        'title': fields_body.get('summary') or '',
        'status': status.get('name') or '',
        'url': f'{base_url}/browse/{body.get("key") or ticket.key}',
        'description': description,
        'assignee': assignee.get('displayName') or assignee.get('emailAddress') or '',
        'labels': fields_body.get('labels') if isinstance(fields_body.get('labels'), list) else [],
        'updated_at': fields_body.get('updated'),
        'issue_type': issue_type.get('name') or '',
        'priority': priority.get('name') or '',
        'metadata': {'provider_id': safe_text(body.get('id'), 80), 'source': 'jira'},
    }


def fetch_linear_ticket(ticket: PullRequestTicketReference) -> dict[str, Any]:
    api_key = os.getenv('LINEAR_API_KEY') or ''
    api_url = os.getenv('LINEAR_API_URL', 'https://api.linear.app/graphql')
    if not api_key:
        raise PullRequestTicketHydrationError('Linear API key is not configured')
    payload = {
        'query': (
            'query SecureReviewIssue($id: String!) { '
            'issue(id: $id) { id identifier url title description priority updatedAt '
            'state { name } assignee { name email } project { name } labels { nodes { name } } } '
            '}'
        ),
        'variables': {'id': ticket.key},
    }
    response = http_json_request(api_url, method='POST', payload=payload, headers={'Authorization': api_key, 'Content-Type': 'application/json'})
    body = response.get('body') if isinstance(response.get('body'), dict) else {}
    if body.get('errors'):
        raise PullRequestTicketHydrationError(f'Linear API returned errors: {safe_text(json.dumps(body["errors"]), 500)}')
    issue = ((body.get('data') or {}).get('issue') or {}) if isinstance(body, dict) else {}
    if not issue:
        raise PullRequestTicketHydrationError('Linear issue was not found')
    state_payload = issue.get('state') if isinstance(issue.get('state'), dict) else {}
    assignee = issue.get('assignee') if isinstance(issue.get('assignee'), dict) else {}
    project = issue.get('project') if isinstance(issue.get('project'), dict) else {}
    label_nodes = ((issue.get('labels') or {}).get('nodes') or []) if isinstance(issue.get('labels'), dict) else []
    return {
        'key': issue.get('identifier') or ticket.key,
        'title': issue.get('title') or '',
        'status': state_payload.get('name') or '',
        'url': issue.get('url'),
        'description': issue.get('description') or '',
        'assignee': assignee.get('name') or assignee.get('email') or '',
        'labels': [item.get('name') for item in label_nodes if isinstance(item, dict) and item.get('name')],
        'updated_at': issue.get('updatedAt'),
        'priority': str(issue.get('priority') or ''),
        'metadata': {'provider_id': safe_text(issue.get('id'), 80), 'project': safe_text(project.get('name'), 120), 'source': 'linear'},
    }


def fetch_github_issue(ticket: PullRequestTicketReference, state: PullRequestAutomationState) -> dict[str, Any]:
    token = env_first('PR_AUTOMATION_GITHUB_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN')
    if not token:
        raise PullRequestTicketHydrationError('GitHub token is not configured')
    issue_number = ticket.key.lstrip('#')
    if not issue_number.isdigit():
        raise PullRequestTicketHydrationError('GitHub issue references must look like #123')
    repository = state.pull_request.repository or state.repository.full_name
    if not repository or '/' not in repository:
        raise PullRequestTicketHydrationError('GitHub repository full name is unavailable')
    api_url = os.getenv('GITHUB_API_URL', 'https://api.github.com').rstrip('/')
    response = http_json_request(
        f'{api_url}/repos/{repository}/issues/{issue_number}',
        headers={'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json'},
    )
    issue = response.get('body') if isinstance(response.get('body'), dict) else {}
    assignee = issue.get('assignee') if isinstance(issue.get('assignee'), dict) else {}
    labels = issue.get('labels') if isinstance(issue.get('labels'), list) else []
    return {
        'key': f'#{issue.get("number") or issue_number}',
        'title': issue.get('title') or '',
        'status': issue.get('state') or '',
        'url': issue.get('html_url'),
        'description': issue.get('body') or '',
        'assignee': assignee.get('login') or '',
        'labels': [item.get('name') for item in labels if isinstance(item, dict) and item.get('name')],
        'updated_at': issue.get('updated_at'),
        'metadata': {'provider_id': safe_text(issue.get('id'), 80), 'source': 'github'},
    }


def fetch_azure_work_item(ticket: PullRequestTicketReference, state: PullRequestAutomationState) -> dict[str, Any]:
    token = env_first('PR_AUTOMATION_AZURE_DEVOPS_PAT', 'AZURE_DEVOPS_PAT', 'AZURE_DEVOPS_TOKEN')
    org = env_first('PR_AUTOMATION_AZURE_DEVOPS_ORG', 'AZURE_DEVOPS_ORG')
    if not (token and org):
        raise PullRequestTicketHydrationError('Azure DevOps organization and PAT are not configured')
    work_item_id = ticket.key.removeprefix('AB#').lstrip('#')
    if not work_item_id.isdigit():
        raise PullRequestTicketHydrationError('Azure DevOps work item references must look like AB#123 or #123')
    auth = b64encode(f':{token}'.encode('utf-8')).decode('ascii')
    api_version = os.getenv('AZURE_DEVOPS_API_VERSION', '7.1-preview.3')
    response = http_json_request(
        f'https://dev.azure.com/{urllib.parse.quote(org)}/_apis/wit/workitems/{work_item_id}?api-version={api_version}',
        headers={'Authorization': f'Basic {auth}', 'Accept': 'application/json'},
    )
    item = response.get('body') if isinstance(response.get('body'), dict) else {}
    fields = item.get('fields') if isinstance(item.get('fields'), dict) else {}
    assigned_to = fields.get('System.AssignedTo') if isinstance(fields.get('System.AssignedTo'), dict) else {}
    tags = [tag.strip() for tag in str(fields.get('System.Tags') or '').split(';') if tag.strip()]
    return {
        'key': f'AB#{item.get("id") or work_item_id}',
        'title': fields.get('System.Title') or '',
        'status': fields.get('System.State') or '',
        'url': item.get('url'),
        'description': html_to_text(fields.get('System.Description') or fields.get('System.History') or ''),
        'assignee': assigned_to.get('displayName') or assigned_to.get('uniqueName') or '',
        'labels': tags,
        'updated_at': fields.get('System.ChangedDate'),
        'issue_type': fields.get('System.WorkItemType') or '',
        'priority': str(fields.get('Microsoft.VSTS.Common.Priority') or ''),
        'metadata': {'provider_id': safe_text(item.get('id'), 80), 'source': 'azure-devops', 'repository': safe_text(state.pull_request.repository, 200)},
    }


def apply_ticket_metadata(ticket: PullRequestTicketReference, provider: TicketProvider, data: dict[str, Any]) -> None:
    ticket.provider = provider
    ticket.key = safe_text(data.get('key') or ticket.key, 80)
    ticket.url = data.get('url') or ticket.url
    ticket.title = safe_ticket_text(data.get('title') or ticket.title, 300)
    ticket.status = safe_ticket_text(data.get('status') or ticket.status, 80)
    ticket.description_excerpt = safe_ticket_text(data.get('description') or data.get('description_excerpt') or ticket.description_excerpt, 1000)
    ticket.assignee = safe_ticket_text(data.get('assignee') or ticket.assignee, 120)
    ticket.labels = safe_label_list(data.get('labels') or ticket.labels)
    ticket.issue_type = safe_ticket_text(data.get('issue_type') or ticket.issue_type, 80)
    ticket.priority = safe_ticket_text(data.get('priority') or ticket.priority, 80)
    ticket.updated_at = safe_text(data.get('updated_at'), 80) or ticket.updated_at
    ticket.hydrated = True
    ticket.hydration_status = 'hydrated'
    ticket.source = 'hydrated'
    ticket.metadata.update(safe_metadata(data.get('metadata') if isinstance(data.get('metadata'), dict) else {}))


def summarize_hydrated_intent(state: PullRequestAutomationState) -> PullRequestIntent:
    ticket_context = [f'{ticket.key}: {ticket.title}' for ticket in state.tickets if ticket.title]
    description_context = [ticket.description_excerpt for ticket in state.tickets if ticket.description_excerpt]
    base_text = '\n'.join(filter(None, [state.pull_request.title, state.pull_request.description_excerpt, *ticket_context, *description_context]))
    base_intent = summarize_intent(state.pull_request.title, state.pull_request.description_excerpt, state.tickets)
    hydrated_count = sum(1 for ticket in state.tickets if ticket.hydrated)
    focus = review_focus_for_text(base_text, state.diff.manifest)
    business_context = summarize_business_context(state.tickets)
    summary = base_intent.summary
    if ticket_context:
        summary = safe_ticket_text(f'{summary} Ticket context: {"; ".join(ticket_context[:3])}', 700)
    confidence = 'high' if hydrated_count else base_intent.confidence
    if state.tickets and confidence == 'low':
        confidence = 'medium'
    return PullRequestIntent(
        summary=summary,
        source='hydrated-ticket-pr' if hydrated_count else base_intent.source,
        ticket_keys=[ticket.key for ticket in state.tickets],
        risk_keywords=sorted(set(base_intent.risk_keywords + risk_keywords_for_text(base_text))),
        review_focus=focus,
        business_context=business_context,
        hydrated_from_tickets=bool(hydrated_count),
        confidence=confidence,
    )


def review_focus_for_text(text: str, manifest: list[PullRequestFileChange]) -> list[str]:
    lowered = text.lower()
    focus: set[str] = set()
    keyword_focus = {
        'auth': 'authentication and authorization boundaries',
        'permission': 'authorization boundaries',
        'token': 'token handling',
        'secret': 'secret handling',
        'crypto': 'cryptography usage',
        'sql': 'database query safety',
        'schema': 'schema and migration safety',
        'migration': 'schema and migration safety',
        'dependency': 'dependency and SBOM impact',
        'deserialization': 'unsafe deserialization',
        'upload': 'file upload handling',
        'webhook': 'webhook trust boundary',
    }
    for keyword, label in keyword_focus.items():
        if keyword in lowered:
            focus.add(label)
    languages = sorted({item.language for item in manifest if item.language != 'unknown'})
    for language in languages[:5]:
        focus.add(f'{language} change review')
    return sorted(focus)[:8]


def summarize_business_context(tickets: list[PullRequestTicketReference]) -> str:
    hydrated = [ticket for ticket in tickets if ticket.hydrated]
    source = hydrated or tickets
    parts = []
    for ticket in source[:3]:
        detail = ticket.title or ticket.status or ticket.key
        if detail:
            parts.append(f'{ticket.key}: {detail}')
    return safe_ticket_text('; '.join(parts), 500)


def hydration_status_from_summary(summary: dict[str, int]) -> str:
    total = summary.get('total', 0)
    if total == 0:
        return 'no_tickets'
    if summary.get('hydrated') == total:
        return 'completed'
    if summary.get('hydrated', 0) > 0:
        return 'partial'
    if summary.get('failed', 0) > 0:
        return 'failed'
    if summary.get('not_configured', 0) > 0:
        return 'not_configured'
    return 'skipped'


def add_or_replace_evidence(state: PullRequestAutomationState, evidence: PullRequestEvidencePointer) -> None:
    state.evidence = [item for item in state.evidence if item.kind != evidence.kind]
    state.evidence.append(evidence)


def record_pr_hydration_governance(state: PullRequestAutomationState, summary: dict[str, int], providers: list[TicketProvider]) -> None:
    try:
        from .governance import record_governance_event

        record_governance_event(
            category='pr-automation',
            action='pr_hydration.completed',
            actor='pr-automation',
            resource=state.state_id,
            scan_id=None,
            reason='PR ticket metadata and intent were hydrated using bounded, redacted ticket summaries.',
            metadata={
                'repository': safe_text(state.pull_request.repository, 200),
                'pull_request': str(state.pull_request.number),
                'providers': ','.join(providers),
                'status': state.agent_status.get('ticket_hydration', ''),
                'ticket_total': str(summary.get('total', 0)),
                'ticket_hydrated': str(summary.get('hydrated', 0)),
                'ticket_not_configured': str(summary.get('not_configured', 0)),
                'ticket_failed': str(summary.get('failed', 0)),
            },
            evidence_refs={
                'state_id': state.state_id,
                'ticket_keys': [ticket.key for ticket in state.tickets],
                'intent_source': state.intent.source,
            },
        )
    except Exception:
        pass


def http_json_request(url: str, method: str = 'GET', payload: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={'User-Agent': 'secure-code-review-assistant', **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read().decode('utf-8', errors='replace')
            return {
                'status_code': response.status,
                'headers': dict(response.headers.items()),
                'body': json.loads(raw) if raw.strip() else {},
            }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode('utf-8', errors='replace')
        raise PullRequestTicketHydrationError(f'{method} {url} failed with {exc.code}: {safe_text(body, 500)}') from exc
    except urllib.error.URLError as exc:
        raise PullRequestTicketHydrationError(f'{method} {url} failed: {exc}') from exc


def parse_unified_diff_manifest(diff_text: str) -> list[PullRequestFileChange]:
    files: list[PullRequestFileChange] = []
    current: dict[str, Any] | None = None
    patch_lines: list[str] = []

    def flush() -> None:
        nonlocal current, patch_lines
        if not current:
            return
        patch_text = '\n'.join(patch_lines)
        current['changes'] = int(current.get('additions', 0)) + int(current.get('deletions', 0))
        current['patch_sha256'] = sha256_text(patch_text) if patch_text else ''
        files.append(PullRequestFileChange(**current))
        current = None
        patch_lines = []

    for line in diff_text.splitlines():
        if line.startswith('diff --git '):
            flush()
            path = parse_diff_git_path(line)
            current = {'path': path, 'status': 'modified', 'additions': 0, 'deletions': 0, 'language': language_for_path(path)}
            patch_lines = [line]
            continue
        if current is None:
            continue
        patch_lines.append(line)
        if line.startswith('new file mode'):
            current['status'] = 'added'
        elif line.startswith('deleted file mode'):
            current['status'] = 'deleted'
        elif line.startswith('rename from '):
            current['previous_path'] = line.removeprefix('rename from ').strip()
            current['status'] = 'renamed'
        elif line.startswith('rename to '):
            current['path'] = line.removeprefix('rename to ').strip()
            current['language'] = language_for_path(current['path'])
            current['status'] = 'renamed'
        elif line.startswith('+++ b/'):
            current['path'] = line.removeprefix('+++ b/').strip()
            current['language'] = language_for_path(current['path'])
        elif line.startswith('+') and not line.startswith('+++'):
            current['additions'] = int(current.get('additions', 0)) + 1
        elif line.startswith('-') and not line.startswith('---'):
            current['deletions'] = int(current.get('deletions', 0)) + 1
    flush()
    return files


def normalize_file_change(item: dict[str, Any]) -> PullRequestFileChange:
    change = PullRequestFileChange.model_validate(item)
    if not change.changes:
        change.changes = change.additions + change.deletions
    if change.language == 'unknown':
        change.language = language_for_path(change.path)
    return change


def normalize_tickets(tickets: list[dict[str, Any]]) -> list[PullRequestTicketReference]:
    normalized: list[PullRequestTicketReference] = []
    for ticket in tickets:
        if not isinstance(ticket, dict) or not ticket.get('key'):
            continue
        normalized.append(PullRequestTicketReference(
            key=safe_text(ticket.get('key'), 80),
            provider=normalize_ticket_provider(ticket.get('provider')),
            url=ticket.get('url'),
            title=safe_text(ticket.get('title'), 300),
            status=safe_text(ticket.get('status'), 80),
            source=safe_text(ticket.get('source') or 'hydrated', 80),
            description_excerpt=safe_ticket_text(ticket.get('description_excerpt') or ticket.get('description'), 1000),
            assignee=safe_ticket_text(ticket.get('assignee'), 120),
            labels=safe_label_list(ticket.get('labels')),
            issue_type=safe_ticket_text(ticket.get('issue_type'), 80),
            priority=safe_ticket_text(ticket.get('priority'), 80),
            updated_at=safe_text(ticket.get('updated_at'), 80) or None,
            hydrated=bool(ticket.get('hydrated')),
            hydration_status=safe_text(ticket.get('hydration_status') or 'pending', 80),
            metadata=safe_metadata(ticket.get('metadata') if isinstance(ticket.get('metadata'), dict) else {}),
        ))
    return normalized


def extract_ticket_refs(*texts: str, hash_provider: TicketProvider = 'github') -> list[PullRequestTicketReference]:
    refs: list[PullRequestTicketReference] = []
    combined = ' '.join(text for text in texts if text)
    for key in sorted(set(re.findall(r'\b[A-Z][A-Z0-9]+-\d+\b', combined))):
        refs.append(PullRequestTicketReference(key=key, provider=infer_ticket_provider(key), source='extracted'))
    for issue in sorted(set(re.findall(r'\bAB#(\d{1,8})\b', combined, flags=re.IGNORECASE))):
        refs.append(PullRequestTicketReference(key=f'AB#{issue}', provider='azure-devops', source='extracted'))
    for issue in sorted(set(re.findall(r'(?<!\w)#(\d{1,8})\b', combined))):
        refs.append(PullRequestTicketReference(key=f'#{issue}', provider=hash_provider, source='extracted'))
    return refs


def dedupe_tickets(tickets: list[PullRequestTicketReference]) -> list[PullRequestTicketReference]:
    seen: set[str] = set()
    result: list[PullRequestTicketReference] = []
    for ticket in tickets:
        if ticket.key in seen:
            continue
        seen.add(ticket.key)
        result.append(ticket)
    return result


def summarize_intent(title: str, description: str, tickets: list[PullRequestTicketReference]) -> PullRequestIntent:
    text = f'{title}\n{description}'.strip()
    risk_keywords = risk_keywords_for_text(text)
    confidence = 'medium' if tickets or len(text) >= 40 else 'low'
    return PullRequestIntent(
        summary=safe_text(first_sentence(text) or title or 'No PR intent supplied.', 500),
        ticket_keys=[ticket.key for ticket in tickets],
        risk_keywords=risk_keywords,
        review_focus=review_focus_for_text(text, []),
        confidence=confidence,
    )


def pr_state_guardrails() -> list[str]:
    return [
        'PR automation state stores diff digests, file manifests, bounded excerpts, and evidence pointers; it does not require full raw diff persistence.',
        'Agent findings in this state are recommendations only and cannot mutate scanner rules, suppressions, parser code, or repository files.',
        'Inline suggestions must pass the safe-fix workflow and benchmark/governance gates before publication.',
        'Ticket, RAG, and scan evidence should be referenced by pointer or sanitized summary unless a later approved workflow explicitly needs more context.',
    ]


def impact_radius_guardrails() -> list[str]:
    return [
        'Impact radius uses PR state metadata only: changed paths, file stats, language hints, ticket metadata, and intent summaries.',
        'The analyzer does not read repository files, raw diff hunks, cloned repos, or malware-quarantined source.',
        'Impact results prioritize review routing and test selection; they cannot approve fixes, publish comments, or mutate scanner rules.',
        'Risk levels are deterministic heuristics and should be treated as triage guidance until later benchmarked with production PR outcomes.',
    ]


def policy_agent_guardrails() -> list[str]:
    return [
        'The invariant/policy agent evaluates bounded PR state, hydrated ticket summaries, and impact-radius metadata only.',
        'Policy findings create review obligations and routing signals; they do not publish comments, approve PRs, mutate repositories, or rewrite scanner rules.',
        'Blocked means automated publication must stop until a human or governance workflow records the required approval.',
        'The agent never inspects cloned repository files, raw diff hunks, or quarantined source.',
    ]


def feedback_composer_guardrails() -> list[str]:
    return [
        'The feedback composer creates draft review text only; it never publishes to GitHub, GitLab, Azure DevOps, or Bitbucket.',
        'Draft feedback is composed from bounded PR state, impact radius, and policy findings without reading raw source or raw diff hunks.',
        'Inline suggestions are intentionally omitted until a later safe-fix and publisher-governance workflow approves them.',
        'Blocked or review-required policy decisions stay visible in the draft and prevent treating the feedback as publish-ready.',
    ]


def feedback_publisher_guardrails() -> list[str]:
    return [
        'Publishing is dry-run by default and requires publish=true plus configured provider credentials for a real code-host API call.',
        'Blocked or review-required feedback cannot be published unless force=true records an explicit governance override.',
        'Inline suggestions are excluded unless allow_suggestions=true, and suggestions are only rendered from already-approved feedback items.',
        'The publisher sends bounded review text and file/line metadata only; it does not read raw source, raw diff hunks, or cloned repositories.',
    ]


def governance_evidence_guardrails() -> list[str]:
    return [
        'Governance evidence is generated from saved PR automation state and governance events only; it does not inspect cloned repositories or raw source.',
        'The evidence artifact records action lineage, hashes, bounded metadata, and event IDs without storing raw diff hunks or provider secrets.',
        'Missing action evidence produces a partial report instead of silently marking the PR automation flow complete.',
        'Safety violations such as raw code persistence, repository mutation, or scanner-rule mutation force attention_required status.',
    ]


def impact_intent_text(state: PullRequestAutomationState) -> str:
    ticket_text = ' '.join(
        ' '.join(filter(None, [ticket.key, ticket.title, ticket.status, ticket.description_excerpt, ' '.join(ticket.labels)]))
        for ticket in state.tickets
    )
    return ' '.join(filter(None, [
        state.pull_request.title,
        state.pull_request.description_excerpt,
        state.intent.summary,
        ' '.join(state.intent.risk_keywords),
        ' '.join(state.intent.review_focus),
        state.intent.business_context,
        ticket_text,
    ]))


def normalize_path(path: str) -> str:
    return str(path or '').replace('\\', '/').strip().strip('/')


def is_dependency_file(lowered_path: str) -> bool:
    name = lowered_path.rsplit('/', 1)[-1]
    return name in {
        'requirements.txt',
        'requirements-dev.txt',
        'requirements-test.txt',
        'pyproject.toml',
        'poetry.lock',
        'pipfile',
        'pipfile.lock',
        'package.json',
        'package-lock.json',
        'yarn.lock',
        'pnpm-lock.yaml',
        'go.mod',
        'go.sum',
        'cargo.toml',
        'cargo.lock',
        'composer.json',
        'composer.lock',
        'pom.xml',
        'build.gradle',
        'build.gradle.kts',
        'gradle.lockfile',
        'gemfile',
        'gemfile.lock',
        'packages.lock.json',
        'nuget.config',
    } or lowered_path.endswith(('.csproj', '.fsproj', '.vbproj'))


def is_ci_file(lowered_path: str) -> bool:
    name = lowered_path.rsplit('/', 1)[-1]
    return (
        lowered_path.startswith('.github/workflows/')
        or lowered_path.startswith('.gitlab/')
        or lowered_path.startswith('.circleci/')
        or name in {'azure-pipelines.yml', 'azure-pipelines.yaml', 'jenkinsfile', 'buildkite.yml', 'buildkite.yaml'}
    )


def is_iac_file(lowered_path: str) -> bool:
    name = lowered_path.rsplit('/', 1)[-1]
    return (
        lowered_path.startswith(('terraform/', 'infra/', 'infrastructure/', 'deploy/', 'deployment/', 'k8s/', 'charts/'))
        or name in {'dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'helmfile.yaml', 'helmfile.yml'}
        or lowered_path.endswith(('.tf', '.tfvars', '.hcl'))
    )


def is_database_file(lowered_path: str) -> bool:
    return any(marker in lowered_path for marker in ['/migrations/', '/migration/', '/schema/', 'schema.sql', 'alembic/', 'db/migrate'])


def is_security_sensitive_path(lowered_path: str) -> bool:
    return any(marker in lowered_path for marker in [
        'auth',
        'oauth',
        'jwt',
        'token',
        'secret',
        'password',
        'credential',
        'permission',
        'policy',
        'crypto',
        'session',
        'webhook',
    ])


def is_config_file(lowered_path: str) -> bool:
    name = lowered_path.rsplit('/', 1)[-1]
    return (
        name.startswith('.env')
        or name in {'settings.py', 'config.py', 'appsettings.json', 'web.config', 'nginx.conf', 'values.yaml', 'values.yml'}
        or lowered_path.endswith(('.toml', '.ini', '.conf'))
        or '/config/' in lowered_path
    )


def is_test_file(lowered_path: str) -> bool:
    name = lowered_path.rsplit('/', 1)[-1]
    return lowered_path.startswith(('tests/', 'test/', 'spec/')) or name.startswith('test_') or name.endswith(('_test.go', '.spec.ts', '.spec.js', '.test.ts', '.test.js'))


def is_docs_file(lowered_path: str) -> bool:
    return lowered_path.startswith(('docs/', 'doc/')) or lowered_path.endswith(('.md', '.rst', '.txt'))


def intent_keyword_focus(keyword: str) -> str:
    return {
        'auth': 'authentication and authorization boundaries',
        'crypto': 'cryptography usage',
        'sql': 'database query safety',
        'secret': 'secret handling',
        'token': 'token handling',
        'permission': 'authorization boundaries',
        'schema': 'schema and migration safety',
        'migration': 'schema and migration safety',
        'dependency': 'dependency and SBOM impact',
        'deserialization': 'unsafe deserialization',
        'upload': 'file upload handling',
        'webhook': 'webhook trust boundary',
    }.get(keyword, '')


def agent_for_language(language: str) -> str:
    return {
        'python': 'python-specialist-review',
        'javascript': 'javascript-typescript-agent',
        'typescript': 'javascript-typescript-agent',
        'go': 'go-agent',
        'rust': 'rust-agent',
        'php': 'php-agent',
        'java': 'java-kotlin-agent',
        'kotlin': 'java-kotlin-agent',
        'csharp': 'dotnet-csharp-agent',
        'ruby': 'ruby-agent',
        'terraform': 'iac-devops-agent',
        'yaml': 'iac-devops-agent',
        'powershell': 'iac-devops-agent',
        'shell': 'iac-devops-agent',
    }.get(language, 'scanner-reliability-agent')


def dedupe_strings(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = safe_text(value, 500)
        if text and text not in result:
            result.append(text)
    return result


def severity_rank(severity: str) -> int:
    return {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}.get(str(severity or '').upper(), 0)


def changed_test_files(state: PullRequestAutomationState) -> list[str]:
    return [change.path for change in state.diff.manifest if is_test_file(normalize_path(change.path).lower())]


def ticket_provider_configuration() -> dict[str, dict[str, Any]]:
    jira_base = (os.getenv('JIRA_BASE_URL') or '').rstrip('/')
    linear_url = os.getenv('LINEAR_API_URL', 'https://api.linear.app/graphql')
    github_api = os.getenv('GITHUB_API_URL', 'https://api.github.com')
    return {
        'jira': {
            'configured': bool(jira_base and os.getenv('JIRA_EMAIL') and (os.getenv('JIRA_API_TOKEN') or os.getenv('JIRA_TOKEN'))),
            'base_url_configured': bool(jira_base),
            'email_configured': bool(os.getenv('JIRA_EMAIL')),
            'token_configured': bool(os.getenv('JIRA_API_TOKEN') or os.getenv('JIRA_TOKEN')),
        },
        'linear': {
            'configured': bool(os.getenv('LINEAR_API_KEY')),
            'api_url': linear_url,
            'api_key_configured': bool(os.getenv('LINEAR_API_KEY')),
        },
        'github': {
            'configured': bool(env_first('PR_AUTOMATION_GITHUB_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN')),
            'api_url': github_api,
            'token_configured': bool(env_first('PR_AUTOMATION_GITHUB_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN')),
        },
        'azure-devops': {
            'configured': bool(env_first('PR_AUTOMATION_AZURE_DEVOPS_PAT', 'AZURE_DEVOPS_PAT', 'AZURE_DEVOPS_TOKEN') and env_first('PR_AUTOMATION_AZURE_DEVOPS_ORG', 'AZURE_DEVOPS_ORG')),
            'org_configured': bool(env_first('PR_AUTOMATION_AZURE_DEVOPS_ORG', 'AZURE_DEVOPS_ORG')),
            'token_configured': bool(env_first('PR_AUTOMATION_AZURE_DEVOPS_PAT', 'AZURE_DEVOPS_PAT', 'AZURE_DEVOPS_TOKEN')),
        },
    }


def hydration_provider_order() -> list[TicketProvider]:
    raw = os.getenv('PR_AUTOMATION_TICKET_PROVIDER_ORDER', 'jira,linear,github,azure-devops')
    providers: list[TicketProvider] = []
    for item in re.split(r'[;,]', raw):
        provider = normalize_ticket_provider(item.strip())
        if provider != 'unknown' and provider not in providers:
            providers.append(provider)
    return providers or ['jira', 'linear', 'github', 'azure-devops']


def normalize_hydration_providers(providers: str) -> list[TicketProvider]:
    value = (providers or 'auto').strip().lower()
    if value in {'auto', 'all', '*'}:
        return hydration_provider_order()
    selected: list[TicketProvider] = []
    for item in re.split(r'[;,]', value):
        provider = normalize_ticket_provider(item.strip())
        if provider == 'unknown':
            raise PullRequestTicketHydrationError(f'Unsupported ticket hydration provider: {item}')
        if provider not in selected:
            selected.append(provider)
    return selected


def ticket_provider_candidates(ticket: PullRequestTicketReference, state: PullRequestAutomationState, selected_providers: list[TicketProvider]) -> list[TicketProvider]:
    if ticket.provider != 'unknown':
        return [ticket.provider] if ticket.provider in selected_providers else []
    if ticket.key.upper().startswith('AB#'):
        return ['azure-devops'] if 'azure-devops' in selected_providers else []
    if ticket.key.startswith('#'):
        preferred: TicketProvider = 'azure-devops' if state.pull_request.provider == 'azure-devops' else 'github'
        return [preferred] if preferred in selected_providers else []
    if re.match(r'^[A-Z][A-Z0-9]+-\d+$', ticket.key):
        return [provider for provider in selected_providers if provider in {'jira', 'linear'}]
    return selected_providers


def risk_keywords_for_text(text: str) -> list[str]:
    lowered = (text or '').lower()
    return sorted({keyword for keyword in ['auth', 'crypto', 'sql', 'secret', 'token', 'permission', 'schema', 'migration', 'dependency', 'deserialization', 'upload', 'webhook'] if keyword in lowered})


def jira_document_text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts: list[str] = []
        text = value.get('text')
        if isinstance(text, str):
            parts.append(text)
        content = value.get('content')
        if isinstance(content, list):
            parts.extend(jira_document_text(item) for item in content)
        return ' '.join(part for part in parts if part).strip()
    if isinstance(value, list):
        return ' '.join(jira_document_text(item) for item in value).strip()
    return safe_text(value, 1000)


def html_to_text(value: str) -> str:
    text = re.sub(r'<[^>]+>', ' ', str(value or ''))
    return re.sub(r'\s+', ' ', text).strip()


def safe_ticket_text(value: Any, limit: int) -> str:
    return safe_text(redact_sensitive_text(value), limit)


def redact_sensitive_text(value: Any) -> str:
    text = str(value or '').replace('\x00', '').strip()
    replacements = [
        (r'(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|pwd)\b\s*[:=]\s*["\']?[^"\'\s,;]+', r'\1=[REDACTED]'),
        (r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}', 'Bearer [REDACTED]'),
        (r'(?i)\bBasic\s+[A-Za-z0-9+/=-]{12,}', 'Basic [REDACTED]'),
    ]
    for pattern, replacement in replacements:
        text = re.sub(pattern, replacement, text)
    return text


def safe_label_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    labels = []
    for item in value:
        label = safe_ticket_text(item, 80)
        if label and label not in labels:
            labels.append(label)
        if len(labels) >= 20:
            break
    return labels


def safe_metadata(value: dict[str, Any]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for key, item in list(value.items())[:20]:
        safe_key = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(key or '').strip())[:80]
        if not safe_key:
            continue
        metadata[safe_key] = safe_ticket_text(item, 240)
    return metadata


def sanitize_evidence_metadata(value: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key, item in list(value.items())[:50]:
        safe_key = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(key or '').strip())[:80]
        if not safe_key:
            continue
        metadata[safe_key] = sanitize_json_value(item)
    return metadata


def sanitize_json_refs(value: dict[str, Any]) -> dict[str, Any]:
    refs: dict[str, Any] = {}
    for key, item in list(value.items())[:50]:
        safe_key = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(key or '').strip())[:80]
        if not safe_key:
            continue
        refs[safe_key] = sanitize_json_value(item)
    return refs


def sanitize_json_value(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return safe_ticket_text(value, 240)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value
    if isinstance(value, str):
        return safe_ticket_text(value, 500)
    if isinstance(value, list):
        return [sanitize_json_value(item, depth + 1) for item in value[:30]]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:30]:
            safe_key = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(key or '').strip())[:80]
            if safe_key:
                result[safe_key] = sanitize_json_value(item, depth + 1)
        return result
    return safe_ticket_text(value, 500)


def pr_state_id(provider: str, repository: str, pr_number: int, head_sha: str = '') -> str:
    digest = sha256_text(f'{provider}:{repository}:{pr_number}:{head_sha}')[:16]
    return f'prstate-{digest}'


def normalize_provider(provider: str) -> PullRequestProvider:
    value = str(provider or '').strip().lower().replace('_', '-')
    aliases = {
        'gh': 'github',
        'github.com': 'github',
        'gitlab.com': 'gitlab',
        'azure': 'azure-devops',
        'ado': 'azure-devops',
        'azuredevops': 'azure-devops',
        'bitbucket-cloud': 'bitbucket',
        'bitbucket-server': 'bitbucket',
    }
    normalized = aliases.get(value, value)
    if normalized in {'github', 'gitlab', 'azure-devops', 'bitbucket'}:
        return normalized  # type: ignore[return-value]
    raise PullRequestIngressError(f'Unsupported PR automation provider: {provider}')


def provider_env(provider: str) -> str:
    return normalize_provider(provider).upper().replace('-', '_')


def env_first(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def strip_ref(value: str) -> str:
    text = str(value or '')
    for prefix in ('refs/heads/', 'refs/tags/'):
        if text.startswith(prefix):
            return text[len(prefix):]
    return text


def pr_automation_dir() -> Path:
    return data_dir() / 'pr-automation'


def pr_states_dir() -> Path:
    return pr_automation_dir() / 'states'


def pr_state_path(state_id: str) -> Path:
    safe_id = re.sub(r'[^A-Za-z0-9_.-]+', '_', state_id)
    return pr_states_dir() / f'{safe_id}.json'


def parse_diff_git_path(line: str) -> str:
    parts = line.split()
    if len(parts) >= 4 and parts[3].startswith('b/'):
        return parts[3][2:]
    if len(parts) >= 3 and parts[2].startswith('a/'):
        return parts[2][2:]
    return 'unknown'


def language_for_path(path: str) -> str:
    suffix = path.rsplit('.', 1)[-1].lower() if '.' in path else ''
    return {
        'py': 'python',
        'js': 'javascript',
        'jsx': 'javascript',
        'ts': 'typescript',
        'tsx': 'typescript',
        'go': 'go',
        'rs': 'rust',
        'php': 'php',
        'java': 'java',
        'kt': 'kotlin',
        'cs': 'csharp',
        'rb': 'ruby',
        'tf': 'terraform',
        'yaml': 'yaml',
        'yml': 'yaml',
        'json': 'json',
        'ps1': 'powershell',
        'sh': 'shell',
    }.get(suffix, 'unknown')


def looks_generated(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in ['/dist/', '/build/', '/vendor/', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock'])


def normalize_ticket_provider(value: Any) -> TicketProvider:
    provider = str(value or 'unknown').lower()
    if provider in {'jira', 'linear', 'github', 'azure-devops'}:
        return provider  # type: ignore[return-value]
    return 'unknown'


def infer_ticket_provider(key: str) -> TicketProvider:
    if key.startswith('#'):
        return 'github'
    return 'unknown'


def first_sentence(text: str) -> str:
    cleaned = ' '.join((text or '').split())
    if not cleaned:
        return ''
    match = re.search(r'(?<=[.!?])\s+', cleaned)
    return cleaned[: match.start()].strip() if match else cleaned


def safe_text(value: Any, limit: int) -> str:
    text = str(value or '').replace('\x00', '').strip()
    return text if len(text) <= limit else text[: max(0, limit - 3)] + '...'


def safe_filename(value: Any) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', str(value or '').strip())[:160] or 'unknown'


def sha256_text(value: str) -> str:
    return hashlib.sha256((value or '').encode('utf-8')).hexdigest()


def url_quote(value: Any) -> str:
    return urllib.parse.quote(str(value or ''), safe='')


def int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value not in {None, ''} else None
    except (TypeError, ValueError):
        return None


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == '':
        return default
    return value.lower() in {'1', 'true', 'yes', 'on'}
