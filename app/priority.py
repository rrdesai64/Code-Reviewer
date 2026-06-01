from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .execution_evidence import ExecutionEvidenceProvider, NullExecutionEvidenceProvider
from .models import Finding, FindingPriority, FindingScope, PriorityDecisionFactor, ScanResult
from .scope import classify_path_scope

PRIORITY_SCHEMA_VERSION = 'finding-prioritization-v1'
SUPPRESSED_DECISIONS = {'false_positive', 'risk_accepted', 'suppressed'}
PATH_CAP_P3 = {'test', 'vendor', 'generated'}


@dataclass(frozen=True)
class PriorityConfig:
    severity_weights: dict[str, float] = field(default_factory=lambda: {
        'CRITICAL': 100,
        'HIGH': 70,
        'MEDIUM': 40,
        'LOW': 15,
        'INFO': 5,
    })
    dataflow_reachable: float = 25
    confirmed_exploitable: float = 35
    high_precision_without_dataflow: float = 10
    tool_agreement_per_extra_tool: float = 8
    tool_agreement_cap: float = 24
    path_class_weights: dict[str, float] = field(default_factory=lambda: {
        'production': 0,
        'dependency': 0,
        'endpoint': 0,
        'unknown': 0,
        'config': -10,
        'docs': -20,
        'example': -25,
        'generated': -35,
        'test': -40,
        'vendor': -40,
    })
    pr_diff: float = 20
    recent_change: float = 5
    stale_change: float = -10
    executed: float = 15
    not_executed: float = -20
    p0_threshold: float = 100
    p1_threshold: float = 70
    p2_threshold: float = 35


def apply_priority_scoring(scan: ScanResult, provider: ExecutionEvidenceProvider | None = None, config: PriorityConfig | None = None) -> ScanResult:
    provider = provider or NullExecutionEvidenceProvider()
    config = config or PriorityConfig()
    populate_corroborating_tools(scan)
    for finding in scan.findings:
        enrich_priority_context(finding, provider)
        finding.priority = score_priority(finding, config)
    update_priority_summary(scan)
    return scan


def populate_corroborating_tools(scan: ScanResult) -> None:
    by_id = {finding.id: finding for finding in scan.findings}
    for finding in scan.findings:
        if not finding.priority_context.corroborating_tools:
            finding.priority_context.corroborating_tools = [finding.source]
    for cluster in scan.consolidated_findings:
        for finding_id in cluster.finding_ids:
            finding = by_id.get(finding_id)
            if not finding:
                continue
            finding.cluster_id = cluster.cluster_id
            finding.priority_context.corroborating_tools = list(cluster.sources or [finding.source])


def enrich_priority_context(finding: Finding, provider: ExecutionEvidenceProvider) -> None:
    context = finding.priority_context
    context.path_class = classify_path_scope(finding.location.path)
    metadata = finding.scanner_metadata or {}
    if context.in_pr_diff is None:
        context.in_pr_diff = metadata.get('changed_file_context') == 'true'
    if context.last_modified_days is None:
        if metadata.get('changed_file_context') == 'true':
            context.last_modified_days = 0
        elif metadata.get('recent_file_context') == 'true':
            try:
                context.last_modified_days = int(metadata.get('recent_change_days', '30'))
            except ValueError:
                context.last_modified_days = 30
    evidence = provider.evidence(finding.location.path, finding.location.line)
    context.execution = evidence.state
    context.execution_source = evidence.source
    context.execution_hits = evidence.hits


def score_priority(finding: Finding, config: PriorityConfig) -> FindingPriority:
    factors: list[PriorityDecisionFactor] = []
    add_factor(factors, 'base_severity', config.severity_weights.get(finding.severity, 5), f'{finding.severity} scanner severity baseline.')

    if finding.dataflow.has_dataflow:
        add_factor(factors, 'dataflow_reachable', config.dataflow_reachable, 'Scanner reported source-to-sink dataflow.')
    elif finding.dataflow.tool_precision in {'high', 'very-high'}:
        add_factor(factors, 'tool_precision', config.high_precision_without_dataflow, f'{finding.dataflow.tool_precision} tool precision without explicit dataflow.')
    if finding.dataflow.confirmed_exploitable:
        detail = dynamic_detail(finding)
        add_factor(factors, 'confirmed_exploitable', config.confirmed_exploitable, f'DAST dynamically confirmed exploitability{detail}.')

    tools = sorted(set(finding.priority_context.corroborating_tools or [finding.source]))
    agreement = min(config.tool_agreement_cap, max(0, len(tools) - 1) * config.tool_agreement_per_extra_tool)
    if agreement:
        add_factor(factors, 'tool_agreement', agreement, f'{len(tools)} tools corroborate this issue: {", ".join(tools)}.')

    path_class = finding.priority_context.path_class
    add_factor(factors, 'path_class', config.path_class_weights.get(path_class, 0), f'Path classified as {path_class}.')

    if finding.priority_context.in_pr_diff:
        add_factor(factors, 'git_recency', config.pr_diff, 'Finding is in the PR diff or supplied changed-file list.')
    elif finding.priority_context.last_modified_days is not None:
        days = finding.priority_context.last_modified_days
        if days <= 90:
            add_factor(factors, 'git_recency', config.recent_change, f'File changed within {days} day(s).')
        elif days > 730:
            add_factor(factors, 'git_recency', config.stale_change, f'File appears untouched for {days} day(s).')

    if finding.priority_context.execution == 'executed':
        add_factor(factors, 'execution_evidence', config.executed, 'Line was executed by test coverage; this is not attacker reachability.')
    elif finding.priority_context.execution == 'not_executed':
        add_factor(factors, 'execution_evidence', config.not_executed, 'File is in test coverage but this line was not covered; uncovered does not mean safe.')

    score = round(sum(factor.delta for factor in factors), 2)
    tier = assign_tier(finding, score, tools, path_class, config)
    if finding.decision in SUPPRESSED_DECISIONS:
        factors.append(PriorityDecisionFactor(name='suppressed_decision', delta=0, reason=f'Finding decision is {finding.decision}; excluded from active ranking.'))
        tier = None
    return FindingPriority(tier=tier, score=score, factors=factors)


def assign_tier(finding: Finding, score: float, tools: list[str], path_class: FindingScope, config: PriorityConfig) -> str:
    if path_class in PATH_CAP_P3:
        return 'P3'
    p0_guard = finding.dataflow.confirmed_exploitable or finding.dataflow.has_dataflow or len(set(tools)) >= 2
    if score >= config.p0_threshold and p0_guard:
        return 'P0'
    if score >= config.p1_threshold:
        return 'P1'
    if score >= config.p2_threshold:
        return 'P2'
    return 'P3'


def update_priority_summary(scan: ScanResult) -> None:
    active = [finding for finding in scan.findings if finding.priority and finding.priority.tier]
    suppressed = [finding for finding in scan.findings if finding.priority and finding.priority.tier is None]
    scan.summary.finding_priority_counts = dict(sorted(Counter(finding.priority.tier for finding in active).items()))
    scan.summary.top_finding_priority_score = max((finding.priority.score or 0 for finding in scan.findings if finding.priority), default=0)
    scan.summary.active_prioritized_findings = len(active)
    scan.summary.suppressed_prioritized_findings = len(suppressed)


def prioritization_report(scan: ScanResult, limit: int = 100) -> dict[str, Any]:
    update_priority_summary(scan)
    ranked = sorted(scan.findings, key=priority_sort_key)
    return {
        'schema_version': PRIORITY_SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'summary': {
            'priority_counts': scan.summary.finding_priority_counts,
            'top_score': scan.summary.top_finding_priority_score,
            'active_findings': scan.summary.active_prioritized_findings,
            'suppressed_findings': scan.summary.suppressed_prioritized_findings,
        },
        'policy': {
            'p0_guard': 'P0 requires score >= 100 and either dataflow evidence or at least two corroborating tools.',
            'path_cap': 'test, vendor, and generated findings are capped at P3 but retained.',
            'execution_caveat': 'Coverage evidence is test execution only; uncovered does not mean dead or safe.',
            'raw_code_included': False,
        },
        'findings': [priority_record(finding) for finding in ranked[:max(0, limit)]],
    }


def priority_record(finding: Finding) -> dict[str, Any]:
    priority = finding.priority or FindingPriority()
    return {
        'finding_id': finding.id,
        'fingerprint': finding.fingerprint,
        'cluster_id': finding.cluster_id or '',
        'source': finding.source,
        'rule_id': finding.rule_id,
        'title': finding.title,
        'location': {'path': finding.location.path, 'line': finding.location.line},
        'severity': finding.severity,
        'decision': finding.decision,
        'priority': priority.model_dump(mode='json'),
        'dataflow': finding.dataflow.model_dump(mode='json'),
        'dynamic': finding.dynamic.model_dump(mode='json') if finding.dynamic else None,
        'context': finding.priority_context.model_dump(mode='json'),
    }


def priority_sort_key(finding: Finding) -> tuple[int, float, str, int, str]:
    tier_rank = {'P0': 4, 'P1': 3, 'P2': 2, 'P3': 1, None: 0}
    priority = finding.priority
    return (
        -tier_rank.get(priority.tier if priority else None, 0),
        -(priority.score if priority and priority.score is not None else -1),
        finding.location.path,
        finding.location.line,
        finding.id,
    )


def add_factor(factors: list[PriorityDecisionFactor], name: str, delta: float, reason: str) -> None:
    if delta:
        factors.append(PriorityDecisionFactor(name=name, delta=delta, reason=reason))


def dynamic_detail(finding: Finding) -> str:
    if not finding.dynamic:
        return ''
    values = [finding.dynamic.tool or finding.source, finding.dynamic.method, finding.dynamic.url]
    if finding.dynamic.param:
        values.append(f'param {finding.dynamic.param}')
    return f" ({' '.join(str(value) for value in values if value)})"
