from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any

from . import catalog_knowledge as catalog
from .consolidation import ensure_consolidated_scan
from .models import ConsolidatedFinding, Finding, FixSuggestion, ScanResult
from .priority import apply_priority_scoring, priority_sort_key
from .refactor import estimate_effort, is_mechanically_supported, validation_commands_for
from .scope import is_blocking_secret, is_production_impacting, normalize_path

SOUNDNESS_SCHEMA_VERSION = 'soundness-verdict-v1'
BLOCK_PRIORITIES = {'P0', 'P1'}
ACTIONABLE_DECISION = 'open'


def soundness_verdict(scan: ScanResult, limit: int = 100) -> dict[str, Any]:
    scan = apply_priority_scoring(ensure_consolidated_scan(scan))
    issues = soundness_issues(scan)
    limited_issues = issues[:max(0, limit)]
    blocking = [issue for issue in issues if issue['gate']['effect'] == 'block']
    reason_counts = Counter(reason for issue in blocking for reason in issue['gate']['reason_codes'])
    return {
        'schema_version': SOUNDNESS_SCHEMA_VERSION,
        'contract': {
            'consumer': 'autonomous-orchestrator',
            'purpose': 'inside-out-soundness-gate-and-agent-feedback',
            'deterministic': True,
            'raw_code_included': False,
            'human_formatting_required': False,
        },
        'subject': {
            'project_name': scan.project_name,
            'target_path_hash': stable_hash(scan.target_path),
            'target_name_hint': sanitize_name(Path(scan.target_path).name or scan.project_name),
        },
        'verdict': {
            'status': 'block' if blocking else 'pass',
            'confidence': verdict_confidence(scan, blocking),
            'blocking_issue_count': len(blocking),
            'reason_counts': dict(sorted(reason_counts.items())),
            'top_issue_id': issues[0]['issue_id'] if issues else '',
        },
        'policy': {
            'block_priorities': sorted(BLOCK_PRIORITIES),
            'block_critical_production': True,
            'block_high_confidence_secrets': True,
            'actionable_decision': ACTIONABLE_DECISION,
            'dast_used_for_autofix': False,
        },
        'summary': {
            'finding_count': len(scan.findings),
            'consolidated_issue_count': len(issues),
            'returned_issue_count': len(limited_issues),
            'priority_counts': dict(sorted(Counter(issue['priority']['tier'] for issue in issues if issue['priority']['tier']).items())),
            'suppressed_or_non_open_findings': sum(1 for finding in scan.findings if finding.decision != ACTIONABLE_DECISION),
            'tool_statuses': dict(sorted(scan.summary.tools.items())),
        },
        'issues': limited_issues,
        'determinism': {
            'stable_order': 'priority tier, priority score, severity, path, semantic class, issue id',
            'line_insensitive_issue_ids': True,
            'volatile_timestamps_included': False,
            'scan_id_included': False,
        },
    }


def soundness_issues(scan: ScanResult) -> list[dict[str, Any]]:
    by_id = {finding.id: finding for finding in scan.findings}
    issues = [issue_from_cluster(scan, cluster, by_id) for cluster in scan.consolidated_findings]
    issues = [issue for issue in issues if issue is not None]
    issues.sort(key=issue_sort_key)
    for index, issue in enumerate(issues, 1):
        issue['rank'] = index
    return issues


def issue_from_cluster(scan: ScanResult, cluster: ConsolidatedFinding, by_id: dict[str, Finding]) -> dict[str, Any] | None:
    findings = [by_id[finding_id] for finding_id in cluster.finding_ids if finding_id in by_id]
    actionable = [finding for finding in findings if finding.decision == ACTIONABLE_DECISION]
    if not actionable:
        return None
    representative = sorted(actionable, key=priority_sort_key)[0]
    rule = catalog_rule_for(representative)
    fix = catalog.build_fix(rule) if rule else representative.fix
    gate = gate_for_issue(representative)
    return {
        'rank': 0,
        'issue_id': stable_issue_id(cluster, representative, rule),
        'cluster_id': cluster.cluster_id,
        'machine_key': machine_key(cluster, representative, rule),
        'gate': gate,
        'priority': priority_payload(representative),
        'vulnerability': vulnerability_payload(cluster, representative, rule),
        'location': {
            'path': normalize_path(cluster.path or representative.location.path),
            'line': int(cluster.line_start or representative.location.line or 1),
            'end_line': int(cluster.line_end or representative.location.end_line or cluster.line_start or representative.location.line or 1),
        },
        'evidence': {
            'sources': sorted(cluster.sources),
            'rules': sorted(cluster.rules),
            'finding_ids': sorted(finding.id for finding in actionable),
            'raw_finding_count': len(findings),
            'actionable_finding_count': len(actionable),
            'tool_agreement_count': int(cluster.agreement_count),
            'cwe': sorted(cluster.cwe),
            'sink': cluster.sink,
            'dataflow': representative.dataflow.model_dump(mode='json'),
            'context': representative.priority_context.model_dump(mode='json'),
        },
        'remediation': remediation_payload(scan, representative, fix, rule),
    }


def gate_for_issue(finding: Finding) -> dict[str, Any]:
    reasons: list[str] = []
    priority_tier = finding.priority.tier if finding.priority else finding.risk.priority
    if priority_tier in BLOCK_PRIORITIES and is_production_impacting(finding):
        reasons.append(f'priority:{priority_tier}')
    if finding.severity == 'CRITICAL' and is_production_impacting(finding):
        reasons.append('critical-production')
    if is_blocking_secret(finding):
        reasons.append('blocking-secret')
    return {
        'effect': 'block' if reasons else 'none',
        'reason_codes': sorted(set(reasons)),
    }


def priority_payload(finding: Finding) -> dict[str, Any]:
    if finding.priority:
        return finding.priority.model_dump(mode='json')
    return {'tier': finding.risk.priority, 'score': float(finding.risk.score), 'factors': []}


def vulnerability_payload(cluster: ConsolidatedFinding, finding: Finding, rule: dict[str, Any] | None) -> dict[str, Any]:
    catalog_id = str(rule.get('id') or '') if rule else ''
    return {
        'class': cluster.sink or catalog_id or finding.rule_id,
        'title': finding.title,
        'severity': finding.severity,
        'confidence': finding.confidence,
        'catalog': catalog_payload(rule),
        'source_rule': {
            'source': finding.source,
            'rule_id': finding.rule_id,
            'cwe': sorted(finding.cwe),
            'owasp': sorted(finding.owasp),
        },
    }


def remediation_payload(scan: ScanResult, finding: Finding, fix: FixSuggestion, rule: dict[str, Any] | None) -> dict[str, Any]:
    mechanical = is_mechanically_supported(finding)
    guidance = [item for item in [fix.summary, *fix.guidance, *finding.remediation] if item]
    return {
        'source': 'catalog' if rule else 'finding',
        'summary': fix.summary,
        'guidance': sorted(set(guidance)),
        'agent_actions': agent_actions_for(finding, mechanical),
        'mechanical_patch_available': mechanical,
        'effort': estimate_effort(finding, mechanical=mechanical),
        'proposal_endpoint': f'/api/scans/{{scan_id}}/findings/{finding.id}/fix-proposal',
        'validation_commands': validation_commands_for(scan, finding),
        'rescan_required': True,
    }


def agent_actions_for(finding: Finding, mechanical: bool) -> list[dict[str, str]]:
    actions = [
        {'kind': 'inspect_location', 'path': normalize_path(finding.location.path), 'line': str(finding.location.line)},
        {'kind': 'apply_remediation_guidance', 'rule_id': finding.rule_id, 'mechanical_patch_supported': str(mechanical).lower()},
        {'kind': 'rerun_soundness_gate', 'expected_outcome': 'finding_resolved_without_new_blockers'},
    ]
    if finding.source in {'pip-audit', 'dependency-manifest', 'snyk'}:
        actions.insert(1, {'kind': 'update_dependency', 'path': normalize_path(finding.location.path), 'line': str(finding.location.line)})
    return actions


def catalog_rule_for(finding: Finding) -> dict[str, Any] | None:
    catalog_rule_id = (finding.scanner_metadata or {}).get('catalog_rule_id', '')
    if catalog_rule_id:
        rule = catalog.get_rule(catalog_rule_id)
        if rule:
            return rule
    return catalog.match_rule(finding.rule_id, finding.message, finding.cwe)


def catalog_payload(rule: dict[str, Any] | None) -> dict[str, Any]:
    if not rule:
        return {'matched': False}
    return {
        'matched': True,
        'rule_id': str(rule.get('id') or ''),
        'name': str(rule.get('name') or ''),
        'category': str(rule.get('category') or ''),
        'languages': sorted(str(item) for item in (rule.get('languages') or [])),
        'cwe': [f'CWE-{item}' for item in (rule.get('cwe') or [])],
        'owasp': [str(item) for item in (rule.get('owasp') or [])],
        'detection': str(rule.get('detection') or ''),
    }


def stable_issue_id(cluster: ConsolidatedFinding, finding: Finding, rule: dict[str, Any] | None) -> str:
    return stable_hash(machine_key(cluster, finding, rule))[:24]


def machine_key(cluster: ConsolidatedFinding, finding: Finding, rule: dict[str, Any] | None) -> str:
    catalog_id = str(rule.get('id') or '') if rule else ''
    parts = [
        'soundness-issue-v1',
        normalize_path(cluster.path or finding.location.path),
        catalog_id or cluster.semantic_key or finding.rule_id,
        ','.join(sorted(cluster.cwe or finding.cwe)),
        cluster.sink or '',
        normalize_message(finding.title or finding.message),
    ]
    return '|'.join(parts)


def issue_sort_key(issue: dict[str, Any]) -> tuple[int, float, int, str, str, str]:
    priority_rank = {'P0': 0, 'P1': 1, 'P2': 2, 'P3': 3, None: 4}
    severity_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    priority = issue.get('priority', {})
    location = issue.get('location', {})
    vulnerability = issue.get('vulnerability', {})
    return (
        priority_rank.get(priority.get('tier'), 4),
        -float(priority.get('score') or 0),
        severity_rank.get(vulnerability.get('severity'), 5),
        str(location.get('path') or ''),
        str(vulnerability.get('class') or ''),
        str(issue.get('issue_id') or ''),
    )


def verdict_confidence(scan: ScanResult, blocking: list[dict[str, Any]]) -> str:
    if not blocking:
        if any(status_needs_attention(status) for status in scan.summary.tools.values()):
            return 'medium'
        return 'high'
    if any(issue['evidence']['tool_agreement_count'] > 1 or issue['evidence']['dataflow'].get('has_dataflow') for issue in blocking):
        return 'high'
    return 'medium'


def status_needs_attention(status: str) -> bool:
    text = str(status or '').lower()
    return any(token in text for token in ('error', 'partial', 'not installed', 'disabled'))


def stable_hash(value: str) -> str:
    return hashlib.sha256(str(value or '').encode('utf-8')).hexdigest()


def normalize_message(value: str) -> str:
    text = re.sub(r'\b\d+\b', '#', str(value or '').lower())
    return re.sub(r'\s+', ' ', text).strip()[:160]


def sanitize_name(value: str) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', str(value or '').strip()).strip('._-')[:120]
