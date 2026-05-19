from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .memory import memory_summary
from .models import Finding, ScanResult
from .storage import apply_decisions, list_scans, load_scan

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGNS_PATH = ROOT / 'data' / 'security_campaigns.json'
PRIORITY_ORDER = {'P0': 0, 'P1': 1, 'P2': 2, 'P3': 3, 'P4': 4}


def empty_campaign_store() -> dict[str, Any]:
    return {'schema_version': 1, 'campaigns': []}


def load_campaigns() -> dict[str, Any]:
    if not CAMPAIGNS_PATH.exists():
        return empty_campaign_store()
    data = json.loads(CAMPAIGNS_PATH.read_text(encoding='utf-8'))
    data.setdefault('schema_version', 1)
    data.setdefault('campaigns', [])
    return data


def save_campaigns(data: dict[str, Any]) -> None:
    CAMPAIGNS_PATH.parent.mkdir(parents=True, exist_ok=True)
    data.setdefault('schema_version', 1)
    data.setdefault('campaigns', [])
    CAMPAIGNS_PATH.write_text(json.dumps(data, indent=2), encoding='utf-8')


def create_campaign(
    title: str,
    focus_area: str,
    owner: str | None = None,
    due_date: str | None = None,
    description: str | None = None,
    status: str = 'planned',
    scan_id: str | None = None,
    rule_ids: list[str] | None = None,
    repository_keys: list[str] | None = None,
    target_reduction_percent: int = 80,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    campaign = {
        'id': campaign_id(title, focus_area, now),
        'title': title,
        'focus_area': focus_area,
        'description': description or '',
        'status': status,
        'owner': owner or 'unassigned',
        'due_date': due_date,
        'created_at': now,
        'updated_at': now,
        'source': 'manual',
        'scan_id': scan_id,
        'rule_ids': rule_ids or [],
        'repository_keys': repository_keys or [],
        'target_reduction_percent': max(0, min(target_reduction_percent, 100)),
        'success_criteria': [
            f'Reduce matching open findings by at least {max(0, min(target_reduction_percent, 100))}%.',
            'Record accepted exceptions with decision rationale.',
            'Add one team learning note or coding guideline update.',
        ],
        'recommended_actions': actions_for_focus(focus_area),
    }
    store = load_campaigns()
    store['campaigns'].insert(0, campaign)
    save_campaigns(store)
    return campaign


def team_learning_dashboard(limit: int = 100) -> dict[str, Any]:
    scans = [apply_decisions(scan) for scan in list_scans()[: max(1, min(limit, 500))]]
    campaigns = load_campaigns().get('campaigns', [])
    latest_scan = scans[0] if scans else None
    all_findings = [finding for scan in scans for finding in scan.findings]
    open_findings = [finding for finding in all_findings if finding.decision not in {'false_positive', 'risk_accepted'}]
    repo_summary = memory_summary()
    metrics = dashboard_metrics(scans, open_findings, repo_summary)
    patterns = recurring_patterns(scans, open_findings)
    learning = learning_recommendations(patterns, metrics)
    recommendations = campaign_recommendations(patterns, latest_scan)
    active_campaigns = [campaign for campaign in campaigns if campaign.get('status') in {'planned', 'active'}]
    completed_campaigns = [campaign for campaign in campaigns if campaign.get('status') == 'completed']
    return {
        'schema_version': 1,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': dashboard_status(metrics),
        'scan_count': len(scans),
        'latest_scan_id': latest_scan.scan_id if latest_scan else None,
        'latest_project': latest_scan.project_name if latest_scan else None,
        'metrics': metrics,
        'trends': risk_trends(scans),
        'patterns': patterns,
        'learning_recommendations': learning,
        'campaigns': {
            'active': active_campaigns,
            'completed': completed_campaigns[:25],
            'recommended': recommendations,
        },
        'dashboard_cards': dashboard_cards(metrics, patterns, active_campaigns, learning),
        'memory_summary': repo_summary,
        'guardrails': [
            'Use campaigns to reduce recurring risk patterns, not to hide findings.',
            'Completed campaigns should be validated by a new scan and decision audit review.',
            'Training recommendations are derived from local scan history and do not require external LLM calls.',
        ],
    }


def scan_learning_brief(scan: ScanResult) -> dict[str, Any]:
    scan = apply_decisions(scan)
    open_findings = [finding for finding in scan.findings if finding.decision not in {'false_positive', 'risk_accepted'}]
    patterns = recurring_patterns([scan], open_findings)
    metrics = dashboard_metrics([scan], open_findings, memory_summary())
    return {
        'schema_version': 1,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'status': dashboard_status(metrics),
        'metrics': metrics,
        'patterns': patterns,
        'learning_recommendations': learning_recommendations(patterns, metrics),
        'campaign_recommendations': campaign_recommendations(patterns, scan),
    }


def scan_learning_brief_by_id(scan_id: str) -> dict[str, Any]:
    return scan_learning_brief(load_scan(scan_id))


def dashboard_metrics(scans: list[ScanResult], open_findings: list[Finding], repo_summary: dict[str, Any]) -> dict[str, Any]:
    p0 = sum(1 for finding in open_findings if finding.risk.priority == 'P0')
    p1 = sum(1 for finding in open_findings if finding.risk.priority == 'P1')
    accepted = sum(1 for scan in scans for finding in scan.findings if finding.decision == 'risk_accepted')
    false_positive = sum(1 for scan in scans for finding in scan.findings if finding.decision == 'false_positive')
    avg_max_risk = round(sum(scan.summary.max_risk_score for scan in scans) / len(scans), 1) if scans else 0
    avg_findings = round(sum(scan.summary.total_findings for scan in scans) / len(scans), 1) if scans else 0
    return {
        'repositories': len(repo_summary.get('repositories', [])),
        'scans': len(scans),
        'open_findings': len(open_findings),
        'open_p0': p0,
        'open_p1': p1,
        'risk_acceptances': accepted,
        'false_positives': false_positive,
        'avg_max_risk': avg_max_risk,
        'avg_findings_per_scan': avg_findings,
        'campaigns_active': len([c for c in load_campaigns().get('campaigns', []) if c.get('status') in {'planned', 'active'}]),
    }


def recurring_patterns(scans: list[ScanResult], findings: list[Finding]) -> dict[str, Any]:
    rule_counts = Counter(finding.rule_id for finding in findings)
    source_counts = Counter(finding.source for finding in findings)
    file_counts = Counter(finding.location.path for finding in findings)
    cwe_counts = Counter(tag for finding in findings for tag in finding.cwe)
    owasp_counts = Counter(tag for finding in findings for tag in finding.owasp)
    dependency_findings = [finding for finding in findings if is_dependency_finding(finding)]
    secret_findings = [finding for finding in findings if is_secret_finding(finding)]
    injection_findings = [finding for finding in findings if is_injection_finding(finding)]
    scanner_gaps = scanner_gap_summary(scans)
    return {
        'top_rules': counter_items(rule_counts, 10),
        'top_sources': counter_items(source_counts, 10),
        'hotspot_files': counter_items(file_counts, 10),
        'top_cwe': counter_items(cwe_counts, 10),
        'top_owasp': counter_items(owasp_counts, 10),
        'finding_classes': {
            'secrets': len(secret_findings),
            'dependencies': len(dependency_findings),
            'injection': len(injection_findings),
        },
        'scanner_gaps': scanner_gaps,
        'repo_patterns': repo_patterns(scans),
    }


def risk_trends(scans: list[ScanResult]) -> dict[str, Any]:
    if len(scans) < 2:
        return {'status': 'insufficient_history', 'points': trend_points(scans)}
    newest = scans[0]
    oldest = scans[-1]
    finding_delta = newest.summary.total_findings - oldest.summary.total_findings
    p0_delta = newest.summary.priorities.get('P0', 0) - oldest.summary.priorities.get('P0', 0)
    max_risk_delta = newest.summary.max_risk_score - oldest.summary.max_risk_score
    status = 'improving' if finding_delta < 0 and p0_delta <= 0 and max_risk_delta <= 0 else 'worsening' if finding_delta > 0 or p0_delta > 0 or max_risk_delta > 0 else 'stable'
    return {
        'status': status,
        'finding_delta': finding_delta,
        'p0_delta': p0_delta,
        'max_risk_delta': max_risk_delta,
        'points': trend_points(scans[:25]),
    }


def trend_points(scans: list[ScanResult]) -> list[dict[str, Any]]:
    points = []
    for scan in reversed(scans):
        points.append({
            'scan_id': scan.scan_id,
            'project_name': scan.project_name,
            'created_at': scan.created_at.isoformat(),
            'findings': scan.summary.total_findings,
            'max_risk_score': scan.summary.max_risk_score,
            'avg_risk_score': scan.summary.avg_risk_score,
            'p0': scan.summary.priorities.get('P0', 0),
            'p1': scan.summary.priorities.get('P1', 0),
        })
    return points


def repo_patterns(scans: list[ScanResult]) -> list[dict[str, Any]]:
    grouped: dict[str, list[ScanResult]] = defaultdict(list)
    for scan in scans:
        grouped[scan.target_path].append(scan)
    rows = []
    for path, repo_scans in grouped.items():
        latest = sorted(repo_scans, key=lambda item: item.created_at, reverse=True)[0]
        rows.append({
            'project_name': latest.project_name,
            'target_path': path,
            'scan_count': len(repo_scans),
            'latest_scan_id': latest.scan_id,
            'open_findings': latest.summary.total_findings,
            'max_risk_score': latest.summary.max_risk_score,
            'p0': latest.summary.priorities.get('P0', 0),
            'p1': latest.summary.priorities.get('P1', 0),
        })
    return sorted(rows, key=lambda item: (-item['p0'], -item['max_risk_score'], -item['scan_count']))[:25]


def learning_recommendations(patterns: dict[str, Any], metrics: dict[str, Any]) -> list[dict[str, Any]]:
    recommendations = []
    classes = patterns.get('finding_classes', {})
    if classes.get('secrets', 0):
        recommendations.append(learning_item('Secrets handling', 'secret-management', classes['secrets'], [
            'Use approved secret stores and CI secret variables.',
            'Rotate leaked values before closing findings.',
            'Add pre-commit or push-protection checks for high-risk repositories.',
        ]))
    if classes.get('dependencies', 0):
        recommendations.append(learning_item('Dependency upgrade hygiene', 'dependency-risk', classes['dependencies'], [
            'Review reachable runtime dependencies first.',
            'Track fixed versions and update lockfiles in the same change.',
            'Define an SLA for critical and high dependency vulnerabilities.',
        ]))
    if classes.get('injection', 0):
        recommendations.append(learning_item('Injection-safe coding', 'injection-prevention', classes['injection'], [
            'Use parameterized APIs and safe process execution wrappers.',
            'Avoid shell=True and string-built commands.',
            'Add focused code review checklist items for input boundaries.',
        ]))
    if metrics.get('open_p0', 0):
        recommendations.append(learning_item('Release-blocking risk triage', 'risk-triage', metrics['open_p0'], [
            'Review P0 findings before release.',
            'Require explicit risk acceptance for deferred P0 work.',
            'Pair security reviewer and feature owner on top-risk files.',
        ]))
    for gap in patterns.get('scanner_gaps', [])[:3]:
        recommendations.append(learning_item(f'Scanner coverage: {gap["tool"]}', 'scanner-coverage', gap['count'], [
            gap['recommendation'],
            'Document scanner setup in onboarding and CI runbooks.',
        ]))
    return recommendations or [learning_item('Keep scanning to build learning history', 'baseline', 0, ['Run scans on each active repository and save baselines for trend learning.'])]


def campaign_recommendations(patterns: dict[str, Any], latest_scan: ScanResult | None) -> list[dict[str, Any]]:
    recommendations = []
    classes = patterns.get('finding_classes', {})
    if classes.get('secrets', 0):
        recommendations.append(recommended_campaign('Secrets exposure reduction', 'secrets', classes['secrets'], latest_scan, ['Rotate exposed values', 'Move secrets to approved stores', 'Enable push protection in CI']))
    if classes.get('dependencies', 0):
        recommendations.append(recommended_campaign('Critical dependency upgrade sprint', 'dependencies', classes['dependencies'], latest_scan, ['Patch reachable critical/high dependencies', 'Update lockfiles', 'Document upgrade owners']))
    if classes.get('injection', 0):
        recommendations.append(recommended_campaign('Injection risk hardening', 'injection', classes['injection'], latest_scan, ['Replace unsafe command/query construction', 'Add tests for malicious input', 'Review shared input validation helpers']))
    hotspot = (patterns.get('hotspot_files') or [{}])[0]
    if hotspot.get('count', 0) >= 3:
        recommendations.append(recommended_campaign(f'Hotspot cleanup: {hotspot["key"]}', 'hotspot-files', hotspot['count'], latest_scan, ['Refactor risky hotspot file', 'Add focused owner review', 'Reduce duplicate finding classes']))
    for gap in patterns.get('scanner_gaps', [])[:2]:
        recommendations.append(recommended_campaign(f'Scanner coverage: {gap["tool"]}', 'scanner-coverage', gap['count'], latest_scan, [gap['recommendation'], 'Verify in CI and record evidence']))
    return recommendations


def dashboard_cards(metrics: dict[str, Any], patterns: dict[str, Any], active_campaigns: list[dict[str, Any]], learning: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {'title': 'Open P0/P1 Risk', 'value': metrics.get('open_p0', 0) + metrics.get('open_p1', 0), 'detail': f"P0={metrics.get('open_p0', 0)}, P1={metrics.get('open_p1', 0)}"},
        {'title': 'Active Campaigns', 'value': len(active_campaigns), 'detail': 'planned or active security campaigns'},
        {'title': 'Top Rule', 'value': (patterns.get('top_rules') or [{'key': 'none'}])[0].get('key', 'none'), 'detail': 'most frequent open rule'},
        {'title': 'Learning Focus', 'value': (learning or [{'title': 'Baseline'}])[0].get('title', 'Baseline'), 'detail': 'highest-signal team learning topic'},
    ]


def scanner_gap_summary(scans: list[ScanResult]) -> list[dict[str, Any]]:
    gaps = Counter()
    for scan in scans:
        for tool, status in scan.summary.tools.items():
            text = str(status).lower()
            if 'disabled' in text or 'not installed' in text or 'not configured' in text or 'missing' in text:
                gaps[tool] += 1
    return [
        {'tool': tool, 'count': count, 'recommendation': scanner_recommendation(tool)}
        for tool, count in gaps.most_common(10)
    ]


def dashboard_status(metrics: dict[str, Any]) -> str:
    if metrics.get('open_p0', 0):
        return 'action_required'
    if metrics.get('open_p1', 0):
        return 'review_required'
    if metrics.get('open_findings', 0):
        return 'monitor'
    return 'healthy'


def learning_item(title: str, topic: str, evidence_count: int, actions: list[str]) -> dict[str, Any]:
    return {
        'title': title,
        'topic': topic,
        'evidence_count': evidence_count,
        'recommended_actions': actions,
        'format': '30-minute team review plus checklist update',
    }


def recommended_campaign(title: str, focus_area: str, evidence_count: int, scan: ScanResult | None, actions: list[str]) -> dict[str, Any]:
    return {
        'id': campaign_id(title, focus_area, scan.scan_id if scan else 'no-scan'),
        'title': title,
        'focus_area': focus_area,
        'source': 'recommended',
        'scan_id': scan.scan_id if scan else None,
        'evidence_count': evidence_count,
        'target_reduction_percent': 80,
        'recommended_actions': actions,
        'success_criteria': [
            'Open matching findings reduced by 80%.',
            'No P0 findings remain without accepted risk rationale.',
            'Team checklist or secure coding guideline updated.',
        ],
    }


def actions_for_focus(focus_area: str) -> list[str]:
    focus = (focus_area or '').lower()
    if 'secret' in focus:
        return ['Rotate exposed values', 'Move secrets to a managed store', 'Enable push protection and review history exposure']
    if 'depend' in focus:
        return ['Patch reachable critical/high packages', 'Update lockfiles', 'Record deferred upgrades with owners']
    if 'inject' in focus:
        return ['Replace unsafe query/command construction', 'Add malicious-input tests', 'Review shared input boundary helpers']
    if 'scanner' in focus:
        return ['Install missing scanner tooling', 'Configure CI evidence artifacts', 'Document local setup']
    return ['Triage top findings', 'Assign owners', 'Validate with a fresh scan']


def scanner_recommendation(tool: str) -> str:
    lower = tool.lower()
    if 'codeql' in lower:
        return 'Install/configure CodeQL query packs for semantic coverage.'
    if 'sonar' in lower:
        return 'Configure SonarQube/SonarCloud credentials and project key.'
    if 'gitleaks' in lower or 'trufflehog' in lower:
        return 'Install external secret scanners for defense-in-depth.'
    return f'Configure or document scanner availability for {tool}.'


def counter_items(counter: Counter, limit: int) -> list[dict[str, Any]]:
    return [{'key': key, 'count': count} for key, count in counter.most_common(limit)]


def is_secret_finding(finding: Finding) -> bool:
    text = f'{finding.source} {finding.rule_id} {finding.title}'.lower()
    return 'secret' in text or 'credential' in text or 'token' in text


def is_dependency_finding(finding: Finding) -> bool:
    text = f'{finding.source} {finding.rule_id} {finding.title}'.lower()
    return any(item in text for item in ['pip-audit', 'dependency', 'vulnerable dependency', 'npm', 'package'])


def is_injection_finding(finding: Finding) -> bool:
    text = f'{finding.rule_id} {finding.title} {" ".join(finding.cwe)} {" ".join(finding.owasp)}'.lower()
    return any(item in text for item in ['injection', 'cwe-78', 'cwe-79', 'cwe-89', 'command', 'sql'])


def campaign_id(title: str, focus_area: str, seed: str) -> str:
    raw = f'{title}:{focus_area}:{seed}'.encode('utf-8')
    return hashlib.sha256(raw).hexdigest()[:16]
