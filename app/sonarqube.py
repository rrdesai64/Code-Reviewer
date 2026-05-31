from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .models import Finding, ScanResult


def sonarqube_quality_report(scan: ScanResult) -> dict[str, Any]:
    sonar_findings = [finding for finding in scan.findings if finding.source == 'sonarqube']
    gate_findings = [finding for finding in sonar_findings if is_quality_gate_finding(finding)]
    issue_findings = [finding for finding in sonar_findings if not is_quality_gate_finding(finding)]
    tool_status = scan.summary.tools.get('sonarqube', 'missing')
    gate_status = first_gate_status(gate_findings) or parse_quality_gate_status(tool_status)
    status = report_status(tool_status, gate_status, gate_findings)
    severity_counts = Counter(finding.severity for finding in issue_findings)
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': status,
        'tool_status': tool_status,
        'quality_gate': {
            'status': gate_status or 'UNKNOWN',
            'failing_conditions': [quality_gate_condition(finding) for finding in gate_findings],
            'failed_condition_count': len(gate_findings),
        },
        'issues': {
            'total': len(issue_findings),
            'critical': severity_counts.get('CRITICAL', 0),
            'high': severity_counts.get('HIGH', 0),
            'medium': severity_counts.get('MEDIUM', 0),
            'low': severity_counts.get('LOW', 0),
            'info': severity_counts.get('INFO', 0),
            'top': [issue_summary(finding) for finding in top_issues(issue_findings)],
        },
        'policy': policy_summary(status, gate_status, issue_findings, gate_findings, tool_status),
    }


def is_quality_gate_finding(finding: Finding) -> bool:
    metadata = finding.scanner_metadata or {}
    return metadata.get('sonar_kind') == 'quality_gate' or finding.rule_id.startswith('sonarqube-quality-gate')


def first_gate_status(findings: list[Finding]) -> str | None:
    for finding in findings:
        status = (finding.scanner_metadata or {}).get('quality_gate_status')
        if status:
            return status.upper()
    return None


def parse_quality_gate_status(tool_status: str) -> str | None:
    match = re.search(r'quality_gate=([A-Za-z_]+)', tool_status or '')
    return match.group(1).upper() if match else None


def report_status(tool_status: str, gate_status: str | None, gate_findings: list[Finding]) -> str:
    lowered = (tool_status or '').lower()
    if 'not configured' in lowered or 'not installed' in lowered or 'disabled' in lowered or tool_status == 'missing':
        return 'not_configured'
    if 'scanner failed' in lowered or 'fetch_failed' in lowered:
        return 'needs_attention'
    if gate_status in {'ERROR', 'FAILED'} or any(finding.severity == 'CRITICAL' for finding in gate_findings):
        return 'failed'
    if gate_status == 'WARN' or gate_findings:
        return 'warning'
    if gate_status in {'OK', 'PASS'}:
        return 'passed'
    return 'needs_attention'


def quality_gate_condition(finding: Finding) -> dict[str, Any]:
    metadata = finding.scanner_metadata or {}
    return {
        'finding_id': finding.id,
        'metric_key': metadata.get('metric_key', ''),
        'metric_name': metadata.get('metric_name', ''),
        'status': metadata.get('quality_gate_condition_status', finding.severity),
        'actual_value': metadata.get('actual_value', ''),
        'error_threshold': metadata.get('error_threshold', ''),
        'comparator': metadata.get('comparator', ''),
        'message': finding.message,
        'severity': finding.severity,
    }


def issue_summary(finding: Finding) -> dict[str, Any]:
    metadata = finding.scanner_metadata or {}
    return {
        'id': finding.id,
        'rule_id': finding.rule_id,
        'title': finding.title,
        'severity': finding.severity,
        'risk_score': finding.risk.score,
        'priority': finding.risk.priority,
        'path': finding.location.path,
        'line': finding.location.line,
        'type': metadata.get('type', ''),
        'status': metadata.get('status', ''),
        'message': finding.message,
    }


def top_issues(findings: list[Finding], limit: int = 50) -> list[Finding]:
    severity_rank = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
    return sorted(findings, key=lambda item: (item.risk.score, severity_rank.get(item.severity, 0)), reverse=True)[:limit]


def policy_summary(status: str, gate_status: str | None, issue_findings: list[Finding], gate_findings: list[Finding], tool_status: str) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    if status == 'not_configured':
        warnings.append('SonarQube is installed but not active for this scan, or its environment variables are missing.')
    if gate_status in {'ERROR', 'FAILED'}:
        blockers.append('SonarQube quality gate failed.')
    if gate_findings:
        blockers.append(f'{len(gate_findings)} failing SonarQube quality gate condition(s) were ingested as findings.')
    high_issues = [finding for finding in issue_findings if finding.severity in {'CRITICAL', 'HIGH'}]
    if high_issues:
        warnings.append(f'{len(high_issues)} high-severity SonarQube issue(s) need triage.')
    if 'issue_fetch_failed' in (tool_status or ''):
        warnings.append('The scanner ran, but SonarQube issue retrieval failed.')
    if 'quality_gate_fetch_failed' in (tool_status or ''):
        warnings.append('The scanner ran, but SonarQube quality gate retrieval failed.')
    return {
        'pass': not blockers and status in {'passed', 'warning'},
        'blockers': blockers,
        'warnings': warnings,
        'recommended_action': recommended_action(blockers, warnings, status),
    }


def recommended_action(blockers: list[str], warnings: list[str], status: str) -> str:
    if status == 'not_configured':
        return 'Configure SonarQube credentials and rerun the scan to collect quality gate evidence.'
    if blockers:
        return 'Block promotion until the SonarQube quality gate and failing conditions are resolved or formally waived.'
    if warnings:
        return 'Review SonarQube issues before merge and keep the quality gate visible in release evidence.'
    if status == 'passed':
        return 'Quality gate passed. Keep this report with the scan evidence.'
    return 'Check the SonarQube adapter status and rerun the scan when the server is reachable.'
