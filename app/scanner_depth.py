from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Finding, ScanResult

ROOT = Path(__file__).resolve().parents[1]
SEMGREP_RULES = ROOT / 'rules' / 'semgrep-security.yml'
CODEQL_LANGUAGE_NAMES = {
    'python': 'Python',
    'javascript': 'JavaScript/TypeScript',
    'java-kotlin': 'Java/Kotlin',
    'cpp': 'C/C++',
    'csharp': 'C#',
    'go': 'Go',
    'ruby': 'Ruby',
    'swift': 'Swift',
}
LANGUAGE_TO_CODEQL = {
    'Python': 'python',
    'JavaScript': 'javascript',
    'TypeScript': 'javascript',
    'Java': 'java-kotlin',
    'Kotlin': 'java-kotlin',
    'C': 'cpp',
    'C++': 'cpp',
    'C/C++': 'cpp',
    'C#': 'csharp',
    'Go': 'go',
    'Ruby': 'ruby',
    'Swift': 'swift',
}


def scanner_depth_report(scan: ScanResult) -> dict[str, Any]:
    semgrep_findings = [finding for finding in scan.findings if finding.source == 'semgrep']
    codeql_findings = [finding for finding in scan.findings if finding.source == 'codeql']
    tools = scan.summary.tools or {}
    semgrep_status = tools.get('semgrep', 'missing')
    codeql_status = tools.get('codeql', 'missing')
    language_coverage = codeql_language_coverage(scan, codeql_status)
    gaps = coverage_gaps(semgrep_status, codeql_status, language_coverage)
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': depth_status(semgrep_status, codeql_status, gaps),
        'semgrep': {
            'tool_status': semgrep_status,
            'findings': len(semgrep_findings),
            'rule_inventory': semgrep_rule_inventory(),
            'severity_counts': severity_counts(semgrep_findings),
            'top_rules': top_rules(semgrep_findings),
        },
        'codeql': {
            'tool_status': codeql_status,
            'findings': len(codeql_findings),
            'languages': language_coverage,
            'severity_counts': severity_counts(codeql_findings),
            'top_rules': top_rules(codeql_findings),
        },
        'coverage_gaps': gaps,
        'recommended_next_steps': recommended_next_steps(semgrep_status, codeql_status, gaps),
    }


def semgrep_rule_inventory() -> dict[str, Any]:
    if not SEMGREP_RULES.exists():
        return {'rules_file': str(SEMGREP_RULES), 'rule_count': 0, 'families': {}, 'available': False}
    text = SEMGREP_RULES.read_text(encoding='utf-8', errors='ignore')
    rule_ids = re.findall(r'^\s*-\s+id:\s*([^\s]+)', text, flags=re.MULTILINE)
    families = Counter(rule_id.split('-')[0] for rule_id in rule_ids)
    return {
        'rules_file': str(SEMGREP_RULES),
        'rule_count': len(rule_ids),
        'families': dict(sorted(families.items())),
        'available': True,
    }


def codeql_language_coverage(scan: ScanResult, codeql_status: str) -> list[dict[str, Any]]:
    status_by_language = parse_codeql_status(codeql_status)
    rows: list[dict[str, Any]] = []
    for detected_language, count in sorted(scan.summary.languages.items()):
        codeql_language = LANGUAGE_TO_CODEQL.get(detected_language)
        if not codeql_language:
            continue
        rows.append({
            'detected_language': detected_language,
            'files': count,
            'codeql_language': codeql_language,
            'display_name': CODEQL_LANGUAGE_NAMES.get(codeql_language, codeql_language),
            'status': status_by_language.get(codeql_language, 'not_run'),
            'covered': status_by_language.get(codeql_language, '').startswith('ok'),
        })
    return rows


def parse_codeql_status(status: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in (status or '').split(';'):
        if '=' not in part:
            continue
        key, value = part.split('=', 1)
        result[key.strip()] = value.strip()
    return result


def coverage_gaps(semgrep_status: str, codeql_status: str, language_coverage: list[dict[str, Any]]) -> list[str]:
    gaps: list[str] = []
    lowered_semgrep = (semgrep_status or '').lower()
    lowered_codeql = (codeql_status or '').lower()
    if 'not installed' in lowered_semgrep or 'disabled' in lowered_semgrep or semgrep_status == 'missing':
        gaps.append('Semgrep is not active, so local rule coverage is missing.')
    if 'not installed' in lowered_codeql or 'disabled' in lowered_codeql or codeql_status == 'missing':
        gaps.append('CodeQL is not active, so semantic query coverage is missing.')
    for row in language_coverage:
        if not row['covered']:
            gaps.append(f"CodeQL did not complete for {row['display_name']} despite {row['files']} detected file(s): {row['status']}.")
    return gaps


def depth_status(semgrep_status: str, codeql_status: str, gaps: list[str]) -> str:
    if 'scanner failed' in (semgrep_status or '').lower() or 'failed' in (codeql_status or '').lower():
        return 'needs_attention'
    if gaps:
        return 'partial'
    return 'active'


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    return {severity: counts.get(severity, 0) for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']}


def top_rules(findings: list[Finding], limit: int = 10) -> list[dict[str, Any]]:
    counter = Counter(finding.rule_id for finding in findings)
    return [{'rule_id': rule_id, 'count': count} for rule_id, count in counter.most_common(limit)]


def recommended_next_steps(semgrep_status: str, codeql_status: str, gaps: list[str]) -> list[str]:
    steps: list[str] = []
    if 'not installed' in (semgrep_status or '').lower():
        steps.append('Install Semgrep in the project virtual environment or on PATH.')
    if 'not installed' in (codeql_status or '').lower():
        steps.append('Install CodeQL CLI or set CODEQL_EXE to the local CodeQL executable.')
    if gaps:
        steps.append('Review coverage gaps before treating this scan as complete release evidence.')
    steps.append('Use SEMGREP_CONFIGS and CODEQL_EXTRA_QUERY_SUITES to add organization-specific rules and query packs.')
    steps.append('Use CODEQL_THREADS, CODEQL_RAM, and CODEQL_TIMEOUT_SECONDS to tune large repository scans.')
    return steps