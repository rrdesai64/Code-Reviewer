from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

PYTHON_AGENT_ID = 'hermes-python-security-specialist'
PYTHON_AGENT_VERSION = '1.0.0'

PYTHON_SOURCES = {'bandit', 'python-ast', 'pip-audit'}
PYTHON_TOOL_NAMES = {'bandit', 'python-ast', 'pip-audit', 'semgrep', 'codeql', 'sonarqube'}
PYTHON_FILE_MARKERS = (
    '.py',
    'requirements.txt',
    'requirements-dev.txt',
    'pyproject.toml',
    'poetry.lock',
    'pipfile',
    'pipfile.lock',
    'setup.py',
    'setup.cfg',
)
PYTHON_TEXT_MARKERS = (
    'python',
    'pip-audit',
    'bandit',
    'python-ast',
    'requirements',
    'pyproject',
    'poetry',
    'pipfile',
    'django',
    'flask',
    'fastapi',
    'pickle',
    'yaml.load',
    'subprocess',
)
SCANNER_GAP_WORDS = ('error', 'failed', 'not installed', 'disabled', 'missing', 'skipped', 'unavailable')


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def python_agent_registry_entry() -> dict[str, Any]:
    return {
        'agent_id': PYTHON_AGENT_ID,
        'name': 'Hermes Python Security Specialist',
        'version': PYTHON_AGENT_VERSION,
        'enabled': True,
        'deterministic': True,
        'capabilities': [
            'python-security-review',
            'python-dependency-review',
            'python-scanner-coverage',
            'python-remediation-routing',
            'python-framework-risk',
        ],
        'item_types': ['scan-summary', 'finding-pattern', 'rule-pattern', 'dependency-signal', 'scanner-status'],
        'languages': ['python'],
        'safety_level': 'sanitized-memory-only',
        'framework_alignment': {
            'upstream': 'NousResearch/hermes-agent',
            'integration_mode': 'native-compatible-agent',
            'dependency_policy': 'no new runtime packages',
            'security_model': 'OS isolation is the real boundary; this agent is an in-process governance layer.',
        },
    }


def is_python_memory_item(item: dict[str, Any]) -> bool:
    tags = {str(tag).lower() for tag in item.get('tags', [])}
    metadata = {str(key).lower(): str(value).lower() for key, value in (item.get('metadata') or {}).items()}
    text = ' '.join(
        [
            str(item.get('title') or ''),
            str(item.get('text') or ''),
            ' '.join(str(tag) for tag in item.get('tags', [])),
            ' '.join(metadata.values()),
            str(item.get('source', {}).get('project_name') or ''),
        ]
    ).lower()
    if 'python' in tags:
        return True
    if metadata.get('source') in PYTHON_SOURCES:
        return True
    if any(source in text for source in PYTHON_SOURCES):
        return True
    if any(marker in text for marker in PYTHON_FILE_MARKERS):
        return True
    return any(marker in text for marker in PYTHON_TEXT_MARKERS)


def python_task_types_for_item(item: dict[str, Any], goal: str) -> list[tuple[str, str]]:
    if not is_python_memory_item(item):
        return []
    item_type = item.get('item_type')
    tags = {str(tag).upper() for tag in item.get('tags', [])}
    metadata = item.get('metadata') or {}
    tasks: list[tuple[str, str]] = []
    if item_type in {'finding-pattern', 'rule-pattern'}:
        tasks.append(('python-specialist-review', 'Python-specific security pattern needs language-aware triage.'))
        tasks.append(('python-remediation-routing', 'Python remediation should preserve runtime behavior and validation evidence.'))
    if item_type == 'dependency-signal' or 'DEPENDENCY' in tags or metadata.get('source') == 'pip-audit':
        tasks.append(('python-dependency-review', 'Python package or dependency signal needs supply-chain review.'))
    if item_type == 'scanner-status':
        tasks.append(('python-scanner-coverage-review', 'Python scanner status should be checked for Bandit, pip-audit, AST, Semgrep, and CodeQL coverage.'))
    if goal == 'supply-chain-review':
        return [task for task in tasks if task[0] == 'python-dependency-review'] or tasks[:1]
    if goal == 'scanner-improvement-planning':
        return [task for task in tasks if task[0] == 'python-scanner-coverage-review'] or tasks[:1]
    if goal == 'release-readiness':
        return [task for task in tasks if task[0] in {'python-specialist-review', 'python-dependency-review', 'python-scanner-coverage-review'}] or tasks[:1]
    return tasks


def python_agent_matches_task(task: dict[str, Any]) -> bool:
    return task.get('task_type') in {
        'python-specialist-review',
        'python-remediation-routing',
        'python-dependency-review',
        'python-scanner-coverage-review',
    }


def run_python_specialist(agent: dict[str, Any], task: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    signals = python_signals(item)
    findings = []
    recommendations = []
    status = 'record-only'

    if task.get('task_type') == 'python-scanner-coverage-review':
        gaps = python_scanner_gaps(item)
        if gaps:
            status = 'coverage-gap'
            findings.extend(gaps)
            recommendations.extend([
                'Confirm Bandit, pip-audit, python-ast, Semgrep, and CodeQL Python coverage before treating the scan as complete.',
                'Keep scanner changes as benchmarked proposals; do not change rules or suppressions automatically.',
            ])
        else:
            findings.append('No Python scanner coverage gap was visible in sanitized memory.')
            recommendations.append('Keep Python scanner coverage evidence attached to the scan record.')
    elif task.get('task_type') == 'python-dependency-review':
        status = dependency_status(item, signals)
        findings.extend(signals['dependency_findings'] or ['Python dependency signal requires package/version review.'])
        recommendations.extend([
            'Confirm fixed versions, lockfile impact, and runtime reachability before closure.',
            'Run pip-audit and dependency review again after package changes.',
            'Avoid broad version ranges for security fixes; prefer reviewed pins or bounded ranges with a lockfile.',
        ])
    elif task.get('task_type') == 'python-remediation-routing':
        status = 'human-approval-required' if signals['high_risk'] else 'manual-remediation'
        findings.extend(signals['risk_findings'] or ['Python remediation should be prepared as review-only guidance.'])
        recommendations.extend(python_validation_steps(signals))
    else:
        status = python_review_status(signals)
        findings.extend(signals['risk_findings'] or ['No Python-specific blocker detected from sanitized memory.'])
        recommendations.extend(python_validation_steps(signals))

    active_lessons: list[dict[str, Any]] = []

    return {
        'result_id': stable_id(agent['agent_id'], task['task_id'], status),
        'agent_id': agent['agent_id'],
        'agent_name': agent['name'],
        'agent_version': agent['version'],
        'task_id': task['task_id'],
        'task_type': task['task_type'],
        'item_id': item.get('item_id'),
        'item_type': item.get('item_type'),
        'status': status,
        'confidence': confidence_for_status(status),
        'findings': dedupe(findings),
        'recommendations': dedupe(recommendations),
        'evidence_refs': {
            'scan_id': item.get('source', {}).get('scan_id'),
            'project_name': item.get('source', {}).get('project_name'),
            'memory_item_id': item.get('item_id'),
            'language': 'python',
            'tags': item.get('tags', [])[:20],
        },
        'python_review': {
            'categories': sorted(signals['categories']),
            'scanner_gaps': signals['scanner_gaps'],
            'dependency_findings': signals['dependency_findings'],
            'validation_commands': python_validation_commands(signals),
            'active_teacher_lessons': active_lessons,
            'teacher_student_learning_enabled': False,
            'requires_human_approval': True,
            'requires_benchmark_gate': signals['scanner_tuning_candidate'],
        },
        'side_effects': [],
        'safety': {
            'raw_code_accessed': False,
            'repository_executed': False,
            'external_calls_made': False,
            'files_modified': False,
            'dependency_installed': False,
        },
        'generated_at': now_iso(),
    }


def python_signals(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get('metadata') or {}
    tags = {str(tag).upper() for tag in item.get('tags', [])}
    text = normalized_text(item)
    categories: set[str] = set()
    findings: list[str] = []
    dependency_findings: list[str] = []

    risk_score = safe_int(metadata.get('risk_score') or metadata.get('max_risk_score') or 0)
    priority = str(metadata.get('priority') or best_tag(tags, ['P0', 'P1', 'P2', 'P3', 'P4']))
    severity = str(metadata.get('severity') or best_tag(tags, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']))

    if any(token in text for token in ['eval', 'exec(', 'subprocess', 'shell=true', 'os.system', 'command injection', 'cwe-78']):
        categories.add('dangerous-execution')
        findings.append('Python dangerous execution or command-injection pattern appears in sanitized evidence.')
    if any(token in text for token in ['pickle', 'yaml.load', 'marshal.loads', 'deserialization', 'cwe-502']):
        categories.add('unsafe-deserialization')
        findings.append('Python unsafe deserialization pattern appears in sanitized evidence.')
    if any(token in text for token in ['sql injection', 'raw sql', 'format string', 'cwe-89']):
        categories.add('sql-injection')
        findings.append('Python SQL injection or query-construction risk appears in sanitized evidence.')
    if any(token in text for token in ['path traversal', '../', 'cwe-22']):
        categories.add('path-traversal')
        findings.append('Python path traversal risk appears in sanitized evidence.')
    if any(token in text for token in ['verify=false', 'disable tls', 'insecure transport', 'cwe-295']):
        categories.add('tls-disabled')
        findings.append('Python TLS verification or transport hardening issue appears in sanitized evidence.')
    if any(token in text for token in ['secret', 'password', 'token', 'private key', 'api_key', 'cwe-798']):
        categories.add('secret-handling')
        findings.append('Python secret-handling risk appears in sanitized evidence.')
    if any(token in text for token in ['debug=true', 'flask debug', 'django debug', 'cwe-489']):
        categories.add('debug-mode')
        findings.append('Python debug-mode risk appears in sanitized evidence.')
    if any(token in text for token in ['pip-audit', 'dependency', 'package', 'requirements', 'pyproject', 'poetry', 'cve-', 'vulnerable range']):
        categories.add('dependency-risk')
        package = metadata.get('package') or metadata.get('dependency_name') or metadata.get('rule_id') or 'unknown package'
        dependency_findings.append(f'Python dependency/package signal for {package}.')
    if any(token in text for token in ['unpinned', 'wildcard', 'malicious locking range', 'dependency confusion', 'typosquat']):
        categories.add('dependency-hygiene')
        dependency_findings.append('Python dependency hygiene or locking-range concern appears in sanitized evidence.')

    scanner_gaps = python_scanner_gaps(item)
    if scanner_gaps:
        categories.add('scanner-coverage')
        findings.extend(scanner_gaps)

    high_risk = priority in {'P0', 'P1'} or severity in {'CRITICAL', 'HIGH'} or risk_score >= 70
    return {
        'categories': categories,
        'risk_findings': findings,
        'dependency_findings': dependency_findings,
        'scanner_gaps': scanner_gaps,
        'risk_score': risk_score,
        'priority': priority,
        'severity': severity,
        'high_risk': high_risk,
        'scanner_tuning_candidate': bool(scanner_gaps or 'scanner-coverage' in categories),
    }


def python_scanner_gaps(item: dict[str, Any]) -> list[str]:
    metadata = item.get('metadata') or {}
    text = normalized_text(item)
    gaps: list[str] = []
    for key, value in metadata.items():
        key_text = str(key).lower()
        value_text = str(value).lower()
        if key_text in PYTHON_TOOL_NAMES or any(tool in key_text for tool in PYTHON_TOOL_NAMES):
            if any(word in value_text for word in SCANNER_GAP_WORDS):
                gaps.append(f'Python scanner coverage gap: {key}={value}')
    if item.get('item_type') == 'scanner-status':
        for tool in ['bandit', 'pip-audit', 'python-ast']:
            if tool not in text:
                gaps.append(f'Python scanner status does not mention {tool}.')
    return dedupe(gaps)


def python_review_status(signals: dict[str, Any]) -> str:
    categories = signals['categories']
    if signals['scanner_gaps']:
        return 'coverage-gap'
    if categories & {'dangerous-execution', 'sql-injection'} and signals['high_risk']:
        return 'release-blocker'
    if categories & {'dependency-risk', 'dependency-hygiene'} and signals['high_risk']:
        return 'critical-dependency-risk'
    if categories:
        return 'review-required'
    return 'record-only'


def dependency_status(item: dict[str, Any], signals: dict[str, Any]) -> str:
    if signals['high_risk'] or 'dependency-risk' in signals['categories']:
        return 'critical-dependency-risk'
    return 'review-required'


def python_validation_steps(signals: dict[str, Any]) -> list[str]:
    steps = [
        'Use disposable worktrees or VM workers for untrusted repositories.',
        'Keep generated remediation as review-only until a human approves it.',
    ]
    if signals['categories'] & {'dangerous-execution', 'sql-injection', 'unsafe-deserialization', 'path-traversal'}:
        steps.append('Add focused Python regression tests for the affected source-to-sink behavior.')
    if signals['categories'] & {'dependency-risk', 'dependency-hygiene'}:
        steps.append('Re-run pip-audit and dependency review after package or lockfile changes.')
    if signals['scanner_gaps']:
        steps.append('Fix scanner availability first, then rerun the scan before accepting coverage.')
    steps.extend(f'Validation command: {command}' for command in python_validation_commands(signals))
    return steps


def python_validation_commands(signals: dict[str, Any]) -> list[str]:
    commands = ['python -m compileall .']
    if signals['categories'] & {'dependency-risk', 'dependency-hygiene'}:
        commands.append('pip-audit')
    if signals['categories'] - {'dependency-risk', 'dependency-hygiene'} or signals['scanner_gaps']:
        commands.append('bandit -r .')
    commands.append('pytest')
    return dedupe(commands)


def active_teacher_lessons_for_item(item: dict[str, Any], signals: dict[str, Any]) -> list[dict[str, Any]]:
    return []


def lesson_recommendations(lessons: list[dict[str, Any]]) -> list[str]:
    return []


def public_teacher_lesson(lesson: dict[str, Any]) -> dict[str, Any]:
    return {
        'lesson_id': lesson.get('lesson_id'),
        'title': lesson.get('title'),
        'category': lesson.get('category'),
        'source': lesson.get('source'),
        'rule_id': lesson.get('rule_id'),
        'proposed_change': lesson.get('proposed_change'),
        'learning_influence_allowed': bool(lesson.get('learning_influence_allowed')),
    }


def dedupe_lessons(lessons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for lesson in lessons:
        key = lesson.get('lesson_id') or lesson.get('title')
        if key and key not in seen:
            seen.add(key)
            result.append(lesson)
    return result


def normalized_text(item: dict[str, Any]) -> str:
    metadata = item.get('metadata') or {}
    return ' '.join(
        [
            str(item.get('title') or ''),
            str(item.get('text') or ''),
            ' '.join(str(tag) for tag in item.get('tags', [])),
            ' '.join(f'{key}:{value}' for key, value in metadata.items()),
        ]
    ).lower()


def confidence_for_status(status: str) -> str:
    if status in {'release-blocker', 'critical-dependency-risk', 'coverage-gap'}:
        return 'high'
    if status in {'review-required', 'human-approval-required', 'manual-remediation'}:
        return 'medium'
    return 'low'


def best_tag(tags: set[str], options: list[str]) -> str:
    for option in options:
        if option in tags:
            return option
    return ''


def safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def stable_id(*parts: str) -> str:
    raw = '\n'.join(str(part or '') for part in parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]


def dedupe(values: list[str]) -> list[str]:
    seen = set()
    result: list[str] = []
    for value in values:
        text = re.sub(r'\s+', ' ', str(value or '')).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result
