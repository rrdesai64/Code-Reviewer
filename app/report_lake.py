from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .models import Finding, ScanResult
from .paths import data_dir
from .quarantine import quarantine_policy_for_scan

SCHEMA_VERSION = 1
MAX_TEXT_LENGTH = 500
MAX_METADATA_VALUE_LENGTH = 300
MAX_PATH_PARTS = 5
MAX_FINDINGS_PER_REPORT = 5000

SENSITIVE_ASSIGNMENT = re.compile(
    r'(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|authorization)\b'
    r'\s*[:=]\s*(".*?"|\'.*?\'|[^\s,;]+)'
)
BEARER_TOKEN = re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}')
AWS_ACCESS_KEY = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
GITHUB_TOKEN = re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{20,}\b')
SLACK_TOKEN = re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b')
PRIVATE_KEY_BLOCK = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', re.DOTALL)
URL_CREDENTIALS = re.compile(r'(?i)\b(https?://)([^/\s:@]+):([^@\s]+)@')
CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

DROP_METADATA_KEY_PARTS = (
    'snippet',
    'line_text',
    'matched_text',
    'secret_value',
    'source_code',
    'patch',
    'diff',
)
DROP_METADATA_EXACT = {'raw', 'raw_json', 'raw_payload', 'body', 'request_body', 'response_body'}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def report_lake_dir() -> Path:
    return data_dir() / 'report-lake'


def report_lake_scans_dir() -> Path:
    return report_lake_dir() / 'scans'


def ensure_report_lake() -> None:
    report_lake_scans_dir().mkdir(parents=True, exist_ok=True)


def sanitized_scan_report(scan: ScanResult) -> dict[str, Any]:
    from .consolidation import ensure_consolidated_scan

    scan = ensure_consolidated_scan(scan)
    policy = quarantine_policy_for_scan(scan)
    learning_allowed = bool(policy.get('controls', {}).get('agent_learning', True))
    findings = [sanitize_finding(finding, learning_allowed=learning_allowed) for finding in scan.findings[:MAX_FINDINGS_PER_REPORT]]
    consolidated = [sanitize_consolidated_finding(item) for item in scan.consolidated_findings[:MAX_FINDINGS_PER_REPORT]]
    target_hint = sanitize_path(scan.target_path, max_parts=3)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'lake_record_type': 'sanitized-scan-report',
        'source_scan': {
            'scan_id': sanitize_identifier(scan.scan_id),
            'project_name': sanitize_text(scan.project_name, max_length=160),
            'created_at': scan.created_at.isoformat(),
            'target': {
                'repo_name': repository_name(scan),
                'target_path_hash': stable_hash(scan.target_path),
                'target_path_hint': target_hint,
                'full_path_stored': False,
            },
        },
        'summary': sanitize_summary(scan),
        'quarantine': sanitize_quarantine_policy(policy),
        'learning_eligibility': learning_eligibility(policy),
        'findings': findings,
        'consolidated_findings': consolidated,
        'suppressions': [sanitize_suppression_record(record) for record in scan.suppressions],
        'invalid_suppressions': [sanitize_invalid_suppression(record) for record in scan.invalid_suppressions],
        'finding_count': len(scan.findings),
        'stored_finding_count': len(findings),
        'consolidated_finding_count': len(scan.consolidated_findings),
        'stored_consolidated_finding_count': len(consolidated),
        'truncated_findings': max(0, len(scan.findings) - len(findings)),
        'lineage': {
            'source': 'saved-scan-result',
            'raw_repository_read': False,
            'raw_report_file_read': False,
            'raw_code_included': False,
            'patches_included': False,
            'full_local_paths_included': False,
            'secret_redaction': 'pattern-based',
        },
        'guardrails': [
            'No raw source code, patches, or full local target paths are stored in this lake record.',
            'Secret-like strings are redacted before report-lake persistence.',
            'Quarantine controls are preserved so Hermes/RAG consumers can deny unsafe learning by policy.',
            'Scanner/rule improvements remain human-approved and benchmark-tested before promotion.',
        ],
    }


def save_sanitized_scan(scan: ScanResult) -> dict[str, Any]:
    ensure_report_lake()
    report = sanitized_scan_report(scan)
    path = report_lake_scans_dir() / f'{safe_scan_filename(scan.scan_id)}.json'
    report['storage'] = {
        'lake_path': str(path),
        'lake_path_hash': stable_hash(str(path)),
        'path_discloses_repository': False,
    }
    path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


def load_sanitized_scan(scan_id: str) -> dict[str, Any]:
    path = report_lake_scans_dir() / f'{safe_scan_filename(scan_id)}.json'
    if not path.exists():
        raise FileNotFoundError(scan_id)
    return json.loads(path.read_text(encoding='utf-8'))


def list_sanitized_scans(limit: int = 100) -> list[dict[str, Any]]:
    ensure_report_lake()
    max_records = max(0, limit)
    if max_records == 0:
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(report_lake_scans_dir().glob('*.json'), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            payload = json.loads(path.read_text(encoding='utf-8'))
            records.append(report_lake_index_record(payload, path))
        except (OSError, json.JSONDecodeError) as exc:
            records.append({'scan_id': path.stem, 'status': 'unreadable', 'error': str(exc)[:200]})
        if len(records) >= max_records:
            break
    return records


def report_lake_status() -> dict[str, Any]:
    ensure_report_lake()
    files = list(report_lake_scans_dir().glob('*.json'))
    total_bytes = sum(path.stat().st_size for path in files if path.exists())
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'lake_dir': str(report_lake_dir()),
        'scan_record_count': len(files),
        'total_bytes': total_bytes,
        'latest_records': list_sanitized_scans(limit=10),
        'guardrails': [
            'The lake is populated from ScanResult objects, not by opening cloned repositories.',
            'Sanitized records omit raw source, patches, full local paths, and obvious secret values.',
            'Use learning_eligibility before any RAG, agent, or benchmark consumer reads a record.',
        ],
    }


def reindex_report_lake(limit: int = 100, include_quarantined: bool = True) -> dict[str, Any]:
    from .storage import list_scans

    ensure_report_lake()
    saved: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for scan in list_scans()[:max(0, limit)]:
        policy = quarantine_policy_for_scan(scan)
        if policy.get('matched') and not include_quarantined:
            skipped.append({'scan_id': scan.scan_id, 'project_name': scan.project_name, 'reason': 'quarantined'})
            continue
        report = save_sanitized_scan(scan)
        saved.append(report_lake_index_record(report, report_lake_scans_dir() / f'{safe_scan_filename(scan.scan_id)}.json'))
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'completed',
        'indexed': len(saved),
        'skipped': skipped,
        'records': saved,
        'include_quarantined': include_quarantined,
    }


def report_lake_index_record(report: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    source = report.get('source_scan', {})
    summary = report.get('summary', {})
    record = {
        'scan_id': source.get('scan_id'),
        'project_name': source.get('project_name'),
        'created_at': source.get('created_at'),
        'generated_at': report.get('generated_at'),
        'target': source.get('target', {}),
        'summary': {
            'total_findings': summary.get('total_findings', 0),
            'files_scanned': summary.get('files_scanned', 0),
            'languages': summary.get('languages', {}),
            'risk_tiers': summary.get('risk_tiers', {}),
            'priorities': summary.get('priorities', {}),
            'consolidated_findings': summary.get('consolidated_findings', 0),
            'cross_tool_clusters': summary.get('cross_tool_clusters', 0),
            'consolidated_priorities': summary.get('consolidated_priorities', {}),
            'top_consolidated_priority_score': summary.get('top_consolidated_priority_score', 0),
            'finding_priority_counts': summary.get('finding_priority_counts', {}),
            'top_finding_priority_score': summary.get('top_finding_priority_score', 0),
            'suppressed_findings': summary.get('suppressed_findings', 0),
            'invalid_suppression_annotations': summary.get('invalid_suppression_annotations', 0),
            'scope_counts': summary.get('scope_counts', {}),
        },
        'quarantine': report.get('quarantine', {}),
        'learning_eligibility': report.get('learning_eligibility', {}),
        'finding_count': report.get('finding_count', 0),
        'stored_finding_count': report.get('stored_finding_count', 0),
    }
    if path:
        record['lake_path'] = str(path)
        record['lake_path_hash'] = stable_hash(str(path))
    return record


def sanitize_summary(scan: ScanResult) -> dict[str, Any]:
    summary = scan.summary
    return {
        'total_findings': safe_int(summary.total_findings),
        'critical': safe_int(summary.critical),
        'high': safe_int(summary.high),
        'medium': safe_int(summary.medium),
        'low': safe_int(summary.low),
        'info': safe_int(summary.info),
        'files_scanned': safe_int(summary.files_scanned),
        'languages': sanitize_count_map(summary.languages),
        'tools': {sanitize_text(key, max_length=80): sanitize_text(value, max_length=180) for key, value in summary.tools.items()},
        'max_risk_score': safe_int(summary.max_risk_score),
        'avg_risk_score': float(summary.avg_risk_score or 0),
        'risk_tiers': sanitize_count_map(summary.risk_tiers),
        'priorities': sanitize_count_map(summary.priorities),
        'scope_counts': sanitize_count_map(summary.scope_counts),
        'production_findings': safe_int(summary.production_findings),
        'hygiene_findings': safe_int(summary.hygiene_findings),
        'all_max_risk_score': safe_int(summary.all_max_risk_score),
        'all_avg_risk_score': float(summary.all_avg_risk_score or 0),
        'all_risk_tiers': sanitize_count_map(summary.all_risk_tiers),
        'all_priorities': sanitize_count_map(summary.all_priorities),
        'consolidated_findings': safe_int(summary.consolidated_findings),
        'cross_tool_clusters': safe_int(summary.cross_tool_clusters),
        'consolidated_priorities': sanitize_count_map(summary.consolidated_priorities),
        'top_consolidated_priority_score': safe_int(summary.top_consolidated_priority_score),
        'finding_priority_counts': sanitize_count_map(summary.finding_priority_counts),
        'top_finding_priority_score': float(summary.top_finding_priority_score or 0),
        'active_prioritized_findings': safe_int(summary.active_prioritized_findings),
        'suppressed_prioritized_findings': safe_int(summary.suppressed_prioritized_findings),
        'suppressed_findings': safe_int(summary.suppressed_findings),
        'invalid_suppression_annotations': safe_int(summary.invalid_suppression_annotations),
        'reachability_counts': sanitize_count_map(summary.reachability_counts),
        'exploitability_counts': sanitize_count_map(summary.exploitability_counts),
        'changed_file_findings': safe_int(summary.changed_file_findings),
        'request_handler_findings': safe_int(summary.request_handler_findings),
        'new_finding_count': len(scan.new_findings),
        'resolved_finding_count': len(scan.resolved_findings),
        'unchanged_finding_count': len(scan.unchanged_findings),
    }


def sanitize_suppression_record(record: Any) -> dict[str, Any]:
    return {
        'finding_id': sanitize_identifier(record.finding_id),
        'fingerprint': sanitize_identifier(record.fingerprint),
        'rule_id': sanitize_text(record.rule_id, max_length=160),
        'source': sanitize_text(record.source, max_length=80),
        'path': sanitize_path(record.path),
        'line': safe_int(record.line),
        'annotation_line': safe_int(record.annotation_line),
        'reason': sanitize_text(record.reason, max_length=300),
        'matched_rule': sanitize_text(record.matched_rule, max_length=160),
        'scope': record.scope,
        'raw_code_included': False,
    }


def sanitize_invalid_suppression(record: Any) -> dict[str, Any]:
    return {
        'path': sanitize_path(record.path),
        'line': safe_int(record.line),
        'reason': sanitize_text(record.reason, max_length=220),
        'raw_code_included': False,
    }


def sanitize_consolidated_finding(item: Any) -> dict[str, Any]:
    return {
        'cluster_id': sanitize_identifier(item.cluster_id),
        'title': sanitize_text(item.title, max_length=220),
        'location': {
            'path': sanitize_path(item.path),
            'line_start': safe_int(item.line_start),
            'line_end': safe_int(item.line_end),
            'full_path_stored': False,
        },
        'semantic_key': sanitize_text(item.semantic_key, max_length=120),
        'cwe': [sanitize_text(value, max_length=40) for value in item.cwe],
        'sink': sanitize_text(item.sink, max_length=80),
        'severity': item.severity,
        'confidence': sanitize_text(item.confidence, max_length=40),
        'priority_score': safe_int(item.priority_score),
        'priority': item.priority,
        'risk_tier': item.risk_tier,
        'recommended_action': sanitize_text(item.recommended_action, max_length=220),
        'agreement_count': safe_int(item.agreement_count),
        'tool_agreement_score': safe_int(item.tool_agreement_score),
        'raw_count': safe_int(item.raw_count),
        'sources': [sanitize_text(value, max_length=80) for value in item.sources],
        'rules': [sanitize_text(value, max_length=160) for value in item.rules],
        'finding_ids': [sanitize_identifier(value) for value in item.finding_ids],
        'representative_finding_id': sanitize_identifier(item.representative_finding_id),
        'factors': [
            {
                'name': sanitize_text(factor.name, max_length=80),
                'label': sanitize_text(factor.label, max_length=120),
                'points': safe_int(factor.points),
                'detail': sanitize_text(factor.detail, max_length=220),
            }
            for factor in item.factors
        ],
        'evidence': [
            {
                'finding_id': sanitize_identifier(evidence.finding_id),
                'source': sanitize_text(evidence.source, max_length=80),
                'rule_id': sanitize_text(evidence.rule_id, max_length=160),
                'severity': evidence.severity,
                'confidence': sanitize_text(evidence.confidence, max_length=40),
                'path': sanitize_path(evidence.path),
                'line': safe_int(evidence.line),
                'cwe': [sanitize_text(value, max_length=40) for value in evidence.cwe],
                'sink': sanitize_text(evidence.sink, max_length=80),
                'message': sanitize_text(evidence.message, max_length=220),
                'decision': evidence.decision,
            }
            for evidence in item.evidence[:25]
        ],
    }


def sanitize_finding(finding: Finding, learning_allowed: bool) -> dict[str, Any]:
    risk = finding.risk.model_dump(mode='json')
    risk['recommended_action'] = sanitize_text(str(risk.get('recommended_action') or ''), max_length=220)
    risk['factors'] = [
        {
            'name': sanitize_text(item.get('name'), max_length=80),
            'label': sanitize_text(item.get('label'), max_length=120),
            'points': safe_int(item.get('points')),
            'detail': sanitize_text(item.get('detail'), max_length=220),
        }
        for item in risk.get('factors', [])
    ]
    metadata, dropped = sanitize_metadata(finding.scanner_metadata)
    message = sanitize_text(finding.message)
    explanation = sanitize_text(finding.explanation)
    return {
        'id': sanitize_identifier(finding.id),
        'source': sanitize_text(finding.source, max_length=80),
        'rule_id': sanitize_text(finding.rule_id, max_length=160),
        'title': sanitize_text(finding.title, max_length=220),
        'severity': finding.severity,
        'confidence': sanitize_text(finding.confidence, max_length=40),
        'location': {
            'path': sanitize_path(finding.location.path),
            'line': safe_int(finding.location.line),
            'column': safe_int(finding.location.column),
            'end_line': safe_int(finding.location.end_line) if finding.location.end_line else None,
            'full_path_stored': False,
        },
        'message': message,
        'message_hash': stable_hash(finding.message),
        'explanation': explanation,
        'explanation_hash': stable_hash(finding.explanation),
        'cwe': [sanitize_text(item, max_length=40) for item in finding.cwe],
        'owasp': [sanitize_text(item, max_length=80) for item in finding.owasp],
        'references': [sanitize_reference(item) for item in finding.references[:20]],
        'fingerprint': sanitize_identifier(finding.fingerprint),
        'scanner_metadata': metadata,
        'dropped_metadata_keys': dropped,
        'exploitability': sanitize_text(finding.exploitability, max_length=80),
        'reachability': sanitize_text(finding.reachability, max_length=80),
        'dataflow': sanitize_dataflow(finding),
        'priority_context': sanitize_priority_context(finding),
        'priority': sanitize_finding_priority(finding),
        'cluster_id': sanitize_identifier(finding.cluster_id) if finding.cluster_id else '',
        'policy_impact': [sanitize_text(item, max_length=160) for item in finding.policy_impact],
        'remediation': [sanitize_text(item, max_length=220) for item in finding.remediation],
        'scope': finding.scope,
        'risk': risk,
        'decision': {
            'state': finding.decision,
            'reason': sanitize_text(finding.decision_reason, max_length=300) if finding.decision_reason else None,
        },
        'fix': {
            'summary': sanitize_text(finding.fix.summary, max_length=220),
            'guidance': [sanitize_text(item, max_length=220) for item in finding.fix.guidance],
            'patch_included': False,
        },
        'learning_labels': {
            'pattern_learning_allowed': learning_allowed,
            'raw_code_available': False,
            'requires_human_review_before_training': True,
        },
    }


def sanitize_dataflow(finding: Finding) -> dict[str, Any]:
    dataflow = finding.dataflow
    return {
        'has_dataflow': bool(dataflow.has_dataflow),
        'source': sanitize_location(dataflow.source),
        'sink': sanitize_location(dataflow.sink),
        'steps': safe_int(dataflow.steps) if dataflow.steps is not None else None,
        'tool_precision': sanitize_text(dataflow.tool_precision, max_length=40) if dataflow.tool_precision else None,
    }


def sanitize_priority_context(finding: Finding) -> dict[str, Any]:
    context = finding.priority_context
    return {
        'path_class': context.path_class,
        'in_pr_diff': context.in_pr_diff,
        'last_modified_days': safe_int(context.last_modified_days) if context.last_modified_days is not None else None,
        'execution': context.execution,
        'execution_source': sanitize_text(context.execution_source, max_length=80) if context.execution_source else None,
        'execution_hits': safe_int(context.execution_hits) if context.execution_hits is not None else None,
        'corroborating_tools': [sanitize_text(item, max_length=80) for item in context.corroborating_tools],
    }


def sanitize_finding_priority(finding: Finding) -> dict[str, Any] | None:
    priority = finding.priority
    if not priority:
        return None
    return {
        'tier': priority.tier,
        'score': float(priority.score or 0),
        'factors': [
            {
                'name': sanitize_text(factor.name, max_length=80),
                'delta': float(factor.delta),
                'reason': sanitize_text(factor.reason, max_length=220),
            }
            for factor in priority.factors
        ],
    }


def sanitize_location(location: Any) -> dict[str, Any] | None:
    if not location:
        return None
    return {
        'path': sanitize_path(location.path),
        'line': safe_int(location.line),
        'column': safe_int(location.column),
        'end_line': safe_int(location.end_line) if location.end_line else None,
        'full_path_stored': False,
    }


def sanitize_quarantine_policy(policy: dict[str, Any]) -> dict[str, Any]:
    entry = policy.get('entry') or {}
    return {
        'matched': bool(policy.get('matched')),
        'status': sanitize_text(policy.get('status'), max_length=40),
        'severity': sanitize_text(policy.get('severity'), max_length=40),
        'controls': {sanitize_text(key, max_length=80): bool(value) for key, value in (policy.get('controls') or {}).items()},
        'entry_key': sanitize_text(entry.get('key'), max_length=160) if entry else None,
        'tags': [sanitize_text(item, max_length=80) for item in entry.get('tags', [])] if entry else [],
        'reason': sanitize_text(entry.get('reason'), max_length=300) if entry else None,
    }


def learning_eligibility(policy: dict[str, Any]) -> dict[str, Any]:
    controls = policy.get('controls') or {}
    agent_allowed = bool(controls.get('agent_learning', True))
    clear = not bool(policy.get('matched')) and str(policy.get('status') or 'clear') == 'clear'
    return {
        'agent_learning_allowed': agent_allowed,
        'rag_ingest_allowed': agent_allowed and clear,
        'fine_tuning_allowed': False,
        'prompt_ready': agent_allowed and clear,
        'requires_human_review': True,
        'requires_benchmark_gate': True,
        'blocked_reason': '' if agent_allowed and clear else 'quarantine or watch policy denies autonomous learning',
    }


def sanitize_metadata(metadata: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    sanitized: dict[str, str] = {}
    dropped: list[str] = []
    for key, value in sorted((metadata or {}).items()):
        safe_key = sanitize_text(key, max_length=120)
        normalized_key = safe_key.lower()
        if normalized_key in DROP_METADATA_EXACT or any(part in normalized_key for part in DROP_METADATA_KEY_PARTS):
            dropped.append(safe_key)
            continue
        sanitized[safe_key] = sanitize_text(value, max_length=MAX_METADATA_VALUE_LENGTH)
    return sanitized, dropped


def sanitize_text(value: Any, max_length: int = MAX_TEXT_LENGTH) -> str:
    text = '' if value is None else str(value)
    text = CONTROL_CHARS.sub(' ', text)
    text = PRIVATE_KEY_BLOCK.sub('[REDACTED_PRIVATE_KEY]', text)
    text = URL_CREDENTIALS.sub(r'\1[REDACTED]@', text)
    text = BEARER_TOKEN.sub('Bearer [REDACTED]', text)
    text = AWS_ACCESS_KEY.sub('AKIA[REDACTED]', text)
    text = GITHUB_TOKEN.sub('[REDACTED_GITHUB_TOKEN]', text)
    text = SLACK_TOKEN.sub('[REDACTED_SLACK_TOKEN]', text)
    text = SENSITIVE_ASSIGNMENT.sub(lambda match: f'{match.group(1)}=[REDACTED]', text)
    text = re.sub(r'\s+', ' ', text).strip()
    if max_length and len(text) > max_length:
        return f'{text[: max_length - 14].rstrip()}...[truncated]'
    return text


def sanitize_path(value: Any, max_parts: int = MAX_PATH_PARTS) -> str:
    text = sanitize_text(value, max_length=600).replace('\\', '/')
    text = re.sub(r'^[A-Za-z]:/+', '', text)
    text = text.lstrip('/')
    parts = [part for part in text.split('/') if part and part not in {'.', '..'}]
    if len(parts) > max_parts:
        parts = parts[-max_parts:]
    return '/'.join(parts)


def sanitize_reference(value: Any) -> str:
    text = sanitize_text(value, max_length=300)
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    if parsed.username or parsed.password:
        netloc = parsed.hostname or ''
        if parsed.port:
            netloc = f'{netloc}:{parsed.port}'
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    return text


def sanitize_identifier(value: Any) -> str:
    text = sanitize_text(value, max_length=200)
    return re.sub(r'[^A-Za-z0-9_.:-]+', '-', text).strip('-') or 'unknown'


def repository_name(scan: ScanResult) -> str:
    name = sanitize_path(scan.project_name or Path(str(scan.target_path)).name, max_parts=1)
    if not name:
        name = sanitize_path(scan.target_path, max_parts=1)
    return re.sub(r'[^A-Za-z0-9_.-]+', '-', name).strip('-._')[:120] or 'repository'


def sanitize_count_map(values: dict[str, int]) -> dict[str, int]:
    return {sanitize_text(key, max_length=80): safe_int(value) for key, value in sorted((values or {}).items())}


def safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def stable_hash(value: Any) -> str:
    normalized = str(value or '').replace('\\', '/').strip().lower()
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def safe_scan_filename(scan_id: str) -> str:
    return sanitize_identifier(scan_id).replace(':', '-')[:160]
