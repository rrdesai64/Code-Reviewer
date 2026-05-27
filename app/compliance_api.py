from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = 1
API_NAME = 'secure-review-compliance-api'


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compliance_api_schema() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'name': API_NAME,
        'purpose': 'Vendor-neutral compliance and security telemetry for Secure Code Review Assistant.',
        'data_products': [
            'activity-events',
            'agent-actions',
            'approval-lineage',
            'memory-version-lineage',
            'quarantine-alerts',
            'scan-inventory',
            'compliance-evidence-bundles',
        ],
        'source_contract': {
            'raw_repository_code_included': False,
            'raw_scan_report_included': False,
            'conversation_content_included': False,
            'patch_content_included': False,
            'full_local_paths_included': False,
            'sanitized_report_lake_allowed': True,
            'rag_memory_metadata_allowed': True,
            'governance_events_allowed': True,
            'legacy_audit_events_allowed': True,
        },
        'event_contract': {
            'required_fields': [
                'event_id',
                'created_at',
                'event_source',
                'event_type',
                'actor',
                'action',
                'category',
                'resource',
                'scan_id',
                'metadata',
                'evidence_refs',
                'safety',
            ],
            'safety_defaults': safety_attestation(),
        },
        'partner_categories': [
            'siem',
            'dlp',
            'data-security-posture-management',
            'ai-security-posture-management',
            'identity-governance',
            'ediscovery-and-legal-hold',
            'observability',
            'soar',
            'grc',
        ],
        'guardrails': compliance_guardrails(),
    }


def compliance_api_status() -> dict[str, Any]:
    from .benchmark_gate import benchmark_gate_status
    from .governance import governance_events
    from .quarantine import quarantine_registry_report
    from .rag_memory import rag_memory_status
    from .report_lake import report_lake_status

    governance_count = len(governance_events(limit=1000))
    benchmark = benchmark_gate_status()
    memory = rag_memory_status()
    lake = report_lake_status()
    quarantine = quarantine_registry_report()
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'ready',
        'api_name': API_NAME,
        'data_sources': {
            'governance_events': governance_count,
            'legacy_audit_events': len(compliance_legacy_audit_events(limit=1000)),
            'sanitized_report_lake_records': lake.get('scan_record_count', 0),
            'rag_memory_records': memory.get('scan_memory_record_count', 0),
            'benchmark_lessons': benchmark.get('lesson_count', 0),
            'active_learning_influences': benchmark.get('active_influence_count', 0),
            'quarantine_entries': quarantine.get('total_entries', 0),
        },
        'schema': compliance_api_schema(),
    }


def compliance_partner_manifest() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'api_name': API_NAME,
        'integration_mode': 'pull-api-and-exportable-json',
        'authentication': {
            'recommended': 'Use the existing enterprise auth boundary and scoped enterprise:read permission.',
            'write_access_required': False,
        },
        'endpoints': [
            {'method': 'GET', 'path': '/api/compliance/status', 'data_product': 'api-status'},
            {'method': 'GET', 'path': '/api/compliance/schema', 'data_product': 'schema'},
            {'method': 'GET', 'path': '/api/compliance/events', 'data_product': 'activity-events'},
            {'method': 'GET', 'path': '/api/compliance/agent-actions', 'data_product': 'agent-actions'},
            {'method': 'GET', 'path': '/api/compliance/approvals', 'data_product': 'approval-lineage'},
            {'method': 'GET', 'path': '/api/compliance/memory-lineage', 'data_product': 'memory-version-lineage'},
            {'method': 'GET', 'path': '/api/compliance/quarantine-alerts', 'data_product': 'quarantine-alerts'},
            {'method': 'GET', 'path': '/api/compliance/scans', 'data_product': 'scan-inventory'},
            {'method': 'GET', 'path': '/api/compliance/evidence', 'data_product': 'compliance-evidence-bundle'},
            {'method': 'GET', 'path': '/api/scans/{scan_id}/compliance/evidence', 'data_product': 'scan-scoped-compliance-evidence'},
        ],
        'tool_mappings': {
            'siem': ['events', 'agent-actions', 'quarantine-alerts'],
            'dlp': ['events metadata only', 'quarantine-alerts', 'scan-inventory metadata only'],
            'grc': ['evidence', 'approvals', 'memory-lineage'],
            'ai_security_posture': ['agent-actions', 'memory-lineage', 'approvals', 'scan-inventory'],
            'ediscovey': ['events metadata only', 'evidence bundles without raw code or prompts'],
        },
        'not_supported': [
            'Raw repository source export.',
            'Raw scanner report export.',
            'Prompt/response transcript export.',
            'Patch export.',
            'Direct scanner rule mutation by partner tools.',
        ],
        'guardrails': compliance_guardrails(),
    }


def compliance_activity_events(
    *,
    limit: int = 100,
    category: str | None = None,
    scan_id: str | None = None,
    event_source: str | None = None,
) -> dict[str, Any]:
    max_rows = max(0, min(int(limit or 100), 1000))
    requested_source = safe_slug(event_source) if event_source else ''
    events = []
    if requested_source in {'', 'governance'}:
        events.extend(compliance_governance_events(limit=max_rows, category=category, scan_id=scan_id))
    if requested_source in {'', 'legacy-audit'}:
        events.extend(compliance_legacy_audit_events(limit=max_rows, category=category, scan_id=scan_id))
    rows = sorted(events, key=lambda item: item.get('created_at') or '', reverse=True)[:max_rows]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'count': len(rows),
        'scope': {
            'category': category or '',
            'scan_id': scan_id or '',
            'event_source': event_source or 'all',
            'limit': max_rows,
        },
        'event_type_counts': dict(Counter(row.get('event_type', 'unknown') for row in rows)),
        'category_counts': dict(Counter(row.get('category', 'unknown') for row in rows)),
        'events': rows,
        'safety': safety_attestation(),
    }


def compliance_agent_actions(limit: int = 100, scan_id: str | None = None) -> dict[str, Any]:
    events = compliance_activity_events(limit=limit, category='agent-action', scan_id=scan_id, event_source='governance')['events']
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'count': len(events),
        'scope': {'scan_id': scan_id or 'all'},
        'events': events,
        'safety': safety_attestation(),
    }


def compliance_approvals(limit: int = 100, scan_id: str | None = None) -> dict[str, Any]:
    from .benchmark_gate import list_benchmark_lessons
    from .governance import approval_records_from_lessons

    records = approval_records_from_lessons(list_benchmark_lessons().get('lessons', []), scan_id=scan_id)
    rows = [public_approval_record(item) for item in records[:max(0, min(limit, 1000))]]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'count': len(rows),
        'scope': {'scan_id': scan_id or 'all'},
        'records': rows,
        'policy': {
            'required_sequence': 'proposed -> reviewed -> benchmarked -> approved -> active',
            'influence_rule': 'Only active lessons with passing benchmark evidence and approval may influence future scanner/rule recommendations.',
        },
        'safety': safety_attestation(),
    }


def compliance_memory_lineage(limit: int = 100, scan_id: str | None = None) -> dict[str, Any]:
    from .rag_memory import list_memory_versions

    versions = [public_memory_version(item) for item in list_memory_versions(scan_id=scan_id, limit=max(0, min(limit, 1000)))]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'count': len(versions),
        'scope': {'scan_id': scan_id or 'all'},
        'versions': versions,
        'rollback': {
            'supported': True,
            'endpoint': '/api/rag-memory/versions/{version_id}/rollback',
            'raw_scan_or_repository_mutated': False,
        },
        'safety': safety_attestation(),
    }


def compliance_quarantine_alerts(limit: int = 100) -> dict[str, Any]:
    from .quarantine import quarantine_registry_report

    report = quarantine_registry_report()
    entries = [
        public_quarantine_entry(item)
        for item in report.get('entries', [])
        if item.get('status') in {'watch', 'quarantined', 'blocked'}
    ][:max(0, min(limit, 1000))]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'count': len(entries),
        'status_counts': dict(Counter(item.get('status', 'unknown') for item in entries)),
        'entries': entries,
        'safety': safety_attestation(),
    }


def compliance_scan_inventory(limit: int = 100) -> dict[str, Any]:
    from .report_lake import list_sanitized_scans

    rows = [public_scan_record(item) for item in list_sanitized_scans(limit=max(0, min(limit, 1000)))]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'count': len(rows),
        'records': rows,
        'safety': safety_attestation(),
    }


def compliance_evidence_bundle(scan_id: str | None = None, limit: int = 250) -> dict[str, Any]:
    from .governance import compliance_evidence_export
    from .teaching_loop import list_teaching_sessions

    max_rows = max(0, min(int(limit or 250), 1000))
    governance_export = compliance_evidence_export(scan_id=scan_id, limit=max_rows)
    events = compliance_activity_events(limit=max_rows, scan_id=scan_id)
    approvals = compliance_approvals(limit=max_rows, scan_id=scan_id)
    memory = compliance_memory_lineage(limit=max_rows, scan_id=scan_id)
    agent_actions = compliance_agent_actions(limit=max_rows, scan_id=scan_id)
    scans = compliance_scan_inventory(limit=max_rows)
    if scan_id:
        scans['records'] = [item for item in scans['records'] if item.get('scan_id') == scan_id]
        scans['count'] = len(scans['records'])
    teaching_sessions = [
        public_teaching_session(item)
        for item in list_teaching_sessions(limit=max_rows)
        if not scan_id or (item.get('source') or {}).get('scan_id') == scan_id
    ]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'evidence_type': 'secure-review-compliance-api-bundle',
        'exportable': True,
        'scope': {'scan_id': scan_id or 'all'},
        'control_summary': {
            'activity_events': events['count'],
            'agent_actions': agent_actions['count'],
            'approvals': approvals['count'],
            'memory_versions': memory['count'],
            'scan_records': scans['count'],
            'teaching_sessions': len(teaching_sessions),
            'quarantine_alerts': compliance_quarantine_alerts(limit=max_rows)['count'] if not scan_id else 'global',
        },
        'events': events,
        'agent_actions': agent_actions,
        'approvals': approvals,
        'memory_lineage': memory,
        'scan_inventory': scans,
        'teaching_sessions': teaching_sessions,
        'enterprise_governance_evidence': sanitize_jsonable(governance_export),
        'attestation': {
            **safety_attestation(),
            'lessons_influence_only_after_approved_and_benchmarked': True,
            'scanner_rule_mutation_allowed_by_api': False,
        },
        'guardrails': compliance_guardrails(),
    }


def compliance_governance_events(limit: int, category: str | None = None, scan_id: str | None = None) -> list[dict[str, Any]]:
    from .governance import governance_events

    return [
        normalize_governance_event(item)
        for item in governance_events(limit=limit, category=category, scan_id=scan_id)
    ]


def compliance_legacy_audit_events(limit: int, category: str | None = None, scan_id: str | None = None) -> list[dict[str, Any]]:
    from .enterprise import audit_events

    rows = []
    for item in reversed(audit_events(limit=limit)):
        normalized = normalize_legacy_audit_event(item)
        if category and normalized.get('category') != category and normalized.get('action') != category:
            continue
        if scan_id and normalized.get('scan_id') != scan_id and normalized.get('resource') != scan_id:
            continue
        rows.append(normalized)
    return rows


def normalize_governance_event(event: dict[str, Any]) -> dict[str, Any]:
    metadata = sanitize_jsonable(event.get('metadata') or {})
    evidence = sanitize_jsonable(event.get('evidence_refs') or {})
    category = safe_text(event.get('category'), 80)
    action = safe_text(event.get('action'), 160)
    return {
        'schema_version': SCHEMA_VERSION,
        'event_id': safe_text(event.get('event_id') or stable_id(json.dumps(event, sort_keys=True)), 80),
        'created_at': safe_text(event.get('created_at'), 80),
        'event_source': 'governance',
        'event_type': event_type_for(category, action),
        'actor': safe_text(event.get('actor'), 120),
        'action': action,
        'category': category,
        'resource': safe_text(event.get('resource'), 240),
        'scan_id': safe_text(event.get('scan_id'), 160),
        'reason': safe_text(event.get('reason'), 1000),
        'metadata': metadata,
        'evidence_refs': evidence,
        'safety': normalized_safety(event.get('safety') or {}),
    }


def normalize_legacy_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    metadata = sanitize_jsonable(event.get('metadata') or {})
    action = safe_text(event.get('action'), 160)
    scan_id = safe_text(metadata.get('scan_id') or event.get('resource') if looks_like_scan_event(action) else metadata.get('scan_id') or '', 160)
    return {
        'schema_version': SCHEMA_VERSION,
        'event_id': safe_text(event.get('event_id') or stable_id(json.dumps(event, sort_keys=True)), 80),
        'created_at': safe_text(event.get('created_at'), 80),
        'event_source': 'legacy-audit',
        'event_type': event_type_for('', action),
        'actor': safe_text(event.get('actor'), 120),
        'action': action,
        'category': safe_text(metadata.get('category') or category_for_action(action), 80),
        'resource': safe_text(event.get('resource'), 240),
        'scan_id': scan_id,
        'reason': safe_text(metadata.get('reason') or '', 1000),
        'metadata': metadata,
        'evidence_refs': {},
        'safety': safety_attestation(),
    }


def public_approval_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        'lesson_id': record.get('lesson_id'),
        'title': record.get('title'),
        'language': record.get('language'),
        'category': record.get('category'),
        'source': record.get('source'),
        'rule_id': record.get('rule_id'),
        'promotion_state': record.get('promotion_state'),
        'learning_influence_allowed': bool(record.get('learning_influence_allowed')),
        'created_by': record.get('created_by'),
        'reviewed_by': record.get('reviewed_by'),
        'approved_by': record.get('approved_by'),
        'approved_at': record.get('approved_at'),
        'approval_note': record.get('approval_note'),
        'promotion_reason': record.get('promotion_reason'),
        'benchmark_status': record.get('benchmark_status'),
        'benchmark_passed': bool(record.get('benchmark_passed')),
    }


def public_memory_version(version: dict[str, Any]) -> dict[str, Any]:
    return {
        'version_id': version.get('version_id'),
        'created_at': version.get('created_at'),
        'scan_id': version.get('scan_id'),
        'project_name': version.get('project_name'),
        'status': version.get('status'),
        'item_count': version.get('item_count', 0),
        'previous_version_id': version.get('previous_version_id', ''),
        'active': bool(version.get('active')),
        'snapshot_path_hash': stable_id(str(version.get('snapshot_path') or '')) if version.get('snapshot_path') else '',
        'raw_code_included': False,
        'raw_report_included': False,
    }


def public_quarantine_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        'key': entry.get('key'),
        'repository': entry.get('repository'),
        'status': entry.get('status'),
        'severity': entry.get('severity'),
        'reason': safe_text(entry.get('reason'), 1000),
        'source': entry.get('source'),
        'created_at': entry.get('created_at'),
        'updated_at': entry.get('updated_at'),
        'tags': entry.get('tags', []),
        'controls': entry.get('controls', {}),
    }


def public_scan_record(record: dict[str, Any]) -> dict[str, Any]:
    target = record.get('target') if isinstance(record.get('target'), dict) else {}
    summary = record.get('summary') or {}
    return {
        'scan_id': record.get('scan_id'),
        'project_name': record.get('project_name'),
        'created_at': record.get('created_at'),
        'generated_at': record.get('generated_at'),
        'repo_name': target.get('repo_name', ''),
        'target_path_hash': target.get('target_path_hash', ''),
        'summary': {
            'total_findings': summary.get('total_findings', 0),
            'files_scanned': summary.get('files_scanned', 0),
            'languages': summary.get('languages', {}),
            'risk_tiers': summary.get('risk_tiers', {}),
            'priorities': summary.get('priorities', {}),
            'scope_counts': summary.get('scope_counts', {}),
        },
        'quarantine': record.get('quarantine', {}),
        'learning_eligibility': record.get('learning_eligibility', {}),
        'finding_count': record.get('finding_count', 0),
        'stored_finding_count': record.get('stored_finding_count', 0),
        'lake_path_hash': record.get('lake_path_hash', ''),
    }


def public_teaching_session(card: dict[str, Any]) -> dict[str, Any]:
    return {
        'session_id': card.get('session_id'),
        'created_at': card.get('created_at'),
        'completed_at': card.get('completed_at'),
        'status': card.get('status'),
        'source': card.get('source', {}),
        'curriculum_count': card.get('curriculum_count', 0),
        'mastered_count': card.get('mastered_count', 0),
        'deferred_count': card.get('deferred_count', 0),
        'summary': card.get('summary', ''),
    }


def normalized_safety(safety: dict[str, Any]) -> dict[str, bool]:
    return {
        'raw_code_included': bool(safety.get('raw_code_included', False)),
        'raw_report_included': bool(safety.get('raw_report_included', False)),
        'repository_mutated': bool(safety.get('repository_mutated', False)),
        'scanner_rule_mutated': bool(safety.get('scanner_rule_mutated', False)),
        'conversation_content_included': False,
        'full_local_paths_included': False,
    }


def safety_attestation() -> dict[str, bool]:
    return {
        'raw_code_included': False,
        'raw_report_included': False,
        'repository_mutated': False,
        'scanner_rule_mutated': False,
        'conversation_content_included': False,
        'full_local_paths_included': False,
    }


def event_type_for(category: str, action: str) -> str:
    if category == 'agent-action' or action.startswith('agent.'):
        return 'agent-action'
    if category in {'approval', 'benchmark-gate'} or action.startswith('lesson.'):
        return 'approval'
    if category in {'memory-version', 'memory-rollback'} or action.startswith('rag_memory.'):
        return 'memory-lineage'
    if category.startswith('quarantine') or action.startswith('quarantine.'):
        return 'quarantine'
    if 'scan' in action:
        return 'scan-activity'
    if action.startswith('auth.'):
        return 'identity-activity'
    return category or 'activity'


def category_for_action(action: str) -> str:
    if action.startswith('auth.'):
        return 'identity'
    if action.startswith('scan.'):
        return 'scan'
    if action.startswith('hermes.') or action.startswith('agent.'):
        return 'agent-action'
    if action.startswith('benchmark_gate.') or action.startswith('lesson.'):
        return 'approval'
    if action.startswith('rag_memory.'):
        return 'memory-version'
    if action.startswith('quarantine.'):
        return 'quarantine'
    return 'activity'


def looks_like_scan_event(action: str) -> bool:
    return 'scan' in action or action.startswith(('hermes.', 'rag_memory.', 'teaching_loop.'))


def compliance_guardrails() -> list[str]:
    return [
        'Compliance API exports metadata, audit events, governance evidence, and sanitized report inventory only.',
        'Compliance API does not export raw repository source, raw scan reports, prompt/response transcripts, patches, secrets, or full local paths.',
        'Partner tools may observe and alert, but they must not mutate scanner rules, parser code, suppressions, memory lessons, or repositories.',
        'Lesson influence remains blocked unless the Benchmark Gate marks the lesson active after passing benchmark evidence and approval.',
        'Quarantine records are treated as security controls and are included as alert metadata without opening hostile repositories.',
    ]


def sanitize_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            safe_key = safe_text(key, 120)
            lowered = safe_key.lower()
            if 'path' in lowered and not lowered.endswith('_hash'):
                continue
            cleaned[safe_key] = sanitize_jsonable(item)
        return cleaned
    if isinstance(value, list):
        return [sanitize_jsonable(item) for item in value[:200]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return safe_text(value, 2000) if isinstance(value, str) else value
    return safe_text(value, 500)


def safe_text(value: Any, limit: int) -> str:
    text = '' if value is None else str(value)
    text = re.sub(r'[\x00-\x1f\x7f]+', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return f'{text[: limit - 14].rstrip()}...[truncated]' if len(text) > limit else text


def safe_slug(value: Any) -> str:
    return re.sub(r'[^a-zA-Z0-9_.:-]+', '-', str(value or '').strip()).strip('-').lower()


def stable_id(*parts: str) -> str:
    raw = '\n'.join(str(part or '') for part in parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]
