from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .enterprise import audit, audit_events
from .paths import data_dir

SCHEMA_VERSION = 1


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def governance_dir() -> Path:
    return data_dir() / 'governance'


def governance_events_path() -> Path:
    return governance_dir() / 'events.jsonl'


def ensure_governance_dirs() -> None:
    governance_dir().mkdir(parents=True, exist_ok=True)


def record_governance_event(
    *,
    actor: str,
    action: str,
    resource: str,
    category: str,
    scan_id: str = '',
    reason: str = '',
    metadata: dict[str, Any] | None = None,
    evidence_refs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ensure_governance_dirs()
    event = {
        'schema_version': SCHEMA_VERSION,
        'event_id': uuid.uuid4().hex[:16],
        'created_at': now_iso(),
        'actor': safe_text(actor, 120) or 'system',
        'action': safe_text(action, 160),
        'category': safe_text(category, 80),
        'resource': safe_text(resource, 240),
        'scan_id': safe_text(scan_id, 160),
        'reason': safe_text(reason, 1000),
        'metadata': sanitize_jsonable(metadata or {}),
        'evidence_refs': sanitize_jsonable(evidence_refs or {}),
        'safety': {
            'raw_code_included': False,
            'raw_report_included': False,
            'repository_mutated': False,
            'scanner_rule_mutated': False,
        },
    }
    with governance_events_path().open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(event, sort_keys=True) + '\n')
    audit(
        event['actor'],
        event['action'],
        event['resource'],
        audit_metadata({
            'category': event['category'],
            'scan_id': event['scan_id'],
            'reason': event['reason'],
            **event['metadata'],
        }),
    )
    return event


def governance_events(limit: int = 100, category: str | None = None, scan_id: str | None = None) -> list[dict[str, Any]]:
    path = governance_events_path()
    if not path.exists():
        return []
    requested_category = (category or '').strip()
    requested_scan = (scan_id or '').strip()
    rows: list[dict[str, Any]] = []
    for line in reversed(path.read_text(encoding='utf-8').splitlines()):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if requested_category and event.get('category') != requested_category:
            continue
        if requested_scan and event.get('scan_id') != requested_scan:
            continue
        rows.append(event)
        if len(rows) >= max(0, limit):
            break
    return rows


def record_agent_actions_for_run(run: dict[str, Any]) -> list[dict[str, Any]]:
    source = run.get('source') or {}
    memory_version_id = source.get('memory_version_id') or ''
    requester = str(run.get('requester') or 'system')
    events: list[dict[str, Any]] = []
    for result in run.get('agent_results', []):
        events.append(record_governance_event(
            actor=requester,
            action='agent.action',
            category='agent-action',
            resource=str(result.get('result_id') or result.get('task_id') or result.get('agent_id') or run.get('run_id')),
            scan_id=str(source.get('scan_id') or result.get('evidence_refs', {}).get('scan_id') or ''),
            reason='Hermes dispatched a deterministic agent over sanitized memory.',
            metadata={
                'run_id': run.get('run_id'),
                'agent_id': result.get('agent_id'),
                'agent_version': result.get('agent_version'),
                'task_id': result.get('task_id'),
                'task_type': result.get('task_type'),
                'status': result.get('status'),
                'memory_item_id': result.get('item_id'),
                'memory_version_id': memory_version_id,
            },
            evidence_refs={
                'run_id': run.get('run_id'),
                'memory_version_id': memory_version_id,
                'source': source,
                'result_id': result.get('result_id'),
            },
        ))
    for error in run.get('agent_errors', []):
        events.append(record_governance_event(
            actor=requester,
            action='agent.error',
            category='agent-action',
            resource=str(error.get('task_id') or run.get('run_id')),
            scan_id=str(source.get('scan_id') or ''),
            reason=str(error.get('error') or 'Hermes agent dispatch error.'),
            metadata={
                'run_id': run.get('run_id'),
                'agent_id': error.get('agent_id'),
                'task_id': error.get('task_id'),
                'memory_version_id': memory_version_id,
            },
            evidence_refs={'run_id': run.get('run_id'), 'memory_version_id': memory_version_id, 'source': source},
        ))
    if not run.get('agent_results') and run.get('policy', {}).get('decision') == 'blocked':
        events.append(record_governance_event(
            actor=requester,
            action='agent.policy_blocked',
            category='agent-action',
            resource=str(run.get('run_id') or source.get('scan_id') or 'hermes'),
            scan_id=str(source.get('scan_id') or ''),
            reason='Hermes did not dispatch agents because memory policy blocked the run.',
            metadata={
                'run_id': run.get('run_id'),
                'memory_version_id': memory_version_id,
                'blocked_reasons': ', '.join(run.get('policy', {}).get('blocked_reasons', [])),
            },
            evidence_refs={'run_id': run.get('run_id'), 'memory_version_id': memory_version_id, 'source': source},
        ))
    return events


def record_lesson_promotion_event(
    lesson: dict[str, Any],
    *,
    previous_state: str,
    target_state: str,
    actor: str,
    reason: str,
) -> dict[str, Any]:
    action = 'lesson.approved' if target_state == 'approved' else 'lesson.promoted'
    if target_state == 'active':
        action = 'lesson.activated'
    return record_governance_event(
        actor=actor,
        action=action,
        category='approval',
        resource=str(lesson.get('lesson_id') or ''),
        scan_id=str((lesson.get('evidence_summary') or {}).get('scan_id') or ''),
        reason=reason,
        metadata={
            'lesson_id': lesson.get('lesson_id'),
            'title': lesson.get('title'),
            'language': lesson.get('language'),
            'category': lesson.get('category'),
            'source': lesson.get('source'),
            'rule_id': lesson.get('rule_id'),
            'previous_state': previous_state,
            'target_state': target_state,
            'approved_by': (lesson.get('approval') or {}).get('approved_by', ''),
            'benchmark_passed': str(bool((lesson.get('benchmark') or {}).get('passed'))),
            'learning_influence_allowed': str(bool(lesson.get('learning_influence_allowed'))),
        },
        evidence_refs={
            'lesson_id': lesson.get('lesson_id'),
            'benchmark': lesson.get('benchmark') or {},
            'approval': lesson.get('approval') or {},
            'history': lesson.get('history', [])[-5:],
        },
    )


def record_memory_version_event(memory: dict[str, Any], *, previous_version_id: str = '', actor: str = 'system') -> dict[str, Any]:
    version = memory.get('memory_version') or {}
    source = memory.get('source') or {}
    return record_governance_event(
        actor=actor,
        action='rag_memory.version_created',
        category='memory-version',
        resource=str(version.get('version_id') or ''),
        scan_id=str(source.get('scan_id') or ''),
        reason='Sanitized RAG memory version recorded for scan lineage.',
        metadata={
            'memory_version_id': version.get('version_id'),
            'previous_version_id': previous_version_id,
            'project_name': source.get('project_name'),
            'status': memory.get('status'),
            'item_count': str(memory.get('item_count', 0)),
        },
        evidence_refs={'memory_version': version, 'source': source},
    )


def enterprise_governance_report(scan_id: str | None = None, limit: int = 100) -> dict[str, Any]:
    from .benchmark_gate import list_benchmark_lessons
    from .hermes import list_hermes_runs, load_hermes_run
    from .rag_memory import list_memory_versions

    events = governance_events(limit=limit, scan_id=scan_id)
    audit_rows = filter_scan_rows(audit_events(limit=max(limit, 500)), scan_id)
    lessons = list_benchmark_lessons().get('lessons', [])
    approvals = approval_records_from_lessons(lessons, scan_id=scan_id)
    versions = list_memory_versions(scan_id=scan_id, limit=limit)
    hermes_runs = []
    for card in list_hermes_runs(limit=limit):
        if scan_id and (card.get('source') or {}).get('scan_id') != scan_id:
            continue
        try:
            hermes_runs.append(load_hermes_run(str(card.get('run_id'))))
        except FileNotFoundError:
            continue
    agent_actions = [event for event in events if event.get('category') == 'agent-action']
    if not agent_actions:
        agent_actions = [
            event
            for event in governance_events(limit=max(limit, 500), category='agent-action')
            if not scan_id or event.get('scan_id') == scan_id
        ][:limit]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'ready',
        'scope': {'scan_id': scan_id or 'all'},
        'audit_trail': {
            'event_count': len(events),
            'events': events,
            'legacy_audit_count': len(audit_rows),
            'legacy_audit_events': audit_rows[:limit],
            'categories': dict(Counter(event.get('category', 'unknown') for event in events)),
        },
        'agent_actions': {
            'count': len(agent_actions),
            'events': agent_actions[:limit],
            'hermes_runs': [run_card(run) for run in hermes_runs],
        },
        'approvals': {
            'count': len(approvals),
            'records': approvals,
            'policy': 'Lessons require proposed -> reviewed -> benchmarked -> approved -> active before influence.',
        },
        'memory_lineage': {
            'version_count': len(versions),
            'versions': versions,
            'rollback_supported': True,
            'rollback_endpoint': '/api/rag-memory/versions/{version_id}/rollback',
        },
        'evidence_export': {
            'endpoint': '/api/enterprise/governance/evidence',
            'scan_endpoint': '/api/scans/{scan_id}/governance',
            'artifact': 'governance-evidence.json',
            'raw_code_included': False,
            'raw_reports_included': False,
        },
        'guardrails': governance_guardrails(),
    }


def compliance_evidence_export(scan_id: str | None = None, limit: int = 250) -> dict[str, Any]:
    report = enterprise_governance_report(scan_id=scan_id, limit=limit)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'evidence_type': 'enterprise-governance-compliance',
        'exportable': True,
        'scope': report['scope'],
        'control_summary': {
            'agent_action_audit': report['agent_actions']['count'] > 0,
            'approval_traceability': report['approvals']['count'] >= 0,
            'memory_version_lineage': report['memory_lineage']['version_count'] >= 0,
            'memory_rollback_supported': report['memory_lineage']['rollback_supported'],
        },
        'evidence': report,
        'attestation': {
            'raw_repository_code_included': False,
            'raw_scan_report_included': False,
            'scanner_rule_mutation_allowed': False,
            'lessons_influence_only_after_approved_and_benchmarked': True,
        },
    }


def approval_records_from_lessons(lessons: list[dict[str, Any]], scan_id: str | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for lesson in lessons:
        evidence = lesson.get('evidence_summary') or {}
        if scan_id and evidence.get('scan_id') and evidence.get('scan_id') != scan_id:
            continue
        history = lesson.get('history') or []
        records.append({
            'lesson_id': lesson.get('lesson_id'),
            'title': lesson.get('title'),
            'language': lesson.get('language'),
            'category': lesson.get('category'),
            'source': lesson.get('source'),
            'rule_id': lesson.get('rule_id'),
            'promotion_state': lesson.get('promotion_state'),
            'learning_influence_allowed': bool(lesson.get('learning_influence_allowed')),
            'created_by': lesson.get('created_by'),
            'reviewed_by': (lesson.get('review') or {}).get('reviewed_by'),
            'approved_by': (lesson.get('approval') or {}).get('approved_by'),
            'approved_at': (lesson.get('approval') or {}).get('approved_at'),
            'approval_note': (lesson.get('approval') or {}).get('note'),
            'promotion_reason': lesson.get('promotion_reason') or latest_history_note(history),
            'benchmark_status': (lesson.get('benchmark') or {}).get('status'),
            'benchmark_passed': bool((lesson.get('benchmark') or {}).get('passed')),
            'history': history,
        })
    return records


def filter_scan_rows(rows: list[dict[str, Any]], scan_id: str | None) -> list[dict[str, Any]]:
    if not scan_id:
        return rows
    return [
        row
        for row in rows
        if row.get('resource') == scan_id
        or row.get('metadata', {}).get('scan_id') == scan_id
        or row.get('metadata', {}).get('source_scan_id') == scan_id
    ]


def run_card(run: dict[str, Any]) -> dict[str, Any]:
    return {
        'run_id': run.get('run_id'),
        'created_at': run.get('created_at'),
        'status': run.get('status'),
        'requester': run.get('requester'),
        'goal': run.get('goal'),
        'source': run.get('source', {}),
        'memory_version_id': (run.get('source') or {}).get('memory_version_id'),
        'task_count': run.get('plan', {}).get('task_count', 0),
        'agent_result_count': len(run.get('agent_results', [])),
    }


def governance_guardrails() -> list[str]:
    return [
        'Governance evidence is derived from audit logs, sanitized RAG memory, Benchmark Gate lessons, and Hermes run records.',
        'Governance exports do not include raw repository code, raw scan reports, patches, or full local paths.',
        'Agent actions are planning/audit outputs only and cannot mutate scanner rules or repository files.',
        'Memory rollback restores sanitized RAG memory records and rebuilds the retrieval index; it does not alter raw scans.',
    ]


def audit_metadata(payload: dict[str, Any]) -> dict[str, str]:
    return {safe_text(key, 80): safe_text(value, 500) for key, value in payload.items() if key}


def sanitize_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {safe_text(key, 120): sanitize_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_jsonable(item) for item in value[:200]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return safe_text(value, 2000) if isinstance(value, str) else value
    return safe_text(value, 500)


def safe_text(value: Any, limit: int) -> str:
    text = '' if value is None else str(value)
    text = ' '.join(text.split())
    return text if len(text) <= limit else f'{text[: limit - 14].rstrip()}...[truncated]'


def latest_history_note(history: list[dict[str, Any]]) -> str:
    for item in reversed(history):
        note = item.get('note') or item.get('reason')
        if note:
            return str(note)
    return ''
