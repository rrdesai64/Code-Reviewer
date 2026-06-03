from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import data_dir
from .rag_memory import rag_memory_for_scan, scan_rag_memory_report

SCHEMA_VERSION = 1
RETIRED_REASON = 'Teacher-student learning between Codex and Hermes agents has been retired.'
DEFAULT_PASS_SCORE = 7
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_LIMIT = 50
MAX_CURRICULUM_ITEMS = 200
MASTERED = 'mastered'
DEFERRED = 'deferred_review_required'
BLOCKED = 'blocked'


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def teaching_loop_dir() -> Path:
    return data_dir() / 'teaching-loop'


def teaching_sessions_dir() -> Path:
    return teaching_loop_dir() / 'sessions'


def ensure_teaching_loop_dirs() -> None:
    teaching_sessions_dir().mkdir(parents=True, exist_ok=True)


def teaching_loop_schema() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'name': 'secure-review-teacher-student-loop-retired',
        'status': 'retired',
        'retired_reason': RETIRED_REASON,
        'source_contract': {
            'accepted_source': 'rag-memory-from-sanitized-report-lake',
            'raw_repository_reads_allowed': False,
            'raw_report_file_reads_allowed': False,
            'disposable_vm_code_inspection_allowed': False,
            'source_execution_allowed': False,
            'fine_tuning_allowed': False,
        },
        'curriculum_states': ['pending', 'in_progress', MASTERED, DEFERRED, 'skipped'],
        'teaching_contract': {
            'enabled': False,
            'teacher': None,
            'student': None,
            'student_input': None,
            'proof_of_work': None,
            'circuit_breaker_attempts': DEFAULT_MAX_ATTEMPTS,
            'pass_score': DEFAULT_PASS_SCORE,
        },
        'promotion_contract': {
            'mastery_does_not_promote_rules': True,
            'mastery_does_not_apply_fixes': True,
            'benchmark_gate_required_for_future_influence': True,
            'only_active_benchmarked_approved_lessons_can_influence_agents': True,
        },
        'guardrails': teaching_guardrails(),
    }


def teaching_guardrails() -> list[str]:
    return [
        RETIRED_REASON,
        'No Hermes student run is created.',
        'No mastery record is produced.',
        'No scanner/rule influence is derived from repository scan learning.',
    ]


def teaching_loop_status() -> dict[str, Any]:
    ensure_teaching_loop_dirs()
    sessions = list_teaching_sessions(limit=20)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'retired',
        'retired': True,
        'retired_reason': RETIRED_REASON,
        'teaching_loop_dir': str(teaching_loop_dir()),
        'session_count': len(list(teaching_sessions_dir().glob('*.json'))),
        'latest_sessions': sessions,
        'schema': teaching_loop_schema(),
    }


def create_teaching_session(
    *,
    scan_id: str,
    requester: str = 'system',
    limit: int = DEFAULT_LIMIT,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    pass_score: int = DEFAULT_PASS_SCORE,
    persist: bool = True,
    rebuild_memory: bool = True,
) -> dict[str, Any]:
    if not scan_id:
        raise ValueError('scan_id is required')
    memory = scan_rag_memory_report(scan_id, rebuild=rebuild_memory)
    session = run_teaching_loop_on_memory(
        memory,
        requester=requester,
        limit=limit,
        max_attempts=max_attempts,
        pass_score=pass_score,
        persist=persist,
    )
    return session


def teaching_loop_report_for_scan(scan: Any, *, limit: int = DEFAULT_LIMIT, max_attempts: int = DEFAULT_MAX_ATTEMPTS, pass_score: int = DEFAULT_PASS_SCORE) -> dict[str, Any]:
    memory = rag_memory_for_scan(scan)
    return run_teaching_loop_on_memory(
        memory,
        requester='report-bundle',
        limit=limit,
        max_attempts=max_attempts,
        pass_score=pass_score,
        persist=False,
    )


def run_teaching_loop_on_memory(
    memory: dict[str, Any],
    *,
    requester: str = 'system',
    limit: int = DEFAULT_LIMIT,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    pass_score: int = DEFAULT_PASS_SCORE,
    persist: bool = True,
) -> dict[str, Any]:
    started = time.time()
    max_attempts = min(max(int(max_attempts or DEFAULT_MAX_ATTEMPTS), 1), 5)
    pass_score = min(max(int(pass_score or DEFAULT_PASS_SCORE), 1), 10)
    source = memory.get('source') or {}
    session_id = stable_id(str(source.get('scan_id') or 'global'), requester, now_iso(), str(limit), str(max_attempts))
    policy = evaluate_teaching_policy(memory)
    base = base_session(session_id, memory, requester, max_attempts, pass_score, policy)
    base.update({
        'status': 'retired',
        'completed_at': now_iso(),
        'duration_seconds': round(time.time() - started, 3),
        'summary': RETIRED_REASON,
        'synthesis': {
            'status': 'retired',
            'curriculum_count': 0,
            'mastered_count': 0,
            'deferred_count': 0,
            'summary': RETIRED_REASON,
            'teacher_student_learning_enabled': False,
            'repository_learning_enabled': False,
            'raw_repository_reads': 0,
            'raw_report_reads': 0,
        },
    })
    if persist:
        save_teaching_session(base)
    return base


def evaluate_teaching_policy(memory: dict[str, Any]) -> dict[str, Any]:
    status = str(memory.get('status') or 'missing')
    eligibility = memory.get('eligibility') or {}
    source = memory.get('source') or {}
    item_count = int(memory.get('item_count') or 0)
    blocked_reasons: list[str] = []
    safety_violations: list[str] = []
    if status in {'missing', 'skipped'}:
        blocked_reasons.append(memory.get('skipped_reason') or f'rag memory status is {status}')
    if not bool(eligibility.get('rag_ingest_allowed')):
        blocked_reasons.append(eligibility.get('blocked_reason') or 'rag ingest is denied by policy')
    if item_count <= 0:
        blocked_reasons.append('no eligible RAG memory items are available')
    for item in memory.get('items', []):
        safety = item.get('safety') or {}
        if safety.get('raw_code_included') or safety.get('patches_included') or safety.get('full_local_paths_included'):
            safety_violations.append(str(item.get('item_id') or 'unknown'))
    if safety_violations:
        blocked_reasons.append(f'safety violations detected in memory items: {", ".join(safety_violations[:5])}')
    return {
        'schema_version': SCHEMA_VERSION,
        'decision': BLOCKED if blocked_reasons else 'allowed',
        'blocked_reasons': dedupe(blocked_reasons),
        'safety_violations': safety_violations,
        'scan_id': source.get('scan_id'),
        'project_name': source.get('project_name'),
        'memory_status': status,
        'item_count': item_count,
        **teaching_loop_schema()['source_contract'],
    }


def base_session(session_id: str, memory: dict[str, Any], requester: str, max_attempts: int, pass_score: int, policy: dict[str, Any]) -> dict[str, Any]:
    source = memory.get('source') or {}
    version = memory.get('memory_version') or {}
    return {
        'schema_version': SCHEMA_VERSION,
        'session_id': session_id,
        'session_type': 'agent-learning-retired',
        'created_at': now_iso(),
        'completed_at': None,
        'duration_seconds': 0,
        'status': 'running',
        'requester': requester,
        'source': {
            'scan_id': source.get('scan_id'),
            'project_name': source.get('project_name'),
            'repo_name': source.get('repo_name'),
            'target_path_hash': source.get('target_path_hash'),
            'memory_version_id': source.get('memory_version_id') or version.get('version_id', ''),
            'source_report_type': source.get('source_report_type') or 'rag-memory',
        },
        'policy': policy,
        'settings': {
            'max_attempts': max_attempts,
            'pass_score': pass_score,
            'curriculum_limit': MAX_CURRICULUM_ITEMS,
            'sanitized_report_only': True,
        },
        'curriculum': [],
        'attempts_by_lesson': {},
        'mastered_records': [],
        'deferred_records': [],
        'hermes_student_run': {},
        'synthesis': {},
        'safety': {
            'raw_repository_reads_allowed': False,
            'raw_report_file_reads_allowed': False,
            'disposable_vm_code_inspection_allowed': False,
            'source_execution_allowed': False,
            'files_modified': False,
        },
        'guardrails': teaching_guardrails(),
    }


def build_curriculum(memory: dict[str, Any], limit: int = DEFAULT_LIMIT) -> list[dict[str, Any]]:
    items = [
        item
        for item in memory.get('items', [])
        if item.get('eligibility', {}).get('retrieval_allowed') and item.get('eligibility', {}).get('agent_learning_allowed')
    ]
    max_items = min(max(int(limit or DEFAULT_LIMIT), 0), MAX_CURRICULUM_ITEMS)
    ranked = sorted(items, key=lambda item: (-item_risk_score(item), item_type_rank(item), str(item.get('title') or '')))
    return [curriculum_unit(item, index + 1) for index, item in enumerate(ranked[:max_items])]


def curriculum_unit(item: dict[str, Any], sequence: int) -> dict[str, Any]:
    item_type = str(item.get('item_type') or 'unknown')
    title = safe_text(item.get('title') or item_type, 220)
    concept = concept_for_item(item)
    lesson_id = stable_id(str(item.get('source', {}).get('scan_id') or ''), str(item.get('item_id') or ''), concept)
    return {
        'lesson_id': lesson_id,
        'sequence': sequence,
        'status': 'pending',
        'item_id': item.get('item_id'),
        'item_type': item_type,
        'title': title,
        'concept': concept,
        'teacher_lesson': (
            f"Study this sanitized {item_type} memory item: {title}. "
            f"Explain the risk signal, evidence limits, scanner/source context, and safe validation plan without reading raw code."
        ),
        'challenge_prompt': (
            f"Hermes, using only sanitized RAG memory item {item.get('item_id')}, explain what was detected, "
            'why it matters, which evidence you can cite, and what remains unproven.'
        ),
        'source_item': item,
    }


def student_answer_for_item(item: dict[str, Any], results: list[dict[str, Any]], attempt: int) -> dict[str, Any]:
    if not results:
        return {
            'answer_id': stable_id(str(item.get('item_id') or ''), str(attempt), 'no-answer'),
            'attempt': attempt,
            'status': 'no-student-evidence',
            'student_agent_ids': [],
            'summary': 'No Hermes agent result was available for this sanitized memory item.',
            'findings': [],
            'recommendations': [],
            'proof_of_work': {
                'source_contract': 'sanitized-rag-memory-only',
                'memory_item_id': item.get('item_id'),
                'scan_id': item.get('source', {}).get('scan_id'),
                'agent_result_ids': [],
            },
            'safety': safe_student_safety(),
            'limitations': ['No matching Hermes specialist or governor result was produced.'],
        }

    ranked = sorted(results, key=result_rank)
    selected = ranked[:3]
    findings = dedupe([finding for result in selected for finding in result.get('findings', [])])
    recommendations = dedupe([rec for result in selected for rec in result.get('recommendations', [])])
    statuses = [str(result.get('status') or '') for result in selected]
    agent_ids = [str(result.get('agent_id') or '') for result in selected]
    return {
        'answer_id': stable_id(str(item.get('item_id') or ''), str(attempt), *agent_ids, *statuses),
        'attempt': attempt,
        'status': best_status(statuses),
        'student_agent_ids': agent_ids,
        'summary': answer_summary(item, selected, findings),
        'findings': findings[:8],
        'recommendations': recommendations[:8],
        'proof_of_work': {
            'source_contract': 'sanitized-rag-memory-only',
            'memory_item_id': item.get('item_id'),
            'scan_id': item.get('source', {}).get('scan_id'),
            'agent_result_ids': [result.get('result_id') for result in selected],
            'task_types': [result.get('task_type') for result in selected],
            'evidence_refs': [result.get('evidence_refs', {}) for result in selected],
        },
        'safety': merged_student_safety(selected),
        'limitations': [
            'Answer is based on sanitized scan/RAG evidence only.',
            'No raw repository file, raw report, patch, or executable source was inspected.',
        ],
    }


def judge_student_answer(unit: dict[str, Any], answer: dict[str, Any], *, pass_score: int = DEFAULT_PASS_SCORE) -> dict[str, Any]:
    score = 0
    feedback: list[str] = []
    safety = answer.get('safety') or {}
    proof = answer.get('proof_of_work') or {}
    findings = answer.get('findings') or []
    recommendations = answer.get('recommendations') or []
    limitations = answer.get('limitations') or []

    safety_ok = (
        not safety.get('raw_code_accessed')
        and not safety.get('raw_report_accessed')
        and not safety.get('repository_executed')
        and not safety.get('files_modified')
        and proof.get('source_contract') == 'sanitized-rag-memory-only'
    )
    if safety_ok:
        score += 3
    else:
        feedback.append('Safety proof failed; student answer must stay sanitized-report-only.')
    if proof.get('memory_item_id') == unit.get('item_id') and proof.get('scan_id'):
        score += 2
    else:
        feedback.append('Proof of work must cite the source scan and memory item.')
    if proof.get('agent_result_ids'):
        score += 1
    else:
        feedback.append('No Hermes agent result was cited.')
    if findings:
        score += 1
    else:
        feedback.append('Answer did not identify a concrete finding or risk signal.')
    if recommendations:
        score += 1
    else:
        feedback.append('Answer did not provide safe validation or reviewer guidance.')
    if answer.get('student_agent_ids'):
        score += 1
    else:
        feedback.append('No student agent identity was attached.')
    if limitations:
        score += 1
    else:
        feedback.append('Answer should state evidence limits.')

    understood = safety_ok and score >= pass_score
    return {
        'schema_version': SCHEMA_VERSION,
        'judged_at': now_iso(),
        'teacher': 'codex',
        'understood': understood,
        'score': min(score, 10),
        'pass_score': pass_score,
        'feedback': feedback or ['Hermes demonstrated sufficient understanding from sanitized memory evidence.'],
        'next_state': MASTERED if understood else DEFERRED,
        'requires_benchmark_gate_for_future_influence': True,
    }


def mastery_record(unit: dict[str, Any], answer: dict[str, Any], judgment: dict[str, Any]) -> dict[str, Any]:
    return {
        'mastery_id': stable_id(unit['lesson_id'], answer.get('answer_id'), 'mastered'),
        'lesson_id': unit['lesson_id'],
        'item_id': unit.get('item_id'),
        'item_type': unit.get('item_type'),
        'concept': unit.get('concept'),
        'mastered_at': now_iso(),
        'score': judgment.get('score', 0),
        'student_agent_ids': answer.get('student_agent_ids', []),
        'student_summary': answer.get('summary', ''),
        'findings': answer.get('findings', [])[:5],
        'recommendations': answer.get('recommendations', [])[:5],
        'evidence_refs': answer.get('proof_of_work', {}),
        'teacher_feedback': judgment.get('feedback', []),
        'future_use': {
            'retrieval_context_allowed': True,
            'scanner_rule_influence_allowed': False,
            'requires_benchmark_gate': True,
        },
        'safety': safe_student_safety(),
    }


def deferred_record(unit: dict[str, Any], judgment: dict[str, Any], attempts: int) -> dict[str, Any]:
    return {
        'lesson_id': unit['lesson_id'],
        'item_id': unit.get('item_id'),
        'item_type': unit.get('item_type'),
        'concept': unit.get('concept'),
        'deferred_at': now_iso(),
        'attempts': attempts,
        'score': judgment.get('score', 0),
        'reason': '; '.join(judgment.get('feedback', []))[:1000],
        'next_action': 'Keep as review-required teaching debt; do not promote a lesson or mutate scanner behavior.',
    }


def save_teaching_session(session: dict[str, Any]) -> dict[str, Any]:
    ensure_teaching_loop_dirs()
    path = teaching_sessions_dir() / f"{safe_filename(session['session_id'])}.json"
    session['storage'] = {'path': str(path), 'path_discloses_repository': False}
    path.write_text(json.dumps(session, indent=2), encoding='utf-8')
    record_teaching_governance(session)
    return session


def load_teaching_session(session_id: str) -> dict[str, Any]:
    path = teaching_sessions_dir() / f'{safe_filename(session_id)}.json'
    if not path.exists():
        raise FileNotFoundError(session_id)
    return json.loads(path.read_text(encoding='utf-8'))


def list_teaching_sessions(limit: int = 100) -> list[dict[str, Any]]:
    ensure_teaching_loop_dirs()
    records: list[dict[str, Any]] = []
    for path in sorted(teaching_sessions_dir().glob('*.json'), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            records.append(teaching_session_card(json.loads(path.read_text(encoding='utf-8'))))
        except (OSError, json.JSONDecodeError) as exc:
            records.append({'session_id': path.stem, 'status': 'unreadable', 'error': str(exc)[:200]})
        if len(records) >= max(0, limit):
            break
    return records


def teaching_session_card(session: dict[str, Any]) -> dict[str, Any]:
    return {
        'session_id': session.get('session_id'),
        'created_at': session.get('created_at'),
        'completed_at': session.get('completed_at'),
        'status': session.get('status'),
        'requester': session.get('requester'),
        'source': session.get('source', {}),
        'curriculum_count': (session.get('synthesis') or {}).get('curriculum_count', 0),
        'mastered_count': (session.get('synthesis') or {}).get('mastered_count', 0),
        'deferred_count': (session.get('synthesis') or {}).get('deferred_count', 0),
        'summary': session.get('summary', ''),
    }


def blocked_synthesis(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        'status': BLOCKED,
        'curriculum_count': 0,
        'mastered_count': 0,
        'deferred_count': 0,
        'blocked_reasons': policy.get('blocked_reasons', []),
        'summary': 'Teaching loop blocked before curriculum generation.',
        'benchmark_gate_required_for_influence': True,
    }


def record_teaching_governance(session: dict[str, Any]) -> None:
    try:
        from .governance import record_governance_event

        source = session.get('source') or {}
        record_governance_event(
            actor=str(session.get('requester') or 'system'),
            action='teaching_loop.session_completed',
            category='agent-learning-retired',
            resource=str(session.get('session_id') or ''),
            scan_id=str(source.get('scan_id') or ''),
            reason=str(session.get('summary') or 'Sanitized-only teaching loop completed.'),
            metadata={
                'status': session.get('status'),
                'mastered_count': str((session.get('synthesis') or {}).get('mastered_count', 0)),
                'deferred_count': str((session.get('synthesis') or {}).get('deferred_count', 0)),
                'memory_version_id': source.get('memory_version_id', ''),
            },
            evidence_refs={
                'session_id': session.get('session_id'),
                'source_contract': teaching_loop_schema()['source_contract'],
                'guardrails': teaching_guardrails(),
            },
        )
    except Exception:
        pass


def group_agent_results_by_item(results: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for result in results:
        item_id = str(result.get('item_id') or '')
        if not item_id:
            continue
        grouped.setdefault(item_id, []).append(result)
    return grouped


def public_curriculum_unit(unit: dict[str, Any]) -> dict[str, Any]:
    return {
        'lesson_id': unit.get('lesson_id'),
        'sequence': unit.get('sequence'),
        'status': unit.get('status'),
        'item_id': unit.get('item_id'),
        'item_type': unit.get('item_type'),
        'title': unit.get('title'),
        'concept': unit.get('concept'),
        'teacher_lesson': unit.get('teacher_lesson'),
        'challenge_prompt': unit.get('challenge_prompt'),
    }


def concept_for_item(item: dict[str, Any]) -> str:
    metadata = item.get('metadata') or {}
    tags = {str(tag).upper() for tag in item.get('tags', [])}
    if item.get('item_type') == 'scanner-status':
        return 'scanner-coverage-and-reliability'
    if item.get('item_type') == 'dependency-signal' or tags & {'DEPENDENCY', 'SCA', 'SBOM'}:
        return 'supply-chain-risk'
    if metadata.get('rule_id'):
        return safe_text(metadata.get('rule_id'), 120)
    if tags & {'SECRET', 'SECRETS'}:
        return 'secret-handling'
    if tags & {'P0', 'P1', 'CRITICAL', 'HIGH'}:
        return 'high-risk-finding-triage'
    return safe_text(item.get('item_type') or 'sanitized-evidence', 120)


def result_rank(result: dict[str, Any]) -> tuple[int, str]:
    status_rank = {
        'release-blocker': 0,
        'critical-dependency-risk': 1,
        'coverage-gap': 2,
        'review-required': 3,
        'human-approval-required': 4,
        'manual-remediation': 5,
        'evidence-required': 6,
        'record-only': 8,
    }
    return (status_rank.get(str(result.get('status') or ''), 7), str(result.get('agent_id') or ''))


def best_status(statuses: list[str]) -> str:
    if not statuses:
        return 'unknown'
    return sorted(statuses, key=lambda status: result_rank({'status': status, 'agent_id': ''}))[0]


def answer_summary(item: dict[str, Any], results: list[dict[str, Any]], findings: list[str]) -> str:
    agents = ', '.join(str(result.get('agent_id') or '') for result in results if result.get('agent_id'))
    title = safe_text(item.get('title') or item.get('item_type') or 'memory item', 160)
    if findings:
        return safe_text(f'Hermes analyzed {title} using {agents}: {findings[0]}', 500)
    return safe_text(f'Hermes analyzed {title} using {agents} with sanitized memory evidence.', 500)


def merged_student_safety(results: list[dict[str, Any]]) -> dict[str, bool]:
    safety = safe_student_safety()
    for result in results:
        result_safety = result.get('safety') or {}
        safety['raw_code_accessed'] = safety['raw_code_accessed'] or bool(result_safety.get('raw_code_accessed'))
        safety['repository_executed'] = safety['repository_executed'] or bool(result_safety.get('repository_executed'))
        safety['external_calls_made'] = safety['external_calls_made'] or bool(result_safety.get('external_calls_made'))
        safety['files_modified'] = safety['files_modified'] or bool(result_safety.get('files_modified'))
    return safety


def safe_student_safety() -> dict[str, bool]:
    return {
        'raw_code_accessed': False,
        'raw_report_accessed': False,
        'repository_executed': False,
        'external_calls_made': False,
        'files_modified': False,
        'scanner_rule_mutated': False,
        'lesson_promoted': False,
    }


def item_risk_score(item: dict[str, Any]) -> int:
    metadata = item.get('metadata') or {}
    try:
        return int(metadata.get('risk_score') or metadata.get('max_risk_score') or 0)
    except (TypeError, ValueError):
        return 0


def item_type_rank(item: dict[str, Any]) -> int:
    rank = {'finding-pattern': 0, 'dependency-signal': 1, 'scanner-status': 2, 'rule-pattern': 3, 'scan-summary': 4}
    return rank.get(str(item.get('item_type') or ''), 9)


def synthesis_summary(source: dict[str, Any], mastered: list[dict[str, Any]], deferred: list[dict[str, Any]]) -> str:
    project = source.get('project_name') or source.get('scan_id') or 'scan'
    if deferred:
        return f"Teaching loop completed for {project}: {len(mastered)} mastered, {len(deferred)} deferred for review."
    return f"Teaching loop completed for {project}: {len(mastered)} curriculum item(s) mastered from sanitized memory."


def safe_filename(value: str) -> str:
    safe = re.sub(r'[^A-Za-z0-9_.:-]+', '-', str(value or '').strip()).strip('-')
    return safe.replace(':', '-')[:160] or 'unknown'


def safe_text(value: Any, max_length: int) -> str:
    text = re.sub(r'[\x00-\x1f\x7f]+', ' ', str(value or ''))
    text = re.sub(r'\s+', ' ', text).strip()
    return f'{text[: max_length - 14].rstrip()}...[truncated]' if len(text) > max_length else text


def stable_id(*parts: str) -> str:
    raw = '\n'.join(str(part or '') for part in parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]


def dedupe(values: list[str]) -> list[str]:
    seen = set()
    result: list[str] = []
    for value in values:
        text = safe_text(value, 500)
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result
