from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any

from .benchmark_gate import list_benchmark_lessons, transition_benchmark_lesson
from .finding_ai import build_finding_ai_review
from .quarantine import quarantine_policy, quarantine_policy_for_scan
from .storage import apply_decisions, list_scans, load_scan
from .vm_worker import create_vm_scan_job

SCHEMA_VERSION = 1
OPENCLAW_CHANNELS = {'api', 'whatsapp', 'telegram', 'slack', 'teams'}
DEFAULT_FEATURES: dict[str, dict[str, Any]] = {
    'scan-status': {
        'title': 'Scan Status',
        'commands': ['status', 'scan status', 'latest'],
        'backend_api': '/api/scans/{scan_id}',
        'mutating': False,
        'approved': True,
    },
    'approval-requests': {
        'title': 'Approval Requests',
        'commands': ['approvals', 'approval requests', 'pending approvals'],
        'backend_api': '/api/benchmark-gate/lessons',
        'mutating': False,
        'approved': True,
    },
    'quarantine-alerts': {
        'title': 'Quarantine Alerts',
        'commands': ['quarantine', 'quarantine alert'],
        'backend_api': '/api/quarantine/lookup',
        'mutating': False,
        'approved': True,
    },
    'explain-finding': {
        'title': 'Explain Finding',
        'commands': ['explain', 'explain finding'],
        'backend_api': '/api/scans/{scan_id}/findings/{finding_id}/ai-review',
        'mutating': False,
        'approved': True,
    },
    'approve-memory-lesson': {
        'title': 'Approve Memory Lesson',
        'commands': ['/approve', 'approve lesson', 'review lesson', 'activate lesson'],
        'backend_api': '/api/benchmark-gate/lessons/{lesson_id}/transition',
        'mutating': True,
        'approved': True,
    },
    'rerun-disposable-vm': {
        'title': 'Rerun Repo In Disposable VM',
        'commands': ['rerun vm', 'rerun disposable vm', 'rerun repo in vm'],
        'backend_api': '/api/vm-worker/jobs',
        'mutating': True,
        'approved': True,
    },
}
FORBIDDEN_MUTATION_WORDS = ('edit rule', 'rewrite rule', 'disable rule', 'suppress rule', 'change scanner', 'mutate scanner')


class OpenClawError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def openclaw_status() -> dict[str, Any]:
    features = openclaw_feature_registry()
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'ready',
        'integration_mode': 'openclaw-compatible-backend',
        'upstream': {
            'repository': 'openclaw/openclaw',
            'creator': 'Peter Steinberger',
            'role': 'self-hosted chat gateway and control UI',
            'runtime_dependency_installed': False,
        },
        'channels': {
            channel: {
                'supported': True,
                'inbound_route': f'/api/openclaw/webhook/{channel}' if channel != 'api' else '/api/openclaw/messages',
            }
            for channel in sorted(OPENCLAW_CHANNELS)
        },
        'feature_count': len(features),
        'features': list(features.values()),
        'security': {
            'requires_backend_auth': True,
            'direct_scanner_rule_mutation_allowed': False,
            'host_code_execution_allowed': False,
            'approval_commands_route_to_backend_apis': True,
        },
        'guardrails': openclaw_guardrails(),
    }


def openclaw_feature_registry() -> dict[str, dict[str, Any]]:
    requested = {item.strip() for item in os.getenv('OPENCLAW_FEATURES', 'all').split(',') if item.strip()}
    registry: dict[str, dict[str, Any]] = {}
    for feature_id, feature in DEFAULT_FEATURES.items():
        enabled = 'all' in requested or feature_id in requested
        registry[feature_id] = {
            'feature_id': feature_id,
            'enabled': enabled,
            'approval_status': 'approved' if feature.get('approved') else 'proposed',
            'rule_mutation_allowed': False,
            **feature,
        }
    return registry


def openclaw_feature_report() -> dict[str, Any]:
    registry = openclaw_feature_registry()
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'features': list(registry.values()),
        'update_model': {
            'source': 'backend feature registry',
            'new_features_require_backend_code_or_config': True,
            'new_mutating_features_require_approved_backend_api': True,
            'scanner_rule_mutation_allowed': False,
        },
        'guardrails': openclaw_guardrails(),
    }


def scan_openclaw_control(scan_id: str) -> dict[str, Any]:
    scan = apply_decisions(load_scan(scan_id))
    return openclaw_control_for_scan(scan)


def openclaw_control_for_scan(scan) -> dict[str, Any]:
    queue = approval_queue()
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'status': scan_status_payload(scan),
        'quarantine': quarantine_policy_for_scan(scan),
        'approval_queue': queue,
        'commands': command_examples(scan),
        'guardrails': openclaw_guardrails(),
    }


def handle_openclaw_message(payload: dict[str, Any], actor: str = 'system') -> dict[str, Any]:
    message = normalize_openclaw_message(payload)
    text = message['text']
    command = parse_openclaw_command(text)
    feature_id = command['feature_id']
    registry = openclaw_feature_registry()
    feature = registry.get(feature_id)

    base = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'integration': 'openclaw',
        'channel': message['channel'],
        'sender': message['sender'],
        'actor': actor,
        'text': text,
        'feature_id': feature_id,
        'command': command,
        'backend_action': None,
        'guardrails': openclaw_guardrails(),
    }

    forbidden = forbidden_mutation_requested(text)
    if forbidden:
        return {
            **base,
            'accepted': False,
            'status': 'blocked',
            'response_text': 'Blocked: OpenClaw cannot mutate scanner rules, suppressions, parser code, or scanner config. Use backend approval workflows and benchmark gates.',
            'payload': {'reason': forbidden},
        }

    if not feature:
        return help_response(base, accepted=False)
    if not feature.get('enabled'):
        return {
            **base,
            'accepted': False,
            'status': 'disabled',
            'response_text': f'Feature is disabled: {feature["title"]}.',
            'payload': {'feature': feature},
        }

    try:
        if feature_id == 'scan-status':
            return handle_scan_status(base, command)
        if feature_id == 'approval-requests':
            return handle_approval_requests(base, command)
        if feature_id == 'quarantine-alerts':
            return handle_quarantine_alert(base, command)
        if feature_id == 'explain-finding':
            return handle_explain_finding(base, command)
        if feature_id == 'approve-memory-lesson':
            return handle_approve_lesson(base, command, actor)
        if feature_id == 'rerun-disposable-vm':
            return handle_rerun_vm(base, command, actor)
    except FileNotFoundError as exc:
        return error_response(base, 'not_found', str(exc))
    except ValueError as exc:
        return error_response(base, 'rejected', str(exc))
    except OpenClawError as exc:
        return error_response(base, 'rejected', str(exc))
    return help_response(base, accepted=False)


def handle_scan_status(base: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
    scan = resolve_scan(command.get('scan_id'))
    payload = scan_status_payload(scan)
    return {
        **base,
        'accepted': True,
        'status': 'completed',
        'response_text': f"Scan {scan.scan_id} for {scan.project_name}: {scan.summary.total_findings} findings, max risk {scan.summary.max_risk_score}.",
        'backend_action': {'method': 'GET', 'path': f'/api/scans/{scan.scan_id}', 'executed': True, 'mutating': False},
        'payload': payload,
    }


def handle_approval_requests(base: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
    state = command.get('state') or None
    queue = approval_queue(state=state)
    return {
        **base,
        'accepted': True,
        'status': 'completed',
        'response_text': f'OpenClaw found {queue["count"]} benchmark lesson approval item(s).',
        'backend_action': {'method': 'GET', 'path': '/api/benchmark-gate/lessons', 'executed': True, 'mutating': False},
        'payload': queue,
    }


def handle_quarantine_alert(base: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
    target = command.get('target') or ''
    if not target:
        scan = resolve_scan(None)
        policy = quarantine_policy_for_scan(scan)
        target = scan.scan_id
    else:
        try:
            scan = load_scan(target)
            policy = quarantine_policy_for_scan(scan)
        except FileNotFoundError:
            policy = quarantine_policy(target)
    return {
        **base,
        'accepted': True,
        'status': 'completed',
        'response_text': f"Quarantine status for {target}: {policy.get('status', 'unknown')}.",
        'backend_action': {'method': 'POST', 'path': '/api/quarantine/lookup', 'executed': True, 'mutating': False},
        'payload': {'target': target, 'quarantine_policy': policy},
    }


def handle_explain_finding(base: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
    scan_id = command.get('scan_id')
    finding_id = command.get('finding_id')
    if not scan_id or not finding_id:
        raise OpenClawError('Use: explain <scan_id> <finding_id>.')
    scan = apply_decisions(load_scan(scan_id))
    review = build_finding_ai_review(scan, finding_id, provider='offline', include_prompts=False)
    explanation = review.get('ai_explanation', {}).get('text', '')
    return {
        **base,
        'accepted': True,
        'status': 'completed',
        'response_text': safe_line(explanation, 900) or f'Explanation generated for finding {finding_id}.',
        'backend_action': {'method': 'GET', 'path': f'/api/scans/{scan_id}/findings/{finding_id}/ai-review', 'executed': True, 'mutating': False},
        'payload': {
            'scan_id': scan_id,
            'finding_id': finding_id,
            'scenario': review.get('scenario', {}),
            'finding': review.get('finding', {}),
            'ai_explanation': review.get('ai_explanation', {}),
            'remediation_suggestion': review.get('remediation_suggestion', {}),
        },
    }


def handle_approve_lesson(base: dict[str, Any], command: dict[str, Any], actor: str) -> dict[str, Any]:
    lesson_id = command.get('lesson_id')
    target_state = command.get('target_state') or 'approved'
    if not lesson_id:
        raise OpenClawError('Use: approve lesson <lesson_id>, review lesson <lesson_id>, or activate lesson <lesson_id>.')
    lesson = transition_benchmark_lesson(
        lesson_id,
        target_state,
        actor=actor,
        note=f"OpenClaw {base['channel']} request from {base['sender'] or actor}",
    )
    return {
        **base,
        'accepted': True,
        'status': 'completed',
        'response_text': f"Lesson {lesson_id} moved to {lesson['promotion_state']}. Influence allowed={lesson['learning_influence_allowed']}.",
        'backend_action': {
            'method': 'POST',
            'path': f'/api/benchmark-gate/lessons/{lesson_id}/transition',
            'executed': True,
            'mutating': True,
            'scanner_rule_mutation_allowed': False,
        },
        'payload': {'lesson': lesson},
    }


def handle_rerun_vm(base: dict[str, Any], command: dict[str, Any], actor: str) -> dict[str, Any]:
    scan = resolve_scan(command.get('scan_id'))
    approved_quarantine = bool(command.get('approved_quarantine'))
    job = create_vm_scan_job(
        repository_path=scan.target_path,
        project_name=scan.project_name,
        output_root_path=None,
        reports_dir='reports',
        run_id=f'openclaw-{scan.scan_id}',
        network_policy='offline',
        approved_quarantine=approved_quarantine,
        job_name=f'openclaw-{scan.project_name}-{scan.scan_id}',
    )
    return {
        **base,
        'accepted': True,
        'status': 'prepared',
        'response_text': f"Disposable VM job prepared for {scan.project_name}: {job['job_id']}. Launch is still a human action.",
        'backend_action': {
            'method': 'POST',
            'path': '/api/vm-worker/jobs',
            'executed': True,
            'mutating': True,
            'scanner_rule_mutation_allowed': False,
            'launch_executed': False,
        },
        'payload': {'job': job},
    }


def normalize_openclaw_message(payload: dict[str, Any]) -> dict[str, Any]:
    channel = normalize_channel(payload.get('channel') or payload.get('provider') or payload.get('platform') or 'api')
    text = str(payload.get('text') or payload.get('message') or payload.get('command') or '')
    sender = str(payload.get('user') or payload.get('sender') or payload.get('from') or '')
    channel_id = str(payload.get('channel_id') or payload.get('chat_id') or payload.get('to') or '')

    telegram_message = payload.get('message') if isinstance(payload.get('message'), dict) else {}
    if telegram_message:
        text = str(telegram_message.get('text') or text)
        sender_data = telegram_message.get('from') if isinstance(telegram_message.get('from'), dict) else {}
        chat_data = telegram_message.get('chat') if isinstance(telegram_message.get('chat'), dict) else {}
        sender = str(sender_data.get('username') or sender_data.get('id') or sender)
        channel_id = str(chat_data.get('id') or channel_id)

    messages = payload.get('messages')
    if isinstance(messages, list) and messages:
        first = messages[0] if isinstance(messages[0], dict) else {}
        body = first.get('text') if isinstance(first.get('text'), dict) else {}
        text = str(body.get('body') or first.get('body') or text)
        sender = str(first.get('from') or sender)

    return {
        'channel': channel,
        'text': text.strip(),
        'sender': sender,
        'channel_id': channel_id,
        'metadata': payload.get('metadata') if isinstance(payload.get('metadata'), dict) else {},
    }


def parse_openclaw_command(text: str) -> dict[str, Any]:
    normalized = re.sub(r'\s+', ' ', str(text or '').strip())
    lowered = normalized.lower()
    tokens = normalized.split()
    lower_tokens = lowered.split()
    if not tokens:
        return {'feature_id': 'help', 'args': []}
    if lowered in {'help', '/help'}:
        return {'feature_id': 'help', 'args': []}
    if lowered.startswith('/approve '):
        lesson_id = tokens[1] if len(tokens) > 1 else ''
        decision = lower_tokens[2] if len(lower_tokens) > 2 else 'approved'
        return {'feature_id': 'approve-memory-lesson', 'lesson_id': lesson_id, 'target_state': normalize_lesson_decision(decision), 'args': tokens[1:]}
    if lowered.startswith('approve lesson '):
        return {'feature_id': 'approve-memory-lesson', 'lesson_id': tokens[2] if len(tokens) > 2 else '', 'target_state': 'approved', 'args': tokens[2:]}
    if lowered.startswith('review lesson '):
        return {'feature_id': 'approve-memory-lesson', 'lesson_id': tokens[2] if len(tokens) > 2 else '', 'target_state': 'reviewed', 'args': tokens[2:]}
    if lowered.startswith('activate lesson '):
        return {'feature_id': 'approve-memory-lesson', 'lesson_id': tokens[2] if len(tokens) > 2 else '', 'target_state': 'active', 'args': tokens[2:]}
    if lowered.startswith('explain '):
        return {'feature_id': 'explain-finding', 'scan_id': tokens[1] if len(tokens) > 1 else '', 'finding_id': tokens[2] if len(tokens) > 2 else '', 'args': tokens[1:]}
    if lowered.startswith('quarantine'):
        return {'feature_id': 'quarantine-alerts', 'target': tokens[1] if len(tokens) > 1 else '', 'args': tokens[1:]}
    if lowered.startswith('approvals') or lowered.startswith('approval requests') or lowered.startswith('pending approvals'):
        state = next((item for item in lower_tokens if item in {'proposed', 'reviewed', 'benchmarked', 'approved', 'active'}), '')
        return {'feature_id': 'approval-requests', 'state': state, 'args': tokens[1:]}
    if (
        lowered.startswith('rerun vm')
        or lowered.startswith('rerun disposable vm')
        or lowered.startswith('rerun repo in vm')
        or lowered.startswith('rerun repo in disposable vm')
        or lowered.startswith('rerun this repo in disposable vm')
    ):
        ignored = {'rerun', 'vm', 'disposable', 'repo', 'in', 'this', 'current', 'approved', 'quarantine'}
        scan_id = next((item for item in tokens if item.lower() not in ignored), '')
        return {
            'feature_id': 'rerun-disposable-vm',
            'scan_id': scan_id,
            'approved_quarantine': 'approved' in lower_tokens and 'quarantine' in lower_tokens,
            'args': tokens[2:],
        }
    if lowered.startswith('scan status') or lowered.startswith('status') or lowered.startswith('latest'):
        scan_id = ''
        for item in tokens[1:]:
            if item.lower() not in {'status', 'latest'}:
                scan_id = item
                break
        return {'feature_id': 'scan-status', 'scan_id': scan_id, 'args': tokens[1:]}
    return {'feature_id': 'help', 'args': tokens}


def resolve_scan(scan_id: str | None):
    if scan_id and scan_id.lower() != 'latest':
        return apply_decisions(load_scan(scan_id))
    scans = list_scans()
    if not scans:
        raise FileNotFoundError('no saved scans are available')
    return apply_decisions(scans[0])


def scan_status_payload(scan) -> dict[str, Any]:
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'created_at': scan.created_at.isoformat(),
        'summary': {
            'total_findings': scan.summary.total_findings,
            'files_scanned': scan.summary.files_scanned,
            'production_findings': scan.summary.production_findings,
            'hygiene_findings': scan.summary.hygiene_findings,
            'max_risk_score': scan.summary.max_risk_score,
            'avg_risk_score': scan.summary.avg_risk_score,
            'priorities': scan.summary.priorities,
            'risk_tiers': scan.summary.risk_tiers,
            'tools': scan.summary.tools,
        },
        'quarantine_status': quarantine_policy_for_scan(scan).get('status'),
    }


def approval_queue(state: str | None = None) -> dict[str, Any]:
    requested_state = state or None
    lessons = list_benchmark_lessons(state=requested_state).get('lessons', [])
    pending = [lesson for lesson in lessons if lesson.get('promotion_state') != 'active'][:25]
    return {
        'count': len(pending),
        'state': requested_state or 'all-pending',
        'lessons': [
            {
                'lesson_id': lesson.get('lesson_id'),
                'language': lesson.get('language'),
                'category': lesson.get('category'),
                'title': lesson.get('title'),
                'promotion_state': lesson.get('promotion_state'),
                'learning_influence_allowed': lesson.get('learning_influence_allowed'),
            }
            for lesson in pending
        ],
    }


def command_examples(scan) -> list[str]:
    finding = scan.findings[0].id if scan.findings else '<finding_id>'
    return [
        f'status {scan.scan_id}',
        f'explain {scan.scan_id} {finding}',
        'approvals',
        'approve lesson <lesson_id>',
        f'rerun vm {scan.scan_id}',
        f'quarantine {scan.scan_id}',
    ]


def normalize_channel(value: Any) -> str:
    channel = str(value or 'api').lower().strip()
    return channel if channel in OPENCLAW_CHANNELS else 'api'


def normalize_lesson_decision(value: str) -> str:
    normalized = value.lower().strip()
    if normalized in {'review', 'reviewed'}:
        return 'reviewed'
    if normalized in {'approve', 'approved', 'allow', 'allow-once', 'allow-always'}:
        return 'approved'
    if normalized in {'activate', 'active'}:
        return 'active'
    if normalized == 'benchmarked':
        return 'benchmarked'
    if normalized in {'deny', 'denied'}:
        raise OpenClawError('Deny is recorded by leaving the lesson unpromoted; no scanner/rule change was made.')
    raise OpenClawError(f'Unsupported approval decision: {value}')


def forbidden_mutation_requested(text: str) -> str:
    lowered = text.lower()
    return next((word for word in FORBIDDEN_MUTATION_WORDS if word in lowered), '')


def help_response(base: dict[str, Any], accepted: bool) -> dict[str, Any]:
    commands = []
    for feature in openclaw_feature_registry().values():
        if feature.get('enabled'):
            commands.extend(feature.get('commands', [])[:2])
    return {
        **base,
        'accepted': accepted,
        'status': 'help',
        'response_text': 'OpenClaw commands: ' + ', '.join(commands),
        'payload': {'features': list(openclaw_feature_registry().values())},
    }


def error_response(base: dict[str, Any], status: str, message: str) -> dict[str, Any]:
    return {
        **base,
        'accepted': False,
        'status': status,
        'response_text': message,
        'payload': {'error': message},
    }


def openclaw_guardrails() -> list[str]:
    return [
        'OpenClaw is a chat/control frontend; scanner rules, parser code, suppressions, and scanner config are never mutated directly.',
        'Approval commands call backend approval APIs such as the Benchmark Gate transition endpoint.',
        'Disposable VM reruns prepare a worker job only; launching the VM remains a human action.',
        'Finding explanations use existing AI review APIs and do not include raw source or patches.',
        'Inbound chat text is treated as untrusted command input and must pass backend auth/policy gates.',
    ]


def safe_line(value: str, limit: int) -> str:
    text = re.sub(r'\s+', ' ', str(value or '')).strip()
    return text if len(text) <= limit else f'{text[: limit - 14].rstrip()}...[truncated]'
