from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .governance import record_governance_event
from .models import InsideOutAutofixLoopRequest, ScanResult, VerifiedAutofixRequest
from .paths import data_dir
from .scanner import run_scan
from .soundness import soundness_verdict
from .verified_autofix import run_verified_autofix

REPORT_SCHEMA = 'inside-out-autofix-loop-v1'
PHASE2A_MAX_ITERATIONS = 1
PASSED_AUTOFIX_STATUSES = {'verified', 'pr_opened'}
LOOP_RUNS_DIRNAME = 'inside-out-autofix-loops'

ScannerFn = Callable[[Path, str | None], ScanResult]


def run_inside_out_autofix_loop(
    scan: ScanResult,
    request: InsideOutAutofixLoopRequest,
    actor: str = 'system',
    scanner_fn: ScannerFn | None = None,
) -> dict[str, Any]:
    scanner_fn = scanner_fn or rescan_target
    initial_verdict = soundness_verdict(scan)
    selected = select_loop_issues(initial_verdict, request)
    selected_finding_ids = selected_finding_ids_for_issues(selected, request)
    report = base_report(scan, request, actor, initial_verdict, selected, selected_finding_ids)

    if initial_verdict['verdict']['status'] == 'pass' and not selected:
        report['status'] = 'already_sound'
        report['gate'] = 'passed'
        report['termination'] = 'initial_soundness_gate_passed'
        return finalize_loop_report(report, request)
    if not selected_finding_ids:
        report['status'] = 'no_eligible_fixes'
        report['gate'] = 'blocked'
        report['termination'] = 'no_soundness_queue_items_selected'
        return finalize_loop_report(report, request)

    verified_request = verified_request_from_loop(request, selected_finding_ids)
    autofix_report = run_verified_autofix(scan, verified_request, actor=actor)
    iteration = iteration_record(1, selected, selected_finding_ids, autofix_report)
    report['iterations'].append(iteration)
    report['summary']['iterations_attempted'] = 1
    report['summary']['autofix_status'] = autofix_report['status']

    if request.dry_run:
        report['status'] = 'dry_run'
        report['gate'] = 'not_run'
        report['termination'] = 'dry_run_no_files_changed'
        return finalize_loop_report(report, request)

    if autofix_report['status'] not in PASSED_AUTOFIX_STATUSES:
        report['status'] = autofix_report['status']
        report['gate'] = autofix_report.get('gate') or 'failed'
        report['termination'] = 'verified_autofix_did_not_reach_green_test_gate'
        return finalize_loop_report(report, request)

    if not request.rescan_after_apply:
        report['status'] = 'verified_without_rescan'
        report['gate'] = 'blocked'
        report['termination'] = 'rescan_gate_disabled'
        report['blocked_reasons'].append('rescan_after_apply=true is required for Phase 2A closure')
        return finalize_loop_report(report, request)

    worktree_target = rescan_path_from_autofix(scan, autofix_report)
    if not worktree_target:
        report['status'] = 'rescan_failed'
        report['gate'] = 'failed'
        report['termination'] = 'could_not_resolve_worktree_rescan_path'
        report['blocked_reasons'].append('verified autofix did not report a usable worktree path')
        return finalize_loop_report(report, request)

    try:
        rescan = scanner_fn(worktree_target, scan.project_name)
    except Exception as exc:  # defensive: loop reports scanner failures instead of hiding them
        report['status'] = 'rescan_failed'
        report['gate'] = 'failed'
        report['termination'] = 'rescan_exception'
        report['blocked_reasons'].append(str(exc)[:1000])
        return finalize_loop_report(report, request)

    rescan_verdict = soundness_verdict(rescan)
    verification = verify_loop_resolution(initial_verdict, rescan_verdict, selected)
    iteration['rescan'] = rescan_summary(rescan, rescan_verdict)
    iteration['verification'] = verification
    report['rescan'] = iteration['rescan']
    report['verification'] = verification
    report['anti_oscillation'] = anti_oscillation(initial_verdict, rescan_verdict, verification)
    report['summary'].update({
        'resolved_issues': len(verification['resolved_issue_ids']),
        'unresolved_issues': len(verification['unresolved_issue_ids']),
        'new_blockers': len(verification['new_blocker_issue_ids']),
    })

    if verification['new_blocker_issue_ids']:
        report['status'] = 'new_blockers'
        report['gate'] = 'blocked'
        report['termination'] = 'rescan_found_new_blockers'
    elif verification['unresolved_issue_ids']:
        report['status'] = 'max_iterations_reached'
        report['gate'] = 'blocked'
        report['termination'] = 'selected_issues_still_present_after_phase2a_iteration'
    else:
        report['status'] = 'resolved'
        report['gate'] = 'passed'
        report['termination'] = 'selected_issues_resolved_without_new_blockers'
    return finalize_loop_report(report, request)


def rescan_target(target: Path, project_name: str | None) -> ScanResult:
    return run_scan(target, project_name=project_name)


def finalize_loop_report(report: dict[str, Any], request: InsideOutAutofixLoopRequest) -> dict[str, Any]:
    if not request.persist:
        return report
    events = record_loop_governance_events(report)
    report['governance'] = {
        'event_ids': [event['event_id'] for event in events],
        'event_count': len(events),
        'category': 'agent-action',
    }
    path = save_inside_out_autofix_loop_run(report)
    report['storage'] = {
        'persisted': True,
        'record_path': str(path),
        'record_path_hash': stable_id(str(path)),
    }
    path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


def save_inside_out_autofix_loop_run(report: dict[str, Any]) -> Path:
    path = loop_run_path(str(report['scan_id']), str(report['loop_id']))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    return path


def list_inside_out_autofix_loop_runs(scan_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    root = loop_runs_dir()
    if not root.exists():
        return []
    if scan_id:
        paths = list((root / safe_id(scan_id)).glob('*.json'))
    else:
        paths = list(root.glob('*/*.json'))
    runs: list[dict[str, Any]] = []
    for path in paths:
        try:
            runs.append(loop_run_card(json.loads(path.read_text(encoding='utf-8'))))
        except Exception:
            continue
    runs.sort(key=lambda item: item.get('generated_at') or '', reverse=True)
    return runs[:max(0, min(limit, 1000))]


def load_inside_out_autofix_loop_run(loop_id: str) -> dict[str, Any]:
    requested = safe_id(loop_id)
    for path in loop_runs_dir().glob(f'*/{requested}.json'):
        return json.loads(path.read_text(encoding='utf-8'))
    raise FileNotFoundError(loop_id)


def loop_runs_dir() -> Path:
    return data_dir() / LOOP_RUNS_DIRNAME


def loop_run_path(scan_id: str, loop_id: str) -> Path:
    return loop_runs_dir() / safe_id(scan_id) / f'{safe_id(loop_id)}.json'


def base_report(
    scan: ScanResult,
    request: InsideOutAutofixLoopRequest,
    actor: str,
    initial_verdict: dict[str, Any],
    selected: list[dict[str, Any]],
    selected_finding_ids: list[str],
) -> dict[str, Any]:
    return {
        'schema_version': REPORT_SCHEMA,
        'loop_id': new_loop_id(),
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'actor': actor,
        'status': 'initialized',
        'gate': 'not_run',
        'dry_run': request.dry_run,
        'termination': '',
        'blocked_reasons': [],
        'policy': {
            'phase': '2A',
            'max_iterations_requested': max(1, request.max_iterations),
            'max_iterations_supported': PHASE2A_MAX_ITERATIONS,
            'queue_source': 'soundness.agent_fix_queue',
            'safe_autofix_only': request.safe_autofix_only,
            'requires_verified_autofix_green_gate': True,
            'requires_rescan_after_apply': True,
            'requires_no_new_blockers': True,
            'anti_oscillation_enabled': True,
            'persist_requested': request.persist,
            'raw_code_included': False,
        },
        'summary': {
            'initial_status': initial_verdict['verdict']['status'],
            'initial_blocking_issue_count': initial_verdict['verdict']['blocking_issue_count'],
            'initial_agent_fix_queue_count': initial_verdict['summary']['agent_fix_queue_count'],
            'selected_issue_count': len(selected),
            'selected_finding_count': len(selected_finding_ids),
            'iterations_attempted': 0,
            'autofix_status': '',
            'resolved_issues': 0,
            'unresolved_issues': 0,
            'new_blockers': 0,
        },
        'initial_soundness': compact_verdict(initial_verdict),
        'selected_issues': selected_issue_records(selected),
        'selected_finding_ids': selected_finding_ids,
        'iterations': [],
        'rescan': None,
        'verification': None,
        'anti_oscillation': None,
        'storage': {'persisted': False, 'record_path': '', 'record_path_hash': ''},
        'governance': {'event_ids': [], 'event_count': 0},
    }


def select_loop_issues(verdict: dict[str, Any], request: InsideOutAutofixLoopRequest) -> list[dict[str, Any]]:
    requested_issues = set(request.issue_ids)
    requested_findings = set(request.finding_ids)
    queue_ids = {item['issue_id'] for item in verdict.get('agent_fix_queue', [])}
    candidates = [issue for issue in verdict.get('issues', []) if issue.get('issue_id') in queue_ids]
    if request.safe_autofix_only:
        candidates = [issue for issue in candidates if issue.get('agent', {}).get('safe_autofix_candidate')]
    if requested_issues:
        candidates = [issue for issue in candidates if issue.get('issue_id') in requested_issues]
    if requested_findings:
        candidates = [
            issue for issue in candidates
            if requested_findings.intersection(issue.get('evidence', {}).get('finding_ids', []))
        ]
    return sorted(candidates, key=lambda item: int(item.get('rank') or 0))[:max(1, request.limit)]


def selected_finding_ids_for_issues(issues: list[dict[str, Any]], request: InsideOutAutofixLoopRequest) -> list[str]:
    requested = set(request.finding_ids)
    selected: list[str] = []
    for issue in issues:
        finding_ids = [str(item) for item in issue.get('evidence', {}).get('finding_ids', []) if item]
        if requested:
            finding_ids = [item for item in finding_ids if item in requested]
        if finding_ids:
            selected.append(sorted(finding_ids)[0])
    return dedupe(selected)[:max(1, request.limit)]


def verified_request_from_loop(request: InsideOutAutofixLoopRequest, finding_ids: list[str]) -> VerifiedAutofixRequest:
    return VerifiedAutofixRequest(
        finding_ids=finding_ids,
        limit=request.limit,
        provider=request.provider,
        model=request.model,
        dry_run=request.dry_run,
        approved=request.approved,
        allow_placeholders=request.allow_placeholders,
        branch_name=request.branch_name,
        base_branch=request.base_branch,
        remote=request.remote,
        test_commands=request.test_commands,
        test_timeout_seconds=request.test_timeout_seconds,
        allow_auto_detect_tests=request.allow_auto_detect_tests,
        push_branch=request.push_branch,
        publish_pr=request.publish_pr,
        pr_title=request.pr_title,
        pr_body=request.pr_body,
        commit_message=request.commit_message,
    )


def iteration_record(index: int, selected: list[dict[str, Any]], finding_ids: list[str], autofix_report: dict[str, Any]) -> dict[str, Any]:
    return {
        'iteration': index,
        'selected_issue_ids': [issue['issue_id'] for issue in selected],
        'selected_finding_ids': finding_ids,
        'verified_autofix': autofix_report,
        'rescan': None,
        'verification': None,
    }


def rescan_path_from_autofix(scan: ScanResult, autofix_report: dict[str, Any]) -> Path | None:
    raw_worktree = (autofix_report.get('branch') or {}).get('worktree_path') or ''
    if not raw_worktree:
        return None
    worktree = Path(raw_worktree)
    subpath = (autofix_report.get('git') or {}).get('target_subpath') or ''
    target = worktree / subpath if subpath and subpath not in {'.', './'} else worktree
    return target if target.exists() else worktree


def verify_loop_resolution(initial: dict[str, Any], rescan: dict[str, Any], selected: list[dict[str, Any]]) -> dict[str, Any]:
    selected_keys = {issue_key(issue): issue['issue_id'] for issue in selected}
    rescan_by_key = {issue_key(issue): issue for issue in rescan.get('issues', [])}
    initial_blocking_keys = {
        issue_key(issue)
        for issue in initial.get('issues', [])
        if issue.get('gate', {}).get('effect') == 'block'
    }
    new_blockers = [
        issue for issue in rescan.get('issues', [])
        if issue.get('gate', {}).get('effect') == 'block' and issue_key(issue) not in initial_blocking_keys
    ]
    resolved = [issue_id for key, issue_id in selected_keys.items() if key not in rescan_by_key]
    unresolved = [issue_id for key, issue_id in selected_keys.items() if key in rescan_by_key]
    return {
        'resolved_issue_ids': sorted(resolved),
        'unresolved_issue_ids': sorted(unresolved),
        'new_blocker_issue_ids': sorted(issue['issue_id'] for issue in new_blockers),
        'new_blocker_keys': sorted(issue_key(issue) for issue in new_blockers),
        'rescan_status': rescan['verdict']['status'],
        'rescan_replay_digest': rescan['determinism']['replay_digest'],
    }


def rescan_summary(scan: ScanResult, verdict: dict[str, Any]) -> dict[str, Any]:
    return {
        'scan_id': scan.scan_id,
        'target_path_hash': verdict['subject']['target_path_hash'],
        'finding_count': verdict['summary']['finding_count'],
        'consolidated_issue_count': verdict['summary']['consolidated_issue_count'],
        'agent_fix_queue_count': verdict['summary']['agent_fix_queue_count'],
        'verdict': verdict['verdict'],
        'determinism': verdict['determinism'],
    }


def anti_oscillation(initial: dict[str, Any], rescan: dict[str, Any], verification: dict[str, Any]) -> dict[str, Any]:
    initial_digest = initial['determinism']['replay_digest']
    rescan_digest = rescan['determinism']['replay_digest']
    initial_issue_digest = issue_set_digest(initial)
    rescan_issue_digest = issue_set_digest(rescan)
    no_progress = bool(verification['unresolved_issue_ids']) and initial_issue_digest == rescan_issue_digest
    return {
        'initial_replay_digest': initial_digest,
        'rescan_replay_digest': rescan_digest,
        'initial_issue_set_digest': initial_issue_digest,
        'rescan_issue_set_digest': rescan_issue_digest,
        'no_progress_detected': no_progress,
        'repeated_digest_count': 1 if no_progress else 0,
        'action': 'stop_loop' if no_progress else 'continue_only_if_policy_allows_more_iterations',
    }


def compact_verdict(verdict: dict[str, Any]) -> dict[str, Any]:
    return {
        'schema_version': verdict['schema_version'],
        'subject': verdict['subject'],
        'verdict': verdict['verdict'],
        'summary': verdict['summary'],
        'agent_loop_readiness': verdict.get('agent_loop_readiness'),
        'determinism': verdict['determinism'],
    }


def selected_issue_records(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            'rank': issue.get('rank'),
            'issue_id': issue['issue_id'],
            'agent_correlation_key': issue['correlation']['agent_correlation_key'],
            'priority': issue['priority'],
            'gate': issue['gate'],
            'location': issue['location'],
            'finding_ids': issue.get('evidence', {}).get('finding_ids', []),
            'safe_autofix_candidate': issue.get('agent', {}).get('safe_autofix_candidate', False),
            'remediation_class': issue.get('agent', {}).get('safety', {}).get('remediation_class', ''),
        }
        for issue in issues
    ]


def issue_key(issue: dict[str, Any]) -> str:
    return str((issue.get('correlation') or {}).get('agent_correlation_key') or issue.get('issue_id') or '')


def issue_set_digest(verdict: dict[str, Any]) -> str:
    payload = json.dumps(sorted(issue_key(issue) for issue in verdict.get('issues', [])), separators=(',', ':'))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def record_loop_governance_events(report: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    loop_id = str(report.get('loop_id') or '')
    scan_id = str(report.get('scan_id') or '')
    actor = str(report.get('actor') or 'system')
    selected_issue_ids = [item.get('issue_id') for item in report.get('selected_issues', [])]
    selected_finding_ids = report.get('selected_finding_ids', [])
    common = {
        'actor': actor,
        'category': 'agent-action',
        'resource': loop_id,
        'scan_id': scan_id,
    }
    events.append(record_governance_event(
        **common,
        action='inside_out_loop.requested',
        reason='Inside-out autofix loop was requested from a soundness verdict.',
        metadata=loop_metadata(report),
        evidence_refs=loop_evidence_refs(report),
    ))
    if selected_issue_ids:
        events.append(record_governance_event(
            **common,
            action='inside_out_loop.issues_selected',
            reason='Loop selected issues from soundness.agent_fix_queue.',
            metadata={'selected_issue_count': len(selected_issue_ids), 'selected_finding_count': len(selected_finding_ids)},
            evidence_refs={'loop_id': loop_id, 'scan_id': scan_id, 'selected_issue_ids': selected_issue_ids, 'selected_finding_ids': selected_finding_ids},
        ))
    if report.get('iterations'):
        iteration = report['iterations'][0]
        autofix = iteration.get('verified_autofix') or {}
        events.append(record_governance_event(
            **common,
            action='inside_out_loop.verified_autofix_invoked',
            reason='Loop invoked verified autofix as its controlled edit mechanism.',
            metadata={
                'autofix_status': autofix.get('status', ''),
                'autofix_gate': autofix.get('gate', ''),
                'dry_run': str(bool(report.get('dry_run'))),
                'commit_sha': (autofix.get('branch') or {}).get('commit_sha', ''),
            },
            evidence_refs=loop_evidence_refs(report),
        ))
        test_action = test_governance_action(autofix)
        if test_action:
            events.append(record_governance_event(
                **common,
                action=test_action,
                reason='Loop recorded the verified autofix test gate outcome.',
                metadata=test_metadata(autofix),
                evidence_refs={'loop_id': loop_id, 'scan_id': scan_id, 'test_commands': test_command_names(autofix)},
            ))
    if report.get('rescan'):
        rescan_status = ((report.get('rescan') or {}).get('verdict') or {}).get('status', '')
        events.append(record_governance_event(
            **common,
            action='inside_out_loop.rescan_passed' if report.get('gate') == 'passed' else 'inside_out_loop.rescan_failed',
            reason='Loop reran the inside-out soundness gate after the verified autofix test gate.',
            metadata={
                'rescan_status': rescan_status,
                'resolved_issues': str((report.get('summary') or {}).get('resolved_issues', 0)),
                'unresolved_issues': str((report.get('summary') or {}).get('unresolved_issues', 0)),
                'new_blockers': str((report.get('summary') or {}).get('new_blockers', 0)),
            },
            evidence_refs=loop_evidence_refs(report),
        ))
    events.append(record_governance_event(
        **common,
        action='inside_out_loop.completed',
        reason=str(report.get('termination') or 'Inside-out autofix loop completed.'),
        metadata=loop_metadata(report),
        evidence_refs=loop_evidence_refs(report),
    ))
    return events


def loop_run_card(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get('summary') or {}
    storage = report.get('storage') or {}
    return {
        'schema_version': report.get('schema_version', REPORT_SCHEMA),
        'loop_id': report.get('loop_id'),
        'generated_at': report.get('generated_at'),
        'scan_id': report.get('scan_id'),
        'project_name': report.get('project_name'),
        'actor': report.get('actor'),
        'status': report.get('status'),
        'gate': report.get('gate'),
        'dry_run': bool(report.get('dry_run')),
        'termination': report.get('termination'),
        'selected_issue_count': summary.get('selected_issue_count', 0),
        'selected_finding_count': summary.get('selected_finding_count', 0),
        'iterations_attempted': summary.get('iterations_attempted', 0),
        'resolved_issues': summary.get('resolved_issues', 0),
        'unresolved_issues': summary.get('unresolved_issues', 0),
        'new_blockers': summary.get('new_blockers', 0),
        'persisted': bool(storage.get('persisted')),
        'record_path_hash': storage.get('record_path_hash', ''),
        'governance_event_count': (report.get('governance') or {}).get('event_count', 0),
    }


def loop_metadata(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get('summary') or {}
    return {
        'loop_id': report.get('loop_id'),
        'status': report.get('status'),
        'gate': report.get('gate'),
        'termination': report.get('termination'),
        'dry_run': str(bool(report.get('dry_run'))),
        'selected_issue_count': str(summary.get('selected_issue_count', 0)),
        'selected_finding_count': str(summary.get('selected_finding_count', 0)),
        'iterations_attempted': str(summary.get('iterations_attempted', 0)),
        'resolved_issues': str(summary.get('resolved_issues', 0)),
        'unresolved_issues': str(summary.get('unresolved_issues', 0)),
        'new_blockers': str(summary.get('new_blockers', 0)),
    }


def loop_evidence_refs(report: dict[str, Any]) -> dict[str, Any]:
    iteration = (report.get('iterations') or [{}])[0]
    autofix = iteration.get('verified_autofix') or {}
    return {
        'loop_id': report.get('loop_id'),
        'scan_id': report.get('scan_id'),
        'selected_issue_ids': [item.get('issue_id') for item in report.get('selected_issues', [])],
        'selected_finding_ids': report.get('selected_finding_ids', []),
        'initial_soundness': {
            'status': ((report.get('initial_soundness') or {}).get('verdict') or {}).get('status', ''),
            'blocking_issue_count': ((report.get('initial_soundness') or {}).get('verdict') or {}).get('blocking_issue_count', 0),
            'replay_digest': ((report.get('initial_soundness') or {}).get('determinism') or {}).get('replay_digest', ''),
        },
        'verified_autofix': {
            'status': autofix.get('status', ''),
            'gate': autofix.get('gate', ''),
            'selected_finding_ids': autofix.get('selected_finding_ids', []),
            'commit_sha': (autofix.get('branch') or {}).get('commit_sha', ''),
            'pushed': bool((autofix.get('branch') or {}).get('pushed', False)),
            'pull_request_created': bool((autofix.get('pull_request') or {}).get('created', False)),
        },
        'rescan': {
            'status': (((report.get('rescan') or {}).get('verdict') or {}).get('status', '')),
            'replay_digest': (((report.get('rescan') or {}).get('determinism') or {}).get('replay_digest', '')),
        },
        'anti_oscillation': report.get('anti_oscillation') or {},
    }


def test_governance_action(autofix: dict[str, Any]) -> str:
    tests = (autofix.get('verification') or {}).get('tests') or []
    if not tests:
        return ''
    return 'inside_out_loop.tests_passed' if all(item.get('passed') for item in tests) else 'inside_out_loop.tests_failed'


def test_metadata(autofix: dict[str, Any]) -> dict[str, str]:
    tests = (autofix.get('verification') or {}).get('tests') or []
    return {
        'test_count': str(len(tests)),
        'passed': str(all(item.get('passed') for item in tests) if tests else False),
        'timed_out': str(any(item.get('timed_out') for item in tests)),
    }


def test_command_names(autofix: dict[str, Any]) -> list[str]:
    return [
        stable_id(str(item.get('command') or ''))
        for item in ((autofix.get('verification') or {}).get('tests') or [])
    ]


def new_loop_id() -> str:
    return f'iol-{uuid.uuid4().hex[:16]}'


def safe_id(value: str) -> str:
    text = re.sub(r'[^A-Za-z0-9_.-]+', '-', str(value or '').strip()).strip('-._')
    return text[:120] or 'unknown'


def stable_id(value: str) -> str:
    return hashlib.sha256(str(value or '').encode('utf-8')).hexdigest()[:24]


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
