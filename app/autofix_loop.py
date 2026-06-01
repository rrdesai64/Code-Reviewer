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
TASK_PACKET_SCHEMA = 'inside-out-agent-task-v1'
PHASE2C_MAX_ITERATIONS = 5
PASSED_AUTOFIX_STATUSES = {'verified', 'pr_opened'}
LOOP_RUNS_DIRNAME = 'inside-out-autofix-loops'

ScannerFn = Callable[[Path, str | None], ScanResult]
AutofixFn = Callable[[ScanResult, VerifiedAutofixRequest, str], dict[str, Any]]


def run_inside_out_autofix_loop(
    scan: ScanResult,
    request: InsideOutAutofixLoopRequest,
    actor: str = 'system',
    scanner_fn: ScannerFn | None = None,
    autofix_fn: AutofixFn | None = None,
) -> dict[str, Any]:
    scanner_fn = scanner_fn or rescan_target
    autofix_fn = autofix_fn or run_verified_autofix
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

    active_scan = scan
    active_verdict = initial_verdict
    active_selected = selected
    max_iterations = bounded_max_iterations(request)

    for index in range(1, max_iterations + 1):
        active_finding_ids = selected_finding_ids_for_issues(
            active_selected,
            request,
            respect_requested_findings=index == 1,
        )
        if not active_selected or not active_finding_ids:
            report['status'] = 'needs-human-review'
            report['gate'] = 'blocked'
            report['termination'] = 'unresolved_issues_no_longer_have_agent_eligible_fixes'
            report['blocked_reasons'].append('remaining issues could not be converted into an agent task packet')
            return finalize_loop_report(report, request)

        task_packet = agent_task_packet(report, request, active_scan, active_verdict, active_selected, active_finding_ids, index)
        verified_request = verified_request_from_loop(request, active_finding_ids, index)
        autofix_report = autofix_fn(active_scan, verified_request, actor)
        regression = regression_check_from_autofix(autofix_report, request)
        iteration = iteration_record(index, active_selected, active_finding_ids, task_packet, autofix_report, regression)
        report['iterations'].append(iteration)
        report['summary']['iterations_attempted'] = index
        report['summary']['agent_task_count'] = len(report['iterations'])
        report['summary']['autofix_status'] = autofix_report['status']
        report['summary']['regression_status'] = regression['status']
        if regression['status'] == 'failed':
            report['summary']['regression_failures'] += 1

        if request.dry_run:
            report['status'] = 'dry_run'
            report['gate'] = 'not_run'
            report['termination'] = 'dry_run_no_files_changed'
            return finalize_loop_report(report, request)

        if regression['status'] == 'failed':
            report['status'] = 'regressed'
            report['gate'] = 'blocked'
            report['termination'] = 'regression_tests_failed'
            report['blocked_reasons'].append('the attempted fix failed the target app test gate')
            return finalize_loop_report(report, request)

        if regression['status'] == 'missing' and request.require_regression_tests:
            report['status'] = 'needs-human-review'
            report['gate'] = 'blocked'
            report['termination'] = 'regression_tests_missing'
            report['blocked_reasons'].append('no target app regression test evidence was produced')
            return finalize_loop_report(report, request)

        if autofix_report['status'] not in PASSED_AUTOFIX_STATUSES:
            report['status'] = autofix_report['status']
            report['gate'] = autofix_report.get('gate') or 'failed'
            report['termination'] = 'agent_response_did_not_reach_verified_green_gate'
            return finalize_loop_report(report, request)

        if not request.rescan_after_apply:
            report['status'] = 'verified_without_rescan'
            report['gate'] = 'blocked'
            report['termination'] = 'rescan_gate_disabled'
            report['blocked_reasons'].append('rescan_after_apply=true is required for Phase 2C closure')
            return finalize_loop_report(report, request)

        worktree_target = rescan_path_from_autofix(active_scan, autofix_report)
        if not worktree_target:
            report['status'] = 'rescan_failed'
            report['gate'] = 'failed'
            report['termination'] = 'could_not_resolve_worktree_rescan_path'
            report['blocked_reasons'].append('agent response did not report a usable worktree path')
            return finalize_loop_report(report, request)

        try:
            rescan = scanner_fn(worktree_target, active_scan.project_name)
        except Exception as exc:  # defensive: loop reports scanner failures instead of hiding them
            report['status'] = 'rescan_failed'
            report['gate'] = 'failed'
            report['termination'] = 'rescan_exception'
            report['blocked_reasons'].append(str(exc)[:1000])
            return finalize_loop_report(report, request)

        rescan_verdict = soundness_verdict(rescan)
        verification = verify_loop_resolution(active_verdict, rescan_verdict, active_selected)
        iteration['rescan'] = rescan_summary(rescan, rescan_verdict)
        iteration['verification'] = verification
        iteration['anti_oscillation'] = anti_oscillation(active_verdict, rescan_verdict, verification)
        report['rescan'] = iteration['rescan']
        report['verification'] = verification
        report['anti_oscillation'] = iteration['anti_oscillation']
        report['summary'].update({
            'resolved_issues': len(verification['resolved_issue_ids']),
            'unresolved_issues': len(verification['unresolved_issue_ids']),
            'new_blockers': len(verification['new_blocker_issue_ids']),
        })

        if verification['new_blocker_issue_ids']:
            report['status'] = 'new_blockers'
            report['gate'] = 'blocked'
            report['termination'] = 'rescan_found_new_blockers'
            return finalize_loop_report(report, request)
        if not verification['unresolved_issue_ids']:
            report['status'] = 'resolved'
            report['gate'] = 'passed'
            report['termination'] = 'selected_issues_resolved_without_new_blockers_and_with_green_tests'
            return finalize_loop_report(report, request)
        if iteration['anti_oscillation']['no_progress_detected'] and request.stop_on_oscillation:
            report['status'] = 'oscillating'
            report['gate'] = 'blocked'
            report['termination'] = 'same_issue_set_repeated_after_agent_attempt'
            report['blocked_reasons'].append('anti-oscillation guard stopped the loop after no progress')
            return finalize_loop_report(report, request)
        if index == max_iterations:
            report['status'] = 'unresolved'
            report['gate'] = 'blocked'
            report['termination'] = 'max_iterations_reached_with_unresolved_issues'
            return finalize_loop_report(report, request)

        active_scan = rescan
        active_verdict = rescan_verdict
        next_request = request.model_copy(update={'issue_ids': verification['unresolved_issue_ids'], 'finding_ids': []})
        active_selected = select_loop_issues(active_verdict, next_request)

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
            'phase': '2C',
            'agent_id': request.agent_id,
            'max_iterations_requested': max(1, request.max_iterations),
            'max_iterations_supported': PHASE2C_MAX_ITERATIONS,
            'max_iterations_effective': bounded_max_iterations(request),
            'queue_source': 'soundness.agent_fix_queue',
            'safe_autofix_only': request.safe_autofix_only,
            'requires_verified_autofix_green_gate': True,
            'requires_regression_tests': request.require_regression_tests,
            'requires_rescan_after_apply': True,
            'requires_no_new_blockers': True,
            'anti_oscillation_enabled': True,
            'stop_on_oscillation': request.stop_on_oscillation,
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
            'agent_task_count': 0,
            'autofix_status': '',
            'regression_status': 'not_run',
            'regression_failures': 0,
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


def selected_finding_ids_for_issues(
    issues: list[dict[str, Any]],
    request: InsideOutAutofixLoopRequest,
    respect_requested_findings: bool = True,
) -> list[str]:
    requested = set(request.finding_ids)
    selected: list[str] = []
    for issue in issues:
        finding_ids = [str(item) for item in issue.get('evidence', {}).get('finding_ids', []) if item]
        if requested and respect_requested_findings:
            finding_ids = [item for item in finding_ids if item in requested]
        if finding_ids:
            selected.append(sorted(finding_ids)[0])
    return dedupe(selected)[:max(1, request.limit)]


def verified_request_from_loop(request: InsideOutAutofixLoopRequest, finding_ids: list[str], iteration_index: int = 1) -> VerifiedAutofixRequest:
    return VerifiedAutofixRequest(
        finding_ids=finding_ids,
        limit=request.limit,
        provider=request.provider,
        model=request.model,
        dry_run=request.dry_run,
        approved=request.approved,
        allow_placeholders=request.allow_placeholders,
        branch_name=branch_name_for_iteration(request, iteration_index),
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


def iteration_record(
    index: int,
    selected: list[dict[str, Any]],
    finding_ids: list[str],
    task_packet: dict[str, Any],
    autofix_report: dict[str, Any],
    regression: dict[str, Any],
) -> dict[str, Any]:
    return {
        'iteration': index,
        'iteration_id': task_packet['iteration_id'],
        'selected_issue_ids': [issue['issue_id'] for issue in selected],
        'selected_finding_ids': finding_ids,
        'agent_task_packet': task_packet,
        'agent_response': agent_response_record(autofix_report),
        'verified_autofix': autofix_report,
        'regression_check': regression,
        'rescan': None,
        'verification': None,
        'anti_oscillation': None,
    }


def bounded_max_iterations(request: InsideOutAutofixLoopRequest) -> int:
    return max(1, min(PHASE2C_MAX_ITERATIONS, request.max_iterations))


def branch_name_for_iteration(request: InsideOutAutofixLoopRequest, iteration_index: int) -> str | None:
    if not request.branch_name or iteration_index <= 1:
        return request.branch_name
    return f'{request.branch_name}-iter-{iteration_index}'


def agent_task_packet(
    report: dict[str, Any],
    request: InsideOutAutofixLoopRequest,
    scan: ScanResult,
    verdict: dict[str, Any],
    selected: list[dict[str, Any]],
    finding_ids: list[str],
    iteration_index: int,
) -> dict[str, Any]:
    iteration = f"{report['loop_id']}-iter-{iteration_index}"
    return {
        'schema_version': TASK_PACKET_SCHEMA,
        'task_id': stable_id(f"{report['loop_id']}:{iteration_index}:{','.join(finding_ids)}"),
        'loop_id': report['loop_id'],
        'iteration_id': iteration,
        'iteration': iteration_index,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'agent_id': request.agent_id,
        'target': {
            'scan_id': scan.scan_id,
            'project_name': scan.project_name,
            'target_path_hash': verdict['subject']['target_path_hash'],
            'target_name_hint': verdict['subject'].get('target_name_hint', ''),
        },
        'constraints': {
            'raw_code_included': False,
            'safe_autofix_only': request.safe_autofix_only,
            'approved_to_edit': request.approved and not request.dry_run,
            'dry_run': request.dry_run,
            'rescan_after_apply': request.rescan_after_apply,
            'require_regression_tests': request.require_regression_tests,
            'stop_on_oscillation': request.stop_on_oscillation,
            'max_iterations_effective': bounded_max_iterations(request),
        },
        'regression_gate': {
            'required': request.require_regression_tests,
            'test_commands': request.test_commands,
            'allow_auto_detect_tests': request.allow_auto_detect_tests,
            'timeout_seconds': request.test_timeout_seconds,
        },
        'expected_outcome': {
            'selected_findings_resolved': True,
            'no_new_blockers': True,
            'app_tests_pass': request.require_regression_tests,
            'final_allowed_statuses': [
                'resolved',
                'unresolved',
                'regressed',
                'oscillating',
                'needs-human-review',
                'new_blockers',
                'rescan_failed',
            ],
        },
        'issues': [task_issue_record(issue) for issue in selected],
        'selected_finding_ids': finding_ids,
    }


def task_issue_record(issue: dict[str, Any]) -> dict[str, Any]:
    remediation = issue.get('remediation') or {}
    evidence = issue.get('evidence') or {}
    agent = issue.get('agent') or {}
    return {
        'issue_id': issue.get('issue_id'),
        'agent_correlation_key': (issue.get('correlation') or {}).get('agent_correlation_key', ''),
        'priority': issue.get('priority') or {},
        'gate': issue.get('gate') or {},
        'location': issue.get('location') or {},
        'vulnerability': issue.get('vulnerability') or {},
        'evidence_summary': {
            'sources': evidence.get('sources', []),
            'rules': evidence.get('rules', []),
            'finding_ids': evidence.get('finding_ids', []),
            'tool_agreement_count': evidence.get('tool_agreement_count', 0),
            'cwe': evidence.get('cwe', []),
            'sink': evidence.get('sink', ''),
        },
        'remediation': {
            'summary': remediation.get('summary', ''),
            'guidance': remediation.get('guidance', []),
            'agent_actions': remediation.get('agent_actions', []),
            'mechanical_patch_available': bool(remediation.get('mechanical_patch_available')),
            'validation_commands': remediation.get('validation_commands', []),
            'rescan_required': bool(remediation.get('rescan_required', True)),
        },
        'safety': agent.get('safety') or {},
        'precision': agent.get('precision') or {},
    }


def agent_response_record(autofix_report: dict[str, Any]) -> dict[str, Any]:
    apply_report = autofix_report.get('apply') or {}
    branch = autofix_report.get('branch') or {}
    pull_request = autofix_report.get('pull_request') or {}
    tests = (autofix_report.get('verification') or {}).get('tests') or []
    return {
        'schema_version': 'inside-out-agent-response-v1',
        'status': autofix_report.get('status', ''),
        'gate': autofix_report.get('gate', ''),
        'selected_finding_ids': autofix_report.get('selected_finding_ids', []),
        'applied_change_count': len(apply_report.get('applied', [])),
        'changed_paths': sorted({normalize_path(item.get('path', '')) for item in apply_report.get('applied', []) if item.get('path')}),
        'commit_sha': branch.get('commit_sha', ''),
        'branch_name': branch.get('name', ''),
        'worktree_path_hash': stable_id(branch.get('worktree_path', '')),
        'pull_request_created': bool(pull_request.get('created')),
        'pull_request_url': pull_request.get('url', ''),
        'test_count': len(tests),
        'tests_passed': bool(tests) and all(item.get('passed') for item in tests),
        'blocked_reasons': autofix_report.get('blocked_reasons', []),
    }


def regression_check_from_autofix(autofix_report: dict[str, Any], request: InsideOutAutofixLoopRequest) -> dict[str, Any]:
    tests = (autofix_report.get('verification') or {}).get('tests') or []
    if request.dry_run:
        status = 'not_run'
    elif not tests:
        status = 'missing' if request.require_regression_tests else 'not_required'
    elif all(item.get('passed') for item in tests):
        status = 'passed'
    else:
        status = 'failed'
    return {
        'required': request.require_regression_tests,
        'status': status,
        'test_count': len(tests),
        'passed': status == 'passed',
        'timeout_seconds': request.test_timeout_seconds,
        'tests': regression_test_records(tests),
    }


def regression_test_records(tests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            'command': item.get('command', ''),
            'cwd_hash': stable_id(item.get('cwd', '')),
            'exit_code': item.get('exit_code', 0),
            'passed': bool(item.get('passed')),
            'duration_seconds': item.get('duration_seconds', 0),
            'timed_out': bool(item.get('timed_out')),
            'stdout_summary': output_summary(item.get('stdout', '')),
            'stderr_summary': output_summary(item.get('stderr', '')),
        }
        for item in tests
    ]


def output_summary(value: str, limit: int = 1000) -> str:
    text = re.sub(r'\s+', ' ', str(value or '')).strip()
    return text if len(text) <= limit else text[: max(0, limit - 3)] + '...'


def normalize_path(value: str) -> str:
    return str(value or '').replace('\\', '/').strip()


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
    for iteration in report.get('iterations') or []:
        autofix = iteration.get('verified_autofix') or {}
        iteration_id = str(iteration.get('iteration_id') or '')
        task = iteration.get('agent_task_packet') or {}
        events.append(record_governance_event(
            **common,
            action='inside_out_loop.agent_task_created',
            reason='Loop created a structured agent task packet from the soundness fix queue.',
            metadata={
                'iteration_id': iteration_id,
                'iteration': str(iteration.get('iteration') or ''),
                'agent_id': str(task.get('agent_id') or ''),
                'issue_count': str(len(task.get('issues') or [])),
                'finding_count': str(len(task.get('selected_finding_ids') or [])),
            },
            evidence_refs={
                'loop_id': loop_id,
                'scan_id': scan_id,
                'iteration_id': iteration_id,
                'task_id': task.get('task_id', ''),
                'selected_issue_ids': iteration.get('selected_issue_ids', []),
                'selected_finding_ids': iteration.get('selected_finding_ids', []),
            },
        ))
        events.append(record_governance_event(
            **common,
            action='inside_out_loop.verified_autofix_invoked',
            reason='Loop invoked verified autofix as its controlled edit mechanism.',
            metadata={
                'iteration_id': iteration_id,
                'autofix_status': autofix.get('status', ''),
                'autofix_gate': autofix.get('gate', ''),
                'dry_run': str(bool(report.get('dry_run'))),
                'commit_sha': (autofix.get('branch') or {}).get('commit_sha', ''),
            },
            evidence_refs=loop_evidence_refs(report),
        ))
        events.append(record_governance_event(
            **common,
            action='inside_out_loop.agent_response_ingested',
            reason='Loop ingested the agent fix response and normalized it for convergence checks.',
            metadata=agent_response_metadata(iteration),
            evidence_refs={
                'loop_id': loop_id,
                'scan_id': scan_id,
                'iteration_id': iteration_id,
                'changed_paths': (iteration.get('agent_response') or {}).get('changed_paths', []),
                'commit_sha': (iteration.get('agent_response') or {}).get('commit_sha', ''),
            },
        ))
        regression_action = regression_governance_action(iteration)
        if regression_action:
            events.append(record_governance_event(
                **common,
                action=regression_action,
                reason='Loop recorded the target application regression test gate outcome.',
                metadata=regression_metadata(iteration),
                evidence_refs={
                    'loop_id': loop_id,
                    'scan_id': scan_id,
                    'iteration_id': iteration_id,
                    'test_commands': test_command_names(autofix),
                },
            ))
        if (iteration.get('anti_oscillation') or {}).get('no_progress_detected'):
            events.append(record_governance_event(
                **common,
                action='inside_out_loop.oscillation_detected',
                reason='Loop stopped because the same issue set repeated after an agent attempt.',
                metadata={'iteration_id': iteration_id},
                evidence_refs={'loop_id': loop_id, 'scan_id': scan_id, 'iteration_id': iteration_id, 'anti_oscillation': iteration.get('anti_oscillation') or {}},
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
        'agent_task_count': summary.get('agent_task_count', 0),
        'regression_status': summary.get('regression_status', 'not_run'),
        'regression_failures': summary.get('regression_failures', 0),
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
        'agent_task_count': str(summary.get('agent_task_count', 0)),
        'regression_status': str(summary.get('regression_status', 'not_run')),
        'regression_failures': str(summary.get('regression_failures', 0)),
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


def agent_response_metadata(iteration: dict[str, Any]) -> dict[str, str]:
    response = iteration.get('agent_response') or {}
    return {
        'iteration_id': str(iteration.get('iteration_id') or ''),
        'status': str(response.get('status') or ''),
        'gate': str(response.get('gate') or ''),
        'applied_change_count': str(response.get('applied_change_count', 0)),
        'test_count': str(response.get('test_count', 0)),
        'tests_passed': str(bool(response.get('tests_passed'))),
        'pull_request_created': str(bool(response.get('pull_request_created'))),
    }


def regression_governance_action(iteration: dict[str, Any]) -> str:
    regression = iteration.get('regression_check') or {}
    status = str(regression.get('status') or '')
    if status == 'passed':
        return 'inside_out_loop.regression_passed'
    if status == 'failed':
        return 'inside_out_loop.regression_failed'
    if status == 'missing':
        return 'inside_out_loop.regression_missing'
    if status == 'not_run':
        return 'inside_out_loop.regression_not_run'
    return ''


def regression_metadata(iteration: dict[str, Any]) -> dict[str, str]:
    regression = iteration.get('regression_check') or {}
    return {
        'iteration_id': str(iteration.get('iteration_id') or ''),
        'required': str(bool(regression.get('required'))),
        'status': str(regression.get('status') or ''),
        'test_count': str(regression.get('test_count', 0)),
        'passed': str(bool(regression.get('passed'))),
        'timeout_seconds': str(regression.get('timeout_seconds', 0)),
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
