from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .models import InsideOutAutofixLoopRequest, ScanResult, VerifiedAutofixRequest
from .scanner import run_scan
from .soundness import soundness_verdict
from .verified_autofix import run_verified_autofix

REPORT_SCHEMA = 'inside-out-autofix-loop-v1'
PHASE2A_MAX_ITERATIONS = 1
PASSED_AUTOFIX_STATUSES = {'verified', 'pr_opened'}

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
        return report
    if not selected_finding_ids:
        report['status'] = 'no_eligible_fixes'
        report['gate'] = 'blocked'
        report['termination'] = 'no_soundness_queue_items_selected'
        return report

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
        return report

    if autofix_report['status'] not in PASSED_AUTOFIX_STATUSES:
        report['status'] = autofix_report['status']
        report['gate'] = autofix_report.get('gate') or 'failed'
        report['termination'] = 'verified_autofix_did_not_reach_green_test_gate'
        return report

    if not request.rescan_after_apply:
        report['status'] = 'verified_without_rescan'
        report['gate'] = 'blocked'
        report['termination'] = 'rescan_gate_disabled'
        report['blocked_reasons'].append('rescan_after_apply=true is required for Phase 2A closure')
        return report

    worktree_target = rescan_path_from_autofix(scan, autofix_report)
    if not worktree_target:
        report['status'] = 'rescan_failed'
        report['gate'] = 'failed'
        report['termination'] = 'could_not_resolve_worktree_rescan_path'
        report['blocked_reasons'].append('verified autofix did not report a usable worktree path')
        return report

    try:
        rescan = scanner_fn(worktree_target, scan.project_name)
    except Exception as exc:  # defensive: loop reports scanner failures instead of hiding them
        report['status'] = 'rescan_failed'
        report['gate'] = 'failed'
        report['termination'] = 'rescan_exception'
        report['blocked_reasons'].append(str(exc)[:1000])
        return report

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
    return report


def rescan_target(target: Path, project_name: str | None) -> ScanResult:
    return run_scan(target, project_name=project_name)


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


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
