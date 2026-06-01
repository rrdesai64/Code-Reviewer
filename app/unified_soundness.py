from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .dast import augment_scan_with_dast, dast_verification_report, ingest_dast_reports
from .models import DastScanRequest, ScanResult, UnifiedSoundnessRequest
from .soundness import soundness_verdict, status_needs_attention
from .soundness_tuning import build_soundness_tuning_profile, tuning_adjustment_for_issue

SCHEMA_VERSION = 'unified-soundness-verdict-v1'
PHASE = '5'


def unified_soundness_verdict(scan: ScanResult, request: UnifiedSoundnessRequest | None = None) -> dict[str, Any]:
    request = request or UnifiedSoundnessRequest()
    dast_report, augmented = outside_in_augmented_scan(scan, request)
    inside_out = soundness_verdict(augmented, limit=max(request.limit, 100))
    tuning = build_soundness_tuning_profile(
        scan_id=None,
        limit=200,
        persist=request.persist_tuning,
        actor='unified-soundness',
    ) if request.include_tuning else None
    issues = ranked_unified_issues(inside_out.get('issues', []), tuning, request.limit)
    blocking = [issue for issue in issues if issue['gate']['effect'] == 'block']
    status = 'unsound' if blocking else 'sound'
    confidence = unified_confidence(status, issues, augmented)
    correlation = correlation_summary(issues)
    provider_registry = outside_in_provider_registry()
    verdict = {
        'schema_version': SCHEMA_VERSION,
        'phase': PHASE,
        'contract': {
            'consumer': 'autonomous-orchestrator',
            'purpose': 'single generated-app soundness verdict across inside-out and outside-in evidence',
            'status_values': ['sound', 'unsound'],
            'raw_code_included': False,
            'deterministic_ranked_issues': True,
        },
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'subject': inside_out.get('subject') or {},
        'verdict': {
            'status': status,
            'confidence': confidence,
            'blocking_issue_count': len(blocking),
            'top_issue_id': issues[0]['issue_id'] if issues else '',
            'strongest_signal': strongest_signal(issues),
        },
        'summary': {
            'finding_count': len(augmented.findings),
            'ranked_issue_count': len(issues),
            'returned_issue_count': min(len(issues), max(0, request.limit)),
            'inside_out_issue_count': inside_out['summary']['consolidated_issue_count'],
            'agent_fix_queue_count': inside_out['summary']['agent_fix_queue_count'],
            'safe_autofix_candidate_count': inside_out['summary']['safe_autofix_candidate_count'],
            'outside_in_confirmed_issue_count': correlation['outside_in_confirmed_issue_count'],
            'sast_dast_correlated_issue_count': correlation['sast_dast_correlated_issue_count'],
            'feedback_tuned_issue_count': sum(1 for issue in issues if issue['tuning']['matched']),
        },
        'issues': issues,
        'inside_out': {
            'schema_version': inside_out['schema_version'],
            'verdict': inside_out['verdict'],
            'agent_loop_readiness': inside_out['agent_loop_readiness'],
            'determinism': inside_out['determinism'],
        },
        'outside_in': outside_in_summary(dast_report, provider_registry),
        'correlation': correlation,
        'feedback_tuning': tuning_summary(tuning),
        'policy': {
            'sast_dast_cluster_is_strongest_signal': True,
            'dast_only_can_block_but_cannot_drive_autofix': True,
            'tuning_influence': 'bounded priority metadata from verified loop outcomes',
            'scanner_rule_mutation_allowed': False,
            'per_runtime_expansion_gate': 'providers remain deferred until outputs are runnable inside the sandbox loop',
        },
        'determinism': {
            'stable_order': 'orchestrator score, signal strength, base soundness rank, issue id',
            'replay_digest': stable_payload_digest({
                'status': status,
                'issues': [
                    {
                        'issue_id': issue['issue_id'],
                        'score': issue['orchestrator_score'],
                        'signals': issue['signals'],
                        'tuning': issue['tuning'],
                    }
                    for issue in issues
                ],
                'inside_out_digest': inside_out['determinism']['replay_digest'],
                'tuning_digest': (tuning or {}).get('determinism', {}).get('stable_profile_digest', ''),
            }),
            'volatile_timestamps_included': False,
        },
    }
    return verdict


def outside_in_augmented_scan(
    scan: ScanResult,
    request: UnifiedSoundnessRequest,
) -> tuple[dict[str, Any] | None, ScanResult]:
    if not (request.dast_report_paths or request.dast_run_tools):
        return None, scan
    dast_request = DastScanRequest(
        report_paths=request.dast_report_paths,
        base_url=request.dast_base_url,
        tool=request.dast_tool,
        run_tools=request.dast_run_tools,
        allow_remote_base_url=request.dast_allow_remote_base_url,
        timeout_seconds=request.dast_timeout_seconds,
        require_sandbox_running=request.dast_require_sandbox_running,
    )
    dast_report = dast_verification_report(scan, dast_request)
    report_paths = [Path(item) for item in (dast_report.get('inputs') or {}).get('report_paths', [])]
    findings, _errors = ingest_dast_reports(scan, report_paths)
    return dast_report, augment_scan_with_dast(scan, findings)


def ranked_unified_issues(
    issues: list[dict[str, Any]],
    tuning_profile: dict[str, Any] | None,
    limit: int,
) -> list[dict[str, Any]]:
    records = [unified_issue_record(issue, tuning_profile) for issue in issues]
    records.sort(key=unified_issue_sort_key)
    for rank, issue in enumerate(records, 1):
        issue['rank'] = rank
    return records[: max(0, min(limit, 1000))]


def unified_issue_record(issue: dict[str, Any], tuning_profile: dict[str, Any] | None) -> dict[str, Any]:
    signals = issue_signals(issue)
    tuning = tuning_adjustment_for_issue(issue, tuning_profile)
    base_score = float((issue.get('priority') or {}).get('score') or 0)
    gate_delta = 20.0 if (issue.get('gate') or {}).get('effect') == 'block' else 0.0
    score = round(base_score + signal_score(signals) + gate_delta + float(tuning['priority_delta']), 2)
    evidence = issue.get('evidence') or {}
    agent = issue.get('agent') or {}
    return {
        'rank': 0,
        'issue_id': issue.get('issue_id'),
        'base_soundness_rank': int(issue.get('rank') or 0),
        'orchestrator_score': score,
        'confidence': issue_confidence(issue, signals, tuning),
        'signal_strength': signal_strength(signals),
        'signals': signals,
        'priority': issue.get('priority') or {},
        'gate': issue.get('gate') or {},
        'location': issue.get('location') or {},
        'correlation': issue.get('correlation') or {},
        'vulnerability': issue.get('vulnerability') or {},
        'evidence': {
            'sources': evidence.get('sources') or [],
            'rules': evidence.get('rules') or [],
            'cwe': evidence.get('cwe') or [],
            'tool_agreement_count': evidence.get('tool_agreement_count') or 0,
            'inside_out_sources': inside_out_sources(evidence),
            'outside_in_sources': outside_in_sources(evidence),
            'dynamic_proof_attached': bool(evidence.get('dynamic')),
            'confirmed_exploitable': bool((evidence.get('dataflow') or {}).get('confirmed_exploitable')),
            'dataflow': evidence.get('dataflow') or {},
            'dynamic': evidence.get('dynamic') or [],
        },
        'agent': {
            'fix_queue_eligible': bool(agent.get('fix_queue_eligible')),
            'safe_autofix_candidate': bool(agent.get('safe_autofix_candidate')),
            'reason_codes': agent.get('reason_codes') or [],
            'precision': agent.get('precision') or {},
            'safety': agent.get('safety') or {},
        },
        'tuning': tuning,
        'remediation': issue.get('remediation') or {},
    }


def issue_signals(issue: dict[str, Any]) -> list[str]:
    evidence = issue.get('evidence') or {}
    dataflow = evidence.get('dataflow') or {}
    sources = set(str(source) for source in evidence.get('sources') or [])
    has_dast = bool(outside_in_sources(evidence))
    has_inside_out = bool(inside_out_sources(evidence))
    signals: list[str] = []
    if has_dast and has_inside_out:
        signals.append('inside-out+outside-in-confirmed')
    elif has_dast:
        signals.append('outside-in-confirmed')
    if dataflow.get('confirmed_exploitable'):
        signals.append('confirmed-exploitable')
    if dataflow.get('has_dataflow'):
        signals.append('inside-out-dataflow')
    if int(evidence.get('tool_agreement_count') or len(sources)) >= 2:
        signals.append('tool-agreement')
    if (issue.get('gate') or {}).get('effect') == 'block':
        signals.append('policy-gate-block')
    if (issue.get('agent') or {}).get('fix_queue_eligible'):
        signals.append('agent-fix-eligible')
    return sorted(set(signals), key=signal_sort_key)


def signal_sort_key(signal: str) -> tuple[int, str]:
    rank = {
        'inside-out+outside-in-confirmed': 0,
        'outside-in-confirmed': 1,
        'confirmed-exploitable': 2,
        'inside-out-dataflow': 3,
        'tool-agreement': 4,
        'policy-gate-block': 5,
        'agent-fix-eligible': 6,
    }
    return (rank.get(signal, 99), signal)


def signal_score(signals: list[str]) -> float:
    weights = {
        'inside-out+outside-in-confirmed': 50,
        'outside-in-confirmed': 35,
        'confirmed-exploitable': 20,
        'inside-out-dataflow': 15,
        'tool-agreement': 12,
        'agent-fix-eligible': 5,
    }
    return float(sum(weights.get(signal, 0) for signal in signals))


def signal_strength(signals: list[str]) -> str:
    if 'inside-out+outside-in-confirmed' in signals:
        return 'strongest'
    if 'outside-in-confirmed' in signals or 'confirmed-exploitable' in signals:
        return 'strong'
    if 'inside-out-dataflow' in signals or 'tool-agreement' in signals:
        return 'medium'
    return 'weak'


def issue_confidence(issue: dict[str, Any], signals: list[str], tuning: dict[str, Any]) -> str:
    if 'inside-out+outside-in-confirmed' in signals:
        return 'very-high'
    if 'outside-in-confirmed' in signals or 'confirmed-exploitable' in signals:
        return 'high'
    if 'inside-out-dataflow' in signals or 'tool-agreement' in signals:
        return 'high' if tuning.get('precision_adjustment') != 'decrease-confidence' else 'medium'
    if tuning.get('precision_adjustment') == 'increase-confidence':
        return 'medium'
    return 'low' if (issue.get('agent') or {}).get('precision', {}).get('confidence') == 'low' else 'medium'


def unified_issue_sort_key(issue: dict[str, Any]) -> tuple[float, int, int, str]:
    strength_rank = {'strongest': 0, 'strong': 1, 'medium': 2, 'weak': 3}
    return (
        -float(issue.get('orchestrator_score') or 0),
        strength_rank.get(issue.get('signal_strength'), 9),
        int(issue.get('base_soundness_rank') or 0),
        str(issue.get('issue_id') or ''),
    )


def unified_confidence(status: str, issues: list[dict[str, Any]], scan: ScanResult) -> str:
    if status == 'unsound':
        if any(issue['signal_strength'] == 'strongest' for issue in issues):
            return 'very-high'
        if any(issue['signal_strength'] == 'strong' for issue in issues):
            return 'high'
        return 'medium'
    if any(status_needs_attention(tool_status) for tool_status in scan.summary.tools.values()):
        return 'medium'
    return 'high'


def strongest_signal(issues: list[dict[str, Any]]) -> str:
    for signal in [
        'inside-out+outside-in-confirmed',
        'outside-in-confirmed',
        'confirmed-exploitable',
        'inside-out-dataflow',
        'tool-agreement',
        'policy-gate-block',
    ]:
        if any(signal in issue.get('signals', []) for issue in issues):
            return signal
    return 'none'


def correlation_summary(issues: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(issue['signal_strength'] for issue in issues)
    return {
        'issue_count': len(issues),
        'outside_in_confirmed_issue_count': sum(
            1 for issue in issues if issue['evidence']['outside_in_sources']
        ),
        'inside_out_issue_count': sum(
            1 for issue in issues if issue['evidence']['inside_out_sources']
        ),
        'sast_dast_correlated_issue_count': sum(
            1
            for issue in issues
            if issue['evidence']['outside_in_sources'] and issue['evidence']['inside_out_sources']
        ),
        'signal_strength_counts': dict(sorted(counts.items())),
        'strongest_signal_policy': 'SAST/inside-out plus DAST/outside-in proof ranks above either signal alone.',
    }


def outside_in_summary(
    dast_report: dict[str, Any] | None,
    provider_registry: dict[str, Any],
) -> dict[str, Any]:
    dast_summary = {
        'provided': bool(dast_report),
        'status': (dast_report or {}).get('status', 'not_run'),
        'gate': (dast_report or {}).get('gate') or {},
        'summary': (dast_report or {}).get('summary') or {},
    }
    return {
        'web': {
            'runtime_smoke': 'available-through-phase-3c',
            'dast': dast_summary,
            'provider_status': 'ready',
        },
        'providers': provider_registry,
    }


def outside_in_provider_registry() -> dict[str, Any]:
    providers = [
        provider_record(
            'web',
            'ready',
            ['runtime-plan.json', 'runtime-build-run-worker.json', 'runtime-smoke-posture.json', 'dast-verification.json'],
            [],
        ),
        provider_record(
            'android',
            'deferred',
            [],
            ['APK/AAB build artifact contract is not mature', 'emulator worker output is not in the loop yet'],
        ),
        provider_record(
            'ios',
            'deferred',
            [],
            ['IPA/simulator build artifact contract is not mature', 'macOS runner isolation is not wired into the loop yet'],
        ),
        provider_record(
            'desktop',
            'deferred',
            [],
            ['desktop app launch probes are platform-specific', 'sandboxed UI smoke output is not standardized yet'],
        ),
        provider_record(
            'enterprise-saas',
            'deferred',
            [],
            ['tenant-safe credentials and non-production target policy are required', 'provider reports need stable schemas'],
        ),
    ]
    counts = Counter(item['status'] for item in providers)
    return {
        'schema_version': 'outside-in-provider-registry-v1',
        'phase': PHASE,
        'summary': dict(sorted(counts.items())),
        'providers': providers,
        'activation_policy': [
            'Provider must run inside the Phase 3 disposable/container loop.',
            'Provider must emit a stable machine-readable report consumed by Phase 5.',
            'Provider findings must remain verification feedback, not direct naive autofix input.',
        ],
    }


def provider_record(
    runtime: str,
    status: str,
    accepted_outputs: list[str],
    blockers: list[str],
) -> dict[str, Any]:
    return {
        'runtime': runtime,
        'status': status,
        'accepted_outputs': accepted_outputs,
        'blockers': blockers,
        'runnable_in_loop': status == 'ready',
    }


def tuning_summary(tuning: dict[str, Any] | None) -> dict[str, Any]:
    if not tuning:
        return {
            'enabled': False,
            'schema_version': '',
            'summary': {},
            'precision_tuning': {},
            'policy': 'tuning disabled for this request',
        }
    return {
        'enabled': True,
        'schema_version': tuning.get('schema_version', ''),
        'summary': tuning.get('summary') or {},
        'precision_tuning': tuning.get('precision_tuning') or {},
        'profile_digest': (tuning.get('determinism') or {}).get('stable_profile_digest', ''),
        'governance': tuning.get('governance') or {},
        'policy': (tuning.get('policy') or {}).get('allowed_influence', ''),
    }


def inside_out_sources(evidence: dict[str, Any]) -> list[str]:
    return sorted(source for source in evidence.get('sources') or [] if not str(source).startswith('dast:'))


def outside_in_sources(evidence: dict[str, Any]) -> list[str]:
    return sorted(source for source in evidence.get('sources') or [] if str(source).startswith('dast:'))


def stable_payload_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()
