from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .hermes_python_agent import (
    PYTHON_AGENT_ID,
    python_agent_matches_task,
    python_agent_registry_entry,
    python_task_types_for_item,
    run_python_specialist,
)
from .hermes_specialist_agents import (
    SPECIALIST_AGENT_IDS,
    run_specialist_agent,
    specialist_agent_matches_task,
    specialist_agent_registry_entries,
    specialist_task_types_for_item,
)
from .paths import data_dir
from .rag_memory import rag_memory_for_scan, scan_rag_memory_report

SCHEMA_VERSION = 1
DEFAULT_GOAL = 'secure-review-triage'
MAX_TASKS = 250
BLOCKING_AGENT_STATUSES = {'block', 'release-blocker', 'critical-dependency-risk', 'coverage-gap'}
REVIEW_AGENT_STATUSES = {'review-required', 'evidence-required', 'human-approval-required', 'manual-remediation'}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hermes_dir() -> Path:
    return data_dir() / 'hermes'


def hermes_runs_dir() -> Path:
    return hermes_dir() / 'runs'


def hermes_reviews_path() -> Path:
    return hermes_dir() / 'reviews.jsonl'


def ensure_hermes_dirs() -> None:
    hermes_runs_dir().mkdir(parents=True, exist_ok=True)


def hermes_status() -> dict[str, Any]:
    ensure_hermes_dirs()
    runs = list_hermes_runs(limit=20)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'ready',
        'hermes_dir': str(hermes_dir()),
        'run_count': len(list(hermes_runs_dir().glob('*.json'))),
        'latest_runs': runs,
        'agent_registry': agent_registry(),
        'supported_goals': supported_goals(),
        'safety_contract': safety_contract(),
    }


def supported_goals() -> list[dict[str, str]]:
    return [
        {'goal': 'secure-review-triage', 'description': 'Prioritize findings, blockers, evidence, and next review actions.'},
        {'goal': 'release-readiness', 'description': 'Emphasize release blockers, P0/P1 risk, scanner coverage, and approvals.'},
        {'goal': 'supply-chain-review', 'description': 'Emphasize dependency, SBOM, CVE, and vulnerable package signals.'},
        {'goal': 'scanner-improvement-planning', 'description': 'Identify scanner coverage and noisy-rule candidates without changing rules.'},
    ]


def safety_contract() -> dict[str, Any]:
    return {
        'input_source': 'rag-memory-from-sanitized-report-lake',
        'raw_repository_reads_allowed': False,
        'raw_report_file_reads_allowed': False,
        'source_execution_allowed': False,
        'external_publish_allowed': False,
        'rule_or_scanner_mutation_allowed': False,
        'fix_apply_allowed': False,
        'fine_tuning_allowed': False,
        'requires_human_approval_for_changes': True,
        'requires_benchmark_gate_for_scanner_promotion': True,
    }


def agent_registry() -> list[dict[str, Any]]:
    return [
        {
            'agent_id': 'hermes-risk-governor',
            'name': 'Hermes Risk Governor',
            'version': '1.0.0',
            'enabled': True,
            'deterministic': True,
            'capabilities': ['risk-triage', 'release-gate', 'priority-routing'],
            'item_types': ['scan-summary', 'finding-pattern'],
            'languages': ['all'],
            'safety_level': 'sanitized-memory-only',
        },
        {
            'agent_id': 'hermes-supply-chain-governor',
            'name': 'Hermes Supply Chain Governor',
            'version': '1.0.0',
            'enabled': True,
            'deterministic': True,
            'capabilities': ['dependency-review', 'sbom-risk', 'vulnerable-package-triage'],
            'item_types': ['dependency-signal', 'finding-pattern'],
            'languages': ['all'],
            'safety_level': 'sanitized-memory-only',
        },
        {
            'agent_id': 'hermes-scanner-coverage-governor',
            'name': 'Hermes Scanner Coverage Governor',
            'version': '1.0.0',
            'enabled': True,
            'deterministic': True,
            'capabilities': ['scanner-coverage', 'tool-health', 'benchmark-planning'],
            'item_types': ['scanner-status', 'rule-pattern', 'scan-summary'],
            'languages': ['all'],
            'safety_level': 'sanitized-memory-only',
        },
        {
            'agent_id': 'hermes-remediation-governor',
            'name': 'Hermes Remediation Governor',
            'version': '1.0.0',
            'enabled': True,
            'deterministic': True,
            'capabilities': ['remediation-planning', 'safe-fix-review', 'validation-routing'],
            'item_types': ['finding-pattern', 'dependency-signal'],
            'languages': ['all'],
            'safety_level': 'sanitized-memory-only',
        },
        {
            'agent_id': 'hermes-compliance-governor',
            'name': 'Hermes Compliance Governor',
            'version': '1.0.0',
            'enabled': True,
            'deterministic': True,
            'capabilities': ['audit-evidence', 'policy-evidence', 'decision-records'],
            'item_types': ['scan-summary', 'finding-pattern', 'rule-pattern', 'dependency-signal', 'scanner-status'],
            'languages': ['all'],
            'safety_level': 'sanitized-memory-only',
        },
        python_agent_registry_entry(),
        *specialist_agent_registry_entries(),
    ]


def create_hermes_run(
    *,
    scan_id: str | None = None,
    goal: str = DEFAULT_GOAL,
    requester: str = 'system',
    allowed_agents: list[str] | None = None,
    limit: int = 100,
    include_ineligible: bool = False,
    persist: bool = True,
) -> dict[str, Any]:
    if not scan_id:
        raise ValueError('scan_id is required for persisted Hermes runs')
    memory = scan_rag_memory_report(scan_id, rebuild=True)
    run = run_hermes_on_memory(
        memory,
        goal=goal,
        requester=requester,
        allowed_agents=allowed_agents,
        limit=limit,
        include_ineligible=include_ineligible,
        persist=persist,
    )
    return run


def hermes_report_for_scan(scan: Any, goal: str = DEFAULT_GOAL, limit: int = 100) -> dict[str, Any]:
    memory = rag_memory_for_scan(scan)
    return run_hermes_on_memory(memory, goal=goal, requester='report-bundle', limit=limit, persist=False)


def run_hermes_on_memory(
    memory: dict[str, Any],
    *,
    goal: str = DEFAULT_GOAL,
    requester: str = 'system',
    allowed_agents: list[str] | None = None,
    limit: int = 100,
    include_ineligible: bool = False,
    persist: bool = True,
) -> dict[str, Any]:
    started = time.time()
    resolved_goal = normalize_goal(goal)
    run_id = make_run_id(memory, resolved_goal, requester)
    policy = evaluate_memory_policy(memory, include_ineligible=include_ineligible)
    agents = select_agents(allowed_agents)
    if policy['decision'] == 'blocked':
        run = base_run(run_id, memory, resolved_goal, requester, agents, policy)
        run['status'] = 'blocked'
        run['completed_at'] = now_iso()
        run['duration_seconds'] = round(time.time() - started, 3)
        run['synthesis'] = blocked_synthesis(policy)
        attach_governance_events(run)
        if persist:
            save_hermes_run(run)
        return run

    items = [item for item in memory.get('items', []) if item.get('eligibility', {}).get('retrieval_allowed')]
    tasks = plan_tasks(items, goal=resolved_goal, limit=limit, agents=agents)
    dispatch = dispatch_tasks(tasks, items, agents)
    synthesis = synthesize_run(memory, tasks, dispatch['agent_results'], policy)
    run = base_run(run_id, memory, resolved_goal, requester, agents, policy)
    run.update(
        {
            'status': synthesis['status'],
            'completed_at': now_iso(),
            'duration_seconds': round(time.time() - started, 3),
            'plan': {
                'task_count': len(tasks),
                'task_type_counts': dict(Counter(task['task_type'] for task in tasks)),
                'agent_count': len(agents),
                'goal': resolved_goal,
            },
            'tasks': tasks,
            'agent_results': dispatch['agent_results'],
            'agent_errors': dispatch['agent_errors'],
            'synthesis': synthesis,
        }
    )
    attach_governance_events(run)
    if persist:
        save_hermes_run(run)
    return run


def base_run(run_id: str, memory: dict[str, Any], goal: str, requester: str, agents: list[dict[str, Any]], policy: dict[str, Any]) -> dict[str, Any]:
    source = memory.get('source') or {}
    return {
        'schema_version': SCHEMA_VERSION,
        'run_id': run_id,
        'run_type': 'hermes-orchestration',
        'created_at': now_iso(),
        'completed_at': None,
        'duration_seconds': 0,
        'status': 'running',
        'requester': requester,
        'goal': goal,
        'source': {
            'scan_id': source.get('scan_id'),
            'project_name': source.get('project_name'),
            'repo_name': source.get('repo_name'),
            'target_path_hash': source.get('target_path_hash'),
            'source_report_type': source.get('source_report_type') or 'rag-memory',
            'memory_version_id': source.get('memory_version_id') or (memory.get('memory_version') or {}).get('version_id', ''),
        },
        'policy': policy,
        'agent_registry': agents,
        'plan': {'task_count': 0, 'task_type_counts': {}, 'agent_count': len(agents), 'goal': goal},
        'tasks': [],
        'agent_results': [],
        'agent_errors': [],
        'synthesis': {},
        'approvals': {
            'human_approval_required': True,
            'benchmark_gate_required': True,
            'auto_apply_allowed': False,
            'external_publish_allowed': False,
            'scanner_promotion_allowed': False,
        },
        'guardrails': [
            'Hermes consumes only sanitized RAG memory records.',
            'Hermes does not read cloned repositories, raw reports, source snippets, or patches.',
            'Hermes does not modify scanner rules, suppressions, parser code, or repository files.',
            'Any scanner or remediation change requires human approval and benchmark evidence.',
        ],
    }


def evaluate_memory_policy(memory: dict[str, Any], include_ineligible: bool = False) -> dict[str, Any]:
    status = str(memory.get('status') or 'missing')
    eligibility = memory.get('eligibility') or {}
    source = memory.get('source') or {}
    item_count = int(memory.get('item_count') or 0)
    safety_violations = []
    for item in memory.get('items', []):
        safety = item.get('safety') or {}
        if safety.get('raw_code_included') or safety.get('patches_included') or safety.get('full_local_paths_included'):
            safety_violations.append(str(item.get('item_id') or 'unknown'))
    blocked_reasons = []
    if status in {'missing', 'skipped'}:
        blocked_reasons.append(memory.get('skipped_reason') or f'rag memory status is {status}')
    if not bool(eligibility.get('rag_ingest_allowed')):
        blocked_reasons.append(eligibility.get('blocked_reason') or 'rag ingest is denied by policy')
    if item_count <= 0:
        blocked_reasons.append('no eligible RAG memory items are available')
    if safety_violations:
        blocked_reasons.append(f'safety violations detected in memory items: {", ".join(safety_violations[:5])}')
    if include_ineligible:
        blocked_reasons.append('include_ineligible was requested; Hermes keeps ineligible memory audit-only')
    decision = 'blocked' if blocked_reasons else 'allowed'
    return {
        'schema_version': SCHEMA_VERSION,
        'decision': decision,
        'blocked_reasons': dedupe(blocked_reasons),
        'memory_status': status,
        'scan_id': source.get('scan_id'),
        'project_name': source.get('project_name'),
        'rag_ingest_allowed': bool(eligibility.get('rag_ingest_allowed')),
        'agent_learning_allowed': bool(eligibility.get('agent_learning_allowed')),
        'item_count': item_count,
        'safety_violations': safety_violations,
        **safety_contract(),
    }


def select_agents(allowed_agents: list[str] | None = None) -> list[dict[str, Any]]:
    allowed = {item for item in allowed_agents or [] if item}
    agents = [agent for agent in agent_registry() if agent.get('enabled')]
    if allowed:
        agents = [agent for agent in agents if agent['agent_id'] in allowed]
    return agents


def plan_tasks(items: list[dict[str, Any]], goal: str, limit: int = 100, agents: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    max_tasks = min(max(limit, 0), MAX_TASKS)
    planned: list[dict[str, Any]] = []
    ranked = sorted(items, key=lambda item: (-item_risk_score(item), item.get('item_type', ''), item.get('title', '')))
    for item in ranked:
        for task_type, reason in task_types_for_item(item, goal):
            task = {
                'task_id': stable_id(item.get('item_id', ''), task_type, goal),
                'task_type': task_type,
                'title': f"{task_type.replace('-', ' ').title()}: {item.get('title', '')}",
                'priority': task_priority(item, task_type),
                'reason': reason,
                'item_id': item.get('item_id'),
                'item_type': item.get('item_type'),
                'assigned_agents': [],
                'status': 'planned',
                'evidence': {
                    'source_scan_id': item.get('source', {}).get('scan_id'),
                    'project_name': item.get('source', {}).get('project_name'),
                    'tags': item.get('tags', []),
                    'metadata': safe_metadata(item.get('metadata') or {}),
                },
            }
            planned.append(task)
            if len(planned) >= max_tasks:
                return assign_task_agents(planned, agents=agents)
    return assign_task_agents(planned, agents=agents)


def task_types_for_item(item: dict[str, Any], goal: str) -> list[tuple[str, str]]:
    item_type = item.get('item_type')
    tags = {str(tag).upper() for tag in item.get('tags', [])}
    metadata = item.get('metadata') or {}
    tasks: list[tuple[str, str]] = []
    if item_type == 'scan-summary':
        tasks.append(('release-readiness-review', 'Summarize repository-level release risk from sanitized scan memory.'))
    if item_type == 'finding-pattern':
        tasks.append(('risk-triage', 'Prioritize sanitized finding pattern for human review.'))
        tasks.append(('remediation-routing', 'Prepare safe remediation and validation guidance without applying changes.'))
        if tags & {'P0', 'P1', 'CRITICAL', 'HIGH'} or int(metadata.get('risk_score') or 0) >= 70:
            tasks.append(('release-gate-review', 'High-priority finding requires release gate review.'))
    if item_type == 'dependency-signal' or 'DEPENDENCY' in tags or 'SCA' in tags:
        tasks.append(('supply-chain-review', 'Dependency or package signal requires supply-chain triage.'))
    if item_type == 'rule-pattern':
        tasks.append(('scanner-improvement-candidate', 'Repeated rule evidence can inform a human-approved scanner tuning candidate.'))
    if item_type == 'scanner-status':
        tasks.append(('scanner-coverage-review', 'Scanner status should be checked for disabled, failed, skipped, or missing tools.'))
    tasks.extend(python_task_types_for_item(item, goal))
    tasks.extend(specialist_task_types_for_item(item, goal))
    if goal == 'supply-chain-review':
        return [task for task in tasks if task[0] in {'supply-chain-review', 'release-gate-review'} or task[0].endswith('-dependency-review')] or tasks[:1]
    if goal == 'scanner-improvement-planning':
        return [task for task in tasks if task[0] in {'scanner-improvement-candidate', 'scanner-coverage-review'} or task[0].endswith('-scanner-coverage-review')] or tasks[:1]
    if goal == 'release-readiness':
        return [
            task
            for task in tasks
            if task[0]
            in {
                'release-readiness-review',
                'release-gate-review',
                'scanner-coverage-review',
                'supply-chain-review',
            }
            or task[0].endswith(('-specialist-review', '-dependency-review', '-scanner-coverage-review'))
        ] or tasks[:1]
    return tasks


def assign_task_agents(tasks: list[dict[str, Any]], agents: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    registry = agents or agent_registry()
    for task in tasks:
        task['assigned_agents'] = [
            agent['agent_id']
            for agent in registry
            if agent.get('enabled') and agent_matches_task(agent, task)
        ]
        task['status'] = 'ready' if task['assigned_agents'] else 'unassigned'
    return tasks


def agent_matches_task(agent: dict[str, Any], task: dict[str, Any]) -> bool:
    task_type = task.get('task_type')
    item_type = task.get('item_type')
    capabilities = set(agent.get('capabilities') or [])
    item_types = set(agent.get('item_types') or [])
    if item_type not in item_types:
        return False
    if agent.get('agent_id') == PYTHON_AGENT_ID:
        return python_agent_matches_task(task)
    if agent.get('agent_id') in SPECIALIST_AGENT_IDS:
        return specialist_agent_matches_task(agent, task)
    if 'audit-evidence' in capabilities:
        return True
    if task_type in {'risk-triage', 'release-gate-review', 'release-readiness-review'}:
        return bool(capabilities & {'risk-triage', 'release-gate', 'priority-routing'})
    if task_type == 'supply-chain-review':
        return bool(capabilities & {'dependency-review', 'sbom-risk', 'vulnerable-package-triage'})
    if task_type in {'scanner-coverage-review', 'scanner-improvement-candidate'}:
        return bool(capabilities & {'scanner-coverage', 'tool-health', 'benchmark-planning'})
    if task_type == 'remediation-routing':
        return bool(capabilities & {'remediation-planning', 'safe-fix-review', 'validation-routing'})
    return 'audit-evidence' in capabilities


def dispatch_tasks(tasks: list[dict[str, Any]], items: list[dict[str, Any]], agents: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    items_by_id = {item.get('item_id'): item for item in items}
    agents_by_id = {agent['agent_id']: agent for agent in agents}
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for task in tasks:
        item = items_by_id.get(task.get('item_id'))
        if not item:
            errors.append({'task_id': task.get('task_id'), 'error': 'source memory item not found'})
            continue
        for agent_id in task.get('assigned_agents', []):
            agent = agents_by_id.get(agent_id)
            if not agent:
                continue
            try:
                results.append(run_agent(agent, task, item))
            except Exception as exc:
                errors.append({'task_id': task.get('task_id'), 'agent_id': agent_id, 'error': str(exc)[:500]})
    return {'agent_results': results, 'agent_errors': errors}


def run_agent(agent: dict[str, Any], task: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    agent_id = agent['agent_id']
    if agent_id == 'hermes-risk-governor':
        return risk_governor(agent, task, item)
    if agent_id == 'hermes-supply-chain-governor':
        return supply_chain_governor(agent, task, item)
    if agent_id == 'hermes-scanner-coverage-governor':
        return scanner_coverage_governor(agent, task, item)
    if agent_id == 'hermes-remediation-governor':
        return remediation_governor(agent, task, item)
    if agent_id == 'hermes-compliance-governor':
        return compliance_governor(agent, task, item)
    if agent_id == PYTHON_AGENT_ID:
        return run_python_specialist(agent, task, item)
    if agent_id in SPECIALIST_AGENT_IDS:
        return run_specialist_agent(agent, task, item)
    raise ValueError(f'unknown Hermes agent: {agent_id}')


def risk_governor(agent: dict[str, Any], task: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get('metadata') or {}
    tags = set(item.get('tags') or [])
    risk_score = int(metadata.get('risk_score') or 0)
    priority = metadata.get('priority') or best_tag(tags, ['P0', 'P1', 'P2', 'P3', 'P4'])
    severity = metadata.get('severity') or best_tag(tags, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
    findings = []
    if priority == 'P0' or severity == 'CRITICAL' or risk_score >= 95:
        status = 'release-blocker'
        findings.append('Release-blocking sanitized risk signal detected.')
    elif priority == 'P1' or severity == 'HIGH' or risk_score >= 70:
        status = 'review-required'
        findings.append('High-priority sanitized risk signal requires reviewer attention.')
    else:
        status = 'record-only'
        findings.append('No release-blocking risk factor detected by the risk governor.')
    return agent_result(agent, task, item, status, findings, [
        'Confirm true-positive status and owner before merge.' if status != 'record-only' else 'Track through normal review cadence.',
        'Use sanitized memory and saved scan IDs as audit evidence.',
    ])


def supply_chain_governor(agent: dict[str, Any], task: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    text = ' '.join([str(item.get('title') or ''), str(item.get('text') or ''), ' '.join(item.get('tags', []))]).lower()
    metadata = item.get('metadata') or {}
    findings = []
    status = 'record-only'
    if any(token in text for token in ['cve-', 'vulnerable', 'dependency', 'package', 'sca']):
        status = 'critical-dependency-risk' if metadata.get('severity') in {'CRITICAL', 'HIGH'} or metadata.get('priority') in {'P0', 'P1'} else 'review-required'
        findings.append('Dependency or package risk signal found in sanitized memory.')
    if metadata.get('reachability') and metadata.get('reachability') != 'unknown':
        findings.append(f"Reachability evidence: {metadata.get('reachability')}.")
    return agent_result(agent, task, item, status, findings or ['No dependency-specific blocker detected.'], [
        'Check fixed versions and lockfile impact before closure.',
        'Keep SBOM and dependency review artifacts attached to the decision record.',
    ])


def scanner_coverage_governor(agent: dict[str, Any], task: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get('metadata') or {}
    text = ' '.join([str(value) for value in metadata.values()]).lower()
    gaps = []
    for tool, status in metadata.items():
        lowered = str(status).lower()
        if any(token in lowered for token in ['error', 'failed', 'not installed', 'disabled', 'missing', 'skipped']):
            gaps.append(f'{tool}={status}')
    if not gaps and any(token in text for token in ['error', 'failed', 'not installed', 'disabled', 'missing']):
        gaps.append('scanner status text indicates coverage gap')
    status = 'coverage-gap' if gaps else 'record-only'
    return agent_result(agent, task, item, status, gaps or ['No scanner status gap detected.'], [
        'Treat scanner tuning as a candidate only; do not promote without benchmarks.',
        'Verify local scanner installation and CI parity before marking coverage complete.',
    ])


def remediation_governor(agent: dict[str, Any], task: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get('metadata') or {}
    risk_score = int(metadata.get('risk_score') or 0)
    status = 'human-approval-required' if risk_score >= 70 or metadata.get('priority') in {'P0', 'P1'} else 'manual-remediation'
    return agent_result(agent, task, item, status, [
        'Safe remediation guidance can be prepared from sanitized memory, but code changes remain human controlled.',
    ], [
        'Generate or review fix proposals in dry-run mode only.',
        'Run project tests and a follow-up scan before accepting remediation.',
        'Do not apply patches from Hermes orchestration.',
    ])


def compliance_governor(agent: dict[str, Any], task: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    tags = set(item.get('tags') or [])
    metadata = item.get('metadata') or {}
    evidence_tags = sorted(tag for tag in tags if tag.startswith('CWE-') or tag.startswith('A0') or tag in {'P0', 'P1', 'CRITICAL', 'HIGH'})
    status = 'evidence-required' if evidence_tags or metadata.get('decision') in {'open', ''} else 'record-only'
    return agent_result(agent, task, item, status, evidence_tags or ['No explicit compliance mapping found beyond sanitized scan record.'], [
        'Record reviewer decision, validation evidence, and residual risk rationale.',
        'Attach scan ID, memory item ID, and finding fingerprint to downstream tickets.',
    ])


def agent_result(agent: dict[str, Any], task: dict[str, Any], item: dict[str, Any], status: str, findings: list[str], recommendations: list[str]) -> dict[str, Any]:
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
            'tags': item.get('tags', [])[:20],
        },
        'side_effects': [],
        'safety': {
            'raw_code_accessed': False,
            'repository_executed': False,
            'external_calls_made': False,
            'files_modified': False,
        },
        'generated_at': now_iso(),
    }


def synthesize_run(memory: dict[str, Any], tasks: list[dict[str, Any]], results: list[dict[str, Any]], policy: dict[str, Any]) -> dict[str, Any]:
    blockers = [result for result in results if result['status'] in BLOCKING_AGENT_STATUSES]
    review = [result for result in results if result['status'] in REVIEW_AGENT_STATUSES]
    scanner_candidates = [result for result in results if is_scanner_improvement_candidate(result)]
    recommendations: list[str] = []
    for result in results:
        recommendations.extend(result.get('recommendations', []))
    next_actions = [
        'Review all blocker and evidence-required results with a human security reviewer.',
        'Keep Hermes outputs as planning/audit artifacts; do not auto-apply code, rule, or scanner changes.',
    ]
    if scanner_candidates:
        next_actions.append('Convert scanner improvement candidates into benchmarked change proposals before promotion.')
    if blockers:
        status = 'blocked'
    elif review:
        status = 'review_required'
    else:
        status = 'pass'
    return {
        'status': status,
        'task_count': len(tasks),
        'agent_result_count': len(results),
        'blockers': summarize_results(blockers),
        'review_required': summarize_results(review),
        'scanner_improvement_candidates': summarize_results(scanner_candidates),
        'recommendations': dedupe(recommendations)[:25],
        'next_actions': next_actions,
        'policy_decision': policy['decision'],
        'memory_status': memory.get('status'),
        'human_approval_required': True,
        'benchmark_gate_required': True,
        'auto_apply_allowed': False,
        'summary': summary_text(memory, blockers, review, scanner_candidates),
    }


def blocked_synthesis(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        'status': 'blocked',
        'task_count': 0,
        'agent_result_count': 0,
        'blockers': [{'reason': reason} for reason in policy.get('blocked_reasons', [])],
        'review_required': [],
        'scanner_improvement_candidates': [],
        'recommendations': ['Use sanitized report inspection only, or resolve the policy gate before running Hermes.'],
        'next_actions': ['Do not delegate this memory record to agents while policy is blocked.'],
        'policy_decision': 'blocked',
        'human_approval_required': True,
        'benchmark_gate_required': True,
        'auto_apply_allowed': False,
        'summary': 'Hermes orchestration was blocked by memory eligibility or safety policy.',
    }


def save_hermes_run(run: dict[str, Any]) -> dict[str, Any]:
    ensure_hermes_dirs()
    path = hermes_runs_dir() / f"{safe_filename(run['run_id'])}.json"
    run['storage'] = {'path': str(path), 'path_discloses_repository': False}
    path.write_text(json.dumps(run, indent=2), encoding='utf-8')
    return run


def attach_governance_events(run: dict[str, Any]) -> None:
    try:
        from .governance import record_agent_actions_for_run

        events = record_agent_actions_for_run(run)
    except Exception as exc:
        run['governance'] = {'agent_action_events': 0, 'error': str(exc)[:300]}
        return
    run['governance'] = {
        'agent_action_events': len(events),
        'event_ids': [event.get('event_id') for event in events],
        'memory_version_id': (run.get('source') or {}).get('memory_version_id', ''),
    }


def load_hermes_run(run_id: str) -> dict[str, Any]:
    path = hermes_runs_dir() / f'{safe_filename(run_id)}.json'
    if not path.exists():
        raise FileNotFoundError(run_id)
    return json.loads(path.read_text(encoding='utf-8'))


def list_hermes_runs(limit: int = 100) -> list[dict[str, Any]]:
    ensure_hermes_dirs()
    records: list[dict[str, Any]] = []
    for path in sorted(hermes_runs_dir().glob('*.json'), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            records.append(hermes_run_card(json.loads(path.read_text(encoding='utf-8'))))
        except (OSError, json.JSONDecodeError) as exc:
            records.append({'run_id': path.stem, 'status': 'unreadable', 'error': str(exc)[:200]})
        if len(records) >= max(0, limit):
            break
    return records


def hermes_review_queue(
    *,
    scan_id: str | None = None,
    run_id: str | None = None,
    limit: int = 100,
    include_decided: bool = False,
) -> dict[str, Any]:
    ensure_hermes_dirs()
    decisions = load_hermes_review_decisions()
    selected_runs: list[dict[str, Any]] = []
    if run_id:
        selected_runs.append(load_hermes_run(run_id))
    else:
        for card in list_hermes_runs(limit=max(limit, 100)):
            source = card.get('source') or {}
            if scan_id and source.get('scan_id') != scan_id:
                continue
            try:
                selected_runs.append(load_hermes_run(str(card.get('run_id'))))
            except FileNotFoundError:
                continue
            if len(selected_runs) >= max(limit, 1):
                break

    items: list[dict[str, Any]] = []
    for run in selected_runs:
        for item in review_items_for_run(run, decisions):
            if include_decided or item['review_state'] == 'pending':
                items.append(item)
            if len(items) >= max(limit, 0):
                break
        if len(items) >= max(limit, 0):
            break

    counts = Counter(item['review_state'] for item in items)
    status = 'reviewed' if items and counts.get('pending', 0) == 0 else 'pending_review' if items else 'empty'
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': status,
        'scope': {'scan_id': scan_id or '', 'run_id': run_id or ''},
        'count': len(items),
        'pending_count': counts.get('pending', 0),
        'decided_count': len(items) - counts.get('pending', 0),
        'items': items,
        'guardrails': [
            'Hermes review records human decisions only; it does not apply fixes.',
            'Hermes review does not promote scanner lessons or mutate rules.',
            'Scanner learning influence still requires Benchmark Gate approval and benchmark evidence.',
        ],
    }


def hermes_run_review_report(run_id: str, *, include_decided: bool = True, limit: int = 100) -> dict[str, Any]:
    return hermes_review_queue(run_id=run_id, include_decided=include_decided, limit=limit)


def record_hermes_review(
    run_id: str,
    *,
    decision: str,
    reviewer: str,
    note: str = '',
    review_item_ids: list[str] | None = None,
) -> dict[str, Any]:
    ensure_hermes_dirs()
    run = load_hermes_run(run_id)
    current = hermes_review_queue(run_id=run_id, include_decided=True, limit=MAX_TASKS * 10)
    allowed_ids = {item['review_item_id']: item for item in current.get('items', [])}
    requested_ids = [str(item).strip() for item in review_item_ids or [] if str(item).strip()]
    selected_ids = requested_ids or [item_id for item_id, item in allowed_ids.items() if item.get('review_state') == 'pending']
    unknown = [item_id for item_id in selected_ids if item_id not in allowed_ids]
    if unknown:
        raise ValueError(f'unknown Hermes review item id(s): {", ".join(unknown[:5])}')
    if not selected_ids:
        raise ValueError('no Hermes review items selected')

    reviewer = safe_text(reviewer, 120) or 'local-admin'
    event = {
        'schema_version': SCHEMA_VERSION,
        'review_id': stable_id(run_id, decision, reviewer, now_iso()),
        'created_at': now_iso(),
        'run_id': run_id,
        'scan_id': str((run.get('source') or {}).get('scan_id') or ''),
        'project_name': str((run.get('source') or {}).get('project_name') or ''),
        'reviewer': reviewer,
        'decision': decision,
        'note': safe_text(note, 1000),
        'review_item_ids': selected_ids,
        'item_count': len(selected_ids),
        'safety': {
            'raw_code_included': False,
            'repository_mutated': False,
            'scanner_rule_mutated': False,
            'lesson_promoted': False,
        },
    }
    with hermes_reviews_path().open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(event, sort_keys=True) + '\n')
    record_hermes_review_governance(event, selected_ids, run)
    updated = hermes_review_queue(run_id=run_id, include_decided=False, limit=MAX_TASKS * 10)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'recorded',
        'review': event,
        'remaining_pending_count': updated.get('pending_count', 0),
        'guardrails': [
            'Review recorded as audit evidence only.',
            'No scanner rules, suppressions, parser code, repository files, or memory lessons were changed.',
        ],
    }


def review_items_for_run(run: dict[str, Any], decisions: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    source = run.get('source') or {}
    run_id = str(run.get('run_id') or '')
    items: list[dict[str, Any]] = []
    for result in run.get('agent_results', []):
        if result.get('status') not in BLOCKING_AGENT_STATUSES | REVIEW_AGENT_STATUSES:
            continue
        item_id = review_item_id(run_id, result)
        decision = decisions.get(item_id)
        items.append({
            'review_item_id': item_id,
            'review_state': 'decided' if decision else 'pending',
            'latest_decision': public_review_decision(decision) if decision else None,
            'run_id': run_id,
            'scan_id': source.get('scan_id'),
            'project_name': source.get('project_name'),
            'run_status': run.get('status'),
            'run_summary': (run.get('synthesis') or {}).get('summary', ''),
            'agent_id': result.get('agent_id'),
            'agent_name': result.get('agent_name'),
            'task_id': result.get('task_id'),
            'task_type': result.get('task_type'),
            'status': result.get('status'),
            'confidence': result.get('confidence'),
            'item_id': result.get('item_id'),
            'findings': result.get('findings', [])[:5],
            'recommendations': result.get('recommendations', [])[:5],
            'evidence_refs': result.get('evidence_refs', {}),
            'safety': result.get('safety', {}),
            'allowed_decisions': ['acknowledged', 'confirmed_true_positive', 'accepted_risk', 'false_positive', 'needs_fix', 'needs_more_evidence'],
        })
    return sorted(items, key=lambda item: (item['review_state'] != 'pending', review_status_rank(item['status']), item.get('task_type', ''), item.get('agent_id', '')))


def load_hermes_review_decisions() -> dict[str, dict[str, Any]]:
    path = hermes_reviews_path()
    if not path.exists():
        return {}
    decisions: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        for item_id in event.get('review_item_ids', []):
            decisions[str(item_id)] = event
    return decisions


def public_review_decision(decision: dict[str, Any] | None) -> dict[str, Any] | None:
    if not decision:
        return None
    return {
        'review_id': decision.get('review_id'),
        'created_at': decision.get('created_at'),
        'reviewer': decision.get('reviewer'),
        'decision': decision.get('decision'),
        'note': decision.get('note'),
    }


def review_item_id(run_id: str, result: dict[str, Any]) -> str:
    return stable_id(run_id, str(result.get('result_id') or ''), str(result.get('task_id') or ''), str(result.get('agent_id') or ''), str(result.get('status') or ''))


def review_status_rank(status: str) -> int:
    if status in BLOCKING_AGENT_STATUSES:
        return 0
    if status in REVIEW_AGENT_STATUSES:
        return 1
    return 2


def record_hermes_review_governance(event: dict[str, Any], selected_ids: list[str], run: dict[str, Any]) -> None:
    try:
        from .governance import record_governance_event

        record_governance_event(
            actor=str(event.get('reviewer') or 'local-admin'),
            action='hermes.review_recorded',
            category='approval',
            resource=str(event.get('review_id') or event.get('run_id') or ''),
            scan_id=str(event.get('scan_id') or ''),
            reason=str(event.get('note') or f"Hermes review decision: {event.get('decision')}"),
            metadata={
                'run_id': event.get('run_id'),
                'decision': event.get('decision'),
                'review_item_count': str(len(selected_ids)),
                'project_name': event.get('project_name'),
                'memory_version_id': (run.get('source') or {}).get('memory_version_id', ''),
            },
            evidence_refs={
                'review_id': event.get('review_id'),
                'run_id': event.get('run_id'),
                'review_item_ids': selected_ids[:100],
                'safety': event.get('safety') or {},
            },
        )
    except Exception:
        pass


def hermes_run_card(run: dict[str, Any]) -> dict[str, Any]:
    return {
        'run_id': run.get('run_id'),
        'created_at': run.get('created_at'),
        'completed_at': run.get('completed_at'),
        'status': run.get('status'),
        'goal': run.get('goal'),
        'requester': run.get('requester'),
        'source': run.get('source', {}),
        'task_count': run.get('plan', {}).get('task_count', 0),
        'agent_result_count': len(run.get('agent_results', [])),
        'summary': run.get('synthesis', {}).get('summary', ''),
    }


def normalize_goal(goal: str) -> str:
    value = str(goal or DEFAULT_GOAL).strip().lower().replace('_', '-')
    allowed = {item['goal'] for item in supported_goals()}
    return value if value in allowed else DEFAULT_GOAL


def item_risk_score(item: dict[str, Any]) -> int:
    metadata = item.get('metadata') or {}
    try:
        return int(metadata.get('risk_score') or metadata.get('max_risk_score') or 0)
    except (TypeError, ValueError):
        return 0


def task_priority(item: dict[str, Any], task_type: str) -> str:
    metadata = item.get('metadata') or {}
    tags = set(item.get('tags') or [])
    if metadata.get('priority') in {'P0', 'P1', 'P2', 'P3', 'P4'}:
        return str(metadata['priority'])
    if 'P0' in tags or task_type == 'release-gate-review':
        return 'P0'
    if 'P1' in tags or item_risk_score(item) >= 70:
        return 'P1'
    if 'P2' in tags:
        return 'P2'
    return 'P3'


def safe_metadata(metadata: dict[str, Any]) -> dict[str, str]:
    return {safe_text(key, 80): safe_text(value, 220) for key, value in metadata.items()}


def safe_text(value: Any, max_length: int) -> str:
    text = re.sub(r'\s+', ' ', str(value or '')).strip()
    return f'{text[: max_length - 14].rstrip()}...[truncated]' if len(text) > max_length else text


def confidence_for_status(status: str) -> str:
    if status in BLOCKING_AGENT_STATUSES:
        return 'high'
    if status in REVIEW_AGENT_STATUSES:
        return 'medium'
    return 'low'


def summarize_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            'agent_id': result.get('agent_id'),
            'task_id': result.get('task_id'),
            'status': result.get('status'),
            'item_id': result.get('item_id'),
            'findings': result.get('findings', [])[:5],
        }
        for result in results[:50]
    ]


def summary_text(memory: dict[str, Any], blockers: list[dict[str, Any]], review: list[dict[str, Any]], scanner_candidates: list[dict[str, Any]]) -> str:
    source = memory.get('source') or {}
    if blockers:
        return f"Hermes found {len(blockers)} blocker result(s) for {source.get('project_name')}; human security review is required."
    if review:
        return f"Hermes found {len(review)} review-required result(s) for {source.get('project_name')}; attach evidence before closure."
    if scanner_candidates:
        return f"Hermes found {len(scanner_candidates)} scanner improvement candidate(s); benchmark before promotion."
    return f"Hermes completed orchestration for {source.get('project_name')} with no blocker results."


def is_scanner_improvement_candidate(result: dict[str, Any]) -> bool:
    task_type = str(result.get('task_type') or '')
    if task_type == 'scanner-improvement-candidate':
        return True
    if not task_type.endswith('-scanner-coverage-review'):
        return False
    return (
        result.get('status') == 'coverage-gap'
        or bool(result.get('python_review', {}).get('requires_benchmark_gate'))
        or bool(result.get('specialist_review', {}).get('requires_benchmark_gate'))
    )


def best_tag(tags: set[str], options: list[str]) -> str:
    for option in options:
        if option in tags:
            return option
    return ''


def make_run_id(memory: dict[str, Any], goal: str, requester: str) -> str:
    source = memory.get('source') or {}
    return stable_id(str(source.get('scan_id') or 'global'), goal, requester, now_iso())


def stable_id(*parts: str) -> str:
    raw = '\n'.join(str(part or '') for part in parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]


def safe_filename(value: str) -> str:
    safe = re.sub(r'[^A-Za-z0-9_.:-]+', '-', str(value or '').strip()).strip('-')
    return safe.replace(':', '-')[:160] or 'unknown'


def dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        text = safe_text(value, 500)
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result
