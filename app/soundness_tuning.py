from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .autofix_loop import list_inside_out_autofix_loop_runs, load_inside_out_autofix_loop_run
from .governance import record_governance_event
from .paths import data_dir

SCHEMA_VERSION = 'soundness-feedback-tuning-v1'
PROFILE_FILENAME = 'profile.json'
MAX_PRIORITY_DELTA = 12.0
LEARNABLE_OUTCOMES = {'resolved', 'recurred', 'regressed', 'new_blockers'}
NEGATIVE_OUTCOMES = {'recurred', 'regressed', 'new_blockers'}


def soundness_tuning_status() -> dict[str, Any]:
    profile = load_soundness_tuning_profile()
    return {
        'schema_version': SCHEMA_VERSION,
        'status': 'ready',
        'profile_exists': bool(profile),
        'profile_path_hash': stable_id(str(profile_path())) if profile else '',
        'last_profile': profile_card(profile) if profile else None,
        'guardrails': tuning_guardrails(),
    }


def build_soundness_tuning_profile(
    *,
    scan_id: str | None = None,
    limit: int = 200,
    persist: bool = False,
    actor: str = 'system',
) -> dict[str, Any]:
    runs = load_loop_runs(scan_id=scan_id, limit=limit)
    return build_soundness_tuning_profile_from_runs(
        runs,
        scan_id=scan_id,
        limit=limit,
        persist=persist,
        actor=actor,
    )


def build_soundness_tuning_profile_from_runs(
    runs: list[dict[str, Any]],
    *,
    scan_id: str | None = None,
    limit: int = 200,
    persist: bool = False,
    actor: str = 'system',
) -> dict[str, Any]:
    observations = sorted(
        [item for run in runs for item in loop_observations(run)],
        key=lambda item: (
            item['signature_key'],
            item['issue_id'],
            item['loop_id'],
            item['outcome'],
        ),
    )
    learned = [item for item in observations if item['learned']]
    weights = aggregate_rule_weights(learned)
    profile = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'ready',
        'scope': {'scan_id': scan_id or 'all', 'limit': max(0, min(limit, 1000))},
        'summary': {
            'loop_run_count': len(runs),
            'observation_count': len(observations),
            'learned_observation_count': len(learned),
            'resolved_count': sum(1 for item in learned if item['outcome'] == 'resolved'),
            'recurred_count': sum(1 for item in learned if item['outcome'] == 'recurred'),
            'regressed_count': sum(1 for item in learned if item['outcome'] == 'regressed'),
            'new_blocker_count': sum(1 for item in learned if item['outcome'] == 'new_blockers'),
            'rule_weight_count': len(weights),
        },
        'precision_tuning': precision_tuning_summary(weights),
        'rule_weights': weights,
        'observations': observations[: max(0, min(limit, 1000))],
        'policy': {
            'source': 'persisted inside-out autofix loop outcomes',
            'allowed_influence': 'bounded ranking and precision metadata only',
            'scanner_rule_mutation_allowed': False,
            'autonomous_suppression_allowed': False,
            'raw_code_included': False,
            'dry_run_observations_learned': False,
            'max_priority_delta': MAX_PRIORITY_DELTA,
        },
        'guardrails': tuning_guardrails(),
    }
    profile['determinism'] = {
        'stable_profile_digest': stable_payload_digest({
            'scope': profile['scope'],
            'summary': profile['summary'],
            'rule_weights': profile['rule_weights'],
        }),
        'volatile_timestamps_included': False,
    }
    if persist:
        save_soundness_tuning_profile(profile)
        event = record_soundness_tuning_event(profile, actor=actor)
        profile['governance'] = {
            'persisted': True,
            'event_id': event['event_id'],
            'category': event['category'],
            'profile_path_hash': stable_id(str(profile_path())),
        }
    else:
        profile['governance'] = {'persisted': False, 'event_id': '', 'category': ''}
    return profile


def load_loop_runs(scan_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    cards = list_inside_out_autofix_loop_runs(scan_id=scan_id, limit=max(0, min(limit, 1000)))
    runs: list[dict[str, Any]] = []
    for card in cards:
        loop_id = str(card.get('loop_id') or '')
        if not loop_id:
            continue
        try:
            runs.append(load_inside_out_autofix_loop_run(loop_id))
        except FileNotFoundError:
            continue
    return runs


def loop_observations(run: dict[str, Any]) -> list[dict[str, Any]]:
    issue_records = issue_records_by_id(run)
    selected = [str(item.get('issue_id') or '') for item in run.get('selected_issues', [])]
    if not selected:
        selected = sorted(issue_records)
    verification = run.get('verification') or latest_iteration_verification(run)
    resolved = set(verification.get('resolved_issue_ids') or [])
    unresolved = set(verification.get('unresolved_issue_ids') or [])
    new_blockers = set(verification.get('new_blocker_issue_ids') or [])
    status = str(run.get('status') or '')
    dry_run = bool(run.get('dry_run'))
    observations: list[dict[str, Any]] = []
    for issue_id in selected:
        if not issue_id:
            continue
        issue = issue_records.get(issue_id, {'issue_id': issue_id})
        outcome = outcome_for_issue(issue_id, status, dry_run, resolved, unresolved, new_blockers)
        signature = issue_signature(issue)
        observations.append({
            'loop_id': str(run.get('loop_id') or ''),
            'scan_id': str(run.get('scan_id') or ''),
            'issue_id': issue_id,
            'agent_correlation_key': str(issue.get('agent_correlation_key') or ''),
            'signature_key': signature['key'],
            'signature': signature,
            'outcome': outcome,
            'learned': outcome in LEARNABLE_OUTCOMES and not dry_run,
            'loop_status': status,
            'loop_gate': str(run.get('gate') or ''),
            'regression_status': str((run.get('summary') or {}).get('regression_status') or ''),
            'agent_status': agent_status_for_issue(run, issue_id),
        })
    return observations


def issue_records_by_id(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for item in run.get('selected_issues') or []:
        issue_id = str(item.get('issue_id') or '')
        if issue_id:
            records[issue_id] = {**item}
    for iteration in run.get('iterations') or []:
        task = iteration.get('agent_task_packet') or {}
        for issue in task.get('issues') or []:
            issue_id = str(issue.get('issue_id') or '')
            if not issue_id:
                continue
            records[issue_id] = {**records.get(issue_id, {}), **issue}
    return records


def latest_iteration_verification(run: dict[str, Any]) -> dict[str, Any]:
    for iteration in reversed(run.get('iterations') or []):
        verification = iteration.get('verification')
        if verification:
            return verification
    return {}


def outcome_for_issue(
    issue_id: str,
    status: str,
    dry_run: bool,
    resolved: set[str],
    unresolved: set[str],
    new_blockers: set[str],
) -> str:
    if dry_run:
        return 'dry_run'
    if issue_id in resolved:
        return 'resolved'
    if issue_id in unresolved or status in {'oscillating', 'unresolved'}:
        return 'recurred'
    if status == 'regressed':
        return 'regressed'
    if status == 'new_blockers' or issue_id in new_blockers:
        return 'new_blockers'
    if status in {'needs-human-review', 'rescan_failed'}:
        return 'inconclusive'
    return status or 'unknown'


def agent_status_for_issue(run: dict[str, Any], issue_id: str) -> str:
    for iteration in run.get('iterations') or []:
        if issue_id in set(iteration.get('selected_issue_ids') or []):
            return str((iteration.get('agent_response') or {}).get('status') or '')
    return ''


def issue_signature(issue: dict[str, Any]) -> dict[str, Any]:
    vulnerability = issue.get('vulnerability') or {}
    source_rule = vulnerability.get('source_rule') or {}
    evidence = issue.get('evidence_summary') or issue.get('evidence') or {}
    source = str(source_rule.get('source') or first(evidence.get('sources')) or 'unknown')
    rule_id = str(source_rule.get('rule_id') or first(evidence.get('rules')) or vulnerability.get('class') or 'unknown')
    cwe = sorted(str(item) for item in (evidence.get('cwe') or source_rule.get('cwe') or []) if item)
    vulnerability_class = str(vulnerability.get('class') or evidence.get('sink') or rule_id)
    key = signature_key(source, rule_id, vulnerability_class, cwe)
    return {
        'key': key,
        'source': source,
        'rule_id': rule_id,
        'vulnerability_class': vulnerability_class,
        'cwe': cwe,
        'remediation_class': str((issue.get('safety') or {}).get('remediation_class') or ''),
    }


def signature_key(source: str, rule_id: str, vulnerability_class: str, cwe: list[str]) -> str:
    parts = [
        normalize_token(source),
        normalize_token(rule_id),
        normalize_token(vulnerability_class),
        ','.join(sorted(normalize_token(item) for item in cwe)),
    ]
    return '|'.join(parts)


def aggregate_rule_weights(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in observations:
        grouped[item['signature_key']].append(item)
    weights = [rule_weight(key, items) for key, items in grouped.items()]
    return sorted(weights, key=lambda item: (item['priority_delta'], item['key']), reverse=True)


def rule_weight(key: str, observations: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(item['outcome'] for item in observations)
    learned_count = sum(counts.values())
    resolved = counts.get('resolved', 0)
    negative = sum(counts.get(item, 0) for item in NEGATIVE_OUTCOMES)
    success_rate = resolved / learned_count if learned_count else 0.0
    recurrence_rate = negative / learned_count if learned_count else 0.0
    priority_delta = bounded_priority_delta(success_rate, recurrence_rate, learned_count)
    signature = observations[0]['signature'] if observations else {}
    return {
        'key': key,
        'signature': signature,
        'outcome_counts': dict(sorted(counts.items())),
        'observation_count': learned_count,
        'success_rate': round(success_rate, 4),
        'recurrence_rate': round(recurrence_rate, 4),
        'precision_adjustment': precision_adjustment(success_rate, recurrence_rate, learned_count),
        'priority_delta': priority_delta,
        'confidence': tuning_confidence(learned_count, success_rate, recurrence_rate),
        'reason': tuning_reason(success_rate, recurrence_rate, learned_count),
    }


def bounded_priority_delta(success_rate: float, recurrence_rate: float, count: int) -> float:
    if count <= 0:
        return 0.0
    strength = min(1.0, count / 5)
    raw = (success_rate - recurrence_rate) * MAX_PRIORITY_DELTA * strength
    return round(max(-MAX_PRIORITY_DELTA, min(MAX_PRIORITY_DELTA, raw)), 2)


def precision_adjustment(success_rate: float, recurrence_rate: float, count: int) -> str:
    if count <= 0:
        return 'observe'
    if success_rate >= 0.75 and recurrence_rate <= 0.25:
        return 'increase-confidence'
    if recurrence_rate >= 0.5:
        return 'decrease-confidence'
    return 'observe'


def tuning_confidence(count: int, success_rate: float, recurrence_rate: float) -> str:
    if count >= 5 and abs(success_rate - recurrence_rate) >= 0.4:
        return 'high'
    if count >= 2:
        return 'medium'
    if count == 1:
        return 'low'
    return 'none'


def tuning_reason(success_rate: float, recurrence_rate: float, count: int) -> str:
    if count <= 0:
        return 'No completed loop outcomes available yet.'
    if success_rate > recurrence_rate:
        return 'Agents resolved this issue signature more often than it recurred.'
    if recurrence_rate > success_rate:
        return 'This issue signature recurred or regressed more often than it was resolved.'
    return 'Loop outcomes are balanced; keep observing before changing ranking.'


def precision_tuning_summary(weights: list[dict[str, Any]]) -> dict[str, Any]:
    adjustments = Counter(item['precision_adjustment'] for item in weights)
    return {
        'increase_confidence': adjustments.get('increase-confidence', 0),
        'decrease_confidence': adjustments.get('decrease-confidence', 0),
        'observe': adjustments.get('observe', 0),
        'positive_weight_count': sum(1 for item in weights if item['priority_delta'] > 0),
        'negative_weight_count': sum(1 for item in weights if item['priority_delta'] < 0),
    }


def tuning_adjustment_for_issue(issue: dict[str, Any], profile: dict[str, Any] | None) -> dict[str, Any]:
    if not profile:
        return no_tuning_adjustment()
    weights = {item.get('key'): item for item in profile.get('rule_weights') or []}
    for signature in candidate_issue_signatures(issue):
        item = weights.get(signature['key'])
        if item:
            return {
                'matched': True,
                'signature_key': signature['key'],
                'priority_delta': float(item.get('priority_delta') or 0),
                'precision_adjustment': str(item.get('precision_adjustment') or 'observe'),
                'confidence': str(item.get('confidence') or 'none'),
                'observation_count': int(item.get('observation_count') or 0),
                'success_rate': float(item.get('success_rate') or 0),
                'recurrence_rate': float(item.get('recurrence_rate') or 0),
                'reason': str(item.get('reason') or ''),
            }
    return no_tuning_adjustment()


def candidate_issue_signatures(issue: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerability = issue.get('vulnerability') or {}
    source_rule = vulnerability.get('source_rule') or {}
    evidence = issue.get('evidence') or {}
    sources = [str(item) for item in (evidence.get('sources') or []) if item]
    rules = [str(item) for item in (evidence.get('rules') or []) if item]
    cwe = sorted(str(item) for item in (evidence.get('cwe') or source_rule.get('cwe') or []) if item)
    vulnerability_class = str(vulnerability.get('class') or evidence.get('sink') or first(rules) or 'unknown')
    signatures: list[dict[str, Any]] = []
    if source_rule.get('source') or source_rule.get('rule_id'):
        source = str(source_rule.get('source') or first(sources) or 'unknown')
        rule_id = str(source_rule.get('rule_id') or first(rules) or vulnerability_class)
        signatures.append({'key': signature_key(source, rule_id, vulnerability_class, cwe)})
    for source in sources:
        for rule_id in rules or [vulnerability_class]:
            signatures.append({'key': signature_key(source, rule_id, vulnerability_class, cwe)})
    return dedupe_signatures(signatures)


def no_tuning_adjustment() -> dict[str, Any]:
    return {
        'matched': False,
        'signature_key': '',
        'priority_delta': 0.0,
        'precision_adjustment': 'observe',
        'confidence': 'none',
        'observation_count': 0,
        'success_rate': 0.0,
        'recurrence_rate': 0.0,
        'reason': 'No matching loop outcome tuning exists yet.',
    }


def dedupe_signatures(signatures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for signature in signatures:
        key = signature.get('key') or ''
        if key and key not in seen:
            seen.add(key)
            result.append(signature)
    return result


def profile_path() -> Path:
    return data_dir() / 'soundness-tuning' / PROFILE_FILENAME


def load_soundness_tuning_profile() -> dict[str, Any] | None:
    path = profile_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        return None


def save_soundness_tuning_profile(profile: dict[str, Any]) -> Path:
    path = profile_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profile, indent=2), encoding='utf-8')
    return path


def record_soundness_tuning_event(profile: dict[str, Any], *, actor: str) -> dict[str, Any]:
    summary = profile.get('summary') or {}
    return record_governance_event(
        actor=actor,
        action='soundness_tuning.profile_rebuilt',
        resource='soundness-tuning',
        category='soundness-tuning',
        reason='Feedback-driven soundness tuning profile rebuilt from persisted loop outcomes.',
        metadata={
            'loop_run_count': str(summary.get('loop_run_count', 0)),
            'learned_observation_count': str(summary.get('learned_observation_count', 0)),
            'rule_weight_count': str(summary.get('rule_weight_count', 0)),
            'profile_digest': (profile.get('determinism') or {}).get('stable_profile_digest', ''),
        },
        evidence_refs={
            'profile_path_hash': stable_id(str(profile_path())),
            'precision_tuning': profile.get('precision_tuning') or {},
        },
    )


def profile_card(profile: dict[str, Any]) -> dict[str, Any]:
    summary = profile.get('summary') or {}
    return {
        'generated_at': profile.get('generated_at'),
        'scope': profile.get('scope') or {},
        'loop_run_count': summary.get('loop_run_count', 0),
        'learned_observation_count': summary.get('learned_observation_count', 0),
        'rule_weight_count': summary.get('rule_weight_count', 0),
        'stable_profile_digest': (profile.get('determinism') or {}).get('stable_profile_digest', ''),
    }


def tuning_guardrails() -> list[str]:
    return [
        'Tuning is derived from verified loop outcomes, not raw repository code.',
        'Dry-run and inconclusive loop outcomes are retained as observations but do not influence weights.',
        'Tuning can add bounded ranking metadata; it cannot mutate scanner rules, suppressions, or code.',
        'Negative tuning lowers confidence for signatures that recur or regress after agent attempts.',
    ]


def normalize_token(value: str) -> str:
    text = re.sub(r'[^a-z0-9_.:-]+', '-', str(value or '').lower()).strip('-')
    return text or 'unknown'


def first(values: Any) -> str:
    if isinstance(values, list) and values:
        return str(values[0])
    if isinstance(values, tuple) and values:
        return str(values[0])
    return ''


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_payload_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def stable_id(value: str) -> str:
    return hashlib.sha256(str(value or '').encode('utf-8')).hexdigest()[:24]
