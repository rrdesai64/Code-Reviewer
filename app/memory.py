from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Finding, ScanResult

ROOT = Path(__file__).resolve().parents[1]
MEMORY_PATH = ROOT / 'data' / 'memory.json'
MAX_GLOBAL_HISTORY = 200
MAX_REPO_HISTORY = 50
MAX_FINDING_MEMORY = 1000


def empty_memory() -> dict:
    return {
        'schema_version': 2,
        'repositories': {},
        'scan_history': [],
        'hotspots': {},
        'recurring_rules': {},
    }


def load_memory() -> dict:
    if not MEMORY_PATH.exists():
        return empty_memory()
    memory = json.loads(MEMORY_PATH.read_text(encoding='utf-8'))
    return normalize_memory(memory)


def normalize_memory(memory: dict) -> dict:
    normalized = empty_memory()
    normalized.update(memory if isinstance(memory, dict) else {})
    normalized.setdefault('repositories', {})
    normalized.setdefault('scan_history', [])
    normalized.setdefault('hotspots', {})
    normalized.setdefault('recurring_rules', {})
    normalized['schema_version'] = max(int(normalized.get('schema_version') or 1), 2)
    return normalized


def save_memory(memory: dict) -> None:
    MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    MEMORY_PATH.write_text(json.dumps(normalize_memory(memory), indent=2), encoding='utf-8')


def update_repository_memory(scan: ScanResult) -> dict:
    memory = load_memory()
    repo_key = repo_id(scan.target_path)
    now = datetime.now(timezone.utc).isoformat()
    repo = memory.setdefault('repositories', {}).get(repo_key, {})
    finding_memory = repo.get('finding_memory', {})
    previous_active = set(repo.get('active_fingerprints') or [fp for fp, item in finding_memory.items() if item.get('status') == 'active'])
    current_fingerprints = {finding.fingerprint for finding in scan.findings}
    current_by_fingerprint = {finding.fingerprint: finding for finding in scan.findings}
    scan_already_recorded = scan_seen(memory, repo, scan.scan_id)

    for fingerprint in sorted(previous_active - current_fingerprints):
        item = finding_memory.get(fingerprint)
        if item:
            item['status'] = 'resolved'
            item['resolved_at'] = now
            item['resolved_scan_id'] = scan.scan_id

    for finding in scan.findings:
        item = finding_memory.get(finding.fingerprint, {})
        first_seen = item.get('first_seen') or scan.created_at.isoformat()
        seen_count = int(item.get('seen_count') or 0)
        if item.get('last_scan_id') != scan.scan_id:
            seen_count += 1
        finding_memory[finding.fingerprint] = finding_memory_item(finding, scan, first_seen, seen_count)

    finding_memory = trim_finding_memory(finding_memory, current_fingerprints)
    current_hotspots = Counter(finding.location.path for finding in scan.findings)
    current_rules = Counter(finding.rule_id for finding in scan.findings)
    cumulative_hotspots = Counter(repo.get('cumulative_hotspots', {}))
    cumulative_rules = Counter(repo.get('cumulative_rules', {}))
    if not scan_already_recorded:
        cumulative_hotspots.update(current_hotspots)
        cumulative_rules.update(current_rules)

    repo_history = update_history(repo.get('scan_history', []), scan_history_entry(scan, repo_key))
    global_history = update_history(memory.get('scan_history', []), scan_history_entry(scan, repo_key), limit=MAX_GLOBAL_HISTORY)
    active_findings = [finding_memory[fp] for fp in current_fingerprints if fp in finding_memory]
    repo = {
        'repo_key': repo_key,
        'path': scan.target_path,
        'project_name': scan.project_name,
        'last_scan_id': scan.scan_id,
        'updated_at': now,
        'files_scanned': scan.summary.files_scanned,
        'languages': scan.summary.languages,
        'severity_counts': severity_counts(scan.findings),
        'risk_summary': risk_summary(scan),
        'trend': trend_from_history(repo_history),
        'active_fingerprints': sorted(current_fingerprints),
        'active_findings': len(current_fingerprints),
        'resolved_since_previous': sorted(previous_active - current_fingerprints),
        'new_since_baseline': len(scan.new_findings),
        'resolved_since_baseline': len(scan.resolved_findings),
        'top_hotspots': dict(current_hotspots.most_common(10)),
        'top_recurring_rules': dict(current_rules.most_common(10)),
        'cumulative_hotspots': dict(cumulative_hotspots.most_common(50)),
        'cumulative_rules': dict(cumulative_rules.most_common(50)),
        'top_open_risks': top_open_risks(active_findings),
        'recommendations': recommendations(scan, current_hotspots, current_rules, repo_history, active_findings),
        'scan_history': repo_history,
        'finding_memory': finding_memory,
    }
    memory['repositories'][repo_key] = repo
    memory['scan_history'] = global_history
    memory['hotspots'][repo_key] = repo['cumulative_hotspots']
    memory['recurring_rules'][repo_key] = repo['cumulative_rules']
    save_memory(memory)
    return memory


def finding_memory_item(finding: Finding, scan: ScanResult, first_seen: str, seen_count: int) -> dict:
    return {
        'finding_id': finding.id,
        'fingerprint': finding.fingerprint,
        'status': 'active',
        'title': finding.title,
        'source': finding.source,
        'rule_id': finding.rule_id,
        'path': finding.location.path,
        'line': finding.location.line,
        'severity': finding.severity,
        'confidence': finding.confidence,
        'risk_score': finding.risk.score,
        'risk_tier': finding.risk.tier,
        'priority': finding.risk.priority,
        'decision': finding.decision,
        'cwe': finding.cwe,
        'owasp': finding.owasp,
        'first_seen': first_seen,
        'last_seen': scan.created_at.isoformat(),
        'last_scan_id': scan.scan_id,
        'seen_count': seen_count,
        'days_open': days_between(first_seen, scan.created_at.isoformat()),
    }


def scan_history_entry(scan: ScanResult, repo_key: str) -> dict:
    return {
        'scan_id': scan.scan_id,
        'repo_key': repo_key,
        'project_name': scan.project_name,
        'created_at': scan.created_at.isoformat(),
        'findings': scan.summary.total_findings,
        'new_findings': len(scan.new_findings),
        'resolved_findings': len(scan.resolved_findings),
        'max_risk_score': scan.summary.max_risk_score,
        'avg_risk_score': scan.summary.avg_risk_score,
        'p0': scan.summary.priorities.get('P0', 0),
        'p1': scan.summary.priorities.get('P1', 0),
        'critical': scan.summary.critical,
        'high': scan.summary.high,
        'medium': scan.summary.medium,
        'low': scan.summary.low,
    }


def update_history(history: list[dict], entry: dict, limit: int = MAX_REPO_HISTORY) -> list[dict]:
    without_duplicate = [item for item in history if item.get('scan_id') != entry['scan_id']]
    return [entry, *without_duplicate][:limit]


def scan_seen(memory: dict, repo: dict, scan_id: str) -> bool:
    return any(item.get('scan_id') == scan_id for item in repo.get('scan_history', [])) or any(item.get('scan_id') == scan_id for item in memory.get('scan_history', []))


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    return {key: counts.get(key, 0) for key in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']}


def risk_summary(scan: ScanResult) -> dict:
    return {
        'max_risk_score': scan.summary.max_risk_score,
        'avg_risk_score': scan.summary.avg_risk_score,
        'risk_tiers': scan.summary.risk_tiers,
        'priorities': scan.summary.priorities,
    }


def trend_from_history(history: list[dict]) -> dict:
    if len(history) < 2:
        return {'status': 'insufficient_history', 'scan_count': len(history)}
    current = history[0]
    previous = history[1]
    finding_delta = int(current.get('findings', 0)) - int(previous.get('findings', 0))
    max_risk_delta = int(current.get('max_risk_score', 0)) - int(previous.get('max_risk_score', 0))
    avg_risk_delta = round(float(current.get('avg_risk_score', 0)) - float(previous.get('avg_risk_score', 0)), 1)
    p0_delta = int(current.get('p0', 0)) - int(previous.get('p0', 0))
    direction = 'improving' if finding_delta < 0 and max_risk_delta <= 0 and p0_delta <= 0 else 'worsening' if finding_delta > 0 or max_risk_delta > 0 or p0_delta > 0 else 'stable'
    return {
        'status': direction,
        'scan_count': len(history),
        'finding_delta': finding_delta,
        'max_risk_delta': max_risk_delta,
        'avg_risk_delta': avg_risk_delta,
        'p0_delta': p0_delta,
        'p1_delta': int(current.get('p1', 0)) - int(previous.get('p1', 0)),
    }


def top_open_risks(active_findings: list[dict], limit: int = 10) -> list[dict]:
    ranked = sorted(active_findings, key=lambda item: (-int(item.get('risk_score', 0)), -int(item.get('seen_count', 0)), item.get('path', '')))
    return [{key: item.get(key) for key in ['finding_id', 'title', 'rule_id', 'path', 'line', 'risk_score', 'priority', 'seen_count', 'days_open']} for item in ranked[:limit]]


def recommendations(scan: ScanResult, hotspots: Counter, rules: Counter, history: list[dict], active_findings: list[dict]) -> list[str]:
    notes: list[str] = []
    p0_count = scan.summary.priorities.get('P0', 0)
    p1_count = scan.summary.priorities.get('P1', 0)
    if p0_count:
        notes.append(f'Review {p0_count} P0 findings before release or require formal risk acceptance.')
    if p1_count:
        notes.append(f'Schedule security review for {p1_count} P1 findings.')
    if hotspots:
        path, count = hotspots.most_common(1)[0]
        notes.append(f'Prioritize hotspot file {path}; it has {count} current findings.')
    recurring = [item for item in active_findings if int(item.get('seen_count', 0)) >= 3]
    if recurring:
        notes.append(f'{len(recurring)} active findings have appeared in at least three scans; treat them as recurring debt.')
    trend = trend_from_history(history)
    if trend.get('status') == 'worsening':
        notes.append('Risk trend is worsening compared with the previous scan; review new or higher-risk findings first.')
    if rules:
        rule, count = rules.most_common(1)[0]
        notes.append(f'Most frequent current rule is {rule} with {count} findings; consider a focused remediation pass.')
    return notes or ['No recurring risk pattern is visible yet; keep scanning to build trend history.']


def trim_finding_memory(finding_memory: dict[str, dict], active_fingerprints: set[str]) -> dict[str, dict]:
    if len(finding_memory) <= MAX_FINDING_MEMORY:
        return finding_memory
    active = {fp: item for fp, item in finding_memory.items() if fp in active_fingerprints}
    resolved = [(fp, item) for fp, item in finding_memory.items() if fp not in active_fingerprints]
    resolved.sort(key=lambda pair: pair[1].get('last_seen', ''), reverse=True)
    remaining_slots = max(MAX_FINDING_MEMORY - len(active), 0)
    return {**active, **dict(resolved[:remaining_slots])}


def memory_summary() -> dict:
    memory = load_memory()
    repositories = memory.get('repositories', {})
    active_findings = sum(int(repo.get('active_findings', 0)) for repo in repositories.values())
    p0 = sum(int(repo.get('risk_summary', {}).get('priorities', {}).get('P0', 0)) for repo in repositories.values())
    p1 = sum(int(repo.get('risk_summary', {}).get('priorities', {}).get('P1', 0)) for repo in repositories.values())
    return {
        'schema_version': memory.get('schema_version', 2),
        'repository_count': len(repositories),
        'scan_count': len(memory.get('scan_history', [])),
        'active_findings': active_findings,
        'p0': p0,
        'p1': p1,
        'repositories': [repository_card(repo) for repo in sorted(repositories.values(), key=lambda item: item.get('updated_at', ''), reverse=True)],
    }


def repository_card(repo: dict) -> dict:
    return {
        'repo_key': repo.get('repo_key'),
        'project_name': repo.get('project_name'),
        'path': repo.get('path'),
        'updated_at': repo.get('updated_at'),
        'last_scan_id': repo.get('last_scan_id'),
        'active_findings': repo.get('active_findings', 0),
        'risk_summary': repo.get('risk_summary', {}),
        'trend': repo.get('trend', {}),
        'top_hotspots': repo.get('top_hotspots', {}),
        'recommendations': repo.get('recommendations', []),
    }


def repository_memory(repo_key: str) -> dict:
    memory = load_memory()
    repo = memory.get('repositories', {}).get(repo_key)
    if not repo:
        raise KeyError(repo_key)
    return repo


def repository_memory_for_scan(scan: ScanResult) -> dict:
    memory = load_memory()
    repo_key = repo_id(scan.target_path)
    repo = memory.get('repositories', {}).get(repo_key)
    if not repo or repo.get('last_scan_id') != scan.scan_id:
        memory = update_repository_memory(scan)
        repo = memory.get('repositories', {}).get(repo_key, {})
    return memory_brief(repo)


def memory_brief(repo: dict) -> dict:
    return {
        'repo_key': repo.get('repo_key'),
        'project_name': repo.get('project_name'),
        'last_scan_id': repo.get('last_scan_id'),
        'updated_at': repo.get('updated_at'),
        'active_findings': repo.get('active_findings', 0),
        'risk_summary': repo.get('risk_summary', {}),
        'trend': repo.get('trend', {}),
        'top_hotspots': repo.get('top_hotspots', {}),
        'top_recurring_rules': repo.get('top_recurring_rules', {}),
        'top_open_risks': repo.get('top_open_risks', []),
        'recommendations': repo.get('recommendations', []),
        'recent_scans': repo.get('scan_history', [])[:5],
    }


def repo_id(path: str) -> str:
    return hashlib.sha256(str(Path(path).resolve()).lower().encode('utf-8')).hexdigest()[:16]


def repository_context(target_path: str) -> str:
    memory = load_memory()
    repo = memory.get('repositories', {}).get(repo_id(target_path), {})
    if not repo:
        return 'No prior repository memory exists yet.'
    return 'Repository memory: ' + json.dumps(memory_brief(repo), ensure_ascii=True)


def days_between(start: str, end: str) -> int:
    try:
        start_dt = parse_datetime(start)
        end_dt = parse_datetime(end)
        return max((end_dt - start_dt).days, 0)
    except Exception:
        return 0


def parse_datetime(value: str) -> datetime:
    text = value.replace('Z', '+00:00')
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
