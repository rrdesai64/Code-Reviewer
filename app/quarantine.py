from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import ScanResult
from .paths import data_dir

SCHEMA_VERSION = 1
REGISTRY_FILENAME = 'quarantine-registry.json'
BLOCKING_STATUSES = {'quarantined', 'blocked'}
CONTROL_KEYS = {
    'raw_code_access',
    'execution',
    'agent_learning',
    'report_inspection',
    'vm_required',
    'report_only',
}


def registry_path() -> Path:
    return data_dir() / REGISTRY_FILENAME


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_registry() -> dict[str, Any]:
    entry = make_entry(
        repository='https://github.com/samratashok/nishang',
        status='quarantined',
        severity='critical',
        reason='User reported malware in this repository. Raw-code access, host execution, and agent learning are denied by default.',
        source='user',
        tags=['malware', 'do-not-use', 'report-only'],
        aliases=['samratashok/nishang', 'samratashok__nishang', 'nishang'],
    )
    return {
        'schema_version': SCHEMA_VERSION,
        'updated_at': entry['updated_at'],
        'entries': {entry['key']: entry},
    }


def load_quarantine_registry() -> dict[str, Any]:
    path = registry_path()
    raw = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    return normalize_registry(raw)


def save_quarantine_registry(registry: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_registry(registry)
    normalized['updated_at'] = now_iso()
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(normalized, indent=2), encoding='utf-8')
    return normalized


def quarantine_registry_report() -> dict[str, Any]:
    registry = load_quarantine_registry()
    entries = sorted(registry.get('entries', {}).values(), key=lambda item: (item.get('status', ''), item.get('key', '')))
    counts: dict[str, int] = {}
    for entry in entries:
        status = str(entry.get('status') or 'clear')
        counts[status] = counts.get(status, 0) + 1
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'registry_path': str(registry_path()),
        'total_entries': len(entries),
        'status_counts': counts,
        'entries': entries,
        'guardrails': registry_guardrails(),
    }


def normalize_registry(raw: dict[str, Any] | None) -> dict[str, Any]:
    normalized = {
        'schema_version': SCHEMA_VERSION,
        'updated_at': str((raw or {}).get('updated_at') or now_iso()),
        'entries': {},
    }
    entries = (raw or {}).get('entries', {})
    if isinstance(entries, list):
        iterable = entries
    elif isinstance(entries, dict):
        iterable = entries.values()
    else:
        iterable = []
    for item in iterable:
        if not isinstance(item, dict):
            continue
        entry = normalize_entry(item)
        normalized['entries'][entry['key']] = entry
    for key, entry in default_registry()['entries'].items():
        normalized['entries'].setdefault(key, entry)
    return normalized


def normalize_entry(item: dict[str, Any]) -> dict[str, Any]:
    repository = str(item.get('repository') or item.get('url') or item.get('key') or '').strip()
    key = canonical_repository_key(str(item.get('key') or repository))
    if not key:
        key = canonical_repository_key(repository)
    status = normalize_status(str(item.get('status') or 'quarantined'))
    created_at = str(item.get('created_at') or now_iso())
    updated_at = str(item.get('updated_at') or created_at)
    aliases = sorted(candidate_repository_keys(repository) | candidate_repository_keys(key) | {canonical_repository_key(str(alias)) for alias in item.get('aliases', []) if str(alias).strip()})
    aliases = [alias for alias in aliases if alias]
    controls = default_controls(status)
    controls.update(normalize_controls(item.get('controls') or {}))
    return {
        'key': key,
        'repository': repository or key,
        'status': status,
        'severity': str(item.get('severity') or default_severity(status)),
        'reason': str(item.get('reason') or ''),
        'source': str(item.get('source') or 'user'),
        'created_at': created_at,
        'updated_at': updated_at,
        'aliases': aliases,
        'tags': sorted({str(tag).strip() for tag in item.get('tags', []) if str(tag).strip()}),
        'controls': controls,
    }


def make_entry(
    repository: str,
    status: str = 'quarantined',
    reason: str = '',
    source: str = 'user',
    severity: str | None = None,
    tags: list[str] | None = None,
    aliases: list[str] | None = None,
    controls: dict[str, bool] | None = None,
) -> dict[str, Any]:
    timestamp = now_iso()
    key = canonical_repository_key(repository)
    merged_controls = default_controls(status)
    merged_controls.update(normalize_controls(controls or {}))
    alias_set = candidate_repository_keys(repository)
    for alias in aliases or []:
        alias_set.update(candidate_repository_keys(alias))
    return normalize_entry({
        'key': key,
        'repository': repository,
        'status': status,
        'severity': severity or default_severity(status),
        'reason': reason,
        'source': source,
        'created_at': timestamp,
        'updated_at': timestamp,
        'aliases': sorted(alias_set),
        'tags': tags or [],
        'controls': merged_controls,
    })


def upsert_quarantine_entry(payload: dict[str, Any]) -> dict[str, Any]:
    repository = str(payload.get('repository') or payload.get('key') or '').strip()
    if not repository:
        raise ValueError('repository is required')
    registry = load_quarantine_registry()
    key = canonical_repository_key(repository)
    existing = registry.get('entries', {}).get(key, {})
    created_at = existing.get('created_at') or now_iso()
    entry = make_entry(
        repository=repository,
        status=str(payload.get('status') or existing.get('status') or 'quarantined'),
        reason=str(payload.get('reason') or existing.get('reason') or ''),
        source=str(payload.get('source') or existing.get('source') or 'user'),
        severity=str(payload.get('severity') or existing.get('severity') or ''),
        tags=list(payload.get('tags') or existing.get('tags') or []),
        aliases=list(payload.get('aliases') or existing.get('aliases') or []),
        controls=dict(payload.get('controls') or existing.get('controls') or {}),
    )
    entry['created_at'] = created_at
    entry['updated_at'] = now_iso()
    registry['entries'][entry['key']] = entry
    return save_quarantine_registry(registry)['entries'][entry['key']]


def quarantine_policy_for_scan(scan: ScanResult) -> dict[str, Any]:
    return quarantine_policy(repository=scan.target_path, project_name=scan.project_name)


def quarantine_policy(repository: str, project_name: str | None = None) -> dict[str, Any]:
    entry = find_quarantine_entry(repository=repository, project_name=project_name)
    if not entry:
        controls = default_controls('clear')
        return {
            'schema_version': SCHEMA_VERSION,
            'generated_at': now_iso(),
            'matched': False,
            'status': 'clear',
            'severity': 'none',
            'repository': repository,
            'project_name': project_name,
            'controls': controls,
            'entry': None,
            'guidance': ['No quarantine entry matched this repository. Use normal scanner guardrails.'],
        }
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'matched': True,
        'status': entry['status'],
        'severity': entry['severity'],
        'repository': repository,
        'project_name': project_name,
        'controls': entry['controls'],
        'entry': entry,
        'guidance': guidance_for_entry(entry),
    }


def find_quarantine_entry(repository: str, project_name: str | None = None) -> dict[str, Any] | None:
    candidates = candidate_repository_keys(repository)
    if project_name:
        candidates.update(candidate_repository_keys(project_name))
    registry = load_quarantine_registry()
    for entry in registry.get('entries', {}).values():
        entry_keys = set(entry.get('aliases') or [])
        entry_keys.update(candidate_repository_keys(str(entry.get('key') or '')))
        entry_keys.update(candidate_repository_keys(str(entry.get('repository') or '')))
        if candidates & entry_keys:
            return entry
    return None


def blocks_host_scan(repository: str, project_name: str | None = None) -> bool:
    policy = quarantine_policy(repository, project_name=project_name)
    controls = policy.get('controls', {})
    return bool(policy.get('matched') and (not controls.get('raw_code_access', True) or controls.get('report_only', False)))


def allows_agent_learning(scan: ScanResult) -> bool:
    return bool(quarantine_policy_for_scan(scan).get('controls', {}).get('agent_learning', True))


def normalize_status(status: str) -> str:
    value = status.strip().lower().replace('-', '_')
    if value in {'clear', 'watch', 'quarantined', 'blocked'}:
        return value
    return 'quarantined'


def default_severity(status: str) -> str:
    return {'clear': 'none', 'watch': 'medium', 'quarantined': 'critical', 'blocked': 'critical'}.get(normalize_status(status), 'critical')


def default_controls(status: str) -> dict[str, bool]:
    normalized = normalize_status(status)
    if normalized == 'clear':
        return {
            'raw_code_access': True,
            'execution': True,
            'agent_learning': True,
            'report_inspection': True,
            'vm_required': False,
            'report_only': False,
        }
    if normalized == 'watch':
        return {
            'raw_code_access': True,
            'execution': False,
            'agent_learning': False,
            'report_inspection': True,
            'vm_required': True,
            'report_only': False,
        }
    return {
        'raw_code_access': False,
        'execution': False,
        'agent_learning': False,
        'report_inspection': True,
        'vm_required': True,
        'report_only': True,
    }


def normalize_controls(controls: dict[str, Any]) -> dict[str, bool]:
    return {key: bool(value) for key, value in controls.items() if key in CONTROL_KEYS}


def canonical_repository_key(value: str) -> str:
    text = str(value or '').strip().strip('"\'')
    if not text:
        return ''
    text = text.rstrip('/')
    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        host = parsed.netloc.lower()
        parts = [part for part in parsed.path.strip('/').split('/') if part]
        if len(parts) >= 2:
            return f'{host}/{clean_repo_part(parts[0])}/{clean_repo_part(parts[1])}'
        return f'{host}/{clean_repo_part(parts[0])}' if parts else host
    match = re.search(r'github\.com[:/](?P<owner>[^/\s:]+)[/](?P<repo>[^/\s:]+)', text, re.I)
    if match:
        return f"github.com/{clean_repo_part(match.group('owner'))}/{clean_repo_part(match.group('repo'))}"
    name = basename(text)
    owner_repo = re.match(r'(?P<owner>[A-Za-z0-9_.-]+)__(?P<repo>[A-Za-z0-9_.-]+)$', name)
    if owner_repo:
        return f"{clean_repo_part(owner_repo.group('owner'))}/{clean_repo_part(owner_repo.group('repo'))}"
    slash_repo = re.match(r'(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)$', text)
    if slash_repo:
        return f"{clean_repo_part(slash_repo.group('owner'))}/{clean_repo_part(slash_repo.group('repo'))}"
    return clean_repo_part(name or text)


def candidate_repository_keys(value: str) -> set[str]:
    key = canonical_repository_key(value)
    candidates = {key} if key else set()
    parts = key.split('/')
    if len(parts) >= 3 and '.' in parts[0]:
        owner, repo = parts[-2], parts[-1]
        candidates.update({f'{owner}/{repo}', f'{owner}__{repo}', repo})
    elif len(parts) == 2:
        owner, repo = parts
        candidates.update({f'github.com/{owner}/{repo}', f'{owner}__{repo}', repo})
    elif key:
        candidates.add(key.replace('__', '/'))
    name = basename(value)
    if name:
        candidates.add(clean_repo_part(name))
        name_match = re.match(r'(?P<owner>[A-Za-z0-9_.-]+)__(?P<repo>[A-Za-z0-9_.-]+)$', name)
        if name_match:
            owner = clean_repo_part(name_match.group('owner'))
            repo = clean_repo_part(name_match.group('repo'))
            candidates.update({f'{owner}/{repo}', f'github.com/{owner}/{repo}', f'{owner}__{repo}', repo})
    return {candidate for candidate in candidates if candidate}


def clean_repo_part(value: str) -> str:
    cleaned = re.sub(r'\.git$', '', str(value or '').strip(), flags=re.I)
    return re.sub(r'[^a-z0-9._-]+', '-', cleaned.lower()).strip('-._')


def basename(value: str) -> str:
    text = str(value or '').strip().rstrip('/\\')
    if not text:
        return ''
    return re.split(r'[\\/]', text)[-1]


def guidance_for_entry(entry: dict[str, Any]) -> list[str]:
    controls = entry.get('controls', {})
    guidance = [
        'Treat the repository as hostile input.',
        'Do not execute code, build scripts, tests, package managers, or generated binaries on the host.',
    ]
    if not controls.get('raw_code_access', True):
        guidance.append('Do not inspect or index raw source outside a disposable VM or an approved report-only workflow.')
    if not controls.get('agent_learning', True):
        guidance.append('Do not feed raw code or unsanitized findings from this repository into agent memory or recursive learning.')
    if controls.get('report_inspection', False):
        guidance.append('Only sanitized, inert reports may be inspected after explicit user approval.')
    return guidance


def registry_guardrails() -> list[str]:
    return [
        'Quarantine entries are deny-by-default for host execution and agent learning.',
        'Known malicious repositories must be handled through report-only or disposable-VM workflows.',
        'Raw source from quarantined repositories must not be used for RAG memory, fine-tuning, or prompt context.',
        'Changing a quarantine entry is an auditable governance action.',
    ]
