from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanResult
from .scanner import LANG_BY_EXT, iter_source_files

ROOT = Path(__file__).resolve().parents[1]
MEMORY_PATH = ROOT / 'data' / 'memory.json'


def load_memory() -> dict:
    if not MEMORY_PATH.exists():
        return {'repositories': {}, 'scan_history': [], 'hotspots': {}, 'recurring_rules': {}}
    return json.loads(MEMORY_PATH.read_text(encoding='utf-8'))


def save_memory(memory: dict) -> None:
    MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    MEMORY_PATH.write_text(json.dumps(memory, indent=2), encoding='utf-8')


def update_repository_memory(scan: ScanResult) -> dict:
    memory = load_memory()
    repo_key = repo_id(scan.target_path)
    target = Path(scan.target_path)
    files = list(iter_source_files(target)) if target.exists() else []
    languages = Counter(LANG_BY_EXT.get(path.suffix.lower(), 'Other') for path in files)
    hotspots = Counter(finding.location.path for finding in scan.findings)
    rules = Counter(finding.rule_id for finding in scan.findings)
    severities = Counter(finding.severity for finding in scan.findings)
    memory['repositories'][repo_key] = {
        'path': scan.target_path,
        'project_name': scan.project_name,
        'last_scan_id': scan.scan_id,
        'updated_at': datetime.now(timezone.utc).isoformat(),
        'files_scanned': scan.summary.files_scanned,
        'languages': dict(languages),
        'top_hotspots': dict(hotspots.most_common(10)),
        'severity_counts': dict(severities),
    }
    memory.setdefault('scan_history', []).insert(0, {
        'scan_id': scan.scan_id,
        'repo_key': repo_key,
        'project_name': scan.project_name,
        'created_at': scan.created_at.isoformat(),
        'findings': scan.summary.total_findings,
        'new_findings': len(scan.new_findings),
        'resolved_findings': len(scan.resolved_findings),
    })
    memory['scan_history'] = memory['scan_history'][:100]
    memory.setdefault('hotspots', {})[repo_key] = dict(hotspots.most_common(25))
    memory.setdefault('recurring_rules', {})[repo_key] = dict(rules.most_common(25))
    save_memory(memory)
    return memory


def repo_id(path: str) -> str:
    return hashlib.sha256(str(Path(path).resolve()).lower().encode('utf-8')).hexdigest()[:16]


def repository_context(target_path: str) -> str:
    memory = load_memory()
    repo = memory.get('repositories', {}).get(repo_id(target_path), {})
    if not repo:
        return 'No prior repository memory exists yet.'
    hotspots = repo.get('top_hotspots', {})
    severities = repo.get('severity_counts', {})
    return 'Repository memory: ' + json.dumps({'project': repo.get('project_name'), 'hotspots': hotspots, 'severities': severities}, ensure_ascii=True)
