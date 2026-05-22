from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath
from typing import Any

PRODUCTION_SCOPES = {'production', 'config', 'dependency'}
NON_PRODUCTION_SCOPES = {'test', 'docs', 'example', 'generated', 'unknown'}
SECRET_SOURCES = {'secret-scan', 'gitleaks', 'trufflehog'}
EXTERNAL_SECRET_SOURCES = {'gitleaks', 'trufflehog'}

TEST_DIRS = {'test', 'tests', '__tests__', 'spec', 'specs', 'fixtures', '__fixtures__'}
DOC_DIRS = {'doc', 'docs', 'documentation', 'manual', 'manuals'}
EXAMPLE_DIRS = {'example', 'examples', 'sample', 'samples', 'demo', 'demos'}
GENERATED_DIRS = {'generated', 'gen', 'coverage', 'htmlcov'}
DEPENDENCY_NAMES = {
    'requirements.txt', 'requirements-dev.txt', 'requirements-test.txt', 'requirements-prod.txt',
    'pyproject.toml', 'poetry.lock', 'pipfile', 'pipfile.lock', 'package.json', 'package-lock.json',
    'yarn.lock', 'pnpm-lock.yaml', 'go.mod', 'go.sum', 'cargo.toml', 'cargo.lock', 'pom.xml',
    'build.gradle', 'gradle.lockfile', 'composer.json', 'composer.lock',
}
CONFIG_NAMES = {
    'dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.gitlab-ci.yml', 'azure-pipelines.yml',
    'bitbucket-pipelines.yml', '.pre-commit-config.yaml', '.pre-commit-config.yml',
}
CONFIG_SUFFIXES = {
    '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf', '.properties', '.tf', '.tfvars',
}


def classify_path_scope(path: str) -> str:
    normalized = normalize_path(path)
    if not normalized:
        return 'unknown'
    pure = PurePosixPath(normalized)
    parts = [part.lower() for part in pure.parts if part not in {'', '.'}]
    name = pure.name.lower()
    suffix = pure.suffix.lower()
    if any(part in GENERATED_DIRS for part in parts):
        return 'generated'
    if any(part in TEST_DIRS for part in parts) or name.startswith('test_') or name.endswith('_test.py') or name.endswith('.spec.js') or name.endswith('.test.js'):
        return 'test'
    if any(part in DOC_DIRS for part in parts) or name in {'readme.md', 'changelog.md', 'license', 'license.md'}:
        return 'docs'
    if any(part in EXAMPLE_DIRS for part in parts):
        return 'example'
    if name in DEPENDENCY_NAMES or name.startswith('requirements') and name.endswith('.txt'):
        return 'dependency'
    if '.github' in parts or name in CONFIG_NAMES or name.startswith('.env') or suffix in CONFIG_SUFFIXES:
        return 'config'
    return 'production'


def apply_finding_scope(finding: Any) -> Any:
    scope = classify_path_scope(getattr(getattr(finding, 'location', None), 'path', ''))
    finding.scope = scope
    metadata = dict(getattr(finding, 'scanner_metadata', None) or {})
    metadata['scope'] = scope
    metadata['production_impacting'] = str(is_production_impacting(finding)).lower()
    finding.scanner_metadata = metadata
    return finding


def finding_scope(finding: Any) -> str:
    scope = getattr(finding, 'scope', None) or (getattr(finding, 'scanner_metadata', None) or {}).get('scope')
    return str(scope or classify_path_scope(getattr(getattr(finding, 'location', None), 'path', '')))


def is_production_scope(scope: str) -> bool:
    return scope in PRODUCTION_SCOPES


def is_secret_like(finding: Any) -> bool:
    source = getattr(finding, 'source', '')
    rule_id = str(getattr(finding, 'rule_id', '')).lower()
    title = str(getattr(finding, 'title', '')).lower()
    return source in SECRET_SOURCES or 'secret' in rule_id or 'token' in rule_id or 'credential' in title


def is_blocking_secret(finding: Any) -> bool:
    if not is_secret_like(finding):
        return False
    source = getattr(finding, 'source', '')
    severity = str(getattr(finding, 'severity', '')).upper()
    confidence = str(getattr(finding, 'confidence', '')).upper()
    if source in EXTERNAL_SECRET_SOURCES:
        return severity == 'CRITICAL' or (severity == 'HIGH' and confidence == 'HIGH')
    return severity == 'CRITICAL' or (severity == 'HIGH' and confidence == 'HIGH')


def is_production_impacting(finding: Any) -> bool:
    if is_blocking_secret(finding):
        return True
    scope = finding_scope(finding)
    if scope == 'dependency':
        metadata = getattr(finding, 'scanner_metadata', None) or {}
        dependency_scope = metadata.get('dependency_scope', '')
        reachability = metadata.get('dependency_reachability') or getattr(finding, 'reachability', '')
        if dependency_scope == 'optional' or reachability in {'dev-or-optional', 'reachable-test-import'}:
            return False
    return is_production_scope(scope)


def production_gate_findings(findings: list[Any]) -> list[Any]:
    return [finding for finding in findings if is_production_impacting(finding)]


def hygiene_findings(findings: list[Any]) -> list[Any]:
    return [finding for finding in findings if not is_production_impacting(finding)]


def scope_counts(findings: list[Any]) -> dict[str, int]:
    return dict(sorted(Counter(finding_scope(finding) for finding in findings).items()))


def scope_sort_rank(finding: Any) -> int:
    scope = finding_scope(finding)
    if is_production_impacting(finding):
        return 4
    return {'test': 3, 'config': 4, 'dependency': 4, 'docs': 2, 'example': 2, 'generated': 1}.get(scope, 0)


def normalize_path(path: str) -> str:
    value = str(path or '').replace('\\', '/').strip()
    return value[2:] if value.startswith('./') else value
