from __future__ import annotations

import ast
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Finding, ScanResult
from .scope import classify_path_scope
from .sbom import (
    SbomComponent,
    attach_missing_vulnerable_components,
    canonical_name,
    component_version_value,
    dedupe_components,
    excluded,
    license_review_status,
    read_package_json,
    read_package_lock,
    read_pyproject,
    read_python_requirements,
    relpath,
)

DEPENDENCY_SOURCES = {'pip-audit', 'dependency-manifest', 'snyk'}
RUNTIME_REACHABILITY = {'reachable-source-import', 'direct-manifest'}
UNKNOWN_REACHABILITY = {'manifest-only', 'transitive-unknown', 'package-level', 'unknown'}
SEVERITY_POINTS = {'CRITICAL': 72, 'HIGH': 56, 'MEDIUM': 34, 'LOW': 16, 'INFO': 4}
REACHABILITY_POINTS = {
    'reachable-source-import': 20,
    'direct-manifest': 12,
    'reachable-test-import': 2,
    'manifest-only': 5,
    'transitive-unknown': 2,
    'dev-or-optional': 1,
    'unknown': 0,
}
PYTHON_IMPORT_ALIASES = {
    'beautifulsoup4': {'bs4'},
    'opencv-python': {'cv2'},
    'pillow': {'PIL'},
    'pyjwt': {'jwt'},
    'pyyaml': {'yaml'},
    'python-dateutil': {'dateutil'},
    'python-jose': {'jose'},
    'scikit-learn': {'sklearn'},
}
PYTHON_FILE_EXTENSIONS = {'.py'}
JAVASCRIPT_FILE_EXTENSIONS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
JS_IMPORT_RE = re.compile(r'''(?:from\s*|require\(\s*|import\(\s*|import\s+)['"]([^'"]+)['"]''')


@dataclass(frozen=True)
class DependencyUsage:
    path: str
    line: int
    kind: str
    symbol: str

    def as_dict(self) -> dict[str, Any]:
        return {'path': self.path, 'line': self.line, 'kind': self.kind, 'symbol': self.symbol, 'scope': classify_path_scope(self.path)}


def dependency_review_report(scan: ScanResult) -> dict[str, Any]:
    context = build_dependency_context(Path(scan.target_path), scan.findings)
    components = context['components']
    review_items = [component_review_item(component, context) for component in components]
    vulnerabilities = [vuln for item in review_items for vuln in item['vulnerabilities']]
    reachable_vulnerabilities = [vuln for item in review_items if item['reachability']['status'] in RUNTIME_REACHABILITY for vuln in item['vulnerabilities']]
    unknown_vulnerabilities = [vuln for item in review_items if item['reachability']['status'] in UNKNOWN_REACHABILITY for vuln in item['vulnerabilities']]
    fixable_vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get('fix_versions')]
    policy = dependency_policy(review_items)
    by_reachability = Counter(item['reachability']['status'] for item in review_items)
    by_scope = Counter(item['scope'] for item in review_items)
    by_ecosystem = Counter(item['ecosystem'] for item in review_items)
    by_priority = Counter(item['priority'] for item in review_items)
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': policy['status'],
        'counts': {
            'components': len(review_items),
            'vulnerable_components': sum(1 for item in review_items if item['vulnerabilities']),
            'vulnerabilities': len(vulnerabilities),
            'reachable_vulnerabilities': len(reachable_vulnerabilities),
            'unknown_reachability_vulnerabilities': len(unknown_vulnerabilities),
            'fixable_vulnerabilities': len(fixable_vulnerabilities),
            'source_usage_evidence': sum(len(item['reachability']['evidence']) for item in review_items),
        },
        'risk_model': {
            'severity_points': SEVERITY_POINTS,
            'reachability_points': REACHABILITY_POINTS,
            'runtime_reachability': sorted(RUNTIME_REACHABILITY),
            'unknown_reachability': sorted(UNKNOWN_REACHABILITY),
        },
        'breakdown': {
            'ecosystems': dict(sorted(by_ecosystem.items())),
            'scopes': dict(sorted(by_scope.items())),
            'reachability': dict(sorted(by_reachability.items())),
            'priorities': dict(sorted(by_priority.items())),
        },
        'policy': policy,
        'top_risks': sorted(review_items, key=lambda item: (-item['risk_score'], item['ecosystem'], item['name']))[:20],
        'components': review_items,
    }


def enrich_dependency_findings(target: Path, findings: list[Finding]) -> list[Finding]:
    context = build_dependency_context(target, findings)
    review_by_key = {item['key']: item for item in (component_review_item(component, context) for component in context['components'])}
    for finding in findings:
        if finding.source not in DEPENDENCY_SOURCES:
            continue
        package = dependency_package_from_finding(finding)
        ecosystem = dependency_ecosystem_from_finding(finding)
        if not package:
            continue
        key = component_key(ecosystem, package)
        review = review_by_key.get(key)
        if not review:
            continue
        metadata = dict(finding.scanner_metadata or {})
        reachability = review['reachability']
        vulnerabilities = review['vulnerabilities']
        fix_versions = sorted({version for vuln in vulnerabilities for version in vuln.get('fix_versions', [])})
        metadata.update(
            {
                'dependency_ecosystem': review['ecosystem'],
                'dependency_name': review['name'],
                'dependency_version': str(review['version']),
                'dependency_scope': str(review['scope']),
                'dependency_type': str(review['dependency_type']),
                'dependency_reachability': str(reachability['status']),
                'dependency_reachability_confidence': str(reachability['confidence']),
                'dependency_usage_count': str(len(reachability['evidence'])),
                'dependency_risk_score': str(review['risk_score']),
                'dependency_priority': str(review['priority']),
            }
        )
        if fix_versions:
            metadata['fix_versions'] = ','.join(fix_versions)
            metadata['best_fix_version'] = choose_fix_version(fix_versions)
        if reachability['evidence']:
            metadata['dependency_evidence'] = '; '.join(format_evidence(item) for item in reachability['evidence'][:5])[:500]
        finding.scanner_metadata = metadata
        finding.reachability = reachability['status']
        if vulnerabilities and reachability['status'] == 'reachable-source-import':
            finding.exploitability = 'reachable-known-vulnerability'
        if 'dependency-review' not in finding.policy_impact:
            finding.policy_impact.append('dependency-review')
        if review['risk_score'] >= 85 and 'release-gate' not in finding.policy_impact:
            finding.policy_impact.append('release-gate')
        if fix_versions:
            guidance = f'Upgrade {review["name"]} to {choose_fix_version(fix_versions)} or another non-vulnerable version after compatibility testing.'
            if guidance not in finding.remediation:
                finding.remediation.append(guidance)
        evidence_note = reachability_note(review)
        if evidence_note and evidence_note not in finding.remediation:
            finding.remediation.append(evidence_note)
    return findings


def build_dependency_context(target: Path, findings: list[Finding]) -> dict[str, Any]:
    components = attach_missing_vulnerable_components(discover_target_components(target), findings)
    usage = collect_dependency_usage(target, components)
    vulnerabilities = dependency_vulnerabilities(findings)
    vulnerabilities_by_key: dict[str, list[dict[str, Any]]] = {}
    for vuln in vulnerabilities:
        vulnerabilities_by_key.setdefault(component_key(vuln['ecosystem'], vuln['package']), []).append(vuln)
    return {
        'target': target,
        'components': components,
        'usage': usage,
        'vulnerabilities': vulnerabilities,
        'vulnerabilities_by_key': vulnerabilities_by_key,
    }


def discover_target_components(target: Path) -> list[SbomComponent]:
    if not target.exists() or not target.is_dir():
        return []
    components: list[SbomComponent] = []
    components.extend(read_python_requirements(target))
    components.extend(read_pyproject(target))
    components.extend(read_package_json(target))
    components.extend(read_package_lock(target))
    return dedupe_components(components)


def component_review_item(component: SbomComponent, context: dict[str, Any]) -> dict[str, Any]:
    key = component.key
    vulnerabilities = context['vulnerabilities_by_key'].get(key, [])
    evidence = context['usage'].get(key, [])
    reachability = component_reachability(component, evidence)
    risk_score, risk_factors = component_risk(component, vulnerabilities, reachability)
    return {
        'key': key,
        'ecosystem': component.ecosystem,
        'name': component.name,
        'version': component_version_value(component),
        'version_spec': component.version_spec,
        'scope': component.scope,
        'dependency_type': dependency_type(component),
        'manifest_path': component.manifest_path,
        'package_manager': component.package_manager,
        'purl': component.purl,
        'license': component.license_expression,
        'license_status': license_review_status(component),
        'reachability': reachability,
        'vulnerabilities': vulnerabilities,
        'risk_score': risk_score,
        'priority': priority_for_score(risk_score),
        'risk_factors': risk_factors,
        'recommended_action': dependency_action(risk_score, vulnerabilities, reachability),
    }


def component_reachability(component: SbomComponent, evidence: list[DependencyUsage]) -> dict[str, Any]:
    production_evidence = [item for item in evidence if classify_path_scope(item.path) in {'production', 'config'}]
    if production_evidence:
        status = 'reachable-source-import'
        confidence = 'high'
    elif evidence:
        status = 'reachable-test-import'
        confidence = 'medium'
    elif dependency_type(component) == 'direct' and component.scope == 'required':
        status = 'direct-manifest'
        confidence = 'medium'
    elif component.scope == 'optional':
        status = 'dev-or-optional'
        confidence = 'medium'
    elif dependency_type(component) == 'lockfile':
        status = 'transitive-unknown'
        confidence = 'low'
    else:
        status = 'manifest-only'
        confidence = 'low'
    return {
        'status': status,
        'confidence': confidence,
        'evidence': [item.as_dict() for item in evidence[:10]],
        'production_evidence_count': len(production_evidence),
        'evidence_count': len(evidence),
    }


def component_risk(component: SbomComponent, vulnerabilities: list[dict[str, Any]], reachability: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    factors: list[dict[str, Any]] = []
    if vulnerabilities:
        max_severity = max(vulnerabilities, key=lambda item: SEVERITY_POINTS.get(item['severity'], 0))['severity']
        add_risk_factor(factors, 'vulnerability-severity', 'Highest vulnerability severity', SEVERITY_POINTS.get(max_severity, 4), max_severity)
        if any(vuln.get('fix_versions') for vuln in vulnerabilities):
            add_risk_factor(factors, 'fix-available', 'Fix version available', 3, 'At least one advisory includes a fixed version.')
        else:
            add_risk_factor(factors, 'fix-unavailable', 'No fix version recorded', 6, 'No fixed version is available in the scanner output.')
    add_risk_factor(factors, 'reachability', 'Dependency reachability', REACHABILITY_POINTS.get(reachability['status'], 0), reachability['status'])
    if component.scope == 'required':
        add_risk_factor(factors, 'runtime-scope', 'Runtime dependency scope', 6, 'Required dependency')
    if dependency_type(component) == 'direct':
        add_risk_factor(factors, 'direct-dependency', 'Direct manifest dependency', 5, component.manifest_path)
    if license_review_status(component) in {'unknown', 'legal_review_required', 'prohibited'}:
        add_risk_factor(factors, 'license-review', 'License review signal', 4, license_review_status(component))
    score = max(0, min(100, sum(item['points'] for item in factors)))
    return score, factors


def add_risk_factor(factors: list[dict[str, Any]], name: str, label: str, points: int, detail: str) -> None:
    if points:
        factors.append({'name': name, 'label': label, 'points': points, 'detail': detail})


def dependency_policy(items: list[dict[str, Any]]) -> dict[str, Any]:
    reachable_critical = [item for item in items if item['reachability']['status'] in RUNTIME_REACHABILITY and any(vuln['severity'] == 'CRITICAL' for vuln in item['vulnerabilities'])]
    reachable_high = [item for item in items if item['reachability']['status'] in RUNTIME_REACHABILITY and any(vuln['severity'] == 'HIGH' for vuln in item['vulnerabilities'])]
    unknown_vulnerable = [item for item in items if item['reachability']['status'] in UNKNOWN_REACHABILITY and item['vulnerabilities']]
    no_fix = [item for item in items if item['vulnerabilities'] and not any(vuln.get('fix_versions') for vuln in item['vulnerabilities'])]
    policies = [
        {
            'id': 'no-reachable-critical-vulnerabilities',
            'description': 'Fail when a critical vulnerable package is reachable from source or direct runtime manifests.',
            'status': 'failed' if reachable_critical else 'passed',
            'violations': [dependency_policy_item(item) for item in reachable_critical],
        },
        {
            'id': 'reachable-high-vulnerabilities-reviewed',
            'description': 'Warn when high severity vulnerable packages are reachable and need security review.',
            'status': 'warning' if reachable_high else 'passed',
            'violations': [dependency_policy_item(item) for item in reachable_high],
        },
        {
            'id': 'unknown-reachability-vulnerabilities-reviewed',
            'description': 'Warn when vulnerable packages have insufficient source reachability evidence.',
            'status': 'warning' if unknown_vulnerable else 'passed',
            'violations': [dependency_policy_item(item) for item in unknown_vulnerable],
        },
        {
            'id': 'fix-version-required-for-vulnerable-packages',
            'description': 'Warn when vulnerable packages do not include a fix version in scanner output.',
            'status': 'warning' if no_fix else 'passed',
            'violations': [dependency_policy_item(item) for item in no_fix],
        },
    ]
    failed = any(policy['status'] == 'failed' for policy in policies)
    warning = any(policy['status'] == 'warning' for policy in policies)
    return {'status': 'failed' if failed else 'warning' if warning else 'passed', 'policies': policies}


def dependency_policy_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        'ecosystem': item['ecosystem'],
        'name': item['name'],
        'version': item['version'],
        'manifest_path': item['manifest_path'],
        'reachability': item['reachability']['status'],
        'risk_score': item['risk_score'],
        'priority': item['priority'],
        'vulnerability_ids': [vuln['id'] for vuln in item['vulnerabilities']],
    }


def dependency_vulnerabilities(findings: list[Finding]) -> list[dict[str, Any]]:
    vulnerabilities: list[dict[str, Any]] = []
    for finding in findings:
        if finding.source not in {'pip-audit', 'snyk'}:
            continue
        package = dependency_package_from_finding(finding)
        if not package:
            continue
        ecosystem = dependency_ecosystem_from_finding(finding)
        metadata = finding.scanner_metadata or {}
        version = metadata.get('version') or metadata.get('dependency_version') or parse_version_from_message(finding.message)
        fix_versions = normalize_fix_versions(metadata.get('fix_versions'))
        vulnerabilities.append(
            {
                'id': finding.rule_id,
                'finding_id': finding.id,
                'ecosystem': ecosystem,
                'package': package,
                'version': version,
                'severity': finding.severity,
                'description': finding.message,
                'fix_versions': fix_versions,
                'best_fix_version': choose_fix_version(fix_versions),
                'references': finding.references,
                'risk_score': finding.risk.score,
                'priority': finding.risk.priority,
            }
        )
    return vulnerabilities


def collect_dependency_usage(target: Path, components: list[SbomComponent]) -> dict[str, list[DependencyUsage]]:
    python_aliases: dict[str, str] = {}
    npm_aliases: dict[str, str] = {}
    for component in components:
        if component.ecosystem == 'pypi':
            for alias in python_aliases_for_package(component.name):
                python_aliases[alias.lower()] = component.key
        elif component.ecosystem == 'npm':
            npm_aliases[canonical_name('npm', component.name)] = component.key
    usage: dict[str, list[DependencyUsage]] = {}
    collect_python_usage(target, python_aliases, usage)
    collect_javascript_usage(target, npm_aliases, usage)
    return usage


def collect_python_usage(target: Path, aliases: dict[str, str], usage: dict[str, list[DependencyUsage]]) -> None:
    if not aliases:
        return
    for path in sorted(target.rglob('*')):
        if excluded(path) or not path.is_file() or path.suffix.lower() not in PYTHON_FILE_EXTENSIONS:
            continue
        try:
            tree = ast.parse(path.read_text(encoding='utf-8', errors='ignore'))
        except SyntaxError:
            continue
        rel = relpath(path, target)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split('.', 1)[0].lower()
                    key = aliases.get(root)
                    if key:
                        usage.setdefault(key, []).append(DependencyUsage(rel, getattr(node, 'lineno', 1), 'python-import', alias.name))
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split('.', 1)[0].lower()
                key = aliases.get(root)
                if key:
                    usage.setdefault(key, []).append(DependencyUsage(rel, getattr(node, 'lineno', 1), 'python-from-import', node.module))


def collect_javascript_usage(target: Path, aliases: dict[str, str], usage: dict[str, list[DependencyUsage]]) -> None:
    if not aliases:
        return
    for path in sorted(target.rglob('*')):
        if excluded(path) or not path.is_file() or path.suffix.lower() not in JAVASCRIPT_FILE_EXTENSIONS:
            continue
        rel = relpath(path, target)
        for line_no, line in enumerate(path.read_text(encoding='utf-8', errors='ignore').splitlines(), 1):
            for match in JS_IMPORT_RE.finditer(line):
                module = npm_module_root(match.group(1))
                key = aliases.get(canonical_name('npm', module))
                if key:
                    usage.setdefault(key, []).append(DependencyUsage(rel, line_no, 'javascript-import', module))


def python_aliases_for_package(package: str) -> set[str]:
    canonical = canonical_name('pypi', package)
    aliases = {canonical.replace('-', '_')}
    aliases.update(PYTHON_IMPORT_ALIASES.get(canonical, set()))
    aliases.add(package.replace('-', '_'))
    return {alias for alias in aliases if alias}


def npm_module_root(specifier: str) -> str:
    value = specifier.strip()
    if value.startswith('.') or value.startswith('/'):
        return ''
    if value.startswith('@'):
        parts = value.split('/')
        return '/'.join(parts[:2]) if len(parts) >= 2 else value
    return value.split('/', 1)[0]


def dependency_type(component: SbomComponent) -> str:
    name = Path(component.manifest_path).name.lower()
    if name.startswith('requirements') and name.endswith('.txt'):
        return 'direct'
    if name in {'pyproject.toml', 'package.json'}:
        return 'direct'
    if name in {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'}:
        return 'lockfile'
    if component.manifest_path:
        return 'manifest'
    return 'vulnerable-only'


def dependency_package_from_finding(finding: Finding) -> str:
    metadata = finding.scanner_metadata or {}
    if metadata.get('package'):
        return metadata['package']
    if metadata.get('dependency_name'):
        return metadata['dependency_name']
    if finding.title.startswith('Vulnerable dependency:'):
        return finding.title.replace('Vulnerable dependency:', '').strip()
    match = re.search(r'(?:dependency|package)\s+([A-Za-z0-9_.@/-]+)', finding.message, re.I)
    return match.group(1) if match else ''


def dependency_ecosystem_from_finding(finding: Finding) -> str:
    metadata = finding.scanner_metadata or {}
    if metadata.get('dependency_ecosystem'):
        return metadata['dependency_ecosystem']
    if metadata.get('ecosystem'):
        return metadata['ecosystem']
    if finding.rule_id.startswith('node-') or 'Node dependency' in finding.message:
        return 'npm'
    return 'pypi'


def component_key(ecosystem: str, package: str) -> str:
    return f'{ecosystem}:{canonical_name(ecosystem, package)}'


def parse_version_from_message(message: str) -> str:
    match = re.match(r'^[A-Za-z0-9_.@/-]+\s+([^\s]+)\s+is affected by', message)
    return match.group(1) if match else ''


def normalize_fix_versions(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    text = str(value).strip()
    if not text:
        return []
    return [item.strip() for item in re.split(r'[,;|]', text) if item.strip()]


def choose_fix_version(versions: list[str]) -> str:
    if not versions:
        return ''
    try:
        from packaging.version import InvalidVersion, Version
        parsed = []
        fallback = []
        for version in versions:
            try:
                parsed.append((Version(version), version))
            except InvalidVersion:
                fallback.append(version)
        if parsed:
            return sorted(parsed, key=lambda item: item[0])[-1][1]
        return sorted(fallback)[-1] if fallback else versions[-1]
    except Exception:
        return versions[-1]

def format_evidence(item: dict[str, Any]) -> str:
    return f"{item['path']}:{item['line']} {item['kind']} {item['symbol']}"


def reachability_note(review: dict[str, Any]) -> str:
    status = review['reachability']['status']
    if status == 'reachable-source-import':
        return 'Validate the reachable import/use path and prioritize compatibility testing for the upgrade.'
    if status == 'direct-manifest':
        return 'No source import was detected, but the dependency is declared directly in a runtime manifest; verify runtime/plugin usage before deferring.'
    if status == 'reachable-test-import':
        return 'Dependency usage was detected only in test/docs/example code; verify it is absent from production runtime before raising priority.'
    if status == 'transitive-unknown':
        return 'Dependency appears lockfile-only or transitive; identify the parent dependency before remediation planning.'
    if status == 'dev-or-optional':
        return 'Dependency appears dev/optional; verify it is absent from production runtime images before accepting lower priority.'
    return 'Reachability is not proven; review package usage manually before risk acceptance.'


def dependency_action(score: int, vulnerabilities: list[dict[str, Any]], reachability: dict[str, Any]) -> str:
    if score >= 85:
        return 'Block release until reachable dependency risk is remediated or formally risk-accepted.'
    if vulnerabilities and reachability['status'] in RUNTIME_REACHABILITY:
        return 'Upgrade or patch after compatibility testing before merge/deployment.'
    if vulnerabilities:
        return 'Review reachability and parent dependency path, then schedule upgrade or risk acceptance.'
    if reachability['status'] == 'reachable-source-import':
        return 'Track as an actively used dependency in supplier and license reviews.'
    return 'Keep in SBOM inventory and review when dependency changes.'


def priority_for_score(score: int) -> str:
    if score >= 85:
        return 'P0'
    if score >= 65:
        return 'P1'
    if score >= 40:
        return 'P2'
    if score >= 15:
        return 'P3'
    return 'P4'
