from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .models import Finding, ScanResult

EXCLUDED_DIRS = {'.git', '.venv', 'venv', 'node_modules', 'dist', 'build', '__pycache__', '.mypy_cache', '.pytest_cache', 'data'}
TOOL_NAME = 'Secure Code Review Assistant'
TOOL_VENDOR = 'Secure Review'
CYCLONEDX_SPEC_VERSION = '1.5'
SPDX_SPEC_VERSION = 'SPDX-2.3'


@dataclass(frozen=True)
class SbomComponent:
    ecosystem: str
    name: str
    version: str = ''
    version_spec: str = ''
    scope: str = 'required'
    manifest_path: str = ''
    package_manager: str = ''
    license_expression: str = 'NOASSERTION'

    @property
    def key(self) -> str:
        return f'{self.ecosystem}:{canonical_name(self.ecosystem, self.name)}'

    @property
    def identity(self) -> str:
        version_part = self.version or self.version_spec or 'unknown'
        return f'{self.key}:{version_part}'

    @property
    def bom_ref(self) -> str:
        return make_bom_ref(self.ecosystem, self.name, self.version or self.version_spec)

    @property
    def purl(self) -> str:
        return make_purl(self.ecosystem, self.name, self.version)


def build_cyclonedx(scan: ScanResult) -> dict[str, Any]:
    generated_at = now_iso()
    components = discover_components(scan)
    components = attach_missing_vulnerable_components(components, scan.findings)
    root_ref = f'project:{scan.scan_id}'
    component_payloads = [cyclonedx_component(component) for component in components]
    vulnerabilities = cyclonedx_vulnerabilities(scan.findings, components)
    return {
        'bomFormat': 'CycloneDX',
        'specVersion': CYCLONEDX_SPEC_VERSION,
        'serialNumber': f'urn:uuid:{stable_uuid(scan.scan_id)}',
        'version': 1,
        'metadata': {
            'timestamp': generated_at,
            'tools': {
                'components': [
                    {
                        'type': 'application',
                        'group': TOOL_VENDOR,
                        'name': TOOL_NAME,
                        'version': '0.12.0',
                    }
                ]
            },
            'component': {
                'type': 'application',
                'bom-ref': root_ref,
                'name': scan.project_name,
                'version': scan.scan_id,
                'properties': [
                    {'name': 'secure-review:scan-id', 'value': scan.scan_id},
                    {'name': 'secure-review:target-path', 'value': scan.target_path},
                ],
            },
        },
        'components': component_payloads,
        'dependencies': [
            {
                'ref': root_ref,
                'dependsOn': [component.bom_ref for component in components],
            }
        ],
        'vulnerabilities': vulnerabilities,
        'properties': [
            {'name': 'secure-review:project-name', 'value': scan.project_name},
            {'name': 'secure-review:created-at', 'value': scan.created_at.isoformat()},
            {'name': 'secure-review:dependency-count', 'value': str(len(components))},
            {'name': 'secure-review:vulnerability-count', 'value': str(len(vulnerabilities))},
        ],
    }


def build_spdx(scan: ScanResult) -> dict[str, Any]:
    generated_at = now_iso()
    components = discover_components(scan)
    components = attach_missing_vulnerable_components(components, scan.findings)
    document_id = spdx_id(f'Document-{scan.scan_id}')
    root_id = spdx_id(f'Project-{scan.project_name}-{scan.scan_id}')
    packages = [spdx_package(component) for component in components]
    relationships = [
        {
            'spdxElementId': document_id,
            'relationshipType': 'DESCRIBES',
            'relatedSpdxElement': root_id,
        }
    ]
    relationships.extend(
        {
            'spdxElementId': root_id,
            'relationshipType': 'DEPENDS_ON',
            'relatedSpdxElement': package['SPDXID'],
        }
        for package in packages
    )
    annotations = spdx_vulnerability_annotations(scan.findings, components)
    return {
        'spdxVersion': SPDX_SPEC_VERSION,
        'dataLicense': 'CC0-1.0',
        'SPDXID': document_id,
        'name': f'{scan.project_name}-{scan.scan_id}-sbom',
        'documentNamespace': f'https://secure-review.local/spdx/{scan.scan_id}/{stable_uuid(scan.scan_id)}',
        'creationInfo': {
            'created': generated_at,
            'creators': [f'Tool: {TOOL_NAME}-0.12.0'],
        },
        'packages': [
            {
                'name': scan.project_name,
                'SPDXID': root_id,
                'versionInfo': scan.scan_id,
                'downloadLocation': 'NOASSERTION',
                'filesAnalyzed': False,
                'licenseConcluded': 'NOASSERTION',
                'licenseDeclared': 'NOASSERTION',
                'copyrightText': 'NOASSERTION',
                'supplier': 'NOASSERTION',
                'description': f'Scan target: {scan.target_path}',
            },
            *packages,
        ],
        'relationships': relationships,
        'annotations': annotations,
    }


def sbom_policy_report(scan: ScanResult) -> dict[str, Any]:
    components = attach_missing_vulnerable_components(discover_components(scan), scan.findings)
    vulnerabilities = extract_vulnerabilities(scan.findings)
    critical_vulns = [item for item in vulnerabilities if item['severity'] == 'CRITICAL']
    high_vulns = [item for item in vulnerabilities if item['severity'] == 'HIGH']
    unknown_license_components = [component for component in components if is_unknown_license(component.license_expression)]
    policies = [
        {
            'id': 'no-critical-vulnerabilities',
            'description': 'Fail if a critical package vulnerability exists.',
            'status': 'failed' if critical_vulns else 'passed',
            'severity': 'critical',
            'violations': [policy_vulnerability_item(item) for item in critical_vulns],
        },
        {
            'id': 'known-licenses-required',
            'description': 'Fail if a package component has an unknown license.',
            'status': 'failed' if unknown_license_components else 'passed',
            'severity': 'medium',
            'violations': [policy_component_item(component) for component in unknown_license_components],
        },
        {
            'id': 'high-vulnerabilities-review',
            'description': 'Warn when high severity package vulnerabilities require review.',
            'status': 'warning' if high_vulns else 'passed',
            'severity': 'high',
            'violations': [policy_vulnerability_item(item) for item in high_vulns],
        },
    ]
    failed = any(policy['status'] == 'failed' for policy in policies)
    warning = any(policy['status'] == 'warning' for policy in policies)
    status = 'failed' if failed else 'warning' if warning else 'passed'
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': now_iso(),
        'status': status,
        'counts': {
            'components': len(components),
            'vulnerabilities': len(vulnerabilities),
            'critical_vulnerabilities': len(critical_vulns),
            'high_vulnerabilities': len(high_vulns),
            'unknown_license_components': len(unknown_license_components),
        },
        'policies': policies,
    }


def compare_sboms(current_scan: ScanResult, baseline_scan: ScanResult | None = None) -> dict[str, Any]:
    current_components = component_map(attach_missing_vulnerable_components(discover_components(current_scan), current_scan.findings))
    baseline_components = component_map(attach_missing_vulnerable_components(discover_components(baseline_scan), baseline_scan.findings)) if baseline_scan else {}
    current_keys = set(current_components)
    baseline_keys = set(baseline_components)
    added = [component_compare_item(current_components[key]) for key in sorted(current_keys - baseline_keys)]
    removed = [component_compare_item(baseline_components[key]) for key in sorted(baseline_keys - current_keys)]
    unchanged: list[dict[str, Any]] = []
    version_changes: list[dict[str, Any]] = []
    for key in sorted(current_keys & baseline_keys):
        current = current_components[key]
        baseline = baseline_components[key]
        if component_version_value(current) == component_version_value(baseline):
            unchanged.append(component_compare_item(current))
        else:
            version_changes.append(
                {
                    'ecosystem': current.ecosystem,
                    'name': current.name,
                    'from_version': component_version_value(baseline),
                    'to_version': component_version_value(current),
                    'from_manifest': baseline.manifest_path,
                    'to_manifest': current.manifest_path,
                    'purl': current.purl,
                }
            )
    return {
        'scan_id': current_scan.scan_id,
        'baseline_scan_id': baseline_scan.scan_id if baseline_scan else None,
        'project_name': current_scan.project_name,
        'generated_at': now_iso(),
        'counts': {
            'added': len(added),
            'removed': len(removed),
            'version_changes': len(version_changes),
            'unchanged': len(unchanged),
            'current_components': len(current_components),
            'baseline_components': len(baseline_components),
        },
        'added_components': added,
        'removed_components': removed,
        'version_changes': version_changes,
        'unchanged_components': unchanged,
    }


def discover_components(scan: ScanResult | None) -> list[SbomComponent]:
    if scan is None:
        return []
    target = Path(scan.target_path)
    if not target.exists() or not target.is_dir():
        return []
    components: list[SbomComponent] = []
    components.extend(read_python_requirements(target))
    components.extend(read_pyproject(target))
    components.extend(read_package_json(target))
    components.extend(read_package_lock(target))
    return dedupe_components(components)


def read_python_requirements(target: Path) -> list[SbomComponent]:
    components: list[SbomComponent] = []
    for manifest in sorted(target.rglob('requirements*.txt')):
        if excluded(manifest):
            continue
        rel = relpath(manifest, target)
        lines = manifest.read_text(encoding='utf-8', errors='ignore').splitlines()
        for line in lines:
            parsed = parse_requirement_line(line)
            if not parsed:
                continue
            name, version, spec = parsed
            components.append(SbomComponent('pypi', name, version=version, version_spec=spec, manifest_path=rel, package_manager='pip'))
    return components


def read_pyproject(target: Path) -> list[SbomComponent]:
    manifests = [path for path in sorted(target.rglob('pyproject.toml')) if not excluded(path)]
    if not manifests:
        return []
    try:
        import tomllib
    except ModuleNotFoundError:
        return []
    components: list[SbomComponent] = []
    for manifest in manifests:
        try:
            payload = tomllib.loads(manifest.read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            continue
        rel = relpath(manifest, target)
        project = payload.get('project') or {}
        for item in project.get('dependencies') or []:
            parsed = parse_requirement_line(str(item))
            if parsed:
                name, version, spec = parsed
                components.append(SbomComponent('pypi', name, version=version, version_spec=spec, manifest_path=rel, package_manager='pip'))
        poetry = ((payload.get('tool') or {}).get('poetry') or {}).get('dependencies') or {}
        for name, spec_value in poetry.items():
            if name.lower() == 'python':
                continue
            version, spec = normalize_version_spec(str(spec_value))
            components.append(SbomComponent('pypi', name, version=version, version_spec=spec, manifest_path=rel, package_manager='poetry'))
    return components


def read_package_json(target: Path) -> list[SbomComponent]:
    components: list[SbomComponent] = []
    sections = {
        'dependencies': 'required',
        'devDependencies': 'optional',
        'optionalDependencies': 'optional',
        'peerDependencies': 'optional',
    }
    for manifest in sorted(target.rglob('package.json')):
        if excluded(manifest):
            continue
        try:
            payload = json.loads(manifest.read_text(encoding='utf-8'))
        except json.JSONDecodeError:
            continue
        rel = relpath(manifest, target)
        for section, scope in sections.items():
            deps = payload.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for name, spec_value in deps.items():
                version, spec = normalize_version_spec(str(spec_value))
                components.append(SbomComponent('npm', name, version=version, version_spec=spec, scope=scope, manifest_path=rel, package_manager='npm'))
    return components


def read_package_lock(target: Path) -> list[SbomComponent]:
    components: list[SbomComponent] = []
    for manifest in sorted(target.rglob('package-lock.json')):
        if excluded(manifest):
            continue
        try:
            payload = json.loads(manifest.read_text(encoding='utf-8'))
        except json.JSONDecodeError:
            continue
        rel = relpath(manifest, target)
        packages = payload.get('packages') or {}
        if isinstance(packages, dict):
            for package_path, package_data in packages.items():
                if not package_path or not isinstance(package_data, dict):
                    continue
                name = package_data.get('name') or npm_name_from_lock_path(package_path)
                version = str(package_data.get('version') or '')
                if not name or not version:
                    continue
                scope = 'optional' if package_data.get('dev') else 'required'
                components.append(SbomComponent('npm', str(name), version=version, version_spec=version, scope=scope, manifest_path=rel, package_manager='npm'))
        dependencies = payload.get('dependencies') or {}
        if isinstance(dependencies, dict):
            for name, package_data in dependencies.items():
                if not isinstance(package_data, dict):
                    continue
                version = str(package_data.get('version') or '')
                if version:
                    scope = 'optional' if package_data.get('dev') else 'required'
                    components.append(SbomComponent('npm', name, version=version, version_spec=version, scope=scope, manifest_path=rel, package_manager='npm'))
    return components


def parse_requirement_line(line: str) -> tuple[str, str, str] | None:
    clean = line.split('#', 1)[0].strip()
    if not clean or clean.startswith(('-', '--')):
        return None
    if ' @ ' in clean:
        name = clean.split(' @ ', 1)[0].strip()
        name = name.split('[', 1)[0].strip()
        return (name, '', clean)
    match = re.match(r'^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*([!<>=~]{1,3})?\s*([^;\s]+)?', clean)
    if not match:
        return None
    name = match.group(1).strip()
    operator = match.group(2) or ''
    version_text = (match.group(3) or '').strip()
    if not name:
        return None
    spec = f'{operator}{version_text}' if operator and version_text else clean
    version = version_text if operator in {'==', '==='} else ''
    return (name, version, spec)


def normalize_version_spec(spec_value: str) -> tuple[str, str]:
    spec = spec_value.strip()
    version = spec if re.match(r'^\d+(?:\.\d+)*(?:[-+][A-Za-z0-9_.-]+)?$', spec) else ''
    return version, spec


def attach_missing_vulnerable_components(components: list[SbomComponent], findings: list[Finding]) -> list[SbomComponent]:
    by_key = {component.key: component for component in components}
    by_identity = {component.identity: component for component in components}
    result = list(components)
    for item in extract_vulnerabilities(findings):
        candidate = SbomComponent('pypi', item['package'], version=item['version'], version_spec=item['version'], manifest_path=item['path'], package_manager='pip')
        if candidate.identity in by_identity or candidate.key in by_key:
            continue
        result.append(candidate)
        by_key[candidate.key] = candidate
        by_identity[candidate.identity] = candidate
    return dedupe_components(result)


def cyclonedx_component(component: SbomComponent) -> dict[str, Any]:
    payload: dict[str, Any] = {
        'type': 'library',
        'bom-ref': component.bom_ref,
        'name': component.name,
        'scope': component.scope,
        'purl': component.purl,
        'properties': [
            {'name': 'secure-review:ecosystem', 'value': component.ecosystem},
            {'name': 'secure-review:manifest-path', 'value': component.manifest_path},
            {'name': 'secure-review:package-manager', 'value': component.package_manager},
            {'name': 'secure-review:version-spec', 'value': component.version_spec},
            {'name': 'secure-review:license-status', 'value': 'unknown' if is_unknown_license(component.license_expression) else 'known'},
        ],
    }
    if component.version:
        payload['version'] = component.version
    if not is_unknown_license(component.license_expression):
        payload['licenses'] = [{'expression': component.license_expression}]
    return payload


def cyclonedx_vulnerabilities(findings: list[Finding], components: list[SbomComponent]) -> list[dict[str, Any]]:
    vulnerabilities: list[dict[str, Any]] = []
    components_by_key = component_map(components)
    components_by_identity = {component.identity: component for component in components}
    for item in extract_vulnerabilities(findings):
        candidate = SbomComponent('pypi', item['package'], version=item['version'], version_spec=item['version'], manifest_path=item['path'], package_manager='pip')
        component = components_by_identity.get(candidate.identity) or components_by_key.get(candidate.key) or candidate
        advisories = []
        for reference in item['references']:
            if reference.startswith(('http://', 'https://')):
                advisories.append({'url': reference})
            else:
                advisories.append({'title': reference})
        vuln: dict[str, Any] = {
            'bom-ref': f'vulnerability:{item["id"]}:{item["finding_id"]}',
            'id': item['id'],
            'source': {'name': 'pip-audit'},
            'ratings': [{'severity': item['severity'].lower(), 'method': 'other'}],
            'description': item['description'],
            'recommendation': item['recommendation'],
            'affects': [{'ref': component.bom_ref}],
            'properties': [
                {'name': 'secure-review:finding-id', 'value': item['finding_id']},
                {'name': 'secure-review:package', 'value': item['package']},
                {'name': 'secure-review:manifest-path', 'value': item['path']},
            ],
        }
        if advisories:
            vuln['advisories'] = advisories
        vulnerabilities.append(vuln)
    return vulnerabilities


def extract_vulnerabilities(findings: list[Finding]) -> list[dict[str, Any]]:
    vulnerabilities: list[dict[str, Any]] = []
    for finding in findings:
        if finding.source != 'pip-audit':
            continue
        package, version, description = parse_pip_audit_finding(finding)
        vulnerabilities.append(
            {
                'id': finding.rule_id,
                'finding_id': finding.id,
                'package': package,
                'version': version,
                'severity': finding.severity,
                'description': description,
                'recommendation': finding.fix.summary or 'Upgrade the affected package to a non-vulnerable version.',
                'path': finding.location.path,
                'references': finding.references,
            }
        )
    return vulnerabilities


def parse_pip_audit_finding(finding: Finding) -> tuple[str, str, str]:
    package = finding.title.replace('Vulnerable dependency:', '').strip() or 'dependency'
    version = ''
    description = finding.message
    match = re.match(r'^([A-Za-z0-9_.-]+)\s+([^\s]*)\s+is affected by\s+([^:]+):\s*(.*)$', finding.message)
    if match:
        package = match.group(1) or package
        version = match.group(2) or ''
        description = match.group(4) or finding.message
    return package, version, description


def spdx_package(component: SbomComponent) -> dict[str, Any]:
    package = {
        'name': component.name,
        'SPDXID': spdx_id(f'Package-{component.ecosystem}-{component.name}-{component.version or component.version_spec or "unknown"}'),
        'downloadLocation': 'NOASSERTION',
        'filesAnalyzed': False,
        'licenseConcluded': component.license_expression,
        'licenseDeclared': component.license_expression,
        'copyrightText': 'NOASSERTION',
        'supplier': 'NOASSERTION',
        'externalRefs': [
            {
                'referenceCategory': 'PACKAGE-MANAGER',
                'referenceType': 'purl',
                'referenceLocator': component.purl,
            }
        ],
        'annotations': [
            {
                'annotationType': 'OTHER',
                'annotator': f'Tool: {TOOL_NAME}',
                'annotationDate': now_iso(),
                'comment': f'Manifest: {component.manifest_path}; ecosystem: {component.ecosystem}; version spec: {component.version_spec or "NOASSERTION"}',
            }
        ],
    }
    if component.version:
        package['versionInfo'] = component.version
    return package


def spdx_vulnerability_annotations(findings: list[Finding], components: list[SbomComponent]) -> list[dict[str, Any]]:
    components_by_key = component_map(components)
    annotations: list[dict[str, Any]] = []
    for item in extract_vulnerabilities(findings):
        component = components_by_key.get(SbomComponent('pypi', item['package']).key)
        if not component:
            continue
        annotations.append(
            {
                'SPDXID': spdx_id(f'Annotation-{item["id"]}-{item["finding_id"]}'),
                'annotationType': 'OTHER',
                'annotator': f'Tool: {TOOL_NAME}',
                'annotationDate': now_iso(),
                'comment': f'Vulnerability {item["id"]} affects {spdx_package(component)["SPDXID"]}; finding {item["finding_id"]}; severity {item["severity"]}; {item["description"]}',
            }
        )
    return annotations


def component_map(components: list[SbomComponent]) -> dict[str, SbomComponent]:
    result: dict[str, SbomComponent] = {}
    for component in components:
        existing = result.get(component.key)
        if not existing or component_rank(component) > component_rank(existing):
            result[component.key] = component
    return result


def component_rank(component: SbomComponent) -> int:
    score = 0
    if component.version:
        score += 10
    if component.version_spec and component.version_spec != component.version:
        score += 2
    if component.manifest_path.endswith('package-lock.json'):
        score += 4
    if component.manifest_path.endswith('requirements.txt'):
        score += 3
    return score


def dedupe_components(components: list[SbomComponent]) -> list[SbomComponent]:
    by_identity: dict[str, SbomComponent] = {}
    for component in components:
        existing = by_identity.get(component.identity)
        if not existing or component_rank(component) > component_rank(existing):
            by_identity[component.identity] = component
    result = list(by_identity.values())
    versioned_keys = {component.key for component in result if component.version}
    result = [component for component in result if component.version or component.key not in versioned_keys]
    return sorted(result, key=lambda item: (item.ecosystem, canonical_name(item.ecosystem, item.name), item.version or item.version_spec, item.manifest_path))


def component_compare_item(component: SbomComponent) -> dict[str, Any]:
    return {
        'ecosystem': component.ecosystem,
        'name': component.name,
        'version': component_version_value(component),
        'manifest_path': component.manifest_path,
        'purl': component.purl,
        'license': component.license_expression,
    }


def policy_vulnerability_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        'id': item['id'],
        'finding_id': item['finding_id'],
        'package': item['package'],
        'version': item['version'] or 'unknown',
        'severity': item['severity'],
        'path': item['path'],
    }


def policy_component_item(component: SbomComponent) -> dict[str, Any]:
    return {
        'ecosystem': component.ecosystem,
        'name': component.name,
        'version': component_version_value(component),
        'manifest_path': component.manifest_path,
        'purl': component.purl,
    }


def component_version_value(component: SbomComponent) -> str:
    return component.version or component.version_spec or 'unknown'


def make_purl(ecosystem: str, name: str, version: str = '') -> str:
    package_type = 'pypi' if ecosystem == 'pypi' else ecosystem
    if ecosystem == 'pypi':
        package_name = quote(canonical_name(ecosystem, name), safe='')
    elif ecosystem == 'npm':
        package_name = '/'.join(quote(part, safe='') for part in name.split('/'))
    else:
        package_name = quote(name, safe='')
    version_part = f'@{quote(version, safe="")}' if version else ''
    return f'pkg:{package_type}/{package_name}{version_part}'


def make_bom_ref(ecosystem: str, name: str, version: str = '') -> str:
    raw = f'{ecosystem}:{canonical_name(ecosystem, name)}:{version or "unknown"}'
    safe = re.sub(r'[^A-Za-z0-9_.:-]+', '-', raw).strip('-')
    return f'pkg:{safe}'


def spdx_id(value: str) -> str:
    safe = re.sub(r'[^A-Za-z0-9.-]+', '-', value).strip('-')
    return f'SPDXRef-{safe or "Unknown"}'


def canonical_name(ecosystem: str, name: str) -> str:
    value = name.strip()
    if ecosystem == 'pypi':
        return re.sub(r'[-_.]+', '-', value).lower()
    if ecosystem == 'npm':
        return value.lower()
    return value.lower()


def stable_uuid(value: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f'secure-review:{value}')


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def relpath(path: Path, target: Path) -> str:
    try:
        return str(path.resolve().relative_to(target.resolve())).replace('\\', '/')
    except Exception:
        return str(path).replace('\\', '/')


def excluded(path: Path) -> bool:
    return any(part in EXCLUDED_DIRS for part in path.parts)


def npm_name_from_lock_path(package_path: str) -> str:
    marker = 'node_modules/'
    if marker not in package_path:
        return ''
    name = package_path.rsplit(marker, 1)[-1]
    return name.strip('/')


def is_unknown_license(value: str) -> bool:
    return value.upper() in {'', 'UNKNOWN', 'NOASSERTION'}


