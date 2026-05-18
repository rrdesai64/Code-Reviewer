from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, replace
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
APPROVED_LICENSES = {
    'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD', 'Unlicense', 'CC0-1.0', 'Python-2.0', 'PSF-2.0', 'Zlib', 'MulanPSL-2.0'
}
REVIEW_REQUIRED_LICENSES = {
    'MPL-2.0', 'EPL-1.0', 'EPL-2.0', 'CDDL-1.0', 'CDDL-1.1', 'LGPL-2.0-only', 'LGPL-2.0-or-later', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
    'LGPL-3.0-only', 'LGPL-3.0-or-later', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later', 'AGPL-3.0-only', 'AGPL-3.0-or-later'
}
PROHIBITED_LICENSES = {'SSPL-1.0', 'BUSL-1.1', 'LicenseRef-Commons-Clause', 'LicenseRef-PolyForm-Noncommercial'}
LICENSE_ALIASES = {
    'apache software license': 'Apache-2.0',
    'apache license 2.0': 'Apache-2.0',
    'apache 2.0': 'Apache-2.0',
    'bsd license': 'BSD-3-Clause',
    'new bsd license': 'BSD-3-Clause',
    'modified bsd license': 'BSD-3-Clause',
    'mit license': 'MIT',
    'isc license': 'ISC',
    'python software foundation license': 'PSF-2.0',
    'mozilla public license 2.0': 'MPL-2.0',
    'gnu general public license v2': 'GPL-2.0-only',
    'gnu general public license v3': 'GPL-3.0-only',
    'gnu lesser general public license v2': 'LGPL-2.0-only',
    'gnu lesser general public license v3': 'LGPL-3.0-only',
}
CLASSIFIER_LICENSE_MAP = {
    'Apache Software License': 'Apache-2.0',
    'BSD License': 'BSD-3-Clause',
    'ISC License': 'ISC',
    'MIT License': 'MIT',
    'Mozilla Public License 2.0 (MPL 2.0)': 'MPL-2.0',
    'GNU General Public License v2 (GPLv2)': 'GPL-2.0-only',
    'GNU General Public License v3 (GPLv3)': 'GPL-3.0-only',
    'GNU Lesser General Public License v2 (LGPLv2)': 'LGPL-2.0-only',
    'GNU Lesser General Public License v3 (LGPLv3)': 'LGPL-3.0-only',
}
SPDX_COMPLIANCE_PURPOSES = [
    'legal/license compliance',
    'supplier audits',
    'open-source obligation reports',
    'enterprise procurement requirements',
    'formal software supply chain documentation',
]


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
    supplier: str = 'NOASSERTION'
    originator: str = 'NOASSERTION'
    download_location: str = 'NOASSERTION'
    homepage: str = ''
    source_info: str = ''
    copyright_text: str = 'NOASSERTION'

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
                        'version': '0.13.0',
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
    annotations = spdx_document_annotations(scan, components) + spdx_compliance_annotations(components) + spdx_vulnerability_annotations(scan.findings, components)
    return {
        'spdxVersion': SPDX_SPEC_VERSION,
        'dataLicense': 'CC0-1.0',
        'SPDXID': document_id,
        'name': f'{scan.project_name}-{scan.scan_id}-sbom',
        'documentNamespace': f'https://secure-review.local/spdx/{scan.scan_id}/{stable_uuid(scan.scan_id)}',
        'creationInfo': {
            'created': generated_at,
            'creators': [f'Tool: {TOOL_NAME}-0.13.0'],
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
                'comment': '; '.join(SPDX_COMPLIANCE_PURPOSES),
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
            components.append(enrich_component(SbomComponent('pypi', name, version=version, version_spec=spec, manifest_path=rel, package_manager='pip')))
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
                components.append(enrich_component(SbomComponent('pypi', name, version=version, version_spec=spec, manifest_path=rel, package_manager='pip')))
        poetry = ((payload.get('tool') or {}).get('poetry') or {}).get('dependencies') or {}
        for name, spec_value in poetry.items():
            if name.lower() == 'python':
                continue
            version, spec = normalize_version_spec(str(spec_value))
            components.append(enrich_component(SbomComponent('pypi', name, version=version, version_spec=spec, manifest_path=rel, package_manager='poetry')))
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
                components.append(enrich_component(SbomComponent('npm', name, version=version, version_spec=spec, scope=scope, manifest_path=rel, package_manager='npm')))
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
                components.append(enrich_component(SbomComponent('npm', str(name), version=version, version_spec=version, scope=scope, manifest_path=rel, package_manager='npm', license_expression=normalize_license_expression(package_data.get('license')), supplier=npm_supplier(package_data.get('author')), originator=npm_supplier(package_data.get('author')), download_location=str(package_data.get('resolved') or 'NOASSERTION'), homepage=str(package_data.get('homepage') or ''), source_info=npm_source_info(package_data))))
        dependencies = payload.get('dependencies') or {}
        if isinstance(dependencies, dict):
            for name, package_data in dependencies.items():
                if not isinstance(package_data, dict):
                    continue
                version = str(package_data.get('version') or '')
                if version:
                    scope = 'optional' if package_data.get('dev') else 'required'
                    components.append(enrich_component(SbomComponent('npm', name, version=version, version_spec=version, scope=scope, manifest_path=rel, package_manager='npm', license_expression=normalize_license_expression(package_data.get('license')), supplier=npm_supplier(package_data.get('author')), originator=npm_supplier(package_data.get('author')), download_location=str(package_data.get('resolved') or 'NOASSERTION'), homepage=str(package_data.get('homepage') or ''), source_info=npm_source_info(package_data))))
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
        candidate = enrich_component(SbomComponent('pypi', item['package'], version=item['version'], version_spec=item['version'], manifest_path=item['path'], package_manager='pip'))
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
            {'name': 'secure-review:license-review-status', 'value': license_review_status(component)},
            {'name': 'secure-review:supplier', 'value': component.supplier},
            {'name': 'secure-review:download-location', 'value': component.download_location},
            {'name': 'secure-review:procurement-status', 'value': component_procurement_status(component, [])},
        ],
    }
    if component.version:
        payload['version'] = component.version
    if not is_unknown_license(component.license_expression):
        payload['licenses'] = [{'expression': component.license_expression}]
    if component.supplier != 'NOASSERTION':
        payload['publisher'] = component.supplier.replace('Organization: ', '').replace('Person: ', '')
    return payload


def cyclonedx_vulnerabilities(findings: list[Finding], components: list[SbomComponent]) -> list[dict[str, Any]]:
    vulnerabilities: list[dict[str, Any]] = []
    components_by_key = component_map(components)
    components_by_identity = {component.identity: component for component in components}
    for item in extract_vulnerabilities(findings):
        candidate = enrich_component(SbomComponent('pypi', item['package'], version=item['version'], version_spec=item['version'], manifest_path=item['path'], package_manager='pip'))
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
    obligations = component_obligations(component)
    package = {
        'name': component.name,
        'SPDXID': component_spdx_id(component),
        'downloadLocation': component.download_location,
        'filesAnalyzed': False,
        'licenseConcluded': component.license_expression,
        'licenseDeclared': component.license_expression,
        'copyrightText': component.copyright_text,
        'supplier': component.supplier,
        'originator': component.originator,
        'externalRefs': [
            {
                'referenceCategory': 'PACKAGE-MANAGER',
                'referenceType': 'purl',
                'referenceLocator': component.purl,
            }
        ],
        'attributionTexts': [
            f'License status: {license_review_status(component)}; obligations: {", ".join(obligations) if obligations else "none identified"}'
        ],
        'annotations': [
            {
                'annotationType': 'OTHER',
                'annotator': f'Tool: {TOOL_NAME}',
                'annotationDate': now_iso(),
                'comment': f'Manifest: {component.manifest_path}; ecosystem: {component.ecosystem}; package manager: {component.package_manager}; version spec: {component.version_spec or "NOASSERTION"}; supplier audit: {supplier_audit_status(component)}; procurement status: {component_procurement_status(component, [])}',
            }
        ],
    }
    if component.version:
        package['versionInfo'] = component.version
    if component.homepage:
        package['homepage'] = component.homepage
    if component.source_info:
        package['sourceInfo'] = component.source_info
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
                'comment': f'Vulnerability {item["id"]} affects {component_spdx_id(component)}; finding {item["finding_id"]}; severity {item["severity"]}; {item["description"]}',
            }
        )
    return annotations


def spdx_compliance_report(scan: ScanResult) -> dict[str, Any]:
    components = attach_missing_vulnerable_components(discover_components(scan), scan.findings)
    spdx_doc = build_spdx(scan)
    vulnerabilities_by_key = vulnerabilities_by_component(scan.findings)
    legal_items = [component_legal_item(component, vulnerabilities_by_key.get(component.key, [])) for component in components]
    supplier_items = [component_supplier_item(component) for component in components]
    obligation_items = [component_obligation_item(component, vulnerabilities_by_key.get(component.key, [])) for component in components]
    procurement_statuses = [item['procurement_status'] for item in legal_items]
    requirements = spdx_procurement_requirements(components, scan.findings, spdx_doc)
    status = spdx_overall_status(procurement_statuses, requirements)
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': now_iso(),
        'status': status,
        'procurement_ready': status == 'ready',
        'purposes': SPDX_COMPLIANCE_PURPOSES,
        'counts': {
            'components': len(components),
            'known_licenses': sum(1 for item in legal_items if item['license_status'] != 'unknown'),
            'unknown_licenses': sum(1 for item in legal_items if item['license_status'] == 'unknown'),
            'legal_review_required': sum(1 for item in legal_items if item['license_status'] == 'legal_review_required'),
            'prohibited_licenses': sum(1 for item in legal_items if item['license_status'] == 'prohibited'),
            'missing_suppliers': sum(1 for item in supplier_items if item['supplier_status'] != 'identified'),
            'missing_download_locations': sum(1 for item in supplier_items if item['download_location_status'] != 'identified'),
            'obligation_items': sum(1 for item in obligation_items if item['obligations']),
            'vulnerable_components': sum(1 for item in legal_items if item['vulnerabilities']),
        },
        'legal_license_compliance': {
            'policy': {
                'approved_licenses': sorted(APPROVED_LICENSES),
                'review_required_licenses': sorted(REVIEW_REQUIRED_LICENSES),
                'prohibited_licenses': sorted(PROHIBITED_LICENSES),
                'unknown_license_action': 'legal review required before procurement approval',
            },
            'components': legal_items,
        },
        'supplier_audit': {
            'components': supplier_items,
            'required_evidence': ['SPDX supplier', 'download location or package URL', 'manifest path', 'version or version constraint'],
        },
        'open_source_obligation_report': {
            'components': obligation_items,
            'required_actions': sorted({action for item in obligation_items for action in item['required_actions']}),
        },
        'enterprise_procurement': {
            'status': status,
            'requirements': requirements,
        },
        'formal_supply_chain_documentation': {
            'spdx_version': spdx_doc['spdxVersion'],
            'document_name': spdx_doc['name'],
            'document_namespace': spdx_doc['documentNamespace'],
            'package_count': len(spdx_doc.get('packages', [])),
            'relationship_count': len(spdx_doc.get('relationships', [])),
            'annotation_count': len(spdx_doc.get('annotations', [])),
            'manifest_paths': sorted({component.manifest_path for component in components if component.manifest_path}),
            'target_path': scan.target_path,
            'tool': f'{TOOL_NAME}-0.13.0',
        },
    }


def spdx_document_annotations(scan: ScanResult, components: list[SbomComponent]) -> list[dict[str, Any]]:
    return [
        {
            'SPDXID': spdx_id(f'DocumentCompliance-{scan.scan_id}'),
            'annotationType': 'OTHER',
            'annotator': f'Tool: {TOOL_NAME}',
            'annotationDate': now_iso(),
            'comment': f'Generated for {"; ".join(SPDX_COMPLIANCE_PURPOSES)}. Components: {len(components)}. Target: {scan.target_path}',
        }
    ]


def spdx_compliance_annotations(components: list[SbomComponent]) -> list[dict[str, Any]]:
    annotations: list[dict[str, Any]] = []
    for component in components:
        annotations.append(
            {
                'SPDXID': spdx_id(f'Compliance-{component.ecosystem}-{component.name}-{component.version or component.version_spec or "unknown"}'),
                'annotationType': 'OTHER',
                'annotator': f'Tool: {TOOL_NAME}',
                'annotationDate': now_iso(),
                'comment': f'Package {component_spdx_id(component)} license_status={license_review_status(component)} supplier_audit={supplier_audit_status(component)} obligations={"|".join(component_obligations(component)) or "none"}',
            }
        )
    return annotations


def component_legal_item(component: SbomComponent, vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        **component_report_base(component),
        'license': component.license_expression,
        'license_status': license_review_status(component),
        'license_tokens': license_tokens(component.license_expression),
        'obligations': component_obligations(component),
        'procurement_status': component_procurement_status(component, vulnerabilities),
        'vulnerabilities': [policy_vulnerability_item(item) for item in vulnerabilities],
    }


def component_supplier_item(component: SbomComponent) -> dict[str, Any]:
    return {
        **component_report_base(component),
        'supplier': component.supplier,
        'supplier_status': 'identified' if component.supplier != 'NOASSERTION' else 'missing',
        'originator': component.originator,
        'download_location': component.download_location,
        'download_location_status': 'identified' if component.download_location != 'NOASSERTION' else 'missing',
        'homepage': component.homepage or 'NOASSERTION',
        'source_info': component.source_info or 'NOASSERTION',
    }


def component_obligation_item(component: SbomComponent, vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    obligations = component_obligations(component)
    actions = component_required_actions(component, vulnerabilities)
    return {
        **component_report_base(component),
        'license': component.license_expression,
        'license_status': license_review_status(component),
        'obligations': obligations,
        'required_actions': actions,
        'evidence_refs': [component_spdx_id(component), component.purl, component.manifest_path],
    }


def component_report_base(component: SbomComponent) -> dict[str, Any]:
    return {
        'spdx_id': component_spdx_id(component),
        'ecosystem': component.ecosystem,
        'name': component.name,
        'version': component_version_value(component),
        'scope': component.scope,
        'manifest_path': component.manifest_path,
        'package_manager': component.package_manager,
        'purl': component.purl,
    }


def spdx_procurement_requirements(components: list[SbomComponent], findings: list[Finding], spdx_doc: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerabilities = extract_vulnerabilities(findings)
    critical = [item for item in vulnerabilities if item['severity'] == 'CRITICAL']
    high = [item for item in vulnerabilities if item['severity'] == 'HIGH']
    unknown_licenses = [component for component in components if license_review_status(component) == 'unknown']
    review_licenses = [component for component in components if license_review_status(component) == 'legal_review_required']
    prohibited = [component for component in components if license_review_status(component) == 'prohibited']
    missing_supplier = [component for component in components if component.supplier == 'NOASSERTION']
    missing_download = [component for component in components if component.download_location == 'NOASSERTION']
    return [
        {
            'id': 'formal-spdx-2.3-document-present',
            'description': 'Formal SPDX 2.3 document is available for supply chain documentation.',
            'status': 'passed' if spdx_doc.get('spdxVersion') == SPDX_SPEC_VERSION else 'failed',
            'evidence': spdx_doc.get('documentNamespace'),
        },
        {
            'id': 'declared-license-known',
            'description': 'Every component should have a known declared or concluded license.',
            'status': 'failed' if unknown_licenses else 'passed',
            'violations': [policy_component_item(component) for component in unknown_licenses],
        },
        {
            'id': 'no-prohibited-licenses',
            'description': 'No component should use a prohibited or commercially restricted license.',
            'status': 'failed' if prohibited else 'passed',
            'violations': [policy_component_item(component) for component in prohibited],
        },
        {
            'id': 'legal-review-for-reciprocal-licenses',
            'description': 'Reciprocal, weak-copyleft, custom, or ambiguous licenses require legal review.',
            'status': 'warning' if review_licenses else 'passed',
            'violations': [policy_component_item(component) for component in review_licenses],
        },
        {
            'id': 'supplier-identity-present',
            'description': 'Supplier or maintainer identity should be present for supplier audits.',
            'status': 'warning' if missing_supplier else 'passed',
            'violations': [policy_component_item(component) for component in missing_supplier],
        },
        {
            'id': 'download-location-present',
            'description': 'Download location, registry URL, or package URL should be present for provenance review.',
            'status': 'warning' if missing_download else 'passed',
            'violations': [policy_component_item(component) for component in missing_download],
        },
        {
            'id': 'no-critical-package-vulnerabilities',
            'description': 'Critical package vulnerabilities block procurement approval.',
            'status': 'failed' if critical else 'passed',
            'violations': [policy_vulnerability_item(item) for item in critical],
        },
        {
            'id': 'high-package-vulnerabilities-reviewed',
            'description': 'High package vulnerabilities require security approval before procurement or release.',
            'status': 'warning' if high else 'passed',
            'violations': [policy_vulnerability_item(item) for item in high],
        },
    ]


def spdx_overall_status(procurement_statuses: list[str], requirements: list[dict[str, Any]]) -> str:
    if any(req['status'] == 'failed' for req in requirements) or any(status in {'blocked', 'security_block'} for status in procurement_statuses):
        return 'blocked'
    if any(req['status'] == 'warning' for req in requirements) or any(status != 'ready' for status in procurement_statuses):
        return 'review_required'
    return 'ready'


def vulnerabilities_by_component(findings: list[Finding]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for item in extract_vulnerabilities(findings):
        key = SbomComponent('pypi', item['package']).key
        result.setdefault(key, []).append(item)
    return result


def component_required_actions(component: SbomComponent, vulnerabilities: list[dict[str, Any]]) -> list[str]:
    actions = []
    if is_unknown_license(component.license_expression):
        actions.append('identify declared license before approval')
    if component.supplier == 'NOASSERTION':
        actions.append('identify supplier or maintainer before procurement approval')
    if component.download_location == 'NOASSERTION':
        actions.append('record download location or registry provenance')
    if vulnerabilities:
        actions.append('complete security review for vulnerable component')
    status = license_review_status(component)
    if status == 'prohibited':
        actions.append('obtain exception approval or replace component')
    elif status == 'legal_review_required':
        actions.append('complete legal review of license obligations')
    for obligation in component_obligations(component):
        if obligation == 'include license text':
            actions.append('include license text in notices bundle')
        elif obligation == 'retain copyright notices':
            actions.append('retain copyright notices in distributions')
        elif obligation == 'provide corresponding source':
            actions.append('prepare corresponding source offer when distributing binaries')
        elif obligation == 'network source availability':
            actions.append('prepare network source availability notice')
    return sorted(set(actions))


def component_procurement_status(component: SbomComponent, vulnerabilities: list[dict[str, Any]]) -> str:
    license_status = license_review_status(component)
    if license_status == 'prohibited':
        return 'blocked'
    if any(item['severity'] == 'CRITICAL' for item in vulnerabilities):
        return 'security_block'
    if license_status == 'unknown':
        return 'legal_review_required'
    if any(item['severity'] == 'HIGH' for item in vulnerabilities):
        return 'security_review_required'
    if license_status == 'legal_review_required':
        return 'legal_review_required'
    if component.supplier == 'NOASSERTION' or component.download_location == 'NOASSERTION':
        return 'supplier_review_required'
    return 'ready'


def supplier_audit_status(component: SbomComponent) -> str:
    missing = []
    if component.supplier == 'NOASSERTION':
        missing.append('supplier')
    if component.download_location == 'NOASSERTION':
        missing.append('download_location')
    return 'identified' if not missing else 'missing_' + '_and_'.join(missing)


def component_obligations(component: SbomComponent) -> list[str]:
    expression = component.license_expression
    tokens = license_tokens(expression)
    if is_unknown_license(expression):
        return ['identify license obligations']
    obligations = {'include license text', 'retain copyright notices'}
    if any(token.startswith('Apache-') for token in tokens):
        obligations.add('preserve NOTICE file when present')
        obligations.add('retain patent license notice')
    if any(token.startswith(('GPL-', 'LGPL-', 'AGPL-')) for token in tokens):
        obligations.add('provide corresponding source')
        obligations.add('preserve reciprocal license terms')
    if any(token.startswith('LGPL-') for token in tokens):
        obligations.add('allow relinking for LGPL-covered libraries')
    if any(token.startswith(('MPL-', 'EPL-', 'CDDL-')) for token in tokens):
        obligations.add('disclose modifications to covered files')
    if any(token.startswith('AGPL-') for token in tokens):
        obligations.add('network source availability')
    if license_review_status(component) == 'prohibited':
        obligations.add('procurement exception or replacement required')
    return sorted(obligations)


def license_review_status(component: SbomComponent) -> str:
    expression = component.license_expression
    if is_unknown_license(expression):
        return 'unknown'
    tokens = license_tokens(expression)
    if not tokens:
        return 'unknown'
    if any(token in PROHIBITED_LICENSES or token.startswith('LicenseRef-') for token in tokens):
        return 'prohibited' if any(token in PROHIBITED_LICENSES for token in tokens) else 'legal_review_required'
    if any(token in REVIEW_REQUIRED_LICENSES for token in tokens):
        return 'legal_review_required'
    if all(token in APPROVED_LICENSES for token in tokens):
        return 'approved'
    return 'legal_review_required'


def license_tokens(expression: str) -> list[str]:
    if is_unknown_license(expression):
        return []
    cleaned = expression.replace('(', ' ').replace(')', ' ')
    parts = re.split(r'\s+(?:AND|OR|WITH)\s+', cleaned)
    tokens = []
    for part in parts:
        token = part.strip()
        if token and token not in {'AND', 'OR', 'WITH'}:
            tokens.append(token)
    return tokens


def enrich_component(component: SbomComponent) -> SbomComponent:
    normalized = replace(
        component,
        license_expression=normalize_license_expression(component.license_expression),
        supplier=normalize_spdx_party(component.supplier),
        originator=normalize_spdx_party(component.originator),
        download_location=normalize_assertion(component.download_location),
        copyright_text=normalize_assertion(component.copyright_text),
    )
    if normalized.ecosystem == 'pypi':
        return enrich_pypi_component(normalized)
    return normalized


def enrich_pypi_component(component: SbomComponent) -> SbomComponent:
    dist = installed_distribution(component.name)
    if not dist:
        return component
    metadata = dist.metadata
    license_expression = component.license_expression
    if is_unknown_license(license_expression):
        license_expression = license_from_metadata(metadata)
    supplier = component.supplier if component.supplier != 'NOASSERTION' else supplier_from_metadata(metadata)
    originator = component.originator if component.originator != 'NOASSERTION' else supplier
    homepage = component.homepage or metadata_url(metadata, ['Homepage', 'Home-page', 'Source', 'Repository'])
    source_info = component.source_info or metadata_url(metadata, ['Source', 'Repository', 'Code'])
    download_location = component.download_location
    if download_location == 'NOASSERTION':
        download_location = metadata_value(metadata, 'Download-URL') or homepage or 'NOASSERTION'
    return replace(
        component,
        version=component.version or getattr(dist, 'version', '') or '',
        license_expression=license_expression,
        supplier=supplier,
        originator=originator,
        homepage=homepage,
        source_info=source_info,
        download_location=normalize_assertion(download_location),
    )


def installed_distribution(name: str):
    try:
        import importlib.metadata as importlib_metadata
    except Exception:
        return None
    try:
        return importlib_metadata.distribution(name)
    except importlib_metadata.PackageNotFoundError:
        target = canonical_name('pypi', name)
        for dist in importlib_metadata.distributions():
            dist_name = metadata_value(dist.metadata, 'Name')
            if dist_name and canonical_name('pypi', dist_name) == target:
                return dist
    except Exception:
        return None
    return None


def license_from_metadata(metadata: Any) -> str:
    expression = metadata_value(metadata, 'License-Expression') or metadata_value(metadata, 'License')
    expression = normalize_license_expression(expression)
    if not is_unknown_license(expression):
        return expression
    for classifier in metadata_values(metadata, 'Classifier'):
        if classifier.startswith('License ::'):
            leaf = classifier.split('::')[-1].strip()
            mapped = CLASSIFIER_LICENSE_MAP.get(leaf)
            if mapped:
                return mapped
    return 'NOASSERTION'


def supplier_from_metadata(metadata: Any) -> str:
    value = metadata_value(metadata, 'Author') or metadata_value(metadata, 'Maintainer') or metadata_value(metadata, 'Author-email') or metadata_value(metadata, 'Maintainer-email')
    return normalize_spdx_party(value)


def metadata_value(metadata: Any, key: str) -> str:
    try:
        value = metadata.get(key)
    except Exception:
        value = None
    return str(value).strip() if value else ''


def metadata_values(metadata: Any, key: str) -> list[str]:
    try:
        values = metadata.get_all(key) or []
    except Exception:
        values = []
    return [str(value).strip() for value in values if value]


def metadata_url(metadata: Any, labels: list[str]) -> str:
    lower_labels = {label.lower() for label in labels}
    for key in ['Project-URL', 'Project-url']:
        for item in metadata_values(metadata, key):
            if ',' not in item:
                continue
            label, value = item.split(',', 1)
            if label.strip().lower() in lower_labels and value.strip():
                return value.strip()
    for label in labels:
        value = metadata_value(metadata, label)
        if value:
            return value
    return ''


def normalize_license_expression(value: Any) -> str:
    if not value:
        return 'NOASSERTION'
    text = str(value).strip()
    if not text or text.upper() in {'NOASSERTION', 'UNKNOWN', 'UNKNOWN LICENSE', 'NONE', 'N/A'}:
        return 'NOASSERTION'
    lower = re.sub(r'\s+', ' ', text).strip().lower()
    if lower in LICENSE_ALIASES:
        return LICENSE_ALIASES[lower]
    if text in APPROVED_LICENSES or text in REVIEW_REQUIRED_LICENSES or text in PROHIBITED_LICENSES:
        return text
    if 'apache' in lower and '2' in lower:
        return 'Apache-2.0'
    if 'mit' == lower or lower.startswith('mit '):
        return 'MIT'
    if 'bsd' in lower:
        return 'BSD-3-Clause'
    if 'isc' == lower or lower.startswith('isc '):
        return 'ISC'
    if 'mozilla public license' in lower and '2' in lower:
        return 'MPL-2.0'
    if 'gnu affero general public license' in lower or 'agpl' in lower:
        return 'AGPL-3.0-or-later'
    if 'lesser general public license' in lower or 'lgpl' in lower:
        return 'LGPL-3.0-or-later'
    if 'general public license' in lower or 'gpl' in lower:
        return 'GPL-3.0-or-later'
    if re.match(r'^[A-Za-z0-9.\-+]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.\-+]+)*$', text):
        return text
    token = re.sub(r'[^A-Za-z0-9.-]+', '-', text)[:40].strip('-') or 'Declared'
    return f'LicenseRef-{token}'


def normalize_spdx_party(value: Any) -> str:
    text = str(value or '').strip()
    if not text or text.upper() in {'NOASSERTION', 'UNKNOWN', 'N/A'}:
        return 'NOASSERTION'
    if text.startswith(('Person:', 'Organization:')):
        return text
    org_markers = ['foundation', 'inc', 'llc', 'ltd', 'corp', 'corporation', 'project', 'team', 'community', 'organization']
    prefix = 'Organization' if any(marker in text.lower() for marker in org_markers) else 'Person'
    return f'{prefix}: {text}'


def normalize_assertion(value: Any) -> str:
    text = str(value or '').strip()
    return text if text and text.upper() not in {'UNKNOWN', 'N/A', 'NONE'} else 'NOASSERTION'


def npm_supplier(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get('name') or value.get('email') or ''
    return normalize_spdx_party(value)


def npm_source_info(package_data: dict[str, Any]) -> str:
    bits = []
    if package_data.get('integrity'):
        bits.append(f'integrity={package_data["integrity"]}')
    if package_data.get('resolved'):
        bits.append(f'resolved={package_data["resolved"]}')
    return '; '.join(bits)


def component_spdx_id(component: SbomComponent) -> str:
    return spdx_id(f'Package-{component.ecosystem}-{component.name}-{component.version or component.version_spec or "unknown"}')
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
    if not is_unknown_license(component.license_expression):
        score += 5
    if component.supplier != 'NOASSERTION':
        score += 2
    if component.download_location != 'NOASSERTION':
        score += 1
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
