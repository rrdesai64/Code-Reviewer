from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ai import explain, suggest_fix
from .models import Finding, Location, ScanResult
from .scope import apply_finding_scope, scope_counts

NORMALIZATION_VERSION = 'scanner-mesh-v1'
SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
SEVERITY_ALIASES = {
    'BLOCKER': 'CRITICAL', 'CRITICAL': 'CRITICAL', 'ERROR': 'HIGH', 'HIGH': 'HIGH', 'MAJOR': 'HIGH',
    'WARNING': 'MEDIUM', 'WARN': 'MEDIUM', 'MEDIUM': 'MEDIUM', 'MINOR': 'LOW', 'LOW': 'LOW',
    'NOTE': 'INFO', 'NONE': 'INFO', 'INFO': 'INFO', 'INFORMATIONAL': 'INFO',
}
SARIF_LEVEL_SEVERITY = {'error': 'HIGH', 'warning': 'MEDIUM', 'note': 'LOW', 'none': 'INFO'}
SOURCE_FAMILIES = {
    'semgrep': 'sast', 'bandit': 'sast', 'python-ast': 'sast', 'codeql': 'sast', 'sonarqube': 'quality-security',
    'shellcheck': 'sast', 'sql-artifact': 'sast', 'pip-audit': 'sca', 'govulncheck': 'sca', 'dependency-manifest': 'sca', 'secret-scan': 'secrets', 'gitleaks': 'secrets',
    'trufflehog': 'secrets', 'snyk': 'sca-sast', 'sarif-import': 'sarif',
}
SUPPORTED_SOURCES = [
    {'source': 'semgrep', 'status': 'implemented', 'input': 'Semgrep JSON'},
    {'source': 'bandit', 'status': 'implemented', 'input': 'Bandit JSON'},
    {'source': 'shellcheck', 'status': 'implemented', 'input': 'ShellCheck JSON'},
    {'source': 'sql-artifact', 'status': 'implemented', 'input': 'Native standalone SQL artifact scanner'},
    {'source': 'pip-audit', 'status': 'implemented', 'input': 'pip-audit JSON'},
    {'source': 'govulncheck', 'status': 'implemented', 'input': 'govulncheck JSON lines'},
    {'source': 'codeql', 'status': 'implemented', 'input': 'SARIF 2.1.0'},
    {'source': 'sonarqube', 'status': 'implemented', 'input': 'Sonar issues and quality gate APIs'},
    {'source': 'secret-scan', 'status': 'implemented', 'input': 'Built-in secret scanner'},
    {'source': 'gitleaks', 'status': 'implemented', 'input': 'Gitleaks JSON'},
    {'source': 'trufflehog', 'status': 'implemented', 'input': 'TruffleHog JSON lines'},
    {'source': 'sarif-import', 'status': 'implemented', 'input': 'External SARIF 2.1.0'},
    {'source': 'snyk', 'status': 'ready-adapter', 'input': 'Snyk JSON vulnerability/issues payload'},
]
EXPLOITABLE_KEYWORDS = (
    'command injection', 'sql injection', 'injection', 'xss', 'cross-site scripting', 'path traversal',
    'deserialization', 'ssrf', 'rce', 'remote code execution', 'eval', 'exec', 'shell=true', 'hardcoded secret',
    'hardcoded password', 'token', 'credential', 'private key', 'known vulnerability', 'cve-', 'pysec-',
)
CONFIG_PATTERNS = ('.yml', '.yaml', '.json', '.toml', '.ini', '.cfg', '.conf', '.properties', '.env')
SOURCE_EXTENSIONS = ('.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rs', '.rb', '.php', '.cs', '.c', '.cpp', '.h')
MANIFEST_NAMES = ('requirements.txt', 'package.json', 'package-lock.json', 'pyproject.toml', 'pom.xml', 'go.mod', 'Cargo.toml')


def normalize_finding(
    *,
    source: str,
    rule_id: str,
    title: str | None,
    severity: Any,
    confidence: Any = 'MEDIUM',
    path: str = '',
    line: int = 1,
    column: int = 1,
    message: str = '',
    cwe: Any = None,
    owasp: Any = None,
    references: Any = None,
    raw: dict[str, Any] | None = None,
    raw_severity: Any = None,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    normalized_path = normalize_path(path)
    normalized_rule = str(rule_id or f'{source}-rule')
    normalized_message = str(message or normalized_rule)
    normalized_cwe = normalize_taxonomy(cwe, prefix='CWE-')
    normalized_owasp = normalize_list(owasp)
    normalized_refs = normalize_list(references)
    fingerprint = make_fingerprint(source, normalized_rule, normalized_path, int(line or 1), normalized_message)
    finding = Finding(
        id=fingerprint[:16],
        source=source,
        rule_id=normalized_rule,
        title=title or title_from_rule(normalized_rule),
        severity=normalize_severity(severity),
        confidence=normalize_confidence(confidence),
        location=Location(path=normalized_path, line=max(1, int(line or 1)), column=max(1, int(column or 1))),
        message=normalized_message,
        cwe=normalized_cwe,
        owasp=normalized_owasp,
        references=normalized_refs,
        explanation=explain(normalized_rule, normalized_message, normalized_cwe, normalized_owasp),
        fix=suggest_fix(normalized_rule, normalized_message),
        fingerprint=fingerprint,
        scanner_metadata=metadata_from_raw(source, raw, raw_severity, metadata),
    )
    return enrich_finding(finding)


def enrich_finding(finding: Finding) -> Finding:
    metadata = dict(finding.scanner_metadata or {})
    metadata.setdefault('normalization_version', NORMALIZATION_VERSION)
    metadata.setdefault('scanner_source', finding.source)
    metadata.setdefault('scanner_family', source_family(finding.source))
    metadata.setdefault('normalized_severity', finding.severity)
    metadata.setdefault('normalized_confidence', finding.confidence)
    finding.scanner_metadata = metadata
    finding.exploitability = finding.exploitability if finding.exploitability != 'unknown' else infer_exploitability(finding)
    finding.reachability = finding.reachability if finding.reachability != 'unknown' else infer_reachability(finding)
    if not finding.policy_impact:
        finding.policy_impact = infer_policy_impact(finding)
    if not finding.remediation:
        finding.remediation = infer_remediation(finding)
    return apply_finding_scope(finding)


def finding_from_semgrep(item: dict[str, Any], target: Path) -> Finding:
    extra = item.get('extra', {}) or {}
    metadata = extra.get('metadata', {}) or {}
    start = item.get('start', {}) or {}
    rule_id = item.get('check_id', 'semgrep-rule')
    message = extra.get('message') or rule_id
    return normalize_finding(
        source='semgrep', rule_id=rule_id, title=title_from_rule(rule_id), severity=extra.get('severity'), confidence='HIGH',
        path=relpath(item.get('path', ''), target), line=int(start.get('line') or 1), column=int(start.get('col') or 1),
        message=message, cwe=metadata.get('cwe'), owasp=metadata.get('owasp'), references=metadata.get('references'),
        raw=item, raw_severity=extra.get('severity'), metadata={'engine': 'semgrep'},
    )


def finding_from_bandit(item: dict[str, Any], target: Path) -> Finding:
    rule_id = item.get('test_id') or item.get('test_name') or 'bandit-rule'
    message = item.get('issue_text') or rule_id
    cwe_value = item.get('issue_cwe') or {}
    cwe = [f"CWE-{cwe_value.get('id')}"] if isinstance(cwe_value, dict) and cwe_value.get('id') else []
    refs = [cwe_value.get('link')] if isinstance(cwe_value, dict) and cwe_value.get('link') else []
    return normalize_finding(
        source='bandit', rule_id=rule_id, title=item.get('test_name') or title_from_rule(rule_id), severity=item.get('issue_severity'),
        confidence=item.get('issue_confidence') or 'MEDIUM', path=relpath(item.get('filename', ''), target),
        line=int(item.get('line_number') or 1), column=int(item.get('col_offset') or 1), message=message, cwe=cwe,
        references=refs, raw=item, raw_severity=item.get('issue_severity'), metadata={'engine': 'bandit'},
    )


def finding_from_shellcheck(item: dict[str, Any], target: Path) -> Finding:
    code = str(item.get('code') or item.get('ruleId') or 'shellcheck')
    rule_id = code if code.upper().startswith('SC') else f'SC{code}'
    level = str(item.get('level') or item.get('severity') or 'warning').lower()
    message = str(item.get('message') or rule_id)
    metadata = {'engine': 'shellcheck'}
    catalog_rule = shellcheck_catalog_rule(rule_id)
    if catalog_rule:
        metadata['catalog_rule_id'] = catalog_rule
    return normalize_finding(
        source='shellcheck',
        rule_id=rule_id,
        title=f'ShellCheck {rule_id}',
        severity=shellcheck_severity(level),
        confidence='HIGH',
        path=relpath(str(item.get('file') or item.get('filename') or ''), target),
        line=int(item.get('line') or item.get('startLine') or 1),
        column=int(item.get('column') or item.get('startColumn') or 1),
        message=message,
        raw=item,
        raw_severity=level,
        metadata=metadata,
    )


def shellcheck_severity(level: str) -> str:
    return {
        'error': 'HIGH',
        'warning': 'MEDIUM',
        'info': 'LOW',
        'style': 'INFO',
    }.get(str(level).lower(), 'INFO')


def shellcheck_catalog_rule(rule_id: str) -> str:
    return {
        'SC2086': 'SH-001',
        'SC2045': 'SH-003',
        'SC2010': 'SH-003',
        'SC2294': 'SH-004',
    }.get(rule_id.upper(), '')


def finding_from_pip_audit(dep: dict[str, Any], vuln: dict[str, Any], req_file: Path, target: Path) -> Finding:
    package = dep.get('name', 'dependency')
    version = dep.get('version') or ''
    vuln_id = vuln.get('id', 'known-vulnerability')
    message = f"{package} {version} is affected by {vuln_id}: {vuln.get('description') or 'known vulnerability'}"
    return normalize_finding(
        source='pip-audit', rule_id=vuln_id, title=f'Vulnerable dependency: {package}', severity='HIGH', confidence='HIGH',
        path=relpath(str(req_file), target), line=1, message=message, cwe=[],
        owasp=['A06:2021-Vulnerable and Outdated Components'], references=vuln.get('aliases'),
        raw={'dependency': dep, 'vulnerability': vuln}, raw_severity='HIGH',
        metadata={'engine': 'pip-audit', 'package': str(package), 'version': str(version), 'fix_versions': ','.join(normalize_list(vuln.get('fix_versions')))},
    )


def finding_from_sonar_issue(issue: dict[str, Any]) -> Finding:
    component = str(issue.get('component', ''))
    path = component.split(':', 1)[-1] if ':' in component else component
    line = int(issue.get('line') or issue.get('textRange', {}).get('startLine') or 1)
    rule = issue.get('rule', 'sonarqube-rule')
    issue_type = str(issue.get('type') or '')
    message = issue.get('message', rule)
    return normalize_finding(
        source='sonarqube', rule_id=rule, title=title_from_rule(rule), severity=issue.get('severity') or issue.get('impactSeverity'),
        confidence='MEDIUM', path=path, line=line, message=message, raw=issue, raw_severity=issue.get('severity'),
        metadata={'engine': 'sonarqube', 'type': issue_type, 'status': str(issue.get('status') or ''), 'key': str(issue.get('key') or '')},
    )


def findings_from_sarif_file(path: Path, source: str = 'sarif-import') -> list[Finding]:
    payload = json.loads(path.read_text(encoding='utf-8'))
    return findings_from_sarif_payload(payload, source=source, metadata={'sarif_file': str(path)})


def findings_from_sarif_payload(payload: dict[str, Any], source: str = 'sarif-import', metadata: dict[str, Any] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for run in payload.get('runs', []) or []:
        rules = sarif_rules(run)
        tool = run.get('tool', {}).get('driver', {}) or {}
        tool_name = str(tool.get('name') or source)
        for result in run.get('results', []) or []:
            rule_id = result.get('ruleId') or result.get('rule', {}).get('id') or 'sarif-rule'
            rule = rules.get(rule_id, {})
            location = first_sarif_location(result)
            file_path = location.get('uri', '')
            region = location.get('region', {}) or {}
            line = int(region.get('startLine') or 1)
            column = int(region.get('startColumn') or 1)
            message = sarif_message(result) or rule.get('shortDescription', {}).get('text') or str(rule_id)
            tags = rule.get('properties', {}).get('tags', []) or []
            cwe = [str(tag).upper().replace('CWE', 'CWE-') if re.match(r'(?i)^cwe[-_]?\d+', str(tag)) else str(tag).upper() for tag in tags if str(tag).lower().startswith('cwe')]
            owasp = [str(tag) for tag in tags if 'owasp' in str(tag).lower()]
            props = result.get('properties', {}) if isinstance(result.get('properties'), dict) else {}
            source_name = source or str(props.get('source') or tool_name or 'sarif-import')
            raw_metadata = {'engine': tool_name, 'sarif_rule_name': str(rule.get('name') or ''), **stringify_metadata(metadata or {})}
            findings.append(normalize_finding(
                source=source_name,
                rule_id=str(rule_id),
                title=rule.get('name') or title_from_rule(str(rule_id)),
                severity=props.get('severity') or result.get('level'),
                confidence=props.get('confidence') or rule.get('properties', {}).get('precision', 'MEDIUM'),
                path=file_path,
                line=line,
                column=column,
                message=message,
                cwe=cwe,
                owasp=owasp,
                references=sarif_references(rule),
                raw=result,
                raw_severity=result.get('level'),
                metadata=raw_metadata,
            ))
    return findings


def findings_from_snyk_payload(payload: dict[str, Any], target: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    items = payload.get('vulnerabilities') or payload.get('issues') or []
    if isinstance(items, dict):
        items = list(items.values())
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get('id') or item.get('issueId') or item.get('ruleId') or 'snyk-issue')
        package = item.get('packageName') or item.get('package') or item.get('moduleName')
        title = item.get('title') or item.get('name') or (f'Snyk issue: {package}' if package else title_from_rule(rule_id))
        path = item.get('filePath') or item.get('path') or item.get('from', [''])[0] if isinstance(item.get('from'), list) else ''
        if target and path:
            path = relpath(str(path), target)
        line = int(item.get('lineNumber') or item.get('line') or 1)
        message = item.get('description') or item.get('message') or title
        findings.append(normalize_finding(
            source='snyk', rule_id=rule_id, title=str(title), severity=item.get('severity'), confidence='MEDIUM',
            path=str(path), line=line, message=str(message), cwe=item.get('identifiers', {}).get('CWE') if isinstance(item.get('identifiers'), dict) else item.get('cwe'),
            references=item.get('references'), raw=item, raw_severity=item.get('severity'),
            metadata={'engine': 'snyk', 'package': str(package or ''), 'cvss_score': str(item.get('cvssScore') or '')},
        ))
    return findings


def scanner_mesh_status() -> dict[str, Any]:
    return {
        'schema_version': NORMALIZATION_VERSION,
        'supported_sources': SUPPORTED_SOURCES,
        'normalized_fields': ['source', 'rule_id', 'severity', 'confidence', 'cwe', 'owasp', 'references', 'scope', 'risk', 'scanner_metadata', 'exploitability', 'reachability', 'policy_impact', 'remediation'],
        'sarif_import': {'enabled': True, 'cli_flag': '--sarif-in'},
        'future_connectors': ['snyk-cli', 'snyk-api', 'semgrep-appsec-platform', 'github-code-scanning-sarif'],
    }


def scanner_mesh_report(scan: ScanResult) -> dict[str, Any]:
    by_source = Counter(finding.source for finding in scan.findings)
    by_family = Counter(source_family(finding.source) for finding in scan.findings)
    exploitability = Counter(finding.exploitability for finding in scan.findings)
    reachability = Counter(finding.reachability for finding in scan.findings)
    policy = Counter(tag for finding in scan.findings for tag in finding.policy_impact)
    metadata_coverage = sum(1 for finding in scan.findings if finding.scanner_metadata)
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'schema_version': NORMALIZATION_VERSION,
        'findings': len(scan.findings),
        'sources': dict(sorted(by_source.items())),
        'source_families': dict(sorted(by_family.items())),
        'scopes': scope_counts(scan.findings),
        'production_findings': scan.summary.production_findings,
        'hygiene_findings': scan.summary.hygiene_findings,
        'tools': scan.summary.tools,
        'coverage': {
            'scanner_metadata': metadata_coverage,
            'exploitability': sum(1 for finding in scan.findings if finding.exploitability != 'unknown'),
            'reachability': sum(1 for finding in scan.findings if finding.reachability != 'unknown'),
            'policy_impact': sum(1 for finding in scan.findings if finding.policy_impact),
            'remediation': sum(1 for finding in scan.findings if finding.remediation),
        },
        'exploitability': dict(sorted(exploitability.items())),
        'reachability': dict(sorted(reachability.items())),
        'policy_impact': dict(sorted(policy.items())),
        'top_sources': [{'source': source, 'count': count, 'family': source_family(source)} for source, count in by_source.most_common(10)],
        'supported_sources': SUPPORTED_SOURCES,
    }


def infer_exploitability(finding: Finding) -> str:
    text = ' '.join([finding.title, finding.rule_id, finding.message, finding.explanation]).lower()
    if finding.source in {'secret-scan', 'gitleaks', 'trufflehog'} or any(token in text for token in ('secret', 'token', 'password', 'credential', 'private key')):
        return 'credential-exposure'
    if finding.source in {'pip-audit', 'snyk'} or re.search(r'\b(cve|pysec|ghsa)-', text):
        return 'known-vulnerability'
    if any(keyword in text for keyword in EXPLOITABLE_KEYWORDS):
        return 'likely-exploitable'
    if finding.severity in {'CRITICAL', 'HIGH'}:
        return 'needs-review'
    return 'unknown'


def infer_reachability(finding: Finding) -> str:
    path = finding.location.path.lower()
    if any(path.endswith(name.lower()) for name in MANIFEST_NAMES) or finding.source in {'pip-audit', 'dependency-manifest', 'snyk'}:
        return 'package-level'
    if path.endswith(CONFIG_PATTERNS):
        return 'configuration'
    if path.endswith(SOURCE_EXTENSIONS):
        return 'source-line'
    if finding.source in {'codeql', 'semgrep', 'bandit', 'shellcheck', 'sql-artifact', 'python-ast', 'sonarqube'}:
        return 'source-line'
    return 'unknown'


def infer_policy_impact(finding: Finding) -> list[str]:
    impacts: list[str] = []
    if finding.source in {'secret-scan', 'gitleaks', 'trufflehog'} or 'secret' in finding.rule_id.lower():
        impacts.append('push-protection')
    if finding.source in {'pip-audit', 'dependency-manifest', 'snyk'}:
        impacts.append('dependency-review')
    if finding.source in {'sonarqube'}:
        impacts.append('quality-gate')
    if finding.source in {'codeql', 'semgrep', 'bandit', 'shellcheck', 'sql-artifact', 'python-ast', 'sarif-import'}:
        impacts.append('security-review')
    if finding.severity in {'CRITICAL', 'HIGH'} or finding.risk.priority in {'P0', 'P1'}:
        impacts.append('pr-gate')
    if finding.cwe or finding.owasp:
        impacts.append('compliance-evidence')
    return sorted(set(impacts))


def infer_remediation(finding: Finding) -> list[str]:
    values = [finding.fix.summary] + list(finding.fix.guidance or [])
    if finding.source in {'pip-audit', 'dependency-manifest', 'snyk'}:
        values.append('Review dependency reachability and upgrade to a non-vulnerable pinned version.')
    if finding.source in {'secret-scan', 'gitleaks', 'trufflehog'}:
        values.append('Rotate the credential before marking the finding fixed.')
    return [item for item in values if item]


def metadata_from_raw(source: str, raw: dict[str, Any] | None, raw_severity: Any, metadata: dict[str, Any] | None) -> dict[str, str]:
    result = {
        'normalization_version': NORMALIZATION_VERSION,
        'scanner_source': source,
        'scanner_family': source_family(source),
    }
    if raw_severity is not None:
        result['raw_severity'] = str(raw_severity)
    if raw:
        for key in ('check_id', 'test_id', 'test_name', 'ruleId', 'rule', 'key', 'id'):
            value = raw.get(key)
            if value:
                result[f'raw_{key}'] = str(value)[:200]
        result['raw_type'] = type(raw).__name__
    result.update(stringify_metadata(metadata or {}))
    return result


def sarif_rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for rule in run.get('tool', {}).get('driver', {}).get('rules', []) or []:
        if rule.get('id'):
            rules[str(rule['id'])] = rule
    return rules


def first_sarif_location(result: dict[str, Any]) -> dict[str, Any]:
    locations = result.get('locations') or []
    if not locations:
        return {'uri': '', 'region': {}}
    physical = locations[0].get('physicalLocation', {}) or {}
    return {'uri': physical.get('artifactLocation', {}).get('uri', ''), 'region': physical.get('region', {}) or {}}


def sarif_message(result: dict[str, Any]) -> str:
    message = result.get('message') or {}
    if isinstance(message, dict):
        return str(message.get('text') or message.get('markdown') or '')
    return str(message or '')


def sarif_references(rule: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    help_uri = rule.get('helpUri')
    if help_uri:
        refs.append(str(help_uri))
    for item in rule.get('properties', {}).get('references', []) or []:
        refs.append(str(item))
    return refs


def normalize_severity(value: Any) -> str:
    text = str(value or 'INFO').upper()
    return SEVERITY_ALIASES.get(text, text if text in SEVERITY_ORDER else 'INFO')


def normalize_confidence(value: Any) -> str:
    text = str(value or 'MEDIUM').upper()
    if text in {'VERY-HIGH', 'VERY_HIGH', 'HIGH'}:
        return 'HIGH'
    if text in {'LOW', 'MEDIUM'}:
        return text
    return 'MEDIUM'


def normalize_taxonomy(value: Any, prefix: str) -> list[str]:
    result = []
    for item in normalize_list(value):
        text = str(item).strip().upper().replace('_', '-')
        if prefix == 'CWE-' and re.match(r'^CWE\d+$', text):
            text = text.replace('CWE', 'CWE-')
        if prefix == 'CWE-' and text.isdigit():
            text = f'CWE-{text}'
        result.append(text)
    return sorted(set(result))


def normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, tuple | set):
        return [str(item) for item in value if item]
    if isinstance(value, dict):
        return [str(item) for item in value.values() if item]
    return [str(value)]


def stringify_metadata(values: dict[str, Any]) -> dict[str, str]:
    return {str(key): ','.join(normalize_list(value))[:500] for key, value in values.items() if value is not None}


def source_family(source: str) -> str:
    if source in SOURCE_FAMILIES:
        return SOURCE_FAMILIES[source]
    if source.startswith('sarif'):
        return 'sarif'
    return 'unknown'


def make_fingerprint(source: str, rule_id: str, path: str, line: int, message: str) -> str:
    raw = f'{source}|{rule_id}|{path.replace(os.sep, "/")}|{line}|{message}'
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def title_from_rule(rule_id: str) -> str:
    return str(rule_id).replace('_', '-').replace('.', '-').replace(':', '-').split('/')[-1].replace('-', ' ').title()


def normalize_path(path: str) -> str:
    value = str(path or '').replace('\\', '/')
    return value[2:] if value.startswith('./') else value


def relpath(path: str, target: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(target.resolve())).replace('\\', '/')
    except Exception:
        return normalize_path(path)
