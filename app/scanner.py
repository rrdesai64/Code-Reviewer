from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

from .ai import explain, suggest_fix
from .dependency_review import enrich_dependency_findings
from .ingestion import enrich_finding, finding_from_bandit, finding_from_pip_audit, finding_from_semgrep, findings_from_sarif_file
from .ast_scanner import run_ast_analysis
from .external_scanners import run_codeql, run_sonarqube
from .go_tools import govulncheck_executable, go_tool_env
from .models import Finding, Location, ScanResult, ScanSummary
from .risk import score_scan
from .secrets import run_secret_scan
from .scope import apply_finding_scope, production_gate_findings, scope_counts, scope_sort_rank
from .storage import apply_decisions, compare_to_baseline

ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / 'rules' / 'semgrep-security.yml'
SEMGREP_EXE = ROOT / '.venv' / 'Scripts' / 'semgrep.exe'
BANDIT_EXE = ROOT / '.venv' / 'Scripts' / 'bandit.exe'
PIP_AUDIT_EXE = ROOT / '.venv' / 'Scripts' / 'pip-audit.exe'

EXCLUDED_DIRS = {'.git', '.venv', 'venv', 'node_modules', 'dist', 'build', '__pycache__', '.mypy_cache', '.pytest_cache', '.secure-review-backups', 'data'}
LANG_BY_EXT = {
    '.py': 'Python', '.js': 'JavaScript', '.jsx': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript',
    '.java': 'Java', '.c': 'C', '.h': 'C/C++', '.cpp': 'C++', '.cc': 'C++', '.cs': 'C#', '.go': 'Go',
    '.rs': 'Rust', '.php': 'PHP', '.rb': 'Ruby', '.yml': 'YAML', '.yaml': 'YAML', '.json': 'JSON',
    '.toml': 'TOML', '.txt': 'Text', '.md': 'Markdown', '.ps1': 'PowerShell', '.sh': 'Shell', '.sql': 'SQL',
    '.dockerfile': 'Dockerfile', '.gradle': 'Gradle', '.tf': 'Terraform', '.kt': 'Kotlin', '.swift': 'Swift',
}
LANG_BY_NAME = {
    'Dockerfile': 'Dockerfile', 'dockerfile': 'Dockerfile', 'package-lock.json': 'NPM Lockfile',
    'yarn.lock': 'Yarn Lockfile', 'pnpm-lock.yaml': 'PNPM Lockfile', 'Pipfile': 'Pipenv', 'pyproject.toml': 'Python Project',
    'go.mod': 'Go Module', 'go.sum': 'Go Module Checksum', 'Cargo.toml': 'Rust Cargo', 'Cargo.lock': 'Rust Cargo Lock',
}
SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}


def run_scan(target_path: Path, project_name: str | None = None, extra_sarif_paths: list[Path] | None = None) -> ScanResult:
    target = target_path.resolve()
    scan_id = uuid.uuid4().hex[:12]
    files = list(iter_source_files(target))
    findings: list[Finding] = []
    tools: dict[str, str] = {}

    semgrep_findings, semgrep_status = run_semgrep(target)
    findings.extend(semgrep_findings)
    tools['semgrep'] = semgrep_status

    bandit_findings, bandit_status = run_bandit(target, files)
    findings.extend(bandit_findings)
    tools['bandit'] = bandit_status

    ast_findings, ast_status = run_ast_analysis(target, files)
    findings.extend(ast_findings)
    tools['python-ast'] = ast_status

    secret_findings, secret_status = run_secret_scan(target, files)
    findings.extend(secret_findings)
    tools.update(secret_status)

    codeql_findings, codeql_status = run_codeql(target, files)
    findings.extend(codeql_findings)
    tools['codeql'] = codeql_status

    sonar_findings, sonar_status = run_sonarqube(target, files)
    findings.extend(sonar_findings)
    tools['sonarqube'] = sonar_status

    dependency_findings, dependency_status = run_dependency_checks(target)
    findings.extend(dependency_findings)
    tools.update(dependency_status)

    sarif_findings, sarif_status = run_sarif_imports(extra_sarif_paths or [])
    findings.extend(sarif_findings)
    tools.update(sarif_status)

    findings = [enrich_finding(finding) for finding in dedupe_findings(findings)]
    findings = [apply_finding_scope(finding) for finding in enrich_dependency_findings(target, findings)]
    scan = ScanResult(
        scan_id=scan_id,
        project_name=project_name or target.name,
        target_path=str(target),
        summary=build_summary(files, findings, tools),
        findings=findings,
    )
    scan = score_scan(compare_to_baseline(scan))
    scan.findings = sorted(scan.findings, key=lambda item: (-scope_sort_rank(item), -item.risk.score, -SEVERITY_ORDER.get(item.severity, 0), item.location.path, item.location.line))
    scan.summary = build_summary(files, scan.findings, tools)
    return apply_decisions(scan)


def iter_source_files(target: Path):
    for path in target.rglob('*'):
        if not path.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in LANG_BY_EXT or path.name in LANG_BY_NAME:
            yield path


def build_summary(files: list[Path], findings: list[Finding], tools: dict[str, str]) -> ScanSummary:
    languages = Counter(language_for_path(path) for path in files)
    severities = Counter(f.severity for f in findings)
    production_findings = production_gate_findings(findings)
    production_risk_tiers = Counter(f.risk.tier for f in production_findings)
    production_priorities = Counter(f.risk.priority for f in production_findings)
    all_risk_tiers = Counter(f.risk.tier for f in findings)
    all_priorities = Counter(f.risk.priority for f in findings)
    return ScanSummary(
        total_findings=len(findings),
        critical=severities['CRITICAL'],
        high=severities['HIGH'],
        medium=severities['MEDIUM'],
        low=severities['LOW'],
        info=severities['INFO'],
        files_scanned=len(files),
        languages=dict(sorted(languages.items())),
        tools=tools,
        max_risk_score=max((f.risk.score for f in production_findings), default=0),
        avg_risk_score=round(sum(f.risk.score for f in production_findings) / len(production_findings), 1) if production_findings else 0,
        risk_tiers=dict(sorted(production_risk_tiers.items())),
        priorities=dict(sorted(production_priorities.items())),
        scope_counts=scope_counts(findings),
        production_findings=len(production_findings),
        hygiene_findings=len(findings) - len(production_findings),
        all_max_risk_score=max((f.risk.score for f in findings), default=0),
        all_avg_risk_score=round(sum(f.risk.score for f in findings) / len(findings), 1) if findings else 0,
        all_risk_tiers=dict(sorted(all_risk_tiers.items())),
        all_priorities=dict(sorted(all_priorities.items())),
    )


def run_tool(command: list[str], cwd: Path, timeout: int = 180, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(command, cwd=str(cwd), text=True, encoding='utf-8', errors='replace', capture_output=True, timeout=timeout, env=env)
        return completed.returncode, completed.stdout, completed.stderr
    except FileNotFoundError as exc:
        return 127, '', str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or '', exc.stderr or 'tool timed out'


def run_semgrep(target: Path) -> tuple[list[Finding], str]:
    configured = os.getenv('SEMGREP_EXE')
    semgrep = configured or (str(SEMGREP_EXE) if SEMGREP_EXE.exists() else None) or shutil.which('semgrep')
    if not semgrep:
        return [], 'not installed'
    configs = unique_nonempty([str(RULES_PATH), *split_semicolon_env('SEMGREP_CONFIGS')])
    command = [semgrep, 'scan', '--json', '--quiet', '--disable-version-check', '--metrics=off']
    for config in configs:
        command.extend(['--config', config])
    command.append(str(target))
    timeout = int(os.getenv('SEMGREP_TIMEOUT_SECONDS', '300'))
    code, stdout, stderr = run_tool(command, ROOT, timeout=timeout)
    if not stdout.strip():
        status = f'error: {stderr.strip() or code}' if code not in (0, 1) else f'ok findings=0 configs={len(configs)}'
        return [], status
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return [], 'error: invalid semgrep json'
    findings = [finding_from_semgrep(item, target) for item in payload.get('results', [])]
    if code in (0, 1):
        status = f'ok findings={len(findings)} configs={len(configs)}'
    else:
        status = f'partial findings={len(findings)} configs={len(configs)}: {stderr.strip() or code}'
    return findings, status


def split_semicolon_env(name: str) -> list[str]:
    raw = os.getenv(name, '')
    return [part.strip() for part in raw.split(';') if part.strip()]


def unique_nonempty(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        value = str(value or '').strip()
        if value and value not in seen:
            result.append(value)
            seen.add(value)
    return result


def normalize_semgrep(item: dict[str, Any], target: Path) -> Finding:
    extra = item.get('extra', {})
    metadata = extra.get('metadata', {}) or {}
    path = relpath(item.get('path', ''), target)
    start = item.get('start', {}) or {}
    rule_id = item.get('check_id', 'semgrep-rule')
    message = extra.get('message') or rule_id
    severity = normalize_severity(extra.get('severity'))
    cwe = normalize_list(metadata.get('cwe'))
    owasp = normalize_list(metadata.get('owasp'))
    refs = normalize_list(metadata.get('references'))
    fingerprint = make_fingerprint('semgrep', rule_id, path, start.get('line', 1), message)
    return Finding(
        id=fingerprint[:16], source='semgrep', rule_id=rule_id, title=title_from_rule(rule_id), severity=severity,
        confidence='HIGH', location=Location(path=path, line=start.get('line', 1), column=start.get('col', 1)),
        message=message, cwe=cwe, owasp=owasp, references=refs, explanation=explain(rule_id, message, cwe, owasp),
        fix=suggest_fix(rule_id, message), fingerprint=fingerprint,
    )


def run_bandit(target: Path, files: list[Path]) -> tuple[list[Finding], str]:
    if not BANDIT_EXE.exists():
        return [], 'not installed'
    if not any(path.suffix.lower() == '.py' for path in files):
        return [], 'skipped: no Python files'
    command = [str(BANDIT_EXE), '-r', str(target), '-f', 'json', '-q', '-x', ','.join(EXCLUDED_DIRS)]
    code, stdout, stderr = run_tool(command, ROOT)
    if not stdout.strip():
        return [], f'error: {stderr.strip() or code}' if code not in (0, 1) else 'ok'
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return [], 'error: invalid bandit json'
    findings = [finding_from_bandit(item, target) for item in payload.get('results', [])]
    status = 'ok' if code in (0, 1) else f'partial: {stderr.strip() or code}'
    return findings, status


def normalize_bandit(item: dict[str, Any], target: Path) -> Finding:
    rule_id = item.get('test_id') or item.get('test_name') or 'bandit-rule'
    message = item.get('issue_text') or rule_id
    path = relpath(item.get('filename', ''), target)
    line = int(item.get('line_number') or 1)
    cwe_value = item.get('issue_cwe') or {}
    cwe = [f"CWE-{cwe_value.get('id')}"] if isinstance(cwe_value, dict) and cwe_value.get('id') else []
    refs = [cwe_value.get('link')] if isinstance(cwe_value, dict) and cwe_value.get('link') else []
    severity = normalize_severity(item.get('issue_severity'))
    fingerprint = make_fingerprint('bandit', rule_id, path, line, message)
    return Finding(
        id=fingerprint[:16], source='bandit', rule_id=rule_id, title=item.get('test_name') or title_from_rule(rule_id),
        severity=severity, confidence=item.get('issue_confidence') or 'MEDIUM', location=Location(path=path, line=line),
        message=message, cwe=cwe, owasp=[], references=refs, explanation=explain(rule_id, message, cwe, []),
        fix=suggest_fix(rule_id, message), fingerprint=fingerprint,
    )


def run_dependency_checks(target: Path) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    status: dict[str, str] = {}
    findings.extend(check_unpinned_python_requirements(target))
    findings.extend(check_unpinned_package_json(target))
    audit_findings, audit_status = run_pip_audit(target)
    findings.extend(audit_findings)
    govuln_findings, govuln_status = run_govulncheck(target)
    findings.extend(govuln_findings)
    status['dependency_manifest'] = 'ok'
    status['pip-audit'] = audit_status
    status['govulncheck'] = govuln_status
    return findings, status


def run_sarif_imports(paths: list[Path]) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    status: dict[str, str] = {}
    for path in paths:
        resolved = Path(path).expanduser().resolve()
        key = f'sarif-import:{resolved.name}'
        if not resolved.exists():
            status[key] = 'not found'
            continue
        try:
            imported = findings_from_sarif_file(resolved, source='sarif-import')
        except Exception as exc:
            status[key] = f'error: {str(exc)[:200]}'
            continue
        findings.extend(imported)
        status[key] = f'ok: {len(imported)} findings'
    return findings, status


def run_pip_audit(target: Path) -> tuple[list[Finding], str]:
    if not PIP_AUDIT_EXE.exists():
        return [], 'not installed'
    requirement_files = [p for p in target.rglob('requirements*.txt') if not any(part in EXCLUDED_DIRS for part in p.parts)]
    if not requirement_files:
        return [], 'skipped: no requirements files'
    findings: list[Finding] = []
    for req_file in requirement_files:
        command = [str(PIP_AUDIT_EXE), '-r', str(req_file), '--format', 'json']
        code, stdout, stderr = run_tool(command, ROOT, timeout=180)
        if not stdout.strip():
            if code not in (0, 1):
                return findings, f'partial: {stderr.strip() or code}'
            continue
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return findings, 'partial: invalid pip-audit json'
        for dep in payload.get('dependencies', []):
            for vuln in dep.get('vulns', []):
                findings.append(finding_from_pip_audit(dep, vuln, req_file, target))
    return findings, 'ok'


def run_govulncheck(target: Path) -> tuple[list[Finding], str]:
    enabled = os.getenv('GOVULNCHECK_ENABLED', 'auto').lower()
    if enabled in {'false', '0', 'no', 'off'}:
        return [], 'disabled by GOVULNCHECK_ENABLED=false'
    if not any(p.name == 'go.mod' for p in target.rglob('go.mod') if not any(part in EXCLUDED_DIRS for part in p.parts)):
        return [], 'skipped: no go.mod files'
    exe = govulncheck_executable()
    if not exe:
        return [], 'not installed'
    timeout = int(os.getenv('GOVULNCHECK_TIMEOUT_SECONDS', '300'))
    command = [exe, '-json', './...']
    code, stdout, stderr = run_tool(command, target, timeout=timeout, env=go_tool_env())
    findings = findings_from_govulncheck(stdout, target)
    if code in (0, 1, 3):
        return findings, f'ok findings={len(findings)}'
    if findings:
        return findings, f'partial findings={len(findings)}: {clean_error(stderr or stdout or str(code))}'
    return [], f'error: {clean_error(stderr or stdout or str(code))}'


def findings_from_govulncheck(stdout: str, target: Path) -> list[Finding]:
    osv_index: dict[str, dict[str, Any]] = {}
    raw_findings: list[dict[str, Any]] = []
    for item in parse_json_lines(stdout):
        if isinstance(item.get('osv'), dict):
            osv = item['osv']
            if osv.get('id'):
                osv_index[str(osv['id'])] = osv
        if isinstance(item.get('finding'), dict):
            raw_findings.append(item['finding'])
    return [finding_from_govulncheck(item, osv_index, target) for item in raw_findings]


def finding_from_govulncheck(item: dict[str, Any], osv_index: dict[str, dict[str, Any]], target: Path) -> Finding:
    vuln_id = str(item.get('osv') or item.get('osv_id') or item.get('id') or 'GO-VULN')
    osv = osv_index.get(vuln_id, {})
    trace = item.get('trace') if isinstance(item.get('trace'), list) else []
    module = str(item.get('module') or first_trace_value(trace, 'module') or first_affected_module(osv) or first_trace_value(trace, 'package') or 'go-module')
    version = str(item.get('version') or '')
    fixed_version = str(item.get('fixed_version') or item.get('fixedVersion') or first_fixed_version(osv) or '')
    path, line = first_trace_location(trace, target)
    summary = str(osv.get('summary') or item.get('message') or f'Go vulnerability {vuln_id} affects {module}')
    references = govuln_references(osv)
    message = f'{module} {version or "unknown"} is affected by {vuln_id}: {summary}'
    if fixed_version:
        message += f' Fixed in {fixed_version}.'
    fingerprint = make_fingerprint('govulncheck', vuln_id, path, line, message)
    return Finding(
        id=fingerprint[:16], source='govulncheck', rule_id=vuln_id, title=f'Go vulnerable dependency: {module}',
        severity='HIGH', confidence='HIGH', location=Location(path=path, line=line), message=message,
        cwe=[], owasp=['A06:2021-Vulnerable and Outdated Components'], references=references,
        explanation=explain('go vulnerable dependency', message, [], ['A06:2021-Vulnerable and Outdated Components']),
        fix=suggest_fix('go vulnerable dependency', message), fingerprint=fingerprint,
        scanner_metadata={
            'engine': 'govulncheck', 'ecosystem': 'golang', 'package': module, 'version': version,
            'fix_versions': fixed_version, 'fixed_version': fixed_version,
        },
    )


def parse_json_lines(stdout: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in (stdout or '').splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            items.append(payload)
    return items


def first_trace_value(trace: list[dict[str, Any]], key: str) -> str:
    for frame in trace:
        value = frame.get(key)
        if value:
            return str(value)
    return ''


def first_trace_location(trace: list[dict[str, Any]], target: Path) -> tuple[str, int]:
    for frame in trace:
        position = frame.get('position') if isinstance(frame.get('position'), dict) else {}
        filename = position.get('filename') or frame.get('filename') or frame.get('file')
        if filename:
            return relpath(str(filename), target), int(position.get('line') or frame.get('line') or 1)
    return 'go.mod', 1


def first_affected_module(osv: dict[str, Any]) -> str:
    affected = osv.get('affected') if isinstance(osv.get('affected'), list) else []
    for item in affected:
        package = item.get('package') if isinstance(item, dict) else {}
        name = package.get('name') if isinstance(package, dict) else ''
        if name:
            return str(name)
    return ''


def first_fixed_version(osv: dict[str, Any]) -> str:
    affected = osv.get('affected') if isinstance(osv.get('affected'), list) else []
    for item in affected:
        ranges = item.get('ranges') if isinstance(item, dict) and isinstance(item.get('ranges'), list) else []
        for range_item in ranges:
            events = range_item.get('events') if isinstance(range_item, dict) and isinstance(range_item.get('events'), list) else []
            for event in events:
                fixed = event.get('fixed') if isinstance(event, dict) else ''
                if fixed:
                    return str(fixed)
    return ''


def govuln_references(osv: dict[str, Any]) -> list[str]:
    refs = []
    for ref in osv.get('references') or []:
        if isinstance(ref, dict) and ref.get('url'):
            refs.append(str(ref['url']))
    if osv.get('id'):
        refs.append(f'https://pkg.go.dev/vuln/{osv["id"]}')
    return refs


def clean_error(text: str) -> str:
    return ' '.join((text or '').split())[:500]


def check_unpinned_python_requirements(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    for req in target.rglob('requirements*.txt'):
        if any(part in EXCLUDED_DIRS for part in req.parts):
            continue
        for idx, line in enumerate(req.read_text(encoding='utf-8', errors='ignore').splitlines(), 1):
            clean = line.strip()
            if not clean or clean.startswith('#') or clean.startswith('-'):
                continue
            if not re.search(r'==|===|@\s*(file|https?)', clean):
                message = f'Python dependency is not pinned exactly: {clean}'
                path = relpath(str(req), target)
                fingerprint = make_fingerprint('dependency-manifest', 'python-unpinned-dependency', path, idx, clean)
                findings.append(Finding(
                    id=fingerprint[:16], source='dependency-manifest', rule_id='python-unpinned-dependency',
                    title='Unpinned Python dependency', severity='LOW', confidence='MEDIUM', location=Location(path=path, line=idx),
                    message=message, cwe=[], owasp=['A06:2021-Vulnerable and Outdated Components'], references=[],
                    explanation=explain('unpinned dependency', message, [], ['A06:2021-Vulnerable and Outdated Components']),
                    fix=suggest_fix('unpinned dependency', message), fingerprint=fingerprint,
                    scanner_metadata={'engine': 'dependency-manifest', 'ecosystem': 'pypi', 'package': clean.split('==', 1)[0].split('>=', 1)[0].split('<=', 1)[0].split('~=', 1)[0].split('>', 1)[0].split('<', 1)[0].strip(), 'version_spec': clean},
                ))
    return findings


def check_unpinned_package_json(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    for manifest in target.rglob('package.json'):
        if any(part in EXCLUDED_DIRS for part in manifest.parts):
            continue
        try:
            payload = json.loads(manifest.read_text(encoding='utf-8'))
        except json.JSONDecodeError:
            continue
        deps = {**payload.get('dependencies', {}), **payload.get('devDependencies', {})}
        for name, spec in deps.items():
            if isinstance(spec, str) and (spec.startswith('^') or spec.startswith('~') or spec in {'*', 'latest'}):
                path = relpath(str(manifest), target)
                message = f'Node dependency {name} uses a loose version range: {spec}'
                fingerprint = make_fingerprint('dependency-manifest', 'node-loose-dependency', path, 1, f'{name}{spec}')
                findings.append(Finding(
                    id=fingerprint[:16], source='dependency-manifest', rule_id='node-loose-dependency',
                    title='Loose Node dependency range', severity='LOW', confidence='MEDIUM', location=Location(path=path, line=1),
                    message=message, cwe=[], owasp=['A06:2021-Vulnerable and Outdated Components'], references=[],
                    explanation=explain('unpinned dependency', message, [], ['A06:2021-Vulnerable and Outdated Components']),
                    fix=suggest_fix('unpinned dependency', message), fingerprint=fingerprint,
                    scanner_metadata={'engine': 'dependency-manifest', 'ecosystem': 'npm', 'package': name, 'version_spec': spec},
                ))
    return findings


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen = set()
    result = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        result.append(finding)
    return result


def normalize_severity(value: Any) -> str:
    text = str(value or 'INFO').upper()
    return {'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'WARN': 'MEDIUM'}.get(text, text if text in SEVERITY_ORDER else 'INFO')


def normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]


def make_fingerprint(source: str, rule_id: str, path: str, line: int, message: str) -> str:
    raw = f'{source}|{rule_id}|{path.replace(os.sep, "/")}|{line}|{message}'
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def title_from_rule(rule_id: str) -> str:
    return rule_id.replace('_', '-').replace('.', '-').split(':')[-1].replace('-', ' ').title()


def relpath(path: str, target: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(target.resolve())).replace('\\', '/')
    except Exception:
        return str(path).replace('\\', '/')



def language_for_path(path: Path) -> str:
    return LANG_BY_NAME.get(path.name) or LANG_BY_EXT.get(path.suffix.lower(), 'Other')
