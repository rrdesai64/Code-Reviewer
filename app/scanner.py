from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

from .ai import explain, suggest_fix
from .ast_scanner import run_ast_analysis
from .external_scanners import run_codeql, run_sonarqube
from .models import Finding, Location, ScanResult, ScanSummary
from .storage import apply_decisions, compare_to_baseline

ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / 'rules' / 'semgrep-security.yml'
SEMGREP_EXE = ROOT / '.venv' / 'Scripts' / 'semgrep.exe'
BANDIT_EXE = ROOT / '.venv' / 'Scripts' / 'bandit.exe'
PIP_AUDIT_EXE = ROOT / '.venv' / 'Scripts' / 'pip-audit.exe'

EXCLUDED_DIRS = {'.git', '.venv', 'venv', 'node_modules', 'dist', 'build', '__pycache__', '.mypy_cache', '.pytest_cache', 'data'}
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


def run_scan(target_path: Path, project_name: str | None = None) -> ScanResult:
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

    codeql_findings, codeql_status = run_codeql(target, files)
    findings.extend(codeql_findings)
    tools['codeql'] = codeql_status

    sonar_findings, sonar_status = run_sonarqube(target, files)
    findings.extend(sonar_findings)
    tools['sonarqube'] = sonar_status

    dependency_findings, dependency_status = run_dependency_checks(target)
    findings.extend(dependency_findings)
    tools.update(dependency_status)

    findings = sorted(dedupe_findings(findings), key=lambda item: (-SEVERITY_ORDER.get(item.severity, 0), item.location.path, item.location.line))
    summary = build_summary(files, findings, tools)
    scan = ScanResult(
        scan_id=scan_id,
        project_name=project_name or target.name,
        target_path=str(target),
        summary=summary,
        findings=findings,
    )
    scan = compare_to_baseline(scan)
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
    )


def run_tool(command: list[str], cwd: Path, timeout: int = 180) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(command, cwd=str(cwd), text=True, capture_output=True, timeout=timeout)
        return completed.returncode, completed.stdout, completed.stderr
    except FileNotFoundError as exc:
        return 127, '', str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or '', exc.stderr or 'tool timed out'


def run_semgrep(target: Path) -> tuple[list[Finding], str]:
    if not SEMGREP_EXE.exists():
        return [], 'not installed'
    command = [str(SEMGREP_EXE), 'scan', '--config', str(RULES_PATH), '--json', '--quiet', '--disable-version-check', str(target)]
    code, stdout, stderr = run_tool(command, ROOT)
    if not stdout.strip():
        return [], f'error: {stderr.strip() or code}' if code not in (0, 1) else 'ok'
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return [], 'error: invalid semgrep json'
    findings = [normalize_semgrep(item, target) for item in payload.get('results', [])]
    status = 'ok' if code in (0, 1) else f'partial: {stderr.strip() or code}'
    return findings, status


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
    findings = [normalize_bandit(item, target) for item in payload.get('results', [])]
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
    status['dependency_manifest'] = 'ok'
    status['pip-audit'] = audit_status
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
                package = dep.get('name', 'dependency')
                vuln_id = vuln.get('id', 'known-vulnerability')
                message = f"{package} {dep.get('version') or ''} is affected by {vuln_id}: {vuln.get('description') or 'known vulnerability'}"
                path = relpath(str(req_file), target)
                fingerprint = make_fingerprint('pip-audit', vuln_id, path, 1, package)
                findings.append(Finding(
                    id=fingerprint[:16], source='pip-audit', rule_id=vuln_id, title=f'Vulnerable dependency: {package}',
                    severity='HIGH', confidence='HIGH', location=Location(path=path, line=1), message=message,
                    cwe=[], owasp=['A06:2021-Vulnerable and Outdated Components'], references=normalize_list(vuln.get('aliases')),
                    explanation=explain('dependency vulnerability', message, [], ['A06:2021-Vulnerable and Outdated Components']),
                    fix=suggest_fix('dependency vulnerability', message), fingerprint=fingerprint,
                ))
    return findings, 'ok'


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
