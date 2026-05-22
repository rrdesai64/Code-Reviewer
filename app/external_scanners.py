from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from .ingestion import finding_from_sonar_issue, findings_from_sarif_file, normalize_finding
from .models import Finding

ROOT = Path(__file__).resolve().parents[1]
LOCAL_CODEQL_EXE = ROOT / 'tools' / 'codeql' / 'codeql.exe'
LOCAL_SONAR_SCANNER = ROOT / 'node_modules' / 'sonar-scanner' / 'bin' / 'sonar-scanner.bat'
DEFAULT_JAVA_HOME = Path('C:/Program Files/Eclipse Adoptium/jre-17.0.19.10-hotspot')
CODEQL_LANG_BY_EXT = {
    '.py': 'python', '.js': 'javascript', '.jsx': 'javascript', '.ts': 'javascript', '.tsx': 'javascript',
    '.java': 'java-kotlin', '.kt': 'java-kotlin', '.c': 'cpp', '.h': 'cpp', '.cpp': 'cpp', '.cc': 'cpp',
    '.cs': 'csharp', '.go': 'go', '.rb': 'ruby', '.swift': 'swift',
}
CODEQL_QUERY_SUITE_BY_LANGUAGE = {
    'python': 'codeql/python-queries:codeql-suites/python-code-scanning.qls',
    'javascript': 'codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls',
    'java-kotlin': 'codeql/java-queries:codeql-suites/java-code-scanning.qls',
    'cpp': 'codeql/cpp-queries:codeql-suites/cpp-code-scanning.qls',
    'csharp': 'codeql/csharp-queries:codeql-suites/csharp-code-scanning.qls',
    'go': 'codeql/go-queries:codeql-suites/go-code-scanning.qls',
    'ruby': 'codeql/ruby-queries:codeql-suites/ruby-code-scanning.qls',
    'swift': 'codeql/swift-queries:codeql-suites/swift-code-scanning.qls',
}
CODEQL_NO_BUILD_LANGUAGES = {'python', 'javascript', 'ruby'}


def run_codeql(target: Path, files: list[Path]) -> tuple[list[Finding], str]:
    enabled = os.getenv('CODEQL_ENABLED', 'auto').lower()
    if enabled == 'false':
        return [], 'disabled by CODEQL_ENABLED=false'
    codeql = os.getenv('CODEQL_EXE') or (str(LOCAL_CODEQL_EXE) if LOCAL_CODEQL_EXE.exists() else None) or shutil.which('codeql')
    if not codeql:
        return [], 'not installed'
    languages = sorted({CODEQL_LANG_BY_EXT.get(path.suffix.lower()) for path in files if CODEQL_LANG_BY_EXT.get(path.suffix.lower())})
    if not languages:
        return [], 'skipped: no CodeQL-supported languages'
    findings: list[Finding] = []
    statuses: list[str] = []
    for language in languages:
        language_findings, status = run_codeql_language(Path(codeql), target, language)
        findings.extend(language_findings)
        statuses.append(f'{language}={status}')
    return findings, '; '.join(statuses)


def run_codeql_language(codeql: Path, target: Path, language: str) -> tuple[list[Finding], str]:
    work = ROOT / 'data' / 'codeql' / f'{target.name}-{language}-{uuid.uuid4().hex[:8]}'
    db = work / 'db'
    sarif = work / 'results.sarif'
    query_suites = codeql_query_suites(language)
    if not query_suites:
        return [], 'skipped: no query suite configured'
    timeout = int(os.getenv('CODEQL_TIMEOUT_SECONDS', '900'))
    work.mkdir(parents=True, exist_ok=True)
    create_command = [str(codeql), 'database', 'create', str(db), '--source-root', str(target), '--language', language, '--overwrite']
    create_command.extend(codeql_resource_args())
    build_mode = codeql_build_mode(language)
    build_command = codeql_build_command(language)
    if build_command:
        create_command.append(f'--command={build_command}')
    elif build_mode:
        create_command.append(f'--build-mode={build_mode}')
    code, stdout, stderr = run_tool(create_command, ROOT, timeout=timeout)
    if code != 0:
        return [], f'database create failed: {clean_error(stderr or stdout)}'
    analyze_command = [str(codeql), 'database', 'analyze', str(db), *query_suites, '--format=sarifv2.1.0', f'--output={sarif}']
    analyze_command.extend(codeql_resource_args())
    code, stdout, stderr = run_tool(analyze_command, ROOT, timeout=timeout)
    if code not in (0, 2) or not sarif.exists():
        return [], f'analyze failed: {clean_error(stderr or stdout)}'
    findings = findings_from_sarif(sarif, 'codeql')
    build_label = 'command' if build_command else (build_mode or 'autobuild')
    return findings, f'ok findings={len(findings)} queries={len(query_suites)} build={build_label}'


def run_sonarqube(target: Path, files: list[Path]) -> tuple[list[Finding], str]:
    enabled = os.getenv('SONAR_ENABLED', 'auto').lower()
    if enabled == 'false':
        return [], 'disabled by SONAR_ENABLED=false'
    scanner = os.getenv('SONAR_SCANNER_EXE') or (str(LOCAL_SONAR_SCANNER) if LOCAL_SONAR_SCANNER.exists() else None) or shutil.which('sonar-scanner')
    host = os.getenv('SONAR_HOST_URL')
    token = os.getenv('SONAR_TOKEN')
    project_key = os.getenv('SONAR_PROJECT_KEY', safe_project_key(target.name))
    if not scanner:
        return [], 'not installed'
    if not host or not token:
        return [], 'installed, not configured: SONAR_HOST_URL and SONAR_TOKEN required'
    if sonarcloud_requires_organization(host) and not os.getenv('SONAR_ORGANIZATION', '').strip():
        return [], 'installed, not configured: SONAR_ORGANIZATION required for SonarCloud'
    timeout = int(os.getenv('SONAR_TIMEOUT_SECONDS', '600'))
    command = sonar_scanner_command(scanner, target, host, token, project_key)
    code, stdout, stderr = run_tool(command, target, timeout=timeout, env=sonar_env())
    if code != 0:
        return [], f'scanner failed: {clean_error(stderr or stdout)}'

    findings: list[Finding] = []
    status_parts = ['scan=ok']
    try:
        issues = fetch_sonar_issues(host, token, project_key)
        issue_findings = [finding_from_sonar(issue) for issue in issues]
        findings.extend(issue_findings)
        status_parts.append(f'issues={len(issue_findings)}')
    except Exception as exc:
        status_parts.append(f'issue_fetch_failed={clean_error(str(exc))}')

    if os.getenv('SONAR_QUALITY_GATE_ENABLED', 'true').lower() != 'false':
        try:
            gate = fetch_sonar_quality_gate(host, token, project_key)
            gate_findings = findings_from_sonar_quality_gate(project_key, gate)
            findings.extend(gate_findings)
            status_parts.append(f'quality_gate={quality_gate_status(gate)}')
            status_parts.append(f'gate_findings={len(gate_findings)}')
        except Exception as exc:
            status_parts.append(f'quality_gate_fetch_failed={clean_error(str(exc))}')
    else:
        status_parts.append('quality_gate=disabled')
    return findings, ', '.join(status_parts)


def fetch_sonar_issues(host: str, token: str, project_key: str) -> list[dict[str, Any]]:
    params = {
        'componentKeys': project_key,
        'types': os.getenv('SONAR_ISSUE_TYPES', 'VULNERABILITY,SECURITY_HOTSPOT,BUG,CODE_SMELL'),
        'ps': os.getenv('SONAR_ISSUE_PAGE_SIZE', '500'),
    }
    params.update(sonar_api_context_params())
    severities = os.getenv('SONAR_SEVERITIES')
    if severities:
        params['severities'] = severities
    query = urllib.parse.urlencode(params)
    req = urllib.request.Request(f'{host.rstrip("/")}/api/issues/search?{query}')
    req.add_header('Authorization', 'Basic ' + basic_token(token))
    with urllib.request.urlopen(req, timeout=45) as response:
        payload = json.loads(response.read().decode('utf-8'))
    return payload.get('issues', [])


def fetch_sonar_quality_gate(host: str, token: str, project_key: str) -> dict[str, Any]:
    params = {'projectKey': project_key}
    params.update(sonar_api_context_params(include_pull_request=True))
    query = urllib.parse.urlencode(params)
    req = urllib.request.Request(f'{host.rstrip("/")}/api/qualitygates/project_status?{query}')
    req.add_header('Authorization', 'Basic ' + basic_token(token))
    with urllib.request.urlopen(req, timeout=45) as response:
        payload = json.loads(response.read().decode('utf-8'))
    return payload.get('projectStatus', {}) or {}


def findings_from_sonar_quality_gate(project_key: str, gate: dict[str, Any]) -> list[Finding]:
    if not gate:
        return []
    gate_status = quality_gate_status(gate)
    raw_conditions = gate.get('conditions') if isinstance(gate.get('conditions'), list) else []
    failing = [condition for condition in raw_conditions if str(condition.get('status') or '').upper() not in ('OK', 'PASS', '')]
    if gate_status not in ('OK', 'PASS', 'NONE', 'UNKNOWN', 'DISABLED') and not failing:
        failing = [{'metricKey': 'quality_gate', 'status': gate_status, 'actualValue': gate_status, 'errorThreshold': 'OK'}]
    return [finding_from_sonar_quality_gate_condition(project_key, gate, condition) for condition in failing]


def finding_from_sonar_quality_gate_condition(project_key: str, gate: dict[str, Any], condition: dict[str, Any]) -> Finding:
    gate_status = quality_gate_status(gate)
    metric = str(condition.get('metricKey') or condition.get('metric') or 'quality_gate')
    condition_status = str(condition.get('status') or gate_status or 'ERROR').upper()
    severity = 'CRITICAL' if condition_status == 'ERROR' else 'HIGH' if condition_status == 'WARN' else 'MEDIUM'
    actual = str(condition.get('actualValue') or condition.get('actual') or '')
    threshold = str(condition.get('errorThreshold') or condition.get('threshold') or '')
    comparator = str(condition.get('comparator') or '')
    metric_label = metric.replace('_', ' ')
    details = ', '.join(part for part in [f'actual={actual}' if actual else '', f'comparator={comparator}' if comparator else '', f'threshold={threshold}' if threshold else ''] if part)
    message = f'SonarQube quality gate condition {metric} is {condition_status}' + (f' ({details}).' if details else '.')
    return normalize_finding(
        source='sonarqube',
        rule_id=f'sonarqube-quality-gate:{metric}',
        title=f'SonarQube quality gate failed: {metric_label}',
        severity=severity,
        confidence='HIGH',
        path=f'sonarqube/{safe_project_key(project_key)}',
        line=1,
        message=message,
        owasp=['A05:2021-Security Misconfiguration'],
        raw=condition,
        raw_severity=condition_status,
        metadata={
            'engine': 'sonarqube',
            'sonar_kind': 'quality_gate',
            'project_key': project_key,
            'quality_gate_status': gate_status,
            'quality_gate_condition_status': condition_status,
            'metric_key': metric,
            'metric_name': metric_label,
            'actual_value': actual,
            'error_threshold': threshold,
            'comparator': comparator,
            'period_index': str(condition.get('periodIndex') or ''),
            'ignored_conditions': str(gate.get('ignoredConditions') or ''),
            'cayc_status': str(gate.get('caycStatus') or ''),
        },
    )


def quality_gate_status(gate: dict[str, Any]) -> str:
    return str(gate.get('status') or gate.get('projectStatus') or 'UNKNOWN').upper()


def basic_token(token: str) -> str:
    return base64.b64encode(f'{token}:'.encode('utf-8')).decode('ascii')


def finding_from_sonar(issue: dict[str, Any]) -> Finding:
    return finding_from_sonar_issue(issue)


def findings_from_sarif(path: Path, source: str) -> list[Finding]:
    return findings_from_sarif_file(path, source=source)


def run_tool(command: list[str], cwd: Path, timeout: int, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(command, cwd=str(cwd), text=True, capture_output=True, timeout=timeout, env=env)
        return completed.returncode, completed.stdout, completed.stderr
    except FileNotFoundError as exc:
        return 127, '', str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or '', exc.stderr or 'tool timed out'


def safe_project_key(name: str) -> str:
    return ''.join(ch if ch.isalnum() or ch in '._:-' else '-' for ch in name)


def clean_error(text: str) -> str:
    return ' '.join((text or '').split())[:500]


def sonarcloud_requires_organization(host: str) -> bool:
    return 'sonarcloud.io' in host.lower()


def sonar_scanner_command(scanner: str, target: Path, host: str, token: str, project_key: str) -> list[str]:
    sources = os.getenv('SONAR_SOURCES', '.').strip() or '.'
    command = [
        scanner,
        f'-Dsonar.projectKey={project_key}',
        f'-Dsonar.projectBaseDir={target}',
        f'-Dsonar.sources={sources}',
        f'-Dsonar.host.url={host}',
        f'-Dsonar.token={token}',
    ]
    for key, value in optional_sonar_properties().items():
        if value:
            command.append(f'-D{key}={value}')
    if os.getenv('SONAR_QUALITY_GATE_WAIT', 'false').lower() == 'true':
        command.extend(['-Dsonar.qualitygate.wait=true', f'-Dsonar.qualitygate.timeout={os.getenv("SONAR_QUALITY_GATE_TIMEOUT", "300")}'])
    command.extend(split_semicolon_env('SONAR_EXTRA_ARGS'))
    return command


def optional_sonar_properties() -> dict[str, str]:
    return {
        'sonar.organization': os.getenv('SONAR_ORGANIZATION', '').strip(),
        'sonar.projectName': os.getenv('SONAR_PROJECT_NAME', '').strip(),
        'sonar.sourceEncoding': os.getenv('SONAR_SOURCE_ENCODING', 'UTF-8').strip(),
        'sonar.exclusions': os.getenv('SONAR_EXCLUSIONS', '').strip(),
        'sonar.inclusions': os.getenv('SONAR_INCLUSIONS', '').strip(),
        'sonar.branch.name': os.getenv('SONAR_BRANCH_NAME', '').strip(),
        'sonar.pullrequest.key': os.getenv('SONAR_PULLREQUEST_KEY', '').strip(),
        'sonar.pullrequest.branch': os.getenv('SONAR_PULLREQUEST_BRANCH', '').strip(),
        'sonar.pullrequest.base': os.getenv('SONAR_PULLREQUEST_BASE', '').strip(),
    }


def sonar_api_context_params(include_pull_request: bool = False) -> dict[str, str]:
    params: dict[str, str] = {}
    organization = os.getenv('SONAR_ORGANIZATION', '').strip()
    branch = os.getenv('SONAR_BRANCH_NAME', '').strip()
    pull_request = os.getenv('SONAR_PULLREQUEST_KEY', '').strip()
    if organization:
        params['organization'] = organization
    if include_pull_request and pull_request:
        params['pullRequest'] = pull_request
    elif branch:
        params['branch'] = branch
    return params


def sonar_env() -> dict[str, str]:
    env = os.environ.copy()
    configured = os.getenv('SONAR_JAVA_HOME') or os.getenv('JAVA_HOME')
    if configured and (Path(configured) / 'bin' / 'java.exe').exists():
        env['JAVA_HOME'] = configured
    elif DEFAULT_JAVA_HOME.exists():
        env['JAVA_HOME'] = str(DEFAULT_JAVA_HOME)
    return env


def codeql_query_suites(language: str) -> list[str]:
    env_name = f'CODEQL_QUERY_SUITE_{language.upper().replace("-", "_")}'
    global_suite = os.getenv('CODEQL_QUERY_SUITE', '').strip()
    if global_suite == 'codeql-suites/code-scanning.qls':
        global_suite = ''
    base = os.getenv(env_name) or global_suite or CODEQL_QUERY_SUITE_BY_LANGUAGE.get(language, '')
    suites = [base] if base else []
    suites.extend(split_semicolon_env('CODEQL_EXTRA_QUERY_SUITES'))
    return unique_nonempty(suites)


def codeql_build_mode(language: str) -> str:
    env_name = f'CODEQL_BUILD_MODE_{language.upper().replace("-", "_")}'
    configured = (os.getenv(env_name) or os.getenv('CODEQL_BUILD_MODE') or '').strip().lower()
    if configured in {'auto', 'autobuild'}:
        return ''
    if configured:
        return configured
    return 'none' if language in CODEQL_NO_BUILD_LANGUAGES else ''


def codeql_build_command(language: str) -> str:
    env_name = f'CODEQL_BUILD_COMMAND_{language.upper().replace("-", "_")}'
    return (os.getenv(env_name) or os.getenv('CODEQL_BUILD_COMMAND') or '').strip()


def codeql_resource_args() -> list[str]:
    args: list[str] = []
    threads = os.getenv('CODEQL_THREADS')
    ram = os.getenv('CODEQL_RAM')
    if threads:
        args.append(f'--threads={threads}')
    if ram:
        args.append(f'--ram={ram}')
    return args


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
