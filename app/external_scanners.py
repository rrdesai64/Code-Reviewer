from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from .ingestion import finding_from_sonar_issue, findings_from_sarif_file
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
}


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
    query_suite = os.getenv('CODEQL_QUERY_SUITE') or CODEQL_QUERY_SUITE_BY_LANGUAGE.get(language, '')
    timeout = int(os.getenv('CODEQL_TIMEOUT_SECONDS', '900'))
    work.mkdir(parents=True, exist_ok=True)
    code, stdout, stderr = run_tool([str(codeql), 'database', 'create', str(db), '--source-root', str(target), '--language', language, '--overwrite'], ROOT, timeout=timeout)
    if code != 0:
        return [], f'database create failed: {clean_error(stderr or stdout)}'
    code, stdout, stderr = run_tool([str(codeql), 'database', 'analyze', str(db), query_suite, '--format=sarifv2.1.0', f'--output={sarif}'], ROOT, timeout=timeout)
    if code not in (0, 2) or not sarif.exists():
        return [], f'analyze failed: {clean_error(stderr or stdout)}'
    return findings_from_sarif(sarif, 'codeql'), 'ok'


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
    timeout = int(os.getenv('SONAR_TIMEOUT_SECONDS', '600'))
    command = [scanner, f'-Dsonar.projectKey={project_key}', f'-Dsonar.projectBaseDir={target}', '-Dsonar.sources=.', f'-Dsonar.host.url={host}', f'-Dsonar.token={token}']
    code, stdout, stderr = run_tool(command, target, timeout=timeout, env=sonar_env())
    if code != 0:
        return [], f'scanner failed: {clean_error(stderr or stdout)}'
    try:
        issues = fetch_sonar_issues(host, token, project_key)
    except Exception as exc:
        return [], f'scan ok, issue fetch failed: {exc}'
    return [finding_from_sonar(issue) for issue in issues], 'ok'


def fetch_sonar_issues(host: str, token: str, project_key: str) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode({'componentKeys': project_key, 'types': 'VULNERABILITY,SECURITY_HOTSPOT,BUG', 'ps': 500})
    req = urllib.request.Request(f'{host.rstrip("/")}/api/issues/search?{query}')
    req.add_header('Authorization', 'Basic ' + basic_token(token))
    with urllib.request.urlopen(req, timeout=45) as response:
        payload = json.loads(response.read().decode('utf-8'))
    return payload.get('issues', [])


def basic_token(token: str) -> str:
    import base64
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


def sonar_env() -> dict[str, str]:
    env = os.environ.copy()
    configured = os.getenv('SONAR_JAVA_HOME') or os.getenv('JAVA_HOME')
    if configured and (Path(configured) / 'bin' / 'java.exe').exists():
        env['JAVA_HOME'] = configured
    elif DEFAULT_JAVA_HOME.exists():
        env['JAVA_HOME'] = str(DEFAULT_JAVA_HOME)
    return env
