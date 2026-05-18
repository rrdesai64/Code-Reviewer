from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Finding, FixSuggestion, Location, ScanResult

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / 'data' / 'secrets'

EXCLUDED_DIRS = {
    '.git', '.hg', '.svn', '.venv', 'venv', 'env', 'node_modules', 'dist', 'build', '__pycache__',
    '.mypy_cache', '.pytest_cache', '.ruff_cache', 'data', 'tools', 'vendor', 'coverage', '.idea', '.vscode',
}
TEXT_EXTENSIONS = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rs', '.rb', '.php', '.cs', '.cpp', '.c', '.h',
    '.yml', '.yaml', '.json', '.toml', '.ini', '.cfg', '.conf', '.properties', '.env', '.txt', '.md', '.ps1',
    '.sh', '.bash', '.zsh', '.sql', '.tf', '.tfvars', '.gradle', '.xml', '.html', '.css', '.dockerfile',
}
SENSITIVE_NAMES = {
    '.env', '.env.local', '.env.production', '.env.development', '.npmrc', '.pypirc', '.netrc', '.dockercfg',
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
    'credentials', 'credentials.json', 'secrets.yml', 'secrets.yaml', 'config.yml', 'config.yaml',
}
PLACEHOLDER_MARKERS = (
    'example', 'sample', 'dummy', 'placeholder', 'changeme', 'change-me', 'replace-with', 'redacted',
    'your-', '<', '>', 'xxxx', 'todo', 'optional', 'none', 'null', 'false', 'true', 'client-id', 'client-secret',
)
SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
SECRET_SOURCES = {'secret-scan', 'gitleaks', 'trufflehog'}


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    title: str
    pattern: re.Pattern[str]
    severity: str = 'HIGH'
    confidence: str = 'HIGH'
    value_group: str | None = None
    cwe: tuple[str, ...] = ('CWE-798',)
    owasp: tuple[str, ...] = ('A02:2021-Cryptographic Failures',)


SECRET_RULES = [
    SecretRule(
        'aws-access-key-id', 'AWS access key ID',
        re.compile(r'\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b'), 'CRITICAL', 'HIGH', None,
    ),
    SecretRule(
        'github-token', 'GitHub token',
        re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9_]{59,}\b'),
        'CRITICAL', 'HIGH', None,
    ),
    SecretRule(
        'slack-token', 'Slack token',
        re.compile(r'\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{20,}\b'), 'CRITICAL', 'HIGH', None,
    ),
    SecretRule(
        'stripe-live-secret', 'Stripe live secret key',
        re.compile(r'\bsk_live_[A-Za-z0-9]{20,}\b'), 'CRITICAL', 'HIGH', None,
    ),
    SecretRule(
        'private-key-material', 'Private key material',
        re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'), 'CRITICAL', 'HIGH', None,
    ),
    SecretRule(
        'jwt-token', 'JWT token',
        re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'), 'HIGH', 'MEDIUM', None,
    ),
    SecretRule(
        'database-url-with-credentials', 'Database URL with inline credentials',
        re.compile(r'\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s:/@]+:[^\s/@]+@[^\s]+', re.I),
        'HIGH', 'HIGH', None,
    ),
    SecretRule(
        'generic-secret-assignment', 'Hardcoded secret assignment',
        re.compile(
            r'''(?ix)
            \b(?P<key>
                api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|private[_-]?key|
                access[_-]?token|refresh[_-]?token|auth[_-]?token|connection[_-]?string
            )\b
            \s*[:=]\s*
            ["']?(?P<value>[A-Za-z0-9_./+=:@%,$!\\-]{12,})["']?
            '''
        ),
        'HIGH', 'MEDIUM', 'value',
    ),
]


def run_secret_scan(target: Path, source_files: list[Path] | None = None) -> tuple[list[Finding], dict[str, str]]:
    enabled = os.getenv('SECRET_SCAN_ENABLED', 'true').lower()
    if enabled in {'false', '0', 'no', 'off'}:
        return [], {'secret-scan': 'disabled by SECRET_SCAN_ENABLED=false'}

    candidates = list(secret_candidate_files(target, source_files or []))
    findings, builtin_status = run_builtin_secret_scan(target, candidates)
    statuses = {'secret-scan': builtin_status}

    external_enabled = os.getenv('SECRET_SCAN_EXTERNAL_ENABLED', 'auto').lower()
    if external_enabled not in {'false', '0', 'no', 'off'}:
        gitleaks_findings, gitleaks_status = run_gitleaks(target)
        findings.extend(gitleaks_findings)
        statuses['gitleaks'] = gitleaks_status

        trufflehog_findings, trufflehog_status = run_trufflehog(target)
        findings.extend(trufflehog_findings)
        statuses['trufflehog'] = trufflehog_status
    else:
        statuses['gitleaks'] = 'disabled by SECRET_SCAN_EXTERNAL_ENABLED=false'
        statuses['trufflehog'] = 'disabled by SECRET_SCAN_EXTERNAL_ENABLED=false'

    return findings, statuses


def run_builtin_secret_scan(target: Path, files: list[Path]) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    scanned = 0
    skipped = 0
    max_bytes = int(os.getenv('SECRET_SCAN_MAX_FILE_BYTES', '1048576'))
    for path in files:
        try:
            if path.stat().st_size > max_bytes:
                skipped += 1
                continue
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            skipped += 1
            continue
        scanned += 1
        findings.extend(scan_text_for_secrets(target, path, text))
    status = f'ok: scanned {scanned} files'
    if skipped:
        status += f', skipped {skipped} large/unreadable files'
    return findings, status


def scan_text_for_secrets(target: Path, path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            value = match.group(rule.value_group) if rule.value_group else match.group(0)
            if should_ignore_secret(value):
                continue
            line, column = position_for_index(text, match.start())
            findings.append(secret_finding(target, path, rule, line, column, value))
    return findings


def secret_candidate_files(target: Path, source_files: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    candidates: list[Path] = []

    def add(path: Path) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            return
        if resolved in seen or not path.is_file() or is_excluded(path):
            return
        if is_secret_candidate(path):
            seen.add(resolved)
            candidates.append(path)

    for path in source_files:
        add(path)
    try:
        iterator = target.rglob('*')
        for path in iterator:
            add(path)
    except OSError:
        pass
    return sorted(candidates, key=lambda item: str(item).lower())


def is_secret_candidate(path: Path) -> bool:
    name = path.name
    lower_name = name.lower()
    suffix = path.suffix.lower()
    if name in SENSITIVE_NAMES or lower_name.startswith('.env'):
        return True
    if suffix in TEXT_EXTENSIONS:
        return True
    return any(marker in lower_name for marker in ('secret', 'credential', 'token', 'password', 'apikey', 'api-key'))


def is_excluded(path: Path) -> bool:
    lowered_parts = {part.lower() for part in path.parts}
    return bool(lowered_parts & EXCLUDED_DIRS)


def should_ignore_secret(value: str) -> bool:
    clean = value.strip().strip('"\'` ,;')
    lower = clean.lower()
    if len(clean) < 12:
        return True
    if any(marker in lower for marker in PLACEHOLDER_MARKERS):
        return True
    if lower.startswith(('http://localhost', 'https://localhost', 'http://127.0.0.1', 'https://127.0.0.1')):
        return True
    if '${' in clean or '$(' in clean or '%{' in clean:
        return True
    if len(set(clean)) < 5:
        return True
    return False


def secret_finding(target: Path, path: Path, rule: SecretRule, line: int, column: int, value: str) -> Finding:
    rel = relpath(path, target)
    secret_hash = hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]
    message = f'Potential {rule.title.lower()} detected. Secret value is redacted.'
    fingerprint = make_fingerprint('secret-scan', rule.rule_id, rel, line, secret_hash)
    return Finding(
        id=fingerprint[:16], source='secret-scan', rule_id=rule.rule_id, title=rule.title,
        severity=rule.severity, confidence=rule.confidence, location=Location(path=rel, line=line, column=column),
        message=message, cwe=list(rule.cwe), owasp=list(rule.owasp), references=['https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'],
        explanation='Hardcoded credentials can be copied from source history, build logs, packaged artifacts, or review tools. Treat committed secrets as exposed even after deletion.',
        fix=secret_fix(), fingerprint=fingerprint,
    )


def secret_fix() -> FixSuggestion:
    return FixSuggestion(
        summary='Rotate the exposed credential, remove it from source, and load it from an approved secret store or runtime environment.',
        guidance=[
            'Revoke or rotate the credential before merging or deploying.',
            'Move the value to a secret manager, CI secret, vault, or protected environment variable.',
            'Purge the value from repository history when exposure is confirmed.',
            'Add a regression rule or allowlisted test fixture only if this is a verified false positive.',
        ],
    )


def run_gitleaks(target: Path) -> tuple[list[Finding], str]:
    enabled = os.getenv('GITLEAKS_ENABLED', 'auto').lower()
    if enabled in {'false', '0', 'no', 'off'}:
        return [], 'disabled by GITLEAKS_ENABLED=false'
    exe = os.getenv('GITLEAKS_EXE') or shutil.which('gitleaks')
    if not exe:
        return [], 'not installed'
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    report = DATA_DIR / f'gitleaks-{uuid.uuid4().hex[:8]}.json'
    timeout = int(os.getenv('GITLEAKS_TIMEOUT_SECONDS', '180'))
    command = [exe, 'detect', '--source', str(target), '--report-format', 'json', '--report-path', str(report), '--redact', '--no-banner']
    code, stdout, stderr = run_tool(command, ROOT, timeout=timeout)
    payload = load_json_report(report, stdout)
    if payload is None:
        if code in (0, 1):
            return [], 'ok'
        return [], f'error: {clean_error(stderr or stdout or str(code))}'
    findings = [finding_from_gitleaks(item, target) for item in payload if isinstance(item, dict)]
    status = 'ok' if code in (0, 1) else f'partial: {clean_error(stderr or stdout or str(code))}'
    return findings, status


def run_trufflehog(target: Path) -> tuple[list[Finding], str]:
    enabled = os.getenv('TRUFFLEHOG_ENABLED', 'auto').lower()
    if enabled in {'false', '0', 'no', 'off'}:
        return [], 'disabled by TRUFFLEHOG_ENABLED=false'
    exe = os.getenv('TRUFFLEHOG_EXE') or shutil.which('trufflehog')
    if not exe:
        return [], 'not installed'
    timeout = int(os.getenv('TRUFFLEHOG_TIMEOUT_SECONDS', '180'))
    command = [exe, 'filesystem', '--json', '--no-update', str(target)]
    code, stdout, stderr = run_tool(command, ROOT, timeout=timeout)
    findings = [finding_from_trufflehog(item, target) for item in parse_json_lines(stdout)]
    if findings or code == 0:
        return findings, 'ok'
    return findings, f'partial: {clean_error(stderr or stdout or str(code))}'


def finding_from_gitleaks(item: dict[str, Any], target: Path) -> Finding:
    path = relpath(Path(str(item.get('File') or item.get('file') or '')), target)
    line = int(item.get('StartLine') or item.get('Line') or 1)
    rule = str(item.get('RuleID') or item.get('Rule') or 'gitleaks-secret')
    description = str(item.get('Description') or item.get('Match') or rule)
    fingerprint = make_fingerprint('gitleaks', rule, path, line, description)
    return Finding(
        id=fingerprint[:16], source='gitleaks', rule_id=rule, title=f'Gitleaks: {title_from_rule(rule)}',
        severity='HIGH', confidence='HIGH', location=Location(path=path, line=line),
        message='Gitleaks detected a potential committed secret. Secret value is redacted.',
        cwe=['CWE-798'], owasp=['A02:2021-Cryptographic Failures'], references=[],
        explanation='External secret scanning found a credential-like value in the repository content or history.',
        fix=secret_fix(), fingerprint=fingerprint,
    )


def finding_from_trufflehog(item: dict[str, Any], target: Path) -> Finding:
    source_metadata = item.get('SourceMetadata', {}) if isinstance(item.get('SourceMetadata'), dict) else {}
    data = source_metadata.get('Data', {}) if isinstance(source_metadata.get('Data'), dict) else {}
    filesystem = data.get('Filesystem', {}) if isinstance(data.get('Filesystem'), dict) else {}
    path = relpath(Path(str(filesystem.get('file') or filesystem.get('File') or item.get('SourceName') or '')), target)
    line = int(filesystem.get('line') or filesystem.get('Line') or 1)
    detector = str(item.get('DetectorName') or item.get('DetectorType') or 'trufflehog-secret')
    verified = bool(item.get('Verified'))
    fingerprint = make_fingerprint('trufflehog', detector, path, line, str(item.get('RawV2') or item.get('Redacted') or verified))
    return Finding(
        id=fingerprint[:16], source='trufflehog', rule_id=detector, title=f'TruffleHog: {title_from_rule(detector)}',
        severity='CRITICAL' if verified else 'HIGH', confidence='HIGH' if verified else 'MEDIUM',
        location=Location(path=path, line=line),
        message='TruffleHog detected a potential secret. Secret value is redacted.',
        cwe=['CWE-798'], owasp=['A02:2021-Cryptographic Failures'], references=[],
        explanation='External secret scanning found a credential-like value. Verified secrets should be treated as confirmed exposure.',
        fix=secret_fix(), fingerprint=fingerprint,
    )


def secret_policy_report(scan: ScanResult) -> dict[str, Any]:
    threshold = os.getenv('SECRET_POLICY_BLOCK_SEVERITY', 'HIGH').upper()
    if threshold not in SEVERITY_ORDER:
        threshold = 'HIGH'
    push_protection = os.getenv('PUSH_PROTECTION_ENABLED', 'true').lower() not in {'false', '0', 'no', 'off'}
    secret_findings = [finding for finding in scan.findings if is_secret_finding(finding)]
    open_findings = [finding for finding in secret_findings if finding.decision == 'open']
    blockers = [finding for finding in open_findings if SEVERITY_ORDER.get(finding.severity, 0) >= SEVERITY_ORDER[threshold]]
    status = 'blocked' if push_protection and blockers else 'passed'
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'status': status,
        'push_protection_enabled': push_protection,
        'blocking_threshold': threshold,
        'total_secret_findings': len(secret_findings),
        'open_secret_findings': len(open_findings),
        'blocking_findings': len(blockers),
        'tools': {key: value for key, value in scan.summary.tools.items() if key in {'secret-scan', 'gitleaks', 'trufflehog'}},
        'findings': [policy_finding_summary(finding) for finding in secret_findings],
        'blocking': [policy_finding_summary(finding) for finding in blockers],
        'guidance': [
            'Block merges when high or critical secrets are open.',
            'Rotate leaked credentials before marking a finding fixed or risk-accepted.',
            'Use CLI --fail-on-secrets in pre-push or CI workflows for push protection.',
        ],
    }


def is_secret_finding(finding: Finding) -> bool:
    return finding.source in SECRET_SOURCES or 'secret' in finding.rule_id.lower() or 'token' in finding.rule_id.lower()


def policy_finding_summary(finding: Finding) -> dict[str, Any]:
    return {
        'id': finding.id,
        'source': finding.source,
        'rule_id': finding.rule_id,
        'title': finding.title,
        'severity': finding.severity,
        'risk_score': finding.risk.score,
        'priority': finding.risk.priority,
        'location': {'path': finding.location.path, 'line': finding.location.line, 'column': finding.location.column},
        'decision': finding.decision,
        'message': finding.message,
    }


def position_for_index(text: str, index: int) -> tuple[int, int]:
    line = text.count('\n', 0, index) + 1
    last_newline = text.rfind('\n', 0, index)
    column = index + 1 if last_newline == -1 else index - last_newline
    return line, column


def run_tool(command: list[str], cwd: Path, timeout: int = 180) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(command, cwd=str(cwd), text=True, capture_output=True, timeout=timeout)
        return completed.returncode, completed.stdout, completed.stderr
    except FileNotFoundError as exc:
        return 127, '', str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or '', exc.stderr or 'tool timed out'


def load_json_report(path: Path, stdout: str) -> list[dict[str, Any]] | None:
    raw = path.read_text(encoding='utf-8', errors='ignore') if path.exists() else stdout
    if not raw.strip():
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, list) else None


def parse_json_lines(stdout: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            items.append(payload)
    return items


def make_fingerprint(source: str, rule_id: str, path: str, line: int, message: str) -> str:
    raw = f'{source}|{rule_id}|{path.replace(os.sep, "/")}|{line}|{message}'
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def title_from_rule(rule_id: str) -> str:
    return rule_id.replace('_', '-').replace('.', '-').replace(':', '-').split('/')[-1].replace('-', ' ').title()


def relpath(path: Path, target: Path) -> str:
    try:
        return str(path.resolve().relative_to(target.resolve())).replace('\\', '/')
    except Exception:
        return str(path).replace('\\', '/')


def clean_error(text: str) -> str:
    return ' '.join((text or '').split())[:500]
