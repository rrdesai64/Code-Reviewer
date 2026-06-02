from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .consolidation import ensure_consolidated_scan
from .ingestion import enrich_finding, findings_from_sarif_payload, normalize_finding
from .models import DastScanRequest, DynamicEvidence, Finding, Location, ScanResult
from .priority import apply_priority_scoring
from .risk import score_scan
from .runtime_smoke import allowed_base_url
from .scope import apply_finding_scope, normalize_path
from .soundness import soundness_verdict

SCHEMA_VERSION = 'dast-verification-v1'
PHASE = '4'
MAX_EXCERPT = 500
ROUTE_SCAN_SUFFIXES = {'.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.kt', '.rb', '.php'}
EXCLUDED_DIRS = {'.git', '.venv', 'venv', 'node_modules', 'dist', 'build', 'target', '__pycache__'}


def dast_status() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'phase': PHASE,
        'generated_at': now_iso(),
        'providers': {
            'zap': {
                'available': bool(zap_executable()),
                'executable': zap_executable() or '',
                'mode': 'baseline-json',
            },
            'nuclei': {
                'available': bool(shutil.which('nuclei')),
                'executable': shutil.which('nuclei') or '',
                'mode': 'jsonl',
            },
            'sarif-ingest': {'available': True, 'mode': 'report-ingest'},
        },
        'guardrails': dast_guardrails(),
    }


def dast_verification_report(scan: ScanResult, request: DastScanRequest | None = None) -> dict[str, Any]:
    request = request or DastScanRequest()
    run_result = run_dast_tools(request) if request.run_tools else run_preview(request)
    report_paths = [*request.report_paths, *run_result.get('artifacts', [])]
    report_findings, parse_errors = ingest_dast_reports(scan, [Path(path) for path in report_paths])
    augmented = augment_scan_with_dast(scan, report_findings)
    verdict = soundness_verdict(augmented)
    gate = dast_gate(verdict, report_findings)
    return {
        'schema_version': SCHEMA_VERSION,
        'phase': PHASE,
        'generated_at': now_iso(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'status': gate['status'],
        'summary': {
            'dast_finding_count': len(report_findings),
            'mapped_finding_count': sum(1 for finding in report_findings if not finding.location.path.startswith('[endpoint] ')),
            'endpoint_level_finding_count': sum(1 for finding in report_findings if finding.location.path.startswith('[endpoint] ')),
            'confirmed_exploitable_count': sum(1 for finding in report_findings if finding.dataflow.confirmed_exploitable),
            'blocking_issue_count': gate['blocking_issue_count'],
            'parse_error_count': len(parse_errors),
        },
        'policy': {
            'purpose': 'outside-in-security-verification-gate-and-feedback',
            'dast_used_for_autofix': False,
            'normal_scan_runs_tools': False,
            'run_mode_requires_loopback_or_explicit_remote_allow': True,
            'endpoint_mapping_is_best_effort': True,
            'wrong_mapping_worse_than_unmapped': True,
        },
        'run': run_result,
        'inputs': {
            'report_paths': [str(path) for path in report_paths],
            'base_url': redact_url(request.base_url or ''),
            'tool': request.tool,
            'run_tools': request.run_tools,
        },
        'findings': [dast_finding_record(finding) for finding in report_findings],
        'gate': gate,
        'soundness': {
            'schema_version': verdict['schema_version'],
            'verdict': verdict['verdict'],
            'top_issue': verdict['issues'][0] if verdict['issues'] else None,
            'dast_issue_count': sum(1 for issue in verdict.get('issues', []) if issue_has_dast(issue)),
        },
        'parse_errors': parse_errors,
        'guardrails': dast_guardrails(),
    }


def ingest_dast_reports(scan: ScanResult, paths: list[Path]) -> tuple[list[Finding], list[dict[str, str]]]:
    resolver = EndpointResolver(Path(scan.target_path))
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []
    for path in paths:
        if not path.exists():
            errors.append({'path': str(path), 'error': 'report file not found'})
            continue
        try:
            findings.extend(parse_dast_report(path, resolver))
        except Exception as exc:
            errors.append({'path': str(path), 'error': str(exc)[:500]})
    return findings, errors


def parse_dast_report(path: Path, resolver: 'EndpointResolver') -> list[Finding]:
    text = path.read_text(encoding='utf-8', errors='ignore')
    stripped = text.lstrip()
    if not stripped:
        return []
    if path.suffix.lower() in {'.sarif'} or '"runs"' in stripped[:500] and '"version"' in stripped[:500]:
        payload = json.loads(text)
        return dast_from_sarif(payload, resolver)
    if path.suffix.lower() in {'.jsonl', '.ndjson'}:
        return findings_from_nuclei_jsonl(text, resolver)
    payload = json.loads(text)
    if looks_like_zap(payload):
        return findings_from_zap(payload, resolver)
    if isinstance(payload, list) or looks_like_nuclei(payload):
        return findings_from_nuclei_payload(payload, resolver)
    if isinstance(payload, dict) and 'runs' in payload:
        return dast_from_sarif(payload, resolver)
    return []


def findings_from_zap(payload: dict[str, Any], resolver: 'EndpointResolver') -> list[Finding]:
    alerts = zap_alerts(payload)
    findings: list[Finding] = []
    for alert in alerts:
        instances = alert.get('instances') if isinstance(alert.get('instances'), list) else []
        if not instances:
            instances = [alert]
        for instance in instances:
            url = str(instance.get('uri') or instance.get('url') or alert.get('url') or '')
            if not url:
                continue
            method = str(instance.get('method') or alert.get('method') or 'GET').upper()
            param = str(instance.get('param') or alert.get('param') or '') or None
            cweid = str(alert.get('cweid') or alert.get('cweId') or '')
            cwe = [f'CWE-{cweid}'] if cweid and cweid != '-1' else []
            dynamic = DynamicEvidence(
                method=method,
                url=redact_url(url),
                param=param,
                payload=excerpt(instance.get('attack') or alert.get('attack')),
                request_excerpt=excerpt(instance.get('requestHeader') or instance.get('requestBody') or alert.get('requestHeader')),
                response_excerpt=excerpt(instance.get('evidence') or instance.get('responseBody') or alert.get('evidence')),
                status_code=safe_int(instance.get('statusCode') or alert.get('statusCode')),
                tool='zap',
            )
            finding = dast_finding(
                tool='zap',
                rule_id=str(alert.get('pluginid') or alert.get('pluginId') or alert.get('alertRef') or 'zap-alert'),
                title=str(alert.get('alert') or alert.get('name') or 'ZAP alert'),
                severity=zap_severity(alert.get('risk') or alert.get('riskdesc') or alert.get('riskcode')),
                confidence=alert.get('confidence') or 'MEDIUM',
                message=str(alert.get('desc') or alert.get('description') or alert.get('alert') or 'ZAP dynamic finding'),
                cwe=cwe,
                references=zap_references(alert),
                dynamic=dynamic,
                resolver=resolver,
            )
            findings.append(finding)
    return findings


def findings_from_nuclei_jsonl(text: str, resolver: 'EndpointResolver') -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        findings.extend(findings_from_nuclei_payload(json.loads(line), resolver))
    return findings


def findings_from_nuclei_payload(payload: Any, resolver: 'EndpointResolver') -> list[Finding]:
    items = payload if isinstance(payload, list) else [payload]
    findings: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        info = item.get('info') if isinstance(item.get('info'), dict) else {}
        url = str(item.get('matched-at') or item.get('url') or item.get('host') or '')
        if not url:
            continue
        method = request_method(item.get('request')) or str(item.get('method') or 'GET').upper()
        dynamic = DynamicEvidence(
            method=method,
            url=redact_url(url),
            param=str(item.get('matcher-name') or '') or None,
            payload=excerpt(item.get('extracted-results')),
            request_excerpt=excerpt(item.get('request')),
            response_excerpt=excerpt(item.get('response')),
            status_code=safe_int(item.get('status-code') or item.get('status_code')),
            tool='nuclei',
        )
        cwe = info.get('classification', {}).get('cwe-id') if isinstance(info.get('classification'), dict) else []
        finding = dast_finding(
            tool='nuclei',
            rule_id=str(item.get('template-id') or item.get('templateID') or 'nuclei-template'),
            title=str(info.get('name') or item.get('template-id') or 'Nuclei finding'),
            severity=info.get('severity') or item.get('severity') or 'INFO',
            confidence='HIGH',
            message=str(info.get('description') or info.get('name') or item.get('matcher-name') or 'Nuclei dynamic finding'),
            cwe=cwe,
            references=info.get('reference') or info.get('references') or [],
            dynamic=dynamic,
            resolver=resolver,
        )
        findings.append(finding)
    return findings


def dast_from_sarif(payload: dict[str, Any], resolver: 'EndpointResolver') -> list[Finding]:
    findings = findings_from_sarif_payload(payload, source='dast:sarif', metadata={'engine': 'sarif-dast'})
    for finding in findings:
        props = sarif_result_properties(payload, finding.rule_id, finding.message)
        url = str(props.get('url') or props.get('uri') or props.get('matched-at') or '')
        method = str(props.get('method') or 'GET').upper()
        if url:
            finding.dynamic = DynamicEvidence(
                method=method,
                url=redact_url(url),
                param=str(props.get('param') or '') or None,
                payload=excerpt(props.get('payload')),
                request_excerpt=excerpt(props.get('request') or props.get('requestExcerpt')),
                response_excerpt=excerpt(props.get('response') or props.get('responseExcerpt')),
                status_code=safe_int(props.get('status_code') or props.get('statusCode')),
                tool='sarif',
            )
            apply_resolved_location(finding, resolver.resolve(method, url), method, url)
        mark_dynamic(finding, 'sarif')
    return findings


def dast_finding(
    *,
    tool: str,
    rule_id: str,
    title: str,
    severity: Any,
    confidence: Any,
    message: str,
    cwe: Any,
    references: Any,
    dynamic: DynamicEvidence,
    resolver: 'EndpointResolver',
) -> Finding:
    resolved = resolver.resolve(dynamic.method, dynamic.url)
    path, line = endpoint_location(dynamic.method, dynamic.url)
    if resolved:
        path, line = resolved.path, resolved.line
    finding = normalize_finding(
        source=f'dast:{tool}',
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        path=path,
        line=line,
        message=message,
        cwe=cwe,
        references=references,
        metadata={
            'engine': tool,
            'dast_tool': tool,
            'dast_confirmed_exploitable': 'true',
            'dast_method': dynamic.method,
            'dast_url': dynamic.url,
            'dast_param': dynamic.param or '',
            'dast_mapping': 'resolved' if resolved else 'endpoint',
        },
    )
    finding.dynamic = dynamic
    apply_resolved_location(finding, resolved, dynamic.method, dynamic.url)
    mark_dynamic(finding, tool)
    return finding


def augment_scan_with_dast(scan: ScanResult, findings: list[Finding]) -> ScanResult:
    data = scan.model_dump(mode='json')
    augmented = ScanResult.model_validate(data)
    augmented.findings.extend(findings)
    augmented.findings = [apply_finding_scope(enrich_finding(finding)) for finding in augmented.findings]
    augmented.summary.tools = {**augmented.summary.tools}
    if findings:
        augmented.summary.tools['dast'] = f'ingested findings={len(findings)}'
    augmented = score_scan(augmented)
    augmented = ensure_consolidated_scan(augmented)
    return apply_priority_scoring(augmented)


def run_dast_tools(request: DastScanRequest) -> dict[str, Any]:
    blockers = run_blockers(request)
    if blockers:
        return {'mode': 'run', 'status': 'blocked', 'blockers': blockers, 'commands': dast_commands(request), 'artifacts': []}
    commands = dast_commands(request)
    artifacts: list[str] = []
    errors: list[str] = []
    for command in commands:
        output = command.get('output')
        try:
            completed = subprocess.run(command['argv'], text=True, encoding='utf-8', errors='replace', capture_output=True, timeout=request.timeout_seconds)
            if completed.returncode not in {0, 1, 2}:
                errors.append(f"{command['tool']} exited {completed.returncode}: {completed.stderr[:300]}")
            if output:
                artifacts.append(str(output))
        except Exception as exc:
            errors.append(f"{command['tool']} failed: {exc}")
    return {'mode': 'run', 'status': 'completed' if not errors else 'partial', 'blockers': [], 'commands': commands, 'artifacts': artifacts, 'errors': errors}


def run_preview(request: DastScanRequest) -> dict[str, Any]:
    status = 'report_ingest_requested' if request.report_paths else 'not_run'
    return {'mode': 'ingest', 'status': status, 'blockers': [], 'commands': dast_commands(request), 'artifacts': []}


def run_blockers(request: DastScanRequest) -> list[str]:
    blockers: list[str] = []
    if not request.base_url:
        blockers.append('run mode requires base_url from the Phase 3 sandboxed runtime')
    elif not allowed_base_url(request.base_url, allow_remote=request.allow_remote_base_url):
        blockers.append('DAST run target must be loopback/private unless allow_remote_base_url=true')
    if request.require_sandbox_running:
        blockers.append('run mode requires Phase 3 sandbox evidence or --dast-no-sandbox-required')
    if not dast_commands(request):
        blockers.append('requested DAST tool is not installed or available on PATH')
    return blockers


def dast_commands(request: DastScanRequest) -> list[dict[str, Any]]:
    if not request.base_url:
        return []
    commands: list[dict[str, Any]] = []
    if request.tool in {'auto', 'nuclei'} and shutil.which('nuclei'):
        output = Path('nuclei-dast.jsonl').resolve()
        commands.append({'tool': 'nuclei', 'argv': ['nuclei', '-u', request.base_url, '-jsonl', '-silent', '-o', str(output)], 'output': str(output)})
    zap = zap_executable()
    if request.tool in {'auto', 'zap'} and zap:
        output = Path('zap-dast.json').resolve()
        if Path(zap).name.startswith('zap-baseline'):
            argv = [zap, '-t', request.base_url, '-J', str(output), '-I']
        else:
            argv = [zap, '-cmd', '-quickurl', request.base_url, '-quickout', str(output)]
        commands.append({'tool': 'zap', 'argv': argv, 'output': str(output)})
    return commands


class EndpointResolver:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.routes = discover_routes(self.root)

    def resolve(self, method: str, url: str) -> Location | None:
        route_path = normalize_route_path(urllib.parse.urlparse(url).path or '/')
        method = str(method or 'GET').upper()
        for route in self.routes:
            if method not in route['methods'] and 'ANY' not in route['methods']:
                continue
            if route_matches(route['route'], route_path):
                return Location(path=route['path'], line=route['line'], column=1)
        return heuristic_route_search(self.root, route_path)


def discover_routes(root: Path) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for path in limited_source_files(root):
        rel = relative_path(root, path)
        text = read_text(path)
        for line_no, line in enumerate(text.splitlines(), 1):
            routes.extend(route_records_from_line(line, rel, line_no))
    return routes


def route_records_from_line(line: str, rel: str, line_no: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for match in re.finditer(r'@\w+\.(get|post|put|patch|delete|route)\(\s*[\'"]([^\'"]+)', line, re.I):
        method = match.group(1).upper()
        records.append({'route': normalize_route_path(match.group(2)), 'methods': ['ANY' if method == 'ROUTE' else method], 'path': rel, 'line': line_no})
    for match in re.finditer(r'\b(?:app|router)\.(get|post|put|patch|delete|all|use)\(\s*[\'"]([^\'"]+)', line, re.I):
        method = match.group(1).upper()
        records.append({'route': normalize_route_path(match.group(2)), 'methods': ['ANY' if method in {'ALL', 'USE'} else method], 'path': rel, 'line': line_no})
    for match in re.finditer(r'@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?[\'"]([^\'"]+)', line):
        method = {'GetMapping': 'GET', 'PostMapping': 'POST', 'PutMapping': 'PUT', 'PatchMapping': 'PATCH', 'DeleteMapping': 'DELETE'}.get(match.group(1), 'ANY')
        records.append({'route': normalize_route_path(match.group(2)), 'methods': [method], 'path': rel, 'line': line_no})
    for match in re.finditer(r'\b(get|post|put|patch|delete)\s+[\'"]([^\'"]+)', line, re.I):
        records.append({'route': normalize_route_path(match.group(2)), 'methods': [match.group(1).upper()], 'path': rel, 'line': line_no})
    return records


def heuristic_route_search(root: Path, route_path: str) -> Location | None:
    if route_path in {'', '/'}:
        return None
    literal = route_path.rstrip('/') or '/'
    for path in limited_source_files(root):
        rel = relative_path(root, path)
        for line_no, line in enumerate(read_text(path).splitlines(), 1):
            if literal in line:
                return Location(path=rel, line=line_no, column=max(1, line.find(literal) + 1))
    return None


def limited_source_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    result: list[Path] = []
    for path in root.rglob('*'):
        if len(result) >= 2000:
            break
        if not path.is_file() or path.suffix.lower() not in ROUTE_SCAN_SUFFIXES:
            continue
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            rel_parts = path.parts
        if any(part in EXCLUDED_DIRS for part in rel_parts):
            continue
        result.append(path)
    return sorted(result)


def apply_resolved_location(finding: Finding, resolved: Location | None, method: str, url: str) -> None:
    if resolved:
        finding.location = resolved
        finding.scope = 'production'
        finding.scanner_metadata['dast_mapping'] = 'resolved'
    else:
        path, line = endpoint_location(method, url)
        finding.location = Location(path=path, line=line, column=1)
        finding.scope = 'endpoint'
        finding.scanner_metadata['dast_mapping'] = 'endpoint'
        finding.scanner_metadata['scope'] = 'endpoint'
    finding.priority_context.path_class = finding.scope


def mark_dynamic(finding: Finding, tool: str) -> None:
    finding.source = finding.source if finding.source.startswith('dast:') else f'dast:{tool}'
    finding.dataflow.confirmed_exploitable = True
    finding.reachability = 'dynamic-confirmed'
    finding.exploitability = 'confirmed-exploitable'
    finding.scanner_metadata['dast_confirmed_exploitable'] = 'true'
    finding.scanner_metadata['scanner_family'] = 'dast'
    finding.scanner_metadata['scanner_source'] = finding.source


def dast_gate(verdict: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
    dast_issues = [issue for issue in verdict.get('issues', []) if issue_has_dast(issue)]
    blocking = [issue for issue in dast_issues if (issue.get('gate') or {}).get('effect') == 'block']
    return {
        'status': 'block' if blocking else 'pass',
        'blocking_issue_count': len(blocking),
        'confirmed_issue_count': len(dast_issues),
        'finding_count': len(findings),
        'reason_codes': sorted({reason for issue in blocking for reason in (issue.get('gate') or {}).get('reason_codes', [])}),
        'proof_attached': any(issue.get('evidence', {}).get('dynamic') for issue in blocking),
        'autofix_allowed': False,
    }


def issue_has_dast(issue: dict[str, Any]) -> bool:
    return any(str(source).startswith('dast:') for source in (issue.get('evidence') or {}).get('sources', []))


def dast_finding_record(finding: Finding) -> dict[str, Any]:
    return {
        'finding_id': finding.id,
        'source': finding.source,
        'rule_id': finding.rule_id,
        'title': finding.title,
        'severity': finding.severity,
        'confidence': finding.confidence,
        'location': finding.location.model_dump(mode='json'),
        'scope': finding.scope,
        'cwe': finding.cwe,
        'dynamic': finding.dynamic.model_dump(mode='json') if finding.dynamic else None,
        'confirmed_exploitable': finding.dataflow.confirmed_exploitable,
        'mapping': finding.scanner_metadata.get('dast_mapping', ''),
    }


def zap_alerts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(payload.get('alerts'), list):
        return payload['alerts']
    alerts: list[dict[str, Any]] = []
    for site in payload.get('site', []) or []:
        if isinstance(site, dict):
            alerts.extend(item for item in site.get('alerts', []) or [] if isinstance(item, dict))
    return alerts


def looks_like_zap(payload: Any) -> bool:
    return isinstance(payload, dict) and ('alerts' in payload or 'site' in payload)


def looks_like_nuclei(payload: Any) -> bool:
    return isinstance(payload, dict) and ('template-id' in payload or 'templateID' in payload or 'matched-at' in payload)


def zap_severity(value: Any) -> str:
    text = str(value or '').lower()
    if 'critical' in text:
        return 'CRITICAL'
    if 'high' in text or text == '3':
        return 'HIGH'
    if 'medium' in text or text == '2':
        return 'MEDIUM'
    if 'low' in text or text == '1':
        return 'LOW'
    return 'INFO'


def zap_references(alert: dict[str, Any]) -> list[str]:
    values = []
    for key in ('reference', 'references', 'solution'):
        value = alert.get(key)
        if isinstance(value, list):
            values.extend(str(item) for item in value if item)
        elif value:
            values.append(str(value))
    return values


def sarif_result_properties(payload: dict[str, Any], rule_id: str, message: str) -> dict[str, Any]:
    for run in payload.get('runs', []) or []:
        for result in run.get('results', []) or []:
            if str(result.get('ruleId') or '') == rule_id or message in json.dumps(result):
                props = result.get('properties') if isinstance(result.get('properties'), dict) else {}
                return props
    return {}


def endpoint_location(method: str, url: str) -> tuple[str, int]:
    return f'[endpoint] {str(method or "GET").upper()} {redact_url(url)}', 0


def route_matches(pattern: str, route_path: str) -> bool:
    if pattern == route_path:
        return True
    left = [part for part in pattern.strip('/').split('/') if part]
    right = [part for part in route_path.strip('/').split('/') if part]
    if len(left) != len(right):
        return False
    for expected, actual in zip(left, right):
        if expected.startswith(':') or expected.startswith('{') and expected.endswith('}') or expected.startswith('<') and expected.endswith('>'):
            continue
        if expected != actual:
            return False
    return True


def normalize_route_path(value: str) -> str:
    text = str(value or '/').strip()
    if not text.startswith('/'):
        text = '/' + text
    return text.rstrip('/') or '/'


def read_text(path: Path) -> str:
    try:
        if path.stat().st_size > 512_000:
            return ''
        return path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return ''


def relative_path(root: Path, path: Path) -> str:
    try:
        return normalize_path(str(path.resolve().relative_to(root.resolve())))
    except Exception:
        return normalize_path(str(path))


def excerpt(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        text = ', '.join(str(item) for item in value[:5])
    else:
        text = str(value)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:MAX_EXCERPT] or None


def request_method(value: Any) -> str | None:
    text = str(value or '')
    match = re.match(r'\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+', text, re.I)
    return match.group(1).upper() if match else None


def safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def redact_url(url: str) -> str:
    parsed = urllib.parse.urlparse(str(url or ''))
    if not parsed.username and not parsed.password:
        return str(url or '')
    netloc = parsed.hostname or ''
    if parsed.port:
        netloc = f'{netloc}:{parsed.port}'
    return urllib.parse.urlunparse((parsed.scheme, netloc, parsed.path, '', parsed.query, ''))


def zap_executable() -> str | None:
    for name in ('zap-baseline.py', 'zap-baseline.bat', 'zap.sh', 'zap.bat'):
        found = shutil.which(name)
        if found:
            return found
    return None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def dast_guardrails() -> list[str]:
    return [
        'Run mode is for Phase 3 sandbox loopback targets, not production sensors.',
        'Non-loopback or remote DAST targets require allow_remote_base_url=true.',
        'DAST findings gate and inform; they are not fed directly into naive autofix.',
        'Endpoint-to-code mapping is conservative; unmapped findings stay endpoint-level.',
        'DAST report ingestion is side-effect free and preferred for normal scan/report paths.',
    ]
